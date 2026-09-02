//! The grouped-output converter: groupless input in, designated
//! LEN records re-framed as groups.
//!
//! Designation is a compiled [`Program`]: re-framing a LEN as a
//! group commits its payload to be a message — the group framing
//! exposes the interior to every grouped consumer. This
//! library never guesses messageness, so the caller must say
//! which fields carry messages. A designated occurrence converts:
//! minimal open tag, the payload's records walked and emitted (a
//! parse fault inside is a real fault with the crossing trail;
//! nested designations convert within), minimal end tag — the
//! length prefix vanishes, because groups carry none. A designated
//! occurrence that is not a LEN record is the caller's schema
//! error, faulted loudly. Everything undesignated rides verbatim,
//! and paths crossing an undesignated LEN commit it exactly as
//! `rewrite`'s do — its interior is walked and its length prefix
//! re-settles when conversions inside change its extent (the
//! cascade is why this direction, too, is a buffered two-pass job:
//! an enclosing prefix is unknowable until the interior settles).
//!
//! Output closure: the output always re-ingests under the grouped
//! dialect's `Tolerant` standard (groupless-lawful records are
//! grouped-lawful — the four-code language is a sub-language — and
//! authored framing pairs by construction). It closes under
//! `CanonicalMinimal` exactly when every padded source word was a
//! converted occurrence's dropped framing (its tag or its length
//! prefix) or a resized prefix: authored framing and resized
//! prefixes are minimal, every other word rides verbatim. A job
//! run under the `CanonicalMinimal` input standard admits no
//! padded word, so its output closes canonically by
//! construction. An *empty* program converts nothing and the
//! output is byte-identical — but if identity is the whole job,
//! no machine is needed: unchanged groupless bytes are already
//! grouped-lawful (see the [`crate::convert`] module doc).
//!
//! Coordinates: write · buffered · static · groupless (input) · grouped (output) · Standard (value-level) · borrowed · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::convert::grouped::Converter;
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! // varint f1=150 · LEN f2 [ varint f3=1 ]
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x18, 0x01];
//! let paths: [&[Segment<'_>]; 1] =
//!     [&[Segment::Field(FieldNumber::new(2).unwrap())]];
//! let program = Program::over(&paths).unwrap();
//! let converter =
//!     Converter::new(Standard::Tolerant, DepthLimit::REFERENCE, program);
//! let (out, stats) = converter.convert(&msg).unwrap();
//! // varint f1=150 · group f2 { varint f3=1 }
//! assert_eq!(out, [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14]);
//! assert_eq!(stats.converted(), 1);
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::Infallible;

use crate::admission::usize_of;
use crate::path::{Crossing, Matcher, Program, ix_u32};
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::varint::{emit64, encoded_len32, write64_at};
use crate::wire::PayloadLen;
use crate::wire::grouped::{RecordKind, group_end_word, head_word};
use crate::{DepthLimit, FaultClass, Standard};

/// The conversion job's configuration, judged once — jobs
/// downstream reuse it across documents. The program borrows the
/// caller's path slices, exactly as every static machine's rules
/// do.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct Converter<'r> {
    standard: Standard,
    limit: DepthLimit,
    program: Program<'r>,
}

impl<'r> Converter<'r> {
    /// Declares the input acceptance standard, the container depth
    /// budget, and the conversion policy: the records the compiled
    /// `program` designates re-frame as groups.
    ///
    /// The standard picks a monomorphized walk instance once per
    /// job — both passes run it — so a tolerant job pays no width
    /// comparison and a canonical one refuses every non-minimal
    /// varint width in the input it walks (opaque LEN interiors
    /// stay the caller's declaration).
    #[inline]
    pub const fn new(standard: Standard, limit: DepthLimit, program: Program<'r>) -> Self {
        Self { standard, limit, program }
    }

    /// Converts `input` into fresh bytes (one exact allocation),
    /// with the job receipt.
    ///
    /// # Errors
    ///
    /// [`Fault`] when the input refuses admission, the walk hits
    /// unlawful wire (group codes included — the groupless input
    /// language's capability refusal), a designated occurrence is
    /// not a LEN record, container nesting leaves the declared
    /// budget, or a resized interior or the root outgrows its
    /// class. No bytes are produced on `Err`.
    ///
    /// # Panics
    ///
    /// If the crate's own two passes disagree on what they measured
    /// and what they emitted — a library bug caught at the seam
    /// (the fresh buffer this wrapper allocates cannot reach the
    /// capacity extreme the `_into` face documents).
    #[inline]
    pub fn convert(&self, input: &[u8]) -> Result<(Vec<u8>, Stats), Fault> {
        let mut out = Vec::new();
        let stats = self.convert_into(input, &mut out)?;
        Ok((out, stats))
    }

    /// Converts `input`, appending to `out` — the reuse face.
    ///
    /// Existing content is untouched, all faults precede the
    /// reservation, and the new length is published once — after
    /// the emit pass's invariant pins.
    ///
    /// # Errors
    ///
    /// As [`convert`](Self::convert); `out` is untouched on `Err`.
    ///
    /// # Panics
    ///
    /// If the crate's own two passes disagree on what they measured
    /// and what they emitted — a library bug caught at the seam —
    /// or if appending the output to `out` would overflow the
    /// vector's capacity bounds (an extreme the caller can reach on
    /// 32-bit targets with a near-full buffer).
    pub fn convert_into(&self, input: &[u8], out: &mut Vec<u8>) -> Result<Stats, Fault> {
        match self.standard {
            Standard::Tolerant => run_into::<false>(input, self.program, self.limit, out),
            Standard::CanonicalMinimal => run_into::<true>(input, self.program, self.limit, out),
        }
    }

    /// Converts `input`, handing the output to `sink` as borrowed
    /// slices in output order — preflighted: every fault surfaces
    /// in the measuring pass, ahead of the first handoff, so on
    /// `Err` the sink has received nothing.
    ///
    /// No output buffer exists: verbatim runs pass through as
    /// windows of `input`, authored framing rides a ten-byte stack
    /// window, and the concatenation is exactly
    /// [`convert`](Self::convert)'s output.
    ///
    /// # Errors
    ///
    /// As [`convert`](Self::convert); the sink receives nothing on
    /// `Err`.
    ///
    /// # Panics
    ///
    /// If the crate's own two passes disagree on what they measured
    /// and what they handed over — a library bug caught at the
    /// seam.
    pub fn convert_sink(&self, input: &[u8], mut sink: impl FnMut(&[u8])) -> Result<Stats, Fault> {
        match self.standard {
            Standard::Tolerant => run_sink::<false>(input, self.program, self.limit, &mut sink),
            Standard::CanonicalMinimal => {
                run_sink::<true>(input, self.program, self.limit, &mut sink)
            }
        }
    }
}

/// The job receipt.
///
/// A zero `converted` count is the silently-inapplicable-policy
/// signal: no designated occurrence existed, and the output is
/// byte-identical to the input.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stats {
    converted: u32,
    descended: u32,
}

impl Stats {
    /// LEN records re-framed as groups (nested conversions count
    /// one each).
    #[inline]
    #[must_use]
    pub const fn converted(self) -> u32 {
        self.converted
    }

    /// Undesignated LEN payloads descended into (committed as
    /// messages by crossing paths).
    #[inline]
    #[must_use]
    pub const fn descended(self) -> u32 {
        self.descended
    }
}

/// A job refusal: where, the promise chain crossed to reach it,
/// and which contract broke.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u32,
    trail: Box<[Crossing]>,
    kind: FaultKind,
}

impl Fault {
    /// Whole-input byte coordinate.
    #[inline]
    #[must_use]
    pub const fn at(&self) -> u32 {
        self.at
    }

    /// Committed containers crossed to reach the fault (outermost
    /// first; empty at top level) — converted containers included:
    /// re-framing is a commitment.
    #[inline]
    #[must_use]
    pub fn trail(&self) -> &[Crossing] {
        &self.trail
    }

    /// The broken contract.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> FaultKind {
        self.kind
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.at)
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.kind)
    }
}

/// The converter's refusal classes.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// A committed descent (or the top level) hit unlawful wire —
    /// the groupless traversal vocabulary, summarized (group codes
    /// arrive as its capability refusal).
    Wire(WireBreach),
    /// A designated occurrence is not a LEN record: the program
    /// committed the field to carry messages, and the document
    /// disagrees — the caller's schema error, quoted by path.
    KindMismatch {
        /// The designating path's index.
        path: u32,
    },
    /// A resized interior outgrew the LEN class (an undesignated
    /// container whose designated descendants re-framed).
    Growth {
        /// The interior's computed length.
        len: u64,
    },
    /// The converted root outgrew the admission cap.
    Output {
        /// The root's computed length.
        len: u64,
    },
    /// The input itself exceeds the admission cap.
    Oversize,
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Wire(breach) => write!(f, "{breach}"),
            Self::KindMismatch { path } => {
                write!(f, "path {path} designates a record whose kind is not LEN")
            }
            Self::Growth { len } => {
                write!(f, "a resized interior of {len} bytes outgrew the LEN class")
            }
            Self::Output { len } => {
                write!(f, "the converted root of {len} bytes outgrew the admission cap")
            }
            Self::Oversize => f.write_str("the input exceeds the admission cap"),
        }
    }
}

impl core::error::Error for FaultKind {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(breach) => Some(breach),
            Self::KindMismatch { .. }
            | Self::Growth { .. }
            | Self::Output { .. }
            | Self::Oversize => None,
        }
    }
}

/// The wire breach, summarized by who acts on it: a conversion
/// consumer rejects the document either way — byte-precise
/// diagnosis over the same bytes is the inspector's job.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireBreach {
    /// A varint (tag, length, or value) refused: too wide, out of
    /// class, or cut by the input end.
    Varint,
    /// The tag word is unlawful (field zero or an unassigned code).
    Tag,
    /// A fixed-width or LEN payload exceeds the remaining input.
    Truncated,
    /// A committed descent would nest past the caller's declared
    /// [`DepthLimit`] budget (conversions are commitments too).
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// canonical standard's judgment (the tolerant standard never
    /// judges widths).
    NonMinimal,
    /// A group code appeared — outside the input dialect's
    /// language (an already-grouped document needs no converter).
    GroupCode,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget; [`NonMinimal`] is the
    /// canonical standard).
    ///
    /// [`Depth`]: Self::Depth
    /// [`NonMinimal`]: Self::NonMinimal
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Varint | Self::Tag | Self::Truncated => FaultClass::Grammar,
            Self::Depth | Self::NonMinimal => FaultClass::Policy,
            Self::GroupCode => FaultClass::Capability,
        }
    }
}

impl core::fmt::Display for WireBreach {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Varint => "a varint refused (too wide, out of class, or cut short)",
            Self::Tag => "an unlawful tag word",
            Self::Truncated => "a payload past the input end",
            Self::Depth => "nesting past the declared depth budget",
            Self::NonMinimal => "a varint word wider than its minimal encoding",
            Self::GroupCode => "a group code outside the input dialect",
        })
    }
}

impl core::error::Error for WireBreach {}

#[cold]
const fn breach(kind: crate::cursor::groupless::FaultKind) -> WireBreach {
    use crate::cursor::groupless::FaultKind as T;
    match kind {
        T::Read { .. } => WireBreach::Varint,
        T::FieldZero { .. } | T::Unassigned { .. } => WireBreach::Tag,
        T::GroupCode { .. } => WireBreach::GroupCode,
        T::FixedTruncated { .. } | T::LenOverrun { .. } => WireBreach::Truncated,
        T::NonMinimalTag | T::NonMinimalLen { .. } | T::NonMinimalValue { .. } => {
            WireBreach::NonMinimal
        }
    }
}

// The 64-bit layout is pinned exactly; narrower pointer widths
// are bounded by the same ceiling.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Fault>() == 40);
#[cfg(not(target_pointer_width = "64"))]
const _: () = assert!(core::mem::size_of::<Fault>() <= 40);

// ─── the slot table (private contract type) ───

/// Pre-order slots, one per crossed (undesignated, committed) LEN.
/// Bit 31 is the dirty bit: a dirty slot's low 31 bits carry the
/// new interior length (≤ 2^31 − 1; the Growth judgment upstream
/// of the fill proves it); a clean slot's low 31 bits carry its
/// descendant slot count (strictly under 2^30: every descendant is
/// a crossed LEN costing at least two source bytes out of an input
/// under 2^31), letting pass two skip the whole subtree and memcpy
/// the record. Converted containers claim no slots: they are
/// walked unconditionally in both passes (a conversion dirties
/// every enclosing frame, so no clean subtree contains one) and
/// their bodies need no length. The bit discipline lives behind
/// these methods; raw masks never leak.
struct SlotTable {
    slots: Vec<u32>,
}

const DIRTY: u32 = 1 << 31;

impl SlotTable {
    const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Pass one: claims the next pre-order slot, returning its
    /// index for the fill at descent exit.
    fn claim(&mut self) -> usize {
        self.slots.push(0);
        self.slots.len() - 1
    }

    /// Pass one: fills a claimed slot. `payload` is 31-bit by
    /// class either way (dirty: Growth-judged length; clean:
    /// descendant count under 2^30).
    fn fill(&mut self, slot: usize, dirty: bool, payload: u32) {
        debug_assert!(payload & DIRTY == 0, "slot payloads are 31-bit by class");
        debug_assert!(slot < self.slots.len(), "fills follow claims");
        // SAFETY: `slot` was minted by `claim` as `len - 1`, and
        // the table only ever grows — every claimed index stays in
        // bounds.
        *unsafe { self.slots.get_unchecked_mut(slot) } =
            if dirty { payload | DIRTY } else { payload };
    }

    /// The number of slots claimed so far.
    const fn claimed(&self) -> usize {
        self.slots.len()
    }

    /// Pass two: consumes the slot at the cursor.
    fn read(&self, cursor: usize) -> SlotValue {
        debug_assert!(cursor < self.slots.len(), "the cursor replays pass one's claims");
        // SAFETY: the cursor stays inside the claimed prefix by
        // induction: it starts at 0; a dirty slot advances it by
        // one, a clean slot by one plus its descendant count — and
        // that count is exactly how many slots pass one claimed
        // inside the subtree. The replay premise is typed: the emit
        // walk's input, program, and limit come from the `Plan`
        // that sealed this table, so pass two re-makes pass one's
        // decisions verbatim (conversions claim nothing in either
        // pass). (`finish` additionally witnesses full consumption
        // after the fact; the bound does not rest on it.)
        let raw = *unsafe { self.slots.get_unchecked(cursor) };
        if raw & DIRTY == 0 {
            SlotValue::Clean { descendants: raw }
        } else {
            SlotValue::Dirty { new_len: raw & !DIRTY }
        }
    }
}

/// A consumed slot's meaning.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlotValue {
    /// The subtree changed: emit the new interior length and walk
    /// in.
    Dirty {
        /// The payload's new length.
        new_len: u32,
    },
    /// The subtree is byte-identical: memcpy the whole record and
    /// skip its descendant slots.
    Clean {
        /// How many slots the subtree claimed.
        descendants: u32,
    },
}

// ─── the sealed plan (private contract type) ───

/// The measuring pass's sealed verdict and the replay identity
/// that produced it: the exact input, program, and limit whose
/// walk claimed the slot table, the measured output size (judged
/// into the LEN class at construction), and the tallies. A `Plan`
/// in hand is the emit pass's whole admission.
struct Plan<'i, 'r> {
    input: &'i [u8],
    program: Program<'r>,
    limit: DepthLimit,
    stats: Stats,
    slots: SlotTable,
    /// The measured output size, in class.
    total: u32,
}

impl<'i, 'r> Plan<'i, 'r> {
    /// Seals the measurement; `None` when the converted root
    /// outgrows the LEN class.
    fn new(
        input: &'i [u8],
        program: Program<'r>,
        limit: DepthLimit,
        stats: Stats,
        slots: SlotTable,
        total: u64,
    ) -> Option<Self> {
        if total > u64::from(PayloadLen::MAX.as_inner()) {
            return None;
        }
        // In class: judged above.
        #[allow(clippy::as_conversions, reason = "class-judged total narrows losslessly")]
        Some(Self { input, program, limit, stats, slots, total: total as u32 })
    }
}

// ─── the walk skeleton (private) ───

/// The emit-pass answer to a crossed-LEN descent question.
enum Down {
    /// Walk in (pass one always; pass two on a dirty slot).
    Walk,
    /// The subtree is byte-identical: the walker copies the whole
    /// record verbatim and does not descend.
    Skip,
}

/// One pass's consumer. `verbatim` spans are absolute and
/// contiguous-mergeable; `ascend` reports an over-class interior
/// as `Err(len)` for the walker to coordinate.
///
/// `Refusal` is the pass's fault channel: the measuring pass
/// carries the document [`Fault`] out; the emit pass sits past the
/// fault barrier, so its channel is uninhabited and every walker
/// fault site is dead in its instantiation.
trait Sink {
    type Refusal;
    fn refuse(&self, fault: Fault) -> Self::Refusal;
    fn verbatim(&mut self, from: u32, to: u32);
    /// A designated LEN re-frames: its minimal open tag (`word`)
    /// lands here; the dropped source framing spans
    /// `head..payload_start`.
    fn convert_enter(&mut self, word: u32);
    /// The converted interior settled: the minimal end tag
    /// (`word`) lands here.
    fn convert_exit(&mut self, word: u32);
    fn descend(&mut self, head: u32, tag_end: u32, payload_start: u32, payload_end: u32) -> Down;
    fn ascend(
        &mut self,
        head: u32,
        tag_end: u32,
        payload_start: u32,
        payload_end: u32,
    ) -> Result<(), u64>;
}

/// What opened a walk layer: a crossing (undesignated, prefix
/// re-settles) or a conversion (designated, framing re-authors).
#[derive(Clone, Copy, PartialEq, Eq)]
enum LayerKind {
    Cross,
    Convert,
}

/// One committed LEN layer on the explicit stack.
struct Layer<'i> {
    cursor: Cursor<'i>,
    /// Absolute base of this layer's payload.
    base: u32,
    /// The crossing that opened this layer (`None` at the root).
    crossing: Option<Crossing>,
    /// Record geometry of the opening LEN (meaningless at root).
    head: u32,
    tag_end: u32,
    payload_start: u32,
    payload_end: u32,
    /// LEN commitments still allowed below this layer.
    remaining: u16,
    kind: LayerKind,
}

/// The promise chain: one crossing per committed layer (converted
/// layers included). Allocates, but only on the fault path — every
/// caller is a refusal.
fn trail(layers: &[Layer<'_>]) -> Box<[Crossing]> {
    layers.iter().filter_map(|l| l.crossing).collect()
}

/// Runs one pass. Every fault funnels through the sink's refusal
/// channel: the measuring pass carries [`Fault`] out; the emit
/// pass replays the identical judgment sequence over the same
/// bytes, so its fault sites are dead by construction and its
/// channel is uninhabited. One instance per acceptance standard:
/// the walk rides the traversal cursor's engine split.
fn walk<S: Sink, const MINIMAL: bool>(
    input: &[u8],
    program: Program<'_>,
    limit: DepthLimit,
    sink: &mut S,
) -> Result<Stats, S::Refusal> {
    let mut matcher = Matcher::new(program);
    let mut stats = Stats::default();
    let Ok(root) = Cursor::over(input) else {
        return Err(sink.refuse(Fault { at: 0, trail: Box::new([]), kind: FaultKind::Oversize }));
    };
    let mut layers = Vec::new();
    layers.push(Layer {
        cursor: root,
        base: 0,
        crossing: None,
        head: 0,
        tag_end: 0,
        payload_start: 0,
        payload_end: 0,
        remaining: limit.as_inner(),
        kind: LayerKind::Cross,
    });

    loop {
        // SAFETY: the root layer is pushed above and the only pop
        // sits behind the `len == 1` return below, so the stack is
        // never empty here.
        let layer = unsafe { layers.last_mut().unwrap_unchecked() };
        let base = layer.base;
        let head = base + layer.cursor.pos();
        let Some(item) = layer.cursor.step::<MINIMAL>() else {
            // Layer exhausted cleanly.
            if layers.len() == 1 {
                return Ok(stats);
            }
            // SAFETY: length checked above — at least two layers.
            let done = unsafe { layers.pop().unwrap_unchecked() };
            matcher.exit();
            match done.kind {
                LayerKind::Cross => {
                    if let Err(len) =
                        sink.ascend(done.head, done.tag_end, done.payload_start, done.payload_end)
                    {
                        return Err(sink.refuse(Fault {
                            at: done.head,
                            trail: trail(&layers),
                            kind: FaultKind::Growth { len },
                        }));
                    }
                }
                LayerKind::Convert => {
                    // SAFETY: every non-root layer was pushed with
                    // its crossing.
                    let field = unsafe { done.crossing.unwrap_unchecked() }.field();
                    sink.convert_exit(group_end_word(field));
                }
            }
            continue;
        };
        let entry = match item {
            Ok(entry) => entry,
            Err(fault) => {
                return Err(sink.refuse(Fault {
                    at: base + fault.at(),
                    trail: trail(&layers),
                    kind: FaultKind::Wire(breach(fault.kind())),
                }));
            }
        };
        let end = base + layer.cursor.pos();
        let field = entry.field();

        match entry.kind() {
            EntryKind::Varint(_) | EntryKind::I32(_) | EntryKind::I64(_) => {
                if let Some(path) = matcher.first_target(field) {
                    return Err(sink.refuse(Fault {
                        at: head,
                        trail: trail(&layers),
                        kind: FaultKind::KindMismatch { path: u32::from(path) },
                    }));
                }
                sink.verbatim(head, end);
            }
            EntryKind::Len(payload) => {
                // The payload was delivered by the cursor from admitted input.
                #[allow(
                    clippy::as_conversions,
                    reason = "cursor-delivered payload lies in the LEN class"
                )]
                let payload_start = end - payload.len() as u32;
                let designated = matcher.first_target(field).is_some();
                let routed = matcher.probe_routes(field);
                if !designated && !routed {
                    sink.verbatim(head, end);
                    continue;
                }
                let remaining = layer.remaining;
                if remaining == 0 {
                    return Err(sink.refuse(Fault {
                        at: head,
                        trail: trail(&layers),
                        kind: FaultKind::Wire(WireBreach::Depth),
                    }));
                }
                let tag_end = head + u32::from(layer.cursor.tag_width());
                if designated {
                    stats.converted += 1;
                    sink.convert_enter(head_word(field, RecordKind::Group));
                    matcher.commit_descent();
                    layers.push(Layer {
                        cursor: Cursor::within(payload),
                        base: payload_start,
                        crossing: Some(Crossing::new(field, head)),
                        head,
                        tag_end,
                        payload_start,
                        payload_end: end,
                        remaining: remaining - 1,
                        kind: LayerKind::Convert,
                    });
                } else {
                    match sink.descend(head, tag_end, payload_start, end) {
                        Down::Skip => sink.verbatim(head, end),
                        Down::Walk => {
                            stats.descended += 1;
                            matcher.commit_descent();
                            layers.push(Layer {
                                cursor: Cursor::within(payload),
                                base: payload_start,
                                crossing: Some(Crossing::new(field, head)),
                                head,
                                tag_end,
                                payload_start,
                                payload_end: end,
                                remaining: remaining - 1,
                                kind: LayerKind::Cross,
                            });
                        }
                    }
                }
            }
        }
    }
}

// ─── pass one: measure ───

/// One measuring layer: the running interior total, the slot it
/// fills at ascent (crossings only), and whether any interior byte
/// changed.
struct Frame {
    total: u64,
    /// The pre-order slot claimed at a crossing's descent;
    /// meaningless for converted layers and the root, which never
    /// fill one.
    slot: u32,
    dirty: bool,
}

struct Measure {
    /// Layer accumulators, root first — never empty: the root
    /// frame lives from construction to `root_total`.
    frames: Vec<Frame>,
    slots: SlotTable,
}

impl Measure {
    fn new() -> Self {
        Self {
            frames: alloc::vec![Frame { total: 0, slot: 0, dirty: false }],
            slots: SlotTable::new(),
        }
    }

    fn root_total(&self) -> u64 {
        debug_assert!(self.frames.len() == 1, "all layers ascended");
        // SAFETY: the root frame is pushed at construction and only
        // the exit events pop — each paired with an enter push by
        // the walk — so index zero is always occupied.
        unsafe { self.frames.get_unchecked(0) }.total
    }

    /// The current layer's accumulator.
    fn top(&mut self) -> &mut Frame {
        debug_assert!(!self.frames.is_empty(), "the root frame is never popped");
        // SAFETY: the root frame is pushed at construction and only
        // the exit events pop — each paired with an enter push by
        // the walk.
        unsafe { self.frames.last_mut().unwrap_unchecked() }
    }
}

impl Sink for Measure {
    type Refusal = Fault;

    fn refuse(&self, fault: Fault) -> Fault {
        fault
    }

    fn verbatim(&mut self, from: u32, to: u32) {
        self.top().total += u64::from(to - from);
    }

    fn convert_enter(&mut self, word: u32) {
        // The authored open tag bills the parent; the re-framing
        // dirties it (the source tag and prefix vanish).
        let parent = self.top();
        parent.total += u64::from(encoded_len32(word));
        parent.dirty = true;
        self.frames.push(Frame { total: 0, slot: 0, dirty: false });
    }

    fn convert_exit(&mut self, word: u32) {
        debug_assert!(self.frames.len() >= 2, "enter/exit pairing");
        // SAFETY: paired with the `convert_enter` push — the walk
        // exits only layers it entered, above the permanent root.
        let child = unsafe { self.frames.pop().unwrap_unchecked() };
        let parent = self.top();
        parent.total += child.total + u64::from(encoded_len32(word));
        // A group body needs no length class of its own: the only
        // size judgment left is the root's, at the plan seal.
    }

    fn descend(&mut self, _head: u32, _tag_end: u32, _ps: u32, _pe: u32) -> Down {
        // Lossless: one slot per crossed LEN, and crossed records
        // have distinct heads in an input under 2^31.
        #[allow(
            clippy::as_conversions,
            reason = "slot counts stay under 2^30 (two source bytes per crossed LEN)"
        )]
        let slot = self.slots.claim() as u32;
        self.frames.push(Frame { total: 0, slot, dirty: false });
        Down::Walk
    }

    fn ascend(
        &mut self,
        head: u32,
        tag_end: u32,
        payload_start: u32,
        payload_end: u32,
    ) -> Result<(), u64> {
        debug_assert!(self.frames.len() >= 2, "descend/ascend pairing");
        // SAFETY: paired with the `descend` push — the walk ascends
        // only layers it descended into, above the permanent root.
        let child = unsafe { self.frames.pop().unwrap_unchecked() };
        if child.total > u64::from(PayloadLen::MAX.as_inner()) {
            return Err(child.total);
        }
        let old_len = u64::from(payload_end - payload_start);
        if child.dirty {
            // In class: judged two lines up.
            #[allow(
                clippy::as_conversions,
                reason = "pass-one total was judged against the LEN class"
            )]
            self.slots.fill(usize_of(child.slot), true, child.total as u32);
            let prefix = if child.total == old_len {
                u64::from(payload_start - tag_end)
            } else {
                #[allow(
                    clippy::as_conversions,
                    reason = "pass-one total was judged against the LEN class"
                )]
                u64::from(encoded_len32(child.total as u32))
            };
            let parent = self.top();
            parent.total += u64::from(tag_end - head) + prefix + child.total;
            parent.dirty = true;
        } else {
            debug_assert!(child.total == old_len, "a clean subtree is byte-identical");
            // Lossless: claims are bounded by the record count.
            let descendants = ix_u32(self.slots.claimed() - (usize_of(child.slot) + 1));
            self.slots.fill(usize_of(child.slot), false, descendants);
            self.top().total += u64::from(payload_end - head);
        }
        Ok(())
    }
}

// ─── pass two: emit ───

struct Emit<'i, 'o> {
    input: &'i [u8],
    out: &'o mut Vec<u8>,
    /// The caller's published length at entry: everything past it
    /// is this job's reserved, unpublished spare capacity.
    base: usize,
    /// Bytes written into the spare region so far.
    written: usize,
    /// The reserved emission size (the plan's in-class total).
    total: usize,
    /// Pending verbatim run, absolute half-open.
    run: Option<(u32, u32)>,
    slots: SlotTable,
    cursor: usize,
    /// Logical bytes emitted (runs included before flushing).
    logical: u64,
    /// Per-dirty-crossing ledger: (logical at entry, expected
    /// interior).
    ledger: Vec<(u64, u32)>,
}

impl<'i, 'o> Emit<'i, 'o> {
    /// Opens the emit pass over a sealed plan's table and size:
    /// one exact reservation, and the caller's length stays
    /// unpublished until [`finish`](Self::finish).
    fn new(input: &'i [u8], out: &'o mut Vec<u8>, slots: SlotTable, total: u32) -> Self {
        let total = usize_of(total);
        out.reserve_exact(total);
        let base = out.len();
        Self {
            input,
            out,
            base,
            written: 0,
            total,
            run: None,
            slots,
            cursor: 0,
            logical: 0,
            ledger: Vec::new(),
        }
    }

    /// Appends `bytes` to the unpublished region.
    fn push(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() <= self.total - self.written, "emission stays in the plan");
        // SAFETY: `new` reserved `total` spare bytes past `base`,
        // and the measuring pass accounted this emission into
        // `total` (each sink event emits exactly the bytes the
        // measuring sink counted for it), so the copy lands inside
        // the reservation; `out`'s exclusive borrow keeps source
        // and destination disjoint.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.out.as_mut_ptr().add(self.base + self.written),
                bytes.len(),
            );
        }
        self.written += bytes.len();
    }

    /// Appends `value` as exactly `width` varint bytes. Contract:
    /// `width` is the value's own encoded width — the accounting
    /// already computed it.
    fn push_varint(&mut self, value: u64, width: u32) {
        debug_assert!(usize_of(width) <= self.total - self.written, "emission stays in the plan");
        // SAFETY: as in `push` — the measuring pass accounted
        // exactly `width` bytes for this site, and `width` is the
        // value's own encoded length by the caller's contract.
        unsafe {
            write64_at(self.out.as_mut_ptr().add(self.base + self.written), value, width);
        }
        self.written += usize_of(width);
    }

    fn flush(&mut self) {
        if let Some((from, to)) = self.run.take() {
            // SAFETY: runs are record extents the cursor delivered,
            // merged only when contiguous: from <= to <= input len.
            let src = unsafe { self.input.get_unchecked(usize_of(from)..usize_of(to)) };
            self.push(src);
        }
    }

    /// One authored framing tag, minimal.
    fn tag(&mut self, word: u32) {
        self.flush();
        let width = encoded_len32(word);
        self.logical += u64::from(width);
        self.push_varint(u64::from(word), width);
    }

    /// The three assertions are deliberate library-invariant pins
    /// (slot consumption, ledger closure, measured total), judged
    /// once per job — and publication sits behind them: the
    /// caller's new length appears only after every pin passes.
    fn finish(mut self) {
        self.flush();
        assert!(self.cursor == self.slots.claimed(), "every slot consumed exactly once");
        assert!(self.ledger.is_empty(), "every dirty layer closed");
        assert!(self.written == self.total, "pass two emitted the measured total");
        // SAFETY: `new` reserved `total` bytes past `base`; `push`
        // and `push_varint` initialized every byte below
        // `base + written`, advancing `written` by exactly the
        // bytes they wrote — the published prefix is initialized
        // and inside the reservation.
        unsafe { self.out.set_len(self.base + self.written) };
    }
}

impl Sink for Emit<'_, '_> {
    type Refusal = Infallible;

    #[inline]
    fn refuse(&self, _fault: Fault) -> Infallible {
        // SAFETY: the emit pass replays the measuring pass — the
        // same walk skeleton over the same bytes, program, and
        // limit, with matcher state restored exactly across the
        // subtrees it skips — so every judgment repeats, and a job
        // the measuring pass accepted reaches no fault site here.
        unsafe { core::hint::unreachable_unchecked() }
    }

    fn verbatim(&mut self, from: u32, to: u32) {
        self.logical += u64::from(to - from);
        match &mut self.run {
            Some((_, tail)) if *tail == from => *tail = to,
            Some(_) => {
                self.flush();
                self.run = Some((from, to));
            }
            None => self.run = Some((from, to)),
        }
    }

    fn convert_enter(&mut self, word: u32) {
        self.tag(word);
    }

    fn convert_exit(&mut self, word: u32) {
        self.tag(word);
    }

    fn descend(&mut self, head: u32, tag_end: u32, payload_start: u32, payload_end: u32) -> Down {
        match self.slots.read(self.cursor) {
            SlotValue::Clean { descendants } => {
                self.cursor += 1 + usize_of(descendants);
                Down::Skip
            }
            SlotValue::Dirty { new_len } => {
                self.cursor += 1;
                let old_len = payload_end - payload_start;
                if new_len == old_len {
                    // Value unchanged: the whole frame (tag and
                    // prefix) is untouched bytes.
                    self.verbatim(head, payload_start);
                } else {
                    self.verbatim(head, tag_end);
                    self.flush();
                    let width = encoded_len32(new_len);
                    self.logical += u64::from(width);
                    self.push_varint(u64::from(new_len), width);
                }
                self.ledger.push((self.logical, new_len));
                Down::Walk
            }
        }
    }

    fn ascend(&mut self, _head: u32, _tag_end: u32, _ps: u32, _pe: u32) -> Result<(), u64> {
        debug_assert!(!self.ledger.is_empty(), "dirty layers are ledgered");
        // SAFETY: `descend` pushes a ledger entry for every layer
        // it walks into, and ascents pair with descents.
        let (mark, expected) = unsafe { self.ledger.pop().unwrap_unchecked() };
        assert!(
            self.logical - mark == u64::from(expected),
            "a dirty interior emitted exactly its slot length"
        );
        Ok(())
    }
}

// ─── pass two, the sink twin ───

/// [`Emit`]'s sink twin: the same replay, handing borrowed slices
/// to the caller's sink instead of writing a buffer. Verbatim runs
/// coalesce and pass through as windows of the input; authored
/// words ride a ten-byte stack window. The invariant pins are the
/// buffered twin's, with the written count standing in for the
/// reservation.
struct SinkEmit<'i, 's, F> {
    input: &'i [u8],
    sink: &'s mut F,
    /// Pending verbatim run, absolute half-open.
    run: Option<(u32, u32)>,
    slots: SlotTable,
    cursor: usize,
    /// Bytes handed to the sink so far.
    written: u64,
    /// The plan's in-class total (the finish pin).
    total: u64,
    /// Logical bytes emitted (runs included before flushing).
    logical: u64,
    /// Per-dirty-crossing ledger: (logical at entry, expected
    /// interior).
    ledger: Vec<(u64, u32)>,
}

impl<F: FnMut(&[u8])> SinkEmit<'_, '_, F> {
    /// Hands one non-empty slice to the sink (empty handoffs are
    /// dropped: they carry no bytes to account).
    fn hand(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        {
            self.written += bytes.len() as u64;
        }
        (self.sink)(bytes);
    }

    /// Hands `value` as exactly `width` minimal varint bytes
    /// through the stack window. Contract: `width` is the value's
    /// own encoded width — the accounting already computed it.
    fn hand_varint(&mut self, value: u64, width: u32) {
        let mut window = [0u8; 10];
        let emitted = emit64(value, &mut window);
        debug_assert!(emitted == width, "the accounted width is the value's own");
        self.hand(&window[..usize_of(width)]);
    }

    fn flush(&mut self) {
        if let Some((from, to)) = self.run.take() {
            let input = self.input;
            // SAFETY: runs are record extents the cursor delivered,
            // merged only when contiguous: from <= to <= input len.
            self.hand(unsafe { input.get_unchecked(usize_of(from)..usize_of(to)) });
        }
    }

    /// One authored framing tag, minimal.
    fn tag(&mut self, word: u32) {
        self.flush();
        let width = encoded_len32(word);
        self.logical += u64::from(width);
        self.hand_varint(u64::from(word), width);
    }

    /// The buffered twin's invariant pins, judged once per job.
    fn finish(mut self) {
        self.flush();
        assert!(self.cursor == self.slots.claimed(), "every slot consumed exactly once");
        assert!(self.ledger.is_empty(), "every dirty layer closed");
        assert!(self.written == self.total, "pass two handed the sink the measured total");
    }
}

impl<F: FnMut(&[u8])> Sink for SinkEmit<'_, '_, F> {
    type Refusal = Infallible;

    #[inline]
    fn refuse(&self, _fault: Fault) -> Infallible {
        // SAFETY: as the buffered twin — the emit pass replays the
        // measuring pass over the same bytes, program, and limit,
        // so a job the measuring pass accepted reaches no fault
        // site here.
        unsafe { core::hint::unreachable_unchecked() }
    }

    fn verbatim(&mut self, from: u32, to: u32) {
        self.logical += u64::from(to - from);
        match &mut self.run {
            Some((_, tail)) if *tail == from => *tail = to,
            Some(_) => {
                self.flush();
                self.run = Some((from, to));
            }
            None => self.run = Some((from, to)),
        }
    }

    fn convert_enter(&mut self, word: u32) {
        self.tag(word);
    }

    fn convert_exit(&mut self, word: u32) {
        self.tag(word);
    }

    fn descend(&mut self, head: u32, tag_end: u32, payload_start: u32, payload_end: u32) -> Down {
        match self.slots.read(self.cursor) {
            SlotValue::Clean { descendants } => {
                self.cursor += 1 + usize_of(descendants);
                Down::Skip
            }
            SlotValue::Dirty { new_len } => {
                self.cursor += 1;
                let old_len = payload_end - payload_start;
                if new_len == old_len {
                    // Value unchanged: the whole frame (tag and
                    // prefix) is untouched bytes.
                    self.verbatim(head, payload_start);
                } else {
                    self.verbatim(head, tag_end);
                    self.flush();
                    let width = encoded_len32(new_len);
                    self.logical += u64::from(width);
                    self.hand_varint(u64::from(new_len), width);
                }
                self.ledger.push((self.logical, new_len));
                Down::Walk
            }
        }
    }

    fn ascend(&mut self, _head: u32, _tag_end: u32, _ps: u32, _pe: u32) -> Result<(), u64> {
        debug_assert!(!self.ledger.is_empty(), "dirty layers are ledgered");
        // SAFETY: `descend` pushes a ledger entry for every layer
        // it walks into, and ascents pair with descents.
        let (mark, expected) = unsafe { self.ledger.pop().unwrap_unchecked() };
        assert!(
            self.logical - mark == u64::from(expected),
            "a dirty interior emitted exactly its slot length"
        );
        Ok(())
    }
}

// ─── the job fronts ───

/// One buffered job, one instance per acceptance standard: the
/// measuring pass walks and judges, the emit pass replays the same
/// instance over the sealed plan.
fn run_into<const MINIMAL: bool>(
    input: &[u8],
    program: Program<'_>,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<Stats, Fault> {
    let mut measure = Measure::new();
    let stats = walk::<_, MINIMAL>(input, program, limit, &mut measure)?;
    let total = measure.root_total();
    let Some(plan) = Plan::new(input, program, limit, stats, measure.slots, total) else {
        return Err(Fault { at: 0, trail: Box::new([]), kind: FaultKind::Output { len: total } });
    };
    let Plan { input, program, limit, stats, slots, total } = plan;
    let mut emit = Emit::new(input, out, slots, total);
    // The emit pass is past the fault barrier: its refusal channel
    // is uninhabited, so the pattern is irrefutable.
    let Ok(repeated) = walk::<_, MINIMAL>(input, program, limit, &mut emit);
    debug_assert!(repeated == stats, "the emit pass repeats the measuring pass's judgments");
    emit.finish();
    Ok(stats)
}

/// [`run_into`]'s sink twin.
fn run_sink<const MINIMAL: bool>(
    input: &[u8],
    program: Program<'_>,
    limit: DepthLimit,
    sink: &mut impl FnMut(&[u8]),
) -> Result<Stats, Fault> {
    let mut measure = Measure::new();
    let stats = walk::<_, MINIMAL>(input, program, limit, &mut measure)?;
    let total = measure.root_total();
    let Some(plan) = Plan::new(input, program, limit, stats, measure.slots, total) else {
        return Err(Fault { at: 0, trail: Box::new([]), kind: FaultKind::Output { len: total } });
    };
    let Plan { input, program, limit, stats, slots, total } = plan;
    let mut emit = SinkEmit {
        input,
        sink,
        run: None,
        slots,
        cursor: 0,
        written: 0,
        total: u64::from(total),
        logical: 0,
        ledger: Vec::new(),
    };
    // The emit pass is past the fault barrier: its refusal channel
    // is uninhabited, so the pattern is irrefutable.
    let Ok(repeated) = walk::<_, MINIMAL>(input, program, limit, &mut emit);
    debug_assert!(repeated == stats, "the emit pass repeats the measuring pass's judgments");
    emit.finish();
    Ok(stats)
}

#[cfg(test)]
mod tests;
