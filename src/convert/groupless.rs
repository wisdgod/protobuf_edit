//! The groupless-output converter: grouped input in, every group
//! re-framed as a LEN record.
//!
//! The walk is the grouped traversal's — groups arrive as in-band
//! enter/exit entries — and the re-framing is total: group
//! punctuation identifies every source group by syntax, so no
//! policy exists to declare. Each group becomes a LEN record of
//! the same field: minimal tag, minimal length prefix over the
//! converted body, the body's records in order (nested groups
//! convert bottom-up — the interior settles before the enclosing
//! prefix is knowable; the Vec faces settle each prefix online at
//! its group's exit, the sink face measures first so every fault
//! precedes the first handoff).
//! Everything that is not group framing rides verbatim: scalar
//! records, LEN records whole, and LEN payloads stay opaque — a
//! group hidden inside one is the payload author's domain, and
//! this machine never guesses messageness.
//!
//! Output closure: the output always re-ingests under the
//! groupless dialect's `Tolerant` standard, and it closes under
//! the groupless *language* exactly — no group code survives at
//! any depth the grouped walk reaches (group bodies are in-band;
//! LEN payloads are not walked and ride as the opaque declarations
//! they already were). It closes under `CanonicalMinimal` exactly
//! when every padded source word either was group framing or sat
//! inside some group's body: converted framing is authored
//! minimal, every other word rides verbatim — and a converted
//! group's body becomes a LEN payload, an opaque declaration the
//! canonical judge does not enter, so padding that survives there
//! is the payload author's domain exactly as for any LEN payload.
//! Only a padded word outside every group stays visible and
//! breaks closure. A job run under the `CanonicalMinimal` input
//! standard admits no padded word anywhere it walks, so its
//! output closes canonically by construction.
//!
//! The depth bound is spent as the walk's group-nesting bound
//! (converted from the declared [`DepthLimit`] without loss):
//! conversion never commits a LEN descent, so group nesting is the
//! only recursion the input can spend.
//!
//! Coordinates: write · buffered · static · grouped (input) · groupless (output) · Standard (value-level) · borrowed · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::convert::groupless::Converter;
//! use protobuf_edit::{DepthLimit, Standard};
//!
//! // varint f1=150 · group f2 { varint f3=1 }
//! let msg = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
//! let converter = Converter::new(Standard::Tolerant, DepthLimit::REFERENCE);
//! let (out, stats) = converter.convert(&msg).unwrap();
//! // varint f1=150 · LEN f2 [ varint f3=1 ]
//! assert_eq!(out, [0x08, 0x96, 0x01, 0x12, 0x02, 0x18, 0x01]);
//! assert_eq!(stats.converted(), 1);
//!
//! // Group-free input is the identity: conversion has nothing to
//! // re-frame, and everything else rides verbatim.
//! let flat = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let (out, stats) = converter.convert(&flat).unwrap();
//! assert_eq!(out, flat);
//! assert_eq!(stats.converted(), 0);
//! ```

use alloc::vec::Vec;
use core::convert::Infallible;

use crate::admission::{self, admitted_u32, usize_of};
use crate::cursor::GroupDepth;
use crate::cursor::grouped::{Cursor, EntryKind};
use crate::varint::{emit64, encoded_len32, write64_at};
use crate::wire::PayloadLen;
use crate::wire::groupless::{RecordKind, head_word};
use crate::{DepthLimit, FaultClass, Standard};

/// The conversion job's configuration, judged once — jobs
/// downstream reuse it across documents.
///
/// No conversion policy exists in this direction: group
/// punctuation identifies every source group by syntax, so the
/// whole population converts and a policy parameter would be dead
/// configuration.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct Converter {
    standard: Standard,
    limit: DepthLimit,
}

impl Converter {
    /// Declares the input acceptance standard and the group-nesting
    /// bound.
    ///
    /// The standard picks a monomorphized walk instance once per
    /// job — both passes run it — so a tolerant job pays no width
    /// comparison and a canonical one refuses every non-minimal
    /// varint width in the input it walks (opaque LEN interiors
    /// stay the caller's declaration).
    #[inline]
    pub const fn new(standard: Standard, limit: DepthLimit) -> Self {
        Self { standard, limit }
    }

    /// Converts `input` into fresh bytes, with the job receipt.
    ///
    /// # Errors
    ///
    /// [`Fault`] when the input refuses admission, the walk hits
    /// unlawful wire (broken group pairing included), group nesting
    /// leaves the declared budget, or the output outgrows the
    /// admission cap (the cap and the LEN class share one bound,
    /// so an over-class converted body surfaces as the output
    /// refusal on the Vec faces). No bytes are produced on `Err`.
    #[inline]
    pub fn convert(&self, input: &[u8]) -> Result<(Vec<u8>, Stats), Fault> {
        let mut out = Vec::new();
        let stats = self.convert_into(input, &mut out)?;
        Ok((out, stats))
    }

    /// Converts `input`, appending to `out` — the reuse face.
    ///
    /// Emission is online: appends land past the entry length as
    /// the walk goes, and a faulted job truncates back to it, so
    /// existing content is untouched either way (capacity may have
    /// grown on `Err`).
    ///
    /// # Errors
    ///
    /// As [`convert`](Self::convert); `out` is untouched on `Err`.
    ///
    /// # Panics
    ///
    /// If appending the output to `out` would overflow the
    /// vector's capacity bounds (an extreme the caller can reach on
    /// 32-bit targets with a near-full buffer).
    pub fn convert_into(&self, input: &[u8], out: &mut Vec<u8>) -> Result<Stats, Fault> {
        match self.standard {
            Standard::Tolerant => run_into::<false>(input, self.limit, out),
            Standard::CanonicalMinimal => run_into::<true>(input, self.limit, out),
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
    /// As [`convert`](Self::convert), except an over-class
    /// converted body is its own refusal here ([`Growth`]): the
    /// measuring pass judges bodies ahead of the cap. The sink
    /// receives nothing on `Err`.
    ///
    /// # Panics
    ///
    /// If the crate's own two passes disagree on what they measured
    /// and what they handed over — a library bug caught at the
    /// seam.
    ///
    /// [`Growth`]: FaultKind::Growth
    pub fn convert_sink(&self, input: &[u8], mut sink: impl FnMut(&[u8])) -> Result<Stats, Fault> {
        match self.standard {
            Standard::Tolerant => run_sink::<false>(input, self.limit, &mut sink),
            Standard::CanonicalMinimal => run_sink::<true>(input, self.limit, &mut sink),
        }
    }
}

/// The job receipt.
///
/// A zero count is the identity signal: nothing was re-framed, and
/// the output is byte-identical to the input.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stats {
    converted: u32,
}

impl Stats {
    /// Groups re-framed as LEN records (nested groups count one
    /// each).
    #[inline]
    #[must_use]
    pub const fn converted(self) -> u32 {
        self.converted
    }
}

/// A job refusal: where, and which contract broke.
///
/// Coordinates are whole-input byte offsets — this machine never
/// descends a LEN, so the walk's coordinates are the document's
/// own and no crossing chain exists to quote.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u32,
    kind: FaultKind,
}

impl Fault {
    /// Whole-input byte coordinate.
    #[inline]
    #[must_use]
    pub const fn at(self) -> u32 {
        self.at
    }

    /// The broken contract.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> FaultKind {
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
    /// The walk hit unlawful wire — the grouped traversal
    /// vocabulary, summarized (group pairing breaches included).
    Wire(WireBreach),
    /// A converted group body outgrew the LEN class: the source
    /// group carried no length prefix, and the one this conversion
    /// must author has no lawful spelling. `at` names the group's
    /// open tag.
    Growth {
        /// The body's computed length.
        len: u64,
    },
    /// The converted output outgrew the admission cap.
    Output {
        /// The output's computed length at the refusal.
        len: u64,
    },
    /// The input itself exceeds the admission cap.
    Oversize,
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Wire(breach) => write!(f, "{breach}"),
            Self::Growth { len } => {
                write!(f, "a converted group body of {len} bytes outgrew the LEN class")
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
            Self::Growth { .. } | Self::Output { .. } | Self::Oversize => None,
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
    /// Group framing broke (orphaned, mismatched, or unclosed).
    Grouping,
    /// Group nesting past the declared [`DepthLimit`] budget.
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// canonical standard's judgment (the tolerant standard never
    /// judges widths).
    NonMinimal,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget; [`NonMinimal`] is the
    /// canonical standard); the grouped input language is the
    /// format's whole code alphabet, so no capability member
    /// exists.
    ///
    /// [`Depth`]: Self::Depth
    /// [`NonMinimal`]: Self::NonMinimal
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Varint | Self::Tag | Self::Truncated | Self::Grouping => FaultClass::Grammar,
            Self::Depth | Self::NonMinimal => FaultClass::Policy,
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
            Self::Grouping => "broken group framing",
            Self::Depth => "group nesting past the declared depth budget",
            Self::NonMinimal => "a varint word wider than its minimal encoding",
        })
    }
}

impl core::error::Error for WireBreach {}

#[cold]
const fn breach(kind: crate::cursor::grouped::FaultKind) -> WireBreach {
    use crate::cursor::grouped::FaultKind as T;
    match kind {
        T::Read { .. } => WireBreach::Varint,
        T::FieldZero { .. } | T::Unassigned { .. } => WireBreach::Tag,
        T::FixedTruncated { .. } | T::LenOverrun { .. } => WireBreach::Truncated,
        T::GroupEndMismatch { .. } | T::GroupEndOrphan { .. } | T::GroupUnclosed { .. } => {
            WireBreach::Grouping
        }
        T::DepthExceeded { .. } => WireBreach::Depth,
        T::NonMinimalTag | T::NonMinimalLen { .. } | T::NonMinimalValue { .. } => {
            WireBreach::NonMinimal
        }
    }
}

// ─── the body ledger (private contract type) ───

/// Pre-order body lengths, one per converted group: claimed at the
/// group's enter, filled at its verified exit (the measuring pass),
/// consumed in the same pre-order by the emit pass — which needs
/// each length at the *enter*, where the LEN prefix it authors must
/// land. Every group converts, so no dirty/clean split exists; a
/// filled slot is a class-judged length (the fill site judged
/// Growth first).
struct Ledger {
    slots: Vec<u32>,
}

impl Ledger {
    const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Pass one: claims the next pre-order slot at a group's enter.
    fn claim(&mut self) -> usize {
        self.slots.push(0);
        self.slots.len() - 1
    }

    /// Pass one: fills a claimed slot at the group's exit. `body`
    /// is in the LEN class — the caller judged Growth first.
    fn fill(&mut self, slot: usize, body: u32) {
        debug_assert!(slot < self.slots.len(), "fills follow claims");
        // SAFETY: `slot` was minted by `claim` as `len - 1`, and
        // the ledger only ever grows — every claimed index stays in
        // bounds.
        *unsafe { self.slots.get_unchecked_mut(slot) } = body;
    }

    /// The number of slots claimed so far.
    const fn claimed(&self) -> usize {
        self.slots.len()
    }

    /// Pass two: consumes the slot at the cursor (the emit pass
    /// replays pass one's enters in the same pre-order).
    fn read(&self, cursor: usize) -> u32 {
        debug_assert!(cursor < self.slots.len(), "the cursor replays pass one's claims");
        // SAFETY: the cursor advances by one per group enter, and
        // the emit pass replays the measuring pass's walk over the
        // same bytes and limit — it enters exactly the groups pass
        // one claimed slots for, in the same order, so every read
        // lands on a claimed index. (`finish` additionally
        // witnesses full consumption after the fact; the bound does
        // not rest on it.)
        *unsafe { self.slots.get_unchecked(cursor) }
    }
}

// ─── the sealed plan (private contract type) ───

/// The measuring pass's sealed verdict and the replay identity that
/// produced it: the exact input and limit whose walk claimed the
/// ledger, the measured output size (judged into the LEN class at
/// construction), and the tally. A `Plan` in hand is the emit
/// pass's whole admission — the emit walk draws input and limit
/// from the plan itself, so the replay the ledger reads rely on
/// cannot be driven with mismatched arguments.
struct Plan<'i> {
    input: &'i [u8],
    limit: DepthLimit,
    stats: Stats,
    ledger: Ledger,
    /// The measured output size, in class.
    total: u32,
}

impl<'i> Plan<'i> {
    /// Seals the measurement; `None` when the converted root
    /// outgrows the LEN class.
    fn new(
        input: &'i [u8],
        limit: DepthLimit,
        stats: Stats,
        ledger: Ledger,
        total: u64,
    ) -> Option<Self> {
        if total > u64::from(PayloadLen::MAX.as_inner()) {
            return None;
        }
        // In class: judged above.
        #[allow(clippy::as_conversions, reason = "class-judged total narrows losslessly")]
        Some(Self { input, limit, stats, ledger, total: total as u32 })
    }
}

// ─── the walk skeleton (private) ───

/// One pass's consumer. `verbatim` spans are absolute and
/// contiguous-mergeable; `exit` reports an over-class body as
/// `Err(len)` for the walker to coordinate.
///
/// `Refusal` is the pass's fault channel: the measuring pass
/// carries the document [`Fault`] out; the emit pass sits past the
/// fault barrier, so its channel is uninhabited and every walker
/// fault site is dead in its instantiation.
trait Sink {
    type Refusal;
    fn refuse(&self, fault: Fault) -> Self::Refusal;
    fn verbatim(&mut self, from: u32, to: u32);
    /// A group opened at `head`: the converted record's LEN head
    /// (minimal tag, minimal prefix over the measured body) lands
    /// here. `word` is the LEN head word of the group's field in
    /// the output dialect.
    fn enter(&mut self, word: u32, head: u32);
    /// The matching end tag: the body settles. The end tag's bytes
    /// emit nothing — the LEN framing already carries the extent.
    /// An over-class body reports `Err((open head, length))` for
    /// the walker to coordinate.
    fn exit(&mut self) -> Result<(), (u32, u64)>;
}

/// Runs one pass. Every fault funnels through the sink's refusal
/// channel: the measuring pass carries [`Fault`] out; the emit pass
/// replays the identical judgment sequence over the same bytes, so
/// its fault sites are dead by construction and its channel is
/// uninhabited. One instance per acceptance standard: the walk
/// rides the traversal cursor's engine split, so tolerant jobs pay
/// no minimality test and both passes of a canonical job judge
/// identically.
fn walk<S: Sink, const MINIMAL: bool>(
    input: &[u8],
    limit: DepthLimit,
    sink: &mut S,
) -> Result<Stats, S::Refusal> {
    let mut stats = Stats::default();
    let Ok(mut cursor) = Cursor::over(input, GroupDepth::from(limit)) else {
        return Err(sink.refuse(Fault { at: 0, kind: FaultKind::Oversize }));
    };
    let mut head = 0u32;
    loop {
        let Some(item) = cursor.step::<MINIMAL>() else {
            return Ok(stats);
        };
        let entry = match item {
            Ok(entry) => entry,
            Err(fault) => {
                return Err(sink.refuse(Fault {
                    at: fault.at(),
                    kind: FaultKind::Wire(breach(fault.kind())),
                }));
            }
        };
        let end = cursor.pos();
        match entry.kind() {
            EntryKind::GroupEnter => {
                stats.converted += 1;
                sink.enter(head_word(entry.field(), RecordKind::Len), head);
            }
            EntryKind::GroupExit => {
                if let Err((open, len)) = sink.exit() {
                    return Err(sink.refuse(Fault { at: open, kind: FaultKind::Growth { len } }));
                }
            }
            EntryKind::Varint(_) | EntryKind::I32(_) | EntryKind::I64(_) | EntryKind::Len(_) => {
                sink.verbatim(head, end);
            }
        }
        head = end;
    }
}

// ─── the sink face, pass one: measure ───

/// One open group's accumulator: the running body total, the LEN
/// head word the conversion authors for it, its open-tag offset
/// (the Growth fault coordinate), and the pre-order slot it fills
/// at exit.
struct Frame {
    total: u64,
    word: u32,
    head: u32,
    slot: usize,
}

struct Measure {
    /// Open-group accumulators over the root's, root first — never
    /// empty: the root frame lives from construction to
    /// `root_total`.
    frames: Vec<Frame>,
    ledger: Ledger,
}

impl Measure {
    fn new() -> Self {
        Self {
            frames: alloc::vec![Frame { total: 0, word: 0, head: 0, slot: 0 }],
            ledger: Ledger::new(),
        }
    }

    fn root_total(&self) -> u64 {
        debug_assert!(self.frames.len() == 1, "all groups exited");
        // SAFETY: the root frame is pushed at construction and only
        // `exit` pops — paired with an `enter` push by the walk,
        // whose pairing the cursor verified — so index zero is
        // always occupied.
        unsafe { self.frames.get_unchecked(0) }.total
    }

    /// The current accumulator.
    fn top(&mut self) -> &mut Frame {
        debug_assert!(!self.frames.is_empty(), "the root frame is never popped");
        // SAFETY: the root frame is pushed at construction and only
        // `exit` pops — paired with an `enter` push by the walk.
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

    fn enter(&mut self, word: u32, head: u32) {
        let slot = self.ledger.claim();
        self.frames.push(Frame { total: 0, word, head, slot });
    }

    fn exit(&mut self) -> Result<(), (u32, u64)> {
        debug_assert!(self.frames.len() >= 2, "enter/exit pairing");
        // SAFETY: paired with the `enter` push — the cursor
        // verified the group pairing before delivering this exit,
        // so a frame above the permanent root exists.
        let done = unsafe { self.frames.pop().unwrap_unchecked() };
        if done.total > u64::from(PayloadLen::MAX.as_inner()) {
            return Err((done.head, done.total));
        }
        // In class: judged above.
        #[allow(clippy::as_conversions, reason = "the body total was judged against the LEN class")]
        let body = done.total as u32;
        self.ledger.fill(done.slot, body);
        self.top().total +=
            u64::from(encoded_len32(done.word)) + u64::from(encoded_len32(body)) + done.total;
        Ok(())
    }
}

// ─── the Vec faces: one pass, met-width holes, immediate settle ───

/// The Vec faces' one-pass emitter: walk and emission fused. A
/// group's prefix is unknowable at its open, so the open authors
/// the minimal tag plus a one-byte hole (the met width — bodies
/// under 128 bytes need exactly it), and the matching exit
/// settles: a met hole backpatches in place, a wider need shifts
/// the settled interior right by the difference and re-authors the
/// prefix minimally. Nested groups settle bottom-up (LIFO), and
/// every still-open hole sits below any settling one, so a shift
/// never moves an unsettled hole. All output coordinates are
/// relative to `mark` (the caller buffer's length at entry), kept
/// inside the admission cap by the eager append judgment — so they
/// live in `u32` no matter how full the caller's buffer already
/// is — and a faulted job truncates back to `mark`, leaving the
/// caller's prefix byte-untouched.
struct Online<'i, 'o> {
    input: &'i [u8],
    out: &'o mut Vec<u8>,
    mark: usize,
    /// Pending verbatim run, absolute half-open.
    run: Option<(u32, u32)>,
    /// Open groups' unsettled prefixes, LIFO: the output-relative
    /// position just past each one-byte hole.
    holes: Vec<u32>,
}

impl Online<'_, '_> {
    /// The job's output length so far (inside the cap, so `u32`).
    const fn rel(&self) -> u32 {
        admitted_u32(self.out.len() - self.mark)
    }

    /// The eager cap judgment: every append (and every settle
    /// growth) passes here first.
    fn admit(&self, grow: u64) -> Result<(), u64> {
        let total = u64::from(self.rel()) + grow;
        #[allow(clippy::as_conversions, reason = "MAX is far below u64")]
        if total > admission::MAX as u64 {
            return Err(total);
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), u64> {
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        self.admit(bytes.len() as u64)?;
        self.out.extend_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), u64> {
        if let Some((from, to)) = self.run.take() {
            // SAFETY: runs are record extents the cursor delivered,
            // merged only when contiguous: from <= to <= input len.
            let src = unsafe { self.input.get_unchecked(usize_of(from)..usize_of(to)) };
            self.append(src)?;
        }
        Ok(())
    }

    fn verbatim(&mut self, from: u32, to: u32) {
        match &mut self.run {
            Some((_, tail)) => {
                debug_assert!(*tail == from, "runs break only at group events, which flush");
                *tail = to;
            }
            None => self.run = Some((from, to)),
        }
    }

    /// A group opens: the authored LEN tag rides with its one-byte
    /// prefix hole in one append, and the hole's position joins
    /// the settle stack.
    fn enter(&mut self, word: u32) -> Result<(), u64> {
        self.flush()?;
        let width = encoded_len32(word);
        // Any 32-bit word's width (≤ 5) plus the zeroed hole byte.
        let mut window = [0u8; 6];
        let emitted = emit64(u64::from(word), &mut window);
        debug_assert!(emitted == width, "the authored tag is minimal");
        self.append(&window[..usize_of(width) + 1])?;
        self.holes.push(self.rel());
        Ok(())
    }

    /// The matching end tag: the body settles into its prefix. The
    /// end tag's bytes emit nothing — the LEN framing carries the
    /// extent.
    fn exit(&mut self) -> Result<(), u64> {
        self.flush()?;
        debug_assert!(!self.holes.is_empty(), "exits pair with enters");
        // SAFETY: the cursor verified the group pairing before
        // delivering this exit, and every enter pushed a hole.
        let interior_at = unsafe { self.holes.pop().unwrap_unchecked() };
        let new_len = self.rel() - interior_at;
        // In class by the eager append judgment: the cap is
        // `PayloadLen::MAX`, and a body is a subset of the job's
        // admitted bytes.
        debug_assert!(new_len <= PayloadLen::MAX.as_inner());
        let need = encoded_len32(new_len);
        let hole_abs = self.mark + usize_of(interior_at) - 1;
        if need == 1 {
            // The met width stands: the prefix backpatches in
            // place.
            #[allow(clippy::as_conversions, reason = "a width-1 varint is its value's own byte")]
            {
                self.out[hole_abs] = new_len as u8;
            }
            return Ok(());
        }
        // The body crossed a width boundary: the settled interior
        // shifts right by the difference and the prefix re-authors.
        let grow = usize_of(need - 1);
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        self.admit(grow as u64)?;
        let len_now = self.out.len();
        self.out.reserve(grow);
        let interior_abs = hole_abs + 1;
        let count = len_now - interior_abs;
        // SAFETY: `reserve` provided `grow` spare bytes past
        // `len_now`, so the shifted interior lands inside the
        // allocation; the prefix write covers `need` bytes at
        // `hole_abs`, ending at `interior_abs + grow` — every byte
        // under the published length is initialized before
        // `set_len`.
        unsafe {
            let ptr = self.out.as_mut_ptr();
            core::ptr::copy(ptr.add(interior_abs), ptr.add(interior_abs + grow), count);
            write64_at(ptr.add(hole_abs), u64::from(new_len), need);
            self.out.set_len(len_now + grow);
        }
        Ok(())
    }

    /// The job's last append; group closure is the cursor's own
    /// pairing verdict, so a clean walk end leaves no open hole.
    fn finish(&mut self) -> Result<(), u64> {
        self.flush()?;
        debug_assert!(self.holes.is_empty(), "the cursor verified every group closed");
        Ok(())
    }
}

// ─── pass two: the sink face's emit ───

/// The sink face's emit pass: the sealed plan's replay, handing
/// borrowed slices to the caller's sink. Verbatim runs coalesce
/// and pass through as windows of the input; authored framing
/// rides a ten-byte stack window. The invariant pins (ledger
/// consumption, pairing closure, measured total) are judged once
/// per job at `finish`.
struct SinkEmit<'i, 's, F> {
    input: &'i [u8],
    sink: &'s mut F,
    /// Pending verbatim run, absolute half-open.
    run: Option<(u32, u32)>,
    ledger: Ledger,
    cursor: usize,
    /// Bytes handed to the sink so far.
    written: u64,
    /// The plan's in-class total (the finish pin).
    total: u64,
    /// Logical bytes emitted (runs included before flushing).
    logical: u64,
    /// Per-group pin: (logical at enter, expected body).
    open: Vec<(u64, u32)>,
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

    /// The invariant pins (ledger consumption, pairing closure,
    /// measured total), judged once per job.
    fn finish(mut self) {
        self.flush();
        assert!(self.cursor == self.ledger.claimed(), "every ledger slot consumed exactly once");
        assert!(self.open.is_empty(), "every converted group closed");
        assert!(self.written == self.total, "pass two handed the sink the measured total");
    }
}

impl<F: FnMut(&[u8])> Sink for SinkEmit<'_, '_, F> {
    type Refusal = Infallible;

    #[inline]
    fn refuse(&self, _fault: Fault) -> Infallible {
        // SAFETY: the emit pass replays the measuring pass over the
        // same bytes and limit, so a job the measuring pass
        // accepted reaches no fault site here.
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

    fn enter(&mut self, word: u32, _head: u32) {
        self.flush();
        let body = self.ledger.read(self.cursor);
        self.cursor += 1;
        let tag_width = encoded_len32(word);
        let prefix_width = encoded_len32(body);
        self.logical += u64::from(tag_width) + u64::from(prefix_width);
        self.hand_varint(u64::from(word), tag_width);
        self.hand_varint(u64::from(body), prefix_width);
        self.open.push((self.logical, body));
    }

    fn exit(&mut self) -> Result<(), (u32, u64)> {
        debug_assert!(!self.open.is_empty(), "enters are pinned");
        // SAFETY: `enter` pushes a pin for every group, and the
        // cursor verified the pairing before delivering this exit.
        let (mark, expected) = unsafe { self.open.pop().unwrap_unchecked() };
        assert!(
            self.logical - mark == u64::from(expected),
            "a converted body emitted exactly its ledger length"
        );
        Ok(())
    }
}

// ─── the job fronts ───

/// The output-cap refusal (`at` 0: the job's size is a whole-job
/// judgment, not an event's).
#[cold]
const fn output_fault(len: u64) -> Fault {
    Fault { at: 0, kind: FaultKind::Output { len } }
}

/// One buffered job, one instance per acceptance standard: a
/// single walk, every group's prefix settled online at its exit.
/// Faults abort mid-emission; the truncation back to the entry
/// length restores the caller's buffer observably untouched
/// (bytes and length; capacity may have grown).
fn run_into<const MINIMAL: bool>(
    input: &[u8],
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<Stats, Fault> {
    let mark = out.len();
    match drive::<MINIMAL>(input, limit, out, mark) {
        Ok(stats) => Ok(stats),
        Err(fault) => {
            out.truncate(mark);
            Err(fault)
        }
    }
}

/// [`run_into`]'s fused walk: cursor entries feed the online
/// emitter directly, so the fault sites the sink face discharges
/// by replay stay live here and carry the document [`Fault`] out.
fn drive<const MINIMAL: bool>(
    input: &[u8],
    limit: DepthLimit,
    out: &mut Vec<u8>,
    mark: usize,
) -> Result<Stats, Fault> {
    let mut stats = Stats::default();
    let Ok(mut cursor) = Cursor::over(input, GroupDepth::from(limit)) else {
        return Err(Fault { at: 0, kind: FaultKind::Oversize });
    };
    let mut emit = Online { input, out, mark, run: None, holes: Vec::new() };
    let mut head = 0u32;
    loop {
        let Some(item) = cursor.step::<MINIMAL>() else {
            emit.finish().map_err(output_fault)?;
            return Ok(stats);
        };
        let entry = match item {
            Ok(entry) => entry,
            Err(fault) => {
                return Err(Fault { at: fault.at(), kind: FaultKind::Wire(breach(fault.kind())) });
            }
        };
        let end = cursor.pos();
        match entry.kind() {
            EntryKind::GroupEnter => {
                stats.converted += 1;
                emit.enter(head_word(entry.field(), RecordKind::Len)).map_err(output_fault)?;
            }
            EntryKind::GroupExit => emit.exit().map_err(output_fault)?,
            EntryKind::Varint(_) | EntryKind::I32(_) | EntryKind::I64(_) | EntryKind::Len(_) => {
                emit.verbatim(head, end);
            }
        }
        head = end;
    }
}

/// One sink job, one instance per acceptance standard: the
/// measuring pass walks and judges, the emit pass replays the same
/// instance over the sealed plan.
fn run_sink<const MINIMAL: bool>(
    input: &[u8],
    limit: DepthLimit,
    sink: &mut impl FnMut(&[u8]),
) -> Result<Stats, Fault> {
    let mut measure = Measure::new();
    let stats = walk::<_, MINIMAL>(input, limit, &mut measure)?;
    let total = measure.root_total();
    let Some(plan) = Plan::new(input, limit, stats, measure.ledger, total) else {
        return Err(Fault { at: 0, kind: FaultKind::Output { len: total } });
    };
    let Plan { input, limit, stats, ledger, total } = plan;
    let mut emit = SinkEmit {
        input,
        sink,
        run: None,
        ledger,
        cursor: 0,
        written: 0,
        total: u64::from(total),
        logical: 0,
        open: Vec::new(),
    };
    // The emit pass is past the fault barrier: its refusal channel
    // is uninhabited, so the pattern is irrefutable.
    let Ok(repeated) = walk::<_, MINIMAL>(input, limit, &mut emit);
    debug_assert!(repeated == stats, "the emit pass repeats the measuring pass's judgments");
    emit.finish();
    Ok(stats)
}

#[cfg(test)]
mod tests;
