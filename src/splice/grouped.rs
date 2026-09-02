//! The grouped splicer: the full six-code wire language, group
//! framing verified by the traversal cursor.
//!
//! One ask per delivered record drives everything ([`Rule`]); the
//! two emission back-ends sit behind that one walk, shared with the
//! groupless dialect. Groups add one ask ([`Rule::on_group_enter`])
//! and one law: a group carries no length prefix, so group framing
//! never cascades — a committed group's edits flow straight into
//! the enclosing LEN accumulator (or the top level), and pure-group
//! chains settle nothing. Group exits are punctuation: their bytes
//! ride with their group's verdict, no ask fires.
//!
//! Coordinates: write · buffered · online · grouped · Standard (value-level) · borrowed · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::splice::grouped::{Group, Rule, splice};
//! use protobuf_edit::wire::FieldNumber;
//! use protobuf_edit::{DepthLimit, Standard};
//!
//! // Drop the group wholesale; the sibling scalar rides.
//! struct DropGroups;
//! impl Rule for DropGroups {
//!     fn on_group_enter(&mut self, _at: u32, _field: FieldNumber) -> Group<'_> {
//!         Group::Drop
//!     }
//! }
//!
//! // group f1 { varint f2 = 150 }, varint f3 = 5
//! let msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x05];
//! let out = splice(&msg, &mut DropGroups, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(out, [0x18, 0x05]);
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::back::{Back, Emit, Plan, Word};
use super::{Len, Scalar};
use crate::admission;
use crate::path::Crossing;
use crate::cursor::GroupDepth;
use crate::cursor::grouped::{Cursor, EntryKind};
use crate::wire::FieldNumber;
use crate::{DepthLimit, FaultClass, Standard};

/// A group-enter verdict.
///
/// The wire hands no payload at an enter (groups are only
/// walkable), so the vocabulary is the scalar one with entry in
/// place of rewriting — whole-group replacement composes as
/// [`Insert`] + [`Drop`] across two asks.
///
/// [`Insert`]: Self::Insert
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Group<'a> {
    /// The whole group rides verbatim: framing walked (the cursor
    /// still verifies pairing and depth), asks silenced.
    Pass,
    /// Enter the group and ask per interior record. The framing
    /// tags ride verbatim — a group has no length prefix, so
    /// nothing settles at its exit.
    Commit,
    /// The whole group vanishes: framing walked, asks silenced,
    /// nothing emitted.
    Drop,
    /// The bytes land before the group, which then rides verbatim
    /// (as [`Pass`]) — one terminal verdict, no re-ask. The bytes
    /// are the caller's declaration: accounted, never parsed.
    ///
    /// [`Pass`]: Self::Pass
    Insert(&'a [u8]),
}

/// The consumer's per-record verdicts, one ask method per wire
/// kind — an ill-typed verdict is unspellable, so no mismatch
/// fault class exists.
///
/// Every method defaults to the identity verdict; a rule
/// implements only the kinds it edits.
///
/// `at` is the record head's whole-input byte offset. Answer
/// slices ([`Scalar::Insert`], [`Len::Replace`], [`Len::Insert`],
/// [`Group::Insert`], a commit's tail) are borrowed only for the
/// ask: the machine consumes them before the next delivery.
pub trait Rule {
    /// A varint record completed.
    fn on_varint(&mut self, at: u32, field: FieldNumber, value: u64) -> Scalar<'_, u64> {
        let _ = (at, field, value);
        Scalar::Keep
    }

    /// An I32 record completed (little-endian bits).
    fn on_i32(&mut self, at: u32, field: FieldNumber, bits: u32) -> Scalar<'_, u32> {
        let _ = (at, field, bits);
        Scalar::Keep
    }

    /// An I64 record completed (little-endian bits).
    fn on_i64(&mut self, at: u32, field: FieldNumber, bits: u64) -> Scalar<'_, u64> {
        let _ = (at, field, bits);
        Scalar::Keep
    }

    /// A LEN record completed, payload in hand — the buffered
    /// privilege: a transformation is [`Len::Replace`] computed
    /// from the slice. The verdict may borrow the handed payload
    /// itself (echoes and subslices are free), the rule's own
    /// state, or both.
    fn on_len<'a>(&'a mut self, at: u32, field: FieldNumber, payload: &'a [u8]) -> Len<'a> {
        let _ = (at, field, payload);
        Len::Pass
    }

    /// A group opened. No payload rides the ask (groups are only
    /// walkable); the matching exit is punctuation — its bytes
    /// follow this verdict, no second ask.
    fn on_group_enter(&mut self, at: u32, field: FieldNumber) -> Group<'_> {
        let _ = (at, field);
        Group::Pass
    }
}

/// A job refusal: where, the committed LEN containers crossed to
/// reach it, and which contract broke.
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

    /// Committed LEN containers crossed to reach the fault
    /// (outermost first; empty at top level). Groups cross without
    /// a length obligation and mint no crossing.
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

/// The grouped splicer's refusal classes.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// A committed descent (or the top level) hit unlawful wire —
    /// the grouped traversal vocabulary, summarized.
    Wire(WireBreach),
    /// An answer slice (a replacement, an insert, or a commit's
    /// tail) outside the LEN class — judged at the ask, before any
    /// byte of it is copied. A committed interior itself cannot
    /// outgrow the class: the output cap is judged at every append
    /// and every interior is a sub-range of the output.
    Growth {
        /// The refused slice's length.
        len: u64,
    },
    /// The spliced output outgrew the admission cap — judged at
    /// each append, so every retained output coordinate stays in
    /// the class.
    Output {
        /// The output length the append would have reached.
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
                write!(f, "an answer slice of {len} bytes outgrew the LEN class")
            }
            Self::Output { len } => {
                write!(f, "the spliced output of {len} bytes outgrew the admission cap")
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

/// The wire breach, summarized by who acts on it: a splice
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
    /// Container nesting (groups and [`Len::Commit`] crossings
    /// spend one account) exceeded the caller's declared
    /// [`DepthLimit`] budget. A `Pass`, `Replace`, `Drop`, or
    /// `Insert` at the wall is lawful — only entering costs.
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// declared [`Standard::CanonicalMinimal`]'s judgment (a
    /// tolerant job never judges widths).
    NonMinimal,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget, [`NonMinimal`] the declared
    /// [`Standard`]); this dialect has no capability member (its
    /// language is the format's whole code alphabet).
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
            Self::Depth => "nesting past the declared depth budget",
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

// The 64-bit layout is pinned exactly; narrower pointer widths
// are bounded by the same ceiling.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Fault>() == 40);
#[cfg(not(target_pointer_width = "64"))]
const _: () = assert!(core::mem::size_of::<Fault>() <= 40);

// ─── the walk front (private) ───

/// One committed LEN layer of the walk's input side (the back-ends
/// keep their own settle state in lockstep). Groups never push a
/// layer: they have no length obligation, so a committed group is
/// just a budget mark ([`Layer::group_depth`]) on the layer it
/// opened in.
struct Layer<'i> {
    cursor: Cursor<'i>,
    /// Absolute base of this layer's payload.
    base: u32,
    /// The crossing that opened this layer (`None` at the root).
    crossing: Option<Crossing>,
    /// Container crossings still allowed below this layer; groups
    /// and LEN commits spend from this one account.
    remaining: u16,
    /// Groups the walk has entered inside this layer, open now.
    group_depth: u16,
}

/// The promise chain: one crossing per committed LEN layer.
/// Allocates, but only on the fault path — every caller is a
/// refusal.
fn trail(layers: &[Layer<'_>]) -> Box<[Crossing]> {
    layers.iter().filter_map(|l| l.crossing).collect()
}

#[cold]
fn overcap(at: u32, layers: &[Layer<'_>], len: u64) -> Fault {
    Fault { at, trail: trail(layers), kind: FaultKind::Output { len } }
}

#[cold]
fn depth_wall(at: u32, layers: &[Layer<'_>]) -> Fault {
    Fault { at, trail: trail(layers), kind: FaultKind::Wire(WireBreach::Depth) }
}

/// Judges an answer slice against the LEN class at the ask —
/// before any byte of it is copied.
fn judge_answer(bytes: &[u8], at: u32, layers: &[Layer<'_>]) -> Result<(), Fault> {
    if bytes.len() > admission::MAX {
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        return Err(Fault {
            at,
            trail: trail(layers),
            kind: FaultKind::Growth { len: bytes.len() as u64 },
        });
    }
    Ok(())
}

/// Runs one job: the ask walk over `input`, events handed to the
/// back-end. One instance per acceptance standard: the walk rides
/// the traversal cursor's engine split, so a tolerant job pays no
/// minimality test.
fn walk<R: Rule, B: Back, const MINIMAL: bool>(
    input: &[u8],
    rule: &mut R,
    limit: DepthLimit,
    back: &mut B,
) -> Result<(), Fault> {
    let Ok(root) = Cursor::over(input, GroupDepth::from(limit)) else {
        return Err(Fault { at: 0, trail: Box::new([]), kind: FaultKind::Oversize });
    };
    let mut layers = Vec::new();
    layers.push(Layer {
        cursor: root,
        base: 0,
        crossing: None,
        remaining: limit.as_inner(),
        group_depth: 0,
    });
    // Depth of the group currently riding whole under a `Pass` (or
    // an `Insert`'s verbatim ride): framing walked, asks silenced,
    // every byte verbatim. The cursor still verifies pairing and
    // its own depth bound. A group closes inside the layer that
    // opened it (the cursor faults otherwise), so one walk-global
    // counter suffices.
    let mut ride: u32 = 0;
    // Depth of the group currently vanishing under a `Drop`: the
    // same silenced walk, nothing emitted.
    let mut suppress: u32 = 0;

    loop {
        // SAFETY: the root layer is pushed above and the only pop
        // sits behind the `len == 1` return below, so the stack is
        // never empty here.
        let layer = unsafe { layers.last_mut().unwrap_unchecked() };
        let base = layer.base;
        let head = base + layer.cursor.pos();
        let remaining = layer.remaining;
        let group_depth = layer.group_depth;
        let Some(item) = layer.cursor.step::<MINIMAL>() else {
            // Layer exhausted cleanly (the cursor faults on an
            // unclosed group, so exhaustion means balance): at
            // exhaustion the cursor stands past its last delivered
            // record, so `pos` is the payload's announced length.
            let old_len = layer.cursor.pos();
            if layers.len() == 1 {
                return Ok(());
            }
            // SAFETY: length checked above — at least two layers.
            let done = unsafe { layers.pop().unwrap_unchecked() };
            if let Err(len) = back.close(old_len) {
                // A non-root layer's crossing is minted at its
                // commit; the settle's coordinate is that head.
                let at = done.crossing.map_or(0, Crossing::at);
                return Err(overcap(at, &layers, len));
            }
            continue;
        };
        let entry = match item {
            Ok(entry) => entry,
            Err(fault) => {
                return Err(Fault {
                    at: base + fault.at(),
                    trail: trail(&layers),
                    kind: FaultKind::Wire(breach(fault.kind())),
                });
            }
        };
        let end = base + layer.cursor.pos();

        // A silenced group walk: no asks, counters track nesting.
        // The two modes are exclusive (both are entered from a
        // group ask, and neither fires asks inside).
        if suppress > 0 {
            match entry.kind() {
                EntryKind::GroupEnter => suppress += 1,
                EntryKind::GroupExit => suppress -= 1,
                _ => {}
            }
            continue;
        }
        if ride > 0 {
            match entry.kind() {
                EntryKind::GroupEnter => ride += 1,
                EntryKind::GroupExit => ride -= 1,
                _ => {}
            }
            if let Err(len) = back.verbatim(head, end) {
                return Err(overcap(head, &layers, len));
            }
            continue;
        }

        let tag_end = head + u32::from(layer.cursor.tag_width());
        let field = entry.field();

        let flow = match entry.kind() {
            EntryKind::Varint(value) => match rule.on_varint(head, field, value) {
                Scalar::Keep => back.verbatim(head, end),
                Scalar::Rewrite(word) => {
                    back.verbatim(head, tag_end).and_then(|()| back.author_varint(word))
                }
                Scalar::Drop => {
                    back.dirty();
                    Ok(())
                }
                Scalar::Insert(bytes) => {
                    judge_answer(bytes, head, &layers)?;
                    back.author(bytes).and_then(|()| back.verbatim(head, end))
                }
            },
            EntryKind::I32(_) | EntryKind::I64(_) => {
                let verdict = match entry.kind() {
                    EntryKind::I32(bits) => rule.on_i32(head, field, bits).map(Word::from),
                    EntryKind::I64(bits) => rule.on_i64(head, field, bits).map(Word::from),
                    // The enclosing arm admits exactly the two
                    // fixed kinds.
                    _ => unreachable!("fixed-arm entry"),
                };
                match verdict {
                    Scalar::Keep => back.verbatim(head, end),
                    Scalar::Rewrite(word) => {
                        back.verbatim(head, tag_end).and_then(|()| back.author(word.bytes()))
                    }
                    Scalar::Drop => {
                        back.dirty();
                        Ok(())
                    }
                    Scalar::Insert(bytes) => {
                        judge_answer(bytes, head, &layers)?;
                        back.author(bytes).and_then(|()| back.verbatim(head, end))
                    }
                }
            }
            EntryKind::Len(payload) => {
                // The payload was delivered by the cursor from
                // admitted input.
                #[allow(
                    clippy::as_conversions,
                    reason = "cursor-delivered payload lies in the LEN class"
                )]
                let payload_start = end - payload.len() as u32;
                match rule.on_len(head, field, payload) {
                    Len::Pass => back.verbatim(head, end),
                    Len::Commit { tail } => {
                        // The ask fired; only the entering verdict
                        // spends the budget — one account for
                        // groups and LEN commits alike.
                        if group_depth == remaining {
                            return Err(depth_wall(head, &layers));
                        }
                        if let Some(bytes) = tail {
                            judge_answer(bytes, head, &layers)?;
                        }
                        let opened = back.commit(head, tag_end, payload_start, tail);
                        if opened.is_ok() {
                            layers.push(Layer {
                                cursor: Cursor::within(payload, GroupDepth::from(limit)),
                                base: payload_start,
                                crossing: Some(Crossing::new(field, head)),
                                remaining: remaining - group_depth - 1,
                                group_depth: 0,
                            });
                        }
                        opened
                    }
                    Len::Replace(bytes) => {
                        judge_answer(bytes, head, &layers)?;
                        #[allow(
                            clippy::as_conversions,
                            reason = "the slice was just judged inside the LEN class"
                        )]
                        back.verbatim(head, tag_end)
                            .and_then(|()| back.author_varint(bytes.len() as u64))
                            .and_then(|()| back.author(bytes))
                    }
                    Len::Drop => {
                        back.dirty();
                        Ok(())
                    }
                    Len::Insert(bytes) => {
                        judge_answer(bytes, head, &layers)?;
                        back.author(bytes).and_then(|()| back.verbatim(head, end))
                    }
                }
            }
            EntryKind::GroupEnter => match rule.on_group_enter(head, field) {
                Group::Pass => {
                    ride = 1;
                    back.verbatim(head, end)
                }
                Group::Commit => {
                    // Entering spends the shared budget; the
                    // framing tag itself rides verbatim (no
                    // prefix, nothing to settle at the exit).
                    if group_depth == remaining {
                        return Err(depth_wall(head, &layers));
                    }
                    layer.group_depth += 1;
                    back.verbatim(head, end)
                }
                Group::Drop => {
                    suppress = 1;
                    back.dirty();
                    Ok(())
                }
                Group::Insert(bytes) => {
                    judge_answer(bytes, head, &layers)?;
                    ride = 1;
                    back.author(bytes).and_then(|()| back.verbatim(head, end))
                }
            },
            EntryKind::GroupExit => {
                // Punctuation, not a record: the exit belongs to a
                // group the walk entered (a passed or dropped
                // group's exit was consumed by its silenced walk,
                // and the cursor refuses orphans), so no ask — the
                // end tag rides verbatim.
                debug_assert!(group_depth > 0, "an exit outside any entered group");
                layer.group_depth -= 1;
                back.verbatim(head, end)
            }
        };
        if let Err(len) = flow {
            return Err(overcap(head, &layers, len));
        }
    }
}

// ─── the public faces ───

/// Splices `input` under `rule` into fresh bytes.
///
/// # Errors
///
/// [`Fault`] when the input refuses admission, the walk (at any
/// committed depth) hits unlawful wire under the declared
/// `standard`, a [`Len::Commit`] or [`Group::Commit`] would pass
/// the `limit` budget, an answer slice leaves the LEN class, or
/// the output outgrows the admission cap. No bytes are produced on
/// `Err`; the rule's state is spent for the asks already fired.
///
/// # Examples
///
/// ```
/// use protobuf_edit::splice::Scalar;
/// use protobuf_edit::splice::grouped::{Group, Rule, splice};
/// use protobuf_edit::wire::FieldNumber;
/// use protobuf_edit::{DepthLimit, Standard};
///
/// // Enter the group, rewrite the varint inside it.
/// struct Bump;
/// impl Rule for Bump {
///     fn on_group_enter(&mut self, _at: u32, _field: FieldNumber) -> Group<'_> {
///         Group::Commit
///     }
///     fn on_varint(&mut self, _at: u32, _field: FieldNumber, value: u64) -> Scalar<'_, u64> {
///         Scalar::Rewrite(value + 1)
///     }
/// }
///
/// // group f1 { varint f2 = 2 }
/// let msg = [0x0B, 0x10, 0x02, 0x0C];
/// let out = splice(&msg, &mut Bump, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(out, [0x0B, 0x10, 0x03, 0x0C]);
/// ```
#[inline]
pub fn splice<R: Rule>(
    input: &[u8],
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    splice_into(input, rule, standard, limit, &mut out)?;
    Ok(out)
}

/// Splices `input` under `rule`, appending to `out` — the reuse
/// face.
///
/// Existing content is untouched; on `Err` the buffer truncates
/// back to its entry length, byte-identical — never poisoned, a
/// retry is lawful.
///
/// # Errors
///
/// As [`splice`]; `out` is restored on `Err`.
#[inline]
pub fn splice_into<R: Rule>(
    input: &[u8],
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<(), Fault> {
    let mark = out.len();
    let outcome = {
        let mut back = Emit::new(input, out);
        match standard {
            Standard::Tolerant => walk::<R, _, false>(input, rule, limit, &mut back),
            Standard::CanonicalMinimal => walk::<R, _, true>(input, rule, limit, &mut back),
        }
    };
    if let Err(fault) = outcome {
        out.truncate(mark);
        return Err(fault);
    }
    Ok(())
}

/// Splices `input` under `rule`, handing borrowed windows to
/// `sink` — the zero-buffer face.
///
/// The decision walk is the preflight: it builds a sealed
/// source-ordered overlay (source ranges, staged authored bytes,
/// prefix words settled at each close), and only after the whole
/// walk succeeded does the fold hand a single byte over. The fold
/// carries no rule reference — a second ask is unspellable.
///
/// # Errors
///
/// As [`splice`]; on `Err` the sink was handed nothing.
///
/// # Panics
///
/// If the crate's own fold hands a total different from the
/// walk's account — a library bug caught at the seam.
#[inline]
pub fn splice_sink<R: Rule, F: FnMut(&[u8])>(
    input: &[u8],
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
    mut sink: F,
) -> Result<(), Fault> {
    let mut plan = Plan::new(input);
    match standard {
        Standard::Tolerant => walk::<R, _, false>(input, rule, limit, &mut plan)?,
        Standard::CanonicalMinimal => walk::<R, _, true>(input, rule, limit, &mut plan)?,
    }
    plan.fold(&mut sink);
    Ok(())
}

// The source-transfer walk: the source-aware ask overlay, emitted
// only under the transfer capability.
#[cfg(feature = "transfer-splice-grouped")]
pub mod transfer;

#[cfg(feature = "transfer-splice-grouped")]
pub use transfer::{
    SourceGroup, SourceRule, TransferFault, TransferFaultKind, splice_sources, splice_sources_into,
    splice_sources_sink,
};

#[cfg(test)]
mod tests;
