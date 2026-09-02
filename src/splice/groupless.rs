//! The groupless splicer: the four-code wire language, group codes
//! refused as a capability judgment.
//!
//! One ask per delivered record drives everything ([`Rule`]); the
//! two emission back-ends sit behind that one walk. The Vec faces
//! ride each committed prefix at its met width and settle at the
//! close — nothing on unchanged length, an in-place backpatch on
//! unchanged width, one memmove of the just-closed interior on a
//! width change (the output length is the cascade accumulator: a
//! child's move shifts the end the parent reads, so no length
//! propagates explicitly). The sink face builds a sealed
//! source-ordered overlay during the walk and hands windows only
//! after the whole walk succeeded — `Err` means the sink saw
//! nothing.
//!
//! Coordinates: write · buffered · online · groupless · Standard (value-level) · borrowed · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::splice::groupless::{Rule, splice};
//! use protobuf_edit::splice::{Len, Scalar};
//! use protobuf_edit::wire::FieldNumber;
//! use protobuf_edit::{DepthLimit, Standard};
//!
//! // Deep growth: replace the two-byte payload inside the
//! // committed container; the container's length prefix follows.
//! struct Grow;
//! impl Rule for Grow {
//!     fn on_len(&mut self, _at: u32, field: FieldNumber, _payload: &[u8]) -> Len<'_> {
//!         match field.as_inner() {
//!             1 => Len::Commit { tail: None },
//!             _ => Len::Replace(b"grown"),
//!         }
//!     }
//! }
//!
//! // LEN f1 { LEN f2 "hi" }
//! let msg = [0x0A, 0x04, 0x12, 0x02, 0x68, 0x69];
//! let out = splice(&msg, &mut Grow, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(out, [0x0A, 0x07, 0x12, 0x05, b'g', b'r', b'o', b'w', b'n']);
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::back::{Back, Emit, Plan, Word};
use super::{Len, Scalar};
use crate::admission;
use crate::path::Crossing;
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::wire::FieldNumber;
use crate::{DepthLimit, FaultClass, Standard};

/// The consumer's per-record verdicts, one ask method per wire
/// kind — an ill-typed verdict is unspellable, so no mismatch
/// fault class exists.
///
/// Every method defaults to the identity verdict; a rule
/// implements only the kinds it edits.
///
/// `at` is the record head's whole-input byte offset. Answer
/// slices ([`Scalar::Insert`], [`Len::Replace`], [`Len::Insert`],
/// a commit's tail) are borrowed only for the ask: the machine
/// consumes them before the next delivery.
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
}

/// A job refusal: where, the committed containers crossed to reach
/// it, and which contract broke.
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
    /// first; empty at top level).
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

/// The groupless splicer's refusal classes.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// A committed descent (or the top level) hit unlawful wire —
    /// the groupless traversal vocabulary, summarized (group codes
    /// arrive as its capability refusal).
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
    /// A [`Len::Commit`] verdict past the caller's declared
    /// [`DepthLimit`] budget (a `Pass`, `Replace`, `Drop`, or
    /// `Insert` at the wall is lawful — only entering costs).
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// declared [`Standard::CanonicalMinimal`]'s judgment (a
    /// tolerant job never judges widths).
    NonMinimal,
    /// A group code appeared — outside this dialect's language
    /// (the grouped dialect handles such documents).
    GroupCode,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget, [`NonMinimal`] the declared
    /// [`Standard`]).
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
            Self::Depth => "a commit past the declared depth budget",
            Self::NonMinimal => "a varint word wider than its minimal encoding",
            Self::GroupCode => "a group code outside this dialect",
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

// ─── the walk front (private) ───

/// One committed LEN layer of the walk's input side (the back-ends
/// keep their own settle state in lockstep).
struct Layer<'i> {
    cursor: Cursor<'i>,
    /// Absolute base of this layer's payload.
    base: u32,
    /// The crossing that opened this layer (`None` at the root).
    crossing: Option<Crossing>,
    /// LEN commits still allowed below this layer.
    remaining: u16,
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
    let Ok(root) = Cursor::over(input) else {
        return Err(Fault { at: 0, trail: Box::new([]), kind: FaultKind::Oversize });
    };
    let mut layers = Vec::new();
    layers.push(Layer { cursor: root, base: 0, crossing: None, remaining: limit.as_inner() });

    loop {
        // SAFETY: the root layer is pushed above and the only pop
        // sits behind the `len == 1` return below, so the stack is
        // never empty here.
        let layer = unsafe { layers.last_mut().unwrap_unchecked() };
        let base = layer.base;
        let head = base + layer.cursor.pos();
        let remaining = layer.remaining;
        let Some(item) = layer.cursor.step::<MINIMAL>() else {
            // Layer exhausted cleanly: at exhaustion the cursor
            // stands past its last delivered record, so `pos` is
            // the payload's announced length.
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
                        // spends the budget.
                        if remaining == 0 {
                            return Err(Fault {
                                at: head,
                                trail: trail(&layers),
                                kind: FaultKind::Wire(WireBreach::Depth),
                            });
                        }
                        if let Some(bytes) = tail {
                            judge_answer(bytes, head, &layers)?;
                        }
                        let opened = back.commit(head, tag_end, payload_start, tail);
                        if opened.is_ok() {
                            layers.push(Layer {
                                cursor: Cursor::within(payload),
                                base: payload_start,
                                crossing: Some(Crossing::new(field, head)),
                                remaining: remaining - 1,
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
/// `standard` (group codes included — the capability refusal), a
/// [`Len::Commit`] would pass the `limit` budget, an answer slice
/// leaves the LEN class, or the output outgrows the admission cap.
/// No bytes are produced on `Err`; the rule's state is spent for
/// the asks already fired.
///
/// # Examples
///
/// ```
/// use protobuf_edit::splice::Scalar;
/// use protobuf_edit::splice::groupless::{Rule, splice};
/// use protobuf_edit::wire::FieldNumber;
/// use protobuf_edit::{DepthLimit, Standard};
///
/// // Drop every top-level field 2 record.
/// struct DropF2;
/// impl Rule for DropF2 {
///     fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
///         if field.as_inner() == 2 { Scalar::Drop } else { Scalar::Keep }
///     }
/// }
///
/// let msg = [0x08, 0x01, 0x10, 0x02, 0x18, 0x03];
/// let out = splice(&msg, &mut DropF2, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(out, [0x08, 0x01, 0x18, 0x03]);
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
#[cfg(feature = "transfer-splice-groupless")]
pub mod transfer;

#[cfg(feature = "transfer-splice-groupless")]
pub use transfer::{
    SourceRule, TransferFault, TransferFaultKind, splice_sources, splice_sources_into,
    splice_sources_sink,
};

#[cfg(test)]
mod tests;
