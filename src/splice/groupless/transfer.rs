//! The groupless source-transfer splicer: one ask per record with
//! the source-aware verdicts, over the four-code wire language.
//!
//! The walk is the host's ask walk with [`SourceRule`] in place of
//! the plain rule: `Current` verdicts behave exactly as the host's,
//! transfer verdicts relocate the current occurrence's original
//! bytes per the module contract at [`super::super::transfer`].
//! All three faces run the sealed-overlay custody discipline —
//! decisions first, emission after the whole walk succeeded — so
//! on `Err` nothing has been appended or handed over, and the
//! emitter carries no rule reference.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::super::transfer::{OnlineGap, Overlay, SourceLen, SourceScalar};
use super::super::{Len, Scalar};
use super::{FaultKind, WireBreach, breach};
use crate::admission;
use crate::path::Crossing;
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::wire::FieldNumber;
use crate::wire::groupless::{RecordKind, head_word};
use crate::{DepthLimit, Standard};

/// The consumer's per-record source-aware verdicts, one ask per
/// wire kind; every default is the identity (`Current` of the
/// host's identity verdict), so a rule implements only what it
/// touches.
///
/// `at` is the record head's whole-input byte offset. Answer
/// slices inside `Current` verdicts are borrowed only for the ask,
/// exactly as at the host trait.
pub trait SourceRule {
    /// A varint record completed.
    fn on_varint(&mut self, at: u32, field: FieldNumber, value: u64) -> SourceScalar<'_, u64> {
        let _ = (at, field, value);
        SourceScalar::Current(Scalar::Keep)
    }

    /// An I32 record completed (little-endian bits).
    fn on_i32(&mut self, at: u32, field: FieldNumber, bits: u32) -> SourceScalar<'_, u32> {
        let _ = (at, field, bits);
        SourceScalar::Current(Scalar::Keep)
    }

    /// An I64 record completed (little-endian bits).
    fn on_i64(&mut self, at: u32, field: FieldNumber, bits: u64) -> SourceScalar<'_, u64> {
        let _ = (at, field, bits);
        SourceScalar::Current(Scalar::Keep)
    }

    /// A LEN record completed, payload in hand.
    fn on_len<'a>(&'a mut self, at: u32, field: FieldNumber, payload: &'a [u8]) -> SourceLen<'a> {
        let _ = (at, field, payload);
        SourceLen::Current(Len::Pass)
    }
}

/// A transfer job refusal: where, the committed containers crossed
/// to reach it, and which contract broke.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransferFault {
    at: u32,
    trail: Box<[Crossing]>,
    kind: TransferFaultKind,
}

impl TransferFault {
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
    pub const fn kind(&self) -> TransferFaultKind {
        self.kind
    }
}

impl core::fmt::Display for TransferFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.at)
    }
}

impl core::error::Error for TransferFault {}

/// The transfer job's refusal classes: the host job's own, plus
/// the online anchor law.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferFaultKind {
    /// The host's own refusal classes, unchanged — wire breaches,
    /// answer growth, the caps, the depth budget.
    Job(FaultKind),
    /// A tail destination named a level past the open chain: the
    /// requested ancestor is not an open committed container (zero
    /// never names a level).
    AnchorUnavailable {
        /// The level the verdict requested.
        levels: u16,
    },
}

impl core::fmt::Display for TransferFaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Job(kind) => write!(f, "{kind}"),
            Self::AnchorUnavailable { levels } => {
                write!(f, "no open container {levels} levels up")
            }
        }
    }
}

// ─── the walk front (private) ───

/// One committed LEN layer of the walk's input side.
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
fn trail(layers: &[Layer<'_>]) -> Box<[Crossing]> {
    layers.iter().filter_map(|l| l.crossing).collect()
}

#[cold]
fn overcap(at: u32, layers: &[Layer<'_>], len: u64) -> TransferFault {
    TransferFault {
        at,
        trail: trail(layers),
        kind: TransferFaultKind::Job(FaultKind::Output { len }),
    }
}

#[cold]
fn no_anchor(at: u32, layers: &[Layer<'_>], levels: u16) -> TransferFault {
    TransferFault {
        at,
        trail: trail(layers),
        kind: TransferFaultKind::AnchorUnavailable { levels },
    }
}

/// Judges an answer slice against the LEN class at the ask.
fn judge_answer(bytes: &[u8], at: u32, layers: &[Layer<'_>]) -> Result<(), TransferFault> {
    if bytes.len() > admission::MAX {
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        return Err(TransferFault {
            at,
            trail: trail(layers),
            kind: TransferFaultKind::Job(FaultKind::Growth { len: bytes.len() as u64 }),
        });
    }
    Ok(())
}

/// A tail gap's claim level: `None` for the immediate placements,
/// the level index for the tail forms, or the refused level count.
fn resolve_gap(gap: OnlineGap, over: &Overlay<'_>) -> Result<Option<usize>, u16> {
    match gap {
        OnlineGap::BeforeCurrent | OnlineGap::AfterCurrent => Ok(None),
        OnlineGap::TailOfCurrentLayer => Ok(Some(over.levels() - 1)),
        OnlineGap::TailOfAncestor(levels) => {
            let chain = over.levels();
            if levels == 0 || usize::from(levels) >= chain {
                return Err(levels);
            }
            Ok(Some(chain - 1 - usize::from(levels)))
        }
    }
}

/// One whole-record transfer at its ask: `move` suppresses the
/// origin ride. Immediate placements collapse — a record emitted
/// at its own boundary with a suppressed origin is the span once.
fn transfer_record(
    over: &mut Overlay<'_>,
    gap: OnlineGap,
    head: u32,
    end: u32,
    moved: bool,
    layers: &[Layer<'_>],
) -> Result<(), TransferFault> {
    let level = match resolve_gap(gap, over) {
        Ok(level) => level,
        Err(levels) => return Err(no_anchor(head, layers, levels)),
    };
    let outcome = match (level, gap, moved) {
        (None, OnlineGap::BeforeCurrent, false) => {
            over.edit_record(head, end).and_then(|()| over.verbatim(head, end))
        }
        (None, OnlineGap::AfterCurrent, false) => {
            over.verbatim(head, end).and_then(|()| over.edit_record(head, end))
        }
        (None, _, true) => over.edit_record(head, end),
        (Some(level), _, moved) => over.claim_span(head, end).and_then(|span| {
            over.claim_record(level, span);
            if moved {
                over.dirty();
                Ok(())
            } else {
                over.verbatim(head, end)
            }
        }),
        // `resolve_gap` returns `None` exactly for the two
        // immediate placements.
        (None, _, false) => unreachable!("immediate gaps are the two current placements"),
    };
    outcome.map_err(|len| overcap(head, layers, len))
}

/// One payload transfer at its ask: authored minimal framing over
/// the source interior; `move` suppresses the whole record.
#[allow(clippy::too_many_arguments, reason = "one ask event over the walk's live coordinates")]
fn transfer_payload(
    over: &mut Overlay<'_>,
    gap: OnlineGap,
    field: FieldNumber,
    head: u32,
    payload_start: u32,
    end: u32,
    moved: bool,
    layers: &[Layer<'_>],
) -> Result<(), TransferFault> {
    let level = match resolve_gap(gap, over) {
        Ok(level) => level,
        Err(levels) => return Err(no_anchor(head, layers, levels)),
    };
    let word = head_word(field, RecordKind::Len);
    let outcome = match (level, gap, moved) {
        (None, OnlineGap::BeforeCurrent, false) => {
            over.edit_payload(word, payload_start, end).and_then(|()| over.verbatim(head, end))
        }
        (None, OnlineGap::AfterCurrent, false) => {
            over.verbatim(head, end).and_then(|()| over.edit_payload(word, payload_start, end))
        }
        (None, _, true) => over.edit_payload(word, payload_start, end),
        (Some(level), _, moved) => {
            over.claim_payload(level, word, payload_start, end).and_then(|()| {
                if moved {
                    over.dirty();
                    Ok(())
                } else {
                    over.verbatim(head, end)
                }
            })
        }
        (None, _, false) => unreachable!("immediate gaps are the two current placements"),
    };
    outcome.map_err(|len| overcap(head, layers, len))
}

/// Runs one job: the source-aware ask walk over `input`, decisions
/// into the sealed overlay. One instance per acceptance standard.
fn walk<R: SourceRule, const MINIMAL: bool>(
    input: &[u8],
    rule: &mut R,
    limit: DepthLimit,
    over: &mut Overlay<'_>,
) -> Result<(), TransferFault> {
    let Ok(root) = Cursor::over(input) else {
        return Err(TransferFault {
            at: 0,
            trail: Box::new([]),
            kind: TransferFaultKind::Job(FaultKind::Oversize),
        });
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
            // Layer exhausted cleanly: `pos` is the payload's
            // announced length.
            let old_len = layer.cursor.pos();
            if layers.len() == 1 {
                return Ok(());
            }
            // SAFETY: length checked above — at least two layers.
            let done = unsafe { layers.pop().unwrap_unchecked() };
            if let Err(len) = over.close(old_len) {
                let at = done.crossing.map_or(0, Crossing::at);
                return Err(overcap(at, &layers, len));
            }
            continue;
        };
        let entry = match item {
            Ok(entry) => entry,
            Err(fault) => {
                return Err(TransferFault {
                    at: base + fault.at(),
                    trail: trail(&layers),
                    kind: TransferFaultKind::Job(FaultKind::Wire(breach(fault.kind()))),
                });
            }
        };
        let end = base + layer.cursor.pos();
        let tag_end = head + u32::from(layer.cursor.tag_width());
        let field = entry.field();

        let flow = match entry.kind() {
            EntryKind::Varint(value) => match rule.on_varint(head, field, value) {
                SourceScalar::Current(Scalar::Keep) => over.verbatim(head, end),
                SourceScalar::Current(Scalar::Rewrite(word)) => {
                    over.verbatim(head, tag_end).and_then(|()| over.author_varint(word))
                }
                SourceScalar::Current(Scalar::Drop) => {
                    over.dirty();
                    Ok(())
                }
                SourceScalar::Current(Scalar::Insert(bytes)) => {
                    judge_answer(bytes, head, &layers)?;
                    over.author(bytes).and_then(|()| over.verbatim(head, end))
                }
                SourceScalar::CopyRecord(gap) => {
                    transfer_record(over, gap, head, end, false, &layers)?;
                    Ok(())
                }
                SourceScalar::MoveRecord(gap) => {
                    transfer_record(over, gap, head, end, true, &layers)?;
                    Ok(())
                }
            },
            EntryKind::I32(_) | EntryKind::I64(_) => {
                let verdict = match entry.kind() {
                    EntryKind::I32(bits) => {
                        rule.on_i32(head, field, bits).map(super::super::back::Word::from)
                    }
                    EntryKind::I64(bits) => {
                        rule.on_i64(head, field, bits).map(super::super::back::Word::from)
                    }
                    // The enclosing arm admits exactly the two
                    // fixed kinds.
                    _ => unreachable!("fixed-arm entry"),
                };
                match verdict {
                    SourceScalar::Current(Scalar::Keep) => over.verbatim(head, end),
                    SourceScalar::Current(Scalar::Rewrite(word)) => {
                        over.verbatim(head, tag_end).and_then(|()| over.author(word.bytes()))
                    }
                    SourceScalar::Current(Scalar::Drop) => {
                        over.dirty();
                        Ok(())
                    }
                    SourceScalar::Current(Scalar::Insert(bytes)) => {
                        judge_answer(bytes, head, &layers)?;
                        over.author(bytes).and_then(|()| over.verbatim(head, end))
                    }
                    SourceScalar::CopyRecord(gap) => {
                        transfer_record(over, gap, head, end, false, &layers)?;
                        Ok(())
                    }
                    SourceScalar::MoveRecord(gap) => {
                        transfer_record(over, gap, head, end, true, &layers)?;
                        Ok(())
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
                    SourceLen::Current(Len::Pass) => over.verbatim(head, end),
                    SourceLen::Current(Len::Commit { tail }) => {
                        if remaining == 0 {
                            return Err(TransferFault {
                                at: head,
                                trail: trail(&layers),
                                kind: TransferFaultKind::Job(FaultKind::Wire(WireBreach::Depth)),
                            });
                        }
                        if let Some(bytes) = tail {
                            judge_answer(bytes, head, &layers)?;
                        }
                        let opened = over.commit(head, tag_end, payload_start, tail);
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
                    SourceLen::Current(Len::Replace(bytes)) => {
                        judge_answer(bytes, head, &layers)?;
                        #[allow(
                            clippy::as_conversions,
                            reason = "the slice was just judged inside the LEN class"
                        )]
                        over.verbatim(head, tag_end)
                            .and_then(|()| over.author_varint(bytes.len() as u64))
                            .and_then(|()| over.author(bytes))
                    }
                    SourceLen::Current(Len::Drop) => {
                        over.dirty();
                        Ok(())
                    }
                    SourceLen::Current(Len::Insert(bytes)) => {
                        judge_answer(bytes, head, &layers)?;
                        over.author(bytes).and_then(|()| over.verbatim(head, end))
                    }
                    SourceLen::CopyRecord(gap) => {
                        transfer_record(over, gap, head, end, false, &layers)?;
                        Ok(())
                    }
                    SourceLen::MoveRecord(gap) => {
                        transfer_record(over, gap, head, end, true, &layers)?;
                        Ok(())
                    }
                    SourceLen::CopyPayload { to, field: dest } => {
                        transfer_payload(over, to, dest, head, payload_start, end, false, &layers)?;
                        Ok(())
                    }
                    SourceLen::MovePayload { to, field: dest } => {
                        transfer_payload(over, to, dest, head, payload_start, end, true, &layers)?;
                        Ok(())
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

/// Splices `input` under the source-aware `rule` into fresh bytes.
///
/// # Errors
///
/// [`TransferFault`]: the host's own refusals
/// ([`TransferFaultKind::Job`] — admission, unlawful wire under
/// the declared standard, a commit past the depth budget, answer
/// growth, the output cap) and the online anchor law
/// ([`TransferFaultKind::AnchorUnavailable`]). No bytes are
/// produced on `Err`; the rule's state is spent for the asks
/// already fired.
///
/// # Examples
///
/// ```
/// use protobuf_edit::splice::groupless::{SourceRule, splice_sources};
/// use protobuf_edit::splice::{OnlineGap, SourceScalar};
/// use protobuf_edit::wire::FieldNumber;
/// use protobuf_edit::{DepthLimit, Standard};
///
/// // Move every field-9 record to the document tail, byte-exactly
/// // (the padded value spelling rides along).
/// struct Demote;
/// impl SourceRule for Demote {
///     fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> SourceScalar<'_, u64> {
///         if field.as_inner() == 9 {
///             SourceScalar::MoveRecord(OnlineGap::TailOfCurrentLayer)
///         } else {
///             SourceScalar::Current(protobuf_edit::splice::Scalar::Keep)
///         }
///     }
/// }
///
/// // varint f9=150 padded · varint f1=1
/// let msg = [0x48, 0x96, 0x81, 0x00, 0x08, 0x01];
/// let out = splice_sources(&msg, &mut Demote, Standard::Tolerant, DepthLimit::REFERENCE)
///     .unwrap();
/// assert_eq!(out, [0x08, 0x01, 0x48, 0x96, 0x81, 0x00]);
/// ```
#[inline]
pub fn splice_sources<R: SourceRule>(
    input: &[u8],
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
) -> Result<Vec<u8>, TransferFault> {
    let mut out = Vec::new();
    splice_sources_into(input, rule, standard, limit, &mut out)?;
    Ok(out)
}

/// Splices `input` under the source-aware `rule`, appending to
/// `out` — the reuse face.
///
/// The sealed overlay is the custody: decisions complete before
/// the first append, so `out` is untouched on `Err` — nothing to
/// truncate.
///
/// # Errors
///
/// As [`splice_sources`]; `out` is untouched on `Err`.
///
/// # Panics
///
/// If the crate's own fold hands a total different from the walk's
/// account — a library bug caught at the seam.
pub fn splice_sources_into<R: SourceRule>(
    input: &[u8],
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<(), TransferFault> {
    let mut over = Overlay::new(input);
    match standard {
        Standard::Tolerant => walk::<R, false>(input, rule, limit, &mut over)?,
        Standard::CanonicalMinimal => walk::<R, true>(input, rule, limit, &mut over)?,
    }
    over.root_close();
    over.fold(&mut |bytes| out.extend_from_slice(bytes));
    Ok(())
}

/// Splices `input` under the source-aware `rule`, handing borrowed
/// windows to `sink` — the zero-buffer face.
///
/// The decision walk is the preflight; only after the whole walk
/// succeeded does the fold hand a single byte over, and the fold
/// carries no rule reference — a second ask is unspellable.
///
/// # Errors
///
/// As [`splice_sources`]; on `Err` the sink was handed nothing.
///
/// # Panics
///
/// As [`splice_sources_into`].
pub fn splice_sources_sink<R: SourceRule, F: FnMut(&[u8])>(
    input: &[u8],
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
    mut sink: F,
) -> Result<(), TransferFault> {
    let mut over = Overlay::new(input);
    match standard {
        Standard::Tolerant => walk::<R, false>(input, rule, limit, &mut over)?,
        Standard::CanonicalMinimal => walk::<R, true>(input, rule, limit, &mut over)?,
    }
    over.root_close();
    over.fold(&mut sink);
    Ok(())
}

#[cfg(test)]
mod tests;
