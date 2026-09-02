//! The grouped source-transfer splicer: one ask per record with
//! the source-aware verdicts, over the full six-code wire
//! language.
//!
//! The groupless twin's discipline plus the group laws: a group
//! record-transfer designates the whole structural closure — open
//! tag through the verified end tag — so its span settles at the
//! matching exit while the sealed overlay holds its place (a copy
//! placed before the group emits a window whose end resolves at
//! that exit; nothing is handed until the whole walk succeeded).
//! Committed groups are open containers on the ancestor chain: a
//! tail claim to one settles at its exit, before the end tag's
//! emission. Groups have no detachable interior, so no payload
//! verdict exists in [`SourceGroup`].

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::super::transfer::{OnlineGap, Overlay, SourceLen, SourceScalar};
use super::super::{Len, Scalar};
use super::{FaultKind, Group, WireBreach, breach};
use crate::admission;
use crate::path::Crossing;
use crate::cursor::GroupDepth;
use crate::cursor::grouped::{Cursor, EntryKind};
use crate::wire::FieldNumber;
use crate::wire::grouped::{RecordKind, head_word};
use crate::{DepthLimit, Standard};

/// A group-enter source-aware verdict: the host's own verdict, or
/// a whole-closure transfer. No payload form exists — a group has
/// no detachable interior.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceGroup<'a> {
    /// The host verdict, unchanged.
    Current(Group<'a>),
    /// The whole closure's exact bytes also emit at the gap; the
    /// group rides at its origin, asks silenced (as the host's
    /// `Pass`).
    CopyRecord(OnlineGap),
    /// The whole closure's exact bytes emit at the gap alone; the
    /// origin emits nothing, asks silenced (as the host's `Drop`).
    MoveRecord(OnlineGap),
}

/// The consumer's per-record source-aware verdicts, one ask per
/// wire kind; every default is the identity (`Current` of the
/// host's identity verdict).
///
/// `at` is the record head's whole-input byte offset. Answer
/// slices inside `Current` verdicts are borrowed only for the ask.
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

    /// A group opened. No payload rides the ask; the matching exit
    /// is punctuation — a transfer verdict settles its span there.
    fn on_group_enter(&mut self, at: u32, field: FieldNumber) -> SourceGroup<'_> {
        let _ = (at, field);
        SourceGroup::Current(Group::Pass)
    }
}

/// A transfer job refusal: where, the committed LEN containers
/// crossed to reach it, and which contract broke.
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
    /// The host's own refusal classes, unchanged.
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

/// One committed LEN layer of the walk's input side. Groups never
/// push a layer: a committed group is a budget mark and one claim
/// level.
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

#[cold]
fn depth_wall(at: u32, layers: &[Layer<'_>]) -> TransferFault {
    TransferFault {
        at,
        trail: trail(layers),
        kind: TransferFaultKind::Job(FaultKind::Wire(WireBreach::Depth)),
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

/// One whole-record transfer at its ask (scalar and LEN spans are
/// complete at the ask; group closures ride the capture episodes
/// below instead).
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

/// One payload transfer at its ask.
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

/// How a group-closure capture episode completes at its verified
/// exit.
enum Capture {
    /// A pending emission op holds the place: resolve and account
    /// there.
    Emitted(u32),
    /// A tail claim holds the window: resolve, the settle
    /// accounts.
    Claimed(u32),
    /// Emit at the exit (the after-the-group copy placement).
    EditAfter(u32),
}

/// Runs one job: the source-aware ask walk over `input`, decisions
/// into the sealed overlay. One instance per acceptance standard.
#[expect(
    clippy::too_many_lines,
    reason = "the walk is one event loop, the host skeleton plus the transfer arms; splitting \
              it would scatter the ride/suppress discipline the captures lean on"
)]
fn walk<R: SourceRule, const MINIMAL: bool>(
    input: &[u8],
    rule: &mut R,
    limit: DepthLimit,
    over: &mut Overlay<'_>,
) -> Result<(), TransferFault> {
    let Ok(root) = Cursor::over(input, GroupDepth::from(limit)) else {
        return Err(TransferFault {
            at: 0,
            trail: Box::new([]),
            kind: TransferFaultKind::Job(FaultKind::Oversize),
        });
    };
    let mut layers = Vec::new();
    layers.push(Layer {
        cursor: root,
        base: 0,
        crossing: None,
        remaining: limit.as_inner(),
        group_depth: 0,
    });
    // Silenced group walks, as the host's: `ride` emits verbatim
    // (a passed or copied group), `suppress` emits nothing (a
    // dropped or moved group). A capture episode spans exactly one
    // silenced walk — asks are silenced inside, so episodes never
    // nest.
    let mut ride: u32 = 0;
    let mut suppress: u32 = 0;
    let mut capture: Option<Capture> = None;

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
            // unclosed group): `pos` is the payload's announced
            // length.
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

        // The silenced walks: no asks; captures complete at the
        // episode's matching exit.
        if suppress > 0 {
            match entry.kind() {
                EntryKind::GroupEnter => suppress += 1,
                EntryKind::GroupExit => {
                    suppress -= 1;
                    if suppress == 0
                        && let Err(fault) = settle_capture(over, &mut capture, end, &layers)
                    {
                        return Err(fault);
                    }
                }
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
            if let Err(len) = over.verbatim(head, end) {
                return Err(overcap(head, &layers, len));
            }
            if ride == 0
                && let Err(fault) = settle_capture(over, &mut capture, end, &layers)
            {
                return Err(fault);
            }
            continue;
        }

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
                        if group_depth == remaining {
                            return Err(depth_wall(head, &layers));
                        }
                        if let Some(bytes) = tail {
                            judge_answer(bytes, head, &layers)?;
                        }
                        let opened = over.commit(head, tag_end, payload_start, tail);
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
            EntryKind::GroupEnter => match rule.on_group_enter(head, field) {
                SourceGroup::Current(Group::Pass) => {
                    ride = 1;
                    over.verbatim(head, end)
                }
                SourceGroup::Current(Group::Commit) => {
                    // Entering spends the shared budget; the group
                    // becomes one claim level with no settle
                    // obligation.
                    if group_depth == remaining {
                        return Err(depth_wall(head, &layers));
                    }
                    layer.group_depth += 1;
                    over.group_open();
                    over.verbatim(head, end)
                }
                SourceGroup::Current(Group::Drop) => {
                    suppress = 1;
                    over.dirty();
                    Ok(())
                }
                SourceGroup::Current(Group::Insert(bytes)) => {
                    judge_answer(bytes, head, &layers)?;
                    ride = 1;
                    over.author(bytes).and_then(|()| over.verbatim(head, end))
                }
                SourceGroup::CopyRecord(gap) => {
                    debug_assert!(capture.is_none(), "capture episodes never nest");
                    let level = match resolve_gap(gap, over) {
                        Ok(level) => level,
                        Err(levels) => return Err(no_anchor(head, &layers, levels)),
                    };
                    ride = 1;
                    capture = Some(match (level, gap) {
                        (None, OnlineGap::BeforeCurrent) => {
                            let span = over.open_span(head);
                            over.edit_pending(span);
                            Capture::Emitted(span)
                        }
                        (None, _) => Capture::EditAfter(head),
                        (Some(level), _) => {
                            let span = over.open_span(head);
                            over.claim_record(level, span);
                            Capture::Claimed(span)
                        }
                    });
                    over.verbatim(head, end)
                }
                SourceGroup::MoveRecord(gap) => {
                    debug_assert!(capture.is_none(), "capture episodes never nest");
                    let level = match resolve_gap(gap, over) {
                        Ok(level) => level,
                        Err(levels) => return Err(no_anchor(head, &layers, levels)),
                    };
                    suppress = 1;
                    over.dirty();
                    capture = Some(match level {
                        // Both immediate placements collapse: the
                        // origin is suppressed, so the window
                        // emits once at the ask position.
                        None => {
                            let span = over.open_span(head);
                            over.edit_pending(span);
                            Capture::Emitted(span)
                        }
                        Some(level) => {
                            let span = over.open_span(head);
                            over.claim_record(level, span);
                            Capture::Claimed(span)
                        }
                    });
                    Ok(())
                }
            },
            EntryKind::GroupExit => {
                // Punctuation of a committed group: its tail
                // claims settle before the end tag's emission.
                debug_assert!(group_depth > 0, "an exit outside any entered group");
                layer.group_depth -= 1;
                over.group_close();
                over.verbatim(head, end)
            }
        };
        if let Err(len) = flow {
            return Err(overcap(head, &layers, len));
        }
    }
}

/// A capture episode completes at its verified exit: the closure
/// window resolves (and, for the after-placement, emits).
fn settle_capture(
    over: &mut Overlay<'_>,
    capture: &mut Option<Capture>,
    end: u32,
    layers: &[Layer<'_>],
) -> Result<(), TransferFault> {
    // Silenced walks without a capture exist (the host's own pass
    // and drop verdicts share the counters).
    let Some(done) = capture.take() else { return Ok(()) };
    let outcome = match done {
        Capture::Emitted(span) => over.close_span_emitted(span, end),
        Capture::Claimed(span) => over.close_span_claimed(span, end),
        Capture::EditAfter(head) => over.edit_record(head, end),
    };
    outcome.map_err(|len| overcap(end, layers, len))
}

// ─── the public faces ───

/// Splices `input` under the source-aware `rule` into fresh bytes.
///
/// # Errors
///
/// [`TransferFault`]: the host's own refusals
/// ([`TransferFaultKind::Job`]) and the online anchor law
/// ([`TransferFaultKind::AnchorUnavailable`]). No bytes are
/// produced on `Err`; the rule's state is spent for the asks
/// already fired.
///
/// # Examples
///
/// ```
/// use protobuf_edit::splice::grouped::{SourceGroup, SourceRule, splice_sources};
/// use protobuf_edit::splice::OnlineGap;
/// use protobuf_edit::wire::FieldNumber;
/// use protobuf_edit::{DepthLimit, Standard};
///
/// // Move the whole field-1 group — open tag through end tag —
/// // to the document tail.
/// struct Demote;
/// impl SourceRule for Demote {
///     fn on_group_enter(&mut self, _at: u32, field: FieldNumber) -> SourceGroup<'_> {
///         if field.as_inner() == 1 {
///             SourceGroup::MoveRecord(OnlineGap::TailOfCurrentLayer)
///         } else {
///             SourceGroup::Current(protobuf_edit::splice::grouped::Group::Pass)
///         }
///     }
/// }
///
/// // group f1 { varint f2=150 } · varint f3=5
/// let msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x05];
/// let out = splice_sources(&msg, &mut Demote, Standard::Tolerant, DepthLimit::REFERENCE)
///     .unwrap();
/// assert_eq!(out, [0x18, 0x05, 0x0B, 0x10, 0x96, 0x01, 0x0C]);
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
/// the first append, so `out` is untouched on `Err`.
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
