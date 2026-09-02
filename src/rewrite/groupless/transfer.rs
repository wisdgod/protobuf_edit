//! The groupless transfer engine: [`TransferRuleSet`] jobs over
//! the four-code wire language.
//!
//! Three walks over one skeleton: the designation walk binds every
//! source span, counts destination occurrences, and judges the
//! wire, ownership, and transfer laws; the plan then resolves the
//! pairing equations; the measuring and emitting walks replay the
//! same event sequence with the resolved plan in hand — the host's
//! own measuring and emitting sinks, its slot ledger, and its
//! reservation discipline, unchanged. Every fault precedes the
//! reservation and the first sink handoff, so the transactional
//! contract holds on all three faces. The plan stores coordinates
//! into the borrowed input; no source byte is staged.
//!
//! Two matchers walk in lockstep: the ordinary rules ride the
//! host's insert-admitting matcher (actions, inserts, conflicts —
//! its landed machinery), the transfer paths ride a second matcher
//! whose every terminal is a visit-all entry classified by id.
//! Neither the plain [`RuleSet`](super::super::RuleSet) nor
//! [`InsertRuleSet`](super::super::InsertRuleSet) door compiles any
//! of this: the transfer engine is this module, monomorphic over
//! the transfer plan type.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::super::transfer::{
    Apply, Disposition, Driver, Flow, GapEmission, Scout, TransferBreach, TransferHit,
    TransferPaths, TransferPlan, TransferRuleSet, TransferStats,
};
use super::super::{Gap, Sets, Value, action};
use super::{Down, Emit, Fault, FaultKind, Measure, Sink, SinkEmit, breach, fire_gap, fire_lane};
use crate::admission::usize_of;
use crate::path::{Crossing, Hits, Lane, Matcher};
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::wire::groupless::{RecordKind, head_word};
use crate::wire::{FieldNumber, PayloadLen};
use crate::{DepthLimit, Standard};

/// A transfer job refusal: where, the promise chain crossed to
/// reach it, and which contract broke.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TransferFault {
    at: u32,
    trail: Box<[Crossing]>,
    kind: TransferFaultKind,
}

impl TransferFault {
    /// Whole-input byte coordinate (zero for the plan-level
    /// pairing refusals, which quote rules rather than bytes).
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
/// the transfer laws.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransferFaultKind {
    /// The host's own refusal classes, unchanged — wire breaches,
    /// action conflicts, replacement kind mismatches, growth, and
    /// the caps.
    Job(FaultKind),
    /// A transfer law broke: a source or target kind, a pairing
    /// equation, or a contested occurrence.
    Transfer(TransferBreach),
}

impl core::fmt::Display for TransferFaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Job(kind) => write!(f, "{kind}"),
            Self::Transfer(breach) => write!(f, "{breach}"),
        }
    }
}

// ─── the walk (three instantiations per acceptance standard) ───

/// One committed LEN layer, the insert-admitting door's shape (the
/// ordinary tail flag rides every layer — transfer plans admit
/// insert rules).
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
    /// LEN crossings still allowed below this layer.
    remaining: u16,
    /// Ordinary `TailOf` insert rules hit the opening record.
    tails: bool,
}

/// The promise chain: one crossing per committed LEN layer.
fn trail(layers: &[Layer<'_>]) -> Box<[Crossing]> {
    layers.iter().filter_map(|l| l.crossing).collect()
}

#[cold]
fn conflict(at: u32, layers: &[Layer<'_>], first: u16, second: u16) -> Fault {
    Fault {
        at,
        trail: trail(layers),
        kind: FaultKind::Conflict { first: u32::from(first), second: u32::from(second) },
    }
}

/// The designation walk's sink: judges nothing and emits nothing —
/// the walk itself carries the wire and ordinary-rule judgments,
/// and the driver carries the transfer designations.
struct Designate;

impl Sink for Designate {
    type Refusal = Fault;

    fn refuse(&self, fault: Fault) -> Fault {
        fault
    }

    fn verbatim(&mut self, _from: u32, _to: u32) {}

    fn delete(&mut self) {}

    fn replace(&mut self, _tag_from: u32, _tag_to: u32, _value: Value<'_>) {}

    fn normalize(&mut self, _head: u32, _value: Value<'_>) {}

    fn descend(&mut self, _head: u32, _tag_end: u32, _ps: u32, _pe: u32) -> Down {
        Down::Walk
    }

    fn ascend(&mut self, _head: u32, _tag_end: u32, _ps: u32, _pe: u32) -> Result<(), u64> {
        Ok(())
    }
}

/// The transfer hits at `field` in the current layer, classified.
fn collect_hits<'r>(
    matcher: &Matcher<'r, TransferPaths<'r>>,
    paths: &TransferPaths<'r>,
    field: FieldNumber,
    hits: &mut Vec<TransferHit>,
) {
    hits.clear();
    if matcher.probe_gaps(field).is_empty() {
        return;
    }
    matcher.visit_gaps(field, Lane::Head, |id| hits.push(paths.classify(id)));
}

/// One resolved destination emission lands: a record span rides as
/// input bytes behind the dirty mark (the `delete` event is the
/// measuring sink's dirty bit and emits nothing), an authored
/// payload record rides the host's insert emission.
fn emit_transfer<S: Sink>(
    sink: &mut S,
    input: &[u8],
    tally: &mut TransferStats,
    emission: GapEmission,
) {
    match emission {
        GapEmission::Record { span, moved } => {
            sink.delete();
            sink.verbatim(span.from.as_inner(), span.to.as_inner());
            if moved {
                tally.records_moved += 1;
            } else {
                tally.records_copied += 1;
            }
        }
        GapEmission::Payload { field, span, moved } => {
            sink.insert(
                head_word(field, RecordKind::Len),
                Value::Len(&input[usize_of(span.from.as_inner())..usize_of(span.to.as_inner())]),
            );
            if moved {
                tally.payloads_moved += 1;
            } else {
                tally.payloads_copied += 1;
            }
        }
    }
}

/// Fires every anchor hit of `side`'s kind, in hit order (tables
/// in population order, rule order within each — the same-gap
/// emission order).
fn fire_gap_side<S: Sink, D: Driver>(
    paths: &TransferPaths<'_>,
    hits: &[TransferHit],
    side: Gap,
    sink: &mut S,
    input: &[u8],
    driver: &mut D,
    tally: &mut TransferStats,
) {
    for &hit in hits {
        if paths.gap_side(hit) == Some(side)
            && let Some(emission) = driver.gap_fired(hit)
        {
            emit_transfer(sink, input, tally, emission);
        }
    }
}

/// Runs one pass: the host's walk skeleton with the transfer
/// populations riding a second matcher in lockstep. The
/// designation pass judges (live driver breach channel); the two
/// apply passes replay the same event sequence over the resolved
/// plan (their breach channel is uninhabited), so every fault
/// precedes the reservation and the first handoff.
fn walk<'r, S: Sink, D: Driver, const MINIMAL: bool>(
    input: &[u8],
    set: &TransferRuleSet<'r>,
    limit: DepthLimit,
    sink: &mut S,
    driver: &mut D,
) -> Result<TransferStats, Flow<S::Refusal, D::Breach>> {
    let actions = set.actions();
    let mut action_m = Matcher::new(actions);
    let gapped = action_m.gapped();
    let paths = TransferPaths::new(set);
    let mut transfer_m = Matcher::new(paths);
    let mut tally = TransferStats::default();
    let mut hits: Vec<TransferHit> = Vec::new();
    let Ok(root) = Cursor::over(input) else {
        return Err(Flow::Host(sink.refuse(Fault {
            at: 0,
            trail: Box::new([]),
            kind: FaultKind::Oversize,
        })));
    };
    let mut layers: Vec<Layer<'_>> = Vec::new();
    layers.push(Layer {
        cursor: root,
        base: 0,
        crossing: None,
        head: 0,
        tag_end: 0,
        payload_start: 0,
        payload_end: 0,
        remaining: limit.as_inner(),
        tails: false,
    });
    // Root head gaps: ordinary inserts first, then the transfer
    // anchors, each in rule order.
    actions.root_inserts(Gap::HeadOf, |insert| fire_gap(sink, &mut tally.core, insert));
    paths.root_anchors(Gap::HeadOf, |hit| {
        if let Some(emission) = driver.gap_fired(hit) {
            emit_transfer(sink, input, &mut tally, emission);
        }
    });

    loop {
        // SAFETY: the root layer is pushed above and the only pop
        // sits behind the `len == 1` return below, so the stack is
        // never empty here.
        let layer = unsafe { layers.last_mut().unwrap_unchecked() };
        let base = layer.base;
        let head = base + layer.cursor.pos();
        let remaining = layer.remaining;
        let Some(item) = layer.cursor.step::<MINIMAL>() else {
            // Layer exhausted cleanly.
            if layers.len() == 1 {
                actions.root_inserts(Gap::TailOf, |insert| fire_gap(sink, &mut tally.core, insert));
                paths.root_anchors(Gap::TailOf, |hit| {
                    if let Some(emission) = driver.gap_fired(hit) {
                        emit_transfer(sink, input, &mut tally, emission);
                    }
                });
                return Ok(tally);
            }
            // SAFETY: length checked above — at least two layers.
            let done = unsafe { layers.pop().unwrap_unchecked() };
            action_m.exit();
            transfer_m.exit();
            // SAFETY: every non-root layer is pushed with its
            // crossing.
            let done_field = unsafe { done.crossing.unwrap_unchecked() }.field();
            // Tail gaps fire inside the exhausted interior: the
            // matchers just restored the parent layer, where the
            // opening record's entries live — ordinary inserts
            // first, then the transfer anchors.
            if done.tails {
                fire_lane(&action_m, &actions, done_field, Lane::Tail, sink, &mut tally.core);
            }
            collect_hits(&transfer_m, &paths, done_field, &mut hits);
            fire_gap_side(&paths, &hits, Gap::TailOf, sink, input, driver, &mut tally);
            if let Err(len) =
                sink.ascend(done.head, done.tag_end, done.payload_start, done.payload_end)
            {
                return Err(Flow::Host(sink.refuse(Fault {
                    at: done.head,
                    trail: trail(&layers),
                    kind: FaultKind::Growth { len },
                })));
            }
            continue;
        };
        let entry = match item {
            Ok(entry) => entry,
            Err(fault) => {
                return Err(Flow::Host(sink.refuse(Fault {
                    at: base + fault.at(),
                    trail: trail(&layers),
                    kind: FaultKind::Wire(breach(fault.kind())),
                })));
            }
        };
        let end = base + layer.cursor.pos();
        let tag_end = head + u32::from(layer.cursor.tag_width());
        let field = entry.field();

        match entry.kind() {
            EntryKind::Varint(_) | EntryKind::I32(_) | EntryKind::I64(_) => {
                let action_hits = action_m.probe_target(field);
                if let Hits::Conflict(first, second) = action_hits {
                    return Err(Flow::Host(sink.refuse(conflict(head, &layers, first, second))));
                }
                if gapped && let Some(rule) = action_m.first_interior_gap(field) {
                    return Err(Flow::Host(sink.refuse(Fault {
                        at: head,
                        trail: trail(&layers),
                        kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                    })));
                }
                collect_hits(&transfer_m, &paths, field, &mut hits);
                let owned = match action_hits {
                    Hits::One(rule) => Some(rule),
                    _ => None,
                };
                let disposition = match driver.scalar(head, end, &hits, owned) {
                    Ok(disposition) => disposition,
                    Err(refusal) => {
                        return Err(Flow::Transfer {
                            at: head,
                            trail: trail(&layers),
                            breach: refusal,
                        });
                    }
                };
                match disposition {
                    Disposition::Suppress => sink.delete(),
                    // Replace targets are LEN records by the kind
                    // law, judged in the designation pass.
                    Disposition::Replaced(_) => unreachable!("replace targets are LEN records"),
                    Disposition::Ordinary => match action_hits {
                        Hits::One(rule) => match action(&actions, rule) {
                            super::super::Action::Delete => {
                                tally.core.deleted += 1;
                                sink.delete();
                            }
                            super::super::Action::Replace(value) => {
                                let matches = matches!(
                                    (entry.kind(), value),
                                    (EntryKind::Varint(_), Value::Varint(_))
                                        | (EntryKind::I32(_), Value::I32(_))
                                        | (EntryKind::I64(_), Value::I64(_))
                                );
                                if !matches {
                                    return Err(Flow::Host(sink.refuse(Fault {
                                        at: head,
                                        trail: trail(&layers),
                                        kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                                    })));
                                }
                                tally.core.replaced += 1;
                                sink.replace(head, tag_end, value);
                            }
                            super::super::Action::Normalize => {
                                tally.core.normalized += 1;
                                let (kind, value) = match entry.kind() {
                                    EntryKind::Varint(word) => {
                                        (RecordKind::Varint, Value::Varint(word))
                                    }
                                    EntryKind::I32(bits) => (RecordKind::I32, Value::I32(bits)),
                                    EntryKind::I64(bits) => (RecordKind::I64, Value::I64(bits)),
                                    // The enclosing arm admits
                                    // exactly the three scalar
                                    // kinds.
                                    EntryKind::Len(_) => unreachable!("scalar-arm normalize"),
                                };
                                sink.normalize(head_word(field, kind), value);
                            }
                            // Insert entries never enter the Hits
                            // fold (they ride the gap lanes).
                            super::super::Action::Insert(_) => {
                                unreachable!("targets quote action rules")
                            }
                        },
                        Hits::None => sink.verbatim(head, end),
                        Hits::Conflict(..) => unreachable!("conflicts returned above"),
                    },
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
                let (action_hits, routed_a) = action_m.probe(field);
                if let Hits::Conflict(first, second) = action_hits {
                    return Err(Flow::Host(sink.refuse(conflict(head, &layers, first, second))));
                }
                collect_hits(&transfer_m, &paths, field, &mut hits);
                let owned = match action_hits {
                    Hits::One(rule) => Some(rule),
                    _ => None,
                };
                let disposition = match driver.len(head, payload_start, end, &hits, owned) {
                    Ok(disposition) => disposition,
                    Err(refusal) => {
                        return Err(Flow::Transfer {
                            at: head,
                            trail: trail(&layers),
                            breach: refusal,
                        });
                    }
                };
                match disposition {
                    Disposition::Suppress => sink.delete(),
                    Disposition::Replaced(span) => {
                        tally.payloads_copied += 1;
                        sink.replace(
                            head,
                            tag_end,
                            Value::Len(
                                &input
                                    [usize_of(span.from.as_inner())..usize_of(span.to.as_inner())],
                            ),
                        );
                    }
                    Disposition::Ordinary => match action_hits {
                        Hits::One(rule) => match action(&actions, rule) {
                            super::super::Action::Delete => {
                                tally.core.deleted += 1;
                                sink.delete();
                            }
                            super::super::Action::Replace(
                                value @ (Value::Len(_) | Value::LenParts(_)),
                            ) => {
                                tally.core.replaced += 1;
                                sink.replace(head, tag_end, value);
                            }
                            super::super::Action::Replace(_) => {
                                return Err(Flow::Host(sink.refuse(Fault {
                                    at: head,
                                    trail: trail(&layers),
                                    kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                                })));
                            }
                            super::super::Action::Normalize => {
                                tally.core.normalized += 1;
                                sink.normalize(
                                    head_word(field, RecordKind::Len),
                                    Value::Len(payload),
                                );
                            }
                            super::super::Action::Insert(_) => {
                                unreachable!("targets quote action rules")
                            }
                        },
                        Hits::None => {
                            let interior = gapped && !action_m.probe_gaps(field).is_empty();
                            let anchored = hits.iter().any(|&hit| paths.gap_side(hit).is_some());
                            let routed_t = transfer_m.probe_routes(field);
                            if interior || anchored || routed_a || routed_t {
                                if remaining == 0 {
                                    return Err(Flow::Host(sink.refuse(Fault {
                                        at: head,
                                        trail: trail(&layers),
                                        kind: FaultKind::Wire(super::WireBreach::Depth),
                                    })));
                                }
                                match sink.descend(head, tag_end, payload_start, end) {
                                    Down::Skip => sink.verbatim(head, end),
                                    Down::Walk => {
                                        tally.core.descended += 1;
                                        let mut tails = false;
                                        if interior {
                                            let gaps = action_m.probe_gaps(field);
                                            tails = gaps.tail();
                                            if gaps.head() {
                                                fire_lane(
                                                    &action_m,
                                                    &actions,
                                                    field,
                                                    Lane::Head,
                                                    sink,
                                                    &mut tally.core,
                                                );
                                            }
                                        }
                                        fire_gap_side(
                                            &paths,
                                            &hits,
                                            Gap::HeadOf,
                                            sink,
                                            input,
                                            driver,
                                            &mut tally,
                                        );
                                        action_m.commit_descent();
                                        transfer_m.commit_descent();
                                        layers.push(Layer {
                                            cursor: Cursor::within(payload),
                                            base: payload_start,
                                            crossing: Some(Crossing::new(field, head)),
                                            head,
                                            tag_end,
                                            payload_start,
                                            payload_end: end,
                                            remaining: remaining - 1,
                                            tails,
                                        });
                                    }
                                }
                            } else {
                                sink.verbatim(head, end);
                            }
                        }
                        Hits::Conflict(..) => unreachable!("conflicts returned above"),
                    },
                }
            }
        }
    }
}

// ─── the engine (designate → resolve → measure → emit) ───

/// Maps a fallible pass's two-channel refusal onto the public
/// fault.
fn fault_of<B: Into<TransferBreach>>(flow: Flow<Fault, B>) -> TransferFault {
    match flow {
        Flow::Host(fault) => TransferFault {
            at: fault.at(),
            trail: fault.trail().into(),
            kind: TransferFaultKind::Job(fault.kind()),
        },
        Flow::Transfer { at, trail, breach } => {
            TransferFault { at, trail, kind: TransferFaultKind::Transfer(breach.into()) }
        }
    }
}

/// The designation pass and the plan resolution: every wire,
/// ordinary-rule, and transfer-law fault surfaces here, before any
/// measuring or emission state exists.
fn designate<const MINIMAL: bool>(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    limit: DepthLimit,
) -> Result<TransferPlan, TransferFault> {
    let mut scout = Scout::new(set);
    if let Err(flow) = walk::<_, _, MINIMAL>(input, set, limit, &mut Designate, &mut scout) {
        return Err(fault_of(flow));
    }
    let (mut plan, copy_targets) = scout.finish();
    if let Err(refusal) = plan.resolve(set, &copy_targets) {
        return Err(TransferFault {
            at: 0,
            trail: Box::new([]),
            kind: TransferFaultKind::Transfer(refusal),
        });
    }
    Ok(plan)
}

/// One buffered transfer job, one instance per acceptance
/// standard: designate and resolve, measure over the plan, replay
/// into the reservation.
fn run_into<const MINIMAL: bool>(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<TransferStats, TransferFault> {
    let plan = designate::<MINIMAL>(input, set, limit)?;
    let mut apply = Apply::new(set, &plan);
    let mut measure = Measure::new();
    let tally = match walk::<_, _, MINIMAL>(input, set, limit, &mut measure, &mut apply) {
        Ok(tally) => tally,
        Err(flow) => return Err(fault_of(flow)),
    };
    let total = measure.root_total();
    if total > u64::from(PayloadLen::MAX.as_inner()) {
        return Err(TransferFault {
            at: 0,
            trail: Box::new([]),
            kind: TransferFaultKind::Job(FaultKind::Output { len: total }),
        });
    }
    // In class: judged above.
    #[allow(clippy::as_conversions, reason = "class-judged total narrows losslessly")]
    let total = total as u32;
    apply.rewind();
    let mut emit = Emit::new(input, out, measure.slots, total);
    // The emit pass is past the fault barrier: both its channels
    // are uninhabited, so the pattern is irrefutable.
    let Ok(repeated) = walk::<_, _, MINIMAL>(input, set, limit, &mut emit, &mut apply);
    debug_assert!(
        repeated.judgments() == tally.judgments(),
        "the emit pass repeats the measuring pass's judgments"
    );
    emit.finish();
    Ok(tally)
}

/// [`run_into`]'s sink twin.
fn run_sink<const MINIMAL: bool>(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    limit: DepthLimit,
    sink: &mut impl FnMut(&[u8]),
) -> Result<TransferStats, TransferFault> {
    let plan = designate::<MINIMAL>(input, set, limit)?;
    let mut apply = Apply::new(set, &plan);
    let mut measure = Measure::new();
    let tally = match walk::<_, _, MINIMAL>(input, set, limit, &mut measure, &mut apply) {
        Ok(tally) => tally,
        Err(flow) => return Err(fault_of(flow)),
    };
    let total = measure.root_total();
    if total > u64::from(PayloadLen::MAX.as_inner()) {
        return Err(TransferFault {
            at: 0,
            trail: Box::new([]),
            kind: TransferFaultKind::Job(FaultKind::Output { len: total }),
        });
    }
    apply.rewind();
    let mut emit = SinkEmit {
        input,
        sink,
        run: None,
        slots: measure.slots,
        cursor: 0,
        written: 0,
        total,
        logical: 0,
        ledger: Vec::new(),
    };
    // Past the fault barrier: both channels uninhabited.
    let Ok(repeated) = walk::<_, _, MINIMAL>(input, set, limit, &mut emit, &mut apply);
    debug_assert!(
        repeated.judgments() == tally.judgments(),
        "the emit pass repeats the measuring pass's judgments"
    );
    emit.finish();
    Ok(tally)
}

// ─── the public faces ───

/// Runs `set`'s transfers and ordinary rules over `input` into
/// fresh bytes, with the job receipt.
///
/// # Errors
///
/// [`TransferFault`]: the host's own refusals
/// ([`TransferFaultKind::Job`] — admission, unlawful wire, action
/// conflicts, replacement kind mismatches, the depth budget,
/// growth past the LEN class) and the transfer laws
/// ([`TransferFaultKind::Transfer`] — a non-LEN payload source or
/// replace target, a scalar anchor occurrence, a failed pairing
/// equation, a contested occurrence). No bytes are produced on
/// `Err`.
///
/// # Examples
///
/// ```
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::rewrite::groupless::rewrite_transfers;
/// use protobuf_edit::rewrite::{
///     CopyPairing, Gap, RecordTransfer, RecordTransferRule, TransferRuleSet,
/// };
/// use protobuf_edit::{DepthLimit, FieldNumber};
///
/// // Move every top-level field-1 record to the document tail,
/// // byte-exactly — the padded value spelling rides along.
/// let f1 = FieldNumber::new(1).unwrap();
/// let moves = [RecordTransferRule {
///     source: &[Segment::Field(f1)],
///     anchor: &[],
///     gap: Gap::TailOf,
///     transfer: RecordTransfer::MoveZip,
/// }];
/// let set = TransferRuleSet::over(&[], &moves, &[], &[]).unwrap();
///
/// // varint f1=150 (padded to three bytes) · varint f2=42
/// let msg = [0x08, 0x96, 0x81, 0x00, 0x10, 0x2A];
/// let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(out, [0x10, 0x2A, 0x08, 0x96, 0x81, 0x00]);
/// assert_eq!(stats.records_moved(), 1);
/// ```
///
/// # Panics
///
/// If the crate's own passes disagree on what they measured and
/// what they emitted — a library bug caught at the seam.
#[inline]
pub fn rewrite_transfers(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    limit: DepthLimit,
) -> Result<(Vec<u8>, TransferStats), TransferFault> {
    let mut out = Vec::new();
    let stats = rewrite_transfers_into(input, set, limit, &mut out)?;
    Ok((out, stats))
}

/// Runs `set` over `input`, appending to `out` — the reuse face.
///
/// Existing content is untouched, all faults precede the
/// reservation, and the new length is published once — after the
/// emit pass's invariant pins.
///
/// # Errors
///
/// As [`rewrite_transfers`]; `out` is untouched on `Err`.
///
/// # Panics
///
/// As [`rewrite_transfers`], or if appending the output to `out`
/// would overflow the vector's capacity bounds (an extreme the
/// caller can reach on 32-bit targets with a near-full buffer).
#[inline]
pub fn rewrite_transfers_into(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<TransferStats, TransferFault> {
    run_into::<false>(input, set, limit, out)
}

/// Runs `set` over `input`, handing the output to `sink` as
/// borrowed slices in output order.
///
/// No output buffer exists: verbatim runs and transferred spans
/// pass through as windows of `input`, authored words ride a
/// ten-byte stack window.
///
/// # Errors
///
/// As [`rewrite_transfers`]. Every fault surfaces before the first
/// handoff — on `Err` the sink has received nothing.
///
/// # Panics
///
/// As [`rewrite_transfers`].
pub fn rewrite_transfers_sink(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    limit: DepthLimit,
    mut sink: impl FnMut(&[u8]),
) -> Result<TransferStats, TransferFault> {
    run_sink::<false>(input, set, limit, &mut sink)
}

/// [`rewrite_transfers`] under a declared acceptance
/// [`Standard`].
///
/// The standard picks a monomorphized walk instance once at this
/// entry — all three passes run it — so a canonical job refuses
/// every non-minimal varint width in the input it walks, which
/// covers every transfer source's framing: a padded record cannot
/// enter a canonical job's output, it refuses at the walk (opaque
/// LEN interiors stay the source's declaration and ride exact,
/// exactly as for the plain faces).
///
/// # Errors
///
/// As [`rewrite_transfers`], plus the width refusals the declared
/// standard adds.
///
/// # Examples
///
/// ```
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::rewrite::groupless::{
///     TransferFaultKind, rewrite_transfers_standard,
/// };
/// use protobuf_edit::rewrite::groupless::{FaultKind, WireBreach};
/// use protobuf_edit::rewrite::{
///     CopyPairing, Gap, RecordTransfer, RecordTransferRule, TransferRuleSet,
/// };
/// use protobuf_edit::{DepthLimit, FieldNumber, Standard};
///
/// let f1 = FieldNumber::new(1).unwrap();
/// let copies = [RecordTransferRule {
///     source: &[Segment::Field(f1)],
///     anchor: &[],
///     gap: Gap::TailOf,
///     transfer: RecordTransfer::Copy(CopyPairing::Zip),
/// }];
/// let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
///
/// // varint f1=150 padded: the canonical job refuses the padded
/// // source before any transfer resolves; the tolerant job copies
/// // it byte-exactly.
/// let msg = [0x08, 0x96, 0x81, 0x00];
/// let fault =
///     rewrite_transfers_standard(&msg, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
///         .unwrap_err();
/// assert!(matches!(
///     fault.kind(),
///     TransferFaultKind::Job(FaultKind::Wire(WireBreach::NonMinimal))
/// ));
///
/// let (out, stats) =
///     rewrite_transfers_standard(&msg, &set, Standard::Tolerant, DepthLimit::REFERENCE)
///         .unwrap();
/// assert_eq!(out, [0x08, 0x96, 0x81, 0x00, 0x08, 0x96, 0x81, 0x00]);
/// assert_eq!(stats.records_copied(), 1);
/// ```
///
/// # Panics
///
/// As [`rewrite_transfers`].
#[inline]
pub fn rewrite_transfers_standard(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    standard: Standard,
    limit: DepthLimit,
) -> Result<(Vec<u8>, TransferStats), TransferFault> {
    let mut out = Vec::new();
    let stats = rewrite_transfers_into_standard(input, set, standard, limit, &mut out)?;
    Ok((out, stats))
}

/// [`rewrite_transfers_into`] under a declared acceptance
/// [`Standard`] ([`rewrite_transfers_standard`]'s reuse face).
///
/// # Errors
///
/// As [`rewrite_transfers_standard`]; `out` is untouched on `Err`.
///
/// # Panics
///
/// As [`rewrite_transfers_into`].
#[inline]
pub fn rewrite_transfers_into_standard(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    standard: Standard,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<TransferStats, TransferFault> {
    match standard {
        Standard::Tolerant => run_into::<false>(input, set, limit, out),
        Standard::CanonicalMinimal => run_into::<true>(input, set, limit, out),
    }
}

/// [`rewrite_transfers_sink`] under a declared acceptance
/// [`Standard`] ([`rewrite_transfers_standard`]'s streaming face).
///
/// # Errors
///
/// As [`rewrite_transfers_standard`]. Every fault surfaces before
/// the first handoff — on `Err` the sink has received nothing.
///
/// # Panics
///
/// As [`rewrite_transfers_sink`].
#[inline]
pub fn rewrite_transfers_sink_standard(
    input: &[u8],
    set: &TransferRuleSet<'_>,
    standard: Standard,
    limit: DepthLimit,
    mut sink: impl FnMut(&[u8]),
) -> Result<TransferStats, TransferFault> {
    match standard {
        Standard::Tolerant => run_sink::<false>(input, set, limit, &mut sink),
        Standard::CanonicalMinimal => run_sink::<true>(input, set, limit, &mut sink),
    }
}

#[cfg(test)]
mod tests;
