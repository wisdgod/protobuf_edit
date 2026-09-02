//! The grouped transfer engine: [`TransferRuleSet`] jobs over the
//! full six-code wire language.
//!
//! The engine is the groupless twin's — three walks (designate,
//! measure, emit) over one skeleton, two matchers in lockstep, the
//! host's own sinks and reservation discipline — with the group
//! laws on top: a group record-source designation is the whole
//! structural closure, open tag through its verified end tag, so
//! its span completes at the matching exit (a copied group's
//! interior stays with the walk and other rules lawfully edit the
//! origin; the designation still names the original bytes). A
//! moved or deleted group walks silenced, exactly as the host's
//! delete suppression, and designations inside it never fire.
//! Groups are containers by syntax: transfer anchors fire their
//! head gaps past the open tag and their tail gaps before the end
//! tag, composing with a normalized owner exactly as ordinary
//! insert gaps do. Payload rules stay LEN-only — a group has no
//! detachable interior, so a group occurrence under a payload
//! source or replace target refuses with its kind.

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
use crate::cursor::GroupDepth;
use crate::cursor::grouped::{Cursor, EntryKind};
use crate::wire::grouped::{RecordKind, head_word};
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

    /// Committed LEN containers crossed to reach the fault
    /// (outermost first; empty at top level).
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
            Self::Transfer(refusal) => write!(f, "{refusal}"),
        }
    }
}

// ─── the walk (three instantiations per acceptance standard) ───

/// One committed LEN layer, the insert-admitting door's shape.
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
    /// Depth budget left inside this layer (container crossings).
    remaining: u16,
    /// Open groups inside this layer (they consume budget too).
    group_depth: u16,
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

/// The designation walk's sink: judges nothing and emits nothing.
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

    fn normalize_group(&mut self, _word: u32) {}

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

/// One resolved destination emission lands (the groupless twin's
/// law: the `delete` event is the measuring sink's dirty mark).
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

/// Fires every anchor hit of `side`'s kind, in hit order.
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

/// One `TailOf` transfer anchor pending at an open group, keyed by
/// the group's position exactly as the host's insert pends are.
struct TransferPend {
    layer: usize,
    depth: u16,
    hit: TransferHit,
}

/// One group record-source designation pending its matching exit,
/// keyed like [`TransferPend`]; the slot indexes the rule's source
/// list.
struct CapturePend {
    layer: usize,
    depth: u16,
    hit: TransferHit,
    slot: u32,
}

/// Runs one pass: the host's grouped walk skeleton with the
/// transfer populations riding a second matcher in lockstep (the
/// groupless twin's discipline, plus the group laws).
#[expect(
    clippy::too_many_lines,
    reason = "the walk is one event loop, the host skeleton plus the transfer arms; splitting \
              it would scatter the layer discipline the judgments lean on"
)]
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
    let Ok(root) = Cursor::over(input, GroupDepth::from(limit)) else {
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
        group_depth: 0,
        tails: false,
    });
    // Depth of the group currently vanishing (an action delete or
    // a moved group): body events are skipped wholesale while the
    // cursor verifies pairing.
    let mut suppress: u32 = 0;
    // Groups whose framing re-emits minimally (the host's
    // normalize), keyed (layer count, group depth) at their enter.
    let mut normalizing: Vec<(usize, u16)> = Vec::new();
    // Ordinary insert tail rules pending at open groups.
    let mut gap_pends: Vec<super::GapPend> = Vec::new();
    // Transfer tail anchors pending at open groups, same keying.
    let mut transfer_pends: Vec<TransferPend> = Vec::new();
    // Group record-source designations pending their matching
    // exits: walked groups keyed like `normalizing`; a silenced
    // (deleted or moved) group's designations complete when its
    // suppression closes, so one flat list serves them.
    let mut captures: Vec<CapturePend> = Vec::new();
    let mut suppressed_captures: Vec<(TransferHit, u32)> = Vec::new();
    // Root head gaps: ordinary inserts first, then the transfer
    // anchors, each in rule order.
    actions.root_inserts(Gap::HeadOf, |insert| fire_gap(sink, &mut tally.core, insert));
    paths.root_anchors(Gap::HeadOf, |hit| {
        if let Some(emission) = driver.gap_fired(hit) {
            emit_transfer(sink, input, &mut tally, emission);
        }
    });

    loop {
        let layer_count = layers.len();
        // SAFETY: the root layer is pushed above and the only pop
        // sits behind the `len == 1` return below, so the stack is
        // never empty here.
        let layer = unsafe { layers.last_mut().unwrap_unchecked() };
        let base = layer.base;
        let head = base + layer.cursor.pos();
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

        if suppress > 0 {
            match entry.kind() {
                EntryKind::GroupEnter => suppress += 1,
                EntryKind::GroupExit => {
                    suppress -= 1;
                    if suppress == 0 {
                        // The silenced group closed: its pending
                        // record-source designations complete with
                        // the verified end tag. Drain, not consume:
                        // the buffer serves every later silenced
                        // group in this walk.
                        #[allow(clippy::iter_with_drain, reason = "the buffer is reused")]
                        for (hit, slot) in suppressed_captures.drain(..) {
                            driver.group_source_end(hit, slot, end);
                        }
                    }
                }
                _ => {}
            }
            continue;
        }

        let tag_end = head + u32::from(layer.cursor.tag_width());
        let field = entry.field();
        match entry.kind() {
            EntryKind::GroupExit => {
                action_m.exit();
                transfer_m.exit();
                // Pending group record-source designations complete
                // with the verified end tag (proper nesting makes
                // the matching entries the stack's suffix).
                while captures
                    .last()
                    .is_some_and(|c| c.layer == layer_count && c.depth == layer.group_depth)
                {
                    // The loop condition proved the entry present.
                    let Some(capture) = captures.pop() else { unreachable!("suffix checked") };
                    driver.group_source_end(capture.hit, capture.slot, end);
                }
                // Tail gaps fire inside the group, before its end
                // tag's emission: ordinary inserts first, then the
                // transfer anchors.
                let pend_len = gap_pends.len();
                if pend_len > 0 {
                    let mut pends = pend_len;
                    while pends > 0
                        && gap_pends[pends - 1].layer == layer_count
                        && gap_pends[pends - 1].depth == layer.group_depth
                    {
                        pends -= 1;
                    }
                    for pend in &gap_pends[pends..] {
                        match action(&actions, pend.rule) {
                            super::super::Action::Insert(insert) => {
                                fire_gap(sink, &mut tally.core, insert);
                            }
                            _ => unreachable!("gap lanes quote insert rules"),
                        }
                    }
                    gap_pends.truncate(pends);
                }
                let t_len = transfer_pends.len();
                if t_len > 0 {
                    let mut pends = t_len;
                    while pends > 0
                        && transfer_pends[pends - 1].layer == layer_count
                        && transfer_pends[pends - 1].depth == layer.group_depth
                    {
                        pends -= 1;
                    }
                    for pend in &transfer_pends[pends..] {
                        if let Some(emission) = driver.gap_fired(pend.hit) {
                            emit_transfer(sink, input, &mut tally, emission);
                        }
                    }
                    transfer_pends.truncate(pends);
                }
                if normalizing.last() == Some(&(layer_count, layer.group_depth)) {
                    normalizing.pop();
                    sink.normalize_group(crate::wire::grouped::group_end_word(field));
                } else {
                    sink.verbatim(head, end);
                }
                layer.group_depth -= 1;
            }
            EntryKind::GroupEnter => {
                let (action_hits, _routed) = action_m.probe(field);
                if let Hits::Conflict(first, second) = action_hits {
                    return Err(Flow::Host(sink.refuse(conflict(head, &layers, first, second))));
                }
                collect_hits(&transfer_m, &paths, field, &mut hits);
                let owned = match action_hits {
                    Hits::One(rule) => Some(rule),
                    _ => None,
                };
                let disposition = match driver.group_enter(head, &hits, owned) {
                    Ok(disposition) => disposition,
                    Err(refusal) => {
                        return Err(Flow::Transfer {
                            at: head,
                            trail: trail(&layers),
                            breach: refusal,
                        });
                    }
                };
                // Record-source designations open here; whether
                // they complete at a walked exit or a silenced one
                // follows the group's fate below.
                let deleted = matches!(
                    (disposition, action_hits),
                    (Disposition::Ordinary, Hits::One(rule))
                        if matches!(action(&actions, rule), super::super::Action::Delete)
                );
                let moved = matches!(disposition, Disposition::Suppress);
                for &hit in &hits {
                    if let TransferHit::RecordSource(_) = hit {
                        let slot = driver.group_source_begin(hit, head);
                        if moved || deleted {
                            suppressed_captures.push((hit, slot));
                        } else {
                            captures.push(CapturePend {
                                layer: layer_count,
                                depth: layer.group_depth + 1,
                                hit,
                                slot,
                            });
                        }
                    }
                }
                if moved {
                    suppress = 1;
                    sink.delete();
                    continue;
                }
                match action_hits {
                    Hits::One(rule) => match action(&actions, rule) {
                        super::super::Action::Delete => {
                            suppress = 1;
                            tally.core.deleted += 1;
                            sink.delete();
                        }
                        super::super::Action::Replace(_) => {
                            return Err(Flow::Host(sink.refuse(Fault {
                                at: head,
                                trail: trail(&layers),
                                kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                            })));
                        }
                        super::super::Action::Normalize => {
                            if layer.group_depth == layer.remaining {
                                return Err(Flow::Host(sink.refuse(Fault {
                                    at: head,
                                    trail: trail(&layers),
                                    kind: FaultKind::Wire(super::WireBreach::Depth),
                                })));
                            }
                            tally.core.normalized += 1;
                            sink.normalize_group(head_word(field, RecordKind::Group));
                            enter_group_gaps(
                                &action_m,
                                &actions,
                                &paths,
                                gapped,
                                field,
                                layer_count,
                                layer.group_depth + 1,
                                &hits,
                                sink,
                                input,
                                driver,
                                &mut tally,
                                &mut gap_pends,
                                &mut transfer_pends,
                            );
                            action_m.commit_descent();
                            transfer_m.commit_descent();
                            layer.group_depth += 1;
                            normalizing.push((layer_count, layer.group_depth));
                        }
                        super::super::Action::Insert(_) => {
                            unreachable!("targets quote action rules")
                        }
                    },
                    Hits::None => {
                        if layer.group_depth == layer.remaining {
                            return Err(Flow::Host(sink.refuse(Fault {
                                at: head,
                                trail: trail(&layers),
                                kind: FaultKind::Wire(super::WireBreach::Depth),
                            })));
                        }
                        sink.verbatim(head, end);
                        enter_group_gaps(
                            &action_m,
                            &actions,
                            &paths,
                            gapped,
                            field,
                            layer_count,
                            layer.group_depth + 1,
                            &hits,
                            sink,
                            input,
                            driver,
                            &mut tally,
                            &mut gap_pends,
                            &mut transfer_pends,
                        );
                        action_m.commit_descent();
                        transfer_m.commit_descent();
                        layer.group_depth += 1;
                    }
                    Hits::Conflict(..) => unreachable!("conflicts returned above"),
                }
            }
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
                                    EntryKind::Len(_)
                                    | EntryKind::GroupEnter
                                    | EntryKind::GroupExit => {
                                        unreachable!("scalar-arm normalize")
                                    }
                                };
                                sink.normalize(head_word(field, kind), value);
                            }
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
                                let (group_depth, remaining) = (layer.group_depth, layer.remaining);
                                if group_depth == remaining {
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
                                            cursor: Cursor::within(
                                                payload,
                                                GroupDepth::from(limit),
                                            ),
                                            base: payload_start,
                                            crossing: Some(Crossing::new(field, head)),
                                            head,
                                            tag_end,
                                            payload_start,
                                            payload_end: end,
                                            remaining: remaining - group_depth - 1,
                                            group_depth: 0,
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

/// A committed group's gap sides, scanned in the opening layer
/// ahead of the descent commit: ordinary insert heads fire (tails
/// pend), then the transfer anchors' heads fire (tails pend), the
/// same order every gap follows.
#[expect(
    clippy::too_many_arguments,
    reason = "one emission event over the walk's whole live state; a context struct would only \
              rename the arguments"
)]
fn enter_group_gaps<'r, S: Sink, D: Driver>(
    action_m: &Matcher<'r, super::super::InsertRuleSet<'r>>,
    actions: &super::super::InsertRuleSet<'r>,
    paths: &TransferPaths<'r>,
    gapped: bool,
    field: FieldNumber,
    layer: usize,
    depth: u16,
    hits: &[TransferHit],
    sink: &mut S,
    input: &[u8],
    driver: &mut D,
    tally: &mut TransferStats,
    gap_pends: &mut Vec<super::GapPend>,
    transfer_pends: &mut Vec<TransferPend>,
) {
    if gapped {
        let gaps = action_m.probe_gaps(field);
        if gaps.head() {
            fire_lane(action_m, actions, field, Lane::Head, sink, &mut tally.core);
        }
        if gaps.tail() {
            action_m.visit_gaps(field, Lane::Tail, |rule| {
                gap_pends.push(super::GapPend { layer, depth, rule });
            });
        }
    }
    for &hit in hits {
        match paths.gap_side(hit) {
            Some(Gap::HeadOf) => {
                if let Some(emission) = driver.gap_fired(hit) {
                    emit_transfer(sink, input, tally, emission);
                }
            }
            Some(Gap::TailOf) => transfer_pends.push(TransferPend { layer, depth, hit }),
            None => {}
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
/// standard.
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
/// ([`TransferFaultKind::Job`]) and the transfer laws
/// ([`TransferFaultKind::Transfer`]). No bytes are produced on
/// `Err`.
///
/// # Examples
///
/// ```
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::rewrite::grouped::rewrite_transfers;
/// use protobuf_edit::rewrite::{
///     CopyPairing, Gap, RecordTransfer, RecordTransferRule, TransferRuleSet,
/// };
/// use protobuf_edit::{DepthLimit, FieldNumber};
///
/// // Copy the whole field-1 group — open tag through end tag —
/// // to the document tail.
/// let f1 = FieldNumber::new(1).unwrap();
/// let copies = [RecordTransferRule {
///     source: &[Segment::Field(f1)],
///     anchor: &[],
///     gap: Gap::TailOf,
///     transfer: RecordTransfer::Copy(CopyPairing::Zip),
/// }];
/// let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
///
/// // group f1 { varint f2=150 } · varint f3=5
/// let msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x05];
/// let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(out, [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x05, 0x0B, 0x10, 0x96, 0x01, 0x0C]);
/// assert_eq!(stats.records_copied(), 1);
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
/// every non-minimal varint width in the input it walks, group
/// framing tags included, which covers every transfer source's
/// framing (opaque LEN interiors stay the source's declaration
/// and ride exact).
///
/// # Errors
///
/// As [`rewrite_transfers`], plus the width refusals the declared
/// standard adds.
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
