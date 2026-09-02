//! The grouped collector's module suite: chunk-independence over
//! the grouped boundary corpus (frames crossing every chunk edge),
//! exact group-fault pins at stream offsets, the LEN-in-group and
//! group-in-LEN documents, and the root transaction's grouped face
//! — groups seal no extent, so a LEN under open root groups still
//! rides the one transaction and the groups clip at its cut.

use alloc::vec;
use alloc::vec::Vec;

use super::{Collector, FaultKind, Retained, Snapshot};
use crate::collect::{Advice, Advisor, Ancestry, NoAdvice};
use crate::stream_corpus;
use crate::varint::slice::ReadFault;
use crate::wire::FieldNumber;
use crate::{DepthLimit, Stage, Standard};

/// A pure field-keyed advisor: f2 commits, f3 is opaque bytes,
/// everything else speculates.
#[derive(Clone, Copy)]
struct Pin;

impl Advisor for Pin {
    fn advise(&mut self, _ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
        match field.as_inner() {
            2 => Advice::Commit,
            3 => Advice::Opaque,
            _ => Advice::Speculate,
        }
    }
}

/// A pure commit-everything advisor.
#[derive(Clone, Copy)]
struct CommitAll;

impl Advisor for CommitAll {
    fn advise(&mut self, _ancestry: Ancestry<'_>, _field: FieldNumber) -> Advice {
        Advice::Commit
    }
}

/// Collects `plan`'s chunks under one configuration and seals.
fn collect<A: Advisor>(
    plan: &[Vec<u8>],
    standard: Standard,
    depth: DepthLimit,
    advice: &mut A,
) -> Retained {
    let mut collector = Collector::new(standard, depth, advice);
    for chunk in plan {
        collector.feed(chunk).expect("corpus streams stay inside the coordinate class");
    }
    collector.finish()
}

/// One whole-stream feed.
fn whole<A: Advisor>(
    bytes: &[u8],
    standard: Standard,
    depth: DepthLimit,
    advice: &mut A,
) -> Retained {
    collect(&[bytes.to_vec()], standard, depth, advice)
}

/// The full snapshot beside the source: what chunk-independence
/// compares.
fn state(tree: &Retained) -> (Vec<u8>, Snapshot) {
    (tree.bytes().to_vec(), tree.snapshot())
}

/// The feed plans a document is swept under (Miri keeps the shapes
/// but trims the per-split family).
fn plans_for(bytes: &[u8]) -> Vec<Vec<Vec<u8>>> {
    if cfg!(miri) {
        let mut plans = vec![vec![bytes.to_vec()]];
        for split in [bytes.len() / 3, bytes.len() / 2, (bytes.len() * 2) / 3] {
            plans.push(vec![bytes[..split].to_vec(), bytes[split..].to_vec()]);
        }
        plans.push(bytes.iter().map(|&b| vec![b]).collect());
        plans
    } else {
        stream_corpus::chunkings(bytes)
    }
}

/// The advice- and frame-sensitive documents the flat corpus
/// cannot spell: LEN in group, group in LEN (opaque and judged),
/// group faults, depth edges, and the grouped transaction shapes.
fn advised_items() -> Vec<Vec<u8>> {
    vec![
        // varint f1 · group f2 { varint f3=1 }.
        vec![0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14],
        // Nested groups: f1 { f4 { i32 f5 } } · i64 f6.
        vec![0x0B, 0x23, 0x2D, 1, 2, 3, 4, 0x24, 0x0C, 0x31, 1, 2, 3, 4, 5, 6, 7, 8],
        // A LEN inside a group (f2 commits under Pin).
        vec![0x0B, 0x12, 0x02, 0x08, 0x01, 0x0C],
        // A group inside a LEN: pairing may not cross the seal —
        // speculation absorbs the unclosed interior; a committed
        // read faults it.
        vec![0x12, 0x02, 0x0B, 0x0C],
        vec![0x12, 0x01, 0x0B],
        // Padded group framing: end tag continuation-padded.
        vec![0x0B, 0x8C, 0x80, 0x00],
        // An orphan end tag, and a mismatched end tag.
        vec![0x0C],
        vec![0x0B, 0x1C],
        // A group left open by the stream's end (bare, and with an
        // indexed interior).
        vec![0x0B],
        vec![0x0B, 0x08, 0x01],
        // A group unterminated at a LEN's seal (committed under
        // Pin via f2; absorbed under NoAdvice).
        vec![0x12, 0x02, 0x0B, 0x08],
        // The grouped transaction shapes: a root LEN under an open
        // group, underfilled and proven; a deferred group fault
        // inside the unproven extent.
        vec![0x0B, 0x12, 0x02, 0x08],
        vec![0x0B, 0x12, 0x02, 0x08, 0x01, 0x0C],
        vec![0x12, 0x03, 0x0B, 0x08, 0x01],
        vec![0x12, 0x02, 0x0C, 0xAA],
        // Group-looking bytes opaque inside a LEN (f3 opaque under
        // Pin).
        vec![0x1A, 0x03, 0x0B, 0x14, 0x0C],
        // Truncated framing at the stream end.
        vec![0x0B, 0x18],
        vec![0x13, 0x1A],
    ]
}

#[test]
fn the_finished_product_never_varies_with_the_feed_plan() {
    let mut corpus: Vec<Vec<u8>> =
        stream_corpus::grouped_items().into_iter().map(|(bytes, _)| bytes).collect();
    corpus.extend(advised_items());
    for (index, bytes) in corpus.iter().enumerate() {
        if cfg!(miri) && bytes.len() > 24 {
            continue;
        }
        for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
            for depth in [DepthLimit::REFERENCE, DepthLimit::MIN] {
                let baseline_no = state(&whole(bytes, standard, depth, &mut NoAdvice));
                let baseline_pin = state(&whole(bytes, standard, depth, &mut Pin));
                for plan in plans_for(bytes) {
                    let chunked_no = state(&collect(&plan, standard, depth, &mut NoAdvice));
                    assert_eq!(
                        chunked_no,
                        baseline_no,
                        "item {index} diverged under NoAdvice ({} chunks)",
                        plan.len()
                    );
                    let chunked_pin = state(&collect(&plan, standard, depth, &mut Pin));
                    assert_eq!(
                        chunked_pin,
                        baseline_pin,
                        "item {index} diverged under Pin ({} chunks)",
                        plan.len()
                    );
                }
            }
        }
    }
}

#[test]
fn group_topology_is_indexed_structurally() {
    // Nested groups with a mixed interior: parents, descendants,
    // and the closing facts all land.
    let bytes = [0x0B, 0x23, 0x2D, 1, 2, 3, 4, 0x24, 0x0C, 0x31, 1, 2, 3, 4, 5, 6, 7, 8];
    let tree = whole(&bytes, Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    assert!(tree.is_complete());
    let top: Vec<_> = tree.top().collect();
    assert_eq!(top.len(), 2);
    let outer_kids: Vec<_> = tree.children(top[0]).collect();
    assert_eq!(outer_kids.len(), 1);
    let inner_kids: Vec<_> = tree.children(outer_kids[0]).collect();
    assert_eq!(inner_kids.len(), 1);
    assert_eq!(tree.i32_bits(inner_kids[0]), Some(u32::from_le_bytes([1, 2, 3, 4])));
    assert_eq!(tree.i64_bits(top[1]), Some(u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8])));

    // The reverse index sees through the frames: the end tag
    // belongs to its group.
    let group_span = tree.span(top[0]);
    assert_eq!(tree.narrowest(group_span.end() - 1), Some(top[0]));
}

// ─── group faults at stream offsets ───

#[test]
fn group_faults_land_at_their_buffered_coordinates() {
    // An orphan end tag.
    let tree = whole(&[0x0C], Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    let fault = tree.fault().expect("an orphan end tag faults");
    assert_eq!(fault.at(), 0);
    assert!(matches!(
        fault.kind(),
        FaultKind::GroupEndOrphan { found } if found.as_inner() == 1
    ));

    // A mismatched end tag: f1 open, f3's end found.
    let tree = whole(&[0x0B, 0x1C], Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    let fault = tree.fault().expect("a mismatched end tag faults");
    assert_eq!(fault.at(), 1);
    assert!(matches!(
        fault.kind(),
        FaultKind::GroupEndMismatch { open, found }
            if open.as_inner() == 1 && found.as_inner() == 3
    ));
    // The open group clipped at the cut: interior ends where the
    // bad record began.
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.indexed_end(), 1);

    // A group left open by the stream's end: the extent end that
    // arrived first is the stream length.
    let tree = whole(&[0x0B, 0x08, 0x01], Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    let fault = tree.fault().expect("an unclosed group faults at the end");
    assert_eq!(fault.at(), 3);
    assert!(matches!(
        fault.kind(),
        FaultKind::GroupUnclosed { open } if open.as_inner() == 1
    ));
    assert_eq!(tree.indexed_end(), 3);
    // The clipped group keeps its indexed interior.
    let top: Vec<_> = tree.top().collect();
    assert_eq!(top.len(), 1);
    assert_eq!(tree.children(top[0]).count(), 1);
    assert!(matches!(
        tree.source_spans(top[0]),
        super::RecordSpans::ClippedGroup { interior, .. }
            if interior.start() == 1 && interior.end() == 3
    ));

    // A group unterminated at a LEN's seal, committed: the fault
    // sits at the seal, not the stream end.
    let mut advice = CommitAll;
    let tree = whole(&[0x12, 0x01, 0x0B], Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let fault = tree.fault().expect("a group crossing a seal faults there");
    assert_eq!(fault.at(), 3);
    assert!(matches!(
        fault.kind(),
        FaultKind::GroupUnclosed { open } if open.as_inner() == 1
    ));
    assert_eq!(tree.node_count(), 2);

    // When the seal cuts a word inside the open group instead, the
    // word's own truncation wins — the buffered order (the read
    // refuses before the extent-end walk runs).
    let mut advice = CommitAll;
    let tree =
        whole(&[0x12, 0x02, 0x0B, 0x08], Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let fault = tree.fault().expect("the cut interior word faults");
    assert_eq!(fault.at(), 4);
    assert!(matches!(
        fault.kind(),
        FaultKind::Read { stage: Stage::Value { field }, cause: ReadFault::Truncated }
            if field.as_inner() == 1
    ));

    // A group at the depth bound.
    let tree = whole(&[0x0B, 0x13, 0x14, 0x0C], Standard::Tolerant, DepthLimit::MIN, &mut NoAdvice);
    let fault = tree.fault().expect("a group past the bound refuses");
    assert_eq!(fault.at(), 1);
    assert!(matches!(
        fault.kind(),
        FaultKind::DepthExceeded { field, limit }
            if field.as_inner() == 2 && limit == DepthLimit::MIN
    ));
}

// ─── the root transaction's grouped face ───

#[test]
fn a_root_len_under_open_groups_rides_the_one_transaction() {
    // Groups seal no extent, so the LEN met inside an open root
    // group still opens the transaction; an underfill restores the
    // checkpoint, and the enclosing group clips at the overrun's
    // cut — the buffered geometry exactly.
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x0B, 0x12, 0x02, 0x08]).unwrap();
    let tree = collector.finish();
    let fault = tree.fault().expect("the underfilled declaration faults");
    assert_eq!(fault.at(), 2);
    assert!(matches!(
        fault.kind(),
        FaultKind::LenOverrun { field, declared, zone_left: 1 }
            if field.as_inner() == 2 && declared.as_inner() == 2
    ));
    // The speculative interior rows evaporated; the group row
    // survived the restoration and clipped at the LEN's start.
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.indexed_end(), 1);
    let group = tree.top().next().unwrap();
    assert!(matches!(
        tree.source_spans(group),
        super::RecordSpans::ClippedGroup { interior, .. }
            if interior.start() == 1 && interior.end() == 1
    ));
    assert_eq!(tree.bytes(), [0x0B, 0x12, 0x02, 0x08]);

    // The proven twin: the same document completed closes clean.
    let proven = [0x0B, 0x12, 0x02, 0x08, 0x01, 0x0C];
    let tree = whole(&proven, Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    assert!(tree.is_complete());
    assert_eq!(tree.node_count(), 3);
}

#[test]
fn a_deferred_group_fault_follows_the_transaction_precedence() {
    // An orphan end tag inside the unproven extent: frozen, then
    // committed on proof — or discarded by an underfill.
    let mut advice = CommitAll;
    let doc = [0x12, 0x02, 0x0C, 0xAA];
    let tree = whole(&doc, Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let fault = tree.fault().expect("the proven extent commits its interior fault");
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::GroupEndOrphan { found } if found.as_inner() == 1));
    assert_eq!(tree.indexed_end(), 2);
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.bytes(), doc);

    let mut advice = CommitAll;
    let tree = whole(&doc[..3], Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let fault = tree.fault().expect("the underfilled declaration faults");
    assert_eq!(fault.at(), 1);
    assert!(matches!(
        fault.kind(),
        FaultKind::LenOverrun { field, declared, zone_left: 1 }
            if field.as_inner() == 2 && declared.as_inner() == 2
    ));
    assert_eq!(tree.node_count(), 0);
}

#[test]
fn a_group_open_inside_the_unproven_extent_defers_its_unclosed_fault() {
    // The group opens inside the transaction and never closes
    // before the declared endpoint: at the seal the unterminated
    // group is judged — deferred if unproven, committed on proof.
    let mut advice = CommitAll;
    let doc = [0x12, 0x03, 0x0B, 0x08, 0x01];
    let tree = whole(&doc, Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let fault = tree.fault().expect("the group crossing the proven seal faults");
    assert_eq!(fault.at(), 5);
    assert!(matches!(
        fault.kind(),
        FaultKind::GroupUnclosed { open } if open.as_inner() == 1
    ));
    assert_eq!(tree.indexed_end(), 5);
    // LEN row, group row (clipped at the seal), interior varint.
    assert_eq!(tree.node_count(), 3);

    // The underfilled twin discards the interior story whole.
    let mut advice = CommitAll;
    let tree = whole(&doc[..4], Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let fault = tree.fault().expect("the underfilled declaration faults");
    assert!(matches!(
        fault.kind(),
        FaultKind::LenOverrun { field, .. } if field.as_inner() == 2
    ));
    assert_eq!(tree.node_count(), 0);
}

// ─── end-of-stream judgments ───

#[test]
fn the_end_of_stream_names_the_cut_construct_exactly() {
    /// One pin: bytes, the fault position, and the kind judge.
    type FaultPin = (&'static [u8], u32, fn(FaultKind) -> bool);
    let pins: &[FaultPin] = &[
        // A group's interior varint cut by the end (the group
        // clips at the word's cut).
        (&[0x0B, 0x18], 2, |k| {
            matches!(
                k,
                FaultKind::Read { stage: Stage::Value { field }, cause: ReadFault::Truncated }
                    if field.as_inner() == 3
            )
        }),
        // A nested open tag cut mid-word... a second group open
        // then a partial LEN prefix.
        (&[0x13, 0x1A], 2, |k| {
            matches!(
                k,
                FaultKind::Read { stage: Stage::LenPrefix { field }, cause: ReadFault::Truncated }
                    if field.as_inner() == 3
            )
        }),
    ];
    for &(bytes, at, judge) in pins {
        for plan in [vec![bytes.to_vec()], bytes.iter().map(|&b| vec![b]).collect::<Vec<Vec<u8>>>()]
        {
            let tree = collect(&plan, Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
            let fault = tree.fault().expect("the cut construct faults at the end");
            assert_eq!(fault.at(), at, "position on {bytes:02X?}");
            assert!(judge(fault.kind()), "kind on {bytes:02X?}: {:?}", fault.kind());
        }
    }

    // The bare open group: unclosed at the stream end, its clipped
    // row empty.
    let tree = whole(&[0x0B], Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    let fault = tree.fault().expect("an open group never closes");
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::GroupUnclosed { open } if open.as_inner() == 1));
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.indexed_end(), 1);
}

// ─── custody ───

#[test]
fn every_feed_after_a_latched_fault_still_absorbs_wholly() {
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x0C]).unwrap(); // an orphan end tag latches
    let suffix = [0x13, 0x18, 0x01, 0x14, 0x08, 0x2A];
    for chunk in suffix.chunks(2) {
        collector.feed(chunk).unwrap();
    }
    let tree = collector.finish();
    let fault = tree.fault().expect("the latched fault publishes");
    assert!(matches!(fault.kind(), FaultKind::GroupEndOrphan { .. }));
    assert_eq!(tree.indexed_end(), 0);
    let mut offered = vec![0x0C];
    offered.extend_from_slice(&suffix);
    assert_eq!(tree.bytes(), offered);
}

#[test]
fn a_feed_refusal_owns_the_prior_feeds_and_none_of_the_chunk() {
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x0B, 0x0C]).unwrap();
    let refused = collector.feed_capped(&[0x08, 0x2A], 3).unwrap_err();
    assert_eq!(refused.attempted_end(), 4);
    assert_eq!(refused.source(), [0x0B, 0x0C]);
}

#[test]
#[should_panic(expected = "collector already terminal")]
fn a_spent_shell_refuses_another_feed() {
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let _refused = collector.feed_capped(&[0x0B], 0).unwrap_err();
    let _ = collector.feed(&[0x0C]);
}

#[test]
fn a_cap_refusal_outranks_a_latched_wire_fault() {
    // A wire fault latched the tail; a later feed that would leave
    // the coordinate class still refuses at the pre-read gate.
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x0C]).unwrap(); // the orphan end tag latches
    collector.feed(&[0xAA, 0xBB]).unwrap();
    let refused = collector.feed_capped(&[0xCC, 0xDD], 4).unwrap_err();
    assert_eq!(refused.attempted_end(), 5);
    assert_eq!(refused.source(), [0x0C, 0xAA, 0xBB]);
}

// ─── the word fold against the carry kernel ───

/// A scratch core over `advice`, zoned at `zone`, with `capacity`
/// reserved (the stepper's push contract).
fn scratch_core(advice: &mut NoAdvice, zone: u32, capacity: usize) -> super::Core<'_, NoAdvice> {
    super::Core {
        source: Vec::with_capacity(capacity),
        rows: Vec::new(),
        zone,
        word: super::WordCarry::new(),
        state: super::ParseState::Live(super::Resume::Head),
        stack: Vec::new(),
        path: Vec::new(),
        nearest_absorber: None,
        root_len: None,
        standard: Standard::Tolerant,
        limit: DepthLimit::REFERENCE,
        advice,
    }
}

/// Consumes a carry-kernel completion into the plain verdict the
/// differentials compare on (value out, carry emptied).
fn spent_value(
    step: crate::varint::carry::Step<crate::varint::carry::Complete<'_, u64>>,
) -> crate::varint::carry::Step<u64> {
    use crate::varint::carry::Step;
    match step {
        Step::Done(complete) => Step::Done(complete.take()),
        Step::More => Step::More,
        Step::Cut => Step::Cut,
        Step::TooWide => Step::TooWide,
        Step::OutOfClass => Step::OutOfClass,
    }
}

#[test]
fn the_word_fold_matches_the_carry_kernel_byte_for_byte() {
    use crate::varint::carry::{Carry, Step as CarryStep};

    let mut cases: Vec<(Vec<u8>, u32)> = Vec::new();
    for width in 1..=10usize {
        let mut doc = vec![0x80; width];
        doc[width - 1] = 0x01;
        cases.push((doc, u32::MAX));
    }
    cases.push((vec![0x80; 11], u32::MAX));
    {
        let mut wrap = vec![0x80; 9];
        wrap.push(0x02);
        cases.push((wrap, u32::MAX));
    }
    cases.push((vec![0x80, 0x80, 0x80], 2));
    cases.push((vec![0x80, 0x01, 0xFF], 2));

    for (doc, zone) in &cases {
        for step in 1..=doc.len() {
            let mut carry = Carry::new();
            let mut off = 0u64;
            let mut reference = None;
            for chunk in doc.chunks(step) {
                let mut chunk = chunk;
                match spent_value(carry.step_value64(&mut chunk, &mut off, u64::from(*zone))) {
                    CarryStep::More => {}
                    settled => {
                        reference = Some(settled);
                        break;
                    }
                }
            }
            let mut advice = NoAdvice;
            let mut core = scratch_core(&mut advice, *zone, doc.len());
            let mut mine = None;
            'feed: for chunk in doc.chunks(step) {
                let mut rest = chunk;
                match core.step_word::<crate::varint::ValueWidth, { crate::varint::MAX_LEN64 }, { crate::varint::LAST64 }, true>(
                    &mut rest,
                ) {
                    super::StepWord::More => continue 'feed,
                    settled => {
                        mine = Some(settled);
                        break 'feed;
                    }
                }
            }
            let consumed = core.source.len();
            match (reference, &mine) {
                (Some(CarryStep::Done(value)), Some(super::StepWord::Done { value: v, width })) => {
                    assert_eq!(
                        (value, u64::from(width.as_inner())),
                        (*v, off),
                        "{doc:02X?} step {step}"
                    );
                }
                (Some(CarryStep::Cut), Some(super::StepWord::Cut))
                | (Some(CarryStep::TooWide), Some(super::StepWord::TooWide))
                | (Some(CarryStep::OutOfClass), Some(super::StepWord::OutOfClass)) => {}
                (reference, _) => {
                    panic!("kernel divergence on {doc:02X?} step {step}: carry {reference:?}")
                }
            }
            assert_eq!(u64::try_from(consumed).unwrap(), off, "{doc:02X?} step {step}");
            assert_eq!(core.source, doc[..consumed], "{doc:02X?} step {step}");
        }
    }
}

// ─── the buffered twin (private and public differentials) ───

#[cfg(feature = "retain-grouped")]
mod twin {
    use alloc::format;

    use super::*;
    use crate::collect::NodeId;
    use crate::retain::grouped::Retained as Buffered;
    use crate::retain::{self, NoAdvice as BufferedNoAdvice};

    /// One pure path-sensitive answer both supply traits share:
    /// f3 is opaque bytes everywhere, f2 commits at the root,
    /// f1 commits only under an f2 container, everything else
    /// speculates.
    fn path_answer(outermost: Option<u32>, field: u32) -> Advice {
        match (outermost, field) {
            (_, 3) => Advice::Opaque,
            (None, 2) | (Some(2), 1) => Advice::Commit,
            _ => Advice::Speculate,
        }
    }

    /// The collect side of the path-sensitive advisor.
    struct PathPin;

    impl Advisor for PathPin {
        fn advise(&mut self, ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
            path_answer(ancestry.fields().next().map(FieldNumber::as_inner), field.as_inner())
        }
    }

    impl retain::Advisor for PathPin {
        fn advise(&mut self, ancestry: retain::Ancestry<'_>, field: FieldNumber) -> retain::Advice {
            match path_answer(ancestry.fields().next().map(FieldNumber::as_inner), field.as_inner())
            {
                Advice::Speculate => retain::Advice::Speculate,
                Advice::Commit => retain::Advice::Commit,
                Advice::Opaque => retain::Advice::Opaque,
            }
        }
    }

    /// The retain side of the shared field-keyed advisor.
    impl retain::Advisor for Pin {
        fn advise(
            &mut self,
            _ancestry: retain::Ancestry<'_>,
            field: FieldNumber,
        ) -> retain::Advice {
            match field.as_inner() {
                2 => retain::Advice::Commit,
                3 => retain::Advice::Opaque,
                _ => retain::Advice::Speculate,
            }
        }
    }

    /// Every private and public face of the collected product
    /// against the buffered parse of the concatenated bytes.
    fn agree<CA: Advisor, BA: retain::Advisor>(
        plan: &[Vec<u8>],
        bytes: &[u8],
        standard: Standard,
        depth: DepthLimit,
        ca: &mut CA,
        ba: &mut BA,
    ) {
        let mine = collect(plan, standard, depth, ca);
        let twin = Buffered::parse_standard(bytes.to_vec(), standard, depth, ba)
            .expect("corpus documents sit inside the coordinate class");

        // The private finished-index differential.
        assert_eq!(mine.snapshot(), twin.snapshot(), "snapshots diverge on {bytes:02X?}");

        // The public query parity.
        assert_eq!(mine.bytes(), twin.bytes());
        assert_eq!(mine.is_complete(), twin.is_complete());
        assert_eq!(mine.indexed_end(), twin.indexed_end());
        assert_eq!(mine.node_count(), twin.node_count());
        assert_eq!(mine.is_empty(), twin.is_empty());
        match (mine.fault(), twin.fault()) {
            (None, None) => {}
            (Some(mf), Some(tf)) => {
                assert_eq!(mf.at(), tf.at());
                assert_eq!(format!("{:?}", mf.kind()), format!("{:?}", tf.kind()));
                assert_eq!(format!("{:?}", mf.kind().class()), format!("{:?}", tf.kind().class()));
            }
            (mf, tf) => panic!("fault presence disagrees: {mf:?} vs {tf:?}"),
        }

        let mine_ids: Vec<u32> = mine.nodes().map(NodeId::as_inner).collect();
        let twin_ids: Vec<u32> = twin.nodes().map(retain::NodeId::as_inner).collect();
        assert_eq!(mine_ids, twin_ids, "preorder tables must align");

        for (mid, tid) in mine.nodes().zip(twin.nodes()) {
            assert_eq!(mine.field(mid), twin.field(tid));
            assert_eq!(mine.kind(mid), twin.kind(tid));
            assert_eq!(mine.span(mid), twin.span(tid));
            assert_eq!(
                format!("{:?}", mine.source_spans(mid)),
                format!("{:?}", twin.source_spans(tid))
            );
            assert_eq!(
                mine.parent(mid).map(NodeId::as_inner),
                twin.parent(tid).map(retain::NodeId::as_inner)
            );
            assert_eq!(mine.record_bytes(mid), twin.record_bytes(tid));
            assert_eq!(mine.payload_bytes(mid), twin.payload_bytes(tid));
            assert_eq!(mine.varint_word(mid), twin.varint_word(tid));
            assert_eq!(mine.i32_bits(mid), twin.i32_bits(tid));
            assert_eq!(mine.i64_bits(mid), twin.i64_bits(tid));
            let mine_children: Vec<u32> = mine.children(mid).map(NodeId::as_inner).collect();
            let twin_children: Vec<u32> =
                twin.children(tid).map(retain::NodeId::as_inner).collect();
            assert_eq!(mine_children, twin_children);
            let mine_desc: Vec<u32> = mine.descendants(mid).map(NodeId::as_inner).collect();
            let twin_desc: Vec<u32> = twin.descendants(tid).map(retain::NodeId::as_inner).collect();
            assert_eq!(mine_desc, twin_desc);
            let mine_anc: Vec<u32> = mine.ancestors(mid).map(NodeId::as_inner).collect();
            let twin_anc: Vec<u32> = twin.ancestors(tid).map(retain::NodeId::as_inner).collect();
            assert_eq!(mine_anc, twin_anc);
        }

        for pos in 0..=crate::admission::admitted_u32(bytes.len()) + 1 {
            assert_eq!(
                mine.narrowest(pos).map(NodeId::as_inner),
                twin.narrowest(pos).map(retain::NodeId::as_inner),
                "narrowest({pos}) disagrees on {bytes:02X?}"
            );
        }
    }

    #[test]
    fn the_collected_product_equals_the_buffered_parse() {
        let mut corpus: Vec<Vec<u8>> =
            crate::stream_corpus::grouped_items().into_iter().map(|(bytes, _)| bytes).collect();
        corpus.extend(advised_items());
        let combos: &[(Standard, DepthLimit)] = if cfg!(miri) {
            &[
                (Standard::Tolerant, DepthLimit::REFERENCE),
                (Standard::CanonicalMinimal, DepthLimit::MIN),
            ]
        } else {
            &[
                (Standard::Tolerant, DepthLimit::REFERENCE),
                (Standard::Tolerant, DepthLimit::MIN),
                (Standard::CanonicalMinimal, DepthLimit::REFERENCE),
                (Standard::CanonicalMinimal, DepthLimit::MIN),
            ]
        };
        for bytes in &corpus {
            if cfg!(miri) && bytes.len() > 24 {
                continue;
            }
            for &(standard, depth) in combos {
                for plan in plans_for(bytes) {
                    agree(&plan, bytes, standard, depth, &mut NoAdvice, &mut BufferedNoAdvice);
                    agree(&plan, bytes, standard, depth, &mut Pin, &mut Pin);
                    agree(&plan, bytes, standard, depth, &mut PathPin, &mut PathPin);
                }
            }
        }
    }
}
