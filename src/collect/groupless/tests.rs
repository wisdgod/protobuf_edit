//! The groupless collector's module suite: chunk-independence over
//! the boundary corpus (the finished product never varies with the
//! feed plan), exact end-of-stream and precedence pins for the
//! root-layer LEN transaction, custody rows, and the fault-latch
//! rows.

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

/// The feed plans a document is swept under. Native runs take the
/// corpus's full plan set (whole, every split, byte-at-a-time,
/// empties interspersed); Miri keeps the shapes but trims the
/// per-split family to three cuts.
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

/// The advice-sensitive documents the flat corpus cannot spell:
/// nested LENs under each advice pole, speculation absorbing a
/// malformed interior (rollback landing inside and across chunk
/// edges), demotion at the depth bound, faults followed by
/// large legal-looking suffixes, and the root-transaction shapes.
fn advised_items() -> Vec<Vec<u8>> {
    let mut items: Vec<Vec<u8>> = vec![
        // Nested LENs three deep: f2 { f2 { f1 varint } } — commits
        // under Pin, speculates open under NoAdvice.
        vec![0x12, 0x06, 0x12, 0x04, 0x12, 0x02, 0x08, 0x01],
        // LEN f3: opaque under Pin, speculated open under NoAdvice.
        vec![0x1A, 0x02, 0x08, 0x01],
        // LEN f1 whose payload is not a message: speculation
        // absorbs mid-interior (the rollback row).
        vec![0x0A, 0x02, 0xFF, 0x01],
        // Speculation failing at the interior's very last byte.
        vec![0x0A, 0x03, 0x08, 0x01, 0xFF],
        // Speculation failing at the interior's first byte, with a
        // legal suffix record resuming in the same stream.
        vec![0x0A, 0x01, 0xFF, 0x08, 0x2A],
        // A committed interior fault (f2 commits under Pin).
        vec![0x12, 0x01, 0x08],
        // Padded framing: padded tag, padded value — tolerant rides
        // them, canonical faults at the first.
        vec![0x88, 0x00, 0x96, 0x01],
        vec![0x08, 0x96, 0x81, 0x00],
        // Truncated at the root: legal prefix plus a fault.
        vec![0x08, 0x96, 0x01, 0x08],
        // A group code: this dialect's capability refusal, then a
        // large legal-looking suffix that must still absorb.
        vec![0x0B, 0x0C, 0x08, 0x2A, 0x12, 0x02, 0x68, 0x69],
        // A declared length puncturing a finite seal: LEN f1 wraps
        // a LEN f2 whose declaration overruns f1's zone.
        vec![0x0A, 0x03, 0x12, 0x05, 0x01],
        // The root-transaction shapes: underfilled, exactly filled,
        // deferred interior fault (proven and unproven), and the
        // padded-prefix precedence document.
        vec![0x12, 0x02, 0x08],
        vec![0x12, 0x02, 0x08, 0x96],
        vec![0x12, 0x03, 0x00, 0xAA, 0xBB],
        vec![0x12, 0x03, 0x00, 0xAA],
        vec![0x12, 0x85, 0x80, 0x00],
        // An underfilled root LEN whose partial interior holds
        // complete records (restoration truncates them).
        vec![0x12, 0x06, 0x08, 0x01, 0x08, 0x02],
        // Exactly filled with an interior varint spanning the seal
        // proof byte.
        vec![0x12, 0x03, 0x08, 0x96, 0x01],
        // An empty LEN at the root (a zero-length transaction).
        vec![0x12, 0x00, 0x08, 0x2A],
        // A guaranteed overrun: the declared endpoint leaves the
        // coordinate class, and later bytes only collect.
        vec![0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0xAA, 0xBB],
    ];
    // Depth edges: nesting one past and exactly at a small bound is
    // exercised by sweeping these under `DepthLimit::MIN` below.
    items.push(vec![0x12, 0x04, 0x12, 0x02, 0xAA, 0xBB]);
    items
}

#[test]
fn the_finished_product_never_varies_with_the_feed_plan() {
    let mut corpus: Vec<Vec<u8>> =
        stream_corpus::groupless_items().into_iter().map(|(bytes, _)| bytes).collect();
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
fn speculated_interiors_are_indexed_and_demotions_conclude_bytes() {
    // f2 { f2 { f1 varint } } under NoAdvice: full-depth
    // speculation indexes every level.
    let bytes = [0x12, 0x06, 0x12, 0x04, 0x12, 0x02, 0x08, 0x01];
    let tree = whole(&bytes, Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    assert!(tree.is_complete());
    assert_eq!(tree.node_count(), 4);
    let top: Vec<_> = tree.top().collect();
    assert_eq!(top.len(), 1);
    assert_eq!(tree.descendants(top[0]).count(), 3);

    // The same document at the depth floor: the outermost level
    // still speculates (one frame), the next demotes to opaque.
    let shallow = whole(&bytes, Standard::Tolerant, DepthLimit::MIN, &mut NoAdvice);
    assert!(shallow.is_complete());
    assert_eq!(shallow.node_count(), 2);

    // A payload that is not a message concludes bytes: the leaf
    // keeps its declared span and the suffix record resumes.
    let absorbed = [0x0A, 0x01, 0xFF, 0x08, 0x2A];
    let tree = whole(&absorbed, Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    assert!(tree.is_complete());
    let top: Vec<_> = tree.top().collect();
    assert_eq!(top.len(), 2);
    assert_eq!(tree.payload_bytes(top[0]), [0xFF]);
    assert_eq!(tree.varint_word(top[1]), Some(42));
}

// ─── the root-transaction precedence probes ───

#[test]
fn an_underfilled_root_len_outranks_its_partial_interior() {
    // The declared endpoint is never proven: the outer overrun
    // stands — not the interior word the stream also cut — and the
    // speculative interior rows evaporate.
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x12, 0x02, 0x08]).unwrap();
    let tree = collector.finish();
    let fault = tree.fault().expect("an underfilled declaration faults");
    assert_eq!(fault.at(), 1);
    assert!(matches!(
        fault.kind(),
        FaultKind::LenOverrun { field, declared, zone_left: 1 }
            if field.as_inner() == 2 && declared.as_inner() == 2
    ));
    assert_eq!(tree.node_count(), 0);
    assert_eq!(tree.indexed_end(), 0);
    assert_eq!(tree.bytes(), [0x12, 0x02, 0x08]);
}

#[test]
fn a_proven_seal_lets_the_interior_truncation_win() {
    // The same declaration receives its second byte: the extent is
    // proven, so the interior word cut at the now-final seal is the
    // real fault (committed advice keeps it unabsorbed).
    let mut advice = CommitAll;
    let tree =
        whole(&[0x12, 0x02, 0x08, 0x96], Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let fault = tree.fault().expect("the committed interior truncation surfaces");
    assert_eq!(fault.at(), 3);
    assert!(matches!(
        fault.kind(),
        FaultKind::Read { stage: Stage::Value { field }, cause: ReadFault::Truncated }
            if field.as_inner() == 1
    ));
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.indexed_end(), 2);

    // Under speculation the same interior fault absorbs: the LEN
    // demotes to an opaque leaf and the product completes.
    let tree =
        whole(&[0x12, 0x02, 0x08, 0x96], Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    assert!(tree.is_complete());
    assert_eq!(tree.node_count(), 1);
    let leaf = tree.top().next().unwrap();
    assert_eq!(tree.payload_bytes(leaf), [0x08, 0x96]);
}

#[test]
fn a_padded_prefix_outranks_the_endpoint_under_canonical() {
    // The prefix's width is judged the moment it completes — the
    // buffered order — so the canonical refusal stands even though
    // the declared endpoint would also underfill at the end.
    let mut advice = NoAdvice;
    let mut collector =
        Collector::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x12, 0x85, 0x80, 0x00]).unwrap();
    let tree = collector.finish();
    let fault = tree.fault().expect("the padded prefix refuses");
    assert_eq!(fault.at(), 1);
    assert!(
        matches!(fault.kind(), FaultKind::NonMinimalLen { field } if field.as_inner() == 2),
        "expected the width refusal, got {:?}",
        fault.kind()
    );
    // Tolerant collection of the same bytes reaches the endpoint
    // judgment instead and reports the underfill.
    let tree =
        whole(&[0x12, 0x85, 0x80, 0x00], Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    assert!(matches!(tree.fault().unwrap().kind(), FaultKind::LenOverrun { .. }));
}

// ─── the deferred interior faults ───

#[test]
fn a_deferred_interior_fault_commits_once_the_extent_proves() {
    // FieldZero inside the unproven extent: frozen, the remaining
    // body copies, and the proof commits the buffered verdict.
    let mut advice = CommitAll;
    let tree = whole(
        &[0x12, 0x03, 0x00, 0xAA, 0xBB],
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &mut advice,
    );
    let fault = tree.fault().expect("the proven extent commits its interior fault");
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::FieldZero { .. }));
    assert_eq!(tree.indexed_end(), 2);
    assert_eq!(tree.node_count(), 1);
    assert_eq!(tree.bytes(), [0x12, 0x03, 0x00, 0xAA, 0xBB]);
}

#[test]
fn an_underfilled_extent_discards_its_deferred_fault() {
    // The same interior fault, but the stream ends one byte short:
    // the buffered parse would never have descended, so the outer
    // overrun overrides the frozen interior fault.
    let mut advice = CommitAll;
    let tree =
        whole(&[0x12, 0x03, 0x00, 0xAA], Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let fault = tree.fault().expect("the underfilled declaration faults");
    assert_eq!(fault.at(), 1);
    assert!(matches!(
        fault.kind(),
        FaultKind::LenOverrun { field, declared, zone_left: 2 }
            if field.as_inner() == 2 && declared.as_inner() == 3
    ));
    assert_eq!(tree.node_count(), 0);
    assert_eq!(tree.indexed_end(), 0);
}

#[test]
fn a_deferred_depth_refusal_follows_the_same_precedence() {
    // A committed container at the bound inside the unproven
    // extent: deferred, then committed on proof / discarded on
    // underfill.
    let mut advice = CommitAll;
    let doc = [0x12, 0x04, 0x12, 0x02, 0xAA, 0xBB];
    let tree = whole(&doc, Standard::Tolerant, DepthLimit::MIN, &mut advice);
    let fault = tree.fault().expect("the committed depth claim refuses");
    assert_eq!(fault.at(), 2);
    assert!(matches!(
        fault.kind(),
        FaultKind::DepthExceeded { field, limit }
            if field.as_inner() == 2 && limit == DepthLimit::MIN
    ));
    assert_eq!(tree.indexed_end(), 2);
    assert_eq!(tree.node_count(), 1);

    let mut advice = CommitAll;
    let tree = whole(&doc[..5], Standard::Tolerant, DepthLimit::MIN, &mut advice);
    let fault = tree.fault().expect("the underfilled outer declaration faults");
    assert!(matches!(fault.kind(), FaultKind::LenOverrun { field, .. } if field.as_inner() == 2));
    assert_eq!(tree.node_count(), 0);
}

// ─── the guaranteed overrun ───

/// An advisor that must never be consulted.
struct Untouchable;

impl Advisor for Untouchable {
    fn advise(&mut self, _ancestry: Ancestry<'_>, _field: FieldNumber) -> Advice {
        panic!("a guaranteed-overrun site must not consult the advisor");
    }
}

#[test]
fn a_declared_endpoint_past_the_class_collects_without_consulting() {
    // The declaration reaches past `i32::MAX`: no admissible
    // stream fills it, so the site is never advised, later bytes
    // only collect, and the end constructs the exact overrun.
    let mut advice = Untouchable;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0x07]).unwrap();
    collector.feed(&[0xAA, 0xBB, 0xCC]).unwrap();
    let tree = collector.finish();
    let fault = tree.fault().expect("the class-topping declaration overruns");
    assert_eq!(fault.at(), 1);
    assert!(matches!(
        fault.kind(),
        FaultKind::LenOverrun { field, declared, zone_left: 3 }
            if field.as_inner() == 2 && declared.as_inner() == 0x7FFF_FFFF
    ));
    assert_eq!(tree.node_count(), 0);
    assert_eq!(tree.bytes().len(), 9);
}

// ─── end-of-stream judgments (buffered parity, pinned by hand) ───

#[test]
fn the_end_of_stream_names_the_cut_construct_exactly() {
    // Each pin: bytes, fault position, and the exact kind — the
    // coordinates a buffered parse of the same bytes reports at
    // its extent end. Swept whole and byte-at-a-time.
    /// One pin: bytes, the fault position, and the kind judge.
    type FaultPin = (&'static [u8], u32, fn(FaultKind) -> bool);
    let pins: &[FaultPin] = &[
        // A tag cut mid-word.
        (&[0x80], 0, |k| {
            matches!(k, FaultKind::Read { stage: Stage::Tag, cause: ReadFault::Truncated })
        }),
        // A value cut by the stream end.
        (&[0x08], 1, |k| {
            matches!(
                k,
                FaultKind::Read { stage: Stage::Value { field }, cause: ReadFault::Truncated }
                    if field.as_inner() == 1
            )
        }),
        // A length prefix cut mid-word.
        (&[0x12, 0x80], 1, |k| {
            matches!(
                k,
                FaultKind::Read { stage: Stage::LenPrefix { field }, cause: ReadFault::Truncated }
                    if field.as_inner() == 2
            )
        }),
        // A fixed payload still owed bytes.
        (
            &[0x0D, 0x01, 0x02],
            1,
            |k| matches!(k, FaultKind::FixedTruncated { field, needed: 4 } if field.as_inner() == 1),
        ),
        (
            &[0x09, 0x01],
            1,
            |k| matches!(k, FaultKind::FixedTruncated { field, needed: 8 } if field.as_inner() == 1),
        ),
    ];
    for &(bytes, at, judge) in pins {
        for plan in [vec![bytes.to_vec()], bytes.iter().map(|&b| vec![b]).collect::<Vec<Vec<u8>>>()]
        {
            let tree = collect(&plan, Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
            let fault = tree.fault().expect("the cut construct faults at the end");
            assert_eq!(fault.at(), at, "position on {bytes:02X?}");
            assert!(judge(fault.kind()), "kind on {bytes:02X?}: {:?}", fault.kind());
            assert_eq!(tree.node_count(), 0);
            assert_eq!(tree.indexed_end(), 0);
            assert_eq!(tree.bytes(), bytes);
        }
    }

    // The clean boundary: an empty stream and a complete record.
    let tree = whole(&[], Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    assert!(tree.is_complete() && tree.is_empty());
    let tree = whole(&[0x08, 0x2A], Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
    assert!(tree.is_complete());
    assert_eq!(tree.indexed_end(), 2);
}

// ─── custody ───

#[test]
fn every_feed_after_a_latched_fault_still_absorbs_wholly() {
    // The first record faults (field zero); the index clips, and a
    // large legal-looking suffix — fed across several chunks —
    // still lands in the source byte for byte.
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x00]).unwrap();
    let suffix = [0x08, 0x2A, 0x12, 0x02, 0x68, 0x69, 0x0D, 1, 2, 3, 4];
    for chunk in suffix.chunks(3) {
        collector.feed(chunk).unwrap();
    }
    assert_eq!(collector.offset(), 12);
    let tree = collector.finish();
    let fault = tree.fault().expect("the latched fault publishes");
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::FieldZero { .. }));
    assert_eq!(tree.indexed_end(), 0);
    let mut offered = vec![0x00];
    offered.extend_from_slice(&suffix);
    assert_eq!(tree.bytes(), offered);
}

#[test]
fn the_abandonment_door_returns_the_accumulated_backing() {
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x08, 0x96]).unwrap(); // a value still in flight
    assert_eq!(collector.offset(), 2);
    assert_eq!(collector.into_source(), [0x08, 0x96]);
}

#[test]
fn a_feed_refusal_owns_the_prior_feeds_and_none_of_the_chunk() {
    // The refusal path under a module-scoped cap: the returned
    // source is exactly the prior feeds, and appending the refused
    // chunk reconstructs the offered stream.
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x08, 0x2A]).unwrap();
    let refused = collector.feed_capped(&[0x12, 0x02, 0x68], 4).unwrap_err();
    assert_eq!(refused.attempted_end(), 5);
    assert_eq!(refused.source(), [0x08, 0x2A]);
    let mut offered = refused.into_source();
    offered.extend_from_slice(&[0x12, 0x02, 0x68]);
    assert_eq!(offered, [0x08, 0x2A, 0x12, 0x02, 0x68]);
}

#[test]
#[should_panic(expected = "collector already terminal")]
fn a_spent_shell_refuses_another_feed() {
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    let _refused = collector.feed_capped(&[0x08], 0).unwrap_err();
    let _ = collector.feed(&[0x08]);
}

#[test]
fn a_capacity_hint_past_the_class_refuses_before_allocating() {
    let mut advice = NoAdvice;
    let refused = Collector::with_capacity(
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &mut advice,
        usize::MAX,
    );
    // The refused hint reports at the platform's own width.
    let requested = u64::try_from(usize::MAX).unwrap();
    assert!(matches!(refused, Err(oversize) if oversize.requested() == requested));
}

#[test]
fn the_source_moves_out_of_the_finished_product_without_a_copy() {
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x08, 0x2A, 0x12, 0x02, 0x68, 0x69]).unwrap();
    let tree = collector.finish();
    let addr = tree.bytes().as_ptr().addr();
    let back = tree.into_bytes();
    assert_eq!(back.as_ptr().addr(), addr, "release must move the source, not copy it");
    assert_eq!(back, [0x08, 0x2A, 0x12, 0x02, 0x68, 0x69]);
}

#[test]
fn a_cap_refusal_outranks_a_latched_wire_fault() {
    // A wire fault latched the tail; a later feed that would leave
    // the coordinate class still refuses at the pre-read gate —
    // the source holds exactly the absorbed feeds, and appending
    // the refused chunk reconstructs the offered stream.
    let mut advice = NoAdvice;
    let mut collector = Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    collector.feed(&[0x00]).unwrap(); // FieldZero latches
    collector.feed(&[0xAA, 0xBB]).unwrap(); // tail bytes absorb
    let refused = collector.feed_capped(&[0xCC, 0xDD], 4).unwrap_err();
    assert_eq!(refused.attempted_end(), 5);
    assert_eq!(refused.source(), [0x00, 0xAA, 0xBB]);
    let mut offered = refused.into_source();
    offered.extend_from_slice(&[0xCC, 0xDD]);
    assert_eq!(offered, [0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
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

    // Every Done width, the continuation overflow, the class edge,
    // and seal cuts — under every chunking — against the carry
    // kernel's verdicts, consumption, and bank, and against the
    // buffered slice reader's value on the assembled corpus.
    let mut cases: Vec<(Vec<u8>, u32)> = Vec::new();
    for width in 1..=10usize {
        let mut doc = vec![0x80; width];
        doc[width - 1] = 0x01;
        cases.push((doc, u32::MAX));
    }
    for width in 2..=10usize {
        // Padded spellings of one: tolerant lawful wire.
        let mut doc = vec![0x81];
        doc.extend(vec![0x80; width - 2]);
        doc.push(0x00);
        cases.push((doc, u32::MAX));
    }
    cases.push((vec![0x80; 11], u32::MAX)); // continuation overflow
    {
        let mut wrap = vec![0x80; 9];
        wrap.push(0x02); // the u64 class edge
        cases.push((wrap, u32::MAX));
    }
    cases.push((vec![0x80, 0x80, 0x80], 2)); // a sealed cut
    cases.push((vec![0x80, 0x01, 0xFF], 2)); // terminating exactly at the seal

    for (doc, zone) in &cases {
        for step in 1..=doc.len() {
            // The reference: the carry kernel over the same chunks.
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
            // The collect fold over the same chunks, into a
            // reserved backing.
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
                    // The buffered slice reader agrees on the
                    // assembled value and width.
                    let (sv, sw) = crate::varint::slice::value64(doc, 0, doc.len()).unwrap();
                    assert_eq!((sv, sw), (*v, width.as_inner()));
                    // The minimality judgment both engines share.
                    assert_eq!(
                        width.w() > crate::varint::encoded_len64(*v),
                        u32::from(sw) > crate::varint::encoded_len64(sv)
                    );
                }
                (Some(CarryStep::Cut), Some(super::StepWord::Cut))
                | (Some(CarryStep::TooWide), Some(super::StepWord::TooWide))
                | (Some(CarryStep::OutOfClass), Some(super::StepWord::OutOfClass)) => {}
                (reference, mine) => panic!(
                    "kernel divergence on {doc:02X?} step {step}: carry {reference:?}, fold {}",
                    mine.as_ref().map_or("never settled", |step| match step {
                        super::StepWord::Done { .. } => "Done",
                        super::StepWord::More => "More",
                        super::StepWord::Cut => "Cut",
                        super::StepWord::TooWide => "TooWide",
                        super::StepWord::OutOfClass => "OutOfClass",
                    })
                ),
            }
            // The banked bytes are exactly the consumed prefix, in
            // the final backing.
            assert_eq!(u64::try_from(consumed).unwrap(), off, "{doc:02X?} step {step}");
            assert_eq!(core.source, doc[..consumed], "{doc:02X?} step {step}");
        }
    }
}

#[test]
fn the_width_only_fold_sizes_without_assembling() {
    use crate::varint::carry::{Carry, Step as CarryStep};

    // The tolerant value instance (`FOLD = false`): identical
    // verdicts, widths, consumption, and bank — the value itself
    // is deliberately not built, so `Done` carries zero.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for width in 1..=10usize {
        let mut doc = vec![0x80; width];
        doc[width - 1] = 0x01;
        cases.push(doc);
    }
    cases.push(vec![0x80; 11]);
    for doc in &cases {
        for step in 1..=doc.len() {
            let mut carry = Carry::new();
            let mut off = 0u64;
            let mut reference = None;
            for chunk in doc.chunks(step) {
                let mut chunk = chunk;
                match spent_value(carry.step_value64(&mut chunk, &mut off, u64::MAX)) {
                    CarryStep::More => {}
                    settled => {
                        reference = Some(settled);
                        break;
                    }
                }
            }
            let mut advice = NoAdvice;
            let mut core = scratch_core(&mut advice, u32::MAX, doc.len());
            let mut mine = None;
            'feed: for chunk in doc.chunks(step) {
                let mut rest = chunk;
                match core.step_word::<crate::varint::ValueWidth, { crate::varint::MAX_LEN64 }, { crate::varint::LAST64 }, false>(
                    &mut rest,
                ) {
                    super::StepWord::More => continue 'feed,
                    settled => {
                        mine = Some(settled);
                        break 'feed;
                    }
                }
            }
            match (reference, mine) {
                (Some(CarryStep::Done(_)), Some(super::StepWord::Done { value, width })) => {
                    assert_eq!(value, 0, "the width-only fold must not assemble");
                    assert_eq!(u64::from(width.as_inner()), off);
                }
                (Some(CarryStep::TooWide), Some(super::StepWord::TooWide)) => {}
                (reference, mine) => {
                    panic!(
                        "width-only divergence on {doc:02X?} step {step}: {reference:?} vs {:?}",
                        mine.map(|_| "settled")
                    )
                }
            }
        }
    }
}

// ─── the buffered twin (private and public differentials) ───

#[cfg(feature = "retain-groupless")]
mod twin {
    use alloc::format;

    use super::*;
    use crate::retain::groupless::Retained as Buffered;
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
    /// against the buffered parse of the concatenated bytes:
    /// the construction snapshot (row order and every field, the
    /// indexed end, the exact fault), then each query the product
    /// answers, ending with `narrowest` at every byte and one past
    /// the end.
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

        let mine_ids: Vec<u32> = mine.nodes().map(crate::collect::NodeId::as_inner).collect();
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
                mine.parent(mid).map(crate::collect::NodeId::as_inner),
                twin.parent(tid).map(retain::NodeId::as_inner)
            );
            assert_eq!(mine.record_bytes(mid), twin.record_bytes(tid));
            assert_eq!(mine.payload_bytes(mid), twin.payload_bytes(tid));
            assert_eq!(mine.varint_word(mid), twin.varint_word(tid));
            assert_eq!(mine.i32_bits(mid), twin.i32_bits(tid));
            assert_eq!(mine.i64_bits(mid), twin.i64_bits(tid));
            let mine_children: Vec<u32> =
                mine.children(mid).map(crate::collect::NodeId::as_inner).collect();
            let twin_children: Vec<u32> =
                twin.children(tid).map(retain::NodeId::as_inner).collect();
            assert_eq!(mine_children, twin_children);
            let mine_desc: Vec<u32> =
                mine.descendants(mid).map(crate::collect::NodeId::as_inner).collect();
            let twin_desc: Vec<u32> = twin.descendants(tid).map(retain::NodeId::as_inner).collect();
            assert_eq!(mine_desc, twin_desc);
            let mine_anc: Vec<u32> =
                mine.ancestors(mid).map(crate::collect::NodeId::as_inner).collect();
            let twin_anc: Vec<u32> = twin.ancestors(tid).map(retain::NodeId::as_inner).collect();
            assert_eq!(mine_anc, twin_anc);
        }

        for pos in 0..=crate::admission::admitted_u32(bytes.len()) + 1 {
            assert_eq!(
                mine.narrowest(pos).map(crate::collect::NodeId::as_inner),
                twin.narrowest(pos).map(retain::NodeId::as_inner),
                "narrowest({pos}) disagrees on {bytes:02X?}"
            );
        }
    }

    #[test]
    fn the_collected_product_equals_the_buffered_parse() {
        let mut corpus: Vec<Vec<u8>> =
            crate::stream_corpus::groupless_items().into_iter().map(|(bytes, _)| bytes).collect();
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

// ─── rollback across chunk edges ───

#[test]
fn speculation_unwinds_across_chunks_and_resumes_in_the_same_feed() {
    // The absorber's interior fails in a later chunk than it
    // opened in; the demoted leaf, the skip to its endpoint, and
    // the suffix record all settle without the product varying
    // from the whole-stream feed.
    let doc = [0x0A, 0x04, 0x08, 0x01, 0xFF, 0xFF, 0x08, 0x2A];
    let baseline = state(&whole(&doc, Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice));
    for split in 1..doc.len() {
        let plan = vec![doc[..split].to_vec(), doc[split..].to_vec()];
        let tree = collect(&plan, Standard::Tolerant, DepthLimit::REFERENCE, &mut NoAdvice);
        assert_eq!(state(&tree), baseline, "split {split}");
        assert!(tree.is_complete());
        assert_eq!(tree.top().count(), 2, "split {split}");
    }
}
