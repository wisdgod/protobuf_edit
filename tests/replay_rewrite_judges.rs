//! The replay rewrite cell's in-lane judge battery: zero-retention
//! allocation rows, the pass-two zero-allocation row, pass-count
//! and byte-budget honesty over a counting source, supply-refusal
//! and torn rows (the pinned equal-length residual included), and
//! the differentials against the buffered rewriter over the slice
//! source.

#![cfg(all(
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "construct-grouped"
))]
#![feature(thread_id_value)]

#[path = "support/replay.rs"]
mod replay;

use std::cell::Cell;

use protobuf_edit::path::Segment;
use protobuf_edit::replay_source::{
    Chunk, ReplayFault, ReplayPhase, ReplayWalk, SliceFault, SliceSource, StableReplaySource,
    SupplyFault,
};
use protobuf_edit::{DepthLimit, FieldNumber, replay_rewrite, rewrite};
use replay::{Counting, Refusing, WalkStats, alloc_count_now, corpus, f, measured, payload_scaled};

// ─── the swapping source (torn and residual rows) ───

/// Serves `walks[n]` to the nth walk (the last entry repeats):
/// the instrument for sources whose bytes move between the
/// measuring and the emission walk.
struct Swapping<'a> {
    walks: &'a [&'a [u8]],
    begun: Cell<u32>,
}

struct SwappingWalk<'a> {
    rest: &'a [u8],
}

impl StableReplaySource for Swapping<'_> {
    type Error = SliceFault;

    type Walk<'s>
        = SwappingWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        let nth = usize::try_from(self.begun.get()).expect("test walk counts fit usize");
        self.begun.set(self.begun.get() + 1);
        Ok(SwappingWalk { rest: self.walks[nth.min(self.walks.len() - 1)] })
    }
}

impl ReplayWalk for SwappingWalk<'_> {
    type Error = SliceFault;

    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<Self::Error>> {
        Ok(Chunk::new(self.rest))
    }

    fn consume(&mut self, n: usize) {
        self.rest = &self.rest[n..];
    }

    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<Self::Error>> {
        let take = n.min(self.rest.len() as u64);
        self.rest = &self.rest[usize::try_from(take).expect("test extents fit usize")..];
        Ok(take)
    }
}

// ─── fixtures ───

/// The grouped twin of [`payload_scaled`]: fixed record structure
/// with a group frame around the nested blob, payload sizes
/// scaling.
fn payload_scaled_grouped(payload: usize) -> Vec<u8> {
    let blob = vec![0x5Au8; payload];
    let nested = vec![0xA5u8; payload];
    let mut builder = protobuf_edit::construct::grouped::Builder::new();
    builder.push_varint(f(0), 150);
    builder.push_len(f(1), &blob);
    builder.push_i64(f(2), 7);
    builder.group(f(6), |g| {
        g.push_len_copy(f(4), &nested);
        g.push_varint(f(5), 3);
    });
    builder.finish().expect("the scaled documents stay in the LEN class")
}

/// The scaled documents' rule set: delete the i64, replace the
/// nested varint, normalize the head varint — the two blobs stay
/// untouched, so allocation must not see their bytes.
///
/// `reach` routes to the nested varint: `[f(3), f(5)]` for the
/// message-framed pair, a group-crossing wildcard for the grouped
/// pair.
const fn scaled_rules<'r>(
    reach: &'r [Segment<'r>],
    values: &'r ScaledPaths,
) -> [replay_rewrite::Rule<'r>; 3] {
    [
        replay_rewrite::Rule { path: &values.del, action: replay_rewrite::Action::Delete },
        replay_rewrite::Rule {
            path: reach,
            action: replay_rewrite::Action::Replace(replay_rewrite::Value::Varint(9)),
        },
        replay_rewrite::Rule { path: &values.norm, action: replay_rewrite::Action::Normalize },
    ]
}

/// The scaled rule paths' backing arrays (the rules borrow them).
struct ScaledPaths {
    del: [Segment<'static>; 1],
    norm: [Segment<'static>; 1],
}

fn scaled_paths() -> ScaledPaths {
    ScaledPaths { del: [Segment::Field(f(2))], norm: [Segment::Field(f(0))] }
}

// ─── zero-retention rows ───

/// Zero-retention row: payload-×1000 structure-identical
/// documents must produce identical machine allocation
/// fingerprints through the sink face (no output buffer exists,
/// so the account is the machine's own: script, stack, matcher).
#[test]
fn rewrite_allocation_is_structure_proportional() {
    let paths = scaled_paths();
    let reach = [Segment::Field(f(3)), Segment::Field(f(5))];
    let rules = scaled_rules(&reach, &paths);
    let set = replay_rewrite::RuleSet::over(&rules).unwrap();

    let small = payload_scaled(64);
    let large = payload_scaled(64_000);
    let fingerprint = |bytes: &[u8]| {
        let ((sunk, stats), count, max, total) = measured(|| {
            let mut sunk = 0u64;
            let stats = replay_rewrite::groupless::rewrite_sink(
                &mut SliceSource::new(bytes),
                &set,
                DepthLimit::REFERENCE,
                |view| sunk += view.len() as u64,
            )
            .unwrap();
            (sunk, stats)
        });
        assert!(sunk > bytes.len() as u64 / 2, "the output flowed through the sink");
        assert_eq!(stats.deleted(), 1);
        assert_eq!(stats.replaced(), 1);
        assert_eq!(stats.normalized(), 1);
        (count, max, total)
    };
    assert_eq!(
        fingerprint(&small),
        fingerprint(&large),
        "the groupless rewrite's allocation moved with payload bytes"
    );

    let g_reach = [Segment::AnyDepth { descend: &[f(6)] }, Segment::Field(f(5))];
    let g_rules = scaled_rules(&g_reach, &paths);
    let g_set = replay_rewrite::RuleSet::over(&g_rules).unwrap();
    let fingerprint_grouped = |bytes: &[u8]| {
        let ((sunk, stats), count, max, total) = measured(|| {
            let mut sunk = 0u64;
            let stats = replay_rewrite::grouped::rewrite_sink(
                &mut SliceSource::new(bytes),
                &g_set,
                DepthLimit::REFERENCE,
                |view| sunk += view.len() as u64,
            )
            .unwrap();
            (sunk, stats)
        });
        assert!(sunk > bytes.len() as u64 / 2, "the output flowed through the sink");
        assert_eq!(stats.deleted(), 1);
        assert_eq!(stats.replaced(), 1);
        (count, max, total)
    };
    assert_eq!(
        fingerprint_grouped(&payload_scaled_grouped(64)),
        fingerprint_grouped(&payload_scaled_grouped(64_000)),
        "the grouped rewrite's allocation moved with payload bytes"
    );
}

/// Pass-two zero-allocation row: from the first handoff to the
/// job's end, the armed thread's allocation count must not move —
/// the splicing pump owns no allocation (the script and its arena
/// are compiled before any view is handed).
#[test]
fn rewrite_pass_two_allocates_nothing() {
    let paths = scaled_paths();
    let reach = [Segment::Field(f(3)), Segment::Field(f(5))];
    let rules = scaled_rules(&reach, &paths);
    let set = replay_rewrite::RuleSet::over(&rules).unwrap();
    let doc = payload_scaled(4_000);
    measured(|| {
        let at_first = Cell::new(None);
        replay_rewrite::groupless::rewrite_sink(
            &mut SliceSource::new(&doc),
            &set,
            DepthLimit::REFERENCE,
            |_| {
                if at_first.get().is_none() {
                    at_first.set(Some(alloc_count_now()));
                }
            },
        )
        .unwrap();
        assert_eq!(at_first.get(), Some(alloc_count_now()), "the groupless pump allocated");
    });

    let g_reach = [Segment::AnyDepth { descend: &[f(6)] }, Segment::Field(f(5))];
    let g_rules = scaled_rules(&g_reach, &paths);
    let g_set = replay_rewrite::RuleSet::over(&g_rules).unwrap();
    let doc = payload_scaled_grouped(4_000);
    measured(|| {
        let at_first = Cell::new(None);
        replay_rewrite::grouped::rewrite_sink(
            &mut SliceSource::new(&doc),
            &g_set,
            DepthLimit::REFERENCE,
            |_| {
                if at_first.get().is_none() {
                    at_first.set(Some(alloc_count_now()));
                }
            },
        )
        .unwrap();
        assert_eq!(at_first.get(), Some(alloc_count_now()), "the grouped pump allocated");
    });
}

// ─── pass-count and byte-budget rows ───

/// Pass-count honesty: a rewrite is exactly two walks, each walk
/// touches every byte at most once (lent + sought == 2 × length),
/// and untouched LEN payloads ride the seek in the measuring
/// walk. Chunk partitions differ per walk — the output may not
/// (the slice-source truth pins it).
#[test]
fn rewrite_pass_counts_and_byte_budgets_hold() {
    let paths = scaled_paths();
    let reach = [Segment::Field(f(3)), Segment::Field(f(5))];
    let rules = scaled_rules(&reach, &paths);
    let set = replay_rewrite::RuleSet::over(&rules).unwrap();
    let doc = payload_scaled(4_000);

    let stats = WalkStats::default();
    let steps = [97usize, 3, 33, 5];
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    let (out, job) =
        replay_rewrite::groupless::rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.begins.get(), 2, "a rewrite is exactly two walks");
    assert_eq!(
        stats.lent.get() + stats.skipped.get(),
        2 * doc.len() as u64,
        "each walk touches every byte exactly once"
    );
    assert!(
        stats.skipped.get() >= 8_000,
        "untouched LEN payloads ride the seek in the measuring walk"
    );
    assert_eq!(job.deleted(), 1);

    let (expected, _) = replay_rewrite::groupless::rewrite(
        &mut SliceSource::new(&doc),
        &set,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(out, expected, "chunk partitioning changed the output");

    // The grouped face under the same instrument.
    let g_reach = [Segment::AnyDepth { descend: &[f(6)] }, Segment::Field(f(5))];
    let g_rules = scaled_rules(&g_reach, &paths);
    let g_set = replay_rewrite::RuleSet::over(&g_rules).unwrap();
    let doc = payload_scaled_grouped(4_000);
    let stats = WalkStats::default();
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    let (out, _) =
        replay_rewrite::grouped::rewrite(&mut source, &g_set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.begins.get(), 2, "a grouped rewrite is exactly two walks");
    assert_eq!(
        stats.lent.get() + stats.skipped.get(),
        2 * doc.len() as u64,
        "each walk touches every byte exactly once"
    );
    assert!(stats.skipped.get() >= 4_000, "the untouched top blob rides the seek");
    let (expected, _) = replay_rewrite::grouped::rewrite(
        &mut SliceSource::new(&doc),
        &g_set,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(out, expected, "chunk partitioning changed the output");
}

// ─── torn and refusal rows ───

/// The pinned residual row: an equal-length content tear does NOT
/// fault — the emission walk republishes whatever bytes ride its
/// copied extents, so the output differs from the measuring
/// walk's view. The contract's edge, kept on record.
#[test]
fn an_equal_length_content_tear_is_the_pinned_residual() {
    let del = [Segment::Field(f(1))];
    let rules = [replay_rewrite::Rule { path: &del, action: replay_rewrite::Action::Delete }];
    let set = replay_rewrite::RuleSet::over(&rules).unwrap();
    let full: &[u8] = &[0x08, 0x96, 0x01, 0x10, 0x2A];

    // The tear lands in a copied extent: no fault, the output
    // carries the emission walk's bytes.
    let torn_copied: &[u8] = &[0x08, 0x97, 0x01, 0x10, 0x2A];
    let mut source = Swapping { walks: &[full, torn_copied], begun: Cell::new(0) };
    let (out, _) =
        replay_rewrite::groupless::rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(out, [0x08, 0x97, 0x01], "the copied extent republishes the second walk's bytes");

    // The tear lands in a dropped extent: no fault, and the
    // output cannot see it.
    let torn_dropped: &[u8] = &[0x08, 0x96, 0x01, 0x10, 0x2B];
    let mut source = Swapping { walks: &[full, torn_dropped], begun: Cell::new(0) };
    let (out, _) =
        replay_rewrite::groupless::rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(out, [0x08, 0x96, 0x01]);
}

/// A grouped length-shape tear between walks is refused against
/// the measured coordinates (the fold is dialect-shared; this row
/// pins the grouped face's custody of it).
#[test]
fn a_grouped_torn_source_is_refused_between_walks() {
    let path = [Segment::AnyDepth { descend: &[f(1)] }, Segment::Field(f(0))];
    let rules = [replay_rewrite::Rule { path: &path, action: replay_rewrite::Action::Delete }];
    let set = replay_rewrite::RuleSet::over(&rules).unwrap();
    let full: &[u8] = &[0x13, 0x08, 0x2A, 0x14, 0x08, 0x07];
    let mut source = Swapping { walks: &[full, &full[..3]], begun: Cell::new(0) };
    let fault =
        replay_rewrite::grouped::rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(fault, replay_rewrite::grouped::JobFault::Torn { .. }));
}

/// Supply refusals carry the emit phase and honest custody: the
/// append face truncates back to its mark, the sink face names
/// the exact handed prefix.
#[test]
fn rewrite_supply_refusals_carry_phase_and_custody() {
    let paths = scaled_paths();
    let reach = [Segment::Field(f(3)), Segment::Field(f(5))];
    let rules = scaled_rules(&reach, &paths);
    let set = replay_rewrite::RuleSet::over(&rules).unwrap();
    let doc = payload_scaled(4_000);

    // Refused at the emission walk's begin.
    let mut source =
        Refusing { bytes: &doc, begun: Cell::new(0), refuse_begin: Some(1), refuse_after: None };
    let mut out = vec![0xEE];
    let fault =
        replay_rewrite::groupless::rewrite_into(&mut source, &set, DepthLimit::REFERENCE, &mut out)
            .unwrap_err();
    assert!(matches!(
        fault,
        replay_rewrite::groupless::JobFault::Source(ReplayFault::Rewind {
            phase: ReplayPhase::Emit,
            ..
        })
    ));
    assert_eq!(out, [0xEE], "the append face truncated back to its mark");

    // Refused mid-emission: the measuring walk stays under the
    // lend cap (the blobs ride its seek), the emission walk
    // crosses it copying them.
    let mut source =
        Refusing { bytes: &doc, begun: Cell::new(0), refuse_begin: None, refuse_after: Some(200) };
    let mut handed_total = 0u64;
    let refusal =
        replay_rewrite::groupless::rewrite_sink(&mut source, &set, DepthLimit::REFERENCE, |view| {
            handed_total += view.len() as u64
        })
        .unwrap_err();
    assert!(matches!(
        refusal.fault,
        replay_rewrite::groupless::JobFault::Source(ReplayFault::Read {
            phase: ReplayPhase::Emit,
            ..
        })
    ));
    assert!(refusal.handed > 0, "the refusal followed real handoffs");
    assert_eq!(refusal.handed, handed_total, "the sink face names the exact handed prefix");
}

// ─── the differentials against the buffered rewriter ───

/// The shared rule program, spelled in both languages over the
/// same path arrays: a top-level delete, a deep normalize, a deep
/// delete, and a top-level replace whose occasional kind mismatch
/// exercises the fault rows.
struct TwinPaths {
    all: Vec<FieldNumber>,
}

struct TwinPathArrays<'r> {
    tail: [Segment<'r>; 1],
    norm: [Segment<'r>; 2],
    del: [Segment<'r>; 2],
    rep: [Segment<'r>; 1],
}

impl TwinPaths {
    fn new() -> Self {
        Self {
            all: (1..=24)
                .map(|n| FieldNumber::new(n).expect("small field numbers are in class"))
                .collect(),
        }
    }

    fn arrays(&self) -> TwinPathArrays<'_> {
        TwinPathArrays {
            tail: [Segment::Field(f(3))],
            norm: [Segment::AnyDepth { descend: &self.all }, Segment::Field(f(6))],
            del: [Segment::AnyDepth { descend: &self.all }, Segment::Field(f(8))],
            rep: [Segment::Field(f(1))],
        }
    }
}

const fn buffered_rules<'r>(paths: &'r TwinPathArrays<'r>) -> [rewrite::Rule<'r>; 4] {
    [
        rewrite::Rule { path: &paths.tail, action: rewrite::Action::Delete },
        rewrite::Rule { path: &paths.norm, action: rewrite::Action::Normalize },
        rewrite::Rule { path: &paths.del, action: rewrite::Action::Delete },
        rewrite::Rule {
            path: &paths.rep,
            action: rewrite::Action::Replace(rewrite::Value::Varint(777)),
        },
    ]
}

const fn replay_rules<'r>(paths: &'r TwinPathArrays<'r>) -> [replay_rewrite::Rule<'r>; 4] {
    [
        replay_rewrite::Rule { path: &paths.tail, action: replay_rewrite::Action::Delete },
        replay_rewrite::Rule { path: &paths.norm, action: replay_rewrite::Action::Normalize },
        replay_rewrite::Rule { path: &paths.del, action: replay_rewrite::Action::Delete },
        replay_rewrite::Rule {
            path: &paths.rep,
            action: replay_rewrite::Action::Replace(replay_rewrite::Value::Varint(777)),
        },
    ]
}

#[test]
fn rewrite_matches_the_buffered_twin_over_the_groupless_corpus() {
    let paths = TwinPaths::new();
    let arrays = paths.arrays();
    let b_rules = buffered_rules(&arrays);
    let b_set = rewrite::RuleSet::over(&b_rules).unwrap();
    let r_rules = replay_rules(&arrays);
    let r_set = replay_rewrite::RuleSet::over(&r_rules).unwrap();

    for (nth, doc) in corpus(false).iter().enumerate() {
        compare_groupless(nth, doc, &b_set, &r_set);
        // The one-short prefix: both machines must refuse the
        // truncation at the same coordinate.
        if doc.len() > 1 {
            compare_groupless(nth, &doc[..doc.len() - 1], &b_set, &r_set);
        }
    }
}

fn compare_groupless(
    nth: usize,
    doc: &[u8],
    b_set: &rewrite::RuleSet<'_>,
    r_set: &replay_rewrite::RuleSet<'_>,
) {
    let buffered_out = rewrite::groupless::rewrite(doc, b_set, DepthLimit::REFERENCE);
    let replay_out = replay_rewrite::groupless::rewrite(
        &mut SliceSource::new(doc),
        r_set,
        DepthLimit::REFERENCE,
    );
    match (buffered_out, replay_out) {
        (Ok((b_bytes, b_stats)), Ok((r_bytes, r_stats))) => {
            assert_eq!(r_bytes, b_bytes, "doc {nth}: output bytes diverged");
            assert_eq!(r_stats.deleted(), b_stats.deleted(), "doc {nth}");
            assert_eq!(r_stats.replaced(), b_stats.replaced(), "doc {nth}");
            assert_eq!(r_stats.normalized(), b_stats.normalized(), "doc {nth}");
            assert_eq!(r_stats.descended(), b_stats.descended(), "doc {nth}");
        }
        (Err(b_fault), Err(r_fault)) => {
            let replay_rewrite::groupless::JobFault::Document(fault) = r_fault else {
                panic!("doc {nth}: the slice source cannot fault the supply, got {r_fault:?}");
            };
            assert_eq!(fault.at(), u64::from(b_fault.at()), "doc {nth}: coordinates diverged");
            assert_eq!(fault.trail().len(), b_fault.trail().len(), "doc {nth}: trails diverged");
            for (mine, theirs) in fault.trail().iter().zip(b_fault.trail()) {
                assert_eq!(mine.field(), theirs.field(), "doc {nth}");
                assert_eq!(mine.at(), u64::from(theirs.at()), "doc {nth}");
            }
        }
        (buffered_out, replay_out) => panic!(
            "doc {nth}: verdicts diverged (buffered ok: {}, replay ok: {})",
            buffered_out.is_ok(),
            replay_out.is_ok()
        ),
    }
}

#[test]
fn rewrite_matches_the_buffered_twin_over_the_grouped_corpus() {
    let paths = TwinPaths::new();
    let arrays = paths.arrays();
    let b_rules = buffered_rules(&arrays);
    let b_set = rewrite::RuleSet::over(&b_rules).unwrap();
    let r_rules = replay_rules(&arrays);
    let r_set = replay_rewrite::RuleSet::over(&r_rules).unwrap();

    for (nth, doc) in corpus(true).iter().enumerate() {
        compare_grouped(nth, doc, &b_set, &r_set);
        if doc.len() > 1 {
            compare_grouped(nth, &doc[..doc.len() - 1], &b_set, &r_set);
        }
    }
}

fn compare_grouped(
    nth: usize,
    doc: &[u8],
    b_set: &rewrite::RuleSet<'_>,
    r_set: &replay_rewrite::RuleSet<'_>,
) {
    let buffered_out = rewrite::grouped::rewrite(doc, b_set, DepthLimit::REFERENCE);
    let replay_out =
        replay_rewrite::grouped::rewrite(&mut SliceSource::new(doc), r_set, DepthLimit::REFERENCE);
    match (buffered_out, replay_out) {
        (Ok((b_bytes, b_stats)), Ok((r_bytes, r_stats))) => {
            assert_eq!(r_bytes, b_bytes, "doc {nth}: output bytes diverged");
            assert_eq!(r_stats.deleted(), b_stats.deleted(), "doc {nth}");
            assert_eq!(r_stats.replaced(), b_stats.replaced(), "doc {nth}");
            assert_eq!(r_stats.normalized(), b_stats.normalized(), "doc {nth}");
            assert_eq!(r_stats.descended(), b_stats.descended(), "doc {nth}");
        }
        (Err(b_fault), Err(r_fault)) => {
            let replay_rewrite::grouped::JobFault::Document(fault) = r_fault else {
                panic!("doc {nth}: the slice source cannot fault the supply, got {r_fault:?}");
            };
            assert_eq!(fault.at(), u64::from(b_fault.at()), "doc {nth}: coordinates diverged");
            assert_eq!(fault.trail().len(), b_fault.trail().len(), "doc {nth}: trails diverged");
            for (mine, theirs) in fault.trail().iter().zip(b_fault.trail()) {
                assert_eq!(mine.field(), theirs.field(), "doc {nth}");
                assert_eq!(mine.at(), u64::from(theirs.at()), "doc {nth}");
            }
        }
        (buffered_out, replay_out) => panic!(
            "doc {nth}: verdicts diverged (buffered ok: {}, replay ok: {})",
            buffered_out.is_ok(),
            replay_out.is_ok()
        ),
    }
}
