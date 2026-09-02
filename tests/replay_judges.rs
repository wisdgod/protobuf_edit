//! The replay cells' in-lane judge battery: zero-retention
//! allocation rows, pass-count honesty over a counting source,
//! supply-refusal custody rows, and the differentials against the
//! buffered twins over the slice source.
//!
//! The armed allocator observes requested bytes beside the call
//! count — a call count alone cannot refute a document-sized
//! allocation — and observation covers only the armed thread, so
//! sibling tests never pollute a fingerprint.

#![cfg(all(
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "construct-grouped"
))]
#![feature(thread_id_value)]

#[path = "support/replay.rs"]
mod replay;

use std::cell::Cell;

use protobuf_edit::replay_source::{
    Chunk, ReplayWalk, SliceFault, SliceSource, StableReplaySource, SupplyFault,
};
use protobuf_edit::{DepthLimit, FieldNumber};
use replay::{Counting, Refusing, WalkStats, corpus, f, measured, payload_scaled};

// ─── the swapping source (torn and residual rows) ───

/// Serves `walks[n]` to the nth walk (the last entry repeats):
/// the instrument for sources whose bytes move between the index
/// walk and a later fetch walk.
#[derive(Debug)]
struct Swapping<'a> {
    walks: &'a [&'a [u8]],
    begun: Cell<u32>,
}

#[derive(Debug)]
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

// ─── survey judges ───

mod survey_judges {
    use protobuf_edit::replay_source::ReplayFault;
    use protobuf_edit::survey::{Advice, Advisor, Ancestry, FetchFault, NoAdvice, OpenFault};

    use super::*;

    /// The opaque advisor for the scaled documents' two blob
    /// fields: the huge extents are declared bytes, so the walk
    /// seeks past them (under speculation they would parse as
    /// garbage records, and rows lawfully follow parsed
    /// structure — that is structure, not retention).
    struct Blobs;
    impl Advisor for Blobs {
        fn advise(&mut self, _ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
            if field.as_inner() == 2 || field.as_inner() == 5 {
                Advice::Opaque
            } else {
                Advice::Speculate
            }
        }
    }

    /// Zero-retention row: payload-×1000 structure-identical
    /// documents must produce identical machine allocation
    /// fingerprints — allocation is a function of record
    /// structure, never of source length.
    #[test]
    fn survey_allocation_is_structure_proportional() {
        let small = payload_scaled(64);
        let large = payload_scaled(64_000);
        let fingerprint = |bytes: &[u8]| {
            let (tree, count, max, total) = measured(|| {
                protobuf_edit::survey::groupless::Survey::open(
                    SliceSource::new(bytes),
                    DepthLimit::REFERENCE,
                    &mut Blobs,
                )
                .unwrap()
            });
            assert!(tree.is_complete());
            drop(tree);
            (count, max, total)
        };
        assert_eq!(
            fingerprint(&small),
            fingerprint(&large),
            "the groupless index walk's allocation moved with payload bytes"
        );

        let fingerprint_grouped = |bytes: &[u8]| {
            let (tree, count, max, total) = measured(|| {
                protobuf_edit::survey::grouped::Survey::open(
                    SliceSource::new(bytes),
                    DepthLimit::REFERENCE,
                    &mut Blobs,
                )
                .unwrap()
            });
            assert!(tree.is_complete());
            drop(tree);
            (count, max, total)
        };
        assert_eq!(
            fingerprint_grouped(&small),
            fingerprint_grouped(&large),
            "the grouped index walk's allocation moved with payload bytes"
        );
    }

    /// Pass-count honesty: open = exactly one walk; metadata
    /// queries = zero; each single fetch = one walk; one batch
    /// fetch = one walk. Byte budget: the index walk touches
    /// every byte exactly once, and opaque extents ride the seek,
    /// never the lend. Chunk partitions differ per walk — the
    /// verdicts may not.
    #[test]
    fn survey_pass_counts_and_byte_budgets_hold() {
        let doc = payload_scaled(4_000);
        let stats = WalkStats::default();
        let steps = [97usize, 3, 33, 5];
        let source = Counting { bytes: &doc, steps: &steps, stats: &stats };

        // The opaque advisor pins the two blobs out of the parse:
        // their bytes must ride the seek.
        let mut tree = protobuf_edit::survey::groupless::Survey::open(
            source,
            DepthLimit::REFERENCE,
            &mut Blobs,
        )
        .unwrap();
        assert!(tree.is_complete());
        assert_eq!(stats.begins.get(), 1, "open is one walk");
        assert_eq!(
            stats.lent.get() + stats.skipped.get(),
            doc.len() as u64,
            "the index walk touches every byte exactly once"
        );
        assert!(stats.skipped.get() >= 8_000, "opaque extents ride the seek, not the lend");

        // Metadata queries: zero additional walks.
        let ids: Vec<_> = tree.nodes().collect();
        for &id in &ids {
            let _ = tree.span(id);
            let _ = tree.varint_word(id);
            let _ = tree.field(id);
        }
        assert_eq!(stats.begins.get(), 1, "metadata queries walk nothing");

        // One single-handle fetch = one more walk, and the bytes
        // match the slice truth under a different partition.
        let blob = tree.top().by_field(f(1)).next().expect("the document carries its blob");
        let mut out = Vec::new();
        tree.read_payload(blob, &mut out).unwrap();
        assert_eq!(out.len(), 4_000);
        assert_eq!(stats.begins.get(), 2, "one fetch is one walk");

        // A batch of every LEN = one more walk.
        let batch: Vec<_> = ids
            .iter()
            .copied()
            .filter(|&id| matches!(tree.kind(id), protobuf_edit::wire::groupless::RecordKind::Len))
            .collect();
        assert!(batch.len() >= 2);
        let mut sunk = 0u64;
        tree.fetch_payloads(&batch, |_, bytes| sunk += bytes.len() as u64).unwrap();
        assert!(sunk >= 8_000);
        assert_eq!(stats.begins.get(), 3, "one batch fetch is one walk");
    }

    /// Supply refusals are structured and custody-honest: the
    /// source rides back from a refused open, established
    /// products survive a refused fetch, and the sink face names
    /// its handed prefix.
    #[test]
    fn survey_supply_refusals_return_custody() {
        let doc = payload_scaled(64);

        // Refused at the open's begin.
        let source = Refusing {
            bytes: &doc,
            begun: Cell::new(0),
            refuse_begin: Some(0),
            refuse_after: None,
        };
        let Err((source, fault)) = protobuf_edit::survey::groupless::Survey::open(
            source,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        ) else {
            panic!("the scripted begin refusal fires");
        };
        assert!(matches!(fault, OpenFault::Source(ReplayFault::Rewind { .. })));
        // The recovered handle opens clean (the refusal was
        // scripted for walk zero alone).
        let tree = protobuf_edit::survey::groupless::Survey::open(
            source,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();
        assert!(tree.is_complete());

        // Refused mid-index: custody again.
        let source = Refusing {
            bytes: &doc,
            begun: Cell::new(0),
            refuse_begin: None,
            refuse_after: Some(8),
        };
        let Err((_, fault)) = protobuf_edit::survey::groupless::Survey::open(
            source,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        ) else {
            panic!("the scripted mid-walk refusal fires");
        };
        assert!(matches!(
            fault,
            OpenFault::Source(ReplayFault::Read { at, .. }) if at >= 8
        ));

        // Refused at a fetch's begin: the product stands, the
        // fault names the fetch phase.
        let source = Refusing {
            bytes: &doc,
            begun: Cell::new(0),
            refuse_begin: Some(1),
            refuse_after: None,
        };
        let mut tree = protobuf_edit::survey::groupless::Survey::open(
            source,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();
        let blob = tree.top().by_field(f(1)).next().unwrap();
        let mut out = Vec::from(&b"mark"[..]);
        let fault = tree.read_payload(blob, &mut out).unwrap_err();
        assert!(matches!(fault, FetchFault::Source(ReplayFault::Rewind { .. })));
        assert_eq!(out, b"mark", "the append face truncated to its mark");
        // The product still answers metadata beside the refusal.
        assert!(tree.is_complete());
        assert!(tree.node_count() > 0);
    }

    /// The pinned residual row: an equal-length content tear does
    /// NOT fault — a fetch walk verifies only that the source
    /// still reaches the extent's end, so the changed bytes are
    /// delivered as they now read. The contract's edge, kept on
    /// record for both dialects.
    #[test]
    fn an_equal_length_content_tear_is_the_pinned_residual() {
        // LEN f2 "hi"; every walk after the index flips the
        // payload bytes at equal length.
        let full: &[u8] = &[0x12, 0x02, 0x68, 0x69];
        let flipped: &[u8] = &[0x12, 0x02, 0x58, 0x59];
        let walks: [&[u8]; 2] = [full, flipped];

        let mut tree = protobuf_edit::survey::groupless::Survey::open(
            Swapping { walks: &walks, begun: Cell::new(0) },
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();
        let id = tree.top().next().unwrap();
        let mut out = Vec::new();
        tree.read_payload(id, &mut out).unwrap();
        assert_eq!(out, b"XY", "the fetch hands the flipped bytes, faultless");
        assert_ne!(out, b"hi");

        let mut tree = protobuf_edit::survey::grouped::Survey::open(
            Swapping { walks: &walks, begun: Cell::new(0) },
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();
        let id = tree.top().next().unwrap();
        let mut out = Vec::new();
        tree.read_payload(id, &mut out).unwrap();
        assert_eq!(out, b"XY", "the grouped fetch hands the flipped bytes, faultless");
    }

    /// The growth row: bytes prepended before a fetched extent
    /// are invisible to a fetch walk — the seek to the measured
    /// start and the copy of the measured length both succeed on
    /// a longer source — so the fetch returns `Ok` with different
    /// bytes. The boundary, judged as a fact: a fetch refuses
    /// only a source too short for a measured coordinate.
    #[test]
    fn growth_before_a_fetched_extent_is_undetected() {
        // varint f1=1 · LEN f2 "abcd"; every walk after the index
        // carries two prepended bytes, displacing every measured
        // coordinate.
        let full: &[u8] = &[0x08, 0x01, 0x12, 0x04, 0x61, 0x62, 0x63, 0x64];
        let grown: &[u8] = &[0xEE, 0xEE, 0x08, 0x01, 0x12, 0x04, 0x61, 0x62, 0x63, 0x64];
        let walks: [&[u8]; 2] = [full, grown];

        let mut tree = protobuf_edit::survey::groupless::Survey::open(
            Swapping { walks: &walks, begun: Cell::new(0) },
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();
        let blob = tree.top().nth(1).unwrap();
        let mut out = Vec::new();
        tree.read_payload(blob, &mut out).unwrap();
        assert_eq!(out, [0x12, 0x04, 0x61, 0x62], "the displaced bytes ride out, faultless");
        assert_ne!(out, b"abcd");

        // The batch face walks the same displaced coordinates.
        let mut batched = Vec::new();
        tree.fetch_payloads(&[blob], |_, bytes| batched.extend_from_slice(bytes)).unwrap();
        assert_eq!(batched, [0x12, 0x04, 0x61, 0x62], "the batch face is equally blind");

        let mut tree = protobuf_edit::survey::grouped::Survey::open(
            Swapping { walks: &walks, begun: Cell::new(0) },
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();
        let blob = tree.top().nth(1).unwrap();
        let mut out = Vec::new();
        tree.read_payload(blob, &mut out).unwrap();
        assert_eq!(out, [0x12, 0x04, 0x61, 0x62], "the grouped fetch is equally blind");
    }

    /// The differential against the buffered twin: over a slice
    /// source, the survey answers every shared query exactly as
    /// the resident inspector does, u64 == u32 widened, and
    /// fetched payload bytes equal the resident borrows.
    fn differential_groupless(bytes: &[u8]) {
        let twin = protobuf_edit::retain::groupless::Retained::parse(
            bytes.to_vec(),
            DepthLimit::REFERENCE,
            &mut protobuf_edit::retain::NoAdvice,
        )
        .unwrap();
        let mut tree = protobuf_edit::survey::groupless::Survey::open(
            SliceSource::new(bytes),
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();

        assert_eq!(tree.is_complete(), twin.is_complete());
        assert_eq!(tree.indexed_end(), u64::from(twin.indexed_end()));
        assert_eq!(tree.node_count(), twin.node_count());
        let mine: Vec<_> = tree.nodes().collect();
        let theirs: Vec<_> = twin.nodes().collect();
        for (&a, &b) in mine.iter().zip(theirs.iter()) {
            assert_eq!(tree.field(a), twin.field(b));
            assert_eq!(tree.kind(a), twin.kind(b));
            let span = tree.span(a);
            let twin_span = twin.span(b);
            assert_eq!(span.start(), u64::from(twin_span.start()));
            assert_eq!(span.end(), u64::from(twin_span.end()));
            assert_eq!(tree.varint_word(a), twin.varint_word(b));
            assert_eq!(tree.i32_bits(a), twin.i32_bits(b));
            assert_eq!(tree.i64_bits(a), twin.i64_bits(b));
            assert_eq!(
                tree.parent(a).map(|id| id.as_inner()),
                twin.parent(b).map(|id| id.as_inner())
            );
            assert_eq!(tree.children(a).count(), twin.children(b).count(), "child counts diverged");
        }
        // Fetched bytes equal the resident borrows, for every
        // whole extent.
        for (&a, &b) in mine.iter().zip(theirs.iter()) {
            let span = tree.span(a);
            if span.end() > tree.indexed_end() {
                continue;
            }
            let mut fetched = Vec::new();
            tree.read_payload(a, &mut fetched).unwrap();
            assert_eq!(fetched, twin.payload_bytes(b), "payload bytes diverged");
        }
        // The narrowest answer agrees at every byte of the
        // indexed prefix (bounded corpora keep this affordable).
        if bytes.len() <= 512 {
            for pos in 0..u64::from(twin.indexed_end()) {
                assert_eq!(
                    tree.narrowest(pos).map(|id| id.as_inner()),
                    twin.narrowest(u32::try_from(pos).expect("bounded corpus"))
                        .map(|id| id.as_inner()),
                    "narrowest diverged at {pos}"
                );
            }
        }
    }

    #[test]
    fn survey_matches_retain_over_the_groupless_corpus() {
        let corpus = corpus(false);
        for (nth, doc) in corpus.iter().enumerate() {
            differential_groupless(doc);
            // The one-short prefix: both machines must judge the
            // truncation identically (rows, prefix, faultedness).
            if doc.len() > 1 {
                let cut = &doc[..doc.len() - 1];
                let twin = protobuf_edit::retain::groupless::Retained::parse(
                    cut.to_vec(),
                    DepthLimit::REFERENCE,
                    &mut protobuf_edit::retain::NoAdvice,
                )
                .unwrap();
                let tree = protobuf_edit::survey::groupless::Survey::open(
                    SliceSource::new(cut),
                    DepthLimit::REFERENCE,
                    &mut NoAdvice,
                )
                .unwrap();
                assert_eq!(tree.is_complete(), twin.is_complete(), "doc {nth}");
                assert_eq!(tree.node_count(), twin.node_count(), "doc {nth}");
                assert_eq!(tree.indexed_end(), u64::from(twin.indexed_end()), "doc {nth}");
            }
        }
    }

    #[test]
    fn survey_matches_retain_over_the_grouped_corpus() {
        let corpus = corpus(true);
        for (nth, doc) in corpus.iter().enumerate() {
            let twin = protobuf_edit::retain::grouped::Retained::parse(
                doc.clone(),
                DepthLimit::REFERENCE,
                &mut protobuf_edit::retain::NoAdvice,
            )
            .unwrap();
            let mut tree = protobuf_edit::survey::grouped::Survey::open(
                SliceSource::new(doc),
                DepthLimit::REFERENCE,
                &mut NoAdvice,
            )
            .unwrap();
            assert_eq!(tree.is_complete(), twin.is_complete(), "doc {nth}");
            assert_eq!(tree.indexed_end(), u64::from(twin.indexed_end()), "doc {nth}");
            assert_eq!(tree.node_count(), twin.node_count(), "doc {nth}");
            let mine: Vec<_> = tree.nodes().collect();
            let theirs: Vec<_> = twin.nodes().collect();
            for (&a, &b) in mine.iter().zip(theirs.iter()) {
                assert_eq!(tree.field(a), twin.field(b), "doc {nth}");
                assert_eq!(format!("{:?}", tree.kind(a)), format!("{:?}", twin.kind(b)));
                let span = tree.span(a);
                let twin_span = twin.span(b);
                assert_eq!(span.start(), u64::from(twin_span.start()), "doc {nth}");
                assert_eq!(span.end(), u64::from(twin_span.end()), "doc {nth}");
                assert_eq!(tree.varint_word(a), twin.varint_word(b), "doc {nth}");
                assert_eq!(tree.i32_bits(a), twin.i32_bits(b), "doc {nth}");
                assert_eq!(tree.i64_bits(a), twin.i64_bits(b), "doc {nth}");
            }
            for (&a, &b) in mine.iter().zip(theirs.iter()) {
                if tree.span(a).end() > tree.indexed_end() {
                    continue;
                }
                let mut fetched = Vec::new();
                tree.read_payload(a, &mut fetched).unwrap();
                assert_eq!(fetched, twin.payload_bytes(b), "doc {nth} payload bytes diverged");
            }
        }
    }

    /// Speculation parity: an advisor-pinned document yields
    /// identical topology under both machines, speculative
    /// unwinds included — the replay unwind touches the arena and
    /// the seek, never a re-read, and the products cannot tell.
    #[test]
    fn survey_speculation_parity_holds_under_advice() {
        struct Pinned;
        impl protobuf_edit::retain::Advisor for Pinned {
            fn advise(
                &mut self,
                ancestry: protobuf_edit::retain::Ancestry<'_>,
                field: FieldNumber,
            ) -> protobuf_edit::retain::Advice {
                match (ancestry.len(), field.as_inner() % 3) {
                    (0, 0) => protobuf_edit::retain::Advice::Opaque,
                    (_, 1) => protobuf_edit::retain::Advice::Commit,
                    _ => protobuf_edit::retain::Advice::Speculate,
                }
            }
        }
        struct PinnedReplay;
        impl Advisor for PinnedReplay {
            fn advise(&mut self, ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
                match (ancestry.len(), field.as_inner() % 3) {
                    (0, 0) => Advice::Opaque,
                    (_, 1) => Advice::Commit,
                    _ => Advice::Speculate,
                }
            }
        }
        for doc in corpus(false).iter().filter(|doc| {
            // Commit pins make interior faults real: keep the
            // documents both machines admit cleanly, and let the
            // faulted ones compare through the corpus row above.
            protobuf_edit::retain::groupless::Retained::parse(
                (*doc).clone(),
                DepthLimit::REFERENCE,
                &mut Pinned,
            )
            .unwrap()
            .is_complete()
        }) {
            let twin = protobuf_edit::retain::groupless::Retained::parse(
                doc.clone(),
                DepthLimit::REFERENCE,
                &mut Pinned,
            )
            .unwrap();
            let tree = protobuf_edit::survey::groupless::Survey::open(
                SliceSource::new(doc),
                DepthLimit::REFERENCE,
                &mut PinnedReplay,
            )
            .unwrap();
            assert_eq!(tree.node_count(), twin.node_count());
            for (a, b) in tree.nodes().zip(twin.nodes()) {
                assert_eq!(tree.field(a), twin.field(b));
                assert_eq!(tree.span(a).start(), u64::from(twin.span(b).start()));
                assert_eq!(
                    tree.children(a).count(),
                    twin.children(b).count(),
                    "speculation topology diverged"
                );
            }
        }
    }
}
