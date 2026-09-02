//! The seeded differential judge: deep nested documents drawn from
//! a deterministic generator, read by independent machines that
//! must agree. The fixed suites pin known shapes; this one walks
//! the combination space — depth × kind interleaving × chunk
//! boundaries × dialect × truncation — where no hand-written case
//! lives.
//!
//! Two document families:
//! - group-free: every scalar/LEN/message kind, no group tag. Both
//!   dialects read it (grouped and groupless), whole and chunk-fed,
//!   and must render identical values and transcode bit-true.
//! - grouped: the same plus group frames (grouped dialect only),
//!   one of them at the root where every scanner looks. The grouped
//!   machines agree among themselves (whole vs chunked vs identity
//!   transcode), and the groupless scanner refuses the root group
//!   code — the byte fact that separates the dialects. (A group
//!   buried inside a LEN payload is invisible to a wire-level
//!   scan: without a schema that payload may be bytes, so the
//!   validators do not descend it.)
//!
//! Every document is also truncated one byte short of its trailing
//! two-byte LEN payload, cutting a construct mid-declaration: the
//! readers must refuse the prefix together, not in one machine
//! only. Depth is asserted actually reached, not proxied by byte
//! count.

#![cfg(all(
    feature = "construct-grouped",
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]

use protobuf_edit::construct::grouped::{BodyBuilder, Builder};
use protobuf_edit::inspect::{Admitted, NoAdvice};
use protobuf_edit::scan::Standard;
use protobuf_edit::{DepthLimit, FieldNumber};

#[path = "support/render.rs"]
mod render;

/// Deterministic xorshift; no external RNG dependency.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

const fn f(n: u64) -> FieldNumber {
    FieldNumber::new(1 + (n % 64) as u32).expect("small field numbers are in class")
}

/// What the seeded walk actually did — measured, not assumed: the
/// deepest layer entered. (Group coverage is witnessed on the
/// reader side, by the scan census in the grouped test — counting
/// generator arms would count intent, not coverage.)
#[derive(Default)]
struct GrowStats {
    reached: u32,
}

/// Grows one layer from the seed. `groups` admits group frames (a
/// grouped-only construct).
fn grow(
    rng: &mut Rng,
    body: &mut BodyBuilder<'_, '_>,
    depth: u32,
    budget: &mut u32,
    groups: bool,
    stats: &mut GrowStats,
    here: u32,
) {
    stats.reached = stats.reached.max(here);
    let arms = if groups { 10 } else { 8 };
    while *budget > 0 {
        *budget -= 1;
        match rng.next() % arms {
            0..=2 => body.push_varint(f(rng.next()), rng.next() >> (rng.next() % 60)),
            3 => {
                #[allow(clippy::as_conversions, reason = "seed bits truncate into the i32 domain")]
                body.push_i32(f(rng.next()), rng.next() as u32);
            }
            4 => body.push_i64(f(rng.next()), rng.next()),
            5 => {
                let len = (rng.next() % 24) as usize;
                body.push_len_copy(f(rng.next()), &vec![0xA5u8; len]);
            }
            6 | 7 if depth > 0 => {
                let field = f(rng.next());
                body.message(field, |m| grow(rng, m, depth - 1, budget, groups, stats, here + 1));
            }
            8 | 9 if depth > 0 => {
                let field = f(rng.next());
                body.group(field, |m| grow(rng, m, depth - 1, budget, groups, stats, here + 1));
            }
            _ => body.push_varint(f(rng.next()), rng.next()),
        }
    }
}

/// Grows the scanner-visible chain: groups nested in groups with
/// scalars and LEN records interleaved, never wrapped in messages
/// (a wire-level scan walks group frames but skips LEN payloads,
/// so only unwrapped frames reach its group events).
fn grow_visible(
    rng: &mut Rng,
    body: &mut BodyBuilder<'_, '_>,
    depth: u32,
    budget: &mut u32,
    stats: &mut GrowStats,
    here: u32,
) {
    stats.reached = stats.reached.max(here);
    while *budget > 0 {
        *budget -= 1;
        match rng.next() % 8 {
            0..=3 => body.push_varint(f(rng.next()), rng.next() >> (rng.next() % 60)),
            4 => {
                let len = (rng.next() % 16) as usize;
                body.push_len_copy(f(rng.next()), &vec![0x5Au8; len]);
            }
            _ if depth > 0 => {
                let field = f(rng.next());
                body.group(field, |m| grow_visible(rng, m, depth - 1, budget, stats, here + 1));
            }
            _ => body.push_varint(f(rng.next()), rng.next()),
        }
    }
}

/// One seeded document plus the deepest layer its walk reached. The
/// document ends in a two-byte LEN payload, so dropping one byte
/// always cuts a construct mid-payload (the truncation probe).
fn build(seed: u64, groups: bool) -> (Vec<u8>, GrowStats) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (seed.wrapping_mul(0x0100_0000_01B3)));
    // Nesting stays well inside the reference depth (100): the walk
    // descends `depth` layers at most, plus the root wrapper.
    let depth = 1 + (rng.next() % 40) as u32;
    let mut budget = 120 + (rng.next() % 120) as u32;
    let mut stats = GrowStats::default();
    let mut b = Builder::new();
    b.push_varint(f(seed), seed);
    b.message(f(seed ^ 1), |m| grow(&mut rng, m, depth, &mut budget, groups, &mut stats, 1));
    if groups {
        // A root-level group frame: the one place both dialects'
        // scanners are guaranteed to look, so the groupless refusal
        // below is a certainty. Inside it grows a visible chain —
        // groups nested in groups with LEN records interleaved but
        // no message wrappers, because a wire-level scan skips LEN
        // payloads and anything buried there is invisible to it;
        // the reader-side census in the grouped test counts these
        // frames, and only these can feed it.
        let mut root_budget = 64;
        b.group(f(seed ^ 3), |m| {
            grow_visible(&mut rng, m, depth.min(6), &mut root_budget, &mut stats, 1);
        });
    }
    b.push_len(f(seed ^ 2), &[0xA5, 0x5A]);
    (b.finish().expect("seeded documents stay far under the cap"), stats)
}

/// True when the three grouped readers all refuse `prefix` — a
/// truncation is judged by every machine, not silently accepted by
/// one of them.
fn all_grouped_readers_refuse(prefix: &[u8]) -> bool {
    let scan_refuses = {
        let mut v =
            protobuf_edit::scan::grouped::Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        v.feed(prefix).and_then(|()| v.finish()).is_err()
    };
    let inspect_refuses = {
        let tree = protobuf_edit::inspect::grouped::Tree::parse(
            Admitted::new(prefix).unwrap(),
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        );
        !tree.is_complete()
    };
    let transcode_refuses = {
        let mut t = protobuf_edit::transcode::grouped::Transcoder::new(
            Standard::Tolerant,
            DepthLimit::REFERENCE,
        );
        t.feed(prefix, &mut (), &mut |_: &[u8]| {})
            .and_then(|()| t.finish(&mut (), &mut |_: &[u8]| {}))
            .is_err()
    };
    scan_refuses && inspect_refuses && transcode_refuses
}

#[test]
fn seeded_group_free_documents_agree_across_both_dialects() {
    let mut largest = 0;
    let mut deepest = 0;
    for seed in 0..48u64 {
        let (doc, stats) = build(seed, false);
        // The generator really generated: a vacuously tiny document
        // would pass every agreement below without judging anything.
        assert!(doc.len() >= 100, "seed {seed}: generator produced only {} bytes", doc.len());
        largest = largest.max(doc.len());
        deepest = deepest.max(stats.reached);

        // Scan, both dialects, whole-fed and 7-byte-chunk-fed (the
        // carry/resume seam is on the clock in both dialects).
        for size in [doc.len(), 7] {
            let mut g = protobuf_edit::scan::grouped::Validator::new(
                Standard::Tolerant,
                DepthLimit::REFERENCE,
            );
            let mut p = protobuf_edit::scan::groupless::Validator::new(Standard::Tolerant);
            for part in doc.chunks(size) {
                g.feed(part).unwrap_or_else(|e| panic!("seed {seed}: grouped scan: {e:?}"));
                p.feed(part).unwrap_or_else(|e| panic!("seed {seed}: groupless scan: {e:?}"));
            }
            g.finish().unwrap_or_else(|e| panic!("seed {seed}: grouped finish: {e:?}"));
            p.finish().unwrap_or_else(|e| panic!("seed {seed}: groupless finish: {e:?}"));
        }

        // Inspect, both dialects: complete parses reading the same
        // values from the same bytes.
        let grouped_text = {
            use protobuf_edit::inspect::grouped::Tree;
            let tree =
                Tree::parse(Admitted::new(&doc).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            assert!(tree.is_complete(), "seed {seed}: grouped parse faulted: {:?}", tree.fault());
            render::grouped::render(&tree)
        };
        let groupless_text = {
            use protobuf_edit::inspect::groupless::Tree;
            let tree =
                Tree::parse(Admitted::new(&doc).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            assert!(tree.is_complete(), "seed {seed}: groupless parse faulted: {:?}", tree.fault());
            render::groupless::render(&tree)
        };
        assert_eq!(grouped_text, groupless_text, "seed {seed}: the dialects read different values");

        // Transcode identity, both dialects, bit-true — grouped
        // whole-fed, groupless 7-byte-chunk-fed so the resume seam
        // rides the identity job too.
        {
            let mut out = Vec::new();
            let mut t = protobuf_edit::transcode::grouped::Transcoder::new(
                Standard::Tolerant,
                DepthLimit::REFERENCE,
            );
            t.feed(&doc, &mut (), &mut |b: &[u8]| out.extend_from_slice(b))
                .unwrap_or_else(|e| panic!("seed {seed}: grouped transcode: {e:?}"));
            t.finish(&mut (), &mut |b: &[u8]| out.extend_from_slice(b))
                .unwrap_or_else(|e| panic!("seed {seed}: grouped transcode finish: {e:?}"));
            assert_eq!(out, doc, "seed {seed}: grouped identity moved bytes");
        }
        {
            let mut out = Vec::new();
            let mut t = protobuf_edit::transcode::groupless::Transcoder::new(
                Standard::Tolerant,
                DepthLimit::REFERENCE,
            );
            for part in doc.chunks(7) {
                t.feed(part, &mut (), &mut |b: &[u8]| out.extend_from_slice(b))
                    .unwrap_or_else(|e| panic!("seed {seed}: groupless transcode: {e:?}"));
            }
            t.finish(&mut (), &mut |b: &[u8]| out.extend_from_slice(b))
                .unwrap_or_else(|e| panic!("seed {seed}: groupless transcode finish: {e:?}"));
            assert_eq!(out, doc, "seed {seed}: groupless chunked identity moved bytes");
        }

        // Truncation: one byte off the trailing two-byte LEN payload
        // cuts a construct; every grouped reader must refuse.
        assert!(
            all_grouped_readers_refuse(&doc[..doc.len() - 1]),
            "seed {seed}: a one-byte truncation passed some reader"
        );
    }
    assert!(largest >= 1000, "no seed grew a large document (largest {largest})");
    assert!(deepest >= 8, "no seed reached a deep nesting (deepest {deepest})");
}

#[test]
fn seeded_grouped_documents_agree_among_the_grouped_machines() {
    use protobuf_edit::inspect::grouped::Tree;
    use protobuf_edit::scan::grouped::Validator;
    use protobuf_edit::transcode::grouped::Transcoder;

    // The vacuity guards judge what the scanner actually walks:
    // a group buried in an uncommitted LEN payload is invisible to
    // a wire-level scan, so counting the generator's own arms
    // would count intent, not coverage. The census counts group
    // entries below the root fixture frame (depth >= 2), so the
    // fixture cannot feed the guard; mutating the root helper to
    // groups=false must turn it red.
    struct GroupCensus {
        depth: u32,
        peak: u32,
        nested_enters: u32,
    }
    impl protobuf_edit::scan::grouped::Sink for GroupCensus {
        fn on_group_enter(
            &mut self,
            _: protobuf_edit::FieldNumber,
            _: u64,
        ) -> core::ops::ControlFlow<()> {
            self.depth += 1;
            if self.depth >= 2 {
                self.nested_enters += 1;
            }
            self.peak = self.peak.max(self.depth);
            core::ops::ControlFlow::Continue(())
        }
        fn on_group_exit(
            &mut self,
            _: protobuf_edit::FieldNumber,
            _: u64,
        ) -> core::ops::ControlFlow<()> {
            self.depth -= 1;
            core::ops::ControlFlow::Continue(())
        }
    }

    let mut deepest = 0;
    let mut nested_enters = 0;
    let mut visible_peak = 0;
    for seed in 0..48u64 {
        let (doc, stats) = build(seed, true);
        deepest = deepest.max(stats.reached);

        // Reader-side group census over the same bytes. The floor
        // is per seed: a sum could be carried by one seed while the
        // rest walk no group at all.
        {
            use protobuf_edit::scan::grouped::Parser;
            let mut census = GroupCensus { depth: 0, peak: 0, nested_enters: 0 };
            let mut p = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
            let _flow =
                p.feed(&doc, &mut census).unwrap_or_else(|e| panic!("seed {seed}: census: {e:?}"));
            p.finish().unwrap_or_else(|e| panic!("seed {seed}: census finish: {e:?}"));
            assert!(
                census.nested_enters >= 1,
                "seed {seed}: the scanner walked no generator-grown group"
            );
            nested_enters += census.nested_enters;
            visible_peak = visible_peak.max(census.peak);
        }

        // Whole-fed and 7-byte-chunk-fed scans agree.
        let mut whole = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        whole.feed(&doc).unwrap_or_else(|e| panic!("seed {seed}: grouped scan: {e:?}"));
        whole.finish().unwrap_or_else(|e| panic!("seed {seed}: grouped finish: {e:?}"));

        let mut chunked = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
        for part in doc.chunks(7) {
            chunked.feed(part).unwrap_or_else(|e| panic!("seed {seed}: chunked scan: {e:?}"));
        }
        chunked.finish().unwrap_or_else(|e| panic!("seed {seed}: chunked finish: {e:?}"));

        // A complete parse under the grouped reader.
        {
            let tree =
                Tree::parse(Admitted::new(&doc).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
            assert!(tree.is_complete(), "seed {seed}: grouped parse faulted: {:?}", tree.fault());
        }

        // The identity transcode is bit-true, whole-fed and 7-byte
        // chunk-fed (group frames across the carry/resume seam).
        for size in [doc.len(), 7] {
            let mut out = Vec::new();
            let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
            for part in doc.chunks(size) {
                t.feed(part, &mut (), &mut |b: &[u8]| out.extend_from_slice(b))
                    .unwrap_or_else(|e| panic!("seed {seed}: grouped transcode: {e:?}"));
            }
            t.finish(&mut (), &mut |b: &[u8]| out.extend_from_slice(b))
                .unwrap_or_else(|e| panic!("seed {seed}: grouped transcode finish: {e:?}"));
            assert_eq!(out, doc, "seed {seed}: grouped identity moved bytes (chunk {size})");
        }

        // The root-level group is where the groupless scanner is
        // guaranteed to look: the refusal is unconditional — the
        // byte fact separating the dialects.
        {
            let mut p = protobuf_edit::scan::groupless::Validator::new(Standard::Tolerant);
            let refused = p.feed(&doc).and_then(|()| p.finish()).is_err();
            assert!(refused, "seed {seed}: the groupless dialect accepted a root group code");
        }

        assert!(
            all_grouped_readers_refuse(&doc[..doc.len() - 1]),
            "seed {seed}: a one-byte truncation passed some grouped reader"
        );
    }
    assert!(deepest >= 8, "no grouped seed reached a deep nesting (deepest {deepest})");
    // The scanner really walked generator-grown groups: entries
    // below the fixture frame, and a deep chain among them.
    assert!(
        nested_enters >= 48,
        "the scanner walked only {nested_enters} nested group frames across all seeds"
    );
    assert!(visible_peak >= 3, "no visible group chain ran deep (peak {visible_peak})");
}

/// The convert judges over the same seeded corpus: group-free
/// conversion is byte-identical to the identity transcode's claim,
/// grouped conversion crosses the capability boundary (the
/// groupless machines that refused the input accept the output),
/// re-conversion is a fixed point, and the values survive —
/// compared structurally under the grouped reader, where a source
/// group node must equal its converted LEN node child for child
/// (text rendering cannot judge this: an empty group and an empty
/// LEN print differently while carrying equal values).
#[test]
fn seeded_documents_convert_to_the_groupless_dialect_and_agree() {
    use protobuf_edit::convert::groupless::Converter;
    use protobuf_edit::inspect::NodeId;
    use protobuf_edit::inspect::grouped::Tree;
    use protobuf_edit::wire::grouped::RecordKind;

    /// Structural value equality between a source node and its
    /// converted image: scalars by word, unconverted LEN records
    /// by payload bytes, groups against their re-framed LEN twins
    /// child by child.
    fn value_eq(a: &Tree<'_>, ai: NodeId, b: &Tree<'_>, bi: NodeId) -> bool {
        if a.field(ai) != b.field(bi) {
            return false;
        }
        match (a.kind(ai), b.kind(bi)) {
            (RecordKind::Varint, RecordKind::Varint) => {
                a.varint_word(ai).unwrap() == b.varint_word(bi).unwrap()
            }
            (RecordKind::I32, RecordKind::I32) => {
                a.i32_bits(ai).unwrap() == b.i32_bits(bi).unwrap()
            }
            (RecordKind::I64, RecordKind::I64) => {
                a.i64_bits(ai).unwrap() == b.i64_bits(bi).unwrap()
            }
            // An unconverted LEN rides verbatim: byte equality is
            // the exact judgment, descended or not.
            (RecordKind::Len, RecordKind::Len) => a.payload_bytes(ai) == b.payload_bytes(bi),
            // The conversion itself: the group's children against
            // the LEN's, in order (the converted body always
            // parses — it was walked records — so the speculative
            // descent materializes them).
            (RecordKind::Group, RecordKind::Len) => {
                let left: Vec<NodeId> = a.children(ai).collect();
                let right: Vec<NodeId> = b.children(bi).collect();
                left.len() == right.len()
                    && left.iter().zip(&right).all(|(&l, &r)| value_eq(a, l, b, r))
            }
            _ => false,
        }
    }

    let converter = Converter::new(Standard::Tolerant, DepthLimit::REFERENCE);
    let mut converted_total = 0;
    for seed in 0..48u64 {
        // Group-free: conversion is the identity, byte for byte —
        // the exact claim the identity transcode already pinned
        // over these bytes.
        let (flat, _) = build(seed, false);
        let (out, stats) = converter.convert(&flat).unwrap_or_else(|e| {
            panic!("seed {seed}: group-free conversion refused: {e:?}");
        });
        assert_eq!(out, flat, "seed {seed}: group-free conversion moved bytes");
        assert_eq!(stats.converted(), 0);

        // Grouped: the conversion crosses the capability boundary.
        let (doc, _) = build(seed, true);
        let (out, stats) = converter
            .convert(&doc)
            .unwrap_or_else(|e| panic!("seed {seed}: conversion refused: {e:?}"));
        assert!(stats.converted() >= 1, "seed {seed}: no group converted");
        converted_total += stats.converted();

        // The groupless machines that refuse the input accept the
        // output, whole-fed and chunk-fed.
        for size in [out.len(), 7] {
            let mut p = protobuf_edit::scan::groupless::Validator::new(Standard::Tolerant);
            for part in out.chunks(size) {
                p.feed(part).unwrap_or_else(|e| panic!("seed {seed}: groupless scan: {e:?}"));
            }
            p.finish().unwrap_or_else(|e| panic!("seed {seed}: groupless finish: {e:?}"));
        }

        // Values survive: every source node equals its image under
        // the grouped reader, structurally.
        let before =
            Tree::parse(Admitted::new(&doc).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
        assert!(before.is_complete(), "seed {seed}: source parse faulted: {:?}", before.fault());
        let after = Tree::parse(Admitted::new(&out).unwrap(), DepthLimit::REFERENCE, &mut NoAdvice);
        assert!(after.is_complete(), "seed {seed}: output parse faulted: {:?}", after.fault());
        let left: Vec<NodeId> = before.top().collect();
        let right: Vec<NodeId> = after.top().collect();
        assert_eq!(left.len(), right.len(), "seed {seed}: top-level record count moved");
        for (&l, &r) in left.iter().zip(&right) {
            assert!(
                value_eq(&before, l, &after, r),
                "seed {seed}: a converted value diverged at field {}",
                before.field(l).as_inner()
            );
        }

        // Re-conversion is a fixed point: the output has no group
        // left to re-frame.
        let (again, again_stats) = converter
            .convert(&out)
            .unwrap_or_else(|e| panic!("seed {seed}: re-conversion refused: {e:?}"));
        assert_eq!(again, out, "seed {seed}: conversion is not idempotent");
        assert_eq!(again_stats.converted(), 0);
    }
    assert!(converted_total >= 96, "only {converted_total} groups converted across all seeds");
}

/// The select judges: a corpus with one fixed role per field
/// number, designed so a hand-rolled traverse walker can
/// independently derive every match, and the rewriter's Delete
/// action can independently derive every selected extent.
///
/// Field roles: f1 varints (the wildcard's target), f2 I32s (the
/// exact two-hop target), f3 raw LEN blobs (top-level target,
/// never committed), f4 message LENs (the deep route), f5 groups
/// (grouped corpus: route and top-level target), f6 varint noise,
/// f7 message LENs (top-level target *and* route — the
/// target∩route case), f8 groups outside every descend set.
mod select_judges {
    use protobuf_edit::path::{Program, Segment};
    use protobuf_edit::rewrite::{Action, Rule, RuleSet};
    use protobuf_edit::{DepthLimit, FieldNumber};

    use super::Rng;
    use protobuf_edit::construct::grouped::{BodyBuilder, Builder};

    const fn fd(n: u32) -> FieldNumber {
        FieldNumber::new(n).expect("corpus fields are static")
    }

    /// One observation, projected out of either dialect's match
    /// vocabulary for row-by-row comparison.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Ev<'i> {
        Varint(u64),
        I32(u32),
        Len(&'i [u8]),
        Group(&'i [u8]),
    }

    /// (path index, span start, span end, observation).
    type Row<'i> = (u32, u32, u32, Ev<'i>);

    fn grow(
        rng: &mut Rng,
        body: &mut BodyBuilder<'_, '_>,
        depth: u32,
        budget: &mut u32,
        groups: bool,
    ) {
        while *budget > 0 {
            *budget -= 1;
            match rng.next() % 10 {
                0 | 1 => body.push_varint(fd(1), rng.next() >> (rng.next() % 60)),
                2 => body.push_varint(fd(6), rng.next()),
                3 => {
                    #[allow(
                        clippy::as_conversions,
                        reason = "seed bits truncate into the i32 domain"
                    )]
                    body.push_i32(fd(2), rng.next() as u32);
                }
                4 => {
                    let len = usize::try_from(rng.next() % 12).expect("tiny");
                    body.push_len_copy(fd(3), &vec![0xA5u8; len]);
                }
                5 | 6 if depth > 0 => {
                    body.message(fd(4), |m| grow(rng, m, depth - 1, budget, groups));
                }
                7 if depth > 0 => {
                    body.message(fd(7), |m| grow(rng, m, depth - 1, budget, groups));
                }
                8 if groups && depth > 0 => {
                    body.group(fd(5), |m| grow(rng, m, depth - 1, budget, groups));
                }
                9 if groups && depth > 0 => {
                    body.group(fd(8), |m| grow(rng, m, depth - 1, budget, groups));
                }
                _ => body.push_varint(fd(6), rng.next()),
            }
        }
    }

    /// One seeded document. Deterministic fixtures guarantee every
    /// program leg fires at least once per seed: a top f3 blob, a
    /// top f7 message (target∩route) and a top f4 message with an
    /// exactly-one-hop f2 (the fan-out overlap), a top f5 group in
    /// the grouped flavor, and a trailing unmatched varint so a
    /// perturbed span can always grow into unselected bytes.
    fn build(seed: u64, groups: bool) -> Vec<u8> {
        let mut rng = Rng(0xA076_1D64_78BD_642F ^ (seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)));
        let depth = 1 + u32::try_from(rng.next() % 10).expect("tiny");
        let mut budget = 80 + u32::try_from(rng.next() % 80).expect("tiny");
        let mut b = Builder::new();
        b.push_varint(fd(1), seed);
        b.message(fd(4), |m| grow(&mut rng, m, depth, &mut budget, groups));
        b.push_len(fd(3), b"raw-blob");
        b.message(fd(7), |m| {
            m.push_varint(fd(1), 9);
            m.push_len(fd(3), &[0xFF]);
        });
        b.message(fd(4), |m| {
            m.push_i32(fd(2), 5);
            m.push_varint(fd(1), 1);
        });
        if groups {
            b.group(fd(5), |m| {
                m.push_varint(fd(1), 9);
                m.push_varint(fd(6), 1);
            });
        }
        b.push_varint(fd(6), 7);
        b.finish().expect("seeded documents stay far under the cap")
    }

    /// Leaked path storage keeps the test bodies free of
    /// self-referential lifetimes; test-local, single-shot.
    fn leak<'r>(path: Vec<Segment<'r>>) -> &'r [Segment<'r>] {
        Box::leak(path.into_boxed_slice())
    }

    /// The oracle program: the deep wildcard leg, the exact
    /// two-hop leg, both top-LEN targets, the deliberate f2
    /// overlap (fan-out), and — grouped — the top group target.
    fn oracle_paths<'r>(route: &'r [FieldNumber], groups: bool) -> Vec<&'r [Segment<'r>]> {
        let mut paths: Vec<&[Segment<'_>]> = vec![
            leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(1))]),
            leak(vec![Segment::Field(fd(3))]),
            leak(vec![Segment::Field(fd(4)), Segment::Field(fd(2))]),
            leak(vec![Segment::Field(fd(7))]),
            leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(2))]),
        ];
        if groups {
            paths.push(leak(vec![Segment::Field(fd(5))]));
        }
        paths
    }

    /// The cross-machine program: every target sits at top level
    /// (or inside a container that is itself a top-level target),
    /// so deleting a selected record never re-encodes a surviving
    /// ancestor's LEN prefix — the one condition under which
    /// "document minus selected spans" and "rewrite with Delete"
    /// are byte-identical judgments. Routes lead only into the
    /// targeted f7 (and f5) containers, whose interior spans the
    /// container span subsumes; and no two paths target one
    /// record, so Delete never faults Conflict.
    fn delete_paths<'r>(route: &'r [FieldNumber], groups: bool) -> Vec<&'r [Segment<'r>]> {
        let mut paths: Vec<&[Segment<'_>]> = vec![
            leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(1))]),
            leak(vec![Segment::Field(fd(3))]),
            leak(vec![Segment::Field(fd(4))]),
            leak(vec![Segment::Field(fd(7))]),
        ];
        if groups {
            paths.push(leak(vec![Segment::Field(fd(5))]));
        }
        paths
    }

    /// The hand-rolled traverse oracle: an independent walker that
    /// re-derives the full match sequence for the fixed corpus
    /// programs from the traverse cursors alone. Scope state is
    /// three booleans — `top` (the root layer), `wild` (the
    /// route wildcard is live), `p2` (the exact two-hop path's
    /// second state is live) — because the corpus pins one field
    /// per role.
    mod oracle {
        use super::{Ev, Row, fd};

        /// Path indices in the oracle program (fan-out included).
        const P_WILD_F1: u32 = 0;
        const P_TOP_F3: u32 = 1;
        const P_F4_F2: u32 = 2;
        const P_TOP_F7: u32 = 3;
        const P_WILD_F2: u32 = 4;
        const P_TOP_F5: u32 = 5;

        struct Scope {
            top: bool,
            wild: bool,
            p2: bool,
        }

        fn routed(field: protobuf_edit::FieldNumber, groups: bool) -> bool {
            field == fd(4) || field == fd(7) || (groups && field == fd(5))
        }

        pub fn walk_groupless<'i>(input: &'i [u8], out: &mut Vec<Row<'i>>) {
            layer_groupless(input, 0, &Scope { top: true, wild: true, p2: false }, out);
        }

        fn layer_groupless<'i>(window: &'i [u8], base: u32, scope: &Scope, out: &mut Vec<Row<'i>>) {
            use protobuf_edit::traverse::groupless::{Cursor, EntryKind};
            let mut cursor = Cursor::within(window);
            let mut head = base;
            while let Some(entry) = cursor.next() {
                let entry = entry.expect("the corpus is lawful wire");
                let end = base + cursor.pos();
                let field = entry.field();
                match entry.kind() {
                    EntryKind::Varint(word) => {
                        if scope.wild && field == fd(1) {
                            out.push((P_WILD_F1, head, end, Ev::Varint(word)));
                        }
                    }
                    EntryKind::I32(bits) => {
                        if field == fd(2) {
                            if scope.p2 {
                                out.push((P_F4_F2, head, end, Ev::I32(bits)));
                            }
                            if scope.wild {
                                out.push((P_WILD_F2, head, end, Ev::I32(bits)));
                            }
                        }
                    }
                    EntryKind::I64(_) => {}
                    EntryKind::Len(payload) => {
                        if scope.top && field == fd(3) {
                            out.push((P_TOP_F3, head, end, Ev::Len(payload)));
                        }
                        if scope.top && field == fd(7) {
                            out.push((P_TOP_F7, head, end, Ev::Len(payload)));
                        }
                        if scope.wild && routed(field, false) {
                            let start =
                                end - u32::try_from(payload.len()).expect("LEN-class payload");
                            let child =
                                Scope { top: false, wild: true, p2: scope.top && field == fd(4) };
                            layer_groupless(payload, start, &child, out);
                        }
                    }
                }
                head = end;
            }
        }

        pub fn walk_grouped<'i>(input: &'i [u8], out: &mut Vec<Row<'i>>) {
            layer_grouped(input, 0, Scope { top: true, wild: true, p2: false }, out);
        }

        fn layer_grouped<'i>(window: &'i [u8], base: u32, scope: Scope, out: &mut Vec<Row<'i>>) {
            use protobuf_edit::traverse::GroupDepth;
            use protobuf_edit::traverse::grouped::{Cursor, EntryKind};
            let mut cursor = Cursor::within(window, GroupDepth::REFERENCE);
            let mut head = base;
            // Group frames suspend scopes in-band; the innermost
            // last, each carrying its open geometry and whether it
            // is a selected top-level f5.
            let mut scopes = vec![scope];
            let mut frames: Vec<(u32, u32, bool)> = Vec::new();
            while let Some(entry) = cursor.next() {
                let entry = entry.expect("the corpus is lawful wire");
                let end = base + cursor.pos();
                let field = entry.field();
                let scope = scopes.last().expect("the root scope never pops");
                match entry.kind() {
                    EntryKind::Varint(word) => {
                        if scope.wild && field == fd(1) {
                            out.push((P_WILD_F1, head, end, Ev::Varint(word)));
                        }
                    }
                    EntryKind::I32(bits) => {
                        if field == fd(2) {
                            if scope.p2 {
                                out.push((P_F4_F2, head, end, Ev::I32(bits)));
                            }
                            if scope.wild {
                                out.push((P_WILD_F2, head, end, Ev::I32(bits)));
                            }
                        }
                    }
                    EntryKind::I64(_) => {}
                    EntryKind::Len(payload) => {
                        if scope.top && field == fd(3) {
                            out.push((P_TOP_F3, head, end, Ev::Len(payload)));
                        }
                        if scope.top && field == fd(7) {
                            out.push((P_TOP_F7, head, end, Ev::Len(payload)));
                        }
                        if scope.wild && routed(field, true) {
                            let start =
                                end - u32::try_from(payload.len()).expect("LEN-class payload");
                            let child =
                                Scope { top: false, wild: true, p2: scope.top && field == fd(4) };
                            layer_grouped(payload, start, child, out);
                        }
                    }
                    EntryKind::GroupEnter => {
                        frames.push((head, end, scope.top && field == fd(5)));
                        scopes.push(Scope {
                            top: false,
                            wild: scope.wild && routed(field, true),
                            p2: false,
                        });
                    }
                    EntryKind::GroupExit => {
                        scopes.pop();
                        let (open, body, selected) =
                            frames.pop().expect("the cursor verifies pairing");
                        if selected {
                            let interior = &window[usize::try_from(body - base).expect("in-window")
                                ..usize::try_from(head - base).expect("in-window")];
                            out.push((P_TOP_F5, open, end, Ev::Group(interior)));
                        }
                    }
                }
                head = end;
            }
        }
    }

    fn groupless_rows<'i>(input: &'i [u8], program: &Program<'_>) -> Vec<Row<'i>> {
        use protobuf_edit::select::groupless::{MatchKind, Matches};
        Matches::over(input, program, DepthLimit::REFERENCE)
            .expect("corpus admits")
            .map(|hit| {
                let hit = hit.expect("the corpus is lawful wire");
                let ev = match hit.kind() {
                    MatchKind::Varint(word) => Ev::Varint(word),
                    MatchKind::I32(bits) => Ev::I32(bits),
                    MatchKind::I64(_) => panic!("the corpus carries no I64 targets"),
                    MatchKind::Len(payload) => Ev::Len(payload),
                };
                (hit.path().index(), hit.span().start(), hit.span().end(), ev)
            })
            .collect()
    }

    /// The canonical twin over the same walk: the corpus is
    /// builder-emitted (minimal wire), so its rows must equal the
    /// tolerant selector's exactly.
    fn canonical_groupless_rows<'i>(input: &'i [u8], program: &Program<'_>) -> Vec<Row<'i>> {
        use protobuf_edit::select::groupless::{CanonicalMatches, MatchKind};
        CanonicalMatches::over(input, program, DepthLimit::REFERENCE)
            .expect("corpus admits")
            .map(|hit| {
                let hit = hit.expect("the corpus is minimal wire");
                let ev = match hit.kind() {
                    MatchKind::Varint(word) => Ev::Varint(word),
                    MatchKind::I32(bits) => Ev::I32(bits),
                    MatchKind::I64(_) => panic!("the corpus carries no I64 targets"),
                    MatchKind::Len(payload) => Ev::Len(payload),
                };
                (hit.path().index(), hit.span().start(), hit.span().end(), ev)
            })
            .collect()
    }

    fn grouped_rows<'i>(input: &'i [u8], program: &Program<'_>) -> Vec<Row<'i>> {
        use protobuf_edit::select::grouped::{MatchKind, Matches};
        Matches::over(input, program, DepthLimit::REFERENCE)
            .expect("corpus admits")
            .map(|hit| {
                let hit = hit.expect("the corpus is lawful wire");
                let ev = match hit.kind() {
                    MatchKind::Varint(word) => Ev::Varint(word),
                    MatchKind::I32(bits) => Ev::I32(bits),
                    MatchKind::I64(_) => panic!("the corpus carries no I64 targets"),
                    MatchKind::Len(payload) => Ev::Len(payload),
                    MatchKind::Group(interior) => Ev::Group(interior),
                };
                (hit.path().index(), hit.span().start(), hit.span().end(), ev)
            })
            .collect()
    }

    /// The grouped canonical twin ([`canonical_groupless_rows`]).
    fn canonical_grouped_rows<'i>(input: &'i [u8], program: &Program<'_>) -> Vec<Row<'i>> {
        use protobuf_edit::select::grouped::{CanonicalMatches, MatchKind};
        CanonicalMatches::over(input, program, DepthLimit::REFERENCE)
            .expect("corpus admits")
            .map(|hit| {
                let hit = hit.expect("the corpus is minimal wire");
                let ev = match hit.kind() {
                    MatchKind::Varint(word) => Ev::Varint(word),
                    MatchKind::I32(bits) => Ev::I32(bits),
                    MatchKind::I64(_) => panic!("the corpus carries no I64 targets"),
                    MatchKind::Len(payload) => Ev::Len(payload),
                    MatchKind::Group(interior) => Ev::Group(interior),
                };
                (hit.path().index(), hit.span().start(), hit.span().end(), ev)
            })
            .collect()
    }

    /// Removes the union of `spans` from `doc` — the document
    /// minus everything select reported.
    fn reconstruct(doc: &[u8], spans: &[(u32, u32)]) -> Vec<u8> {
        let mut sorted = spans.to_vec();
        sorted.sort_unstable();
        let mut out = Vec::new();
        let mut at = 0usize;
        for &(start, end) in &sorted {
            let start = usize::try_from(start).expect("admitted coordinate");
            let end = usize::try_from(end).expect("admitted coordinate");
            if start > at {
                out.extend_from_slice(&doc[at..start]);
            }
            at = at.max(end);
        }
        out.extend_from_slice(&doc[at..]);
        out
    }

    #[test]
    fn a_hand_rolled_traverse_oracle_agrees_on_the_full_match_sequence() {
        let route = [fd(4), fd(7)];
        let path_set = oracle_paths(&route, false);
        let program = Program::over(&path_set).expect("corpus paths admit");
        let mut fanned_out = 0;
        for seed in 0..32u64 {
            let doc = build(seed, false);
            assert!(doc.len() >= 80, "seed {seed}: generator produced {} bytes", doc.len());

            let mut expected = Vec::new();
            oracle::walk_groupless(&doc, &mut expected);
            assert!(expected.len() >= 8, "seed {seed}: the oracle derived too few matches");

            // Both dialect machines read the group-free corpus and
            // must both equal the oracle, row for row — the
            // canonical twins too: builder output is minimal wire,
            // so acceptance narrowing changes nothing.
            let groupless = groupless_rows(&doc, &program);
            assert_eq!(groupless, expected, "seed {seed}: the groupless selector diverged");
            let grouped = grouped_rows(&doc, &program);
            assert_eq!(grouped, expected, "seed {seed}: the grouped selector diverged");
            let canonical = canonical_groupless_rows(&doc, &program);
            assert_eq!(canonical, expected, "seed {seed}: the canonical groupless twin diverged");
            let canonical = canonical_grouped_rows(&doc, &program);
            assert_eq!(canonical, expected, "seed {seed}: the canonical grouped twin diverged");

            // The overlap leg really fired: some record delivered
            // to both f2 paths.
            fanned_out += expected
                .windows(2)
                .filter(|pair| pair[0].1 == pair[1].1 && (pair[0].0, pair[1].0) == (2, 4))
                .count();
        }
        assert!(fanned_out >= 16, "the corpus fanned out only {fanned_out} records");
    }

    #[test]
    fn the_grouped_oracle_agrees_over_group_bearing_documents() {
        let route = [fd(4), fd(5), fd(7)];
        let path_set = oracle_paths(&route, true);
        let program = Program::over(&path_set).expect("corpus paths admit");
        let mut group_hits = 0;
        for seed in 0..32u64 {
            let doc = build(seed, true);
            let mut expected = Vec::new();
            oracle::walk_grouped(&doc, &mut expected);
            assert!(expected.len() >= 8, "seed {seed}: the oracle derived too few matches");
            let rows = grouped_rows(&doc, &program);
            assert_eq!(rows, expected, "seed {seed}: the grouped selector diverged");
            let canonical = canonical_grouped_rows(&doc, &program);
            assert_eq!(canonical, expected, "seed {seed}: the canonical grouped twin diverged");
            group_hits += rows.iter().filter(|row| matches!(row.3, Ev::Group(_))).count();
        }
        assert!(group_hits >= 32, "the corpus delivered only {group_hits} group matches");
    }

    #[test]
    fn select_spans_reconstruct_rewrite_deletions_byte_for_byte() {
        // The strongest leg: two independent machines — the read
        // selector and the write rewriter — must factor the
        // document identically. Deleting every selected record
        // (conflict-free, top-level-anchored program) and removing
        // every reported span are the same judgment reached
        // through different code.
        let route_groupless = [fd(7)];
        let route_grouped = [fd(5), fd(7)];
        for (grouped, route) in [(false, &route_groupless[..]), (true, &route_grouped[..])] {
            let path_set = delete_paths(route, grouped);
            let program = Program::over(&path_set).expect("corpus paths admit");
            let rules: Vec<Rule<'_>> =
                path_set.iter().map(|path| Rule { path, action: Action::Delete }).collect();
            let set = RuleSet::over(&rules).expect("corpus rules admit");
            for seed in 0..32u64 {
                let doc = build(seed, grouped);
                let spans: Vec<(u32, u32)> = if grouped {
                    grouped_rows(&doc, &program).iter().map(|row| (row.1, row.2)).collect()
                } else {
                    groupless_rows(&doc, &program).iter().map(|row| (row.1, row.2)).collect()
                };
                assert!(spans.len() >= 4, "seed {seed}: too few spans to judge anything");
                // The target∩route leg really fired: some span
                // sits strictly inside another (an interior match
                // within a selected, routed container).
                assert!(
                    spans.iter().any(|inner| {
                        spans.iter().any(|outer| outer.0 < inner.0 && inner.1 <= outer.1)
                    }),
                    "seed {seed}: no interior span inside a selected container"
                );

                let rewritten = if grouped {
                    protobuf_edit::rewrite::grouped::rewrite(&doc, &set, DepthLimit::REFERENCE)
                        .expect("the corpus rewrites clean")
                        .0
                } else {
                    protobuf_edit::rewrite::groupless::rewrite(&doc, &set, DepthLimit::REFERENCE)
                        .expect("the corpus rewrites clean")
                        .0
                };
                assert_eq!(
                    reconstruct(&doc, &spans),
                    rewritten,
                    "seed {seed} grouped={grouped}: the machines factored the document apart"
                );

                // Negative control: the judge must be able to go
                // red. Growing the last-ending span by one byte
                // eats into the trailing unmatched varint, which no
                // other span covers — the reconstruction must
                // diverge.
                let mut perturbed = spans.clone();
                let widest =
                    perturbed.iter().enumerate().max_by_key(|(_, s)| s.1).expect("spans exist").0;
                assert!(
                    usize::try_from(perturbed[widest].1).expect("admitted") < doc.len(),
                    "seed {seed}: no unselected tail left to perturb into"
                );
                perturbed[widest].1 += 1;
                assert_ne!(
                    reconstruct(&doc, &perturbed),
                    rewritten,
                    "seed {seed} grouped={grouped}: a perturbed span did not redden the judge"
                );
            }
        }
    }
}

/// The route judges: the streaming router against the buffered
/// selector — same documents, same programs, at every chunk split.
///
/// Normalization: scalar events map to rows directly; a tapped LEN
/// materializes one row per targeting path at its head event (the
/// selector's pre-order position) and a tapped group at its
/// verified close (the selector's post-order position), each body
/// filled from that tap's segments. The recording sink asserts the
/// tiling facts as it records — pieces contiguous, sums equal to
/// the declared length, the last piece flush against the exit — so
/// "segments tile the body exactly" is machine-checked on every
/// run, not just implied by byte equality. Equality is then over
/// the full ordered row sequences.
mod route_judges {
    use core::ops::ControlFlow;

    use protobuf_edit::construct::grouped::{BodyBuilder, Builder};
    use protobuf_edit::path::{PathId, Program, Segment};
    use protobuf_edit::route::{Flow, Standard};
    use protobuf_edit::{DepthLimit, FieldNumber, PayloadLen};

    use super::Rng;

    const fn fd(n: u32) -> FieldNumber {
        FieldNumber::new(n).expect("corpus fields are static")
    }

    /// One normalized observation. Scalar rows carry the record
    /// head; container rows carry head, record end, and the body.
    #[derive(Clone, PartialEq, Eq, Debug)]
    enum Row {
        Varint { path: u32, field: u32, at: u64, value: u64 },
        I32 { path: u32, field: u32, at: u64, bits: u32 },
        I64 { path: u32, field: u32, at: u64, bits: u64 },
        Len { path: u32, field: u32, at: u64, end: u64, body: Vec<u8> },
        Group { path: u32, field: u32, at: u64, end: u64, body: Vec<u8> },
    }

    /// A LEN tap fills the row it materialized at its head; a
    /// group tap accumulates until its close materializes the row.
    enum OpenKind {
        Len { row: usize, declared: u64 },
        Group { field: u32, body: Vec<u8> },
    }

    /// One open tap instance under observation, keyed by the
    /// instance identity every segment quotes: (path, record head).
    struct Open {
        path: u32,
        at: u64,
        kind: OpenKind,
        /// Where the next piece must start (taps pin it at their
        /// first piece; groups know it from the enter event).
        next: Option<u64>,
    }

    #[derive(Default)]
    struct Tape {
        rows: Vec<Row>,
        open: Vec<Open>,
    }

    impl Tape {
        fn scalar(&mut self, row: Row) {
            self.rows.push(row);
        }

        fn len(&mut self, path: PathId, field: FieldNumber, at: u64, len: PayloadLen) {
            self.open.push(Open {
                path: path.index(),
                at,
                kind: OpenKind::Len { row: self.rows.len(), declared: u64::from(len.as_inner()) },
                next: None,
            });
            self.rows.push(Row::Len {
                path: path.index(),
                field: field.as_inner(),
                at,
                end: 0,
                body: Vec::new(),
            });
        }

        fn seg(&mut self, path: PathId, at: u64, seg_at: u64, bytes: &[u8]) {
            assert!(!bytes.is_empty(), "no tap delivers an empty piece");
            let open = self
                .open
                .iter_mut()
                .rev()
                .find(|open| open.path == path.index() && open.at == at)
                .expect("a segment names an open tap");
            if let Some(next) = open.next {
                assert_eq!(next, seg_at, "pieces of one tap tile contiguously");
            }
            let width = u64::try_from(bytes.len()).expect("pieces are chunk-bounded");
            open.next = Some(seg_at + width);
            match &mut open.kind {
                OpenKind::Len { row, .. } => {
                    let (Row::Len { body, .. } | Row::Group { body, .. }) = &mut self.rows[*row]
                    else {
                        panic!("open LEN taps point at container rows");
                    };
                    body.extend_from_slice(bytes);
                }
                OpenKind::Group { body, .. } => body.extend_from_slice(bytes),
            }
        }

        fn len_exit(&mut self, path: PathId, field: FieldNumber, at: u64, end: u64) {
            let slot = self
                .open
                .iter()
                .rposition(|open| open.path == path.index() && open.at == at)
                .expect("an exit names an open tap");
            let open = self.open.remove(slot);
            let OpenKind::Len { row, declared } = open.kind else {
                panic!("a LEN exit closes a LEN tap");
            };
            let Row::Len { field: row_field, end: row_end, body, .. } = &mut self.rows[row] else {
                panic!("the LEN tap's row is a LEN row");
            };
            assert_eq!(*row_field, field.as_inner(), "the exit names the head's field");
            assert_eq!(
                u64::try_from(body.len()).expect("bodies are LEN-class"),
                declared,
                "pieces sum to the declared length"
            );
            if let Some(next) = open.next {
                assert_eq!(next, end, "the last piece ends flush at the exit");
            } else {
                assert_eq!(declared, 0, "only a zero-length body delivers no piece");
            }
            *row_end = end;
        }

        fn group_enter(&mut self, path: PathId, field: FieldNumber, at: u64, body_at: u64) {
            self.open.push(Open {
                path: path.index(),
                at,
                kind: OpenKind::Group { field: field.as_inner(), body: Vec::new() },
                next: Some(body_at),
            });
        }

        fn group_exit(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            body_end: u64,
            end: u64,
        ) {
            let slot = self
                .open
                .iter()
                .rposition(|open| open.path == path.index() && open.at == at)
                .expect("an exit names an open tap");
            let open = self.open.remove(slot);
            let OpenKind::Group { field: entered, body } = open.kind else {
                panic!("a group exit closes a group tap");
            };
            assert_eq!(entered, field.as_inner(), "the exit names the enter's field");
            assert_eq!(
                open.next,
                Some(body_end),
                "the pieces tile the body exactly out to the end tag"
            );
            self.rows.push(Row::Group {
                path: path.index(),
                field: field.as_inner(),
                at,
                end,
                body,
            });
        }

        fn settled(self) -> Vec<Row> {
            assert!(self.open.is_empty(), "every tap closed before the verdict");
            self.rows
        }
    }

    impl protobuf_edit::route::groupless::Sink for Tape {
        fn on_varint(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            value: u64,
        ) -> ControlFlow<()> {
            self.scalar(Row::Varint { path: path.index(), field: field.as_inner(), at, value });
            ControlFlow::Continue(())
        }
        fn on_i32(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            bits: u32,
        ) -> ControlFlow<()> {
            self.scalar(Row::I32 { path: path.index(), field: field.as_inner(), at, bits });
            ControlFlow::Continue(())
        }
        fn on_i64(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            bits: u64,
        ) -> ControlFlow<()> {
            self.scalar(Row::I64 { path: path.index(), field: field.as_inner(), at, bits });
            ControlFlow::Continue(())
        }
        fn on_len(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            len: PayloadLen,
        ) -> ControlFlow<()> {
            self.len(path, field, at, len);
            ControlFlow::Continue(())
        }
        fn on_segment(
            &mut self,
            path: PathId,
            at: u64,
            seg_at: u64,
            bytes: &[u8],
        ) -> ControlFlow<()> {
            self.seg(path, at, seg_at, bytes);
            ControlFlow::Continue(())
        }
        fn on_len_exit(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            end: u64,
        ) -> ControlFlow<()> {
            self.len_exit(path, field, at, end);
            ControlFlow::Continue(())
        }
    }

    impl protobuf_edit::route::grouped::Sink for Tape {
        fn on_varint(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            value: u64,
        ) -> ControlFlow<()> {
            self.scalar(Row::Varint { path: path.index(), field: field.as_inner(), at, value });
            ControlFlow::Continue(())
        }
        fn on_i32(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            bits: u32,
        ) -> ControlFlow<()> {
            self.scalar(Row::I32 { path: path.index(), field: field.as_inner(), at, bits });
            ControlFlow::Continue(())
        }
        fn on_i64(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            bits: u64,
        ) -> ControlFlow<()> {
            self.scalar(Row::I64 { path: path.index(), field: field.as_inner(), at, bits });
            ControlFlow::Continue(())
        }
        fn on_len(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            len: PayloadLen,
        ) -> ControlFlow<()> {
            self.len(path, field, at, len);
            ControlFlow::Continue(())
        }
        fn on_segment(
            &mut self,
            path: PathId,
            at: u64,
            seg_at: u64,
            bytes: &[u8],
        ) -> ControlFlow<()> {
            self.seg(path, at, seg_at, bytes);
            ControlFlow::Continue(())
        }
        fn on_len_exit(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            end: u64,
        ) -> ControlFlow<()> {
            self.len_exit(path, field, at, end);
            ControlFlow::Continue(())
        }
        fn on_group_enter(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            body_at: u64,
        ) -> ControlFlow<()> {
            self.group_enter(path, field, at, body_at);
            ControlFlow::Continue(())
        }
        fn on_group_exit(
            &mut self,
            path: PathId,
            field: FieldNumber,
            at: u64,
            body_end: u64,
            end: u64,
        ) -> ControlFlow<()> {
            self.group_exit(path, field, at, body_end, end);
            ControlFlow::Continue(())
        }
    }

    // ─── the corpus (select_judges' roles, plus forced nesting) ───

    fn grow(
        rng: &mut Rng,
        body: &mut BodyBuilder<'_, '_>,
        depth: u32,
        budget: &mut u32,
        groups: bool,
    ) {
        let arms = if groups { 11 } else { 9 };
        while *budget > 0 {
            *budget -= 1;
            match rng.next() % arms {
                0 | 1 => body.push_varint(fd(1), rng.next() >> (rng.next() % 60)),
                2 => body.push_varint(fd(6), rng.next()),
                3 => {
                    #[allow(
                        clippy::as_conversions,
                        reason = "seed bits truncate into the i32 domain"
                    )]
                    body.push_i32(fd(2), rng.next() as u32);
                }
                4 => {
                    let len = usize::try_from(rng.next() % 12).expect("tiny");
                    body.push_len_copy(fd(3), &vec![0xA5u8; len]);
                }
                5 => body.push_i64(fd(9), rng.next()),
                6 | 7 if depth > 0 => {
                    body.message(fd(4), |m| grow(rng, m, depth - 1, budget, groups));
                }
                8 if depth > 0 => {
                    body.message(fd(7), |m| grow(rng, m, depth - 1, budget, groups));
                }
                9 if groups && depth > 0 => {
                    body.group(fd(5), |m| grow(rng, m, depth - 1, budget, groups));
                }
                10 if groups && depth > 0 => {
                    body.group(fd(8), |m| grow(rng, m, depth - 1, budget, groups));
                }
                _ => body.push_varint(fd(6), rng.next()),
            }
        }
    }

    /// One seeded document. Deterministic fixtures force every leg
    /// per seed: a top counted tap (f3), a top tap-and-commit f7
    /// holding a counted tap, a nested f7 (taps inside taps), and —
    /// grouped — a group inside the tapped LEN plus a top group;
    /// the f4 fixture forces the f2 fan-out; the trailing varint
    /// leaves unselected bytes.
    fn build(seed: u64, groups: bool) -> Vec<u8> {
        let mut rng = Rng(0x6C62_272E_07BB_0142 ^ (seed.wrapping_mul(0x9E37_79B9_7F4A_7C15)));
        let depth = 1 + u32::try_from(rng.next() % 8).expect("tiny");
        let mut budget = 60 + u32::try_from(rng.next() % 60).expect("tiny");
        let mut b = Builder::new();
        b.push_varint(fd(1), seed);
        b.message(fd(4), |m| grow(&mut rng, m, depth, &mut budget, groups));
        b.push_len(fd(3), b"raw-blob");
        b.message(fd(7), |m| {
            m.push_varint(fd(1), 9);
            m.push_len(fd(3), &[0xFF]);
            m.message(fd(7), |m2| {
                m2.push_varint(fd(1), 5);
                m2.push_i64(fd(9), 77);
            });
            if groups {
                m.group(fd(5), |g| g.push_varint(fd(1), 3));
            }
        });
        b.message(fd(4), |m| {
            m.push_i32(fd(2), 5);
            m.push_varint(fd(1), 1);
        });
        if groups {
            b.group(fd(5), |g| {
                g.push_varint(fd(1), 9);
                g.push_len(fd(3), b"in-group");
            });
        }
        b.push_varint(fd(6), 7);
        b.finish().expect("seeded documents stay far under the cap")
    }

    /// Leaked path storage keeps the test bodies free of
    /// self-referential lifetimes; test-local, single-shot.
    fn leak(path: Vec<Segment<'static>>) -> &'static [Segment<'static>] {
        Box::leak(path.into_boxed_slice())
    }

    static ROUTE_GROUPLESS: [FieldNumber; 2] = [fd(4), fd(7)];
    static ROUTE_GROUPED: [FieldNumber; 3] = [fd(4), fd(5), fd(7)];

    /// The program family: deep scalars, a top counted tap, the
    /// exact two-hop, the top tap-and-commit, the deliberate f2
    /// and f7 fan-outs, counted taps and I64s at any depth — and,
    /// grouped, group targets at top and at depth.
    fn program_paths(groups: bool) -> Vec<&'static [Segment<'static>]> {
        let route: &'static [FieldNumber] = if groups { &ROUTE_GROUPED } else { &ROUTE_GROUPLESS };
        let mut paths: Vec<&[Segment<'_>]> = vec![
            leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(1))]),
            leak(vec![Segment::Field(fd(3))]),
            leak(vec![Segment::Field(fd(4)), Segment::Field(fd(2))]),
            leak(vec![Segment::Field(fd(7))]),
            leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(2))]),
            leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(7))]),
            leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(3))]),
            leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(9))]),
        ];
        if groups {
            paths.push(leak(vec![Segment::Field(fd(5))]));
            paths.push(leak(vec![Segment::AnyDepth { descend: route }, Segment::Field(fd(5))]));
        }
        paths
    }

    // ─── the two sides ───

    fn select_rows_groupless(doc: &[u8], program: &Program<'_>) -> Vec<Row> {
        use protobuf_edit::select::groupless::{MatchKind, Matches};
        Matches::over(doc, program, DepthLimit::REFERENCE)
            .expect("corpus admits")
            .map(|hit| {
                let hit = hit.expect("the corpus is lawful wire");
                let path = hit.path().index();
                let field = hit.field().as_inner();
                let at = u64::from(hit.span().start());
                match hit.kind() {
                    MatchKind::Varint(value) => Row::Varint { path, field, at, value },
                    MatchKind::I32(bits) => Row::I32 { path, field, at, bits },
                    MatchKind::I64(bits) => Row::I64 { path, field, at, bits },
                    MatchKind::Len(body) => Row::Len {
                        path,
                        field,
                        at,
                        end: u64::from(hit.span().end()),
                        body: body.to_vec(),
                    },
                }
            })
            .collect()
    }

    fn select_rows_grouped(doc: &[u8], program: &Program<'_>) -> Vec<Row> {
        use protobuf_edit::select::grouped::{MatchKind, Matches};
        Matches::over(doc, program, DepthLimit::REFERENCE)
            .expect("corpus admits")
            .map(|hit| {
                let hit = hit.expect("the corpus is lawful wire");
                let path = hit.path().index();
                let field = hit.field().as_inner();
                let at = u64::from(hit.span().start());
                let end = u64::from(hit.span().end());
                match hit.kind() {
                    MatchKind::Varint(value) => Row::Varint { path, field, at, value },
                    MatchKind::I32(bits) => Row::I32 { path, field, at, bits },
                    MatchKind::I64(bits) => Row::I64 { path, field, at, bits },
                    MatchKind::Len(body) => Row::Len { path, field, at, end, body: body.to_vec() },
                    MatchKind::Group(body) => {
                        Row::Group { path, field, at, end, body: body.to_vec() }
                    }
                }
            })
            .collect()
    }

    /// Feeds `doc` split at the given sorted cut positions.
    fn route_rows_groupless(doc: &[u8], program: &Program<'_>, cuts: &[usize]) -> Vec<Row> {
        use protobuf_edit::route::groupless::Router;
        let mut tape = Tape::default();
        let mut router = Router::new(program, Standard::Tolerant, DepthLimit::REFERENCE);
        let mut from = 0;
        for &cut in cuts {
            let flow = router.feed(&doc[from..cut], &mut tape).expect("the corpus is lawful wire");
            assert!(matches!(flow, Flow::More), "the tape never stops early");
            from = cut;
        }
        let flow = router.feed(&doc[from..], &mut tape).expect("the corpus is lawful wire");
        assert!(matches!(flow, Flow::More), "the tape never stops early");
        router.finish().expect("the corpus is lawful wire");
        tape.settled()
    }

    fn route_rows_grouped(doc: &[u8], program: &Program<'_>, cuts: &[usize]) -> Vec<Row> {
        use protobuf_edit::route::grouped::Router;
        let mut tape = Tape::default();
        let mut router = Router::new(program, Standard::Tolerant, DepthLimit::REFERENCE);
        let mut from = 0;
        for &cut in cuts {
            let flow = router.feed(&doc[from..cut], &mut tape).expect("the corpus is lawful wire");
            assert!(matches!(flow, Flow::More), "the tape never stops early");
            from = cut;
        }
        let flow = router.feed(&doc[from..], &mut tape).expect("the corpus is lawful wire");
        assert!(matches!(flow, Flow::More), "the tape never stops early");
        router.finish().expect("the corpus is lawful wire");
        tape.settled()
    }

    /// Seeded multi-cut sets plus fixed chunk sweeps for one doc.
    fn split_family(seed: u64, len: usize) -> Vec<Vec<usize>> {
        let mut family = Vec::new();
        for step in [1usize, 2, 3, 5, 7, 4096] {
            family.push((step..len).step_by(step).collect());
        }
        let mut rng = Rng(seed ^ 0xC0FF_EEBA_DF00_D000);
        for _ in 0..4 {
            let mut cuts: Vec<usize> = (0..(3 + rng.next() % 12))
                .map(|_| {
                    usize::try_from(rng.next() % (u64::try_from(len).expect("tiny") + 1))
                        .expect("tiny")
                })
                .collect();
            cuts.sort_unstable();
            cuts.dedup();
            family.push(cuts);
        }
        family
    }

    /// The vacuity guards: the corpus really nested container rows
    /// (a tap inside a tap) and really fanned records out.
    fn coverage(rows: &[Row]) -> (usize, usize) {
        let containers: Vec<(u64, u64)> = rows
            .iter()
            .filter_map(|row| match row {
                Row::Len { at, end, .. } | Row::Group { at, end, .. } => Some((*at, *end)),
                _ => None,
            })
            .collect();
        let nested = containers
            .iter()
            .filter(|(at, end)| containers.iter().any(|(oat, oend)| oat < at && end <= oend))
            .count();
        let mut fanned = 0;
        for (i, row) in rows.iter().enumerate() {
            let at = match row {
                Row::Varint { at, .. }
                | Row::I32 { at, .. }
                | Row::I64 { at, .. }
                | Row::Len { at, .. }
                | Row::Group { at, .. } => *at,
            };
            fanned += usize::from(rows[i + 1..].iter().any(|other| match other {
                Row::Varint { at: o, .. }
                | Row::I32 { at: o, .. }
                | Row::I64 { at: o, .. }
                | Row::Len { at: o, .. }
                | Row::Group { at: o, .. } => *o == at,
            }));
        }
        (nested, fanned)
    }

    #[test]
    fn the_groupless_router_equals_the_selector_at_every_chunk_split() {
        let paths = program_paths(false);
        let program = Program::over(&paths).expect("corpus paths admit");
        let seeds: u64 = if cfg!(miri) { 2 } else { 24 };
        let every_split_seeds: u64 = if cfg!(miri) { 0 } else { 6 };
        let mut nested = 0;
        let mut fanned = 0;
        for seed in 0..seeds {
            let doc = build(seed, false);
            assert!(doc.len() >= 80, "seed {seed}: generator produced {} bytes", doc.len());
            let expected = select_rows_groupless(&doc, &program);
            assert!(expected.len() >= 10, "seed {seed}: too few rows to judge anything");
            let (n, f) = coverage(&expected);
            nested += n;
            fanned += f;
            assert_eq!(
                route_rows_groupless(&doc, &program, &[]),
                expected,
                "seed {seed}: the whole-fed router diverged"
            );
            for (round, cuts) in split_family(seed, doc.len()).iter().enumerate() {
                assert_eq!(
                    route_rows_groupless(&doc, &program, cuts),
                    expected,
                    "seed {seed} split family {round} moved the observation"
                );
            }
            if seed < every_split_seeds {
                for cut in 0..=doc.len() {
                    assert_eq!(
                        route_rows_groupless(&doc, &program, &[cut]),
                        expected,
                        "seed {seed} cut {cut} moved the observation"
                    );
                }
            }
        }
        assert!(nested >= 24, "only {nested} nested container rows across all seeds");
        assert!(fanned >= 24, "only {fanned} fanned-out records across all seeds");
    }

    #[test]
    fn the_grouped_router_equals_the_selector_at_every_chunk_split() {
        let paths = program_paths(true);
        let program = Program::over(&paths).expect("corpus paths admit");
        let seeds: u64 = if cfg!(miri) { 2 } else { 24 };
        let every_split_seeds: u64 = if cfg!(miri) { 0 } else { 6 };
        let mut nested = 0;
        let mut fanned = 0;
        let mut group_rows = 0;
        for seed in 0..seeds {
            let doc = build(seed, true);
            assert!(doc.len() >= 80, "seed {seed}: generator produced {} bytes", doc.len());
            let expected = select_rows_grouped(&doc, &program);
            assert!(expected.len() >= 10, "seed {seed}: too few rows to judge anything");
            let (n, f) = coverage(&expected);
            nested += n;
            fanned += f;
            group_rows += expected.iter().filter(|row| matches!(row, Row::Group { .. })).count();
            assert_eq!(
                route_rows_grouped(&doc, &program, &[]),
                expected,
                "seed {seed}: the whole-fed router diverged"
            );
            for (round, cuts) in split_family(seed, doc.len()).iter().enumerate() {
                assert_eq!(
                    route_rows_grouped(&doc, &program, cuts),
                    expected,
                    "seed {seed} split family {round} moved the observation"
                );
            }
            if seed < every_split_seeds {
                for cut in 0..=doc.len() {
                    assert_eq!(
                        route_rows_grouped(&doc, &program, &[cut]),
                        expected,
                        "seed {seed} cut {cut} moved the observation"
                    );
                }
            }
        }
        assert!(nested >= 24, "only {nested} nested container rows across all seeds");
        assert!(fanned >= 24, "only {fanned} fanned-out records across all seeds");
        assert!(group_rows >= 24, "only {group_rows} group rows across all seeds");
    }

    #[test]
    fn a_group_end_tag_split_at_every_byte_matches_the_selector() {
        // Two-byte framing tags on field 1000, groups nested in
        // groups: every byte position — the end tags' interiors
        // included — hosts a split, and the row sequences must not
        // move against the buffered selector.
        static BIG_ROUTE: [FieldNumber; 1] = [fd(1000)];
        let paths: Vec<&'static [Segment<'static>]> = vec![
            leak(vec![Segment::Field(fd(1000))]),
            leak(vec![Segment::AnyDepth { descend: &BIG_ROUTE }, Segment::Field(fd(1))]),
            leak(vec![Segment::AnyDepth { descend: &BIG_ROUTE }, Segment::Field(fd(1000))]),
        ];
        let program = Program::over(&paths).expect("corpus paths admit");
        let mut b = Builder::new();
        b.group(fd(1000), |g| {
            g.push_varint(fd(1), 150);
            g.group(fd(1000), |inner| inner.push_varint(fd(1), 2));
            g.push_len(fd(3), b"xy");
        });
        b.push_varint(fd(6), 7);
        let doc = b.finish().expect("the fixture is tiny");
        let expected = select_rows_grouped(&doc, &program);
        assert!(
            expected.iter().filter(|row| matches!(row, Row::Group { .. })).count() >= 3,
            "the fixture must deliver nested group rows"
        );
        assert_eq!(route_rows_grouped(&doc, &program, &[]), expected);
        for cut in 0..=doc.len() {
            assert_eq!(
                route_rows_grouped(&doc, &program, &[cut]),
                expected,
                "cut {cut} moved the observation"
            );
        }
        for step in [1usize, 2, 3] {
            let cuts: Vec<usize> = (step..doc.len()).step_by(step).collect();
            assert_eq!(
                route_rows_grouped(&doc, &program, &cuts),
                expected,
                "step {step} moved the observation"
            );
        }
    }

    #[test]
    fn a_perturbed_normalized_segment_reddens_the_judge() {
        let paths = program_paths(false);
        let program = Program::over(&paths).expect("corpus paths admit");
        let doc = build(0, false);
        let expected = select_rows_groupless(&doc, &program);
        let mut rows = route_rows_groupless(&doc, &program, &[doc.len() / 2]);
        assert_eq!(rows, expected, "sanity: green before the perturbation");
        // The guard: a non-empty tapped body must exist, and the
        // byte really flips — a vacuous perturbation cannot pass.
        let body = rows
            .iter_mut()
            .find_map(|row| match row {
                Row::Len { body, .. } | Row::Group { body, .. } if !body.is_empty() => Some(body),
                _ => None,
            })
            .expect("the corpus delivers a non-empty tapped body");
        let before = body[0];
        body[0] ^= 0xFF;
        assert_ne!(body[0], before, "the perturbation happened");
        assert_ne!(rows, expected, "a perturbed segment must redden the judge");
    }
}

/// The canonical-cell agreement law: run one command script over
/// minimal input through a tolerant cell and its canonical-admission
/// twin, and the tolerant cell's canonical faces must produce the
/// canonical cell's ordinary save bytes — two different cores
/// (width-carrying rows against width-erased rows) landing on one
/// output. The tolerant machine's own fidelity save agrees too
/// (every materialized layer was admitted minimal), and `pending`,
/// statuses, source geometry, and the fidelity bytes are snapshotted
/// around every canonical call. The `|…| …` arguments are macro
/// binders, not closures.
#[cfg(all(
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "session-grouped",
    feature = "session-groupless"
))]
mod canonical_cell_agreement {
    use super::*;

    #[track_caller]
    fn h(s: &str) -> Vec<u8> {
        let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        hex.chunks(2)
            .map(|p| {
                let hi = (p[0] as char).to_digit(16).unwrap();
                let lo = (p[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }

    const fn f(n: u32) -> FieldNumber {
        match FieldNumber::new(n) {
            Some(field) => field,
            None => panic!("test field in range"),
        }
    }

    macro_rules! agreement_row {
        ($mod_name:ident,
         tolerant: |$src:ident| $open_t:expr, $t_insert:path, $t_descent:path,
         canonical: |$src2:ident| $open_c:expr, $c_insert:path, $c_descent:path,
         unwrap: |$obs:ident| $unwrap:expr) => {
            mod $mod_name {
                use super::*;
                use $c_descent as CanonicalDescent;
                use $c_insert as CanonicalInsertAt;
                use $t_descent as TolerantDescent;
                use $t_insert as TolerantInsertAt;

                #[test]
                fn identical_scripts_agree_on_canonical_bytes() {
                    // Minimal input: varint · LEN message · varint ·
                    // LEN blob — every layer admits canonically.
                    let doc = h("089601 12020801 100A 2202AABB");
                    let payload = h("0801");

                    macro_rules! run_script {
                        ($machine:ident, $Descent:ident, $InsertAt:ident) => {{
                            let t: Vec<_> = $machine.top().collect();
                            let $Descent::Opened { first: Some(inner) } =
                                $machine.descend(t[1]).unwrap()
                            else {
                                unreachable!()
                            };
                            $machine.set_varint(inner, 7).unwrap();
                            $machine.set_varint(t[0], 300).unwrap();
                            $machine.insert_varint($InsertAt::After(t[0]), f(9), 1).unwrap();
                            $machine.delete(t[2]).unwrap();
                            $machine.set_payload(t[3], &payload).unwrap();
                            t
                        }};
                    }

                    let $src = &doc[..];
                    let mut tolerant = $open_t;
                    let t = run_script!(tolerant, TolerantDescent, TolerantInsertAt);

                    let $src2 = &doc[..];
                    let mut canonical = $open_c;
                    let _ = run_script!(canonical, CanonicalDescent, CanonicalInsertAt);

                    // The snapshot around every canonical call:
                    // statuses, source geometry, fidelity bytes.
                    macro_rules! snapshot {
                        () => {{
                            let statuses: Vec<_> = t
                                .iter()
                                .map(|&handle| {
                                    let $obs = tolerant.status(handle);
                                    format!("{:?}", $unwrap)
                                })
                                .collect();
                            let spans: Vec<_> = t
                                .iter()
                                .map(|&handle| {
                                    let $obs = tolerant.span(handle);
                                    format!("{:?}", $unwrap)
                                })
                                .collect();
                            (statuses, spans, tolerant.save().unwrap())
                        }};
                    }
                    let before = snapshot!();

                    // The three canonical faces against the canonical
                    // cell's ordinary family, byte for byte. (The
                    // cell's fresh product may be a sealed carrier;
                    // its appended bytes are the same save.)
                    let fresh = tolerant.save_canonical().unwrap();
                    let mut canonical_fresh = Vec::new();
                    canonical.save_into(&mut canonical_fresh).unwrap();
                    assert_eq!(fresh, canonical_fresh, "fresh saves agree");

                    let mut tolerant_into = vec![0xAA];
                    tolerant.save_canonical_into(&mut tolerant_into).unwrap();
                    let mut canonical_into = vec![0xAA];
                    canonical.save_into(&mut canonical_into).unwrap();
                    assert_eq!(tolerant_into, canonical_into, "appended saves agree");

                    let mut tolerant_sink = Vec::new();
                    tolerant
                        .save_canonical_sink(|slice| tolerant_sink.extend_from_slice(slice))
                        .unwrap();
                    let mut canonical_sink = Vec::new();
                    canonical.save_sink(|slice| canonical_sink.extend_from_slice(slice)).unwrap();
                    assert_eq!(tolerant_sink, canonical_sink, "sink saves agree");

                    // The canonical-admission agreement law's other
                    // face: every materialized layer was admitted
                    // minimal, so the tolerant fidelity save is the
                    // same bytes.
                    assert_eq!(fresh, tolerant.save().unwrap(), "fidelity agrees on minimal input");

                    assert_eq!(snapshot!(), before, "the canonical calls read, never wrote");
                }
            }
        };
    }

    mod groupless_pairs {
        use super::*;

        agreement_row!(
            patch_amend,
            tolerant: |src| protobuf_edit::patch::groupless::Patch::open(
                src,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::patch::groupless::InsertAt,
            protobuf_edit::patch::groupless::Descent,
            canonical: |src2| protobuf_edit::amend::groupless::Amend::open(
                src2,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::amend::groupless::InsertAt,
            protobuf_edit::amend::groupless::Descent,
            unwrap: |obs| obs
        );
        agreement_row!(
            borrow_patch_borrow_amend,
            tolerant: |src| protobuf_edit::patch::groupless::BorrowPatch::open(
                src,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::patch::groupless::InsertAt,
            protobuf_edit::patch::groupless::Descent,
            canonical: |src2| protobuf_edit::amend::groupless::BorrowAmend::open(
                src2,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::amend::groupless::InsertAt,
            protobuf_edit::amend::groupless::Descent,
            unwrap: |obs| obs
        );
        agreement_row!(
            adopt_intake,
            tolerant: |src| protobuf_edit::adopt::groupless::Adopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::adopt::groupless::InsertAt,
            protobuf_edit::adopt::groupless::Descent,
            canonical: |src2| protobuf_edit::intake::groupless::Intake::open(
                src2.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::intake::groupless::InsertAt,
            protobuf_edit::intake::groupless::Descent,
            unwrap: |obs| obs
        );
        agreement_row!(
            borrow_adopt_borrow_intake,
            tolerant: |src| protobuf_edit::adopt::groupless::BorrowAdopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::adopt::groupless::InsertAt,
            protobuf_edit::adopt::groupless::Descent,
            canonical: |src2| protobuf_edit::intake::groupless::BorrowIntake::open(
                src2.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::intake::groupless::InsertAt,
            protobuf_edit::intake::groupless::Descent,
            unwrap: |obs| obs
        );
        agreement_row!(
            markup_review,
            tolerant: |src| protobuf_edit::markup::groupless::Markup::open(src).unwrap(),
            protobuf_edit::markup::groupless::InsertAt,
            protobuf_edit::markup::groupless::Descent,
            canonical: |src2| protobuf_edit::review::groupless::Review::open(src2).unwrap(),
            protobuf_edit::review::groupless::InsertAt,
            protobuf_edit::review::groupless::Descent,
            unwrap: |obs| obs.unwrap()
        );
        agreement_row!(
            borrow_markup_borrow_review,
            tolerant: |src| protobuf_edit::markup::groupless::BorrowMarkup::open(src).unwrap(),
            protobuf_edit::markup::groupless::InsertAt,
            protobuf_edit::markup::groupless::Descent,
            canonical: |src2| protobuf_edit::review::groupless::BorrowReview::open(src2)
                .unwrap(),
            protobuf_edit::review::groupless::InsertAt,
            protobuf_edit::review::groupless::Descent,
            unwrap: |obs| obs.unwrap()
        );
        agreement_row!(
            draft_session,
            tolerant: |src| protobuf_edit::draft::groupless::Draft::open_copy(src).unwrap(),
            protobuf_edit::draft::groupless::InsertAt,
            protobuf_edit::draft::groupless::Descent,
            canonical: |src2| protobuf_edit::session::groupless::Session::open_copy(src2)
                .unwrap(),
            protobuf_edit::session::groupless::InsertAt,
            protobuf_edit::session::groupless::Descent,
            unwrap: |obs| obs.unwrap()
        );
        agreement_row!(
            borrow_draft_borrow_session,
            tolerant: |src| protobuf_edit::draft::groupless::BorrowDraft::open_copy(src)
                .unwrap(),
            protobuf_edit::draft::groupless::InsertAt,
            protobuf_edit::draft::groupless::Descent,
            canonical: |src2| protobuf_edit::session::groupless::BorrowSession::open_copy(src2)
                .unwrap(),
            protobuf_edit::session::groupless::InsertAt,
            protobuf_edit::session::groupless::Descent,
            unwrap: |obs| obs.unwrap()
        );
    }

    mod grouped_pairs {
        use super::*;

        agreement_row!(
            patch_amend,
            tolerant: |src| protobuf_edit::patch::grouped::Patch::open(
                src,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::patch::grouped::InsertAt,
            protobuf_edit::patch::grouped::Descent,
            canonical: |src2| protobuf_edit::amend::grouped::Amend::open(
                src2,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::amend::grouped::InsertAt,
            protobuf_edit::amend::grouped::Descent,
            unwrap: |obs| obs
        );
        agreement_row!(
            borrow_patch_borrow_amend,
            tolerant: |src| protobuf_edit::patch::grouped::BorrowPatch::open(
                src,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::patch::grouped::InsertAt,
            protobuf_edit::patch::grouped::Descent,
            canonical: |src2| protobuf_edit::amend::grouped::BorrowAmend::open(
                src2,
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::amend::grouped::InsertAt,
            protobuf_edit::amend::grouped::Descent,
            unwrap: |obs| obs
        );
        agreement_row!(
            adopt_intake,
            tolerant: |src| protobuf_edit::adopt::grouped::Adopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::adopt::grouped::InsertAt,
            protobuf_edit::adopt::grouped::Descent,
            canonical: |src2| protobuf_edit::intake::grouped::Intake::open(
                src2.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::intake::grouped::InsertAt,
            protobuf_edit::intake::grouped::Descent,
            unwrap: |obs| obs
        );
        agreement_row!(
            borrow_adopt_borrow_intake,
            tolerant: |src| protobuf_edit::adopt::grouped::BorrowAdopt::open(
                src.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::adopt::grouped::InsertAt,
            protobuf_edit::adopt::grouped::Descent,
            canonical: |src2| protobuf_edit::intake::grouped::BorrowIntake::open(
                src2.to_vec(),
                DepthLimit::REFERENCE
            )
            .unwrap(),
            protobuf_edit::intake::grouped::InsertAt,
            protobuf_edit::intake::grouped::Descent,
            unwrap: |obs| obs
        );
        agreement_row!(
            markup_review,
            tolerant: |src| protobuf_edit::markup::grouped::Markup::open(src).unwrap(),
            protobuf_edit::markup::grouped::InsertAt,
            protobuf_edit::markup::grouped::Descent,
            canonical: |src2| protobuf_edit::review::grouped::Review::open(src2).unwrap(),
            protobuf_edit::review::grouped::InsertAt,
            protobuf_edit::review::grouped::Descent,
            unwrap: |obs| obs.unwrap()
        );
        agreement_row!(
            borrow_markup_borrow_review,
            tolerant: |src| protobuf_edit::markup::grouped::BorrowMarkup::open(src).unwrap(),
            protobuf_edit::markup::grouped::InsertAt,
            protobuf_edit::markup::grouped::Descent,
            canonical: |src2| protobuf_edit::review::grouped::BorrowReview::open(src2).unwrap(),
            protobuf_edit::review::grouped::InsertAt,
            protobuf_edit::review::grouped::Descent,
            unwrap: |obs| obs.unwrap()
        );
        agreement_row!(
            draft_session,
            tolerant: |src| protobuf_edit::draft::grouped::Draft::open_copy(src).unwrap(),
            protobuf_edit::draft::grouped::InsertAt,
            protobuf_edit::draft::grouped::Descent,
            canonical: |src2| protobuf_edit::session::grouped::Session::open_copy(src2)
                .unwrap(),
            protobuf_edit::session::grouped::InsertAt,
            protobuf_edit::session::grouped::Descent,
            unwrap: |obs| obs.unwrap()
        );
        agreement_row!(
            borrow_draft_borrow_session,
            tolerant: |src| protobuf_edit::draft::grouped::BorrowDraft::open_copy(src).unwrap(),
            protobuf_edit::draft::grouped::InsertAt,
            protobuf_edit::draft::grouped::Descent,
            canonical: |src2| protobuf_edit::session::grouped::BorrowSession::open_copy(src2)
                .unwrap(),
            protobuf_edit::session::grouped::InsertAt,
            protobuf_edit::session::grouped::Descent,
            unwrap: |obs| obs.unwrap()
        );
    }
}

#[cfg(all(
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless"
))]
mod inplace_patch_differential {
    //! The in-place editor against the patch composition it
    //! shadows. Byte form: on width-exact scripts (every new word
    //! at exactly its slot's width — patch re-emits values
    //! minimally, so byte parity is defined exactly there) the two
    //! machines produce identical documents. Semantic form: on
    //! padded slots under Tolerant the in-place editor pads where
    //! patch shrinks — geometry lawfully differs, and the
    //! re-ingested record populations must still agree value for
    //! value.

    use protobuf_edit::inplace::{Action, Rule, RuleSet};
    use protobuf_edit::path::Segment;
    use protobuf_edit::varint::encoded_len64;
    use protobuf_edit::{DepthLimit, FieldNumber};

    use super::Rng;

    const fn fx(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    /// A same-width sibling of `old` — the byte judge's script
    /// constraint.
    fn same_width(old: u64, rng: &mut Rng) -> u64 {
        let width = encoded_len64(old);
        for _ in 0..8 {
            let candidate = old ^ (rng.next() & 0x7F);
            if encoded_len64(candidate) == width {
                return candidate;
            }
        }
        old
    }

    /// One seeded script's operand set.
    struct Script {
        v1: u64,
        bits2: u32,
        bits3: u64,
        payload4: Vec<u8>,
        v5: u64,
        inner: u64,
    }

    /// The seeded document both machines edit: distinct top-level
    /// fields across every editable kind, a nested message, and a
    /// repeated field (0..=2 occurrences — the rule hits them all,
    /// and the handle walk mirrors that).
    fn build(rng: &mut Rng) -> (Vec<u8>, Script, u64) {
        use protobuf_edit::construct::groupless::Builder;
        let v1 = rng.next() >> (rng.next() % 60);
        let bits = rng.next();
        let v5 = rng.next() >> (rng.next() % 60);
        let inner = rng.next() >> (rng.next() % 60);
        let len4 = (rng.next() % 24) as usize;
        let extra = rng.next() % 3;
        let mut b = Builder::new();
        b.push_varint(fx(1), v1);
        #[allow(clippy::as_conversions, reason = "seed bits truncate into the i32 domain")]
        b.push_i32(fx(2), bits as u32);
        b.push_i64(fx(3), bits);
        b.push_len_copy(fx(4), &vec![0xA5u8; len4]);
        b.push_varint(fx(5), v5);
        b.message(fx(6), |m| m.push_varint(fx(9), inner));
        for _ in 0..extra {
            b.push_varint(fx(7), 1);
        }
        let doc = b.finish().expect("seeded documents sit far under the cap");
        let script = Script {
            v1: same_width(v1, rng),
            #[allow(clippy::as_conversions, reason = "seed bits truncate into the i32 domain")]
            bits2: rng.next() as u32,
            bits3: rng.next(),
            payload4: vec![0x5Au8; len4],
            v5: same_width(v5, rng),
            inner: same_width(inner, rng),
        };
        (doc, script, extra)
    }

    /// The script as in-place rules (`f7`'s rule hits every
    /// occurrence; 42 is width-one, as the generated values are).
    fn rules(script: &Script) -> [Rule<'_>; 7] {
        const P1: &[Segment<'static>] = &[Segment::Field(FieldNumber::new(1).unwrap())];
        const P2: &[Segment<'static>] = &[Segment::Field(FieldNumber::new(2).unwrap())];
        const P3: &[Segment<'static>] = &[Segment::Field(FieldNumber::new(3).unwrap())];
        const P4: &[Segment<'static>] = &[Segment::Field(FieldNumber::new(4).unwrap())];
        const P5: &[Segment<'static>] = &[Segment::Field(FieldNumber::new(5).unwrap())];
        const P69: &[Segment<'static>] = &[
            Segment::Field(FieldNumber::new(6).unwrap()),
            Segment::Field(FieldNumber::new(9).unwrap()),
        ];
        const P7: &[Segment<'static>] = &[Segment::Field(FieldNumber::new(7).unwrap())];
        [
            Rule { path: P1, action: Action::SetVarint(script.v1) },
            Rule { path: P2, action: Action::SetI32(script.bits2) },
            Rule { path: P3, action: Action::SetI64(script.bits3) },
            Rule { path: P4, action: Action::SetPayload(&script.payload4) },
            Rule { path: P5, action: Action::SetVarint(script.v5) },
            Rule { path: P69, action: Action::SetVarint(script.inner) },
            Rule { path: P7, action: Action::SetVarint(42) },
        ]
    }

    #[test]
    fn width_exact_scripts_agree_with_patch_byte_for_byte() {
        use protobuf_edit::inplace::groupless::apply;
        use protobuf_edit::patch::groupless::Patch;
        use protobuf_edit::wire::groupless::RecordKind;

        let mut rng = Rng(0xD1F0_5EED_0BAD_CAFE);
        let mut edited_rounds = 0u64;
        for round in 0..64 {
            let (doc, script, extra) = build(&mut rng);
            let script_rules = rules(&script);
            let set = RuleSet::over(&script_rules).unwrap();
            let mut inplace_out = doc.clone();
            let stats = apply(&mut inplace_out, &set, DepthLimit::REFERENCE).unwrap();
            assert_eq!(u64::from(stats.replaced()), 6 + extra, "round {round}");
            edited_rounds += 6 + extra;

            let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
            let tops: Vec<_> = patch.top().collect();
            for handle in tops {
                match (patch.field(handle).as_inner(), patch.kind(handle)) {
                    (1, RecordKind::Varint) => patch.set_varint(handle, script.v1).unwrap(),
                    (2, RecordKind::I32) => patch.set_i32(handle, script.bits2).unwrap(),
                    (3, RecordKind::I64) => patch.set_i64(handle, script.bits3).unwrap(),
                    (4, RecordKind::Len) => {
                        patch.set_payload(handle, &script.payload4).unwrap();
                    }
                    (5, RecordKind::Varint) => patch.set_varint(handle, script.v5).unwrap(),
                    (6, RecordKind::Len) => {
                        use protobuf_edit::patch::groupless::Descent;
                        assert!(
                            matches!(patch.descend(handle).unwrap(), Descent::Opened { .. }),
                            "the generated nested message opens"
                        );
                        let kids: Vec<_> = patch.children(handle).collect();
                        for kid in kids {
                            patch.set_varint(kid, script.inner).unwrap();
                        }
                    }
                    (7, RecordKind::Varint) => patch.set_varint(handle, 42).unwrap(),
                    observed => panic!("unplanned record {observed:?}"),
                }
            }
            let patched = patch.save().unwrap();
            assert_eq!(inplace_out, patched, "round {round}");
        }
        assert!(edited_rounds >= 64 * 6, "the corpus fired its scripts");
    }

    #[test]
    fn width_exact_grouped_scripts_agree_with_patch_byte_for_byte() {
        use protobuf_edit::inplace::grouped::apply;
        use protobuf_edit::patch::grouped::Patch;
        use protobuf_edit::wire::grouped::RecordKind;

        const P8_9: &[Segment<'static>] = &[
            Segment::Field(FieldNumber::new(8).unwrap()),
            Segment::Field(FieldNumber::new(9).unwrap()),
        ];
        let mut rng = Rng(0x6B0B_5EED_D00D_FEED);
        for round in 0..64 {
            // The groupless corpus plus one group wrapping an
            // editable varint — the grouped-only shape.
            let inner = rng.next() >> (rng.next() % 60);
            let (doc, script, _extra) = {
                use protobuf_edit::construct::grouped::Builder;
                let v1 = rng.next() >> (rng.next() % 60);
                let mut b = Builder::new();
                b.push_varint(fx(1), v1);
                b.group(fx(8), |g| g.push_varint(fx(9), inner));
                b.push_varint(fx(5), rng.next() >> (rng.next() % 60));
                let doc = b.finish().expect("seeded documents sit far under the cap");
                (
                    doc,
                    Script {
                        v1: same_width(v1, &mut rng),
                        bits2: 0,
                        bits3: 0,
                        payload4: Vec::new(),
                        v5: 0,
                        inner: same_width(inner, &mut rng),
                    },
                    0,
                )
            };
            let group_rules = [
                Rule { path: &[Segment::Field(fx(1))], action: Action::SetVarint(script.v1) },
                Rule { path: P8_9, action: Action::SetVarint(script.inner) },
            ];
            let set = RuleSet::over(&group_rules).unwrap();
            let mut inplace_out = doc.clone();
            let stats = apply(&mut inplace_out, &set, DepthLimit::REFERENCE).unwrap();
            assert_eq!(stats.replaced(), 2, "round {round}");

            let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
            let tops: Vec<_> = patch.top().collect();
            for handle in tops {
                match (patch.field(handle).as_inner(), patch.kind(handle)) {
                    (1, RecordKind::Varint) => patch.set_varint(handle, script.v1).unwrap(),
                    (8, RecordKind::Group) => {
                        let kids: Vec<_> = patch.children(handle).collect();
                        for kid in kids {
                            patch.set_varint(kid, script.inner).unwrap();
                        }
                    }
                    (5, RecordKind::Varint) => {}
                    observed => panic!("unplanned record {observed:?}"),
                }
            }
            let patched = patch.save().unwrap();
            assert_eq!(inplace_out, patched, "round {round}");
        }
    }

    /// Re-ingests one document into its (field, observation)
    /// population — the semantic judge's common frame.
    fn population(bytes: &[u8]) -> Vec<(u32, String)> {
        use protobuf_edit::traverse::groupless::{Cursor, EntryKind};
        Cursor::over(bytes)
            .unwrap()
            .map(|entry| {
                let entry = entry.expect("both outputs re-ingest");
                let observation = match entry.kind() {
                    EntryKind::Varint(value) => format!("varint {value}"),
                    EntryKind::I64(bits) => format!("i64 {bits}"),
                    EntryKind::I32(bits) => format!("i32 {bits}"),
                    EntryKind::Len(payload) => format!("len {payload:02X?}"),
                };
                (entry.field().as_inner(), observation)
            })
            .collect()
    }

    #[test]
    fn padded_slots_agree_with_patch_on_re_ingested_values() {
        use protobuf_edit::inplace::groupless::apply;
        use protobuf_edit::patch::groupless::Patch;

        // f1's value is padded to three bytes, f2's tag to two —
        // tolerant wire. The script writes narrower values: the
        // in-place editor pads to the met slots, patch re-emits
        // minimally. Geometry differs; the populations must not.
        let doc = [
            0x08, 0x96, 0x81, 0x00, // f1 varint 150, padded value
            0x90, 0x00, 0x05, // f2 varint 5, padded tag
            0x1A, 0x02, 0x68, 0x69, // f3 LEN "hi"
        ];
        const P1: &[Segment<'static>] = &[Segment::Field(FieldNumber::new(1).unwrap())];
        const P2: &[Segment<'static>] = &[Segment::Field(FieldNumber::new(2).unwrap())];
        let script_rules = [
            Rule { path: P1, action: Action::SetVarint(3) },
            Rule { path: P2, action: Action::SetVarint(7) },
        ];
        let set = RuleSet::over(&script_rules).unwrap();
        let mut inplace_out = doc;
        apply(&mut inplace_out, &set, DepthLimit::REFERENCE).unwrap();
        // The pad-fill law, pinned in bytes: the three-byte slot
        // holds 3 continuation-padded.
        assert_eq!(inplace_out[..4], [0x08, 0x83, 0x80, 0x00]);

        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let tops: Vec<_> = patch.top().collect();
        patch.set_varint(tops[0], 3).unwrap();
        patch.set_varint(tops[1], 7).unwrap();
        let patched = patch.save().unwrap();

        assert_ne!(inplace_out.to_vec(), patched, "geometry lawfully differs");
        assert_eq!(population(&inplace_out), population(&patched), "values agree");
    }
}

/// The abstract-normalization differential: where a commitment
/// closure is expressible by static paths, the canonical save must
/// equal the fidelity save pushed through the required bottom-up
/// `Action::Normalize` jobs — one public-rewrite pass per closure
/// depth, deepest first, because a LEN-`Normalize` rides its
/// interior verbatim. The harness refuses closures no static
/// program can express: `Field` segments select every occurrence,
/// so a repeated field with one descended and one opaque occurrence
/// is classified unrepresentable rather than normalized broadly.
/// The abstract-normalization differential: where a commitment
/// closure is expressible by static paths, the canonical save must
/// equal the fidelity save pushed through the required bottom-up
/// `Action::Normalize` jobs — one public-rewrite pass per closure
/// depth, deepest first, because a LEN-`Normalize` rides its
/// interior verbatim. The harness refuses closures no static
/// program can express: `Field` segments select every occurrence,
/// so a repeated field with one descended and one opaque occurrence
/// is classified unrepresentable rather than normalized broadly.
#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
mod normalize_differential {
    use protobuf_edit::path::Segment;
    use protobuf_edit::rewrite::{Action, Rule, RuleSet};

    use super::*;

    #[track_caller]
    fn h(s: &str) -> Vec<u8> {
        let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        hex.chunks(2)
            .map(|p| {
                let hi = (p[0] as char).to_digit(16).unwrap();
                let lo = (p[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }

    const fn f(n: u32) -> FieldNumber {
        match FieldNumber::new(n) {
            Some(field) => field,
            None => panic!("test field in range"),
        }
    }

    /// One bottom-up normalization sequence over the groupless
    /// rewrite: each level is one pass whose rules normalize the
    /// records materialized at that depth, deepest level first.
    fn normalize_bottom_up(doc: &[u8], levels: &[&[&[Segment<'_>]]]) -> Vec<u8> {
        let mut bytes = doc.to_vec();
        for paths in levels {
            let rules: Vec<Rule<'_>> =
                paths.iter().map(|path| Rule { path, action: Action::Normalize }).collect();
            let set = RuleSet::over(&rules).unwrap();
            let (out, _stats) =
                protobuf_edit::rewrite::groupless::rewrite(&bytes, &set, DepthLimit::REFERENCE)
                    .unwrap();
            bytes = out;
        }
        bytes
    }

    #[test]
    fn scalar_padding_deletion_and_authored_payloads_agree() {
        use protobuf_edit::patch::groupless::{InsertAt, Patch};
        // padded tag · padded value · a record to delete · an
        // authored opaque payload of padded-looking bytes.
        let doc = h("8800 01 10 968100 180A");
        let payload = h("8800 8100");
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let t: Vec<_> = patch.top().collect();
        patch.delete(t[2]).unwrap();
        patch.insert_payload(InsertAt::TailOf(None), f(9), &payload).unwrap();

        let fidelity = patch.save().unwrap();
        let canonical = patch.save_canonical().unwrap();
        // The closure is the root layer alone: one pass.
        let level0: [&[Segment<'_>]; 3] =
            [&[Segment::Field(f(1))], &[Segment::Field(f(2))], &[Segment::Field(f(9))]];
        assert_eq!(
            canonical,
            normalize_bottom_up(&fidelity, &[&level0]),
            "canonical save vs fidelity-then-Normalize"
        );
        assert_eq!(canonical, h("0801 109601 4A04 8800 8100"));
    }

    #[test]
    fn same_length_padded_prefixes_need_their_own_pass() {
        use protobuf_edit::patch::groupless::Patch;
        // The LEN prefix is padded but the body length is unchanged
        // by every deeper pass — only the record's own Normalize
        // re-authors it.
        let doc = h("12 8200 6869");
        let patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let fidelity = patch.save().unwrap();
        assert_eq!(fidelity, doc, "no edits: fidelity is the source");
        let canonical = patch.save_canonical().unwrap();
        let level0: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
        assert_eq!(canonical, normalize_bottom_up(&fidelity, &[&level0]));
        assert_eq!(canonical, h("12 02 6869"));
    }

    #[test]
    fn cascading_prefixes_agree_bottom_up() {
        use protobuf_edit::patch::groupless::{Descent, Patch};
        // The corpus cascade: outer LEN { middle LEN { inner LEN
        // (padded prefix) over a blob } }, both containers
        // descended — three levels, deepest first.
        let doc = h("1A06 1A04 128100 61");
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let outer = patch.top().next().unwrap();
        let Descent::Opened { first: Some(middle) } = patch.descend(outer).unwrap() else {
            unreachable!()
        };
        let Descent::Opened { first: Some(_inner) } = patch.descend(middle).unwrap() else {
            unreachable!()
        };

        let fidelity = patch.save().unwrap();
        let canonical = patch.save_canonical().unwrap();
        let deepest: [&[Segment<'_>]; 1] =
            [&[Segment::Field(f(3)), Segment::Field(f(3)), Segment::Field(f(2))]];
        let middle_level: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3)), Segment::Field(f(3))]];
        let root: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3))]];
        assert_eq!(canonical, normalize_bottom_up(&fidelity, &[&deepest, &middle_level, &root]),);
        assert_eq!(canonical, h("1A05 1A03 1201 61"));
    }

    #[test]
    fn groups_compose_in_one_pass() {
        use protobuf_edit::patch::grouped::Patch;
        use protobuf_edit::rewrite::grouped::rewrite;
        // A group-`Normalize` keeps its interior with the walk, so
        // the group and its interior normalize in one pass — the
        // grouped asymmetry against the LEN arm. The interior LEN's
        // payload stays a blob nothing enters.
        let doc = h("8B00 128100 61 8C8000");
        let patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let fidelity = patch.save().unwrap();
        let canonical = patch.save_canonical().unwrap();

        let rules = [
            Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
            Rule { path: &[Segment::Field(f(1)), Segment::Field(f(2))], action: Action::Normalize },
        ];
        let set = RuleSet::over(&rules).unwrap();
        let (rewritten, _stats) = rewrite(&fidelity, &set, DepthLimit::REFERENCE).unwrap();
        assert_eq!(canonical, rewritten);
        assert_eq!(canonical, h("0B 120161 0C"));
    }

    /// The classifier the harness must carry: a static rule program
    /// speaks per field path — `Field` segments select every
    /// occurrence — so a field class whose LEN occurrences split
    /// between descended and opaque has no program.
    const fn representable(descended: usize, occurrences: usize) -> bool {
        descended == 0 || descended == occurrences
    }

    #[test]
    fn occurrence_specific_descent_is_classified_unrepresentable() {
        use protobuf_edit::patch::groupless::{Descent, Patch};
        // Two occurrences of the same repeated field; the editor
        // descends exactly one.
        let doc = h("12 04 8800 8100 12 04 8800 8100");
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let t: Vec<_> = patch.top().collect();
        let Descent::Opened { .. } = patch.descend(t[0]).unwrap() else { unreachable!() };

        // The harness classifies instead of normalizing broadly.
        let descended = 1;
        let occurrences = t.len();
        assert!(
            !representable(descended, occurrences),
            "a split field class must be classified unrepresentable"
        );

        // The broadened program is not the canonical save: it
        // rewrites the opaque twin's declared payload bytes.
        let canonical = patch.save_canonical().unwrap();
        assert_eq!(canonical, h("12 02 0801 12 04 8800 8100"));
        let fidelity = patch.save().unwrap();
        let interior: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2)), Segment::Field(f(1))]];
        let root: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
        let broadened = normalize_bottom_up(&fidelity, &[&interior, &root]);
        assert_eq!(broadened, h("12 02 0801 12 02 0801"), "the program broadens");
        assert_ne!(broadened, canonical, "broadening is not canonical output");

        // Descending the twin too makes the class whole again —
        // and the program exact.
        let Descent::Opened { .. } = patch.descend(t[1]).unwrap() else { unreachable!() };
        assert!(representable(2, occurrences));
        assert_eq!(patch.save_canonical().unwrap(), broadened);
    }
}

/// The construct lossless baseline: on canonical inputs, replaying a
/// document record by record through `push_record` equals both the
/// input and the typed re-spelling; on padded inputs the proof
/// refuses and the byte-exact road is the opaque LEN embedding — the
/// divergence the canonical root assertion exists to force.
#[cfg(all(
    feature = "construct-grouped",
    feature = "construct-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless"
))]
mod construct_push_record {
    use protobuf_edit::inspect::{Admitted, NoAdvice};
    use protobuf_edit::{DepthLimit, FieldNumber};

    #[track_caller]
    fn h(s: &str) -> Vec<u8> {
        let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        hex.chunks(2)
            .map(|p| {
                let hi = (p[0] as char).to_digit(16).unwrap();
                let lo = (p[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }

    #[track_caller]
    const fn f(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    #[test]
    fn push_record_replays_canonical_inputs_losslessly() {
        use protobuf_edit::construct::groupless::{Builder, CopyBuilder};
        use protobuf_edit::inspect::groupless::Tree;

        // Every kind once: varint, I32, I64, LEN.
        let doc = h("08 2A 15 AABBCCDD 19 AABBCCDD11223344 22 02 68 69");
        let input = Admitted::new(&doc).unwrap();
        let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);

        // The designation replay: borrowed, staged, and copy-only.
        let mut replay = Builder::new();
        let mut staged = Builder::new();
        let mut copying = CopyBuilder::new();
        for id in tree.top() {
            let proof = tree.record_ref(id).unwrap().try_canonical().unwrap();
            replay.push_record(proof);
            staged.push_record_copy(proof);
            copying.push_record(proof);
        }
        // The exact-count account: the plan prices the record bytes,
        // nothing re-encoded.
        assert_eq!(replay.planned_len().unwrap(), doc.len() as u64);
        assert_eq!(replay.finish().unwrap(), doc);
        assert_eq!(staged.finish().unwrap(), doc);
        assert_eq!(copying.finish().unwrap(), doc);

        // The typed re-spelling lands on the same bytes: the
        // designation road loses nothing against hand authorship.
        let mut typed = Builder::new();
        typed.push_varint(f(1), 42);
        typed.push_i32(f(2), 0xDDCC_BBAA);
        typed.push_i64(f(3), 0x4433_2211_DDCC_BBAA);
        typed.push_len(f(4), b"hi");
        assert_eq!(typed.finish().unwrap(), doc);
    }

    #[test]
    fn grouped_closures_replay_whole() {
        use protobuf_edit::construct::grouped::Builder;
        use protobuf_edit::inspect::grouped::Tree;

        let doc = h("0B 10 05 1B 10 01 1C 0C 20 09");
        let input = Admitted::new(&doc).unwrap();
        let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
        let mut replay = Builder::new();
        for id in tree.top() {
            replay.push_record(tree.record_ref(id).unwrap().try_canonical().unwrap());
        }
        assert_eq!(replay.finish().unwrap(), doc);
    }

    #[test]
    fn padded_designations_divide_the_roads() {
        use protobuf_edit::construct::groupless::Builder;
        use protobuf_edit::inspect::groupless::Tree;
        use protobuf_edit::source::groupless::Fault;

        // A padded varint record cannot assert a canonical root…
        let doc = h("08 96 81 00");
        let input = Admitted::new(&doc).unwrap();
        let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
        let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
        assert!(matches!(record.try_canonical(), Err(Fault::StandardMismatch { .. })));

        // …but embeds byte-exactly as an opaque LEN payload.
        let mut wrapped = Builder::new();
        wrapped.push_len(f(5), record.as_bytes());
        assert_eq!(wrapped.finish().unwrap(), h("2A 04 08 96 81 00"));
    }
}
