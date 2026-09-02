use alloc::vec::Vec;

use super::*;
use crate::path::Segment;
use crate::replay_rewrite::Rule;
use crate::replay_source::{Chunk, SliceFault, SliceSource, discard_skip};

/// A rewind-only source lending views of at most `step` bytes:
/// the chunk-partition lever (partitioning carries no meaning).
#[derive(Debug)]
struct Chunked<'a> {
    bytes: &'a [u8],
    step: usize,
}

#[derive(Debug)]
struct ChunkedWalk<'a> {
    rest: &'a [u8],
    step: usize,
}

impl StableReplaySource for Chunked<'_> {
    type Error = SliceFault;

    type Walk<'s>
        = ChunkedWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        Ok(ChunkedWalk { rest: self.bytes, step: self.step })
    }
}

impl ReplayWalk for ChunkedWalk<'_> {
    type Error = SliceFault;

    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<Self::Error>> {
        Ok(Chunk::new(&self.rest[..self.step.min(self.rest.len())]))
    }

    fn consume(&mut self, n: usize) {
        self.rest = &self.rest[n..];
    }

    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<Self::Error>> {
        discard_skip(self, n)
    }
}

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

fn job(bytes: &[u8], rules: &[Rule<'_>]) -> Result<(Vec<u8>, Stats), JobFault<SliceFault>> {
    let set = RuleSet::over(rules).unwrap();
    rewrite(&mut SliceSource::new(bytes), &set, DepthLimit::REFERENCE)
}

fn document_kind(fault: JobFault<SliceFault>) -> FaultKind {
    let JobFault::Document(fault) = fault else {
        panic!("a document fault was expected, got {fault:?}");
    };
    fault.kind()
}

// varint f1=150 · group f2 { varint f3=1 · LEN f4 "hi" } · I32 f5
const NESTED: [u8; 16] = [
    0x08, 0x96, 0x01, // varint f1 = 150
    0x13, // group f2 open
    0x18, 0x01, // varint f3 = 1
    0x22, 0x02, 0x68, 0x69, // LEN f4 "hi"
    0x14, // group f2 close
    0x2D, 0x01, 0x02, 0x03, 0x04, // I32 f5
];

#[test]
fn an_identity_job_reproduces_the_source_bytes() {
    let rules = [Rule { path: &[Segment::Field(f(9))], action: Action::Delete }];
    let (out, stats) = job(&NESTED, &rules).unwrap();
    assert_eq!(out, NESTED);
    assert_eq!(stats, Stats::default());
}

#[test]
fn a_deleted_group_vanishes_whole_and_counts_once() {
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Delete }];
    let (out, stats) = job(&NESTED, &rules).unwrap();
    assert_eq!(out, [0x08, 0x96, 0x01, 0x2D, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!((stats.deleted(), stats.replaced()), (1, 0));
}

#[test]
fn deletion_suppresses_interior_rules_and_verifies_pairing() {
    // A rule on f3 inside the deleted f2 group never fires: the
    // vanishing interior is walked for wire law alone.
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Delete },
        Rule {
            path: &[Segment::Field(f(2)), Segment::Field(f(3))],
            action: Action::Replace(Value::Varint(9)),
        },
    ];
    let (out, stats) = job(&NESTED, &rules).unwrap();
    assert_eq!(out, [0x08, 0x96, 0x01, 0x2D, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!((stats.deleted(), stats.replaced()), (1, 0));

    // A mismatched end tag inside the vanishing tree is still a
    // wire fault.
    let broken = [0x13, 0x1C]; // group f2 open · group f3 close
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Delete }];
    let fault = job(&broken, &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Grouping)));

    // Nested groups inside the deletion pair and vanish with it.
    let doc = [0x13, 0x1B, 0x08, 0x07, 0x1C, 0x14, 0x08, 0x2A];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x08, 0x2A]);
    assert_eq!(stats.deleted(), 1);
}

#[test]
fn a_normalized_group_reauthors_its_framing_around_a_live_interior() {
    // Padded group tags around an interior a second rule still
    // rewrites.
    let doc = [
        0x93, 0x80, 0x00, // group f2 open, padded
        0x18, 0x01, // varint f3 = 1
        0x94, 0x80, 0x00, // group f2 close, padded
    ];
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
        Rule {
            path: &[Segment::Field(f(2)), Segment::Field(f(3))],
            action: Action::Replace(Value::Varint(9)),
        },
    ];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x13, 0x18, 0x09, 0x14]);
    assert_eq!((stats.normalized(), stats.replaced()), (1, 1));
}

#[test]
fn replacing_a_group_is_a_kind_mismatch() {
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Replace(Value::Len(b"x")) }];
    let fault = job(&NESTED, &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::KindMismatch { rule: 0 }));
}

#[test]
fn group_framing_faults_summarize_as_grouping() {
    let rules = [Rule { path: &[Segment::Field(f(9))], action: Action::Delete }];

    // Orphaned end tag at the root.
    let fault = job(&[0x14], &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Grouping)));

    // Mismatched end tag inside an open group.
    let fault = job(&[0x13, 0x1C], &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Grouping)));

    // A group left open at the source's end.
    let fault = job(&[0x13, 0x08, 0x01], &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Grouping)));

    // An end tag inside a committed LEN cannot close a group
    // outside it.
    let route = [f(1)];
    let crossing = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(9))],
        action: Action::Delete,
    }];
    let fault = job(&[0x13, 0x0A, 0x01, 0x14], &crossing).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Grouping)));
}

#[test]
fn groups_and_len_crossings_spend_one_depth_account() {
    // group f1 { group f1 { … } } against a budget of one.
    let rules = [Rule { path: &[Segment::Field(f(9))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();
    let doc = [0x0B, 0x0B, 0x0C, 0x0C];
    let fault =
        rewrite(&mut SliceSource::new(&doc), &set, DepthLimit::new(1).unwrap()).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Depth)));

    // A vanishing tree still nests the reader.
    let doc = [0x0B, 0x0B, 0x0C, 0x0C];
    let deleting = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let set = RuleSet::over(&deleting).unwrap();
    let fault =
        rewrite(&mut SliceSource::new(&doc), &set, DepthLimit::new(1).unwrap()).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Depth)));
}

#[test]
fn rules_reach_through_len_and_group_alike() {
    // LEN f1 { group f2 { varint f3 } } — normalize f3 through
    // both crossings; the LEN prefix holds (same width).
    let doc = [0x0A, 0x04, 0x13, 0x18, 0x01, 0x14];
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2)), Segment::Field(f(3))],
        action: Action::Replace(Value::Varint(9)),
    }];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x0A, 0x04, 0x13, 0x18, 0x09, 0x14]);
    assert_eq!((stats.replaced(), stats.descended()), (1, 1));
}

#[test]
fn a_moved_interior_reauthors_the_crossed_len_prefix() {
    // LEN f1 { group f2 { LEN f4 "abc" } } — replace f4's payload
    // with "x": the group is transparent to length, the LEN
    // prefix re-authors.
    let doc = [0x0A, 0x07, 0x13, 0x22, 0x03, b'a', b'b', b'c', 0x14];
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2)), Segment::Field(f(4))],
        action: Action::Replace(Value::Len(b"x")),
    }];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x0A, 0x05, 0x13, 0x22, 0x01, b'x', 0x14]);
    assert_eq!((stats.replaced(), stats.descended()), (1, 1));
}

#[test]
fn the_canonical_face_refuses_padded_framing_outside_normalize() {
    let doc = [0x93, 0x80, 0x00, 0x14]; // padded open tag, minimal close
    let rules = [Rule { path: &[Segment::Field(f(9))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();
    let fault = rewrite_standard(
        &mut SliceSource::new(&doc),
        &set,
        DepthLimit::REFERENCE,
        Standard::CanonicalMinimal,
    )
    .unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::NonMinimal)));
}

#[test]
fn view_partitioning_carries_no_meaning() {
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(4))], action: Action::Delete },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let doc = [
        0x93, 0x80, 0x00, 0x18, 0x01, 0x94, 0x80, 0x00, // padded group f2 { varint f3 }
        0x22, 0x02, 0x68, 0x69, // LEN f4 "hi"
    ];
    let mut whole = SliceSource::new(&doc);
    let expected = rewrite(&mut whole, &set, DepthLimit::REFERENCE).unwrap();
    for step in 1..=doc.len() {
        let mut source = Chunked { bytes: &doc, step };
        let got = rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap();
        assert_eq!(got, expected, "view step {step} diverged");
    }
}

#[test]
fn the_faces_share_the_publication_contract() {
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();

    let mut out = alloc::vec![0xEE];
    let stats = rewrite_into(&mut SliceSource::new(&NESTED), &set, DepthLimit::REFERENCE, &mut out)
        .unwrap();
    assert_eq!(out[0], 0xEE);
    assert_eq!(&out[1..], [0x08, 0x96, 0x01, 0x2D, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(stats.deleted(), 1);

    let mut got = Vec::new();
    let stats = rewrite_sink(&mut SliceSource::new(&NESTED), &set, DepthLimit::REFERENCE, |view| {
        got.extend_from_slice(view);
    })
    .unwrap();
    assert_eq!(got, [0x08, 0x96, 0x01, 0x2D, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(stats.deleted(), 1);
}
