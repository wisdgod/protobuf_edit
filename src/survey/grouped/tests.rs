use alloc::vec::Vec;

use super::*;
use crate::DepthLimit;
use crate::replay_source::{Chunk, SliceSource, discard_skip};
use crate::survey::NoAdvice;

/// A rewind-only source lending views of at most `step` bytes.
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
    type Error = crate::replay_source::SliceFault;

    type Walk<'s>
        = ChunkedWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        Ok(ChunkedWalk { rest: self.bytes, step: self.step })
    }
}

impl ReplayWalk for ChunkedWalk<'_> {
    type Error = crate::replay_source::SliceFault;

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

fn open(bytes: &[u8]) -> Survey<SliceSource<'_>> {
    Survey::open(SliceSource::new(bytes), DepthLimit::REFERENCE, &mut NoAdvice).unwrap()
}

// group f1 { varint f2=7 · LEN f3 [0xFF, 0x01] } · varint f4=1
// (the LEN payload spells an unassigned code, so the speculation
// concludes bytes and the LEN stays a leaf)
const GROUPED: [u8; 10] = [0x0B, 0x10, 0x07, 0x1A, 0x02, 0xFF, 0x01, 0x0C, 0x20, 0x01];

#[test]
fn groups_walk_structurally_and_measure_their_interiors() {
    let msg = &GROUPED[..];
    let tree = open(msg);
    assert!(tree.is_complete());
    let tops: Vec<_> = tree.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(tree.kind(tops[0]), RecordKind::Group);

    // The group's interior is measured, its end tag recorded.
    let span = tree.span(tops[0]);
    assert_eq!((span.start(), span.end()), (0, 8));
    let RecordSpans::Group { tag, interior, end_tag } = tree.source_spans(tops[0]) else {
        panic!("a closed group answers the group geometry");
    };
    assert_eq!((tag.start(), tag.end()), (0, 1));
    assert_eq!((interior.start(), interior.end()), (1, 7));
    assert_eq!((end_tag.start(), end_tag.end()), (7, 8));

    let kids: Vec<_> = tree.children(tops[0]).collect();
    assert_eq!(kids.len(), 2);
    assert_eq!(tree.varint_word(kids[0]), Some(7));
    assert_eq!(tree.kind(kids[1]), RecordKind::Len);

    // The parent chain climbs out of the group.
    assert_eq!(tree.parent(kids[1]), Some(tops[0]));
    assert_eq!(tree.narrowest(5), Some(kids[1]));
}

#[test]
fn group_framing_faults_are_judged_where_they_break() {
    // An orphan end tag.
    let orphan = [0x0C];
    let tree = open(&orphan);
    assert!(
        matches!(tree.fault().unwrap().kind(), FaultKind::GroupEndOrphan { found } if found.as_inner() == 1)
    );

    // A mismatched end tag.
    let mismatch = [0x0B, 0x14]; // open f1, end f2
    let tree = open(&mismatch);
    assert!(matches!(
        tree.fault().unwrap().kind(),
        FaultKind::GroupEndMismatch { open, found }
            if open.as_inner() == 1 && found.as_inner() == 2
    ));

    // A group the source end leaves open: clipped, no end tag.
    let unclosed = [0x0B, 0x10, 0x07];
    let tree = open(&unclosed);
    assert!(matches!(
        tree.fault().unwrap().kind(),
        FaultKind::GroupUnclosed { open } if open.as_inner() == 1
    ));
    let top = tree.top().next().unwrap();
    assert!(matches!(tree.source_spans(top), RecordSpans::ClippedGroup { .. }));

    // A group may not cross its enclosing LEN's boundary — under
    // a committed descent the unclose is a real fault (a
    // speculating ancestor would absorb it instead).
    struct CommitAll;
    impl Advisor for CommitAll {
        fn advise(&mut self, _ancestry: Ancestry<'_>, _field: FieldNumber) -> Advice {
            Advice::Commit
        }
    }
    let crossing = [0x0A, 0x01, 0x0B];
    let tree =
        Survey::open(SliceSource::new(&crossing), DepthLimit::REFERENCE, &mut CommitAll).unwrap();
    assert!(matches!(
        tree.fault().unwrap().kind(),
        FaultKind::GroupUnclosed { open } if open.as_inner() == 1
    ));
}

#[test]
fn speculation_absorbs_group_faults_inside_len_payloads() {
    // LEN f1 whose payload holds an orphan end tag: the
    // speculation concludes "bytes", the walk continues.
    let msg = [0x0A, 0x01, 0x0C, 0x20, 0x01];
    let tree = open(&msg);
    assert!(tree.is_complete());
    let tops: Vec<_> = tree.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(tree.children(tops[0]).count(), 0);
    assert_eq!(tree.varint_word(tops[1]), Some(1));
}

#[test]
fn chunk_partitioning_carries_no_meaning() {
    let msg = &GROUPED[..10];
    let whole = open(msg);
    for step in [1usize, 2, 5] {
        let tree = Survey::open(Chunked { bytes: msg, step }, DepthLimit::REFERENCE, &mut NoAdvice)
            .unwrap();
        assert!(tree.is_complete(), "step {step}");
        assert_eq!(tree.node_count(), whole.node_count(), "step {step}");
        for (a, b) in tree.nodes().zip(whole.nodes()) {
            assert_eq!(tree.span(a), whole.span(b), "step {step}");
            assert_eq!(tree.kind(a), whole.kind(b), "step {step}");
        }
    }
}

#[test]
fn a_group_interior_fetches_like_a_payload() {
    let msg = &GROUPED[..10];
    let mut tree = open(msg);
    let group = tree.top().next().unwrap();
    let mut out = Vec::new();
    tree.read_payload(group, &mut out).unwrap();
    assert_eq!(out, GROUPED[1..7]);

    // The nested LEN's payload rides inside the same batch walk.
    let len = tree.children(group).nth(1).unwrap();
    let mut per_id: Vec<(NodeId, Vec<u8>)> = alloc::vec![(group, Vec::new()), (len, Vec::new())];
    tree.fetch_payloads(&[group, len], |id, bytes| {
        for (key, buf) in &mut per_id {
            if *key == id {
                buf.extend_from_slice(bytes);
            }
        }
    })
    .unwrap();
    assert_eq!(per_id[0].1, GROUPED[1..7]);
    assert_eq!(per_id[1].1, [0xFF, 0x01]);
}

#[test]
fn depth_bounds_groups_as_policy() {
    // Two nested groups under a bound of one.
    let deep = [0x0B, 0x0B, 0x0C, 0x0C];
    let tree =
        Survey::open(SliceSource::new(&deep), DepthLimit::new(1).unwrap(), &mut NoAdvice).unwrap();
    let fault = tree.fault().unwrap();
    assert!(matches!(fault.kind(), FaultKind::DepthExceeded { .. }));
    assert_eq!(fault.kind().class(), crate::FaultClass::Policy);
}
