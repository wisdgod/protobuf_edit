use alloc::vec::Vec;

use super::*;
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

/// The identity rule: every default.
struct Silence;
impl Rule for Silence {}

fn job<R: Rule>(bytes: &[u8], rule: &mut R) -> Result<Vec<u8>, JobFault<SliceFault>> {
    splice(&mut SliceSource::new(bytes), rule, Standard::Tolerant, DepthLimit::REFERENCE)
}

fn document(fault: JobFault<SliceFault>) -> Fault {
    let JobFault::Document(fault) = fault else {
        panic!("a document fault was expected, got {fault:?}");
    };
    fault
}

// varint f1=1 · group f2 { varint f3=5 · LEN f4 "ab" } · varint f1=42
const GROUPED: [u8; 12] = [0x08, 0x01, 0x13, 0x18, 0x05, 0x22, 0x02, b'a', b'b', 0x14, 0x08, 0x2A];

// group f2 { group f2 { varint f3=1 } }
const NESTED: [u8; 8] = [0x13, 0x13, 0x18, 0x01, 0x14, 0x14, 0x08, 0x2A];

#[test]
fn an_identity_job_reproduces_the_source_bytes() {
    assert_eq!(job(&GROUPED, &mut Silence).unwrap(), GROUPED);
    assert_eq!(job(&NESTED[..6], &mut Silence).unwrap(), &NESTED[..6]);
}

#[test]
fn a_passed_group_rides_whole_with_its_asks_silenced() {
    struct Spy(u32);
    impl Rule for Spy {
        fn on_varint(&mut self, at: u64, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            assert_eq!(field.as_inner(), 1, "interior asks are silenced at {at}");
            self.0 += 1;
            Scalar::Keep
        }
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            unreachable!("the LEN inside the passed group must not ask")
        }
    }
    let mut rule = Spy(0);
    assert_eq!(job(&GROUPED, &mut rule).unwrap(), GROUPED);
    assert_eq!(rule.0, 2, "only the two top-level varints ask");
}

#[test]
fn a_dropped_group_vanishes_whole_and_nested_framing_still_pairs() {
    struct DropG2;
    impl Rule for DropG2 {
        fn on_group_enter(&mut self, _at: u64, field: FieldNumber) -> Group<'_> {
            if field.as_inner() == 2 { Group::Drop } else { Group::Pass }
        }
    }
    assert_eq!(job(&GROUPED, &mut DropG2).unwrap(), [0x08, 0x01, 0x08, 0x2A]);
    assert_eq!(job(&NESTED, &mut DropG2).unwrap(), [0x08, 0x2A]);

    // The silenced walk still judges pairing: a mismatched end
    // tag inside the dropped extent refuses.
    // group f2 { end f5 }
    let bad = [0x13, 0x2C];
    let fault = document(job(&bad, &mut DropG2).unwrap_err());
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));
}

#[test]
fn a_committed_group_asks_inside_and_keeps_its_framing_verbatim() {
    struct Enter;
    impl Rule for Enter {
        fn on_group_enter(&mut self, _at: u64, _field: FieldNumber) -> Group<'_> {
            Group::Commit
        }
        fn on_varint(&mut self, _at: u64, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            if field.as_inner() == 3 { Scalar::Rewrite(300) } else { Scalar::Keep }
        }
    }
    let out = job(&GROUPED, &mut Enter).unwrap();
    assert_eq!(out, [0x08, 0x01, 0x13, 0x18, 0xAC, 0x02, 0x22, 0x02, b'a', b'b', 0x14, 0x08, 0x2A]);
}

#[test]
fn a_group_insert_lands_before_the_group_which_rides_verbatim() {
    struct Front;
    impl Rule for Front {
        fn on_group_enter(&mut self, _at: u64, _field: FieldNumber) -> Group<'_> {
            Group::Insert(&[0x30, 0x09])
        }
        fn on_varint(&mut self, _at: u64, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            assert_eq!(field.as_inner(), 1, "the inserted-before group stays silenced");
            Scalar::Keep
        }
    }
    let out = job(&GROUPED, &mut Front).unwrap();
    assert_eq!(
        out,
        [0x08, 0x01, 0x30, 0x09, 0x13, 0x18, 0x05, 0x22, 0x02, b'a', b'b', 0x14, 0x08, 0x2A]
    );
}

#[test]
fn grouping_faults_carry_their_coordinates() {
    // An orphaned end tag at the top level.
    let fault = document(job(&[0x14], &mut Silence).unwrap_err());
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));

    // A mismatched end tag inside an open group.
    let fault = document(job(&[0x13, 0x2C], &mut Silence).unwrap_err());
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));

    // An unclosed group cut by the source end.
    let fault = document(job(&[0x13, 0x18, 0x01], &mut Silence).unwrap_err());
    assert_eq!(fault.at(), 3);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));

    // A group end tag inside a committed LEN.
    struct Commits;
    impl Rule for Commits {
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            Head::Commit { tail: None }
        }
    }
    // LEN f4 { end f2 }
    let fault = document(job(&[0x22, 0x01, 0x14], &mut Commits).unwrap_err());
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));
}

#[test]
fn groups_and_commits_share_one_depth_account() {
    // Any group entry nests the reader — a pass at the wall still
    // walks the framing, so it charges all the same.
    let fault = splice(
        &mut SliceSource::new(&NESTED),
        &mut Silence,
        Standard::Tolerant,
        DepthLimit::new(1).unwrap(),
    )
    .unwrap_err();
    let fault = document(fault);
    assert_eq!(fault.at(), 1, "the inner group's head");
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));

    // A committed LEN inside a committed group spends the same
    // account.
    struct AllIn;
    impl Rule for AllIn {
        fn on_group_enter(&mut self, _at: u64, _field: FieldNumber) -> Group<'_> {
            Group::Commit
        }
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            Head::Commit { tail: None }
        }
    }
    // group f2 { LEN f4 { varint f3=1 } }
    let doc = [0x13, 0x22, 0x02, 0x18, 0x01, 0x14];
    let fault = splice(
        &mut SliceSource::new(&doc),
        &mut AllIn,
        Standard::Tolerant,
        DepthLimit::new(1).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(document(fault).kind(), FaultKind::Wire(WireBreach::Depth)));
    let out = splice(
        &mut SliceSource::new(&doc),
        &mut AllIn,
        Standard::Tolerant,
        DepthLimit::new(2).unwrap(),
    )
    .unwrap();
    assert_eq!(out, doc);
}

#[test]
fn a_commit_inside_a_group_settles_its_cascade() {
    struct Grow;
    impl Rule for Grow {
        fn on_group_enter(&mut self, _at: u64, _field: FieldNumber) -> Group<'_> {
            Group::Commit
        }
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            Head::Commit { tail: Some(&[0x18, 0x07]) }
        }
    }
    // group f2 { LEN f4 { varint f3=1 } }
    let doc = [0x13, 0x22, 0x02, 0x18, 0x01, 0x14];
    let out = job(&doc, &mut Grow).unwrap();
    // The tail (varint f3=7) lands inside the LEN, whose prefix
    // re-authors; the group framing rides verbatim.
    assert_eq!(out, [0x13, 0x22, 0x04, 0x18, 0x01, 0x18, 0x07, 0x14]);
}

#[test]
fn fragments_flow_inside_committed_groups() {
    struct Peek(Vec<u8>);
    impl Rule for Peek {
        fn on_group_enter(&mut self, _at: u64, _field: FieldNumber) -> Group<'_> {
            Group::Commit
        }
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            Head::Observe
        }
        fn on_fragment(&mut self, _at: u64, view: &[u8]) {
            self.0.extend_from_slice(view);
        }
        fn on_close(&mut self, _at: u64, _field: FieldNumber) -> Close<'_> {
            Close::Replace(&[0xFF, 0xEE])
        }
    }
    let mut rule = Peek(Vec::new());
    let out = splice(
        &mut Chunked { bytes: &GROUPED, step: 3 },
        &mut rule,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(rule.0, b"ab");
    assert_eq!(out, [0x08, 0x01, 0x13, 0x18, 0x05, 0x22, 0x02, 0xFF, 0xEE, 0x14, 0x08, 0x2A]);
}

#[test]
fn the_trail_names_committed_lens_alone() {
    struct AllIn;
    impl Rule for AllIn {
        fn on_group_enter(&mut self, _at: u64, _field: FieldNumber) -> Group<'_> {
            Group::Commit
        }
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            Head::Commit { tail: None }
        }
    }
    // group f2 { LEN f4 { field-zero tag } }
    let doc = [0x13, 0x22, 0x02, 0x00, 0x01, 0x14];
    let fault = document(job(&doc, &mut AllIn).unwrap_err());
    assert_eq!(fault.at(), 3);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Tag)));
    let trail: Vec<_> = fault.trail().iter().map(|c| (c.field().as_inner(), c.at())).collect();
    assert_eq!(trail, [(4, 1)], "the group is not a trail element");
}
