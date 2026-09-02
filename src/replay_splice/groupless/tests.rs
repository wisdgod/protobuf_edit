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

/// A source whose second and later walks yield a different byte
/// sequence — the contract-breaking fixture the torn-detection
/// rows drive.
#[derive(Debug)]
struct Shifting<'a> {
    full: &'a [u8],
    later: &'a [u8],
    begun: usize,
}

impl StableReplaySource for Shifting<'_> {
    type Error = crate::replay_source::SliceFault;

    type Walk<'s>
        = ChunkedWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        let bytes = if self.begun == 0 { self.full } else { self.later };
        self.begun += 1;
        Ok(ChunkedWalk { rest: bytes, step: usize::MAX })
    }
}

/// The identity rule: every default.
struct Silence;
impl Rule for Silence {}

fn job<R: Rule>(bytes: &[u8], rule: &mut R) -> Result<Vec<u8>, JobFault<SliceFault>> {
    splice(&mut SliceSource::new(bytes), rule, Standard::Tolerant, DepthLimit::REFERENCE)
}

fn document_kind(fault: JobFault<SliceFault>) -> FaultKind {
    let JobFault::Document(fault) = fault else {
        panic!("a document fault was expected, got {fault:?}");
    };
    fault.kind()
}

// varint f1=150 · varint f2=42
const FLAT: [u8; 5] = [0x08, 0x96, 0x01, 0x10, 0x2A];

// LEN f3 { varint f1=1 } · varint f1=42
const NEST: [u8; 6] = [0x1A, 0x02, 0x08, 0x01, 0x08, 0x2A];

#[test]
fn an_identity_job_reproduces_the_source_bytes() {
    assert_eq!(job(&FLAT, &mut Silence).unwrap(), FLAT);
    assert_eq!(job(&NEST, &mut Silence).unwrap(), NEST);
    assert!(job(&[], &mut Silence).unwrap().is_empty());
}

#[test]
fn a_varint_ask_hands_the_value_and_a_rewrite_reauthors_it() {
    struct Wide(Vec<(u64, u32, u64)>);
    impl Rule for Wide {
        fn on_varint(&mut self, at: u64, field: FieldNumber, value: u64) -> Scalar<'_, u64> {
            self.0.push((at, field.as_inner(), value));
            if field.as_inner() == 2 { Scalar::Rewrite(300) } else { Scalar::Keep }
        }
    }
    let mut rule = Wide(Vec::new());
    let out = job(&FLAT, &mut rule).unwrap();
    // Tag verbatim, the new value at minimal width — wider here.
    assert_eq!(out, [0x08, 0x96, 0x01, 0x10, 0xAC, 0x02]);
    assert_eq!(rule.0, [(0, 1, 150), (3, 2, 42)]);
}

#[test]
fn a_scalar_drop_vanishes_and_an_insert_lands_before_the_record() {
    struct Swap;
    impl Rule for Swap {
        fn on_varint(&mut self, _at: u64, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            match field.as_inner() {
                1 => Scalar::Drop,
                // varint f7=7, declared bytes riding verbatim.
                2 => Scalar::Insert(&[0x38, 0x07]),
                _ => Scalar::Keep,
            }
        }
    }
    let out = job(&FLAT, &mut Swap).unwrap();
    assert_eq!(out, [0x38, 0x07, 0x10, 0x2A]);
}

#[test]
fn fixed_asks_hand_little_endian_bits_and_rewrite_by_kind() {
    // I32 f3=0x04030201 · I64 f4=0x0807060504030201
    let doc = [
        0x1D, 0x01, 0x02, 0x03, 0x04, //
        0x21, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    struct Bits(Vec<u64>);
    impl Rule for Bits {
        fn on_i32(&mut self, _at: u64, _field: FieldNumber, bits: u32) -> Scalar<'_, u32> {
            self.0.push(u64::from(bits));
            Scalar::Rewrite(0xAABB_CCDD)
        }
        fn on_i64(&mut self, _at: u64, _field: FieldNumber, bits: u64) -> Scalar<'_, u64> {
            self.0.push(bits);
            Scalar::Drop
        }
    }
    let mut rule = Bits(Vec::new());
    let out = job(&doc, &mut rule).unwrap();
    assert_eq!(out, [0x1D, 0xDD, 0xCC, 0xBB, 0xAA]);
    assert_eq!(rule.0, [0x0403_0201, 0x0807_0605_0403_0201]);
}

#[test]
fn an_opaque_head_takes_its_close_verdict_and_replace_reauthors_the_prefix() {
    struct Shrink;
    impl Rule for Shrink {
        fn on_len(&mut self, _at: u64, field: FieldNumber, len: PayloadLen) -> Head<'_> {
            assert_eq!((field.as_inner(), len.as_inner()), (3, 2));
            Head::Opaque
        }
        fn on_close(&mut self, at: u64, field: FieldNumber) -> Close<'_> {
            assert_eq!((at, field.as_inner()), (0, 3));
            Close::Replace(&[0xFF])
        }
    }
    let out = job(&NEST, &mut Shrink).unwrap();
    assert_eq!(out, [0x1A, 0x01, 0xFF, 0x08, 0x2A]);
}

#[test]
fn a_close_drop_vanishes_and_a_close_insert_lands_before_the_record() {
    struct Drops;
    impl Rule for Drops {
        fn on_close(&mut self, _at: u64, _field: FieldNumber) -> Close<'_> {
            Close::Drop
        }
    }
    assert_eq!(job(&NEST, &mut Drops).unwrap(), [0x08, 0x2A]);

    struct Inserts;
    impl Rule for Inserts {
        fn on_close(&mut self, _at: u64, _field: FieldNumber) -> Close<'_> {
            Close::Insert(&[0x38, 0x07])
        }
    }
    assert_eq!(job(&NEST, &mut Inserts).unwrap(), [0x38, 0x07, 0x1A, 0x02, 0x08, 0x01, 0x08, 0x2A]);
}

#[test]
fn observe_hands_every_payload_byte_with_absolute_offsets() {
    // LEN f2 "hello"
    let doc = [0x12, 0x05, b'h', b'e', b'l', b'l', b'o'];
    struct Collect {
        seen: Vec<(u64, Vec<u8>)>,
    }
    impl Rule for Collect {
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            Head::Observe
        }
        fn on_fragment(&mut self, at: u64, view: &[u8]) {
            self.seen.push((at, view.to_vec()));
        }
    }
    let mut rule = Collect { seen: Vec::new() };
    // A two-byte view partition: fragments split accordingly.
    let out = splice(
        &mut Chunked { bytes: &doc, step: 2 },
        &mut rule,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(out, doc);
    let mut flat = Vec::new();
    let mut expected_at = 2;
    for (at, view) in &rule.seen {
        assert_eq!(*at, expected_at, "fragment offsets are absolute and contiguous");
        expected_at += view.len() as u64;
        flat.extend_from_slice(view);
    }
    assert_eq!(flat, b"hello");
}

#[test]
fn a_commit_asks_inside_and_settles_the_length_cascade() {
    // LEN f5 { LEN f3 { varint f1=1 } }
    let doc = [0x2A, 0x04, 0x1A, 0x02, 0x08, 0x01];
    struct Deep;
    impl Rule for Deep {
        fn on_varint(&mut self, at: u64, field: FieldNumber, value: u64) -> Scalar<'_, u64> {
            assert_eq!((at, field.as_inner(), value), (4, 1, 1));
            Scalar::Rewrite(300)
        }
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            Head::Commit { tail: None }
        }
        fn on_close(&mut self, _at: u64, _field: FieldNumber) -> Close<'_> {
            unreachable!("committed records settle mechanically, no close ask")
        }
    }
    let out = job(&doc, &mut Deep).unwrap();
    // The value grew a byte; both prefixes re-author.
    assert_eq!(out, [0x2A, 0x05, 0x1A, 0x03, 0x08, 0xAC, 0x02]);
}

#[test]
fn a_commit_tail_lands_inside_at_the_close_and_counts_in_the_prefix() {
    struct Tailed;
    impl Rule for Tailed {
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            // varint f2=7 appended inside the container.
            Head::Commit { tail: Some(&[0x10, 0x07]) }
        }
    }
    let out = job(&NEST, &mut Tailed).unwrap();
    assert_eq!(out, [0x1A, 0x04, 0x08, 0x01, 0x10, 0x07, 0x08, 0x2A]);
}

#[test]
fn only_a_commit_spends_the_depth_budget() {
    // LEN f3 { LEN f3 { varint f1=1 } }
    let doc = [0x1A, 0x04, 0x1A, 0x02, 0x08, 0x01];
    struct Commits;
    impl Rule for Commits {
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            Head::Commit { tail: None }
        }
    }
    let fault = splice(
        &mut SliceSource::new(&doc),
        &mut Commits,
        Standard::Tolerant,
        DepthLimit::new(1).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Depth)));

    // An opaque head at the same wall is lawful.
    struct OneDeep(u32);
    impl Rule for OneDeep {
        fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> Head<'_> {
            self.0 += 1;
            if self.0 == 1 { Head::Commit { tail: None } } else { Head::Opaque }
        }
    }
    let out = splice(
        &mut SliceSource::new(&doc),
        &mut OneDeep(0),
        Standard::Tolerant,
        DepthLimit::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(out, doc);
}

#[test]
fn wire_faults_carry_their_coordinates() {
    // Field zero.
    let fault = job(&[0x00, 0x01], &mut Silence).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Tag)));

    // A group code is this dialect's capability refusal.
    let fault = job(&[0x0B, 0x0C], &mut Silence).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::GroupCode)));

    // A LEN declaring past the source end: refused at the
    // interior's start once the probe finds the source short.
    let fault = job(&[0x1A, 0x05, 0x08], &mut Silence).unwrap_err();
    let JobFault::Document(fault) = fault else { panic!("document fault expected") };
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Truncated)));
}

#[test]
fn the_canonical_face_judges_widths_the_tolerant_face_accepts() {
    // varint f1 with a padded (two-byte) value word for 1.
    let doc = [0x08, 0x81, 0x00];
    assert_eq!(job(&doc, &mut Silence).unwrap(), doc);
    let fault = splice(
        &mut SliceSource::new(&doc),
        &mut Silence,
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
    )
    .unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::NonMinimal)));
}

#[test]
fn a_torn_source_is_refused_between_walks() {
    // The emission walk sees one byte fewer than measured.
    let mut source = Shifting { full: &FLAT, later: &FLAT[..4], begun: 0 };
    let fault =
        splice(&mut source, &mut Silence, Standard::Tolerant, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(fault, JobFault::Torn { .. }));
}

#[test]
fn splice_into_truncates_to_its_mark_on_refusal() {
    let mut out = alloc::vec![0xEE];
    let mut source = Shifting { full: &FLAT, later: &FLAT[..4], begun: 0 };
    let fault =
        splice_into(&mut source, &mut Silence, Standard::Tolerant, DepthLimit::REFERENCE, &mut out)
            .unwrap_err();
    assert!(matches!(fault, JobFault::Torn { .. }));
    assert_eq!(out, [0xEE], "the buffer is back at its entry mark");

    splice_into(
        &mut SliceSource::new(&FLAT),
        &mut Silence,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &mut out,
    )
    .unwrap();
    assert_eq!(out[0], 0xEE);
    assert_eq!(&out[1..], FLAT);
}

#[test]
fn the_sink_face_names_the_handed_prefix() {
    // A pass-one fault precedes every handoff.
    let mut handed = Vec::new();
    let fault = splice_sink(
        &mut SliceSource::new(&[0x00]),
        &mut Silence,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        |view| handed.extend_from_slice(view),
    )
    .unwrap_err();
    assert_eq!(fault.handed, 0);
    assert!(handed.is_empty());

    // A pass-two tear names the exact prefix the sink received.
    let mut source = Shifting { full: &FLAT, later: &FLAT[..4], begun: 0 };
    let mut handed = Vec::new();
    let fault =
        splice_sink(&mut source, &mut Silence, Standard::Tolerant, DepthLimit::REFERENCE, |view| {
            handed.extend_from_slice(view)
        })
        .unwrap_err();
    assert_eq!(fault.handed, handed.len() as u64);
}

#[test]
fn asks_walk_the_source_exactly_once() {
    struct Counter(u32);
    impl Rule for Counter {
        fn on_varint(&mut self, _at: u64, _field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
            self.0 += 1;
            Scalar::Keep
        }
    }
    let mut rule = Counter(0);
    job(&FLAT, &mut rule).unwrap();
    assert_eq!(rule.0, 2, "one ask per record; the emission walk asks nothing");
}
