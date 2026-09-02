use alloc::vec::Vec;

use super::*;
use crate::DepthLimit;
use crate::replay_source::{Chunk, SliceSource, discard_skip};
use crate::survey::NoAdvice;

/// A rewind-only source lending views of at most `step` bytes:
/// the chunk-partition lever (partitioning carries no meaning)
/// and the visible-linear-skip exerciser.
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
/// rows drive (the machine's judgment is under test, not the
/// source's conformance).
#[derive(Debug)]
struct Shrinking<'a> {
    full: &'a [u8],
    later: &'a [u8],
    begun: usize,
}

impl StableReplaySource for Shrinking<'_> {
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

fn open(bytes: &[u8]) -> Survey<SliceSource<'_>> {
    Survey::open(SliceSource::new(bytes), DepthLimit::REFERENCE, &mut NoAdvice).unwrap()
}

// varint f1=150 · LEN f2 "hi" · I32 f3 · I64 f4
const MIXED: [u8; 21] = [
    0x08, 0x96, 0x01, // varint f1 = 150
    0x12, 0x02, 0x68, 0x69, // LEN f2 "hi"
    0x1D, 0x01, 0x00, 0x00, 0x80, // I32 f3
    0x21, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // I64 f4
];

#[test]
fn the_index_banks_topology_geometry_and_words() {
    let tree = open(&MIXED);
    assert!(tree.is_complete());
    assert_eq!(tree.indexed_end(), MIXED.len() as u64);
    let tops: Vec<_> = tree.top().collect();
    assert_eq!(tops.len(), 4);

    assert_eq!(tree.varint_word(tops[0]), Some(150));
    assert_eq!(tree.kind(tops[1]), RecordKind::Len);
    assert_eq!(tree.varint_word(tops[1]), None);
    assert_eq!(tree.i32_bits(tops[2]), Some(0x8000_0001));
    assert_eq!(tree.i64_bits(tops[3]), Some(0x0102_0304_0506_0708));

    let span = tree.span(tops[1]);
    assert_eq!((span.start(), span.end()), (3, 7));
    let RecordSpans::Len { tag, prefix, payload } = tree.source_spans(tops[1]) else {
        panic!("a LEN row answers the LEN geometry");
    };
    assert_eq!((tag.start(), tag.end()), (3, 4));
    assert_eq!((prefix.start(), prefix.end()), (4, 5));
    assert_eq!((payload.start(), payload.end()), (5, 7));

    // "hi" happens to parse as one varint record, so the
    // speculation committed it — the narrowest cover of a payload
    // byte is that child.
    let child = tree.children(tops[1]).next().unwrap();
    assert_eq!(tree.narrowest(5), Some(child));
    assert_eq!(tree.parent(child), Some(tops[1]));
    assert_eq!(tree.narrowest(0), Some(tops[0]));
    assert_eq!(tree.narrowest(MIXED.len() as u64), None);
}

#[test]
fn speculation_builds_the_tree_and_unwinding_demotes_to_bytes() {
    // LEN f1 wrapping { varint f2=7 }: speculation parses it.
    let nested = [0x0A, 0x02, 0x10, 0x07];
    let tree = open(&nested);
    let top: Vec<_> = tree.top().collect();
    assert_eq!(top.len(), 1);
    let kids: Vec<_> = tree.children(top[0]).collect();
    assert_eq!(kids.len(), 1);
    assert_eq!(tree.varint_word(kids[0]), Some(7));

    // LEN f1 whose payload cuts a record short: the speculation
    // concludes "bytes" — one leaf, no fault, and the walk goes
    // on to the sibling.
    let broken = [0x0A, 0x02, 0x10, 0xFF, 0x08, 0x01];
    let tree = open(&broken);
    assert!(tree.is_complete());
    let top: Vec<_> = tree.top().collect();
    assert_eq!(top.len(), 2);
    assert_eq!(tree.children(top[0]).count(), 0);
    assert_eq!(tree.varint_word(top[1]), Some(1));
}

#[test]
fn chunk_partitioning_carries_no_meaning() {
    // The same bytes under radically different view partitions:
    // identical rows, identical verdicts.
    let whole = open(&MIXED);
    for step in [1usize, 2, 3, 7] {
        let tree =
            Survey::open(Chunked { bytes: &MIXED, step }, DepthLimit::REFERENCE, &mut NoAdvice)
                .unwrap();
        assert!(tree.is_complete(), "step {step}");
        assert_eq!(tree.indexed_end(), whole.indexed_end(), "step {step}");
        assert_eq!(tree.node_count(), whole.node_count(), "step {step}");
        for (a, b) in tree.nodes().zip(whole.nodes()) {
            assert_eq!(tree.span(a), whole.span(b), "step {step}");
            assert_eq!(tree.field(a), whole.field(b), "step {step}");
            assert_eq!(tree.kind(a), whole.kind(b), "step {step}");
        }
    }
}

#[test]
fn wire_faults_reside_in_the_product_and_clip_the_index() {
    // A group code stops this dialect at byte 0.
    let grouped = [0x0B, 0x0C];
    let tree = open(&grouped);
    let fault = tree.fault().unwrap();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::GroupCode { .. }));
    assert_eq!(tree.indexed_end(), 0);

    // The legal prefix stays queryable beside the fault.
    let half = [0x08, 0x07, 0x0B];
    let tree = open(&half);
    assert!(!tree.is_complete());
    assert_eq!(tree.indexed_end(), 2);
    let tops: Vec<_> = tree.top().collect();
    assert_eq!(tops.len(), 1);
    assert_eq!(tree.varint_word(tops[0]), Some(7));
}

#[test]
fn truncations_attribute_the_outermost_overrunning_extent() {
    // A LEN declaring five payload bytes over a source holding
    // one: the resident twin refuses at the LEN's open
    // (LenOverrun against the total length), and the replay walk
    // reproduces that verdict when it meets the source's end —
    // same kind, same coordinate, same zone remainder, no row.
    let short = [0x0A, 0x05, 0x10];
    let tree = open(&short);
    let fault = tree.fault().unwrap();
    assert_eq!(fault.at(), 1);
    assert!(matches!(
        fault.kind(),
        FaultKind::LenOverrun { field, declared, zone_left }
            if field.as_inner() == 1 && declared.as_inner() == 5 && zone_left == 1
    ));
    assert_eq!((tree.node_count(), tree.indexed_end()), (0, 0));

    // The same attribution under a committed descent.
    struct CommitAll;
    impl Advisor for CommitAll {
        fn advise(&mut self, _ancestry: Ancestry<'_>, _field: FieldNumber) -> Advice {
            Advice::Commit
        }
    }
    let unclosed = [0x0A, 0x05, 0x08, 0x01];
    let tree =
        Survey::open(SliceSource::new(&unclosed), DepthLimit::REFERENCE, &mut CommitAll).unwrap();
    let fault = tree.fault().unwrap();
    assert!(matches!(
        fault.kind(),
        FaultKind::LenOverrun { field, zone_left, .. }
            if field.as_inner() == 1 && zone_left == 2
    ));

    // A bare tag cut by the source end: no extent to attribute.
    let cut_tag = [0x80];
    let tree = open(&cut_tag);
    let fault = tree.fault().unwrap();
    assert!(matches!(
        fault.kind(),
        FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SourceEnd }
    ));
}

#[test]
fn the_canonical_instance_judges_widths_the_tolerant_one_ignores() {
    // 150 continuation-padded to three bytes.
    let padded = [0x08, 0x96, 0x81, 0x00];
    let tolerant = open(&padded);
    assert!(tolerant.is_complete());

    let canonical = Survey::open_standard(
        SliceSource::new(&padded),
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
        &mut NoAdvice,
    )
    .unwrap();
    let fault = canonical.fault().unwrap();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::NonMinimalValue { .. }));
}

#[test]
fn fetches_answer_byte_questions_by_later_walks() {
    let mut tree = open(&MIXED);
    let tops: Vec<_> = tree.top().collect();

    // The Vec face appends and reports clean.
    let mut out = Vec::from(&b"seed"[..]);
    tree.read_payload(tops[1], &mut out).unwrap();
    assert_eq!(out, b"seedhi");

    // The sink face hands borrowed views.
    let mut sunk = Vec::new();
    tree.payload_sink(tops[1], |bytes| sunk.extend_from_slice(bytes)).unwrap();
    assert_eq!(sunk, b"hi");

    // The batch face: one walk, source order, request identity.
    let mut hits: Vec<(NodeId, Vec<u8>)> = Vec::new();
    tree.fetch_payloads(&[tops[3], tops[1]], |id, bytes| {
        if let Some(last) = hits.last_mut()
            && last.0 == id
        {
            last.1.extend_from_slice(bytes);
        } else {
            hits.push((id, Vec::from(bytes)));
        }
    })
    .unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].0, tops[1]);
    assert_eq!(hits[0].1, b"hi");
    assert_eq!(hits[1].0, tops[3]);
    assert_eq!(hits[1].1, MIXED[13..21]);
}

#[test]
fn nested_batch_requests_share_the_one_walk() {
    // LEN f1 wrapping { LEN f2 "hi" }: parent and child extents
    // nest; each covered byte is handed to each request.
    let nested = [0x0A, 0x04, 0x12, 0x02, 0x68, 0x69];
    let mut tree = open(&nested);
    let parent = tree.top().next().unwrap();
    let child = tree.children(parent).next().unwrap();
    let mut per_id: Vec<(NodeId, Vec<u8>)> = alloc::vec![(parent, Vec::new()), (child, Vec::new())];
    tree.fetch_payloads(&[child, parent], |id, bytes| {
        for (key, buf) in &mut per_id {
            if *key == id {
                buf.extend_from_slice(bytes);
            }
        }
    })
    .unwrap();
    assert_eq!(per_id[0].1, [0x12, 0x02, 0x68, 0x69]);
    assert_eq!(per_id[1].1, b"hi");
}

#[test]
fn a_clipped_extent_refuses_the_fetch() {
    // A committed LEN whose interior hits a wire fault: the walk
    // clips at the interior record, the LEN row keeps its
    // declared, sealed span past the indexed prefix, and the
    // fetch refuses to read bytes the index walk never proved.
    struct CommitAll;
    impl Advisor for CommitAll {
        fn advise(&mut self, _ancestry: Ancestry<'_>, _field: FieldNumber) -> Advice {
            Advice::Commit
        }
    }
    let clipped = [0x0A, 0x02, 0x0B, 0x0C];
    let mut tree =
        Survey::open(SliceSource::new(&clipped), DepthLimit::REFERENCE, &mut CommitAll).unwrap();
    assert!(matches!(tree.fault().unwrap().kind(), FaultKind::GroupCode { .. }));
    assert_eq!(tree.indexed_end(), 2);
    let id = tree.top().next().unwrap();
    assert_eq!(tree.span(id).end(), 4);
    let mut out = Vec::new();
    assert!(matches!(tree.read_payload(id, &mut out), Err(FetchFault::Incomplete { at: 2 })));
    assert!(out.is_empty());
}

#[test]
fn a_shorter_second_walk_is_a_torn_fetch_with_the_exact_coordinate() {
    // Index over the full bytes; fetch walks over a shrunk
    // source: the machine refuses at the measured coordinate it
    // could not reach.
    let full = [0x08, 0x01, 0x12, 0x04, 0x61, 0x62, 0x63, 0x64];

    // Shrunk before the extent start: the seek comes back short.
    let mut tree = Survey::open(
        Shrinking { full: &full, later: &full[..3], begun: 0 },
        DepthLimit::REFERENCE,
        &mut NoAdvice,
    )
    .unwrap();
    let target = tree.top().nth(1).unwrap();
    let mut out = Vec::from(&b"kept"[..]);
    let fault = tree.read_payload(target, &mut out).unwrap_err();
    assert!(matches!(fault, FetchFault::Torn { at: 4 }));
    // The append face restored its mark.
    assert_eq!(out, b"kept");

    // Shrunk inside the extent: the copy comes back short, and
    // the sink face names the exact handed prefix.
    let mut tree = Survey::open(
        Shrinking { full: &full, later: &full[..6], begun: 0 },
        DepthLimit::REFERENCE,
        &mut NoAdvice,
    )
    .unwrap();
    let target = tree.top().nth(1).unwrap();
    let mut sunk = Vec::new();
    let handed = tree.payload_sink(target, |bytes| sunk.extend_from_slice(bytes)).unwrap_err();
    assert_eq!(handed.handed, 2);
    assert_eq!(sunk, b"ab");
    assert!(matches!(handed.fault, FetchFault::Torn { at: 8 }));
}

#[test]
fn the_equal_length_content_tear_is_the_documented_residual() {
    // Same length, different payload bytes on the second walk:
    // the fetch does NOT fault — the output differs. This row
    // pins the contract's edge so it cannot silently move: byte
    // identity across walks is the provider's obligation, not the
    // machine's judgment.
    let full = [0x12, 0x02, 0x68, 0x69];
    let torn = [0x12, 0x02, 0x58, 0x59];
    let mut tree = Survey::open(
        Shrinking { full: &full, later: &torn, begun: 0 },
        DepthLimit::REFERENCE,
        &mut NoAdvice,
    )
    .unwrap();
    let id = tree.top().next().unwrap();
    let mut out = Vec::new();
    tree.read_payload(id, &mut out).unwrap();
    assert_eq!(out, b"XY");
    assert_ne!(out, b"hi");
}

#[test]
fn empty_documents_and_empty_extents_are_lawful() {
    let tree = open(&[]);
    assert!(tree.is_complete());
    assert!(tree.is_empty());
    assert_eq!(tree.indexed_end(), 0);

    // A zero-length LEN payload fetches as zero bytes, no walk
    // owed.
    let empty_len = [0x0A, 0x00];
    let mut tree = open(&empty_len);
    let id = tree.top().next().unwrap();
    let mut out = Vec::new();
    tree.read_payload(id, &mut out).unwrap();
    assert!(out.is_empty());
}

#[test]
fn into_source_releases_the_handle() {
    let bytes = [0x08, 0x01];
    let tree = open(&bytes);
    let source = tree.into_source();
    assert_eq!(source.bytes(), bytes);
}
