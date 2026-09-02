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

// varint f1=150 · varint f2=42
const FLAT: [u8; 5] = [0x08, 0x96, 0x01, 0x10, 0x2A];

#[test]
fn an_identity_job_reproduces_the_source_bytes() {
    let rules = [Rule { path: &[Segment::Field(f(9))], action: Action::Delete }];
    let (out, stats) = job(&FLAT, &rules).unwrap();
    assert_eq!(out, FLAT);
    assert_eq!(stats, Stats::default());

    // The empty source is the empty output.
    let (out, stats) = job(&[], &rules).unwrap();
    assert!(out.is_empty());
    assert_eq!(stats, Stats::default());
}

#[test]
fn deletion_removes_the_record_and_counts_it() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let (out, stats) = job(&FLAT, &rules).unwrap();
    assert_eq!(out, [0x10, 0x2A]);
    assert_eq!(stats.deleted(), 1);
}

#[test]
fn replacement_keeps_the_tag_and_reauthors_the_payload() {
    // The replacement word re-emits minimally at whatever width
    // that takes — wider than the old payload here.
    let rules =
        [Rule { path: &[Segment::Field(f(2))], action: Action::Replace(Value::Varint(300)) }];
    let (out, stats) = job(&FLAT, &rules).unwrap();
    assert_eq!(out, [0x08, 0x96, 0x01, 0x10, 0xAC, 0x02]);
    assert_eq!(stats.replaced(), 1);
}

#[test]
fn fixed_records_replace_by_kind() {
    // I32 f3 · I64 f4
    let doc = [
        0x1D, 0x01, 0x00, 0x00, 0x80, // I32 f3
        0x21, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // I64 f4
    ];
    let rules = [
        Rule { path: &[Segment::Field(f(3))], action: Action::Replace(Value::I32(1)) },
        Rule { path: &[Segment::Field(f(4))], action: Action::Replace(Value::I64(2)) },
    ];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(
        out,
        [0x1D, 0x01, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(stats.replaced(), 2);
}

#[test]
fn a_shrinking_replacement_reauthors_the_crossed_prefix() {
    // LEN f1 { LEN f2 "abc" } — replace f2's payload with "x".
    let doc = [0x0A, 0x05, 0x12, 0x03, b'a', b'b', b'c'];
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2))],
        action: Action::Replace(Value::Len(b"x")),
    }];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x0A, 0x03, 0x12, 0x01, b'x']);
    assert_eq!((stats.replaced(), stats.descended()), (1, 1));
}

#[test]
fn a_growing_replacement_reauthors_the_crossed_prefix() {
    let doc = [0x0A, 0x03, 0x12, 0x01, b'x'];
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2))],
        action: Action::Replace(Value::Len(b"abc")),
    }];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x0A, 0x05, 0x12, 0x03, b'a', b'b', b'c']);
    assert_eq!((stats.replaced(), stats.descended()), (1, 1));
}

#[test]
fn a_held_interior_length_rides_the_source_prefix_verbatim() {
    // A same-width replacement inside a committed container: the
    // interior length holds, so the crossed prefix (padded on
    // purpose) rides verbatim.
    let doc = [0x0A, 0x82, 0x00, 0x08, 0x07];
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(1))],
        action: Action::Replace(Value::Varint(9)),
    }];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x0A, 0x82, 0x00, 0x08, 0x09]);
    assert_eq!(stats.replaced(), 1);
}

#[test]
fn normalize_erases_padding_the_record_carries() {
    // varint f1 padded tag and value · LEN f2 padded prefix.
    let doc = [
        0x88, 0x80, 0x00, 0x96, 0x81, 0x80, 0x00, // varint f1=150, all padded
        0x92, 0x80, 0x00, 0x02, 0x68, 0x69, // LEN f2 "hi", padded tag+prefix...
    ];
    // The LEN prefix 0x02 here is minimal; only its tag is padded.
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
    ];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69]);
    assert_eq!(stats.normalized(), 2);
}

#[test]
fn untouched_records_preserve_their_padding() {
    let doc = [0x88, 0x80, 0x00, 0x96, 0x81, 0x80, 0x00];
    let rules = [Rule { path: &[Segment::Field(f(9))], action: Action::Delete }];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, doc);
    assert_eq!(stats, Stats::default());
}

#[test]
fn the_canonical_face_refuses_padded_words_outside_normalize() {
    let doc = [0x88, 0x80, 0x00, 0x96, 0x81, 0x80, 0x00];
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
fn two_rules_on_one_record_conflict() {
    let route = [f(1)];
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Delete },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
            action: Action::Normalize,
        },
    ];
    let fault = job(&FLAT, &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Conflict { first: 0, second: 1 }));
}

#[test]
fn a_kind_mismatch_is_the_callers_schema_error() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Replace(Value::I32(1)) }];
    let fault = job(&FLAT, &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::KindMismatch { rule: 0 }));
}

#[test]
fn committed_descents_spend_the_depth_budget() {
    // LEN f1 { LEN f1 { varint f2 } } with a budget of one.
    let doc = [0x0A, 0x04, 0x0A, 0x02, 0x10, 0x01];
    let route = [f(1)];
    let rules = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
        action: Action::Replace(Value::Varint(9)),
    }];
    let set = RuleSet::over(&rules).unwrap();
    let fault =
        rewrite(&mut SliceSource::new(&doc), &set, DepthLimit::new(1).unwrap()).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Depth)));
}

#[test]
fn wire_faults_summarize_with_the_trail_attached() {
    // Unassigned code inside a committed container.
    let doc = [0x0A, 0x02, 0x0E, 0x00];
    let rules =
        [Rule { path: &[Segment::Field(f(1)), Segment::Field(f(2))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();
    let fault = rewrite(&mut SliceSource::new(&doc), &set, DepthLimit::REFERENCE).unwrap_err();
    let JobFault::Document(fault) = fault else { panic!("a document fault was expected") };
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Tag)));
    assert_eq!(fault.at(), 2);
    assert_eq!(fault.trail().len(), 1);
    assert_eq!(fault.trail()[0].field(), f(1));
    assert_eq!(fault.trail()[0].at(), 0);

    // A group code is this dialect's capability refusal.
    let doc = [0x0B, 0x0C];
    let fault = job(&doc, &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::GroupCode)));

    // A declared extent past the source's end is truncation.
    let doc = [0x0A, 0x7F, 0x08, 0x01];
    let fault = job(&doc, &rules).unwrap_err();
    assert!(matches!(document_kind(fault), FaultKind::Wire(WireBreach::Truncated)));
}

#[test]
fn unrouted_extents_are_sought_past_not_read() {
    // An unrouted LEN whose payload would be unlawful wire: pass
    // one never reads it, so the job succeeds and copies it.
    let doc = [0x12, 0x03, 0xFF, 0xFF, 0xFF, 0x08, 0x07];
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let (out, stats) = job(&doc, &rules).unwrap();
    assert_eq!(out, [0x12, 0x03, 0xFF, 0xFF, 0xFF]);
    assert_eq!(stats.deleted(), 1);
}

#[test]
fn view_partitioning_carries_no_meaning() {
    let doc = [0x0A, 0x05, 0x12, 0x03, b'a', b'b', b'c', 0x10, 0x96, 0x01];
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2))],
        action: Action::Replace(Value::Len(b"wider")),
    }];
    let set = RuleSet::over(&rules).unwrap();
    let mut whole = SliceSource::new(&doc);
    let expected = rewrite(&mut whole, &set, DepthLimit::REFERENCE).unwrap();
    for step in 1..=doc.len() {
        let mut source = Chunked { bytes: &doc, step };
        let got = rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap();
        assert_eq!(got, expected, "view step {step} diverged");
    }
}

#[test]
fn a_torn_source_is_refused_between_walks() {
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();

    // Shrunk: a copied extent ends early.
    let mut source = Shifting { full: &FLAT, later: &FLAT[..2], begun: 0 };
    let fault = rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(fault, JobFault::Torn { .. }));

    // Grown: the end probe sees bytes past the measured total.
    let longer = [0x08, 0x96, 0x01, 0x10, 0x2A, 0x18, 0x01];
    let mut source = Shifting { full: &FLAT, later: &longer, begun: 0 };
    let fault = rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(fault, JobFault::Torn { at } if at == FLAT.len() as u64));
}

#[test]
fn the_append_face_truncates_back_to_its_mark_on_refusal() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();

    let mut out = alloc::vec![0xEE];
    let stats =
        rewrite_into(&mut SliceSource::new(&FLAT), &set, DepthLimit::REFERENCE, &mut out).unwrap();
    assert_eq!(out, [0xEE, 0x10, 0x2A]);
    assert_eq!(stats.deleted(), 1);

    // A torn second walk refuses; the buffer keeps exactly its
    // entry contents.
    let mut source = Shifting { full: &FLAT, later: &FLAT[..2], begun: 0 };
    let fault = rewrite_into(&mut source, &set, DepthLimit::REFERENCE, &mut out).unwrap_err();
    assert!(matches!(fault, JobFault::Torn { .. }));
    assert_eq!(out, [0xEE, 0x10, 0x2A]);
}

#[test]
fn the_sink_face_names_the_handed_prefix() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();

    let mut got = Vec::new();
    let stats = rewrite_sink(&mut SliceSource::new(&FLAT), &set, DepthLimit::REFERENCE, |view| {
        got.extend_from_slice(view);
    })
    .unwrap();
    assert_eq!(got, [0x10, 0x2A]);
    assert_eq!(stats.deleted(), 1);

    // A measure-pass fault precedes every handoff.
    let broken = [0x0E];
    let refusal = rewrite_sink(&mut SliceSource::new(&broken), &set, DepthLimit::REFERENCE, |_| {
        panic!("no handoff before the measure pass settles")
    })
    .unwrap_err();
    assert_eq!(refusal.handed, 0);
    assert!(matches!(refusal.fault, JobFault::Document(_)));

    // A torn emission walk names the exact prefix handed over.
    let mut source = Shifting { full: &FLAT, later: &FLAT[..2], begun: 0 };
    let mut handed = 0u64;
    let refusal = rewrite_sink(&mut source, &set, DepthLimit::REFERENCE, |view| {
        handed += view.len() as u64;
    })
    .unwrap_err();
    assert!(matches!(refusal.fault, JobFault::Torn { .. }));
    assert_eq!(refusal.handed, handed);
}

#[test]
fn stats_expose_silently_inapplicable_rules() {
    // The route expects a container; a scalar occurrence simply
    // never matches — zero counts are the operator's signal.
    let route = [f(1)];
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
        action: Action::Delete,
    }];
    let (out, stats) = job(&FLAT, &rules).unwrap();
    assert_eq!(out, FLAT);
    assert_eq!(stats, Stats::default());
}
