use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::stream_corpus::{self, CutStage, ExpectedNode, cut_stage_tree};
use crate::wire::grouped::RecordKind;

/// Feeds `chunks` and seals.
fn ingest(chunks: &[Vec<u8>]) -> Result<Draft, Failure> {
    let mut ingest = Ingest::new();
    for chunk in chunks {
        ingest.feed(chunk)?;
    }
    ingest.finish()
}

/// The wire code the corpus stores for a kind.
const fn code_of(kind: RecordKind) -> u32 {
    match kind {
        RecordKind::Varint => 0,
        RecordKind::I64 => 1,
        RecordKind::Len => 2,
        RecordKind::Group => 3,
        RecordKind::I32 => 5,
    }
}

/// One layer of the geometry tree against the machine's faces,
/// recursing into group interiors.
fn assert_layer(draft: &Draft, bytes: &[u8], handles: &[Handle], expected: &[ExpectedNode]) {
    assert_eq!(handles.len(), expected.len());
    for (&handle, exp) in handles.iter().zip(expected) {
        assert_eq!(draft.field(handle).unwrap().as_inner(), exp.row.field);
        assert_eq!(code_of(draft.kind(handle).unwrap()), exp.row.code);
        let span = draft.span(handle).unwrap().expect("scanned rows have source spans");
        assert_eq!((span.start(), span.end()), (exp.row.start, exp.row.end));
        match draft.kind(handle).unwrap() {
            RecordKind::Varint => assert_eq!(draft.varint_word(handle).ok(), exp.row.value),
            RecordKind::Len => {
                let body = &bytes[exp.row.payload_start as usize
                    ..(exp.row.payload_start + exp.row.payload_len) as usize];
                assert_eq!(draft.payload_bytes(handle).unwrap(), body);
            }
            RecordKind::Group => {
                let kids: Vec<Handle> = draft.children(handle).unwrap().collect();
                assert_layer(draft, bytes, &kids, &exp.kids);
            }
            RecordKind::I32 | RecordKind::I64 => {}
        }
    }
}

/// The deepest expected node covering `pos`.
fn deepest(expected: &[ExpectedNode], pos: u32) -> Option<&ExpectedNode> {
    let node = expected.iter().find(|n| n.row.start <= pos && pos < n.row.end)?;
    Some(deepest(&node.kids, pos).unwrap_or(node))
}

/// Every derived expectation against the sealed machine's public
/// faces, group interiors included.
fn assert_sealed(draft: &Draft, bytes: &[u8], expected: &[ExpectedNode]) {
    assert_eq!(draft.source(), bytes);
    assert_eq!(draft.pending(), 0);
    let tops: Vec<Handle> = draft.top().collect();
    assert_layer(draft, bytes, &tops, expected);
    for pos in 0..u32::try_from(bytes.len()).unwrap() {
        let named = draft.narrowest(pos).map(|h| {
            let span = draft.span(h).unwrap().expect("narrowest answers scanned rows");
            (draft.field(h).unwrap().as_inner(), span.start(), span.end())
        });
        let derived = deepest(expected, pos).map(|n| (n.row.field, n.row.start, n.row.end));
        assert_eq!(named, derived, "narrowest at {pos}");
    }
    assert_eq!(draft.save().unwrap(), bytes);
}

#[test]
fn the_boundary_corpus_seals_identically_under_every_chunking() {
    for (bytes, expected) in stream_corpus::grouped_items() {
        for plan in stream_corpus::chunkings(&bytes) {
            let draft = ingest(&plan).unwrap_or_else(|failure| {
                panic!("plan of {} chunks refused: {failure}", plan.len())
            });
            assert_sealed(&draft, &bytes, &expected);
        }
    }
}

/// Prunes the derived tree to the records completed strictly before
/// `cut` (a group completes at its verified close).
fn sealed_prefix(expected: &[ExpectedNode], cut: u32) -> Vec<ExpectedNode> {
    expected.iter().filter(|node| node.row.end <= cut).cloned().collect()
}

#[test]
fn truncation_at_every_cut_names_the_stage_or_seals_the_prefix() {
    for (bytes, expected) in stream_corpus::grouped_items() {
        for cut in 0..=bytes.len() {
            let cut_u32 = u32::try_from(cut).unwrap();
            let prefix = &bytes[..cut];
            for plan in [vec![prefix.to_vec()], prefix.iter().map(|&b| vec![b]).collect::<Vec<_>>()]
            {
                let outcome = ingest(&plan);
                match cut_stage_tree(&expected, cut_u32) {
                    CutStage::Boundary => {
                        assert_sealed(
                            &outcome.unwrap(),
                            prefix,
                            &sealed_prefix(&expected, cut_u32),
                        );
                    }
                    stage => {
                        let Err(failure) = outcome else {
                            panic!("a mid-record cut at {cut} must truncate");
                        };
                        assert_eq!(failure.source(), prefix);
                        assert_eq!(failure.chunk(), ChunkDisposition::Absorbed);
                        let fault = failure.fault();
                        assert_eq!(fault.at(), cut_u32 as u64, "stream coordinate is EOF");
                        let IngestFaultKind::Wire(wire) = fault.kind() else {
                            panic!("truncation is a wire fault, got {:?}", fault.kind());
                        };
                        match (stage, wire.kind) {
                            (
                                CutStage::Tag { start },
                                FaultKind::Tag { fault: ReadFault::Truncated },
                            ) => assert_eq!(wire.at, start),
                            (
                                CutStage::Value { field, value_at },
                                FaultKind::Value { field: f, fault: ReadFault::Truncated },
                            ) => {
                                assert_eq!((f.as_inner(), wire.at), (field, value_at));
                            }
                            (
                                CutStage::LenWord { field, value_at },
                                FaultKind::Len { field: f, fault: ReadFault::Truncated },
                            ) => {
                                assert_eq!((f.as_inner(), wire.at), (field, value_at));
                            }
                            (
                                CutStage::Payload { field, at, need, have },
                                FaultKind::PayloadCut { field: f, need: n, have: h },
                            ) => {
                                assert_eq!((f.as_inner(), wire.at, n, h), (field, at, need, have));
                            }
                            (
                                CutStage::Unclosed { field, at },
                                FaultKind::GroupUnclosed { open },
                            ) => {
                                assert_eq!((open.as_inner(), wire.at), (field, at));
                            }
                            (stage, kind) => panic!("cut {cut} judged {kind:?} at {stage:?}"),
                        }
                    }
                }
            }
        }
    }
}

/// A faulting document: the bytes, the deciding byte's offset, and
/// the pinned verdict.
struct FaultDoc {
    bytes: Vec<u8>,
    deciding: usize,
    at: u64,
    kind: IngestFaultKind,
}

fn fault_docs() -> Vec<FaultDoc> {
    let field1 = FieldNumber::new(1).unwrap();
    let field2 = FieldNumber::new(2).unwrap();
    vec![
        FaultDoc {
            bytes: vec![0x0C],
            deciding: 0,
            at: 0,
            kind: IngestFaultKind::Wire(Fault {
                at: 0,
                kind: FaultKind::GroupEndOrphan { found: field1 },
            }),
        },
        FaultDoc {
            bytes: vec![0x0B, 0x14],
            deciding: 1,
            at: 1,
            kind: IngestFaultKind::Wire(Fault {
                at: 1,
                kind: FaultKind::GroupEndMismatch { open: field1, found: field2 },
            }),
        },
        FaultDoc {
            bytes: vec![0x0B, 0x00],
            deciding: 1,
            at: 1,
            kind: IngestFaultKind::Wire(Fault { at: 1, kind: FaultKind::FieldZero }),
        },
    ]
}

#[test]
fn custody_reconstructs_the_offered_stream_at_every_split() {
    for doc in fault_docs() {
        for split in 0..=doc.deciding {
            let mut ingest = Ingest::new();
            let mut offered = Vec::new();
            let failure = 'job: {
                for chunk in [&doc.bytes[..split], &doc.bytes[split..]] {
                    offered.extend_from_slice(chunk);
                    if let Err(failure) = ingest.feed(chunk) {
                        break 'job failure;
                    }
                }
                panic!("the deciding byte was offered; the job must fail");
            };
            assert_eq!(failure.chunk(), ChunkDisposition::Absorbed);
            assert_eq!(failure.source(), offered, "split {split}");
            assert_eq!(failure.fault().at(), doc.at);
            assert_eq!(failure.fault().kind(), doc.kind);
        }
    }
}

#[test]
#[should_panic(expected = "ingest already terminal")]
fn a_spent_shell_refuses_another_feed() {
    let mut ingest = Ingest::new();
    let _failure = ingest.feed(&[0x0C]).unwrap_err();
    let _ = ingest.feed(&[0x08]);
}

#[test]
fn deep_nesting_is_lawful_without_a_bound() {
    // No depth policy exists on this host: a 300-deep frame chain —
    // past every buffered reader's reference bound — seals cleanly,
    // fed byte by byte.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x0B; 300]);
    bytes.extend_from_slice(&[0x0C; 300]);
    let plan: Vec<Vec<u8>> = bytes.iter().map(|&b| vec![b]).collect();
    let draft = ingest(&plan).unwrap();
    assert_eq!(draft.top().count(), 1);
    assert_eq!(draft.save().unwrap(), bytes);
}

#[test]
fn a_deep_closure_designates_with_its_exact_depth() {
    // 65,536 nested groups — past the sixteen-bit edge on a host
    // with no depth bound — built arithmetically: 128 KiB of
    // one-byte group tags.
    let mut bytes = vec![0x0B; 65_536];
    bytes.extend_from_slice(&vec![0x0C; 65_536]);
    let draft = ingest(&[bytes.clone()]).unwrap();
    let top = draft.top().next().unwrap();
    let record = draft.record_ref(top).unwrap();
    assert_eq!(record.group_depth(), 65_536);
    assert_eq!(record.as_bytes(), bytes);
}

/// The finished-state differential: feed against the buffered twin
/// over the concatenated bytes — public faces (group interiors
/// recursively) and the private construction snapshot both.
#[cfg(feature = "draft-grouped")]
mod twin {
    use super::*;
    use crate::draft::grouped as buffered;

    /// One layer's public projections, recursing into groups.
    fn assert_layer_match(
        mine: &Draft,
        twin: &buffered::Draft,
        my_handles: &[Handle],
        twin_handles: &[crate::draft::Handle],
    ) {
        assert_eq!(my_handles.len(), twin_handles.len());
        for (&m, &t) in my_handles.iter().zip(twin_handles) {
            assert_eq!(mine.field(m).unwrap(), twin.field(t).unwrap());
            assert_eq!(mine.kind(m).unwrap(), twin.kind(t).unwrap());
            assert_eq!(mine.span(m).unwrap(), twin.span(t).unwrap());
            assert_eq!(mine.varint_word(m).ok(), twin.varint_word(t).ok());
            assert_eq!(mine.payload_bytes(m).ok(), twin.payload_bytes(t).ok());
            if matches!(mine.kind(m).unwrap(), RecordKind::Group) {
                let my_kids: Vec<_> = mine.children(m).unwrap().collect();
                let twin_kids: Vec<_> = twin.children(t).unwrap().collect();
                assert_layer_match(mine, twin, &my_kids, &twin_kids);
            }
        }
    }

    /// The public projections, compared pairwise.
    fn assert_faces_match(mine: &Draft, twin: &buffered::Draft) {
        assert_eq!(mine.source(), twin.source());
        assert_eq!(mine.pending(), twin.pending());
        assert_eq!(mine.save_len().unwrap(), twin.save_len().unwrap());
        assert_eq!(mine.save().unwrap(), twin.save().unwrap());
        assert_eq!(mine.save_canonical().unwrap(), twin.save_canonical().unwrap());
        let my_tops: Vec<_> = mine.top().collect();
        let twin_tops: Vec<_> = twin.top().collect();
        assert_layer_match(mine, twin, &my_tops, &twin_tops);
        for pos in 0..u32::try_from(mine.source().len()).unwrap() {
            let m = mine.narrowest(pos).map(|h| (mine.field(h).unwrap(), mine.span(h).unwrap()));
            let t = twin.narrowest(pos).map(|h| (twin.field(h).unwrap(), twin.span(h).unwrap()));
            assert_eq!(m, t, "narrowest at {pos}");
        }
    }

    #[test]
    fn the_seal_builds_exactly_what_the_buffered_open_builds() {
        for (bytes, _) in stream_corpus::grouped_items() {
            for plan in stream_corpus::chunkings(&bytes) {
                let mut mine = ingest(&plan).unwrap();
                let mut twin = buffered::Draft::open(bytes.clone()).unwrap();
                assert_eq!(mine.construction_snapshot(), twin.construction_snapshot());
                assert_faces_match(&mine, &twin);
                // Descend every LEN top on both sides; the committed
                // interiors must agree again, snapshot included.
                let my_tops: Vec<_> = mine.top().collect();
                let twin_tops: Vec<_> = twin.top().collect();
                for (&m, &t) in my_tops.iter().zip(&twin_tops) {
                    if matches!(mine.kind(m).unwrap(), RecordKind::Len) {
                        let my_shape = match mine.descend(m).unwrap() {
                            Descent::Opened { first } => (0u8, first.is_some()),
                            Descent::Faulted(_) => (1, false),
                        };
                        let twin_shape = match twin.descend(t).unwrap() {
                            buffered::Descent::Opened { first } => (0u8, first.is_some()),
                            buffered::Descent::Faulted(_) => (1, false),
                        };
                        assert_eq!(my_shape, twin_shape);
                    }
                }
                assert_eq!(mine.construction_snapshot(), twin.construction_snapshot());
                assert_faces_match(&mine, &twin);
            }
        }
    }
}

/// The fault differential: ingest against the scanner under
/// `OpaqueSkip` and the matched tolerant standard — first-fault
/// class and `u64` coordinate. The scanner requires a depth bound
/// this host deliberately lacks; the reference bound never bites on
/// the corpus, and the divergence is the named exception row below.
#[cfg(feature = "scan-grouped")]
mod scan_parity {
    use core::ops::ControlFlow;

    use super::*;
    use crate::scan::LenDisposition;
    use crate::scan::grouped::{Parser, Sink};
    use crate::{DepthLimit, FaultClass, Standard};

    struct Skip;
    impl Sink for Skip {
        fn on_len(
            &mut self,
            _field: FieldNumber,
            _len: PayloadLen,
            _at: u64,
        ) -> ControlFlow<(), LenDisposition> {
            ControlFlow::Continue(LenDisposition::OpaqueSkip)
        }
    }

    fn scan_outcome(plan: &[Vec<u8>]) -> Result<(), (u64, FaultClass)> {
        let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
        for chunk in plan {
            if let Err(fault) = parser.feed(chunk, &mut Skip) {
                return Err((fault.at(), fault.kind().class()));
            }
        }
        parser.finish().map_err(|fault| (fault.at(), fault.kind().class()))
    }

    const fn class_of(kind: IngestFaultKind) -> FaultClass {
        match kind {
            IngestFaultKind::Wire(_) => FaultClass::Grammar,
            IngestFaultKind::CoordinateLimit { .. } => FaultClass::Capability,
            // Resource refusals have no scanner counterpart and no
            // row in this judge.
            IngestFaultKind::Resource(_) => unreachable!(),
        }
    }

    fn ingest_outcome(plan: &[Vec<u8>]) -> Result<(), (u64, FaultClass)> {
        let mut job = Ingest::new();
        for chunk in plan {
            if let Err(failure) = job.feed(chunk) {
                let fault = failure.fault();
                return Err((fault.at(), class_of(fault.kind())));
            }
        }
        job.finish().map(|_| ()).map_err(|failure| {
            let fault = failure.fault();
            (fault.at(), class_of(fault.kind()))
        })
    }

    #[test]
    fn every_cut_of_every_item_matches_the_scanner_verdict() {
        for (bytes, _) in stream_corpus::grouped_items() {
            for cut in 0..=bytes.len() {
                let prefix = bytes[..cut].to_vec();
                for plan in
                    [vec![prefix.clone()], prefix.iter().map(|&b| vec![b]).collect::<Vec<_>>()]
                {
                    assert_eq!(ingest_outcome(&plan), scan_outcome(&plan), "cut {cut}");
                }
            }
        }
    }

    #[test]
    fn every_fault_document_matches_the_scanner_verdict() {
        for doc in fault_docs() {
            for split in 0..=doc.deciding {
                let plan = vec![doc.bytes[..split].to_vec(), doc.bytes[split..].to_vec()];
                assert_eq!(ingest_outcome(&plan), scan_outcome(&plan));
            }
        }
    }

    /// The named exception row: this host declares no depth bound
    /// (its buffered twin's law), so nesting the scanner's policy
    /// refuses at its bound seals cleanly here — no
    /// scanner-equivalent unbounded policy exists.
    #[test]
    fn unbounded_nesting_is_the_named_scanner_divergence() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x0B; 300]);
        bytes.extend_from_slice(&[0x0C; 300]);
        let plan = vec![bytes];
        assert_eq!(ingest_outcome(&plan), Ok(()));
        // The 101st open tag leaves the reference bound: policy, at
        // its own offset.
        assert_eq!(scan_outcome(&plan), Err((100, FaultClass::Policy)));
    }
}

#[test]
fn the_sealed_machine_revises_group_interiors_as_the_buffered_shape() {
    // group f2 { varint f3=9 }: interior edits, an authored group,
    // and exact revision back to the fed bytes.
    let msg = [0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x09, 0x14];
    let mut draft = ingest(&[msg.to_vec()]).unwrap();
    let tops: Vec<Handle> = draft.top().collect();
    let inner = draft.children(tops[1]).unwrap().next().unwrap();
    draft.set_varint(inner, 7).unwrap();
    let f4 = FieldNumber::new(4).unwrap();
    draft.insert_group(InsertAt::TailOf(None), f4).unwrap();
    assert_eq!(draft.save().unwrap(), [0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x07, 0x14, 0x23, 0x24]);
    draft.revert_all();
    assert_eq!(draft.save().unwrap(), msg);
}
