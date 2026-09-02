use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::stream_corpus::{self, CutStage, Expected, cut_stage};
use crate::wire::groupless::RecordKind;

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
        RecordKind::I32 => 5,
    }
}

/// Every derived expectation against the sealed machine's public
/// faces: source bytes, top order, projections, exact spans, the
/// reverse index, the clean save, and the fresh revision log.
fn assert_sealed(draft: &Draft, bytes: &[u8], expected: &[Expected]) {
    assert_eq!(draft.source(), bytes);
    assert_eq!(draft.pending(), 0);
    let tops: Vec<Handle> = draft.top().collect();
    assert_eq!(tops.len(), expected.len());
    for (&handle, exp) in tops.iter().zip(expected) {
        assert_eq!(draft.field(handle).unwrap().as_inner(), exp.field);
        assert_eq!(code_of(draft.kind(handle).unwrap()), exp.code);
        let span = draft.span(handle).unwrap().expect("scanned rows have source spans");
        assert_eq!((span.start(), span.end()), (exp.start, exp.end));
        match draft.kind(handle).unwrap() {
            RecordKind::Varint => {
                assert_eq!(draft.varint_word(handle).ok(), exp.value);
            }
            RecordKind::Len => {
                let body = &bytes
                    [exp.payload_start as usize..(exp.payload_start + exp.payload_len) as usize];
                assert_eq!(draft.payload_bytes(handle).unwrap(), body);
            }
            RecordKind::I32 | RecordKind::I64 => {}
        }
    }
    // The reverse index at every byte: the narrowest covering
    // record is the containing top row (no descents ran).
    for pos in 0..u32::try_from(bytes.len()).unwrap() {
        let covering = expected.iter().position(|e| e.start <= pos && pos < e.end);
        let named = draft
            .narrowest(pos)
            .map(|h| tops.iter().position(|&t| t == h).expect("narrowest answers top rows"));
        assert_eq!(named, covering, "narrowest at {pos}");
    }
    assert_eq!(draft.save().unwrap(), bytes);
}

#[test]
fn the_boundary_corpus_seals_identically_under_every_chunking() {
    for (bytes, expected) in stream_corpus::groupless_items() {
        for plan in stream_corpus::chunkings(&bytes) {
            let draft = ingest(&plan).unwrap_or_else(|failure| {
                panic!("plan of {} chunks refused: {failure}", plan.len())
            });
            assert_sealed(&draft, &bytes, &expected);
        }
    }
}

#[test]
fn truncation_at_every_cut_names_the_stage_or_seals_the_prefix() {
    for (bytes, expected) in stream_corpus::groupless_items() {
        for cut in 0..=bytes.len() {
            let cut_u32 = u32::try_from(cut).unwrap();
            let prefix = &bytes[..cut];
            for plan in [vec![prefix.to_vec()], prefix.iter().map(|&b| vec![b]).collect::<Vec<_>>()]
            {
                let outcome = ingest(&plan);
                match cut_stage(&expected, cut_u32) {
                    CutStage::Boundary => {
                        let sealed = expected
                            .iter()
                            .filter(|e| e.end <= cut_u32)
                            .copied()
                            .collect::<Vec<_>>();
                        assert_sealed(&outcome.unwrap(), prefix, &sealed);
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
    /// The offset of the byte whose arrival decides the fault.
    deciding: usize,
    at: u64,
    kind: IngestFaultKind,
}

fn fault_docs() -> Vec<FaultDoc> {
    let field1 = FieldNumber::new(1).unwrap();
    // The carried-prefix control: nine continuation bytes ride the
    // carry, the deciding byte arrives later.
    let mut wrap = vec![0x08];
    wrap.extend_from_slice(&[0x80; 9]);
    wrap.push(0x02);
    vec![
        FaultDoc {
            bytes: vec![0x00],
            deciding: 0,
            at: 0,
            kind: IngestFaultKind::Wire(Fault { at: 0, kind: FaultKind::FieldZero }),
        },
        FaultDoc {
            bytes: vec![0x80; 5],
            deciding: 4,
            at: 0,
            kind: IngestFaultKind::Wire(Fault {
                at: 0,
                kind: FaultKind::Tag { fault: ReadFault::TooWide },
            }),
        },
        FaultDoc {
            bytes: vec![0x0B],
            deciding: 0,
            at: 0,
            kind: IngestFaultKind::Refused(Refusal::GroupCode {
                at: 0,
                field: field1,
                low3: Low3::from_word(0x0B),
            }),
        },
        FaultDoc {
            bytes: wrap,
            deciding: 10,
            at: 1,
            kind: IngestFaultKind::Wire(Fault {
                at: 1,
                kind: FaultKind::Value { field: field1, fault: ReadFault::OutOfClass },
            }),
        },
        FaultDoc {
            bytes: vec![0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0x07],
            deciding: 5,
            at: 6,
            kind: IngestFaultKind::CoordinateLimit {
                limit: 0x7FFF_FFFF,
                attempted_end: 6 + 0x7FFF_FFFF,
            },
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
    let _failure = ingest.feed(&[0x00]).unwrap_err();
    let _ = ingest.feed(&[0x08]);
}

#[test]
fn the_abandonment_door_returns_the_accumulated_backing() {
    let mut ingest = Ingest::new();
    ingest.feed(&[0x08, 0x96]).unwrap(); // a value still in flight
    assert_eq!(ingest.offset(), 2);
    assert_eq!(ingest.into_source(), [0x08, 0x96]);
}

#[test]
fn an_oversize_capacity_declaration_refuses_at_the_start_door() {
    let refused = Ingest::with_capacity(usize::MAX);
    assert!(matches!(refused, Err(StartFault::TooLarge { capacity: usize::MAX })));
}

#[test]
fn both_finish_doors_seal_the_same_parts() {
    let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let feed = |bytes: &[u8]| {
        let mut ingest = Ingest::new();
        ingest.feed(bytes).unwrap();
        ingest
    };
    let copying = feed(&msg).finish().unwrap();
    let borrowing = feed(&msg).finish_borrow().unwrap();
    assert_eq!(copying.save().unwrap(), msg);
    assert_eq!(borrowing.save().unwrap(), msg);
    assert_eq!(copying.top().count(), 2);
    assert_eq!(borrowing.top().count(), 2);
}

/// The finished-state differential: feed against the buffered twin
/// over the concatenated bytes — public faces and the private
/// construction snapshot both.
#[cfg(feature = "draft-groupless")]
mod twin {
    use super::*;
    use crate::draft::groupless as buffered;

    /// The public projections, compared pairwise.
    fn assert_faces_match(mine: &Draft, twin: &buffered::Draft) {
        assert_eq!(mine.source(), twin.source());
        assert_eq!(mine.pending(), twin.pending());
        assert_eq!(mine.save_len().unwrap(), twin.save_len().unwrap());
        assert_eq!(mine.save().unwrap(), twin.save().unwrap());
        assert_eq!(mine.save_canonical().unwrap(), twin.save_canonical().unwrap());
        let my_tops: Vec<_> = mine.top().collect();
        let twin_tops: Vec<_> = twin.top().collect();
        assert_eq!(my_tops.len(), twin_tops.len());
        for (&m, &t) in my_tops.iter().zip(&twin_tops) {
            assert_eq!(mine.field(m).unwrap(), twin.field(t).unwrap());
            assert_eq!(mine.kind(m).unwrap(), twin.kind(t).unwrap());
            assert_eq!(mine.span(m).unwrap(), twin.span(t).unwrap());
            assert_eq!(mine.varint_word(m).ok(), twin.varint_word(t).ok());
            assert_eq!(mine.payload_bytes(m).ok(), twin.payload_bytes(t).ok());
        }
        for pos in 0..u32::try_from(mine.source().len()).unwrap() {
            let m = mine.narrowest(pos).map(|h| (mine.field(h).unwrap(), mine.span(h).unwrap()));
            let t = twin.narrowest(pos).map(|h| (twin.field(h).unwrap(), twin.span(h).unwrap()));
            assert_eq!(m, t, "narrowest at {pos}");
        }
    }

    #[test]
    fn the_seal_builds_exactly_what_the_buffered_open_builds() {
        for (bytes, _) in stream_corpus::groupless_items() {
            for plan in stream_corpus::chunkings(&bytes) {
                let mut mine = ingest(&plan).unwrap();
                let mut twin = buffered::Draft::open(bytes.clone()).unwrap();
                // The private snapshot: arena order, links, widths,
                // edit state, the root layer, and the source run —
                // the handle-numeric comparison public iteration
                // cannot give.
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
                            Descent::Refused(_) => (2, false),
                        };
                        let twin_shape = match twin.descend(t).unwrap() {
                            buffered::Descent::Opened { first } => (0u8, first.is_some()),
                            buffered::Descent::Faulted(_) => (1, false),
                            buffered::Descent::Refused(_) => (2, false),
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
/// class and `u64` coordinate.
#[cfg(feature = "scan-groupless")]
mod scan_parity {
    use core::ops::ControlFlow;

    use super::*;
    use crate::scan::LenDisposition;
    use crate::scan::groupless::{Parser, Sink};
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
        // The depth bound never bites under `OpaqueSkip` — no LEN
        // is committed — and this host declares none of its own.
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
            IngestFaultKind::Refused(_) | IngestFaultKind::CoordinateLimit { .. } => {
                FaultClass::Capability
            }
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
        for (bytes, _) in stream_corpus::groupless_items() {
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
            if matches!(doc.kind, IngestFaultKind::CoordinateLimit { .. }) {
                continue; // the explicit exception row below
            }
            for split in 0..=doc.deciding {
                let plan = vec![doc.bytes[..split].to_vec(), doc.bytes[split..].to_vec()];
                assert_eq!(ingest_outcome(&plan), scan_outcome(&plan));
            }
        }
    }

    /// The named exception row: the editor's `i32::MAX` source cap
    /// refuses a declared LEN endpoint the scanner's `u64` space
    /// still hosts.
    #[test]
    fn the_editor_cap_refuses_earlier_than_the_scanner() {
        let doc = [0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        assert_eq!(ingest_outcome(&[doc.to_vec()]), Err((6, FaultClass::Capability)));
        assert_eq!(scan_outcome(&[doc.to_vec()]), Err((6, FaultClass::Grammar)));
    }
}

#[test]
fn the_sealed_machine_revises_as_the_buffered_shape() {
    // Edit, insert, revert all: byte fidelity — padding included —
    // restores the fed bytes exactly, and the undo log runs the
    // sealed machine's whole command set.
    let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
    let mut draft = ingest(&[msg.to_vec()]).unwrap();
    let tops: Vec<Handle> = draft.top().collect();
    draft.set_varint(tops[0], 7).unwrap();
    let f3 = FieldNumber::new(3).unwrap();
    draft.insert_varint(InsertAt::TailOf(None), f3, 1).unwrap();
    draft.delete(tops[1]).unwrap();
    assert_eq!(draft.save().unwrap(), [0x08, 0x07, 0x18, 0x01]);
    assert_eq!(draft.pending(), 3);
    draft.revert_all();
    assert_eq!(draft.save().unwrap(), msg);
}

#[test]
fn the_sealed_machine_descends_and_edits_as_the_buffered_shape() {
    // LEN f2 wrapping { varint f1=1 }: descend after the seal uses
    // the buffered slice scan over the now-buffered payload.
    let msg = [0x08, 0x01, 0x12, 0x02, 0x08, 0x01];
    let mut draft = ingest(&[msg.to_vec()]).unwrap();
    let f2 = FieldNumber::new(2).unwrap();
    let container = draft.top().by_field(f2).next().unwrap();
    let Descent::Opened { first: Some(inner) } = draft.descend(container).unwrap() else {
        panic!("a well-formed payload opens");
    };
    draft.set_varint(inner, 7).unwrap();
    assert_eq!(draft.save().unwrap(), [0x08, 0x01, 0x12, 0x02, 0x08, 0x07]);
    draft.revert();
    assert_eq!(draft.save().unwrap(), msg);
}
