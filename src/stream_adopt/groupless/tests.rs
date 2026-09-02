use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::stream_corpus::{self, CutStage, Expected, cut_stage};
use crate::varint::carry::{Carry, Step as CarryStep};
use crate::wire::groupless::RecordKind;

/// Feeds `chunks` and seals.
fn ingest(chunks: &[Vec<u8>]) -> Result<Adopt<'static>, Failure> {
    let mut ingest = Ingest::new(DepthLimit::REFERENCE);
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
/// reverse index, and the clean save.
fn assert_sealed(adopt: &Adopt<'_>, bytes: &[u8], expected: &[Expected]) {
    assert_eq!(adopt.source(), bytes);
    let tops: Vec<Handle> = adopt.top().collect();
    assert_eq!(tops.len(), expected.len());
    for (&handle, exp) in tops.iter().zip(expected) {
        assert_eq!(adopt.field(handle).as_inner(), exp.field);
        assert_eq!(code_of(adopt.kind(handle)), exp.code);
        let span = adopt.span(handle).expect("scanned rows have source spans");
        assert_eq!((span.start(), span.end()), (exp.start, exp.end));
        match adopt.kind(handle) {
            RecordKind::Varint => {
                assert_eq!(adopt.varint_word(handle), exp.value);
            }
            RecordKind::Len => {
                let body = &bytes
                    [exp.payload_start as usize..(exp.payload_start + exp.payload_len) as usize];
                assert_eq!(adopt.payload_bytes(handle), Some(body));
            }
            RecordKind::I32 | RecordKind::I64 => {}
        }
    }
    // The reverse index at every byte: the narrowest covering
    // record is the containing top row (no descents ran).
    for pos in 0..u32::try_from(bytes.len()).unwrap() {
        let covering = expected.iter().position(|e| e.start <= pos && pos < e.end);
        let named = adopt
            .narrowest(pos)
            .map(|h| tops.iter().position(|&t| t == h).expect("narrowest answers top rows"));
        assert_eq!(named, covering, "narrowest at {pos}");
    }
    assert_eq!(adopt.save().unwrap(), bytes);
}

#[test]
fn the_boundary_corpus_seals_identically_under_every_chunking() {
    for (bytes, expected) in stream_corpus::groupless_items() {
        for plan in stream_corpus::chunkings(&bytes) {
            let adopt = ingest(&plan).unwrap_or_else(|failure| {
                panic!("plan of {} chunks refused: {failure}", plan.len())
            });
            assert_sealed(&adopt, &bytes, &expected);
        }
    }
}

#[test]
fn truncation_at_every_cut_names_the_stage_or_seals_the_prefix() {
    for (bytes, expected) in stream_corpus::groupless_items() {
        for cut in 0..=bytes.len() {
            let cut_u32 = u32::try_from(cut).unwrap();
            let prefix = &bytes[..cut];
            // Whole-prefix and byte-at-a-time feeds agree.
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
    // Nine carried continuation bytes ahead of the deciding one:
    // the carried-prefix controls.
    let mut wide = vec![0x08];
    wide.extend_from_slice(&[0x80; 10]);
    let mut wrap = vec![0x08];
    wrap.extend_from_slice(&[0x80; 9]);
    wrap.push(0x02);
    vec![
        // A first-byte fault: field zero.
        FaultDoc {
            bytes: vec![0x00],
            deciding: 0,
            at: 0,
            kind: IngestFaultKind::Wire(Fault { at: 0, kind: FaultKind::FieldZero }),
        },
        // A tag past the five-byte window.
        FaultDoc {
            bytes: vec![0x80; 5],
            deciding: 4,
            at: 0,
            kind: IngestFaultKind::Wire(Fault {
                at: 0,
                kind: FaultKind::Tag { fault: ReadFault::TooWide },
            }),
        },
        // A tag whose fifth byte leaves the u32 class.
        FaultDoc {
            bytes: vec![0x88, 0x80, 0x80, 0x80, 0x10],
            deciding: 4,
            at: 0,
            kind: IngestFaultKind::Wire(Fault {
                at: 0,
                kind: FaultKind::Tag { fault: ReadFault::OutOfClass },
            }),
        },
        // A group code: lawful wire outside this dialect.
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
        // An unassigned code (6).
        FaultDoc {
            bytes: vec![0x0E],
            deciding: 0,
            at: 0,
            kind: IngestFaultKind::Wire(Fault {
                at: 0,
                kind: FaultKind::Unassigned { field: field1, low3: Low3::from_word(0x0E) },
            }),
        },
        // A value carried through nine continuation bytes, then
        // judged too wide on the eleventh construct byte.
        FaultDoc {
            bytes: wide,
            deciding: 10,
            at: 1,
            kind: IngestFaultKind::Wire(Fault {
                at: 1,
                kind: FaultKind::Value { field: field1, fault: ReadFault::TooWide },
            }),
        },
        // A tenth value byte above the u64 class.
        FaultDoc {
            bytes: wrap,
            deciding: 10,
            at: 1,
            kind: IngestFaultKind::Wire(Fault {
                at: 1,
                kind: FaultKind::Value { field: field1, fault: ReadFault::OutOfClass },
            }),
        },
        // A length prefix leaving the length class.
        FaultDoc {
            bytes: vec![0x12, 0x80, 0x80, 0x80, 0x80, 0x08],
            deciding: 5,
            at: 1,
            kind: IngestFaultKind::Wire(Fault {
                at: 1,
                kind: FaultKind::Len {
                    field: FieldNumber::new(2).unwrap(),
                    fault: ReadFault::OutOfClass,
                },
            }),
        },
        // A completed LEN prefix whose declared endpoint leaves the
        // editor's coordinate class: judged the moment the prefix
        // completes, though no body byte ever arrives.
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
            let mut ingest = Ingest::new(DepthLimit::REFERENCE);
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
            // Mid-parse faults absorb the failing chunk whole: the
            // source is exactly the concatenation offered so far.
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
    let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    let _failure = ingest.feed(&[0x00]).unwrap_err();
    let _ = ingest.feed(&[0x08]);
}

/// Consumes a carry-kernel completion into the plain verdict the
/// differential compares on (value out, carry emptied).
fn spent_value(
    step: crate::varint::carry::Step<crate::varint::carry::Complete<'_, u64>>,
) -> crate::varint::carry::Step<u64> {
    match step {
        CarryStep::Done(complete) => CarryStep::Done(complete.take()),
        CarryStep::More => CarryStep::More,
        CarryStep::Cut => CarryStep::Cut,
        CarryStep::TooWide => CarryStep::TooWide,
        CarryStep::OutOfClass => CarryStep::OutOfClass,
    }
}

#[test]
fn the_ingest_stepper_matches_the_carry_kernel_byte_for_byte() {
    // The value-domain differential the design owes: every Done
    // width, both terminal wides, the class edge — under every
    // chunking — against `varint::carry::Carry`'s own verdicts and
    // consumption.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for width in 1..=10usize {
        let mut case = vec![0x80; width];
        case[width - 1] = 0x01;
        cases.push(case);
    }
    cases.push(vec![0x80; 11]); // TooWide
    {
        let mut wrap = vec![0x80; 9];
        wrap.push(0x02); // OutOfClass at the cap
        cases.push(wrap);
    }
    for case in cases {
        for step in 1..=case.len() {
            // The reference: the carry kernel over the same chunks.
            let mut carry = Carry::new();
            let mut carry_off = 0u64;
            let mut carry_verdict = None;
            for chunk in case.chunks(step) {
                let mut chunk = chunk;
                match spent_value(carry.step_value64(&mut chunk, &mut carry_off, u64::MAX)) {
                    CarryStep::More => {}
                    settled => {
                        carry_verdict = Some(settled);
                        break;
                    }
                }
            }
            // The ingest stepper over the same chunks, into a
            // reserved backing.
            let mut core = IngestCore {
                source: Vec::with_capacity(case.len()),
                rows: Vec::new(),
                first: None,
                last: None,
                carry: VarintCarry::new(),
                phase: Phase::Head,
                limit: DepthLimit::REFERENCE,
            };
            let mut ingest_verdict = None;
            'feed: for chunk in case.chunks(step) {
                let mut rest = chunk;
                // One construct per stepper call: `More` always
                // drains the chunk, so one step settles or resumes.
                match core.step::<ValueWidth, LAST64>(&mut rest) {
                    Step::More => {}
                    settled => {
                        ingest_verdict = Some(settled);
                        break 'feed;
                    }
                }
            }
            match (carry_verdict, ingest_verdict) {
                (Some(CarryStep::Done(value)), Some(Step::Done { value: v, width })) => {
                    assert_eq!((value, u64::from(width.as_inner())), (v, carry_off));
                }
                (Some(CarryStep::TooWide), Some(Step::TooWide))
                | (Some(CarryStep::OutOfClass), Some(Step::OutOfClass)) => {}
                (reference, mine) => panic!(
                    "kernel divergence on {case:02X?} step {step}: carry {reference:?}, \
                     ingest settled {}",
                    mine.map_or("never", |step| match step {
                        Step::Done { .. } => "Done",
                        Step::More => "More",
                        Step::TooWide => "TooWide",
                        Step::OutOfClass => "OutOfClass",
                    })
                ),
            }
            // The banked bytes are the consumed prefix, in the
            // final backing.
            assert_eq!(core.source, case[..core.source.len()]);
            assert_eq!(core.source.len() as u64, carry_off.max(core.source.len() as u64));
        }
    }
}

#[test]
fn the_abandonment_door_returns_the_accumulated_backing() {
    let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    ingest.feed(&[0x08, 0x96]).unwrap(); // a value still in flight
    assert_eq!(ingest.offset(), 2);
    assert_eq!(ingest.into_source(), [0x08, 0x96]);
}

#[test]
fn an_oversize_capacity_declaration_refuses_at_the_start_door() {
    let refused = Ingest::with_capacity(DepthLimit::REFERENCE, usize::MAX);
    assert!(matches!(refused, Err(StartFault::TooLarge { capacity: usize::MAX })));
}

#[test]
fn every_finish_door_seals_the_same_parts() {
    let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let feed = |bytes: &[u8]| {
        let mut ingest = Ingest::new(DepthLimit::REFERENCE);
        ingest.feed(bytes).unwrap();
        ingest
    };
    let mixed = feed(&msg).finish().unwrap();
    let borrowed = feed(&msg).finish_borrow().unwrap();
    let copied = feed(&msg).finish_copy().unwrap();
    assert_eq!(mixed.save().unwrap(), msg);
    assert_eq!(borrowed.save().unwrap(), msg);
    assert_eq!(copied.save().unwrap(), msg);
    assert_eq!(mixed.top().count(), 2);
    assert_eq!(borrowed.top().count(), 2);
    assert_eq!(copied.top().count(), 2);
}

/// The finished-state differential: feed against the buffered twin
/// over the concatenated bytes — public faces and the private
/// construction snapshot both.
#[cfg(feature = "adopt-groupless")]
mod twin {
    use super::*;
    use crate::adopt::groupless as buffered;

    /// The public projections, compared pairwise.
    fn assert_faces_match(mine: &Adopt<'_>, twin: &buffered::Adopt<'_>) {
        assert_eq!(mine.source(), twin.source());
        assert_eq!(mine.save_len().unwrap(), twin.save_len().unwrap());
        assert_eq!(mine.save().unwrap(), twin.save().unwrap());
        assert_eq!(mine.save_canonical().unwrap(), twin.save_canonical().unwrap());
        let my_tops: Vec<_> = mine.top().collect();
        let twin_tops: Vec<_> = twin.top().collect();
        assert_eq!(my_tops.len(), twin_tops.len());
        for (&m, &t) in my_tops.iter().zip(&twin_tops) {
            assert_eq!(mine.field(m), twin.field(t));
            assert_eq!(mine.kind(m), twin.kind(t));
            assert_eq!(mine.span(m), twin.span(t));
            assert_eq!(mine.varint_word(m), twin.varint_word(t));
            assert_eq!(mine.payload_bytes(m), twin.payload_bytes(t));
        }
        for pos in 0..u32::try_from(mine.source().len()).unwrap() {
            let m = mine.narrowest(pos).map(|h| (mine.field(h), mine.span(h)));
            let t = twin.narrowest(pos).map(|h| (twin.field(h), twin.span(h)));
            assert_eq!(m, t, "narrowest at {pos}");
        }
    }

    #[test]
    fn the_seal_builds_exactly_what_the_buffered_open_builds() {
        for (bytes, _) in stream_corpus::groupless_items() {
            for plan in stream_corpus::chunkings(&bytes) {
                let mut mine = ingest(&plan).unwrap();
                let mut twin = buffered::Adopt::open(bytes.clone(), DepthLimit::REFERENCE).unwrap();
                // The private snapshot: arena order, links, widths,
                // value words, edit state, and the top anchor — the
                // handle-numeric comparison public iteration cannot
                // give.
                assert_eq!(mine.construction_snapshot(), twin.construction_snapshot());
                assert_faces_match(&mine, &twin);
                // Descend every LEN top on both sides; the committed
                // interiors must agree again, snapshot included.
                let my_tops: Vec<_> = mine.top().collect();
                let twin_tops: Vec<_> = twin.top().collect();
                for (&m, &t) in my_tops.iter().zip(&twin_tops) {
                    if matches!(mine.kind(m), RecordKind::Len) {
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

    /// The sealed limit is machine state, and a later descent is
    /// its discriminator: a 101-level LEN nest opens one level at
    /// the minimum bound, one hundred at the reference bound, and
    /// all hundred and one at the maximum — the twin sealed from
    /// chunks must match the buffered open at every bound,
    /// snapshot included.
    #[test]
    fn the_seal_retains_its_limit_across_the_depth_range() {
        let mut bytes = vec![0x10, 0x01];
        for _ in 0..101 {
            let mut wrapped = vec![0x0A];
            crate::varint::push64(&mut wrapped, u64::try_from(bytes.len()).unwrap());
            wrapped.extend_from_slice(&bytes);
            bytes = wrapped;
        }
        for (limit, expected) in
            [(DepthLimit::MIN, 1u32), (DepthLimit::REFERENCE, 100), (DepthLimit::MAX, 101)]
        {
            let mut ingest = Ingest::new(limit);
            ingest.feed(&bytes).unwrap();
            let mut mine = ingest.finish().unwrap();
            let mut twin = buffered::Adopt::open(bytes.clone(), limit).unwrap();
            assert_eq!(mine.construction_snapshot(), twin.construction_snapshot());

            let mut opened = 0u32;
            let mut m = mine.top().next().unwrap();
            let mut t = twin.top().next().unwrap();
            loop {
                let my_step = mine.descend(m).unwrap();
                let twin_step = twin.descend(t).unwrap();
                let (my_first, twin_first) = match (my_step, twin_step) {
                    (Descent::Opened { first: a }, buffered::Descent::Opened { first: b }) => {
                        opened += 1;
                        (a, b)
                    }
                    (Descent::Refused(_), buffered::Descent::Refused(_)) => break,
                    _ => unreachable!("the twins descend in lockstep"),
                };
                let (Some(next_m), Some(next_t)) = (my_first, twin_first) else {
                    unreachable!("every opened level holds one record")
                };
                if matches!(mine.kind(next_m), RecordKind::Varint) {
                    break;
                }
                m = next_m;
                t = next_t;
            }
            assert_eq!(opened, expected, "opened levels under {limit:?}");
            assert_eq!(mine.construction_snapshot(), twin.construction_snapshot());
        }
    }
}

/// The fault differential: ingest against the scanner under
/// `OpaqueSkip`, the matched tolerant standard, and the matched
/// depth bound — first-fault class and `u64` coordinate.
#[cfg(feature = "scan-groupless")]
mod scan_parity {
    use core::ops::ControlFlow;

    use super::*;
    use crate::scan::LenDisposition;
    use crate::scan::groupless::{Parser, Sink};
    use crate::{FaultClass, Standard};

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
            // The groupless refusal alphabet is the group code.
            IngestFaultKind::Refused(_) | IngestFaultKind::CoordinateLimit { .. } => {
                FaultClass::Capability
            }
        }
    }

    fn ingest_outcome(plan: &[Vec<u8>]) -> Result<(), (u64, FaultClass)> {
        let mut job = Ingest::new(DepthLimit::REFERENCE);
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
    /// still hosts — the scanner keeps counting and only EOF
    /// truncates it.
    #[test]
    fn the_editor_cap_refuses_earlier_than_the_scanner() {
        let doc = [0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        assert_eq!(ingest_outcome(&[doc.to_vec()]), Err((6, FaultClass::Capability)));
        assert_eq!(scan_outcome(&[doc.to_vec()]), Err((6, FaultClass::Grammar)));
    }
}

#[test]
fn the_sealed_machine_descends_and_edits_as_the_buffered_shape() {
    // LEN f2 wrapping { varint f1=1 }: descend after the seal uses
    // the buffered slice scan over the now-buffered payload.
    let msg = [0x08, 0x01, 0x12, 0x02, 0x08, 0x01];
    let mut adopt = ingest(&[msg.to_vec()]).unwrap();
    let f2 = FieldNumber::new(2).unwrap();
    let container = adopt.top().by_field(f2).next().unwrap();
    let Descent::Opened { first: Some(inner) } = adopt.descend(container).unwrap() else {
        panic!("a well-formed payload opens");
    };
    adopt.set_varint(inner, 7).unwrap();
    assert_eq!(adopt.save().unwrap(), [0x08, 0x01, 0x12, 0x02, 0x08, 0x07]);
}
