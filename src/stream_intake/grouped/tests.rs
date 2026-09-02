use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::stream_corpus::{self, CutStage, ExpectedNode, cut_stage_tree};
use crate::varint::carry::{Carry, Step as CarryStep};
use crate::wire::grouped::RecordKind;

/// Feeds `chunks` and seals.
fn ingest(chunks: &[Vec<u8>]) -> Result<Intake<'static>, Failure> {
    let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    for chunk in chunks {
        ingest.feed(chunk)?;
    }
    ingest.finish()
}

/// Feeds `chunks` and expects a mid-feed failure, returning it
/// beside the bytes offered up to and including the failing chunk.
fn ingest_refusal(chunks: &[Vec<u8>]) -> (Failure, Vec<u8>) {
    let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    let mut offered = Vec::new();
    for chunk in chunks {
        offered.extend_from_slice(chunk);
        if let Err(failure) = ingest.feed(chunk) {
            return (failure, offered);
        }
    }
    panic!("the offered bytes must refuse at feed");
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

/// The first canonical refusal a corpus item owes, derived from its
/// emission-time geometry tree (`None`: every framing word and
/// value is minimal and the item seals). Words are judged in the
/// fused scan's own byte order — a group's open tag, its interior,
/// then its end tag — so the first padded word in document order
/// decides.
struct DerivedRefusal {
    refusal: Refusal,
    /// The padded word's first byte: the fault coordinate in both
    /// conventions.
    at: u32,
    /// One past the padded word's last byte: the refusal decides
    /// when this offset's byte arrives.
    word_end: u32,
}

fn scan_node(node: &ExpectedNode) -> Option<DerivedRefusal> {
    let row = &node.row;
    let head = (row.field << 3) | row.code;
    if row.tag_width > encoded_len32(head) {
        return Some(DerivedRefusal {
            refusal: Refusal::NonMinimalTag {
                at: row.start,
                width: u8::try_from(row.tag_width).unwrap(),
            },
            at: row.start,
            word_end: row.start + row.tag_width,
        });
    }
    if row.code == 3 {
        if let Some(derived) = node.kids.iter().find_map(scan_node) {
            return Some(derived);
        }
        let end_at = row.end - row.delim_width;
        let end_word = (row.field << 3) | 4;
        if row.delim_width > encoded_len32(end_word) {
            return Some(DerivedRefusal {
                refusal: Refusal::NonMinimalTag {
                    at: end_at,
                    width: u8::try_from(row.delim_width).unwrap(),
                },
                at: end_at,
                word_end: row.end,
            });
        }
        return None;
    }
    let field = FieldNumber::new(row.field).unwrap();
    let value_at = row.start + row.tag_width;
    match row.code {
        0 if row.payload_len > encoded_len64(row.value.unwrap()) => Some(DerivedRefusal {
            refusal: Refusal::NonMinimalValue {
                at: value_at,
                field,
                width: u8::try_from(row.payload_len).unwrap(),
            },
            at: value_at,
            word_end: value_at + row.payload_len,
        }),
        2 if row.delim_width > encoded_len32(row.payload_len) => Some(DerivedRefusal {
            refusal: Refusal::NonMinimalLen {
                at: value_at,
                field,
                width: u8::try_from(row.delim_width).unwrap(),
            },
            at: value_at,
            word_end: value_at + row.delim_width,
        }),
        _ => None,
    }
}

fn derived_refusal(expected: &[ExpectedNode]) -> Option<DerivedRefusal> {
    expected.iter().find_map(scan_node)
}

/// One layer of the geometry tree against the machine's faces,
/// recursing into group interiors.
fn assert_layer(intake: &Intake<'_>, bytes: &[u8], handles: &[Handle], expected: &[ExpectedNode]) {
    assert_eq!(handles.len(), expected.len());
    for (&handle, exp) in handles.iter().zip(expected) {
        assert_eq!(intake.field(handle).as_inner(), exp.row.field);
        assert_eq!(code_of(intake.kind(handle)), exp.row.code);
        let span = intake.span(handle).expect("scanned rows have source spans");
        assert_eq!((span.start(), span.end()), (exp.row.start, exp.row.end));
        match intake.kind(handle) {
            RecordKind::Varint => assert_eq!(intake.varint_word(handle), exp.row.value),
            RecordKind::Len => {
                let body = &bytes[exp.row.payload_start as usize
                    ..(exp.row.payload_start + exp.row.payload_len) as usize];
                assert_eq!(intake.payload_bytes(handle), Some(body));
            }
            RecordKind::Group => {
                let kids: Vec<Handle> = intake.children(handle).collect();
                assert_layer(intake, bytes, &kids, &exp.kids);
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
fn assert_sealed(intake: &Intake<'_>, bytes: &[u8], expected: &[ExpectedNode]) {
    assert_eq!(intake.source(), bytes);
    let tops: Vec<Handle> = intake.top().collect();
    assert_layer(intake, bytes, &tops, expected);
    for pos in 0..u32::try_from(bytes.len()).unwrap() {
        let named = intake.narrowest(pos).map(|h| {
            let span = intake.span(h).expect("narrowest answers scanned rows");
            (intake.field(h).as_inner(), span.start(), span.end())
        });
        let derived = deepest(expected, pos).map(|n| (n.row.field, n.row.start, n.row.end));
        assert_eq!(named, derived, "narrowest at {pos}");
    }
    assert_eq!(intake.save().unwrap(), bytes);
}

#[test]
fn the_boundary_corpus_seals_or_refuses_identically_under_every_chunking() {
    for (bytes, expected) in stream_corpus::grouped_items() {
        match derived_refusal(&expected) {
            None => {
                for plan in stream_corpus::chunkings(&bytes) {
                    let intake = ingest(&plan).unwrap_or_else(|failure| {
                        panic!("plan of {} chunks refused: {failure}", plan.len())
                    });
                    assert_sealed(&intake, &bytes, &expected);
                }
            }
            // A padded item refuses the moment the offending word's
            // last byte arrives, under every chunking, with exact
            // whole-chunk custody.
            Some(derived) => {
                for plan in stream_corpus::chunkings(&bytes) {
                    let (failure, offered) = ingest_refusal(&plan);
                    assert_eq!(failure.chunk(), ChunkDisposition::Absorbed);
                    assert_eq!(failure.source(), offered);
                    assert_eq!(failure.fault().at(), u64::from(derived.at));
                    assert_eq!(failure.fault().kind(), IngestFaultKind::Refused(derived.refusal));
                }
            }
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
        // Cuts at or past a padded word's completion refuse at feed
        // (the boundary judge above); truncation semantics live
        // strictly before the deciding byte.
        let cut_top = derived_refusal(&expected)
            .map_or(bytes.len(), |derived| usize::try_from(derived.word_end).unwrap() - 1);
        for cut in 0..=cut_top {
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
    /// The offset of the byte whose arrival decides the fault.
    deciding: usize,
    at: u64,
    kind: IngestFaultKind,
}

fn fault_docs() -> Vec<FaultDoc> {
    let field1 = FieldNumber::new(1).unwrap();
    let field2 = FieldNumber::new(2).unwrap();
    vec![
        // An end tag with no open frame.
        FaultDoc {
            bytes: vec![0x0C],
            deciding: 0,
            at: 0,
            kind: IngestFaultKind::Wire(Fault {
                at: 0,
                kind: FaultKind::GroupEndOrphan { found: field1 },
            }),
        },
        // An end tag closing the wrong field.
        FaultDoc {
            bytes: vec![0x0B, 0x14],
            deciding: 1,
            at: 1,
            kind: IngestFaultKind::Wire(Fault {
                at: 1,
                kind: FaultKind::GroupEndMismatch { open: field1, found: field2 },
            }),
        },
        // An orphan end tag after a whole closed frame.
        FaultDoc {
            bytes: vec![0x0B, 0x0C, 0x14],
            deciding: 2,
            at: 2,
            kind: IngestFaultKind::Wire(Fault {
                at: 2,
                kind: FaultKind::GroupEndOrphan { found: field2 },
            }),
        },
        // Field zero and unassigned codes inside an open frame.
        FaultDoc {
            bytes: vec![0x0B, 0x00],
            deciding: 1,
            at: 1,
            kind: IngestFaultKind::Wire(Fault { at: 1, kind: FaultKind::FieldZero }),
        },
        FaultDoc {
            bytes: vec![0x0B, 0x0E],
            deciding: 1,
            at: 1,
            kind: IngestFaultKind::Wire(Fault {
                at: 1,
                kind: FaultKind::Unassigned { field: field1, low3: Low3::from_word(0x0E) },
            }),
        },
        // A padded group open tag: the canonical refusal at the
        // frame's first byte.
        FaultDoc {
            bytes: vec![0x8B, 0x00],
            deciding: 1,
            at: 0,
            kind: IngestFaultKind::Refused(Refusal::NonMinimalTag { at: 0, width: 2 }),
        },
        // A padded group end tag: an end tag is a tag word and
        // takes the same judgment, at its own offset.
        FaultDoc {
            bytes: vec![0x0B, 0x8C, 0x00],
            deciding: 2,
            at: 1,
            kind: IngestFaultKind::Refused(Refusal::NonMinimalTag { at: 1, width: 2 }),
        },
        // A padded end tag that would also mismatch the open frame:
        // the canonical judgment precedes the frame verification,
        // as in the buffered root scan.
        FaultDoc {
            bytes: vec![0x0B, 0x94, 0x00],
            deciding: 2,
            at: 1,
            kind: IngestFaultKind::Refused(Refusal::NonMinimalTag { at: 1, width: 2 }),
        },
        // A padded value inside an open frame.
        FaultDoc {
            bytes: vec![0x0B, 0x08, 0x81, 0x00],
            deciding: 3,
            at: 2,
            kind: IngestFaultKind::Refused(Refusal::NonMinimalValue {
                at: 2,
                field: field1,
                width: 2,
            }),
        },
        // A padded length prefix inside an open frame.
        FaultDoc {
            bytes: vec![0x0B, 0x12, 0x82, 0x00],
            deciding: 3,
            at: 2,
            kind: IngestFaultKind::Refused(Refusal::NonMinimalLen {
                at: 2,
                field: field2,
                width: 2,
            }),
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
            assert_eq!(failure.chunk(), ChunkDisposition::Absorbed);
            assert_eq!(failure.source(), offered, "split {split}");
            assert_eq!(failure.fault().at(), doc.at);
            assert_eq!(failure.fault().kind(), doc.kind);
        }
    }
}

#[test]
fn a_group_past_the_declared_bound_refuses_at_its_open_tag() {
    // Under the tightest bound, the root group opens and its nested
    // twin refuses — across every split of the two open tags.
    let bytes = [0x0B, 0x0B];
    for split in 0..=bytes.len() {
        let mut ingest = Ingest::new(DepthLimit::MIN);
        let outcome = ingest.feed(&bytes[..split]).and_then(|()| ingest.feed(&bytes[split..]));
        let failure = outcome.expect_err("the nested open leaves the bound");
        assert_eq!(failure.fault().at(), 1);
        assert_eq!(
            failure.fault().kind(),
            IngestFaultKind::Refused(Refusal::DepthExceeded {
                at: 1,
                field: FieldNumber::new(1).unwrap(),
            })
        );
    }
}

#[test]
#[should_panic(expected = "ingest already terminal")]
fn a_spent_shell_refuses_another_feed() {
    let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    let _failure = ingest.feed(&[0x0C]).unwrap_err();
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
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for width in 1..=10usize {
        let mut case = vec![0x80; width];
        case[width - 1] = 0x01;
        cases.push(case);
    }
    cases.push(vec![0x80; 11]);
    {
        let mut wrap = vec![0x80; 9];
        wrap.push(0x02);
        cases.push(wrap);
    }
    for case in cases {
        for step in 1..=case.len() {
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
            let mut core = IngestCore {
                source: Vec::with_capacity(case.len()),
                rows: Vec::new(),
                first: None,
                last: None,
                open: None,
                open_depth: 0,
                carry: VarintCarry::new(),
                phase: Phase::Head,
                limit: DepthLimit::REFERENCE,
            };
            let mut ingest_verdict = None;
            'feed: for chunk in case.chunks(step) {
                let mut rest = chunk;
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
            assert_eq!(core.source, case[..core.source.len()]);
        }
    }
}

/// The finished-state differential: feed against the buffered twin
/// over the concatenated bytes — public faces (group interiors
/// recursively) and the private construction snapshot on the sealed
/// side, refusal kind and coordinates on the refused side.
#[cfg(feature = "intake-grouped")]
mod twin {
    use super::*;
    use crate::intake::grouped as buffered;

    /// The buffered twin's refusal in this module's nominal type,
    /// variant for variant.
    fn as_local(refusal: buffered::Refusal) -> Refusal {
        match refusal {
            buffered::Refusal::NonMinimalTag { at, width } => Refusal::NonMinimalTag { at, width },
            buffered::Refusal::NonMinimalLen { at, field, width } => {
                Refusal::NonMinimalLen { at, field, width }
            }
            buffered::Refusal::NonMinimalValue { at, field, width } => {
                Refusal::NonMinimalValue { at, field, width }
            }
            buffered::Refusal::DepthExceeded { at, field } => Refusal::DepthExceeded { at, field },
        }
    }

    /// One layer's public projections, recursing into groups.
    fn assert_layer_match(
        mine: &Intake<'_>,
        twin: &buffered::Intake<'_>,
        my_handles: &[Handle],
        twin_handles: &[crate::intake::Handle],
    ) {
        assert_eq!(my_handles.len(), twin_handles.len());
        for (&m, &t) in my_handles.iter().zip(twin_handles) {
            assert_eq!(mine.field(m), twin.field(t));
            assert_eq!(mine.kind(m), twin.kind(t));
            assert_eq!(mine.span(m), twin.span(t));
            assert_eq!(mine.varint_word(m), twin.varint_word(t));
            assert_eq!(mine.payload_bytes(m), twin.payload_bytes(t));
            if matches!(mine.kind(m), RecordKind::Group) {
                let my_kids: Vec<_> = mine.children(m).collect();
                let twin_kids: Vec<_> = twin.children(t).collect();
                assert_layer_match(mine, twin, &my_kids, &twin_kids);
            }
        }
    }

    /// The public projections, compared pairwise.
    fn assert_faces_match(mine: &Intake<'_>, twin: &buffered::Intake<'_>) {
        assert_eq!(mine.source(), twin.source());
        assert_eq!(mine.save_len().unwrap(), twin.save_len().unwrap());
        assert_eq!(mine.save().unwrap(), twin.save().unwrap());
        let my_tops: Vec<_> = mine.top().collect();
        let twin_tops: Vec<_> = twin.top().collect();
        assert_layer_match(mine, twin, &my_tops, &twin_tops);
        for pos in 0..u32::try_from(mine.source().len()).unwrap() {
            let m = mine.narrowest(pos).map(|h| (mine.field(h), mine.span(h)));
            let t = twin.narrowest(pos).map(|h| (twin.field(h), twin.span(h)));
            assert_eq!(m, t, "narrowest at {pos}");
        }
    }

    #[test]
    fn the_seal_builds_exactly_what_the_buffered_open_builds() {
        for (bytes, expected) in stream_corpus::grouped_items() {
            if derived_refusal(&expected).is_some() {
                continue; // the refusal-parity judge below
            }
            for plan in stream_corpus::chunkings(&bytes) {
                let mut mine = ingest(&plan).unwrap();
                let mut twin =
                    buffered::Intake::open(bytes.clone(), DepthLimit::REFERENCE).unwrap();
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

    /// Canonical refusal parity: every padded corpus item faults
    /// with the buffered intake's refusal — same variant, same
    /// construct coordinates, frame tags included — and the stream
    /// cell answers it at every split inside the offending word.
    #[test]
    fn every_padded_item_refuses_as_the_buffered_intake_at_the_padded_word() {
        // The judge must have seen all three padded families, or
        // the corpus stopped carrying them (frame tags land in the
        // tag family, open and end alike).
        let mut met = [false; 3];
        for (bytes, expected) in stream_corpus::grouped_items() {
            let Some(derived) = derived_refusal(&expected) else { continue };
            met[match derived.refusal {
                Refusal::NonMinimalTag { .. } => 0,
                Refusal::NonMinimalValue { .. } => 1,
                Refusal::NonMinimalLen { .. } => 2,
                Refusal::DepthExceeded { .. } => {
                    unreachable!("the derivation names padding only")
                }
            }] = true;
            // The buffered twin refuses the concatenated bytes with
            // the same judgment, buffer intact.
            let Err((back, fault)) = buffered::Intake::open(bytes.clone(), DepthLimit::REFERENCE)
            else {
                panic!("the buffered twin refuses padded framing");
            };
            assert_eq!(back, bytes);
            let buffered::OpenFault::Refused(refusal) = fault else {
                panic!("padding is a refusal, got {fault:?}");
            };
            assert_eq!(as_local(refusal), derived.refusal);
            // The stream cell under every split inside the padded
            // word: the carry crosses the chunk edge and the
            // judgment still lands on the word's last byte.
            for split in usize_of(derived.at)..usize_of(derived.word_end) {
                let plan = vec![bytes[..split].to_vec(), bytes[split..].to_vec()];
                let (failure, offered) = ingest_refusal(&plan);
                assert_eq!(failure.fault().kind(), IngestFaultKind::Refused(derived.refusal));
                assert_eq!(failure.fault().at(), u64::from(derived.at));
                assert_eq!(failure.chunk(), ChunkDisposition::Absorbed);
                assert_eq!(failure.source(), offered, "split {split}");
            }
        }
        assert_eq!(met, [true; 3], "tag/value/len padding rows all present");
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
            let mut twin = buffered::Intake::open(bytes.clone(), limit).unwrap();
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
/// `OpaqueSkip`, the matched canonical-minimal standard, and the
/// matched depth bound — first-fault class and `u64` coordinate.
/// Group syntax is in-band for both machines, so frame faults,
/// depth refusals, and the `NonMinimal*` refusals are parity rows
/// here, not exceptions.
#[cfg(feature = "scan-grouped")]
mod scan_parity {
    use core::ops::ControlFlow;

    use super::*;
    use crate::scan::LenDisposition;
    use crate::scan::grouped::{Parser, Sink};
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

    fn scan_outcome(plan: &[Vec<u8>], limit: DepthLimit) -> Result<(), (u64, FaultClass)> {
        let mut parser = Parser::new(Standard::CanonicalMinimal, limit);
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
            // The grouped refusal alphabet is policy whole: padding
            // and the depth bound both admit another configuration.
            IngestFaultKind::Refused(_) => FaultClass::Policy,
            IngestFaultKind::CoordinateLimit { .. } => FaultClass::Capability,
        }
    }

    fn ingest_outcome(plan: &[Vec<u8>], limit: DepthLimit) -> Result<(), (u64, FaultClass)> {
        let mut job = Ingest::new(limit);
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
                    assert_eq!(
                        ingest_outcome(&plan, DepthLimit::REFERENCE),
                        scan_outcome(&plan, DepthLimit::REFERENCE),
                        "cut {cut}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_fault_document_matches_the_scanner_verdict() {
        for doc in fault_docs() {
            for split in 0..=doc.deciding {
                let plan = vec![doc.bytes[..split].to_vec(), doc.bytes[split..].to_vec()];
                assert_eq!(
                    ingest_outcome(&plan, DepthLimit::REFERENCE),
                    scan_outcome(&plan, DepthLimit::REFERENCE)
                );
            }
        }
    }

    /// The matched-bound depth refusal is a parity row: both
    /// machines refuse the nested open tag as policy, at the same
    /// coordinate.
    #[test]
    fn the_matched_depth_bound_refuses_in_both_machines() {
        let doc = vec![vec![0x0B, 0x0B]];
        assert_eq!(ingest_outcome(&doc, DepthLimit::MIN), scan_outcome(&doc, DepthLimit::MIN));
        assert_eq!(ingest_outcome(&doc, DepthLimit::MIN), Err((1, FaultClass::Policy)));
    }

    /// The named exception row: the editor's `i32::MAX` source cap
    /// refuses a declared LEN endpoint the scanner's `u64` space
    /// still hosts.
    #[test]
    fn the_editor_cap_refuses_earlier_than_the_scanner() {
        let doc = [0x12, 0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        assert_eq!(
            ingest_outcome(&[doc.to_vec()], DepthLimit::REFERENCE),
            Err((6, FaultClass::Capability))
        );
        assert_eq!(
            scan_outcome(&[doc.to_vec()], DepthLimit::REFERENCE),
            Err((6, FaultClass::Grammar))
        );
    }
}

#[test]
fn the_sealed_machine_edits_group_interiors_as_the_buffered_shape() {
    // group f2 { varint f3=9 } after a scalar: interior edits land
    // through the sealed frame, and the grouped command set
    // (insert_group) works on the sealed machine.
    let msg = [0x08, 0x96, 0x01, 0x13, 0x18, 0x09, 0x14];
    let mut intake = ingest(&[msg.to_vec()]).unwrap();
    let tops: Vec<Handle> = intake.top().collect();
    let inner = intake.children(tops[1]).next().unwrap();
    intake.set_varint(inner, 7).unwrap();
    let f4 = FieldNumber::new(4).unwrap();
    intake.insert_group(InsertAt::TailOf(None), f4).unwrap();
    assert_eq!(intake.save().unwrap(), [0x08, 0x96, 0x01, 0x13, 0x18, 0x07, 0x14, 0x23, 0x24]);
}
