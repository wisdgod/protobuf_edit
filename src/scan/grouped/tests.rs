//! Contract pins: each test states one clause of the machine's
//! contract. The load-bearing property is chunking invariance —
//! every transcript and every verdict is asserted identical across
//! chunk sizes, including fault coordinates.

use alloc::vec::Vec;
use core::num::NonZeroU32;
use core::ops::ControlFlow;

use super::*;
use crate::DepthLimit;

#[track_caller]
fn h(s: &str) -> Vec<u8> {
    let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "odd hex literal");
    hex.chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap();
            let lo = (pair[1] as char).to_digit(16).unwrap();
            (hi * 16 + lo) as u8
        })
        .collect()
}

fn nz(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("nonzero test literal")
}

const D: DepthLimit = DepthLimit::REFERENCE;

/// The transcript vocabulary. Fields are raw u32 for literal
/// assertions; consecutive segments merge on push, because fragment
/// boundaries follow chunk boundaries — the chunking-invariant
/// statement is the *concatenation*.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Ev {
    Len(u32, u32, u64),
    LenExit(u32, u64),
    GroupEnter(u32, u64),
    GroupExit(u32, u64),
    Varint(u32, u64),
    I32(u32, u32),
    I64(u32, u64),
    Segment(Vec<u8>),
}

/// A recording sink: dispositions by field list, optional stop
/// after the nth event.
struct Rec {
    events: Vec<Ev>,
    descend: &'static [u32],
    bytes: &'static [u32],
    stop_after: Option<usize>,
}

impl Rec {
    fn new(descend: &'static [u32], bytes: &'static [u32]) -> Self {
        Self { events: Vec::new(), descend, bytes, stop_after: None }
    }

    fn push(&mut self, ev: Ev) -> ControlFlow<()> {
        if let (Ev::Segment(tail), Some(Ev::Segment(head))) = (&ev, self.events.last_mut()) {
            head.extend_from_slice(tail);
        } else {
            self.events.push(ev);
        }
        match self.stop_after {
            Some(n) if self.events.len() >= n => ControlFlow::Break(()),
            _ => ControlFlow::Continue(()),
        }
    }
}

impl Sink for Rec {
    fn on_len(
        &mut self,
        field: FieldNumber,
        len: PayloadLen,
        at: u64,
    ) -> ControlFlow<(), LenDisposition> {
        let f = field.as_inner();
        if self.push(Ev::Len(f, len.as_inner(), at)).is_break() {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(if self.descend.contains(&f) {
            LenDisposition::Commit
        } else if self.bytes.contains(&f) {
            LenDisposition::OpaqueBytes
        } else {
            LenDisposition::OpaqueSkip
        })
    }

    fn on_len_exit(&mut self, field: FieldNumber, at: u64) -> ControlFlow<()> {
        self.push(Ev::LenExit(field.as_inner(), at))
    }

    fn on_group_enter(&mut self, field: FieldNumber, at: u64) -> ControlFlow<()> {
        self.push(Ev::GroupEnter(field.as_inner(), at))
    }

    fn on_group_exit(&mut self, field: FieldNumber, at: u64) -> ControlFlow<()> {
        self.push(Ev::GroupExit(field.as_inner(), at))
    }

    fn on_varint(&mut self, field: FieldNumber, value: u64) -> ControlFlow<()> {
        self.push(Ev::Varint(field.as_inner(), value))
    }

    fn on_i32(&mut self, field: FieldNumber, bits: u32) -> ControlFlow<()> {
        self.push(Ev::I32(field.as_inner(), bits))
    }

    fn on_i64(&mut self, field: FieldNumber, bits: u64) -> ControlFlow<()> {
        self.push(Ev::I64(field.as_inner(), bits))
    }

    fn on_segment(&mut self, bytes: &[u8]) -> ControlFlow<()> {
        self.push(Ev::Segment(bytes.to_vec()))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum End {
    Clean,
    Stopped,
}

#[track_caller]
fn run(data: &[u8], step: usize, rec: &mut Rec, standard: Standard) -> Result<End, Fault> {
    let mut parser = Parser::new(standard, D);
    for chunk in data.chunks(step.max(1)) {
        match parser.feed(chunk, rec)? {
            Flow::More => {}
            Flow::Stopped => return Ok(End::Stopped),
        }
    }
    parser.finish().map(|()| End::Clean)
}

/// Runs every chunking and asserts the transcript and the verdict
/// never move; returns the (chunking-free) observation.
#[track_caller]
fn invariant(
    data: &[u8],
    descend: &'static [u32],
    bytes: &'static [u32],
    standard: Standard,
) -> (Result<End, Fault>, Vec<Ev>) {
    let mut base: Option<(Result<End, Fault>, Vec<Ev>)> = None;
    for step in [1, 2, 3, 5, 7, data.len().max(1)] {
        let mut rec = Rec::new(descend, bytes);
        let out = run(data, step, &mut rec, standard);
        let cur = (out, rec.events);
        match &base {
            None => base = Some(cur),
            Some(b) => assert_eq!(*b, cur, "chunk step {step} moved the observation"),
        }
    }
    base.expect("at least one step ran")
}

#[track_caller]
fn fault_of(data: &[u8], standard: Standard) -> Fault {
    let (out, _) = invariant(data, &[2, 4, 6], &[3], standard);
    out.expect_err("expected a fault")
}

// ─── the composite walk (transcript + chunking invariance) ───

#[test]
fn transcript_is_chunking_invariant_across_the_language() {
    // f1 varint 150 · f2 i64 · f3 len=5 "hello" (bytes) ·
    // f4 len=4 descend { f5 varint 1 · f6 len=0 descend } ·
    // f7 len=0 skip · group f7 { f1 varint 1 } · f8 i32.
    let data = h("08 9601
                  11 0807060504030201
                  1A 05 68656C6C6F
                  22 04 2801 3200
                  3A 00
                  3B 0801 3C
                  45 AABBCCDD");
    let (end, events) = invariant(&data, &[4, 6], &[3], Standard::CanonicalMinimal);
    assert_eq!(end, Ok(End::Clean));
    assert_eq!(
        events,
        [
            Ev::Varint(1, 150),
            Ev::I64(2, 0x0102_0304_0506_0708),
            Ev::Len(3, 5, 14),
            Ev::Segment(b"hello".to_vec()),
            Ev::Len(4, 4, 21),
            Ev::Varint(5, 1),
            Ev::Len(6, 0, 25),
            Ev::LenExit(6, 25),
            Ev::LenExit(4, 25),
            Ev::Len(7, 0, 27),
            Ev::GroupEnter(7, 28),
            Ev::Varint(1, 1),
            Ev::GroupExit(7, 30),
            Ev::I32(8, 0xDDCC_BBAA),
        ]
    );
}

#[test]
fn a_zero_length_payload_at_a_chunk_boundary_is_not_truncation() {
    // Regression pin: a counting mode must never owe zero — the
    // chunk ending exactly after the length word once left a
    // zero-owing counting mode for finish to misjudge.
    for bytes in [&[3][..], &[][..]] {
        let data = h("0A 00");
        let mut rec = Rec::new(&[], bytes);
        let mut parser = Parser::new(Standard::CanonicalMinimal, D);
        assert_eq!(parser.feed(&data, &mut rec), Ok(Flow::More));
        assert_eq!(parser.finish(), Ok(()));
        assert_eq!(rec.events, [Ev::Len(1, 0, 2)], "no fragment for an empty payload");
    }
}

// ─── fault verdicts (each pinned, all chunking-invariant) ───

#[test]
fn window_and_class_faults_name_the_constructs_first_byte() {
    let s = Standard::Tolerant;
    assert_eq!(
        fault_of(&h("80 80 80 80 80"), s),
        Fault { at: 0, kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::TooWide } }
    );
    assert_eq!(
        fault_of(&h("FF FF FF FF 1F"), s),
        Fault { at: 0, kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::OutOfClass } }
    );
    let f = |n: u32| FieldNumber::new(n).unwrap();
    assert_eq!(
        fault_of(&h("0A 80 80 80 80 80"), s),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(1) },
                cause: ReadFault::TooWide
            }
        }
    );
    assert_eq!(
        fault_of(&h("0A FF FF FF FF 08"), s),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(1) },
                cause: ReadFault::OutOfClass
            }
        }
    );
    assert_eq!(
        fault_of(&h("08 80 80 80 80 80 80 80 80 80 80"), s),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::TooWide
            }
        }
    );
    assert_eq!(
        fault_of(&h("08 FF FF FF FF FF FF FF FF FF 02"), s),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::OutOfClass
            }
        }
    );
}

#[test]
fn tag_structure_faults_pin_field_zero_and_unassigned_codes() {
    let s = Standard::Tolerant;
    assert_eq!(fault_of(&h("00"), s), Fault { at: 0, kind: FaultKind::FieldZero });
    let f = |n: u32| FieldNumber::new(n).unwrap();
    let code6 = Low3::new(6).unwrap();
    let code7 = Low3::new(7).unwrap();
    assert_eq!(
        fault_of(&h("0E"), s),
        Fault { at: 0, kind: FaultKind::Unassigned { field: f(1), code: code6 } }
    );
    assert_eq!(
        fault_of(&h("0F"), s),
        Fault { at: 0, kind: FaultKind::Unassigned { field: f(1), code: code7 } }
    );
}

#[test]
fn group_pairing_faults_quote_both_sides() {
    let s = Standard::Tolerant;
    let f = |n: u32| FieldNumber::new(n).unwrap();
    assert_eq!(
        fault_of(&h("0C"), s),
        Fault { at: 0, kind: FaultKind::GroupEndOrphan { end: f(1) } }
    );
    assert_eq!(
        fault_of(&h("0B 14"), s),
        Fault { at: 1, kind: FaultKind::GroupEndMismatch { end: f(2), open: f(1) } }
    );
    // f2 is in the harness descend set: group f1 opens, LEN f2
    // descends, and f1's end tag inside the LEN pierces the seal.
    assert_eq!(
        fault_of(&h("0B 12 01 0C"), s),
        Fault { at: 3, kind: FaultKind::GroupEndAcrossLen { end: f(1), open_len: f(2) } }
    );
    // The dual: the descended LEN f2 ends while group f1 inside it
    // is open.
    assert_eq!(
        fault_of(&h("12 01 0B"), s),
        Fault { at: 3, kind: FaultKind::GroupUnclosedAtLenEnd { group: f(1) } }
    );
}

#[test]
fn seals_cut_constructs_and_reject_overruns() {
    let s = Standard::Tolerant;
    let f = |n: u32| FieldNumber::new(n).unwrap();
    assert_eq!(
        fault_of(&h("12 01 80"), s),
        Fault { at: 3, kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SealCut } }
    );
    assert_eq!(
        fault_of(&h("12 02 1A 80"), s),
        Fault {
            at: 4,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(3) },
                cause: ReadFault::SealCut
            }
        }
    );
    assert_eq!(
        fault_of(&h("12 02 08 80"), s),
        Fault {
            at: 4,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::SealCut
            }
        }
    );
    assert_eq!(
        fault_of(&h("12 02 0D 00"), s),
        Fault { at: 3, kind: FaultKind::FixedOverrun { field: f(1) } }
    );
    assert_eq!(
        fault_of(&h("12 02 1A 7F"), s),
        Fault {
            at: 4,
            kind: FaultKind::LenOverrun { field: f(3), len: PayloadLen::new(127).unwrap() }
        }
    );
}

#[test]
fn a_word_suspended_across_the_seal_is_the_seal_cut() {
    let s = Standard::Tolerant;
    let f = |n: u32| FieldNumber::new(n).unwrap();
    // The tag closes at the seal, the value word lies outside:
    // the seal truncates the record. The endpoint must not pop
    // under the suspended word; no value splices from the parent
    // zone.
    assert_eq!(
        fault_of(&h("12 01 08 2A"), s),
        Fault {
            at: 3,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::SealCut
            }
        }
    );
    // The same suspension at a nested LEN record's length word.
    assert_eq!(
        fault_of(&h("12 01 1A 01"), s),
        Fault {
            at: 3,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(3) },
                cause: ReadFault::SealCut
            }
        }
    );
    // Stream end at the seal changes nothing: the record cannot
    // complete inside the seal, and the head decides the moment
    // the tag closes.
    assert_eq!(
        fault_of(&h("12 01 08"), s),
        Fault {
            at: 3,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::SealCut
            }
        }
    );
}

#[test]
fn the_depth_bound_refuses_the_deepest_open() {
    let one = DepthLimit::MIN;
    let f = |n: u32| FieldNumber::new(n).unwrap();
    // Group past the bound.
    let mut parser = Parser::new(Standard::Tolerant, one);
    let fault = parser.feed(&h("0B 13"), &mut ()).unwrap_err();
    assert_eq!(fault, Fault { at: 1, kind: FaultKind::DepthExceeded { field: f(2) } });
    // Descended LEN past the bound (the descend answer is the
    // opening move, so the refusal names the payload start).
    let mut rec = Rec::new(&[2, 4], &[]);
    let mut parser = Parser::new(Standard::Tolerant, one);
    let fault = parser.feed(&h("12 04 22 02 0801"), &mut rec).unwrap_err();
    assert_eq!(fault, Fault { at: 4, kind: FaultKind::DepthExceeded { field: f(4) } });
}

#[test]
fn the_reference_depth_walks_a_hundred_and_refuses_the_next() {
    let mut deep = alloc::vec![0x0B_u8; 100];
    deep.extend_from_slice(&alloc::vec![0x0C_u8; 100]);
    let (end, _) = invariant(&deep, &[], &[], Standard::Tolerant);
    assert_eq!(end, Ok(End::Clean));

    let over = alloc::vec![0x0B_u8; 101];
    let (end, _) = invariant(&over, &[], &[], Standard::Tolerant);
    let f = |n: u32| FieldNumber::new(n).unwrap();
    assert_eq!(end, Err(Fault { at: 100, kind: FaultKind::DepthExceeded { field: f(1) } }));
}

// ─── the declared standard ───

#[test]
fn minimality_is_judged_by_the_declared_standard() {
    // Padded tag (field 1 varint in two bytes), then value 1.
    let padded_tag = h("88 00 01");
    let (end, events) = invariant(&padded_tag, &[], &[], Standard::Tolerant);
    assert_eq!((end, events), (Ok(End::Clean), alloc::vec![Ev::Varint(1, 1)]));
    assert_eq!(
        fault_of(&padded_tag, Standard::CanonicalMinimal),
        Fault { at: 0, kind: FaultKind::NonMinimalTag }
    );

    // Padded length word (2 in three bytes).
    let f = |n: u32| FieldNumber::new(n).unwrap();
    let padded_len = h("0A 82 80 00 61 62");
    let (end, _) = invariant(&padded_len, &[], &[], Standard::Tolerant);
    assert_eq!(end, Ok(End::Clean));
    assert_eq!(
        fault_of(&padded_len, Standard::CanonicalMinimal),
        Fault { at: 1, kind: FaultKind::NonMinimalLen { field: f(1) } }
    );

    // Padded value (1 in two bytes).
    let padded_value = h("08 81 00");
    let (end, events) = invariant(&padded_value, &[], &[], Standard::Tolerant);
    assert_eq!((end, events), (Ok(End::Clean), alloc::vec![Ev::Varint(1, 1)]));
    assert_eq!(
        fault_of(&padded_value, Standard::CanonicalMinimal),
        Fault { at: 1, kind: FaultKind::NonMinimalValue { field: f(1) } }
    );
}

// ─── EOF verdicts ───

#[test]
fn eof_inside_a_construct_names_what_was_cut() {
    let s = Standard::Tolerant;
    let f = |n: u32| FieldNumber::new(n).unwrap();
    assert_eq!(
        fault_of(&h("80"), s),
        Fault { at: 1, kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::StreamEnd } }
    );
    assert_eq!(
        fault_of(&h("0A"), s),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(1) },
                cause: ReadFault::StreamEnd
            }
        }
    );
    assert_eq!(
        fault_of(&h("0A 80"), s),
        Fault {
            at: 2,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(1) },
                cause: ReadFault::StreamEnd
            }
        }
    );
    assert_eq!(
        fault_of(&h("08"), s),
        Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::StreamEnd
            }
        }
    );
    assert_eq!(
        fault_of(&h("0D 00 00"), s),
        Fault { at: 3, kind: FaultKind::FixedTruncated { field: f(1) } }
    );
    assert_eq!(
        fault_of(&h("0A 05 61 61"), s),
        Fault { at: 4, kind: FaultKind::PayloadTruncated { remaining: nz(3) } }
    );
    // f2 is in the harness descend set.
    assert_eq!(
        fault_of(&h("12 02"), s),
        Fault { at: 2, kind: FaultKind::UnclosedLen { field: f(2) } }
    );
    assert_eq!(
        fault_of(&h("0B"), s),
        Fault { at: 1, kind: FaultKind::GroupUnclosed { field: f(1) } }
    );
}

#[test]
fn deep_resumption_paths_pin_the_faults_field() {
    let s = Standard::Tolerant;
    let f = |n: u32| FieldNumber::new(n).unwrap();
    // A value cut at EOF inside an open group: the record's own
    // field (5), not the enclosing group's (2), rides on the fault.
    assert_eq!(
        fault_of(&h("13 28 80"), s),
        Fault {
            at: 3,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(5) },
                cause: ReadFault::StreamEnd
            }
        }
    );
}

// ─── the sink's authority ───

#[test]
fn bytes_commitment_delivers_the_exact_payload() {
    let mut data = h("1A 0B");
    data.extend_from_slice(b"hello world");
    let (end, events) = invariant(&data, &[], &[3], Standard::CanonicalMinimal);
    assert_eq!(end, Ok(End::Clean));
    assert_eq!(events, [Ev::Len(3, 11, 2), Ev::Segment(b"hello world".to_vec())]);
}

#[test]
fn skips_emit_nothing_and_offset_reads_progress() {
    let mut data = h("1A 0B");
    data.extend_from_slice(b"hello world");
    let mut rec = Rec::new(&[], &[]);
    let mut parser = Parser::new(Standard::CanonicalMinimal, D);
    assert_eq!(parser.feed(&data, &mut rec), Ok(Flow::More));
    assert_eq!(parser.offset(), 13);
    assert_eq!(parser.finish(), Ok(()));
    assert_eq!(rec.events, [Ev::Len(3, 11, 2)]);
}

#[test]
fn an_early_stop_ends_the_stream() {
    let data = h("08 01 08 02 08 03");
    let mut rec = Rec::new(&[], &[]);
    rec.stop_after = Some(2);
    let mut parser = Parser::new(Standard::CanonicalMinimal, D);
    assert_eq!(parser.feed(&data, &mut rec), Ok(Flow::Stopped));
    assert_eq!(rec.events, [Ev::Varint(1, 1), Ev::Varint(1, 2)]);
}

#[test]
#[should_panic(expected = "stream already terminal")]
fn feeding_after_a_stop_is_a_named_caller_bug() {
    let mut rec = Rec::new(&[], &[]);
    rec.stop_after = Some(1);
    let mut parser = Parser::new(Standard::CanonicalMinimal, D);
    let _ = parser.feed(&h("08 01"), &mut rec);
    let _ = parser.feed(&h("08 02"), &mut rec);
}

#[test]
#[should_panic(expected = "stream already terminal")]
fn feeding_after_a_fault_is_a_named_caller_bug() {
    let mut parser = Parser::new(Standard::CanonicalMinimal, D);
    let _ = parser.feed(&h("00"), &mut ());
    let _ = parser.feed(&h("08 01"), &mut ());
}

#[test]
fn the_feed_gate_refuses_a_chunk_past_the_coordinate_space() {
    // The cursor is injected two bytes short of the space's top
    // (`u64::MAX − 1` admissible bytes): a one-byte chunk still
    // admits and consumes...
    let mut parser = Parser::new(Standard::Tolerant, D);
    parser.pump.off = u64::MAX - 2;
    assert_eq!(parser.feed(&h("08"), &mut ()).unwrap(), Flow::More);
    assert_eq!(parser.offset(), u64::MAX - 1);

    // ...and one byte more would need the unaddressable sentinel
    // coordinate: refused whole at admission, nothing consumed,
    // terminal.
    let fault = parser.feed(&h("00"), &mut ()).unwrap_err();
    assert_eq!(fault, Fault { at: u64::MAX - 1, kind: FaultKind::OffsetExhausted });
    assert_eq!(fault.kind().class(), crate::FaultClass::Capability);
}

#[test]
fn a_len_declared_out_to_the_coordinate_ceiling_is_refused() {
    // The space holds `u64::MAX − 1` bytes, so a payload whose end
    // lands on the sentinel coordinate can never be satisfied: the
    // declaration is refused where it is read, not left to starve.
    // Head and prefix consume two bytes (cursor → MAX−2), and the
    // declared end is (MAX−2)+2 = MAX.
    let f = |n: u32| FieldNumber::new(n).unwrap();
    let mut parser = Parser::new(Standard::Tolerant, D);
    parser.pump.off = u64::MAX - 4;
    let fault = parser.feed(&h("0A 02"), &mut ()).unwrap_err();
    assert_eq!(
        fault,
        Fault {
            at: u64::MAX - 2,
            kind: FaultKind::LenUnsatisfiable { field: f(1), len: PayloadLen::new(2).unwrap() }
        }
    );
    // Position-dependent, so capability — the same bytes are lawful
    // at a lower cursor (the control below), unlike a seal pierce.
    assert_eq!(fault.kind().class(), crate::FaultClass::Capability);

    // One byte lower, the same declaration ends at MAX−1 and is
    // admitted (the machine then waits on the payload).
    let mut parser = Parser::new(Standard::Tolerant, D);
    parser.pump.off = u64::MAX - 5;
    assert_eq!(parser.feed(&h("0A 02"), &mut ()).unwrap(), Flow::More);
}

// ─── the validator face ───

#[test]
fn the_validator_is_the_parsers_verdict() {
    let mut ok = Validator::new(Standard::CanonicalMinimal, D);
    assert_eq!(ok.feed(&h("08 96 01 3B 3C")), Ok(()));
    assert_eq!(ok.offset(), 5);
    assert_eq!(ok.finish(), Ok(()));

    let mut bad = Validator::new(Standard::CanonicalMinimal, D);
    assert_eq!(
        bad.feed(&h("0E")),
        Err(Fault {
            at: 0,
            kind: FaultKind::Unassigned {
                field: FieldNumber::new(1).unwrap(),
                code: Low3::new(6).unwrap(),
            },
        })
    );
}
