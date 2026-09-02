//! Contract pins for the groupless scanner: exhaustive on the
//! dialect-specific clauses (capability refusal, groupless
//! vocabulary), representative on semantics shared with the grouped
//! dialect (chunking invariance, seals, standards, EOF verdicts).

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

const D: DepthLimit = DepthLimit::REFERENCE;

/// Transcript vocabulary; consecutive segments merge on push (the
/// chunking-invariant statement is the concatenation).
#[derive(Clone, PartialEq, Eq, Debug)]
enum Ev {
    Len(u32, u32, u64),
    LenExit(u32, u64),
    Varint(u32, u64),
    I32(u32, u32),
    I64(u32, u64),
    Segment(Vec<u8>),
}

struct Rec {
    events: Vec<Ev>,
    descend: &'static [u32],
    bytes: &'static [u32],
}

impl Rec {
    fn new(descend: &'static [u32], bytes: &'static [u32]) -> Self {
        Self { events: Vec::new(), descend, bytes }
    }

    fn push(&mut self, ev: Ev) -> ControlFlow<()> {
        if let (Ev::Segment(tail), Some(Ev::Segment(head))) = (&ev, self.events.last_mut()) {
            head.extend_from_slice(tail);
        } else {
            self.events.push(ev);
        }
        ControlFlow::Continue(())
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
        let _ = self.push(Ev::Len(f, len.as_inner(), at));
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

#[track_caller]
fn invariant(
    data: &[u8],
    descend: &'static [u32],
    bytes: &'static [u32],
    standard: Standard,
) -> (Result<(), Fault>, Vec<Ev>) {
    let mut base: Option<(Result<(), Fault>, Vec<Ev>)> = None;
    for step in [1, 2, 3, 5, 7, data.len().max(1)] {
        let mut rec = Rec::new(descend, bytes);
        let out = (|| {
            let mut parser = Parser::new(standard, D);
            for chunk in data.chunks(step.max(1)) {
                match parser.feed(chunk, &mut rec)? {
                    Flow::More => {}
                    Flow::Stopped => unreachable!("this harness never stops early"),
                }
            }
            parser.finish()
        })();
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
    let (out, _) = invariant(data, &[2, 4], &[3], standard);
    out.expect_err("expected a fault")
}

// ─── capability refusal (the dialect's own clause) ───

#[test]
fn group_codes_are_refused_as_capability_not_noise() {
    let f = |n: u32| FieldNumber::new(n).unwrap();
    let code3 = Low3::new(3).unwrap();
    let code4 = Low3::new(4).unwrap();
    assert_eq!(
        fault_of(&h("0B"), Standard::Tolerant),
        Fault { at: 0, kind: FaultKind::GroupCode { field: f(1), code: code3 } }
    );
    assert_eq!(
        fault_of(&h("0C"), Standard::Tolerant),
        Fault { at: 0, kind: FaultKind::GroupCode { field: f(1), code: code4 } }
    );
    // Distinct from format-unassigned codes.
    let code6 = Low3::new(6).unwrap();
    assert_eq!(
        fault_of(&h("0E"), Standard::Tolerant),
        Fault { at: 0, kind: FaultKind::Unassigned { field: f(1), code: code6 } }
    );
}

#[test]
fn a_group_code_inside_a_descended_len_is_the_same_refusal() {
    let f = |n: u32| FieldNumber::new(n).unwrap();
    let code4 = Low3::new(4).unwrap();
    assert_eq!(
        fault_of(&h("12 01 0C"), Standard::Tolerant),
        Fault { at: 2, kind: FaultKind::GroupCode { field: f(1), code: code4 } }
    );
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

// ─── shared semantics, representative ───

#[test]
fn transcript_is_chunking_invariant_across_the_language() {
    // f1 varint 150 · f2 i64 · f3 len=5 "hello" (bytes) ·
    // f4 len=4 descend { f5 varint 1 · f6 len=0 descend } ·
    // f7 len=0 skip · f8 i32.
    let data = h("08 9601
                  11 0807060504030201
                  1A 05 68656C6C6F
                  22 04 2801 3200
                  3A 00
                  45 AABBCCDD");
    let (end, events) = invariant(&data, &[4, 6], &[3], Standard::CanonicalMinimal);
    assert_eq!(end, Ok(()));
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
            Ev::I32(8, 0xDDCC_BBAA),
        ]
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
    // under the suspended word — no exit event, no value spliced
    // from the parent zone.
    let (out, events) = invariant(&h("12 01 08 2A"), &[2, 4], &[3], s);
    assert_eq!(
        out,
        Err(Fault {
            at: 3,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::SealCut
            }
        })
    );
    assert_eq!(events, [Ev::Len(2, 1, 2)], "no exit fires under the suspended word");
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
fn minimality_is_judged_by_the_declared_standard() {
    let padded_value = h("08 81 00");
    let (end, events) = invariant(&padded_value, &[], &[], Standard::Tolerant);
    assert_eq!((end, events), (Ok(()), alloc::vec![Ev::Varint(1, 1)]));
    let f = |n: u32| FieldNumber::new(n).unwrap();
    assert_eq!(
        fault_of(&padded_value, Standard::CanonicalMinimal),
        Fault { at: 1, kind: FaultKind::NonMinimalValue { field: f(1) } }
    );
}

#[test]
fn eof_inside_a_construct_names_what_was_cut() {
    let s = Standard::Tolerant;
    let f = |n: u32| FieldNumber::new(n).unwrap();
    assert_eq!(
        fault_of(&h("80"), s),
        Fault { at: 1, kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::StreamEnd } }
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
        Fault {
            at: 4,
            kind: FaultKind::PayloadTruncated { remaining: NonZeroU32::new(3).unwrap() }
        }
    );
    // f2 is in the harness descend set.
    assert_eq!(
        fault_of(&h("12 02"), s),
        Fault { at: 2, kind: FaultKind::UnclosedLen { field: f(2) } }
    );
}

#[test]
fn deep_resumption_paths_pin_the_faults_field() {
    let s = Standard::Tolerant;
    let f = |n: u32| FieldNumber::new(n).unwrap();
    // A two-byte tag (field 1000) that the 1-byte chunk steps split
    // across the carry, then a value cut at EOF: the field decoded
    // from the resumed tag must ride onto the fault.
    assert_eq!(
        fault_of(&h("C0 3E 80"), s),
        Fault {
            at: 3,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1000) },
                cause: ReadFault::StreamEnd
            }
        }
    );
    // Two seals deep: f2's payload descends, f4's length word runs
    // into f2's seal — the inner field, not the outer, is named.
    assert_eq!(
        fault_of(&h("12 03 22 81 80"), s),
        Fault {
            at: 5,
            kind: FaultKind::Read {
                stage: Stage::LenPrefix { field: f(4) },
                cause: ReadFault::SealCut
            }
        }
    );
}

#[test]
fn a_zero_length_payload_at_a_chunk_boundary_is_not_truncation() {
    let data = h("0A 00");
    let mut rec = Rec::new(&[], &[]);
    let mut parser = Parser::new(Standard::CanonicalMinimal, D);
    assert_eq!(parser.feed(&data, &mut rec), Ok(Flow::More));
    assert_eq!(parser.finish(), Ok(()));
    assert_eq!(rec.events, [Ev::Len(1, 0, 2)]);
}

#[test]
#[should_panic(expected = "stream already terminal")]
fn feeding_after_a_fault_is_a_named_caller_bug() {
    let mut parser = Parser::new(Standard::CanonicalMinimal, D);
    let _ = parser.feed(&h("0B"), &mut ());
    let _ = parser.feed(&h("08 01"), &mut ());
}

// ─── the validator face ───

#[test]
fn the_validator_is_the_parsers_verdict_and_takes_no_dead_bound() {
    // No DepthLimit parameter: the unit sink never descends and
    // groups are refused, so the stack stays empty by construction.
    let mut ok = Validator::new(Standard::CanonicalMinimal);
    assert_eq!(ok.feed(&h("08 96 01 1A 02 61 62")), Ok(()));
    assert_eq!(ok.offset(), 7);
    assert_eq!(ok.finish(), Ok(()));

    let code3 = Low3::new(3).unwrap();
    let f = |n: u32| FieldNumber::new(n).unwrap();
    let mut bad = Validator::new(Standard::CanonicalMinimal);
    assert_eq!(
        bad.feed(&h("0B")),
        Err(Fault { at: 0, kind: FaultKind::GroupCode { field: f(1), code: code3 } })
    );
}

#[test]
fn the_validator_matches_the_unit_sink_parser_across_the_fault_space() {
    // The stackless engine's contract: verdict and coordinate equal
    // the parser's over a sink that descends nothing — for every
    // fault family this dialect can judge, under both standards, at
    // every chunk split.
    let corpus: &[&str] = &[
        "08 96 01 1A 02 61 62",               // clean: varint · LEN
        "0D 01 02 03 04 11 0102030405060708", // fixed pair
        "08 96 81 00",                        // padded value (canonical refusal)
        "88 80 80 00 01",                     // padded tag (canonical refusal)
        "12 82 80 00 61 62",                  // padded LEN prefix
        "0B",                                 // group code (capability)
        "0F",                                 // unassigned code 7
        "00",                                 // field zero
        "0D 01 02",                           // fixed truncated
        "12 05 61 62",                        // counted payload truncated
        "12",                                 // tag alone, then EOF
        "08",                                 // varint value never arrives
        "12 04",                              // LEN word complete, payload absent
        "FF FF FF FF 7F 01",                  // tag out of u32 class
        "08 FFFFFFFFFFFFFFFFFF02",            // value out of u64 class
        "12 FF FF FF FF 7F",                  // length out of class
    ];
    for hex in corpus {
        let data = h(hex);
        for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
            let oracle = {
                let mut parser = Parser::new(standard, D);
                let fed = data.chunks(data.len().max(1)).try_for_each(|chunk| {
                    parser.feed(chunk, &mut ()).map(|flow| debug_assert!(flow == Flow::More))
                });
                fed.and_then(|()| parser.finish())
            };
            for step in 1..=data.len().max(1) {
                let mut validator = Validator::new(standard);
                let verdict = data
                    .chunks(step)
                    .try_for_each(|chunk| validator.feed(chunk))
                    .and_then(|()| validator.finish());
                assert_eq!(
                    verdict, oracle,
                    "{hex:?} under {standard:?} at step {step}: the engines disagree"
                );
            }
        }
    }
}
