//! Contract pins for the groupless router: exhaustive on the
//! program-law clauses (the four arms, fan-out and pour order,
//! tap framing), representative on wire semantics shared with the
//! scan twin (chunking invariance, seals, standards, EOF
//! verdicts).

use alloc::vec::Vec;
use core::num::NonZeroU32;
use core::ops::ControlFlow;

use super::*;
use crate::DepthLimit;
use crate::path::Segment;

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

#[track_caller]
fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

const D: DepthLimit = DepthLimit::REFERENCE;

/// Raw transcript vocabulary — segments unmerged, so exact-order
/// pins see every pour.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Ev {
    Varint { path: u32, field: u32, at: u64, value: u64 },
    I32 { path: u32, field: u32, at: u64, bits: u32 },
    I64 { path: u32, field: u32, at: u64, bits: u64 },
    Len { path: u32, field: u32, at: u64, len: u32 },
    Seg { path: u32, at: u64, seg_at: u64, bytes: Vec<u8> },
    LenExit { path: u32, field: u32, at: u64, end: u64 },
}

#[derive(Default)]
struct Rec {
    events: Vec<Ev>,
}

impl Sink for Rec {
    fn on_varint(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        value: u64,
    ) -> ControlFlow<()> {
        self.events.push(Ev::Varint { path: path.index(), field: field.as_inner(), at, value });
        ControlFlow::Continue(())
    }
    fn on_i32(&mut self, path: PathId, field: FieldNumber, at: u64, bits: u32) -> ControlFlow<()> {
        self.events.push(Ev::I32 { path: path.index(), field: field.as_inner(), at, bits });
        ControlFlow::Continue(())
    }
    fn on_i64(&mut self, path: PathId, field: FieldNumber, at: u64, bits: u64) -> ControlFlow<()> {
        self.events.push(Ev::I64 { path: path.index(), field: field.as_inner(), at, bits });
        ControlFlow::Continue(())
    }
    fn on_len(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        len: PayloadLen,
    ) -> ControlFlow<()> {
        self.events.push(Ev::Len {
            path: path.index(),
            field: field.as_inner(),
            at,
            len: len.as_inner(),
        });
        ControlFlow::Continue(())
    }
    fn on_segment(&mut self, path: PathId, at: u64, seg_at: u64, bytes: &[u8]) -> ControlFlow<()> {
        self.events.push(Ev::Seg { path: path.index(), at, seg_at, bytes: bytes.to_vec() });
        ControlFlow::Continue(())
    }
    fn on_len_exit(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        end: u64,
    ) -> ControlFlow<()> {
        self.events.push(Ev::LenExit { path: path.index(), field: field.as_inner(), at, end });
        ControlFlow::Continue(())
    }
}

/// The chunking-invariant projection: non-segment events in order,
/// and per (path, tap instance) the poured body — first piece's
/// offset plus the concatenation, with contiguity asserted at
/// every append (pieces must tile).
#[derive(PartialEq, Eq, Debug)]
struct Norm {
    events: Vec<Ev>,
    bodies: Vec<(u32, u64, u64, Vec<u8>)>,
}

#[track_caller]
fn norm(events: &[Ev]) -> Norm {
    let mut out = Norm { events: Vec::new(), bodies: Vec::new() };
    for ev in events {
        if let Ev::Seg { path, at, seg_at, bytes } = ev {
            if let Some(body) = out.bodies.iter_mut().find(|b| b.0 == *path && b.1 == *at) {
                #[allow(clippy::as_conversions, reason = "test bodies are tiny")]
                let expected = body.2 + body.3.len() as u64;
                assert_eq!(expected, *seg_at, "pieces of one tap tile contiguously");
                body.3.extend_from_slice(bytes);
            } else {
                out.bodies.push((*path, *at, *seg_at, bytes.clone()));
            }
        } else {
            out.events.push(ev.clone());
        }
    }
    out
}

/// Runs the whole input as one chunk; the raw transcript.
#[track_caller]
fn run(data: &[u8], paths: &[&[Segment<'_>]], standard: Standard) -> (Result<(), Fault>, Vec<Ev>) {
    let program = Program::over(paths).expect("test paths admit");
    let mut rec = Rec::default();
    let out = (|| {
        let mut router = Router::new(&program, standard, D);
        match router.feed(data, &mut rec)? {
            Flow::More => {}
            Flow::Stopped => unreachable!("this harness never stops early"),
        }
        router.finish()
    })();
    (out, rec.events)
}

/// Feeds `data` at several chunk steps: the verdict and the
/// normalized transcript must not move. Returns the whole-fed run.
#[track_caller]
fn invariant(
    data: &[u8],
    paths: &[&[Segment<'_>]],
    standard: Standard,
) -> (Result<(), Fault>, Vec<Ev>) {
    let program = Program::over(paths).expect("test paths admit");
    let whole = run(data, paths, standard);
    let base = norm(&whole.1);
    for step in [1, 2, 3, 5, 7] {
        let mut rec = Rec::default();
        let out = (|| {
            let mut router = Router::new(&program, standard, D);
            for chunk in data.chunks(step) {
                match router.feed(chunk, &mut rec)? {
                    Flow::More => {}
                    Flow::Stopped => unreachable!("this harness never stops early"),
                }
            }
            router.finish()
        })();
        assert_eq!(whole.0, out, "chunk step {step} moved the verdict");
        assert_eq!(base, norm(&rec.events), "chunk step {step} moved the observation");
    }
    whole
}

/// The canonical mixed document: every arm of the program law in
/// one stream. Fields by role: f1 scalars (targeted at top and at
/// depth), f3 raw LEN taps, f4 a committed silent route, f7 the
/// tap-and-commit container, f2 a skipped LEN with unparseable
/// bytes, f6 noise.
fn mixed() -> Vec<u8> {
    h("08 9601
       1A 02 6162
       22 02 0801
       3A 07 0802 1A017A 3009
       12 01 FF
       30 07")
}

fn mixed_paths() -> [&'static [Segment<'static>]; 5] {
    const ROUTE: [FieldNumber; 2] = [FieldNumber::new(4).unwrap(), FieldNumber::new(7).unwrap()];
    const F1: FieldNumber = FieldNumber::new(1).unwrap();
    const F3: FieldNumber = FieldNumber::new(3).unwrap();
    const F7: FieldNumber = FieldNumber::new(7).unwrap();
    [
        &[Segment::Field(F1)],
        &[Segment::Field(F3)],
        &[Segment::Field(F7)],
        &[Segment::AnyDepth { descend: &ROUTE }, Segment::Field(F1)],
        &[Segment::Field(F7), Segment::Field(F3)],
    ]
}

// ─── the program law, pinned on one exact transcript ───

#[test]
fn the_four_arms_fan_out_and_pour_order_pin_one_exact_transcript() {
    // Whole-fed raw order pins, in one stream: fan-out ascending
    // (paths 0 and 3 on the first record), the pure tap (f3 at 3),
    // the silent commit (f4 at 7 delivers only its interior), the
    // tap-and-commit container (f7 at 11) whose constructs pour
    // ahead of their own events, the nested counted tap (f3 at 15)
    // receiving its piece after the outer tap (outermost first),
    // the skipped unparseable LEN (f2 at 20 — counted, never
    // parsed, no event), and both exit coordinates.
    let (end, events) = invariant(&mixed(), &mixed_paths(), Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Varint { path: 0, field: 1, at: 0, value: 150 },
            Ev::Varint { path: 3, field: 1, at: 0, value: 150 },
            Ev::Len { path: 1, field: 3, at: 3, len: 2 },
            Ev::Seg { path: 1, at: 3, seg_at: 5, bytes: h("6162") },
            Ev::LenExit { path: 1, field: 3, at: 3, end: 7 },
            Ev::Varint { path: 3, field: 1, at: 9, value: 1 },
            Ev::Len { path: 2, field: 7, at: 11, len: 7 },
            Ev::Seg { path: 2, at: 11, seg_at: 13, bytes: h("08") },
            Ev::Seg { path: 2, at: 11, seg_at: 14, bytes: h("02") },
            Ev::Varint { path: 3, field: 1, at: 13, value: 2 },
            Ev::Seg { path: 2, at: 11, seg_at: 15, bytes: h("1A") },
            Ev::Seg { path: 2, at: 11, seg_at: 16, bytes: h("01") },
            Ev::Len { path: 4, field: 3, at: 15, len: 1 },
            Ev::Seg { path: 2, at: 11, seg_at: 17, bytes: h("7A") },
            Ev::Seg { path: 4, at: 15, seg_at: 17, bytes: h("7A") },
            Ev::LenExit { path: 4, field: 3, at: 15, end: 18 },
            Ev::Seg { path: 2, at: 11, seg_at: 18, bytes: h("30") },
            Ev::Seg { path: 2, at: 11, seg_at: 19, bytes: h("09") },
            Ev::LenExit { path: 2, field: 7, at: 11, end: 20 },
        ]
    );
}

#[test]
fn a_counted_tap_is_never_parsed_and_a_commitment_faults_for_real() {
    // The same unparseable byte behind the two arms: a pure tap
    // counts it out and delivers it; a commitment parses and
    // faults. The sink has no say in either.
    let tap: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3))]];
    let (end, events) = invariant(&h("1A 01 FF"), &tap, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Len { path: 0, field: 3, at: 0, len: 1 },
            Ev::Seg { path: 0, at: 0, seg_at: 2, bytes: h("FF") },
            Ev::LenExit { path: 0, field: 3, at: 0, end: 3 },
        ]
    );

    let commit: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3)), Segment::Field(f(9))]];
    let (end, events) = invariant(&h("1A 01 FF"), &commit, Standard::Tolerant);
    assert_eq!(
        end,
        Err(Fault {
            at: 3,
            kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SealCut }
        })
    );
    assert_eq!(events, [], "a silent commitment delivers nothing of its own");
}

#[test]
fn one_container_fans_out_to_every_targeting_path_ascending() {
    // Two paths target the same LEN: one head event each and one
    // segment per piece per tap, ascending path order inside the
    // one frame.
    let route = [f(7)];
    let paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(7))], &[Segment::AnyDepth { descend: &route }, Segment::Field(f(7))]];
    let (end, events) = invariant(&h("3A 02 0801"), &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Len { path: 0, field: 7, at: 0, len: 2 },
            Ev::Len { path: 1, field: 7, at: 0, len: 2 },
            Ev::Seg { path: 0, at: 0, seg_at: 2, bytes: h("08") },
            Ev::Seg { path: 1, at: 0, seg_at: 2, bytes: h("08") },
            Ev::Seg { path: 0, at: 0, seg_at: 3, bytes: h("01") },
            Ev::Seg { path: 1, at: 0, seg_at: 3, bytes: h("01") },
            Ev::LenExit { path: 0, field: 7, at: 0, end: 4 },
            Ev::LenExit { path: 1, field: 7, at: 0, end: 4 },
        ]
    );
}

#[test]
fn converging_wildcard_states_tap_once_per_instance() {
    // Stacked wildcards sharing member f1 reach the f4 terminal
    // through two live states: the record still taps once.
    let outer = [f(1), f(2)];
    let inner = [f(1), f(3)];
    let paths: [&[Segment<'_>]; 1] = [&[
        Segment::AnyDepth { descend: &outer },
        Segment::AnyDepth { descend: &inner },
        Segment::Field(f(4)),
    ]];
    // f1{ f1{ f4:LEN "abc" } }
    let (end, events) = invariant(&h("0A 07 0A 05 22 03 616263"), &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Len { path: 0, field: 4, at: 4, len: 3 },
            Ev::Seg { path: 0, at: 4, seg_at: 6, bytes: h("616263") },
            Ev::LenExit { path: 0, field: 4, at: 4, end: 9 },
        ]
    );
}

#[test]
fn an_empty_program_is_the_root_level_validator() {
    let none: [&[Segment<'_>]; 0] = [];
    // Lawful wire — an unrouted LEN's interior is opaque bytes.
    let (end, events) = invariant(&h("08 01 12 01 FF"), &none, Standard::Tolerant);
    assert_eq!((end, events), (Ok(()), alloc::vec![]));
    // Unlawful wire still faults: routing reads the document.
    let (end, events) = run(&h("00"), &none, Standard::Tolerant);
    assert_eq!(end, Err(Fault { at: 0, kind: FaultKind::FieldZero }));
    assert_eq!(events, []);
    // Group codes are the capability refusal.
    let (end, _) = run(&h("0B"), &none, Standard::Tolerant);
    let fault = end.unwrap_err();
    assert_eq!(
        fault,
        Fault { at: 0, kind: FaultKind::GroupCode { field: f(1), code: Low3::new(3).unwrap() } }
    );
    assert_eq!(fault.kind().class(), crate::FaultClass::Capability);
}

#[test]
fn a_zero_length_tap_closes_at_its_head_without_a_piece() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3))]];
    let (end, events) = invariant(&h("1A 00"), &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Len { path: 0, field: 3, at: 0, len: 0 },
            Ev::LenExit { path: 0, field: 3, at: 0, end: 2 },
        ]
    );
}

// ─── faults follow the stream rulings ───

#[test]
fn the_depth_budget_gates_committed_descent() {
    let program_paths: [&[Segment<'_>]; 1] =
        [&[Segment::Field(f(1)), Segment::Field(f(1)), Segment::Field(f(1))]];
    let program = Program::over(&program_paths).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::MIN);
    let fault = router.feed(&h("0A 04 0A 02 0801"), &mut Rec::default()).unwrap_err();
    assert_eq!(fault, Fault { at: 4, kind: FaultKind::DepthExceeded { field: f(1) } });
    assert_eq!(fault.kind().class(), crate::FaultClass::Policy);
}

#[test]
fn a_word_suspended_across_the_seal_is_the_seal_cut() {
    // Tap-and-commit f2 whose one-byte body is a lone varint tag:
    // the tag closes at the seal, the value lies outside. The head
    // event and the tag's pour already landed; the seal then cuts
    // the suspended value — and no exit fires under it.
    let paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(2))], &[Segment::Field(f(2)), Segment::Field(f(9))]];
    let (end, events) = invariant(&h("12 01 08 2A"), &paths, Standard::Tolerant);
    assert_eq!(
        end,
        Err(Fault {
            at: 3,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::SealCut
            }
        })
    );
    assert_eq!(
        events,
        [
            Ev::Len { path: 0, field: 2, at: 0, len: 1 },
            Ev::Seg { path: 0, at: 0, seg_at: 2, bytes: h("08") },
        ],
        "no exit fires under the suspended word"
    );

    // The same verdict at the completing feed when the suspension
    // crosses a chunk boundary (the seal endpoint refuses to pop
    // under a suspended word).
    let program = Program::over(&paths).unwrap();
    let mut rec = Rec::default();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    assert_eq!(router.feed(&h("12 01"), &mut rec), Ok(Flow::More));
    let fault = router.feed(&h("08 2A"), &mut rec).unwrap_err();
    assert_eq!(
        fault,
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
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1))]];
    let padded = h("08 81 00");
    let (end, events) = invariant(&padded, &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(events, [Ev::Varint { path: 0, field: 1, at: 0, value: 1 }]);
    let (end, events) = run(&padded, &paths, Standard::CanonicalMinimal);
    assert_eq!(end, Err(Fault { at: 1, kind: FaultKind::NonMinimalValue { field: f(1) } }));
    assert_eq!(events, []);
}

#[test]
fn eof_verdicts_name_what_was_cut_taps_included() {
    let none: [&[Segment<'_>]; 0] = [];
    let (end, _) = run(&h("08"), &none, Standard::Tolerant);
    assert_eq!(
        end,
        Err(Fault {
            at: 1,
            kind: FaultKind::Read {
                stage: Stage::Value { field: f(1) },
                cause: ReadFault::StreamEnd
            }
        })
    );

    // A tap still owed bytes at EOF is the counted truncation.
    let tap: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3))]];
    let (end, events) = run(&h("1A 05 61"), &tap, Standard::Tolerant);
    assert_eq!(
        end,
        Err(Fault {
            at: 3,
            kind: FaultKind::PayloadTruncated { remaining: NonZeroU32::new(4).unwrap() }
        })
    );
    assert_eq!(
        events,
        [
            Ev::Len { path: 0, field: 3, at: 0, len: 5 },
            Ev::Seg { path: 0, at: 0, seg_at: 2, bytes: h("61") },
        ],
        "delivered pieces stand; the exit never fires"
    );

    // A tapped commitment still open at EOF is the unclosed LEN,
    // and its exit never fires.
    let both: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(2))], &[Segment::Field(f(2)), Segment::Field(f(9))]];
    let (end, events) = run(&h("12 02"), &both, Standard::Tolerant);
    assert_eq!(end, Err(Fault { at: 2, kind: FaultKind::UnclosedLen { field: f(2) } }));
    assert_eq!(events, [Ev::Len { path: 0, field: 2, at: 0, len: 2 }]);
}

#[test]
fn the_feed_gate_refuses_a_chunk_past_the_coordinate_space() {
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    // The cursor is injected two bytes short of the space's top: a
    // one-byte chunk still admits and consumes...
    let mut router = Router::new(&program, Standard::Tolerant, D);
    router.pump.off = u64::MAX - 2;
    assert_eq!(router.feed(&h("08"), &mut ()).unwrap(), Flow::More);
    assert_eq!(router.offset(), u64::MAX - 1);
    // ...and one byte more would need the unaddressable sentinel
    // coordinate: refused whole at admission, nothing consumed,
    // terminal.
    let fault = router.feed(&h("00"), &mut ()).unwrap_err();
    assert_eq!(fault, Fault { at: u64::MAX - 1, kind: FaultKind::OffsetExhausted });
    assert_eq!(fault.kind().class(), crate::FaultClass::Capability);
}

#[test]
fn a_len_declared_out_to_the_coordinate_ceiling_is_refused() {
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    router.pump.off = u64::MAX - 4;
    let fault = router.feed(&h("0A 02"), &mut ()).unwrap_err();
    assert_eq!(
        fault,
        Fault {
            at: u64::MAX - 2,
            kind: FaultKind::LenUnsatisfiable { field: f(1), len: PayloadLen::new(2).unwrap() }
        }
    );
    assert_eq!(fault.kind().class(), crate::FaultClass::Capability);
    // One byte lower, the same declaration ends at MAX−1 and is
    // admitted (the machine then waits on the payload).
    let mut router = Router::new(&program, Standard::Tolerant, D);
    router.pump.off = u64::MAX - 5;
    assert_eq!(router.feed(&h("0A 02"), &mut ()).unwrap(), Flow::More);
}

// ─── terminality ───

/// Breaks on the first event it sees.
struct First;
impl Sink for First {
    fn on_varint(
        &mut self,
        _path: PathId,
        _field: FieldNumber,
        _at: u64,
        _value: u64,
    ) -> ControlFlow<()> {
        ControlFlow::Break(())
    }
}

#[test]
fn a_sinks_break_is_an_orderly_terminal_stop() {
    let program_paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1))]];
    let program = Program::over(&program_paths).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    let flow = router.feed(&h("08 2A 10 07"), &mut First).unwrap();
    assert_eq!(flow, Flow::Stopped);
}

#[test]
#[should_panic(expected = "stream already terminal")]
fn feeding_after_a_fault_is_a_named_caller_bug() {
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    let _ = router.feed(&h("0B"), &mut ());
    let _ = router.feed(&h("08 01"), &mut ());
}

#[test]
#[should_panic(expected = "stream already terminal")]
fn feeding_after_an_early_stop_is_a_named_caller_bug() {
    let program_paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1))]];
    let program = Program::over(&program_paths).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    let _ = router.feed(&h("08 2A"), &mut First);
    let _ = router.feed(&h("08 01"), &mut Rec::default());
}

#[test]
fn a_break_mid_fan_out_delivers_nothing_further() {
    // Two paths target one record; the sink breaks on the first
    // delivery — the second path's event never fires.
    struct Count(u32);
    impl Sink for Count {
        fn on_varint(
            &mut self,
            _path: PathId,
            _field: FieldNumber,
            _at: u64,
            _value: u64,
        ) -> ControlFlow<()> {
            self.0 += 1;
            ControlFlow::Break(())
        }
    }
    let route = [f(3)];
    let program_paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(1))], &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))]];
    let program = Program::over(&program_paths).unwrap();
    let mut sink = Count(0);
    let mut router = Router::new(&program, Standard::Tolerant, D);
    assert_eq!(router.feed(&h("08 2A"), &mut sink).unwrap(), Flow::Stopped);
    assert_eq!(sink.0, 1);
}

#[test]
fn offset_reads_consumed_progress() {
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    assert_eq!(router.feed(&h("08 96"), &mut ()).unwrap(), Flow::More);
    assert_eq!(router.offset(), 2);
    assert_eq!(router.feed(&h("01"), &mut ()).unwrap(), Flow::More);
    assert_eq!(router.offset(), 3);
    router.finish().unwrap();
}
