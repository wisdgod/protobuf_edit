//! Contract pins for the grouped router: exhaustive on the group
//! clauses (tapped-group framing, the end-tag exclusion, framing
//! faults, the shared depth account), representative on semantics
//! shared with the groupless twin (arms, fan-out, chunking
//! invariance, EOF verdicts).

use alloc::vec::Vec;
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
    Enter { path: u32, field: u32, at: u64, body_at: u64 },
    Exit { path: u32, field: u32, at: u64, body_end: u64, end: u64 },
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
    fn on_group_enter(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        body_at: u64,
    ) -> ControlFlow<()> {
        self.events.push(Ev::Enter { path: path.index(), field: field.as_inner(), at, body_at });
        ControlFlow::Continue(())
    }
    fn on_group_exit(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        body_end: u64,
        end: u64,
    ) -> ControlFlow<()> {
        self.events.push(Ev::Exit {
            path: path.index(),
            field: field.as_inner(),
            at,
            body_end,
            end,
        });
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

// ─── tapped groups, pinned on one exact transcript ───

#[test]
fn a_tapped_group_streams_its_body_between_the_framing_tags() {
    // One stream pins the group clauses: the tapped f5 group's own
    // tags (2B at 2, 2C at 12) never enter its segments; the
    // untapped nested f8 group's framing tags are ordinary body of
    // the outer tap; interior scalars match through the wildcard;
    // the nested counted f3 tap receives its piece after the outer
    // tap (outermost first); the exit carries the framing geometry.
    let route = [f(5)];
    let paths: [&[Segment<'_>]; 3] = [
        &[Segment::Field(f(5))],
        &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
        &[Segment::Field(f(5)), Segment::Field(f(3))],
    ];
    // varint f1=1 · group f5 { varint f1=2 · LEN f3 "z" ·
    // group f8 { varint f1=3 } } · varint f6=7
    let doc = h("08 01 2B 08 02 1A 01 7A 43 08 03 44 2C 30 07");
    let (end, events) = invariant(&doc, &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Varint { path: 1, field: 1, at: 0, value: 1 },
            Ev::Enter { path: 0, field: 5, at: 2, body_at: 3 },
            Ev::Seg { path: 0, at: 2, seg_at: 3, bytes: h("08") },
            Ev::Seg { path: 0, at: 2, seg_at: 4, bytes: h("02") },
            Ev::Varint { path: 1, field: 1, at: 3, value: 2 },
            Ev::Seg { path: 0, at: 2, seg_at: 5, bytes: h("1A") },
            Ev::Seg { path: 0, at: 2, seg_at: 6, bytes: h("01") },
            Ev::Len { path: 2, field: 3, at: 5, len: 1 },
            Ev::Seg { path: 0, at: 2, seg_at: 7, bytes: h("7A") },
            Ev::Seg { path: 2, at: 5, seg_at: 7, bytes: h("7A") },
            Ev::LenExit { path: 2, field: 3, at: 5, end: 8 },
            Ev::Seg { path: 0, at: 2, seg_at: 8, bytes: h("43") },
            Ev::Seg { path: 0, at: 2, seg_at: 9, bytes: h("08") },
            Ev::Seg { path: 0, at: 2, seg_at: 10, bytes: h("03") },
            Ev::Seg { path: 0, at: 2, seg_at: 11, bytes: h("44") },
            Ev::Exit { path: 0, field: 5, at: 2, body_end: 12, end: 13 },
        ]
    );
}

#[test]
fn a_wide_end_tag_split_at_every_byte_never_leaks_into_the_tap() {
    // Field 1000's framing tags span two bytes each: split the
    // stream at every byte — including inside the end tag — and
    // the tap's body must stay exactly the interior.
    let big = f(1000);
    let program_paths: [&[Segment<'_>]; 1] = [&[Segment::Field(big)]];
    let program = Program::over(&program_paths).unwrap();
    // group f1000 { varint f1=150 }
    let doc = h("C33E 08 9601 C43E");
    let expected = {
        let mut rec = Rec::default();
        let mut router = Router::new(&program, Standard::Tolerant, D);
        assert_eq!(router.feed(&doc, &mut rec).unwrap(), Flow::More);
        router.finish().unwrap();
        norm(&rec.events)
    };
    assert_eq!(
        expected.bodies,
        [(0, 0, 2, h("08 9601"))],
        "the whole-fed body is the interior, framing tags excluded"
    );
    for cut in 0..=doc.len() {
        let mut rec = Rec::default();
        let mut router = Router::new(&program, Standard::Tolerant, D);
        assert_eq!(router.feed(&doc[..cut], &mut rec).unwrap(), Flow::More);
        assert_eq!(router.feed(&doc[cut..], &mut rec).unwrap(), Flow::More);
        router.finish().unwrap();
        assert_eq!(expected, norm(&rec.events), "split at {cut} moved the observation");
    }
}

#[test]
fn a_nested_tapped_groups_end_tag_pours_only_to_the_outer_taps() {
    // Tapped f5 inside tapped f5: the inner end tag is body of the
    // outer taps and of nothing else — and the retired inner tap's
    // ids must not haunt the outer pour (the arena view stops at
    // the closing tap's mark).
    let route = [f(5)];
    let paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(5))], &[Segment::AnyDepth { descend: &route }, Segment::Field(f(5))]];
    // f5 { f5 { varint f1=1 } }
    let (end, events) = invariant(&h("2B 2B 08 01 2C 2C"), &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Enter { path: 0, field: 5, at: 0, body_at: 1 },
            Ev::Enter { path: 1, field: 5, at: 0, body_at: 1 },
            Ev::Seg { path: 0, at: 0, seg_at: 1, bytes: h("2B") },
            Ev::Seg { path: 1, at: 0, seg_at: 1, bytes: h("2B") },
            Ev::Enter { path: 1, field: 5, at: 1, body_at: 2 },
            Ev::Seg { path: 0, at: 0, seg_at: 2, bytes: h("08") },
            Ev::Seg { path: 1, at: 0, seg_at: 2, bytes: h("08") },
            Ev::Seg { path: 1, at: 1, seg_at: 2, bytes: h("08") },
            Ev::Seg { path: 0, at: 0, seg_at: 3, bytes: h("01") },
            Ev::Seg { path: 1, at: 0, seg_at: 3, bytes: h("01") },
            Ev::Seg { path: 1, at: 1, seg_at: 3, bytes: h("01") },
            Ev::Seg { path: 0, at: 0, seg_at: 4, bytes: h("2C") },
            Ev::Seg { path: 1, at: 0, seg_at: 4, bytes: h("2C") },
            Ev::Exit { path: 1, field: 5, at: 1, body_end: 4, end: 5 },
            Ev::Exit { path: 0, field: 5, at: 0, body_end: 5, end: 6 },
            Ev::Exit { path: 1, field: 5, at: 0, body_end: 5, end: 6 },
        ]
    );
}

#[test]
fn nested_taps_close_through_all_three_seams_in_one_walk() {
    // group f2 { LEN f3 { varint f1=1 · LEN f4 "ab" } }: path 2's
    // counted f4 tap closes at exhaustion, path 1's committed f3
    // tap closes at the sealed endpoint's cascade, and path 0's
    // group tap closes at the verified end tag — the three close
    // seams, nested in one walk, chunk-stepped by the harness.
    let msg = h("13 1A 06 08 01 22 02 61 62 14");
    let paths: [&[Segment<'_>]; 3] = [
        &[Segment::Field(f(2))],
        &[Segment::Field(f(2)), Segment::Field(f(3))],
        &[Segment::Field(f(2)), Segment::Field(f(3)), Segment::Field(f(4))],
    ];
    let (out, events) = invariant(&msg, &paths, Standard::Tolerant);
    out.unwrap();
    let exits: Vec<&Ev> =
        events.iter().filter(|ev| matches!(ev, Ev::LenExit { .. } | Ev::Exit { .. })).collect();
    assert_eq!(
        exits,
        [
            &Ev::LenExit { path: 2, field: 4, at: 5, end: 9 },
            &Ev::LenExit { path: 1, field: 3, at: 1, end: 9 },
            &Ev::Exit { path: 0, field: 2, at: 0, body_end: 9, end: 10 },
        ],
        "the closes retire innermost first, each through its own seam"
    );
}

#[test]
fn group_fan_out_delivers_each_targeting_path_ascending() {
    // Two paths target the top-level group: paired enters and
    // exits, ascending, and each piece pours once per tap.
    let route = [f(5)];
    let paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(5))], &[Segment::AnyDepth { descend: &route }, Segment::Field(f(5))]];
    let (end, events) = invariant(&h("2B 08 01 2C"), &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Enter { path: 0, field: 5, at: 0, body_at: 1 },
            Ev::Enter { path: 1, field: 5, at: 0, body_at: 1 },
            Ev::Seg { path: 0, at: 0, seg_at: 1, bytes: h("08") },
            Ev::Seg { path: 1, at: 0, seg_at: 1, bytes: h("08") },
            Ev::Seg { path: 0, at: 0, seg_at: 2, bytes: h("01") },
            Ev::Seg { path: 1, at: 0, seg_at: 2, bytes: h("01") },
            Ev::Exit { path: 0, field: 5, at: 0, body_end: 3, end: 4 },
            Ev::Exit { path: 1, field: 5, at: 0, body_end: 3, end: 4 },
        ]
    );
}

// ─── group framing faults ───

#[test]
fn group_framing_breaks_are_the_scan_rulings() {
    let none: [&[Segment<'_>]; 0] = [];
    // An orphan end tag.
    let (end, _) = run(&h("0C"), &none, Standard::Tolerant);
    assert_eq!(end, Err(Fault { at: 0, kind: FaultKind::GroupEndOrphan { end: f(1) } }));
    // A mismatched end tag.
    let (end, _) = run(&h("0B 14"), &none, Standard::Tolerant);
    assert_eq!(
        end,
        Err(Fault { at: 1, kind: FaultKind::GroupEndMismatch { end: f(2), open: f(1) } })
    );
    // An end tag across a committed LEN's unfinished seal.
    let commit: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2)), Segment::Field(f(9))]];
    let (end, _) = run(&h("12 02 0C 00"), &commit, Standard::Tolerant);
    assert_eq!(
        end,
        Err(Fault { at: 2, kind: FaultKind::GroupEndAcrossLen { end: f(1), open_len: f(2) } })
    );
    // A LEN endpoint under an open group.
    let (end, _) = run(&h("12 01 0B"), &commit, Standard::Tolerant);
    assert_eq!(end, Err(Fault { at: 3, kind: FaultKind::GroupUnclosedAtLenEnd { group: f(1) } }));
    // EOF with a group open.
    let (end, _) = run(&h("0B"), &none, Standard::Tolerant);
    assert_eq!(end, Err(Fault { at: 1, kind: FaultKind::GroupUnclosed { field: f(1) } }));
}

#[test]
fn groups_and_committed_lens_spend_one_depth_account() {
    let commit: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2)), Segment::Field(f(9))]];
    let program = Program::over(&commit).unwrap();
    // The committed f2 takes the one account; the group inside
    // overdraws it.
    let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::MIN);
    let fault = router.feed(&h("12 02 0B 0C"), &mut Rec::default()).unwrap_err();
    assert_eq!(fault, Fault { at: 2, kind: FaultKind::DepthExceeded { field: f(1) } });
    // And the other order: the group takes it, the committed LEN
    // inside overdraws (the path must route through the group for
    // its interior to commit at all).
    let through: [&[Segment<'_>]; 1] =
        [&[Segment::Field(f(1)), Segment::Field(f(2)), Segment::Field(f(9))]];
    let program = Program::over(&through).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::MIN);
    let fault = router.feed(&h("0B 12 00 0C"), &mut Rec::default()).unwrap_err();
    assert_eq!(fault, Fault { at: 3, kind: FaultKind::DepthExceeded { field: f(2) } });
}

// ─── shared semantics, representative ───

#[test]
fn the_len_arms_mirror_the_groupless_twin() {
    // Tap-and-commit with a nested counted tap, transplanted from
    // the groupless suite: the grouped machine reads the same
    // group-free wire identically.
    let route = [f(4), f(7)];
    let paths: [&[Segment<'_>]; 3] = [
        &[Segment::Field(f(7))],
        &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
        &[Segment::Field(f(7)), Segment::Field(f(3))],
    ];
    let (end, events) = invariant(&h("3A 07 0802 1A017A 3009"), &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Len { path: 0, field: 7, at: 0, len: 7 },
            Ev::Seg { path: 0, at: 0, seg_at: 2, bytes: h("08") },
            Ev::Seg { path: 0, at: 0, seg_at: 3, bytes: h("02") },
            Ev::Varint { path: 1, field: 1, at: 2, value: 2 },
            Ev::Seg { path: 0, at: 0, seg_at: 4, bytes: h("1A") },
            Ev::Seg { path: 0, at: 0, seg_at: 5, bytes: h("01") },
            Ev::Len { path: 2, field: 3, at: 4, len: 1 },
            Ev::Seg { path: 0, at: 0, seg_at: 6, bytes: h("7A") },
            Ev::Seg { path: 2, at: 4, seg_at: 6, bytes: h("7A") },
            Ev::LenExit { path: 2, field: 3, at: 4, end: 7 },
            Ev::Seg { path: 0, at: 0, seg_at: 7, bytes: h("30") },
            Ev::Seg { path: 0, at: 0, seg_at: 8, bytes: h("09") },
            Ev::LenExit { path: 0, field: 7, at: 0, end: 9 },
        ]
    );
}

#[test]
fn scalar_targets_deliver_their_own_observations() {
    let paths: [&[Segment<'_>]; 3] =
        [&[Segment::Field(f(1))], &[Segment::Field(f(2))], &[Segment::Field(f(3))]];
    // varint f1=150 · I32 f2 · I64 f3
    let (end, events) =
        invariant(&h("08 9601 15 01000000 19 0200000000000000"), &paths, Standard::Tolerant);
    assert_eq!(end, Ok(()));
    assert_eq!(
        events,
        [
            Ev::Varint { path: 0, field: 1, at: 0, value: 150 },
            Ev::I32 { path: 1, field: 2, at: 3, bits: 1 },
            Ev::I64 { path: 2, field: 3, at: 8, bits: 2 },
        ]
    );
}

#[test]
fn an_empty_program_is_the_root_level_validator() {
    let none: [&[Segment<'_>]; 0] = [];
    // Groups still walk by syntax: framing is verified eventless.
    let (end, events) = invariant(&h("0B 08 01 0C 12 01 FF"), &none, Standard::Tolerant);
    assert_eq!((end, events), (Ok(()), alloc::vec![]));
    let (end, _) = run(&h("00"), &none, Standard::Tolerant);
    assert_eq!(end, Err(Fault { at: 0, kind: FaultKind::FieldZero }));
}

#[test]
fn eof_names_the_open_construct() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3))]];
    let (end, events) = run(&h("1A 05 61"), &paths, Standard::Tolerant);
    assert_eq!(
        end,
        Err(Fault {
            at: 3,
            kind: FaultKind::PayloadTruncated { remaining: core::num::NonZeroU32::new(4).unwrap() }
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
}

// ─── terminality ───

/// Breaks on the first enter it sees.
struct First;
impl Sink for First {
    fn on_group_enter(
        &mut self,
        _path: PathId,
        _field: FieldNumber,
        _at: u64,
        _body_at: u64,
    ) -> ControlFlow<()> {
        ControlFlow::Break(())
    }
}

#[test]
fn a_sinks_break_is_an_orderly_terminal_stop() {
    let program_paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(5))]];
    let program = Program::over(&program_paths).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    let flow = router.feed(&h("2B 08 01 2C"), &mut First).unwrap();
    assert_eq!(flow, Flow::Stopped);
}

#[test]
#[should_panic(expected = "stream already terminal")]
fn feeding_after_a_fault_is_a_named_caller_bug() {
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    let _ = router.feed(&h("0C"), &mut ());
    let _ = router.feed(&h("08 01"), &mut ());
}

#[test]
#[should_panic(expected = "stream already terminal")]
fn finishing_after_an_early_stop_is_a_named_caller_bug() {
    let program_paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(5))]];
    let program = Program::over(&program_paths).unwrap();
    let mut router = Router::new(&program, Standard::Tolerant, D);
    let _ = router.feed(&h("2B 08 01 2C"), &mut First);
    let _ = router.finish();
}
