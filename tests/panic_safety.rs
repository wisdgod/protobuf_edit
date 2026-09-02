//! Unwind safety: a `Sink`/`Rule` callback or a construct body
//! closure may panic, and a caller may catch it with
//! `catch_unwind` — all through safe APIs. The machines must not
//! let a later safe call reach undefined behavior on the
//! half-updated state the unwind left behind.
//!
//! The scan/transcode machines poison themselves (terminal latch)
//! when a feed unwinds, so a re-feed hits the entry assert instead
//! of resuming a `FixedTail` against a popped zone (which would
//! reach the unreachable `Collect::Cut`). The construct builders
//! refuse to emit while a frame is still open (a body unwound
//! between open and close), instead of a `set_len` over
//! uninitialized spare.
//!
//! The replay cells stand outside this battery's gate: each
//! mounts its pump inside a single public call, so an unwinding
//! callback drops the whole walk with the call frame and the next
//! call re-begins from byte zero — there is no latch because
//! there is no resumable state; a replay cell that ever holds a
//! walk across public calls joins this file.
//!
//! The stream-ingest cells stand outside it on the other ground:
//! their `Ingest` phases do hold parse state across public calls,
//! but no caller callback runs inside `feed`, so an unwind cannot
//! be observed by a later safe call through a half-state the
//! caller caused; any future ingest face that takes a callback
//! joins this file.
//!
//! Every `.is_err()` here is a caught panic (the safe, sound
//! outcome). Run under Miri to prove the poisoned re-entry reaches
//! that panic rather than the UB it guards.

#![cfg(any(
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]

use std::panic::{AssertUnwindSafe, catch_unwind};

#[allow(dead_code, reason = "each dialect module below uses the subset its feature enables")]
fn unhex(s: &str) -> Vec<u8> {
    let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    hex.chunks(2)
        .map(|p| {
            ((p[0] as char).to_digit(16).unwrap() * 16 + (p[1] as char).to_digit(16).unwrap()) as u8
        })
        .collect()
}

/// Silences the panic hook so the deliberate panics below do not
/// spam the test log (the hook is global; setting it empty is
/// idempotent and harmless across tests).
#[allow(dead_code, reason = "each dialect module below calls it")]
fn hush() {
    std::panic::set_hook(Box::new(|_| {}));
}

// A two-level committed message ending in an I32 that fills the
// inner LEN, then a 2-byte varint filling the outer: the shape
// whose I32 callback, if it unwinds, leaves a `FixedTail` mode
// that a naive re-feed would re-enter against the popped outer
// zone. `20 00` re-feeds the outer's tail.
#[allow(dead_code, reason = "each dialect module below uses it")]
const NESTED_I32: &str = "0A 09 12 05 1D 01020304 20 00";

#[cfg(feature = "route-grouped")]
mod route_grouped {
    use super::*;
    use protobuf_edit::path::{PathId, Program, Segment};
    use protobuf_edit::route::grouped::{Router, Sink};
    use protobuf_edit::route::Standard;
    use protobuf_edit::{DepthLimit, FieldNumber};
    use std::ops::ControlFlow;

    struct Bomb;
    impl Sink for Bomb {
        fn on_i32(&mut self, _: PathId, _: FieldNumber, _: u64, _: u32) -> ControlFlow<()> {
            panic!("sink bomb");
        }
    }

    #[test]
    fn a_panicking_sink_poisons_the_router() {
        hush();
        // The program commits both LEN levels and targets the I32,
        // so the bomb detonates through the router's own dispatch.
        let f = |n: u32| FieldNumber::new(n).unwrap();
        let paths: [&[Segment<'_>]; 1] =
            [&[Segment::Field(f(1)), Segment::Field(f(2)), Segment::Field(f(3))]];
        let program = Program::over(&paths).unwrap();
        let doc = unhex(NESTED_I32);
        let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::REFERENCE);
        let first = catch_unwind(AssertUnwindSafe(|| {
            let _ = router.feed(&doc, &mut Bomb);
        }));
        assert!(first.is_err(), "the sink panic must unwind out of feed");
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = router.feed(&unhex("20 00"), &mut Bomb);
        }));
        assert!(second.is_err(), "the poisoned router must refuse re-feed, not resume into UB");
    }
}

#[cfg(feature = "route-groupless")]
mod route_groupless {
    use super::*;
    use protobuf_edit::path::{PathId, Program, Segment};
    use protobuf_edit::route::groupless::{Router, Sink};
    use protobuf_edit::route::Standard;
    use protobuf_edit::{DepthLimit, FieldNumber};
    use std::ops::ControlFlow;

    struct Bomb;
    impl Sink for Bomb {
        fn on_i32(&mut self, _: PathId, _: FieldNumber, _: u64, _: u32) -> ControlFlow<()> {
            panic!("sink bomb");
        }
    }

    #[test]
    fn a_panicking_sink_poisons_the_router() {
        hush();
        let f = |n: u32| FieldNumber::new(n).unwrap();
        let paths: [&[Segment<'_>]; 1] =
            [&[Segment::Field(f(1)), Segment::Field(f(2)), Segment::Field(f(3))]];
        let program = Program::over(&paths).unwrap();
        let doc = unhex(NESTED_I32);
        let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::REFERENCE);
        let first = catch_unwind(AssertUnwindSafe(|| {
            let _ = router.feed(&doc, &mut Bomb);
        }));
        assert!(first.is_err(), "the sink panic must unwind out of feed");
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = router.feed(&unhex("20 00"), &mut Bomb);
        }));
        assert!(second.is_err(), "the poisoned router must refuse re-feed, not resume into UB");
    }
}

#[cfg(feature = "scan-grouped")]
mod scan_grouped {
    use super::*;
    use protobuf_edit::scan::LenDisposition;
    use protobuf_edit::scan::grouped::{Parser, Sink};
    use protobuf_edit::scan::Standard;
    use protobuf_edit::{DepthLimit, FieldNumber, PayloadLen};
    use std::ops::ControlFlow;

    struct Bomb;
    impl Sink for Bomb {
        fn on_len(
            &mut self,
            _: FieldNumber,
            _: PayloadLen,
            _: u64,
        ) -> ControlFlow<(), LenDisposition> {
            ControlFlow::Continue(LenDisposition::Commit)
        }
        fn on_i32(&mut self, _: FieldNumber, _: u32) -> ControlFlow<()> {
            panic!("sink bomb");
        }
    }

    #[test]
    fn a_panicking_sink_poisons_the_parser() {
        hush();
        let doc = unhex(NESTED_I32);
        let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let first = catch_unwind(AssertUnwindSafe(|| {
            let _ = parser.feed(&doc, &mut Bomb);
        }));
        assert!(first.is_err(), "the sink panic must unwind out of feed");
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = parser.feed(&unhex("20 00"), &mut Bomb);
        }));
        assert!(second.is_err(), "the poisoned parser must refuse re-feed, not resume into UB");
    }
}

#[cfg(feature = "scan-groupless")]
mod scan_groupless {
    use super::*;
    use protobuf_edit::scan::LenDisposition;
    use protobuf_edit::scan::groupless::{Parser, Sink};
    use protobuf_edit::scan::Standard;
    use protobuf_edit::{DepthLimit, FieldNumber, PayloadLen};
    use std::ops::ControlFlow;

    struct Bomb;
    impl Sink for Bomb {
        fn on_len(
            &mut self,
            _: FieldNumber,
            _: PayloadLen,
            _: u64,
        ) -> ControlFlow<(), LenDisposition> {
            ControlFlow::Continue(LenDisposition::Commit)
        }
        fn on_i32(&mut self, _: FieldNumber, _: u32) -> ControlFlow<()> {
            panic!("sink bomb");
        }
    }

    #[test]
    fn a_panicking_sink_poisons_the_parser() {
        hush();
        let doc = unhex(NESTED_I32);
        let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let first = catch_unwind(AssertUnwindSafe(|| {
            let _ = parser.feed(&doc, &mut Bomb);
        }));
        assert!(first.is_err(), "the sink panic must unwind out of feed");
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = parser.feed(&unhex("20 00"), &mut Bomb);
        }));
        assert!(second.is_err(), "the poisoned parser must refuse re-feed, not resume into UB");
    }
}

#[cfg(feature = "transcode-grouped")]
mod transcode_grouped {
    use super::*;
    use protobuf_edit::transcode::{FreeLen, LockedLen, LockedScalar};
    use protobuf_edit::transcode::grouped::{Rule, Transcoder};
    use protobuf_edit::transcode::Standard;
    use protobuf_edit::{DepthLimit, FieldNumber, PayloadLen};

    struct Bomb;
    impl Rule for Bomb {
        // Detonates in the first callback the walk presents (the
        // outer LEN head): mode is LenWord and the carry still
        // holds the length word — one of the two mid-walk states
        // the poison must fence.
        fn on_len(&mut self, _: u64, _: FieldNumber, _: PayloadLen) -> FreeLen<'_> {
            panic!("rule bomb");
        }
    }

    /// Commits every LEN (free and locked layers alike) and
    /// detonates in the locked I32 hook — the FixedTail state the
    /// module doc names: carry spent by the collection, mode not
    /// yet reset; an unpoisoned resume would first cascade the
    /// inner zone away, then re-enter collection against the outer
    /// seal and reach the unreachable `Collect::Cut`.
    struct FixedBomb;
    impl Rule for FixedBomb {
        fn on_len(&mut self, _: u64, _: FieldNumber, _: PayloadLen) -> FreeLen<'_> {
            FreeLen::Commit
        }
        fn on_len_locked(&mut self, _: u64, _: FieldNumber, _: PayloadLen) -> LockedLen<'_> {
            LockedLen::Commit
        }
        fn on_i32_locked(&mut self, _: u64, _: FieldNumber, _: u32) -> LockedScalar<u32> {
            panic!("fixed bomb");
        }
    }

    #[test]
    fn a_panicking_rule_poisons_the_transcoder() {
        hush();
        let doc = unhex(NESTED_I32);
        let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let first = catch_unwind(AssertUnwindSafe(|| {
            let _ = t.feed(&doc, &mut Bomb, &mut |_: &[u8]| {});
        }));
        assert!(first.is_err(), "the rule panic must unwind out of feed");
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = t.feed(&unhex("20 00"), &mut Bomb, &mut |_: &[u8]| {});
        }));
        assert!(second.is_err(), "the poisoned transcoder must refuse re-feed, not resume into UB");
    }

    #[test]
    fn a_panicking_locked_fixed_hook_poisons_the_transcoder() {
        hush();
        let doc = unhex(NESTED_I32);
        let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let first = catch_unwind(AssertUnwindSafe(|| {
            let _ = t.feed(&doc, &mut FixedBomb, &mut |_: &[u8]| {});
        }));
        assert!(first.is_err(), "the locked fixed hook's panic must unwind out of feed");
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = t.feed(&unhex("20 00"), &mut FixedBomb, &mut |_: &[u8]| {});
        }));
        assert!(
            second.is_err(),
            "the poisoned transcoder must refuse the FixedTail resume, not reach Collect::Cut"
        );
    }
}

#[cfg(feature = "transcode-groupless")]
mod transcode_groupless {
    use super::*;
    use protobuf_edit::transcode::{FreeLen, LockedLen, LockedScalar};
    use protobuf_edit::transcode::groupless::{Rule, Transcoder};
    use protobuf_edit::transcode::Standard;
    use protobuf_edit::{DepthLimit, FieldNumber, PayloadLen};

    struct Bomb;
    impl Rule for Bomb {
        // Detonates in the first callback the walk presents (the
        // outer LEN head): mode is LenWord and the carry still
        // holds the length word — one of the two mid-walk states
        // the poison must fence.
        fn on_len(&mut self, _: u64, _: FieldNumber, _: PayloadLen) -> FreeLen<'_> {
            panic!("rule bomb");
        }
    }

    /// Commits every LEN (free and locked layers alike) and
    /// detonates in the locked I32 hook — the FixedTail state the
    /// module doc names: carry spent by the collection, mode not
    /// yet reset; an unpoisoned resume would first cascade the
    /// inner zone away, then re-enter collection against the outer
    /// seal and reach the unreachable `Collect::Cut`.
    struct FixedBomb;
    impl Rule for FixedBomb {
        fn on_len(&mut self, _: u64, _: FieldNumber, _: PayloadLen) -> FreeLen<'_> {
            FreeLen::Commit
        }
        fn on_len_locked(&mut self, _: u64, _: FieldNumber, _: PayloadLen) -> LockedLen<'_> {
            LockedLen::Commit
        }
        fn on_i32_locked(&mut self, _: u64, _: FieldNumber, _: u32) -> LockedScalar<u32> {
            panic!("fixed bomb");
        }
    }

    #[test]
    fn a_panicking_rule_poisons_the_transcoder() {
        hush();
        let doc = unhex(NESTED_I32);
        let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let first = catch_unwind(AssertUnwindSafe(|| {
            let _ = t.feed(&doc, &mut Bomb, &mut |_: &[u8]| {});
        }));
        assert!(first.is_err(), "the rule panic must unwind out of feed");
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = t.feed(&unhex("20 00"), &mut Bomb, &mut |_: &[u8]| {});
        }));
        assert!(second.is_err(), "the poisoned transcoder must refuse re-feed, not resume into UB");
    }

    #[test]
    fn a_panicking_locked_fixed_hook_poisons_the_transcoder() {
        hush();
        let doc = unhex(NESTED_I32);
        let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let first = catch_unwind(AssertUnwindSafe(|| {
            let _ = t.feed(&doc, &mut FixedBomb, &mut |_: &[u8]| {});
        }));
        assert!(first.is_err(), "the locked fixed hook's panic must unwind out of feed");
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = t.feed(&unhex("20 00"), &mut FixedBomb, &mut |_: &[u8]| {});
        }));
        assert!(
            second.is_err(),
            "the poisoned transcoder must refuse the FixedTail resume, not reach Collect::Cut"
        );
    }
}

#[cfg(feature = "construct-grouped")]
mod construct_grouped {
    use super::*;
    use protobuf_edit::FieldNumber;
    use protobuf_edit::construct::grouped::Builder;

    const fn f(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    #[test]
    fn a_message_body_that_unwinds_refuses_to_emit() {
        hush();
        let mut b = Builder::new();
        let first = catch_unwind(AssertUnwindSafe(|| {
            b.message(f(1), |m| {
                m.push_varint(f(2), 1);
                panic!("body bomb");
            });
        }));
        assert!(first.is_err(), "the body panic must unwind");
        let second = catch_unwind(AssertUnwindSafe(|| b.finish()));
        assert!(
            second.is_err(),
            "the abandoned builder must refuse to emit, not publish uninit bytes"
        );
    }

    #[test]
    fn a_group_body_that_unwinds_refuses_to_emit() {
        hush();
        let mut b = Builder::new();
        let first = catch_unwind(AssertUnwindSafe(|| {
            b.group(f(1), |m| {
                m.push_varint(f(2), 1);
                panic!("body bomb");
            });
        }));
        assert!(first.is_err(), "the body panic must unwind");
        let second = catch_unwind(AssertUnwindSafe(|| b.finish()));
        assert!(
            second.is_err(),
            "the abandoned builder must refuse to emit, not publish uninit bytes"
        );
    }

    #[test]
    fn an_abandoned_builder_leaves_the_callers_buffer_untouched() {
        hush();
        let mut b = Builder::new();
        let first = catch_unwind(AssertUnwindSafe(|| {
            b.message(f(1), |m| {
                m.push_varint(f(2), 1);
                panic!("body bomb");
            });
        }));
        assert!(first.is_err(), "the body panic must unwind");
        // A caller buffer with recognizable contents: the refusal
        // must neither truncate nor extend nor overwrite it.
        let mut out = vec![0xEE_u8; 7];
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = b.finish_into(&mut out);
        }));
        assert!(second.is_err(), "finish_into must refuse the abandoned builder");
        assert_eq!(out, vec![0xEE_u8; 7], "the caller's buffer must ride through intact");
    }
}

#[cfg(feature = "construct-groupless")]
mod construct_groupless {
    use super::*;
    use protobuf_edit::FieldNumber;
    use protobuf_edit::construct::groupless::Builder;

    const fn f(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    #[test]
    fn a_message_body_that_unwinds_refuses_to_emit() {
        hush();
        let mut b = Builder::new();
        let first = catch_unwind(AssertUnwindSafe(|| {
            b.message(f(1), |m| {
                m.push_varint(f(2), 1);
                panic!("body bomb");
            });
        }));
        assert!(first.is_err(), "the body panic must unwind");
        let second = catch_unwind(AssertUnwindSafe(|| b.finish()));
        assert!(
            second.is_err(),
            "the abandoned builder must refuse to emit, not publish uninit bytes"
        );
    }
    #[test]
    fn an_abandoned_builder_leaves_the_callers_buffer_untouched() {
        hush();
        let mut b = Builder::new();
        let first = catch_unwind(AssertUnwindSafe(|| {
            b.message(f(1), |m| {
                m.push_varint(f(2), 1);
                panic!("body bomb");
            });
        }));
        assert!(first.is_err(), "the body panic must unwind");
        // A caller buffer with recognizable contents: the refusal
        // must neither truncate nor extend nor overwrite it.
        let mut out = vec![0xEE_u8; 7];
        let second = catch_unwind(AssertUnwindSafe(|| {
            let _ = b.finish_into(&mut out);
        }));
        assert!(second.is_err(), "finish_into must refuse the abandoned builder");
        assert_eq!(out, vec![0xEE_u8; 7], "the caller's buffer must ride through intact");
    }
}
