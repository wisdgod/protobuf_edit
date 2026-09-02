//! Panic-location contract: a caller-fault panic reports the
//! caller's own line, not a line inside `src/`.
//!
//! One probe per documented chain shape: an in-face assert (const
//! fn), a bounds-checked gate one frame down (inspect), the same
//! gate two and three frames down (session queries, setters, and
//! anchored inserts), and a delegating face (scan's extractor
//! over its parser). The hook captures the reported `Location`;
//! every probe must land in this file — compared by exact file
//! identity — at its own invocation line, passed as `line!() + 1`
//! with the panicking call on the very next line. One negative
//! control pins the helper's discrimination, and the previously
//! installed hook is restored by a drop guard on both exits.
//!
//! Unconstructable contracts are exempt by mechanism equivalence:
//! `DocBytes::clone` overflow needs 2^32 live shares and the
//! traversal admission panics need a > 2 GiB slice, but both ride
//! the same assert/expect threading pinned here.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Mutex;

use protobuf_edit::Span;

static CAPTURED: Mutex<Option<(String, u32)>> = Mutex::new(None);

/// The standard hook carrier, spelled once.
type Hook = Box<dyn Fn(&panic::PanicHookInfo<'_>) + Sync + Send>;

/// Restores the previously installed hook on both exits — a failed
/// probe must not leave this judge's hook capturing other tests.
struct HookGuard(Option<Hook>);

impl Drop for HookGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            panic::set_hook(previous);
        }
    }
}

/// Runs a probe that must panic, and judges the reported location
/// exactly: the file is this one (exact identity, as the compiler
/// spells it) and the line is `want` — the caller passes
/// `line!() + 1` with the panicking call on the very next line.
#[track_caller]
fn location_of<F: FnOnce()>(label: &str, want: u32, probe: F) {
    let outcome = panic::catch_unwind(AssertUnwindSafe(probe));
    assert!(outcome.is_err(), "{label}: probe did not panic");
    let (file, line) = CAPTURED.lock().unwrap().take().expect(label);
    assert_eq!(file, file!(), "{label}: panicked in the wrong file (line {line})");
    assert_eq!(line, want, "{label}: the caller's own line is the contract");
}

#[test]
fn caller_fault_panics_report_at_the_caller() {
    let _guard = HookGuard(Some(panic::take_hook()));
    panic::set_hook(Box::new(|info| {
        if let Some(loc) = info.location() {
            *CAPTURED.lock().unwrap() = Some((loc.file().to_string(), loc.line()));
        }
    }));

    // The judge's own discrimination first: a deliberately wrong
    // expected line must be rejected by the same helper.
    let misjudged = panic::catch_unwind(AssertUnwindSafe(|| {
        location_of("negative control", line!() + 999, || {
            let _ = Span::new(2, 1);
        });
    }));
    assert!(misjudged.is_err(), "the helper accepted a deliberately wrong line");
    *CAPTURED.lock().unwrap() = None;

    // In-face assert in a const fn, one frame.
    location_of("Span::new", line!() + 1, || {
        let _ = Span::new(2, 1);
    });

    // In-face assert over the caller's reservation.
    location_of("emit64", line!() + 1, || {
        let _ = protobuf_edit::varint::emit64(u64::MAX, &mut [0u8; 2]);
    });

    // Bounds-checked id gate, one frame below the query face.
    #[cfg(feature = "inspect-grouped")]
    {
        use protobuf_edit::inspect::grouped::Tree;
        use protobuf_edit::inspect::{Admitted, NoAdvice, NodeId};
        let tree = Tree::parse(
            Admitted::new(&[0x08, 0x01]).unwrap(),
            protobuf_edit::DepthLimit::MIN,
            &mut NoAdvice,
        );
        let forged = NodeId::new(7).unwrap();
        location_of("inspect::grouped::Tree::kind", line!() + 1, || {
            let _ = tree.kind(forged);
        });
    }
    #[cfg(feature = "inspect-groupless")]
    {
        use protobuf_edit::inspect::groupless::Tree;
        use protobuf_edit::inspect::{Admitted, NoAdvice, NodeId};
        let tree = Tree::parse(
            Admitted::new(&[0x08, 0x01]).unwrap(),
            protobuf_edit::DepthLimit::MIN,
            &mut NoAdvice,
        );
        let forged = NodeId::new(7).unwrap();
        location_of("inspect::groupless::Tree::kind", line!() + 1, || {
            let _ = tree.kind(forged);
        });
    }

    // The fixed twin's id gate sits at the same depth below its
    // query faces; the forged handle panics at the caller.
    #[cfg(feature = "fixed-inspect-grouped")]
    {
        use core::mem::MaybeUninit;
        use protobuf_edit::fixed_inspect::grouped::{Plan, Tree};
        use protobuf_edit::inspect::{Admitted, NoAdvice, NodeId};
        let plan = Plan::new(1).unwrap();
        let mut slab = [MaybeUninit::<u8>::uninit(); 64];
        let tree = Tree::parse(
            Admitted::new(&[0x08, 0x01]).unwrap(),
            protobuf_edit::DepthLimit::MIN,
            &mut NoAdvice,
            &plan,
            &mut slab,
        )
        .unwrap();
        let forged = NodeId::new(7).unwrap();
        location_of("fixed_inspect::grouped::Tree::kind", line!() + 1, || {
            let _ = tree.kind(forged);
        });
    }
    #[cfg(feature = "fixed-inspect-groupless")]
    {
        use core::mem::MaybeUninit;
        use protobuf_edit::fixed_inspect::groupless::{Plan, Tree};
        use protobuf_edit::inspect::{Admitted, NoAdvice, NodeId};
        let plan = Plan::new(1).unwrap();
        let mut slab = [MaybeUninit::<u8>::uninit(); 64];
        let tree = Tree::parse(
            Admitted::new(&[0x08, 0x01]).unwrap(),
            protobuf_edit::DepthLimit::MIN,
            &mut NoAdvice,
            &plan,
            &mut slab,
        )
        .unwrap();
        let forged = NodeId::new(7).unwrap();
        location_of("fixed_inspect::groupless::Tree::kind", line!() + 1, || {
            let _ = tree.kind(forged);
        });
    }

    // Arena gate behind two (query), three (setter, after-anchored
    // insert), and four (tail-anchored insert, through the container
    // gate) frames below the face. The forged handle is a
    // third-record handle from a donor session, presented to a
    // one-record session.
    #[cfg(feature = "session-grouped")]
    {
        use protobuf_edit::session::grouped::{InsertAt, Session};
        let donor = Session::open_copy(&[0x08, 0x01, 0x10, 0x02, 0x18, 0x03]).unwrap();
        let forged = donor.top().nth(2).unwrap();
        let mut small = Session::open_copy(&[0x08, 0x01]).unwrap();
        location_of("session::grouped::Session::kind", line!() + 1, || {
            let _ = small.kind(forged);
        });
        location_of("session::grouped::Session::set_varint", line!() + 1, || {
            let _ = small.set_varint(forged, 9);
        });
        let field = protobuf_edit::FieldNumber::new(1).unwrap();
        location_of("session::grouped::Session::insert_varint", line!() + 1, || {
            let _ = small.insert_varint(InsertAt::After(forged), field, 1);
        });
        location_of("session::grouped::Session::insert_varint tail", line!() + 1, || {
            let _ = small.insert_varint(InsertAt::TailOf(Some(forged)), field, 1);
        });
    }
    #[cfg(feature = "session-groupless")]
    {
        use protobuf_edit::session::groupless::{InsertAt, Session};
        let donor = Session::open_copy(&[0x08, 0x01, 0x10, 0x02, 0x18, 0x03]).unwrap();
        let forged = donor.top().nth(2).unwrap();
        let mut small = Session::open_copy(&[0x08, 0x01]).unwrap();
        location_of("session::groupless::Session::kind", line!() + 1, || {
            let _ = small.kind(forged);
        });
        let field = protobuf_edit::FieldNumber::new(1).unwrap();
        location_of("session::groupless::Session::insert_varint", line!() + 1, || {
            let _ = small.insert_varint(InsertAt::After(forged), field, 1);
        });
        location_of("session::groupless::Session::insert_varint tail", line!() + 1, || {
            let _ = small.insert_varint(InsertAt::TailOf(Some(forged)), field, 1);
        });
    }

    // The patch's arena gate behind query, setter, and anchored
    // insert faces. The forged handle is a third-record handle from
    // a donor patch, presented to a one-record patch.
    #[cfg(feature = "patch-grouped")]
    {
        use protobuf_edit::DepthLimit;
        use protobuf_edit::patch::grouped::{InsertAt, Patch};
        let big = [0x08, 0x01, 0x10, 0x02, 0x18, 0x03];
        let donor = Patch::open(&big, DepthLimit::REFERENCE).unwrap();
        let forged = donor.top().nth(2).unwrap();
        let small_doc = [0x08, 0x01];
        let mut small = Patch::open(&small_doc, DepthLimit::REFERENCE).unwrap();
        location_of("patch::grouped::Patch::kind", line!() + 1, || {
            let _ = small.kind(forged);
        });
        location_of("patch::grouped::Patch::varint_word", line!() + 1, || {
            let _ = small.varint_word(forged);
        });
        location_of("patch::grouped::Patch::set_varint", line!() + 1, || {
            let _ = small.set_varint(forged, 9);
        });
        location_of("patch::grouped::Patch::descend", line!() + 1, || {
            let _ = small.descend(forged);
        });
        let field = protobuf_edit::FieldNumber::new(1).unwrap();
        location_of("patch::grouped::Patch::insert_varint", line!() + 1, || {
            let _ = small.insert_varint(InsertAt::After(forged), field, 1);
        });
        location_of("patch::grouped::Patch::insert_varint tail", line!() + 1, || {
            let _ = small.insert_varint(InsertAt::TailOf(Some(forged)), field, 1);
        });
    }
    #[cfg(feature = "patch-groupless")]
    {
        use protobuf_edit::DepthLimit;
        use protobuf_edit::patch::groupless::{InsertAt, Patch};
        let big = [0x08, 0x01, 0x10, 0x02, 0x18, 0x03];
        let donor = Patch::open(&big, DepthLimit::REFERENCE).unwrap();
        let forged = donor.top().nth(2).unwrap();
        let small_doc = [0x08, 0x01];
        let mut small = Patch::open(&small_doc, DepthLimit::REFERENCE).unwrap();
        location_of("patch::groupless::Patch::kind", line!() + 1, || {
            let _ = small.kind(forged);
        });
        location_of("patch::groupless::Patch::set_varint", line!() + 1, || {
            let _ = small.set_varint(forged, 9);
        });
        let field = protobuf_edit::FieldNumber::new(1).unwrap();
        location_of("patch::groupless::Patch::insert_varint", line!() + 1, || {
            let _ = small.insert_varint(InsertAt::After(forged), field, 1);
        });
        location_of("patch::groupless::Patch::insert_varint tail", line!() + 1, || {
            let _ = small.insert_varint(InsertAt::TailOf(Some(forged)), field, 1);
        });
    }

    // Terminal-stream assert, in-face on the router.
    #[cfg(feature = "route-grouped")]
    {
        use protobuf_edit::path::{Program, Segment};
        use protobuf_edit::route::grouped::Router;
        use protobuf_edit::route::Standard;
        let none: [&[Segment<'_>]; 0] = [];
        let program = Program::over(&none).unwrap();
        let mut x = Router::new(&program, Standard::Tolerant, protobuf_edit::DepthLimit::MIN);
        assert!(x.feed(&[0x0C], &mut ()).is_err(), "a stray group end must fault");
        location_of("route::grouped::Router::feed", line!() + 1, || {
            let _ = x.feed(&[0x08], &mut ());
        });
    }
    #[cfg(feature = "route-groupless")]
    {
        use protobuf_edit::path::{Program, Segment};
        use protobuf_edit::route::groupless::Router;
        use protobuf_edit::route::Standard;
        let none: [&[Segment<'_>]; 0] = [];
        let program = Program::over(&none).unwrap();
        let mut x = Router::new(&program, Standard::Tolerant, protobuf_edit::DepthLimit::MIN);
        assert!(x.feed(&[0x04], &mut ()).is_err(), "field zero must fault");
        location_of("route::groupless::Router::feed", line!() + 1, || {
            let _ = x.feed(&[0x08], &mut ());
        });
    }

    // Terminal-stream assert through the delegating validator face.
    #[cfg(feature = "scan-grouped")]
    {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::grouped::Validator;
        let mut x = Validator::new(Standard::Tolerant, protobuf_edit::DepthLimit::MIN);
        assert!(x.feed(&[0x0C]).is_err(), "a stray group end must fault");
        location_of("scan::grouped::Validator::feed", line!() + 1, || {
            let _ = x.feed(&[0x08]);
        });
    }
    #[cfg(feature = "scan-groupless")]
    {
        use protobuf_edit::scan::Standard;
        use protobuf_edit::scan::groupless::Validator;
        let mut x = Validator::new(Standard::Tolerant);
        assert!(x.feed(&[0x04]).is_err(), "field zero must fault");
        location_of("scan::groupless::Validator::feed", line!() + 1, || {
            let _ = x.feed(&[0x08]);
        });
    }

    // The abandoned-builder refusal through the finish face: a body
    // that unwound leaves the frame stack unpaired, and emitting
    // from that builder is the caller's fault to hear.
    #[cfg(feature = "construct-grouped")]
    {
        use protobuf_edit::construct::grouped::Builder;
        let field = protobuf_edit::FieldNumber::new(1).unwrap();
        let mut b = Builder::new();
        let bombed = panic::catch_unwind(AssertUnwindSafe(|| {
            b.message(field, |_| panic!("body bomb"));
        }));
        assert!(bombed.is_err(), "the body bomb must unwind");
        location_of("construct::grouped::Builder::finish", line!() + 1, || {
            let _ = b.finish();
        });
    }
    #[cfg(feature = "construct-groupless")]
    {
        use protobuf_edit::construct::groupless::Builder;
        let field = protobuf_edit::FieldNumber::new(1).unwrap();
        let mut b = Builder::new();
        let bombed = panic::catch_unwind(AssertUnwindSafe(|| {
            b.message(field, |_| panic!("body bomb"));
        }));
        assert!(bombed.is_err(), "the body bomb must unwind");
        location_of("construct::groupless::Builder::finish", line!() + 1, || {
            let _ = b.finish();
        });
    }
}
