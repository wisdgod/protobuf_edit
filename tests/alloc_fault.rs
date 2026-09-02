//! Allocator fault enumeration: every mutation command, on every
//! allocation it performs, must either succeed or return `Err`
//! with the session's abstract logical state unchanged.
//!
//! The armed allocator fails the Nth allocation (alloc and realloc
//! both count). The library's resource edges are all `try_reserve`,
//! so a null return surfaces as `Err(Resource)` — it never reaches
//! `handle_alloc_error`. An infallible allocation that slipped past
//! the protocol would abort the test process here, which is exactly
//! the exposure this harness buys.
//!
//! The fingerprint is the abstract state the protocol promises to
//! preserve on `Err`: the materialized tree with every row's kind,
//! field and status, the pending log length, the reverse index at
//! every document position, and the saved bytes. Capacity growth
//! and allocator traffic are explicitly outside the promise.
//!
//! A probe that never sees an `Err` proved nothing: every sweep
//! asserts at least one fault actually landed before it counts as
//! an enumeration.

#![cfg(all(
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "inspect-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "transfer-session-grouped",
    feature = "transfer-session-groupless",
    feature = "transfer-patch-groupless"
))]
#![feature(thread_id_value)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

struct Armed;

static COUNT: AtomicUsize = AtomicUsize::new(0);
/// Requested-layout byte observation beside the call count: a call
/// count alone cannot refute a document-sized allocation (one
/// `input.len()` request is one call), so the size claims are
/// judged on the armed thread's requested bytes — the running
/// total and the largest single request.
static BYTES_TOTAL: AtomicUsize = AtomicUsize::new(0);
static BYTES_MAX: AtomicUsize = AtomicUsize::new(0);
static FAIL_AT: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Faults hit only the armed thread: the test harness and sibling
/// tests allocate concurrently and must never be shot.
static ARMED_THREAD: AtomicU64 = AtomicU64::new(0);

fn on_armed_thread() -> bool {
    std::thread::current().id().as_u64().get() == ARMED_THREAD.load(Ordering::Relaxed)
}

/// Books one armed-thread request's size.
fn observe(size: usize) {
    BYTES_TOTAL.fetch_add(size, Ordering::Relaxed);
    BYTES_MAX.fetch_max(size, Ordering::Relaxed);
}

/// One recorded allocator event: `ALLOC` starts a lineage at its
/// returned address; `REALLOC` moves the lineage owning its old
/// address. Deallocations are not recorded — a reused address
/// retires its dead lineage at the next `ALLOC` (see
/// [`lineage_peaks`]).
const ALLOC: usize = 1;
const REALLOC: usize = 2;

/// Fixed event slots, written lock- and allocation-free from the
/// allocator hooks (a `Vec` or `Mutex` here would re-enter the
/// armed allocator). Each slot is `[kind, old, new, size]`. The
/// snapshot refuses an overflowing window instead of truncating
/// it silently.
const EVENT_CAP: usize = 4096;
static EVENT_ON: AtomicBool = AtomicBool::new(false);
static EVENT_LEN: AtomicUsize = AtomicUsize::new(0);
static EVENTS: [[AtomicUsize; 4]; EVENT_CAP] =
    [const { [const { AtomicUsize::new(0) }; 4] }; EVENT_CAP];

/// Books one armed-thread event while a traced window is open.
fn record_event(kind: usize, old: usize, new: usize, size: usize) {
    if !EVENT_ON.load(Ordering::Relaxed) {
        return;
    }
    let at = EVENT_LEN.fetch_add(1, Ordering::Relaxed);
    if let Some(slot) = EVENTS.get(at) {
        slot[0].store(kind, Ordering::Relaxed);
        slot[1].store(old, Ordering::Relaxed);
        slot[2].store(new, Ordering::Relaxed);
        slot[3].store(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Armed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if on_armed_thread() {
            observe(layout.size());
            if COUNT.fetch_add(1, Ordering::Relaxed) == FAIL_AT.load(Ordering::Relaxed) {
                return core::ptr::null_mut();
            }
            let ptr = unsafe { System.alloc(layout) };
            record_event(ALLOC, 0, ptr as usize, layout.size());
            return ptr;
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if on_armed_thread() {
            observe(new_size);
            if COUNT.fetch_add(1, Ordering::Relaxed) == FAIL_AT.load(Ordering::Relaxed) {
                return core::ptr::null_mut();
            }
            let moved = unsafe { System.realloc(ptr, layout, new_size) };
            record_event(REALLOC, ptr as usize, moved as usize, new_size);
            return moved;
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Armed = Armed;

/// Serializes armed windows across test threads.
static ARM_LOCK: Mutex<()> = Mutex::new(());

/// Takes the armed window, shrugging off poison: a sibling probe's
/// panic already reports itself, and the lock guards no state.
fn arm_window() -> std::sync::MutexGuard<'static, ()> {
    ARM_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn arm(nth: usize) {
    ARMED_THREAD.store(std::thread::current().id().as_u64().get(), Ordering::Relaxed);
    FAIL_AT.store(COUNT.load(Ordering::Relaxed) + nth, Ordering::Relaxed);
}

fn disarm() {
    FAIL_AT.store(usize::MAX, Ordering::Relaxed);
    ARMED_THREAD.store(0, Ordering::Relaxed);
}

/// Counts allocations across `job` without arming a failure: `arm`
/// with an unreachable countdown keeps the thread counted and the
/// allocator honest.
fn counted<T>(job: impl FnOnce() -> T) -> (T, usize) {
    let _guard = arm_window();
    arm(usize::MAX / 2);
    let before = COUNT.load(Ordering::Relaxed);
    let out = job();
    let grew = COUNT.load(Ordering::Relaxed) - before;
    disarm();
    (out, grew)
}

/// One job's whole allocation account: the call count, the largest
/// single requested layout, and the total requested bytes — the
/// byte observation that makes "no document-sized allocation"
/// refutable (a call count alone cannot see size).
fn measured<T>(job: impl FnOnce() -> T) -> (T, usize, usize, usize) {
    let _guard = arm_window();
    arm(usize::MAX / 2);
    let count_before = COUNT.load(Ordering::Relaxed);
    let total_before = BYTES_TOTAL.load(Ordering::Relaxed);
    BYTES_MAX.store(0, Ordering::Relaxed);
    let out = job();
    let count = COUNT.load(Ordering::Relaxed) - count_before;
    let total = BYTES_TOTAL.load(Ordering::Relaxed) - total_before;
    let max = BYTES_MAX.load(Ordering::Relaxed);
    disarm();
    (out, count, max, total)
}

/// One snapshot event: the kind, the old address (zero for
/// [`ALLOC`]), the new address, and the requested size.
type AllocEvent = (usize, usize, usize, usize);

/// [`measured`] plus the per-allocation event list: one
/// [`AllocEvent`] per armed-thread request, the identity
/// observation that makes "one allocation lineage" refutable (byte
/// totals leave slack a whole extra buffer can hide in). The
/// snapshot is taken after recording stops, so its own `Vec` never
/// books.
fn traced<T>(job: impl FnOnce() -> T) -> (T, Vec<AllocEvent>, usize, usize) {
    let _guard = arm_window();
    arm(usize::MAX / 2);
    BYTES_MAX.store(0, Ordering::Relaxed);
    let total_before = BYTES_TOTAL.load(Ordering::Relaxed);
    EVENT_LEN.store(0, Ordering::Relaxed);
    EVENT_ON.store(true, Ordering::Relaxed);
    let out = job();
    EVENT_ON.store(false, Ordering::Relaxed);
    let len = EVENT_LEN.load(Ordering::Relaxed);
    assert!(len <= EVENT_CAP, "traced window overflowed the event slots: {len}");
    let events = EVENTS[..len]
        .iter()
        .map(|slot| {
            (
                slot[0].load(Ordering::Relaxed),
                slot[1].load(Ordering::Relaxed),
                slot[2].load(Ordering::Relaxed),
                slot[3].load(Ordering::Relaxed),
            )
        })
        .collect();
    let total = BYTES_TOTAL.load(Ordering::Relaxed) - total_before;
    let max = BYTES_MAX.load(Ordering::Relaxed);
    disarm();
    (out, events, max, total)
}

/// Folds an event list into allocation lineages and answers each
/// lineage's peak request. An `ALLOC` starts a lineage at its
/// address (retiring any dead lineage that ended there — the
/// address was free to be reused); a `REALLOC` extends the lineage
/// owning its old address, wherever the block moved. Growing a
/// buffer through `Vec` is therefore one lineage however many
/// doubling steps it takes, while a second logical buffer of any
/// provenance starts a second lineage.
fn lineage_peaks(events: &[AllocEvent]) -> Vec<usize> {
    let mut tip = std::collections::HashMap::new();
    let mut peaks: Vec<usize> = Vec::new();
    for &(kind, old, new, size) in events {
        match kind {
            ALLOC => {
                tip.insert(new, peaks.len());
                peaks.push(size);
            }
            REALLOC => {
                let chain = tip.remove(&old).unwrap_or_else(|| {
                    // The lineage predates the traced window; its
                    // peak inside the window still counts.
                    peaks.push(0);
                    peaks.len() - 1
                });
                peaks[chain] = peaks[chain].max(size);
                tip.insert(new, chain);
            }
            _ => unreachable!("unknown allocator event kind {kind}"),
        }
    }
    peaks
}

#[track_caller]
fn h(s: &str) -> Vec<u8> {
    let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    hex.chunks(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap();
            let lo = (p[1] as char).to_digit(16).unwrap();
            (hi * 16 + lo) as u8
        })
        .collect()
}

macro_rules! dialect_probe {
    ($mod_name:ident, $session:path, open: $open:ident, $src:ident, $handle:path, $insert_at:path,
     $status:path, $kind:path, $descent:path) => {
        mod $mod_name {
            use super::*;

            use $session as Session;
            use $descent as Descent;
            use $handle as Handle;
            use $insert_at as InsertAt;
            use $kind as RecordKind;
            use $status as EditStatus;

            /// One row's observable identity, in topological order.
            type RowPrint = (usize, RecordKind, u32, EditStatus);

            fn shape(s: &Session, handle: Handle, depth: usize, out: &mut Vec<RowPrint>) {
                out.push((
                    depth,
                    s.kind(handle).unwrap(),
                    s.field(handle).unwrap().as_inner(),
                    s.status(handle).unwrap(),
                ));
                for kid in s.children(handle).unwrap() {
                    shape(s, kid, depth + 1, out);
                }
            }

            /// The deep digest of the abstract state the protocol
            /// promises to preserve on `Err`: the materialized tree
            /// (each row's kind, field and status, topological
            /// order), the pending log length, the reverse index at
            /// every document position, and the saved bytes.
            fn fingerprint(s: &Session) -> (Vec<RowPrint>, usize, Vec<Option<Handle>>, Vec<u8>) {
                let mut tree = Vec::new();
                for top in s.top() {
                    shape(s, top, 0, &mut tree);
                }
                let sweep = u32::try_from(s.$src()[..].len()).unwrap() + 2;
                let index: Vec<Option<Handle>> = (0..sweep).map(|pos| s.narrowest(pos)).collect();
                (tree, s.pending(), index, s.save().unwrap().as_slice().to_vec())
            }

            /// Runs `cmd` under allocation fault `nth` after an
            /// unarmed `setup`; `true` from `cmd` means the command
            /// succeeded (stop scanning). On success the sweep must
            /// have injected at least one fault, and `follow` runs
            /// one unarmed mutation so the in-crate lattice oracle
            /// judges the state the command published.
            pub fn probe_all(
                setup: impl Fn(&mut Session),
                mut cmd: impl FnMut(&mut Session) -> bool,
                follow: impl Fn(&mut Session),
                doc: &[u8],
            ) {
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Session::$open(doc).expect("probe doc opens");
                    setup(&mut s);
                    let before = fingerprint(&s);
                    arm(nth);
                    let ok = cmd(&mut s);
                    disarm();
                    if ok {
                        assert!(nth > 0, "probe enumerated zero allocation points");
                        follow(&mut s);
                        return;
                    }
                    let after = fingerprint(&s);
                    assert_eq!(before, after, "state changed on Err at allocation {nth}");
                }
                panic!("command still failing after 32 injected faults");
            }

            #[test]
            fn set_varint_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_varint(t, 7).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn set_i32_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_i32(t, 0xAB).is_ok()
                    },
                    |_| {},
                    &h("0D01000000 1101000000 00000000"),
                );
            }

            #[test]
            fn set_i64_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_i64(t, 0xCD).is_ok()
                    },
                    |_| {},
                    &h("0D01000000 1101000000 00000000"),
                );
            }

            #[test]
            fn set_payload_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        // No allocation inside the armed window:
                        // nth, not collect.
                        let t = s.top().nth(1).unwrap();
                        s.set_payload(t, b"world").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_varint_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_varint(InsertAt::After(t), f9, 1).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_i32_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_i32(InsertAt::After(t), f9, 0xAB).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_i64_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_i64(InsertAt::After(t), f9, 0xCD).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_payload_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_payload(InsertAt::After(t), f9, b"xyz").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn delete_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.delete(t).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn undelete_is_atomic_under_allocator_faults() {
                probe_all(
                    // 63 replacements and one delete leave the log
                    // at len == cap == 64, a `Vec` doubling
                    // boundary, so the command's own `try_reserve`
                    // must allocate; the zero-point assert in
                    // `probe_all` goes red if the growth policy
                    // ever drifts off powers of two.
                    |s| {
                        let t = s.top().next().unwrap();
                        for i in 0..63 {
                            s.set_varint(t, i).expect("setup replace");
                        }
                        s.delete(t).expect("setup delete");
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.undelete(t).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn clear_edit_is_atomic_under_allocator_faults() {
                probe_all(
                    // 64 replacements leave the log at len == cap
                    // == 64, a `Vec` doubling boundary, so the
                    // command's own `try_reserve` must allocate;
                    // the zero-point assert in `probe_all` goes red
                    // if the growth policy ever drifts off powers
                    // of two.
                    |s| {
                        let t = s.top().next().unwrap();
                        for i in 0..64 {
                            s.set_varint(t, i).expect("setup replace");
                        }
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.clear_edit(t).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn authored_descend_is_atomic_under_allocator_faults() {
                // The replaced payload scans out of the store:
                // `seal_scan` publishes a layer with no source run.
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_payload(t, &h("089601")).expect("setup replaces the payload");
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.descend(t).is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A0161 089601"),
                );
            }

            #[test]
            fn tail_insert_into_a_descended_layer_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        let opened = s.descend(t).expect("setup descends");
                        assert!(matches!(opened, Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_varint(InsertAt::TailOf(Some(t)), f9, 5).is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A03089601 089601"),
                );
            }

            #[test]
            fn set_payload_over_an_opened_interior_is_atomic_under_allocator_faults() {
                // The flip orphans the opened interior and unseals
                // the slot.
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        let opened = s.descend(t).expect("setup descends");
                        assert!(matches!(opened, Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_payload(t, b"zz").is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A03089601 089601"),
                );
            }

            #[test]
            fn descend_resource_refusals_leave_the_slot_unopened() {
                let doc = h("12 05 08 96 01 10 07");
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Session::$open(&doc).expect("probe doc opens");
                    let t = s.top().next().unwrap();
                    let before = fingerprint(&s);
                    arm(nth);
                    let outcome = s.descend(t);
                    let ok = outcome.is_ok();
                    disarm();
                    if ok {
                        assert!(nth > 0, "probe enumerated zero allocation points");
                        return;
                    }
                    let after = fingerprint(&s);
                    assert_eq!(before, after, "state changed on Err at allocation {nth}");
                    // Retry must now succeed cleanly (the slot
                    // stayed unopened, no half-scanned layer).
                    assert!(s.descend(t).is_ok(), "retry after fault {nth} failed");
                }
                panic!("descend still failing after 32 injected faults");
            }

            #[test]
            fn save_is_fallible_throughout_and_prepayment_holds() {
                // A dirty session with a nested spine: the dirt
                // sits on the innermost leaf, so save walks both
                // passes and the emit stack through three spine
                // levels. Every allocation (sizes, spine
                // prepayment, output block) must be reportable; an
                // abort here would falsify either SaveFault::Resource
                // or the emit prepayment argument.
                let doc = h("12 07 12 05 12 03 08 96 01 089601");
                let _guard = arm_window();
                for nth in 0..64 {
                    let mut s = Session::$open(&doc).expect("probe doc opens");
                    let mut cur = s.top().next().unwrap();
                    for _ in 0..3 {
                        let opened = s.descend(cur).expect("spine level opens");
                        assert!(matches!(opened, Descent::Opened { .. }));
                        cur = s.children(cur).unwrap().next().unwrap();
                    }
                    s.set_varint(cur, 9).unwrap();
                    arm(nth);
                    let outcome = s.save();
                    disarm();
                    match outcome {
                        Ok(bytes) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(&bytes.as_slice()[..1], &[0x12]);
                            return;
                        }
                        Err(e) => {
                            let d = format!("{e:?}");
                            assert!(d.contains("Resource"), "unexpected save fault: {d}");
                        }
                    }
                }
                panic!("save still failing after 64 injected faults");
            }

            #[test]
            fn save_into_reports_refusals_with_the_buffer_untouched() {
                // The Vec face's fault contract: every Err leaves
                // the caller's buffer at its incoming length and
                // content — the reservation is the one fallible
                // edge past the sizing pass.
                let doc = h("12 07 12 05 12 03 08 96 01 089601");
                let _guard = arm_window();
                for nth in 0..64 {
                    let mut s = Session::$open(&doc).expect("probe doc opens");
                    let mut cur = s.top().next().unwrap();
                    for _ in 0..3 {
                        let opened = s.descend(cur).expect("spine level opens");
                        assert!(matches!(opened, Descent::Opened { .. }));
                        cur = s.children(cur).unwrap().next().unwrap();
                    }
                    s.set_varint(cur, 9).unwrap();
                    let mut out = vec![0xAA, 0xBB];
                    arm(nth);
                    let outcome = s.save_into(&mut out);
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(&out[..2], &[0xAA, 0xBB], "the prefix is untouched");
                            assert_eq!(out[2..], *s.save().unwrap().as_slice());
                            return;
                        }
                        Err(e) => {
                            let d = format!("{e:?}");
                            assert!(d.contains("Resource"), "unexpected save fault: {d}");
                            assert_eq!(out, [0xAA, 0xBB], "Err leaves the buffer untouched");
                        }
                    }
                }
                panic!("save_into still failing after 64 injected faults");
            }

            #[test]
            fn payload_frame_set_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        let Ok(mut frame) = s.begin_set_payload(t) else {
                            return false;
                        };
                        if frame.write(b"wor").is_err() || frame.write(b"ld!").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn payload_frame_insert_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        let Ok(mut frame) = s.begin_insert_payload(InsertAt::After(t), f9) else {
                            return false;
                        };
                        if frame.write(b"xy").is_err() || frame.write(b"z").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn sized_payload_frame_set_is_atomic_under_allocator_faults() {
                // The sized door's reservation is its one fallible
                // allocation; a refusal there must leave the
                // session unchanged, and the writes behind a held
                // reservation cannot fail.
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        let Ok(mut frame) = s.begin_set_payload_sized(t, 6) else {
                            return false;
                        };
                        if frame.write(b"wor").is_err() || frame.write(b"ld!").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn sized_payload_frame_insert_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        let Ok(mut frame) = s.begin_insert_payload_sized(InsertAt::After(t), f9, 3)
                        else {
                            return false;
                        };
                        if frame.write(b"xy").is_err() || frame.write(b"z").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn sized_frame_writes_spend_the_doors_reservation() {
                // The sized door judged and reserved the whole
                // declaration, so the write path owes zero allocator
                // traffic: with the very next allocation armed to
                // fail, every write must still succeed.
                let doc = h("089601 12026869");
                let expected = h("089601 1206776F726C6421");
                let _guard = arm_window();
                let mut s = Session::$open(&doc).expect("probe doc opens");
                let t = s.top().nth(1).unwrap();
                let mut frame = s.begin_set_payload_sized(t, 6).unwrap();
                arm(0);
                let first = frame.write(b"wor");
                let second = frame.write(b"ld!");
                disarm();
                first.expect("a sized write allocated after the door's reservation");
                second.expect("a sized write allocated after the door's reservation");
                frame.finish().unwrap();
                assert_eq!(s.save().unwrap().as_slice(), expected.as_slice());
            }

            #[test]
            fn sized_door_refusals_touch_no_allocator() {
                // The class judgment precedes the reservation, so an
                // over-class declaration refuses before any allocator
                // call: with the very next allocation armed to fail,
                // the refusal must still be the class refusal —
                // allocator traffic would surface as Resource or
                // abort the probe.
                let doc = h("089601 12026869");
                let over = (i32::MAX as usize) + 1;
                let _guard = arm_window();
                let mut s = Session::$open(&doc).expect("probe doc opens");
                let t = s.top().nth(1).unwrap();
                arm(0);
                let refused = s.begin_set_payload_sized(t, over).err();
                disarm();
                let d = format!("{refused:?}");
                assert!(
                    d.contains("PayloadTooLarge"),
                    "over-class declaration must refuse without touching the allocator: {d}"
                );
            }

            #[test]
            fn save_sink_hands_nothing_before_the_sizing_pass_settles() {
                // The sink face's fault contract: every Err
                // precedes the first handoff — the sizing pass
                // fronts each allocation, so a refusal at any of
                // them leaves the sink untouched.
                let doc = h("12 07 12 05 12 03 08 96 01 089601");
                let _guard = arm_window();
                for nth in 0..64 {
                    let mut s = Session::$open(&doc).expect("probe doc opens");
                    let mut cur = s.top().next().unwrap();
                    for _ in 0..3 {
                        let opened = s.descend(cur).expect("spine level opens");
                        assert!(matches!(opened, Descent::Opened { .. }));
                        cur = s.children(cur).unwrap().next().unwrap();
                    }
                    s.set_varint(cur, 9).unwrap();
                    let mut handed = 0usize;
                    arm(nth);
                    let outcome = s.save_sink(|slice| handed += slice.len());
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(handed, s.save().unwrap().as_slice().len());
                            return;
                        }
                        Err(e) => {
                            let d = format!("{e:?}");
                            assert!(d.contains("Resource"), "unexpected save fault: {d}");
                            assert_eq!(handed, 0, "Err at allocation {nth} handed the sink bytes");
                        }
                    }
                }
                panic!("save_sink still failing after 64 injected faults");
            }

            #[test]
            fn open_reports_early_allocator_refusals() {
                let doc = h("089601");
                let _guard = arm_window();
                for nth in 0..32 {
                    arm(nth);
                    let outcome = Session::$open(&doc);
                    disarm();
                    match outcome {
                        Ok(_) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            return;
                        }
                        Err(e) => {
                            let d = format!("{e:?}");
                            assert!(
                                d.contains("Resource") || d.contains("Alloc"),
                                "unexpected open fault under allocator pressure: {d}"
                            );
                        }
                    }
                }
                panic!("open still failing after 32 injected faults");
            }
        }
    };
}

dialect_probe!(
    grouped,
    protobuf_edit::session::grouped::Session,
    open: open_copy,
    doc,
    protobuf_edit::session::Handle,
    protobuf_edit::session::grouped::InsertAt,
    protobuf_edit::session::grouped::EditStatus,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::session::grouped::Descent
);

dialect_probe!(
    groupless,
    protobuf_edit::session::groupless::Session,
    open: open_copy,
    doc,
    protobuf_edit::session::Handle,
    protobuf_edit::session::groupless::InsertAt,
    protobuf_edit::session::groupless::EditStatus,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::session::groupless::Descent
);

// The draft shares the session's growth edges verbatim — store,
// log, arena, layer, run, and save reservations — so the same
// probe battery drives it; only the source accessor differs
// (`source`, the moved-in buffer).
dialect_probe!(
    draft_grouped,
    protobuf_edit::draft::grouped::Draft,
    open: open_copy,
    source,
    protobuf_edit::draft::Handle,
    protobuf_edit::draft::grouped::InsertAt,
    protobuf_edit::draft::grouped::EditStatus,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::draft::grouped::Descent
);

dialect_probe!(
    draft_groupless,
    protobuf_edit::draft::groupless::Draft,
    open: open_copy,
    source,
    protobuf_edit::draft::Handle,
    protobuf_edit::draft::groupless::InsertAt,
    protobuf_edit::draft::groupless::EditStatus,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::draft::groupless::Descent
);

// The markup borrows its source, so the probe battery constructs
// through the borrow door; every growth edge past the door is the
// family core's, shared with the session and draft probes.
dialect_probe!(
    markup_grouped,
    protobuf_edit::markup::grouped::Markup,
    open: open,
    source,
    protobuf_edit::markup::Handle,
    protobuf_edit::markup::grouped::InsertAt,
    protobuf_edit::markup::grouped::EditStatus,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::markup::grouped::Descent
);

dialect_probe!(
    markup_groupless,
    protobuf_edit::markup::groupless::Markup,
    open: open,
    source,
    protobuf_edit::markup::Handle,
    protobuf_edit::markup::groupless::InsertAt,
    protobuf_edit::markup::groupless::EditStatus,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::markup::groupless::Descent
);

// The review is the markup's canonical twin: the same borrow door
// and the same growth edges past it. Every battery document is
// minimal wire, so the canonical door admits them all.
dialect_probe!(
    review_grouped,
    protobuf_edit::review::grouped::Review,
    open: open,
    source,
    protobuf_edit::review::Handle,
    protobuf_edit::review::grouped::InsertAt,
    protobuf_edit::review::grouped::EditStatus,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::review::grouped::Descent
);

dialect_probe!(
    review_groupless,
    protobuf_edit::review::groupless::Review,
    open: open,
    source,
    protobuf_edit::review::Handle,
    protobuf_edit::review::groupless::InsertAt,
    protobuf_edit::review::groupless::EditStatus,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::review::groupless::Descent
);

// The borrowed-payload siblings share the copy-only machines'
// growth edges except the payload channel: an install grows the
// slot table (one `try_reserve`d slot, no byte staging) beside the
// log, and an authored descend rescans a borrowed slot. The frame
// rows have no twin here — no staged frames exist without a copied
// column.
macro_rules! borrow_probe {
    ($mod_name:ident, $machine:path, open: $open:ident, sig: [$($sig:tt)*], any: [$($any:tt)*], $src:ident, $handle:path, $insert_at:path, $descent:path) => {
        mod $mod_name {
            use super::*;

            use $descent as Descent;
            use $handle as Handle;
            use $insert_at as InsertAt;
            use $machine as Machine;

            /// The observable state the protocol promises to
            /// preserve on `Err`: the pending log length, the saved
            /// bytes, and the reverse index at every position.
            fn fingerprint(s: &Machine<$($any)*>) -> (usize, Vec<u8>, Vec<Option<Handle>>) {
                let sweep = u32::try_from(s.$src()[..].len()).unwrap() + 2;
                let index = (0..sweep).map(|pos| s.narrowest(pos)).collect();
                (s.pending(), s.save().unwrap().as_slice().to_vec(), index)
            }

            /// Runs `cmd` under allocation fault `nth` after an
            /// unarmed `setup`; `true` from `cmd` means the command
            /// succeeded (stop scanning). On success the sweep must
            /// have injected at least one fault, and `follow` runs
            /// one unarmed mutation so the in-crate lattice oracle
            /// judges the state the command published. `'p` is the
            /// test's payload tenure: every probe machine borrows
            /// its installs from owners the caller keeps alive.
            pub fn probe_all<'p>(
                setup: impl Fn(&mut Machine<$($sig)*>),
                mut cmd: impl FnMut(&mut Machine<$($sig)*>) -> bool,
                follow: impl Fn(&mut Machine<$($sig)*>),
                doc: &[u8],
            ) {
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Machine::$open(doc).expect("probe doc opens");
                    setup(&mut s);
                    let before = fingerprint(&s);
                    arm(nth);
                    let ok = cmd(&mut s);
                    disarm();
                    if ok {
                        assert!(nth > 0, "probe enumerated zero allocation points");
                        follow(&mut s);
                        return;
                    }
                    let after = fingerprint(&s);
                    assert_eq!(before, after, "state changed on Err at allocation {nth}");
                }
                panic!("command still failing after 32 injected faults");
            }

            #[test]
            fn set_payload_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_payload(t, b"world").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_payload_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_payload(InsertAt::After(t), f9, b"xyz").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn slot_installs_over_a_grown_log_stay_atomic() {
                // 63 replacements and one delete leave the log at
                // len == cap == 64, a `Vec` doubling boundary, so
                // the install's own log reservation must allocate
                // beside the slot push.
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        for i in 0..64 {
                            s.set_varint(t, i).expect("setup replace");
                        }
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_payload(t, b"grown").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn authored_descend_is_atomic_under_allocator_faults() {
                // The replaced payload scans out of its borrowed
                // slot: `seal_scan` publishes a layer with no
                // source run, and a fault must discard the
                // provisional rows whole. The payload owner lives
                // through the sweep — the machines borrow it.
                let payload = h("089601");
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_payload(t, &payload).expect("setup replaces the payload");
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.descend(t).is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A0161 089601"),
                );
            }

            #[test]
            fn set_payload_over_an_opened_interior_is_atomic_under_allocator_faults() {
                // The flip orphans the opened interior and unseals
                // the slot.
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        let opened = s.descend(t).expect("setup descends");
                        assert!(matches!(opened, Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_payload(t, b"zz").is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A03089601 089601"),
                );
            }

            #[test]
            fn open_reports_early_allocator_refusals() {
                let doc = h("089601");
                let _guard = arm_window();
                for nth in 0..32 {
                    arm(nth);
                    let outcome = Machine::$open(&doc);
                    disarm();
                    match outcome {
                        Ok(_) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            return;
                        }
                        Err(e) => {
                            let d = format!("{e:?}");
                            assert!(
                                d.contains("Resource") || d.contains("Alloc"),
                                "unexpected open fault under allocator pressure: {d}"
                            );
                        }
                    }
                }
                panic!("open still failing after 32 injected faults");
            }
        }
    };
}

borrow_probe!(
    borrow_session_grouped,
    protobuf_edit::session::grouped::BorrowSession,
    open: open_copy,
    sig: ['p],
    any: ['_],
    doc,
    protobuf_edit::session::Handle,
    protobuf_edit::session::grouped::InsertAt,
    protobuf_edit::session::grouped::Descent
);

borrow_probe!(
    borrow_session_groupless,
    protobuf_edit::session::groupless::BorrowSession,
    open: open_copy,
    sig: ['p],
    any: ['_],
    doc,
    protobuf_edit::session::Handle,
    protobuf_edit::session::groupless::InsertAt,
    protobuf_edit::session::groupless::Descent
);

borrow_probe!(
    borrow_draft_grouped,
    protobuf_edit::draft::grouped::BorrowDraft,
    open: open_copy,
    sig: ['p],
    any: ['_],
    source,
    protobuf_edit::draft::Handle,
    protobuf_edit::draft::grouped::InsertAt,
    protobuf_edit::draft::grouped::Descent
);

borrow_probe!(
    borrow_draft_groupless,
    protobuf_edit::draft::groupless::BorrowDraft,
    open: open_copy,
    sig: ['p],
    any: ['_],
    source,
    protobuf_edit::draft::Handle,
    protobuf_edit::draft::groupless::InsertAt,
    protobuf_edit::draft::groupless::Descent
);

borrow_probe!(
    borrow_markup_grouped,
    protobuf_edit::markup::grouped::BorrowMarkup,
    open: open,
    sig: ['_, 'p],
    any: ['_, '_],
    source,
    protobuf_edit::markup::Handle,
    protobuf_edit::markup::grouped::InsertAt,
    protobuf_edit::markup::grouped::Descent
);

borrow_probe!(
    borrow_markup_groupless,
    protobuf_edit::markup::groupless::BorrowMarkup,
    open: open,
    sig: ['_, 'p],
    any: ['_, '_],
    source,
    protobuf_edit::markup::Handle,
    protobuf_edit::markup::groupless::InsertAt,
    protobuf_edit::markup::groupless::Descent
);

borrow_probe!(
    borrow_review_grouped,
    protobuf_edit::review::grouped::BorrowReview,
    open: open,
    sig: ['_, 'p],
    any: ['_, '_],
    source,
    protobuf_edit::review::Handle,
    protobuf_edit::review::grouped::InsertAt,
    protobuf_edit::review::grouped::Descent
);

borrow_probe!(
    borrow_review_groupless,
    protobuf_edit::review::groupless::BorrowReview,
    open: open,
    sig: ['_, 'p],
    any: ['_, '_],
    source,
    protobuf_edit::review::Handle,
    protobuf_edit::review::groupless::InsertAt,
    protobuf_edit::review::groupless::Descent
);

// The mixed-backing siblings carry both publication paths: the
// unsuffixed faces reserve one slot beside the log (no byte
// staging), the `_copy` and frame faces reserve the copied byte
// column and the slot, and an authored descend rescans whichever
// backing the effective install names — so every armed row runs
// per backing, and the counting rows pin each backing's selected
// cost (a borrowed install never allocates at payload scale, a
// copied install stages its bytes exactly once, a revert allocates
// nothing).
macro_rules! mix_probe {
    ($mod_name:ident, $machine:path, open: $open:ident, sig: [$($sig:tt)*], any: [$($any:tt)*], $src:ident, $handle:path, $insert_at:path, $descent:path) => {
        mod $mod_name {
            use super::*;

            use $descent as Descent;
            use $handle as Handle;
            use $insert_at as InsertAt;
            use $machine as Machine;

            /// The observable state the protocol promises to
            /// preserve on `Err`: the pending log length, the saved
            /// bytes, and the reverse index at every position.
            fn fingerprint(s: &Machine<$($any)*>) -> (usize, Vec<u8>, Vec<Option<Handle>>) {
                let sweep = u32::try_from(s.$src()[..].len()).unwrap() + 2;
                let index = (0..sweep).map(|pos| s.narrowest(pos)).collect();
                (s.pending(), s.save().unwrap().as_slice().to_vec(), index)
            }

            /// Runs `cmd` under allocation fault `nth` after an
            /// unarmed `setup`; `true` from `cmd` means the command
            /// succeeded (stop scanning). On success the sweep must
            /// have injected at least one fault, and `follow` runs
            /// one unarmed mutation so the in-crate lattice oracle
            /// judges the state the command published. `'p` is the
            /// test's payload tenure: every probe machine borrows
            /// its unsuffixed installs from owners the caller keeps
            /// alive.
            pub fn probe_all<'p>(
                setup: impl Fn(&mut Machine<$($sig)*>),
                mut cmd: impl FnMut(&mut Machine<$($sig)*>) -> bool,
                follow: impl Fn(&mut Machine<$($sig)*>),
                doc: &[u8],
            ) {
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Machine::$open(doc).expect("probe doc opens");
                    setup(&mut s);
                    let before = fingerprint(&s);
                    arm(nth);
                    let ok = cmd(&mut s);
                    disarm();
                    if ok {
                        assert!(nth > 0, "probe enumerated zero allocation points");
                        follow(&mut s);
                        return;
                    }
                    let after = fingerprint(&s);
                    assert_eq!(before, after, "state changed on Err at allocation {nth}");
                }
                panic!("command still failing after 32 injected faults");
            }

            #[test]
            fn set_payload_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_payload(t, b"world").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn set_payload_copy_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_payload_copy(t, b"world").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_payload_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_payload(InsertAt::After(t), f9, b"xyz").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_payload_copy_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_payload_copy(InsertAt::After(t), f9, b"xyz").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn slot_installs_over_a_grown_log_stay_atomic() {
                // 63 replacements and one delete leave the log at
                // len == cap == 64, a `Vec` doubling boundary, so
                // each install's own log reservation must allocate
                // beside its store pushes — for both backings.
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        for i in 0..64 {
                            s.set_varint(t, i).expect("setup replace");
                        }
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_payload(t, b"grown").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        for i in 0..64 {
                            s.set_varint(t, i).expect("setup replace");
                        }
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_payload_copy(t, b"grown").is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn authored_descend_is_atomic_for_the_borrowed_backing() {
                // The replaced payload scans out of its borrowed
                // slot: the provisional row (and, in the grouped
                // dialect, layer) tables must discard whole on a
                // fault. The payload owner lives through the sweep.
                let payload = h("089601");
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_payload(t, &payload).expect("setup replaces the payload");
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.descend(t).is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A0161 089601"),
                );
            }

            #[test]
            fn authored_descend_is_atomic_for_the_copied_backing() {
                // The same discipline over the copied extent's own
                // zone.
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        let transient = h("089601");
                        s.set_payload_copy(t, &transient).expect("setup replaces the payload");
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.descend(t).is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A0161 089601"),
                );
            }

            #[test]
            fn backing_flips_over_an_opened_interior_stay_atomic() {
                // Either backing's install orphans the opened
                // interior and unseals the slot; a fault on the way
                // must leave the tree standing.
                let payload = h("089601");
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        let opened = s.descend(t).expect("setup descends");
                        assert!(matches!(opened, Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_payload(t, &payload).is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A03089601 089601"),
                );
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        let opened = s.descend(t).expect("setup descends");
                        assert!(matches!(opened, Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_payload_copy(t, b"zz").is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A03089601 089601"),
                );
            }

            #[test]
            fn payload_frame_set_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        let Ok(mut frame) = s.begin_set_payload(t) else {
                            return false;
                        };
                        if frame.write(b"wor").is_err() || frame.write(b"ld!").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn sized_payload_frame_insert_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        let Ok(mut frame) = s.begin_insert_payload_sized(InsertAt::After(t), f9, 3)
                        else {
                            return false;
                        };
                        if frame.write(b"xy").is_err() || frame.write(b"z").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn sized_frame_writes_spend_the_doors_reservation() {
                // The sized door judged and reserved the whole
                // declaration, so the write path owes zero allocator
                // traffic: with the very next allocation armed to
                // fail, every write must still succeed.
                let doc = h("089601 12026869");
                let expected = h("089601 1206776F726C6421");
                let _guard = arm_window();
                let mut s = Machine::$open(&doc).expect("probe doc opens");
                let t = s.top().nth(1).unwrap();
                let mut frame = s.begin_set_payload_sized(t, 6).unwrap();
                arm(0);
                let first = frame.write(b"wor");
                let second = frame.write(b"ld!");
                disarm();
                first.expect("a sized write allocated after the door's reservation");
                second.expect("a sized write allocated after the door's reservation");
                frame.finish().unwrap();
                assert_eq!(s.save().unwrap().as_slice(), expected.as_slice());
            }

            #[test]
            fn sized_door_refusals_touch_no_allocator() {
                // The class judgment precedes the reservation, so an
                // over-class declaration refuses before any
                // allocator call.
                let doc = h("089601 12026869");
                let over = (i32::MAX as usize) + 1;
                let _guard = arm_window();
                let mut s = Machine::$open(&doc).expect("probe doc opens");
                let t = s.top().nth(1).unwrap();
                arm(0);
                let refused = s.begin_set_payload_sized(t, over).err();
                disarm();
                let d = format!("{refused:?}");
                assert!(
                    d.contains("PayloadTooLarge"),
                    "over-class declaration must refuse without touching the allocator: {d}"
                );
            }

            #[test]
            fn frame_abandonment_reclaims_without_allocating() {
                let doc = h("089601 12026869");
                let mut s = Machine::$open(&doc).expect("probe doc opens");
                let before = fingerprint(&s);
                let t = s.top().nth(1).unwrap();
                let mut frame = s.begin_set_payload(t).unwrap();
                frame.write(b"abandoned").unwrap();
                let ((), grew) = counted(|| drop(frame));
                assert_eq!(grew, 0, "reclaiming a staged frame allocated");
                assert_eq!(before, fingerprint(&s), "an abandoned frame changed the machine");
                // The reclaimed offset space serves the next install
                // exactly as the door found it.
                s.set_payload_copy(t, b"ok").unwrap();
                assert_eq!(s.payload_bytes(t).unwrap(), *b"ok");
            }

            #[test]
            fn payload_installs_pin_their_backing_cost() {
                // A borrowed install never allocates at payload
                // scale (no staging copy, no copied-column growth);
                // a copied install then stages its bytes in exactly
                // one payload-sized request — the byte column is
                // still untouched after any number of borrowed
                // installs, so its first growth is the exact ask.
                let doc = h("089601 12026869");
                let big = vec![0x61_u8; 8192];
                let mut s = Machine::$open(&doc).expect("probe doc opens");
                let t = s.top().nth(1).unwrap();
                for _ in 0..3 {
                    let ((), _, max, _) = measured(|| s.set_payload(t, &big).unwrap());
                    assert!(max < big.len(), "a borrowed install allocated at payload scale ({max})");
                }
                let ((), _, max, total) = measured(|| s.set_payload_copy(t, &big).unwrap());
                assert_eq!(max, big.len(), "the copied stage is one exact payload-sized request");
                assert!(
                    total < big.len() + 2048,
                    "a copied install staged its bytes more than once ({total})"
                );
            }

            #[test]
            fn revert_allocates_nothing() {
                let doc = h("089601 12026869");
                let payload = h("08 01");
                let mut s = Machine::$open(&doc).expect("probe doc opens");
                let t = s.top().nth(1).unwrap();
                s.set_payload(t, &payload).unwrap();
                s.set_payload_copy(t, b"copied").unwrap();
                s.set_payload(t, &payload).unwrap();
                while s.pending() > 0 {
                    let ((), grew) = counted(|| {
                        s.revert();
                    });
                    assert_eq!(grew, 0, "a revert allocated");
                }
                assert_eq!(s.save().unwrap().as_slice(), doc.as_slice());
            }

            #[test]
            fn open_reports_early_allocator_refusals() {
                let doc = h("089601");
                let _guard = arm_window();
                for nth in 0..32 {
                    arm(nth);
                    let outcome = Machine::$open(&doc);
                    disarm();
                    match outcome {
                        Ok(_) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            return;
                        }
                        Err(e) => {
                            let d = format!("{e:?}");
                            assert!(
                                d.contains("Resource") || d.contains("Alloc"),
                                "unexpected open fault under allocator pressure: {d}"
                            );
                        }
                    }
                }
                panic!("open still failing after 32 injected faults");
            }
        }
    };
}

mix_probe!(
    mix_session_grouped,
    protobuf_edit::session::grouped::MixSession,
    open: open_copy,
    sig: ['p],
    any: ['_],
    doc,
    protobuf_edit::session::Handle,
    protobuf_edit::session::grouped::InsertAt,
    protobuf_edit::session::grouped::Descent
);

mix_probe!(
    mix_session_groupless,
    protobuf_edit::session::groupless::MixSession,
    open: open_copy,
    sig: ['p],
    any: ['_],
    doc,
    protobuf_edit::session::Handle,
    protobuf_edit::session::groupless::InsertAt,
    protobuf_edit::session::groupless::Descent
);

mix_probe!(
    mix_draft_grouped,
    protobuf_edit::draft::grouped::MixDraft,
    open: open_copy,
    sig: ['p],
    any: ['_],
    source,
    protobuf_edit::draft::Handle,
    protobuf_edit::draft::grouped::InsertAt,
    protobuf_edit::draft::grouped::Descent
);

mix_probe!(
    mix_draft_groupless,
    protobuf_edit::draft::groupless::MixDraft,
    open: open_copy,
    sig: ['p],
    any: ['_],
    source,
    protobuf_edit::draft::Handle,
    protobuf_edit::draft::groupless::InsertAt,
    protobuf_edit::draft::groupless::Descent
);

mix_probe!(
    mix_markup_grouped,
    protobuf_edit::markup::grouped::MixMarkup,
    open: open,
    sig: ['_, 'p],
    any: ['_, '_],
    source,
    protobuf_edit::markup::Handle,
    protobuf_edit::markup::grouped::InsertAt,
    protobuf_edit::markup::grouped::Descent
);

mix_probe!(
    mix_markup_groupless,
    protobuf_edit::markup::groupless::MixMarkup,
    open: open,
    sig: ['_, 'p],
    any: ['_, '_],
    source,
    protobuf_edit::markup::Handle,
    protobuf_edit::markup::groupless::InsertAt,
    protobuf_edit::markup::groupless::Descent
);

mix_probe!(
    mix_review_grouped,
    protobuf_edit::review::grouped::MixReview,
    open: open,
    sig: ['_, 'p],
    any: ['_, '_],
    source,
    protobuf_edit::review::Handle,
    protobuf_edit::review::grouped::InsertAt,
    protobuf_edit::review::grouped::Descent
);

mix_probe!(
    mix_review_groupless,
    protobuf_edit::review::groupless::MixReview,
    open: open,
    sig: ['_, 'p],
    any: ['_, '_],
    source,
    protobuf_edit::review::Handle,
    protobuf_edit::review::groupless::InsertAt,
    protobuf_edit::review::groupless::Descent
);

// The replay revisable cells walk a source instead of borrowing a
// slice, and every growth edge books per edge — the rows and layer
// arenas, the revision log, the value stores, and the save's
// script and output each sit behind their own reservation. The
// probe battery is the buffered core plus the walk-facing faces
// the buffered machines lack: the tenure door, source descends,
// the batch settle, the fetch faces, and the walked saves.
macro_rules! replay_probe {
    ($mod_name:ident, $machine:path, $handle:path, $insert_at:path,
     $status:path, $kind:path, $descent:path, $open_fault:path,
     $edit_fault:path, $descend_fault:path, $fetch_fault:path,
     $save_fault:path) => {
        mod $mod_name {
            use super::*;

            use protobuf_edit::replay_source::{Handed, SliceSource};

            use $descend_fault as DescendFault;
            use $descent as Descent;
            use $edit_fault as EditFault;
            use $fetch_fault as FetchFault;
            use $handle as Handle;
            use $insert_at as InsertAt;
            use $kind as RecordKind;
            use $machine as Machine;
            use $open_fault as OpenFault;
            use $save_fault as SaveFault;
            use $status as EditStatus;

            /// One row's observable identity, in topological order.
            type RowPrint = (usize, RecordKind, u32, EditStatus);

            fn shape(
                s: &Machine<SliceSource<'_>>,
                handle: Handle,
                depth: usize,
                out: &mut Vec<RowPrint>,
            ) {
                out.push((
                    depth,
                    s.kind(handle).unwrap(),
                    s.field(handle).unwrap().as_inner(),
                    s.status(handle).unwrap(),
                ));
                for kid in s.children(handle).unwrap() {
                    shape(s, kid, depth + 1, out);
                }
            }

            /// The deep digest of the abstract state the protocol
            /// promises to preserve on `Err`: the materialized tree
            /// (each row's kind, field and status, topological
            /// order), the pending log length, the reverse index at
            /// every document position, and the saved bytes. The
            /// machine holds its source, so the document rides in
            /// for the index sweep's width; the save costs a walk,
            /// which the fingerprint spends unarmed.
            fn fingerprint(
                s: &mut Machine<SliceSource<'_>>,
                doc: &[u8],
            ) -> (Vec<RowPrint>, usize, Vec<Option<Handle>>, Vec<u8>) {
                let mut tree = Vec::new();
                for top in s.top() {
                    shape(s, top, 0, &mut tree);
                }
                let sweep = u64::try_from(doc.len()).unwrap() + 2;
                let index: Vec<Option<Handle>> = (0..sweep).map(|pos| s.narrowest(pos)).collect();
                (tree, s.pending(), index, s.save().expect("fingerprint save"))
            }

            /// Runs `cmd` under allocation fault `nth` after an
            /// unarmed `setup`; `Ok` from `cmd` means the command
            /// succeeded (stop scanning). On success the sweep must
            /// have injected at least one fault, and `follow` runs
            /// one unarmed mutation so the machine's own gates judge
            /// the state the command published. Every `Err` must
            /// speak the resource vocabulary — the per-edge
            /// booking's structured refusal.
            pub fn probe_all(
                setup: impl Fn(&mut Machine<SliceSource<'_>>),
                mut cmd: impl FnMut(&mut Machine<SliceSource<'_>>) -> Result<(), EditFault>,
                follow: impl Fn(&mut Machine<SliceSource<'_>>),
                doc: &[u8],
            ) {
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Machine::open(SliceSource::new(doc))
                        .map_err(|(_, fault)| fault)
                        .expect("probe doc opens");
                    setup(&mut s);
                    let before = fingerprint(&mut s, doc);
                    arm(nth);
                    let outcome = cmd(&mut s);
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            follow(&mut s);
                            return;
                        }
                        Err(fault) => {
                            assert!(
                                matches!(fault, EditFault::Resource),
                                "unexpected fault vocabulary at allocation {nth}: {fault:?}"
                            );
                            let after = fingerprint(&mut s, doc);
                            assert_eq!(before, after, "state changed on Err at allocation {nth}");
                        }
                    }
                }
                panic!("command still failing after 32 injected faults");
            }

            #[test]
            fn set_varint_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_varint(t, 7)
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn set_i32_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_i32(t, 0xAB)
                    },
                    |_| {},
                    &h("0D01000000 1101000000 00000000"),
                );
            }

            #[test]
            fn set_i64_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_i64(t, 0xCD)
                    },
                    |_| {},
                    &h("0D01000000 1101000000 00000000"),
                );
            }

            #[test]
            fn set_payload_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        // No allocation inside the armed window:
                        // nth, not collect.
                        let t = s.top().nth(1).unwrap();
                        s.set_payload(t, b"world")
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_varint_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_varint(InsertAt::After(t), f9, 1).map(drop)
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_i32_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_i32(InsertAt::After(t), f9, 0xAB).map(drop)
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_i64_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_i64(InsertAt::After(t), f9, 0xCD).map(drop)
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn insert_payload_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_payload(InsertAt::After(t), f9, b"xyz").map(drop)
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn delete_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.delete(t)
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn undelete_is_atomic_under_allocator_faults() {
                probe_all(
                    // 63 replacements and one delete leave the log
                    // at len == cap == 64, a `Vec` doubling
                    // boundary, so the command's own `try_reserve`
                    // must allocate; the zero-point assert in
                    // `probe_all` goes red if the growth policy
                    // ever drifts off powers of two.
                    |s| {
                        let t = s.top().next().unwrap();
                        for i in 0..63 {
                            s.set_varint(t, i).expect("setup replace");
                        }
                        s.delete(t).expect("setup delete");
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.undelete(t)
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn clear_edit_is_atomic_under_allocator_faults() {
                probe_all(
                    // 64 replacements leave the log at len == cap
                    // == 64, a `Vec` doubling boundary, so the
                    // command's own `try_reserve` must allocate;
                    // the zero-point assert in `probe_all` goes red
                    // if the growth policy ever drifts off powers
                    // of two.
                    |s| {
                        let t = s.top().next().unwrap();
                        for i in 0..64 {
                            s.set_varint(t, i).expect("setup replace");
                        }
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.clear_edit(t)
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn authored_descend_is_atomic_under_allocator_faults() {
                // The replaced payload scans out of the store: the
                // authored zone publishes a layer with no source
                // run, and its rows are browse-only.
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        s.set_payload(t, &h("089601")).expect("setup replaces the payload");
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.descend(t).map(drop).map_err(|fault| match fault {
                            DescendFault::Edit(edit) => edit,
                            other => panic!("authored descend fell off the gate: {other:?}"),
                        })
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A0161 089601"),
                );
            }

            #[test]
            fn a_faulted_open_returns_the_source_through_the_tenure_door() {
                let doc = h("089601 12026869");
                let _guard = arm_window();
                for nth in 0..32 {
                    arm(nth);
                    let outcome = Machine::open(SliceSource::new(&doc));
                    disarm();
                    match outcome {
                        Ok(mut s) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(s.save().expect("save"), doc);
                            return;
                        }
                        Err((source, fault)) => {
                            assert!(
                                matches!(fault, OpenFault::Resource),
                                "unexpected open fault at allocation {nth}: {fault:?}"
                            );
                            // Transactional custody: the source
                            // rides back beside the fault, whole —
                            // an unarmed retry over the returned
                            // handle opens and re-speaks the
                            // document.
                            let mut retried = Machine::open(source)
                                .map_err(|(_, fault)| fault)
                                .expect("retry after a refused open");
                            assert_eq!(retried.save().expect("save"), doc);
                        }
                    }
                }
                panic!("open still failing after 32 injected faults");
            }

            #[test]
            fn descend_resource_refusals_leave_the_slot_unopened() {
                let doc = h("12 05 08 96 01 10 07");
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Machine::open(SliceSource::new(&doc))
                        .map_err(|(_, fault)| fault)
                        .expect("probe doc opens");
                    let t = s.top().next().unwrap();
                    let before = fingerprint(&mut s, &doc);
                    arm(nth);
                    let outcome = s.descend(t).map(drop);
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            return;
                        }
                        Err(fault) => {
                            assert!(
                                matches!(fault, DescendFault::Edit(EditFault::Resource)),
                                "unexpected descend fault at allocation {nth}: {fault:?}"
                            );
                            let after = fingerprint(&mut s, &doc);
                            assert_eq!(before, after, "state changed on Err at allocation {nth}");
                            // Retry must now succeed cleanly (the
                            // slot stayed unopened, no half-scanned
                            // layer).
                            assert!(s.descend(t).is_ok(), "retry after fault {nth} failed");
                        }
                    }
                }
                panic!("descend still failing after 32 injected faults");
            }

            #[test]
            fn parked_descends_book_their_fault_slot_atomically() {
                // The interior violates the wire grammar, so an
                // unarmed descend parks; under faults the park's
                // own booking (the fault ledger, the layer seal)
                // must refuse with the machine unchanged.
                let doc = h("1201FF");
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Machine::open(SliceSource::new(&doc))
                        .map_err(|(_, fault)| fault)
                        .expect("probe doc opens");
                    let t = s.top().next().unwrap();
                    let before = fingerprint(&mut s, &doc);
                    arm(nth);
                    let outcome = s.descend(t).map(|verdict| match verdict {
                        Descent::Parked(_) => (),
                        Descent::Opened { .. } => panic!("a torn interior opened"),
                    });
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            return;
                        }
                        Err(fault) => {
                            assert!(
                                matches!(fault, DescendFault::Edit(EditFault::Resource)),
                                "unexpected park fault at allocation {nth}: {fault:?}"
                            );
                            let after = fingerprint(&mut s, &doc);
                            assert_eq!(before, after, "state changed on Err at allocation {nth}");
                        }
                    }
                }
                panic!("parked descend still failing after 32 injected faults");
            }

            /// `materialize` is extent-atomic, not call-atomic: a
            /// mid-batch refusal keeps every settled extent and
            /// unwinds the half-scanned one, so the judged property
            /// is convergence — every faulted attempt retries onto
            /// the unfaulted control state.
            #[test]
            fn materialize_settles_extents_atomically_under_allocator_faults() {
                let doc = h("1203089601 1202082A");
                let control = {
                    let mut s = Machine::open(SliceSource::new(&doc))
                        .map_err(|(_, fault)| fault)
                        .expect("control doc opens");
                    let handles: Vec<Handle> = s.top().collect();
                    s.materialize(&handles).expect("control materialize");
                    fingerprint(&mut s, &doc)
                };
                let _guard = arm_window();
                for nth in 0..64 {
                    let mut s = Machine::open(SliceSource::new(&doc))
                        .map_err(|(_, fault)| fault)
                        .expect("probe doc opens");
                    let handles: Vec<Handle> = s.top().collect();
                    arm(nth);
                    let outcome = s.materialize(&handles);
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(
                                fingerprint(&mut s, &doc),
                                control,
                                "the faulted sweep's terminal state diverged from the control"
                            );
                            return;
                        }
                        Err((_, fault)) => {
                            assert!(
                                matches!(fault, DescendFault::Edit(EditFault::Resource)),
                                "unexpected materialize fault at allocation {nth}: {fault:?}"
                            );
                            s.materialize(&handles).expect("retry after fault");
                            assert_eq!(
                                fingerprint(&mut s, &doc),
                                control,
                                "the retried batch diverged from the control at allocation {nth}"
                            );
                        }
                    }
                }
                panic!("materialize still failing after 64 injected faults");
            }

            #[test]
            fn read_payload_refusals_leave_the_buffer_untouched() {
                let doc = h("12026869 089601");
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Machine::open(SliceSource::new(&doc))
                        .map_err(|(_, fault)| fault)
                        .expect("probe doc opens");
                    let t = s.top().next().unwrap();
                    let mut out = vec![0xAA];
                    arm(nth);
                    let outcome = s.read_payload(t, &mut out);
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(
                                out,
                                [0xAA, 0x68, 0x69],
                                "the payload lands past the sentinel"
                            );
                            return;
                        }
                        Err(fault) => {
                            assert!(
                                matches!(fault, FetchFault::Resource),
                                "unexpected fetch fault at allocation {nth}: {fault:?}"
                            );
                            assert_eq!(out, [0xAA], "Err leaves the buffer untouched");
                        }
                    }
                }
                panic!("read_payload still failing after 32 injected faults");
            }

            /// The batch fetch's refusal carrier counts bytes: on
            /// any `Err` the `handed` figure equals the bytes the
            /// sink already received, and an unarmed retry hands
            /// the whole batch.
            #[test]
            fn fetch_payloads_reports_the_handed_bytes_under_allocator_faults() {
                let doc = h("12026869 120161");
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = Machine::open(SliceSource::new(&doc))
                        .map_err(|(_, fault)| fault)
                        .expect("probe doc opens");
                    let handles: Vec<Handle> = s.top().collect();
                    let mut handed_bytes = 0u64;
                    arm(nth);
                    let outcome = s.fetch_payloads(&handles, |_, bytes| {
                        handed_bytes += bytes.len() as u64;
                    });
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(handed_bytes, 3, "both payloads crossed the sink");
                            return;
                        }
                        Err(Handed { handed, fault }) => {
                            assert!(
                                matches!(fault, FetchFault::Resource),
                                "unexpected fetch fault at allocation {nth}: {fault:?}"
                            );
                            assert_eq!(handed, handed_bytes, "the refusal counts the handed bytes");
                            let mut all = Vec::new();
                            s.fetch_payloads(&handles, |_, bytes| all.extend_from_slice(bytes))
                                .expect("retry after fault");
                            assert_eq!(all, b"hia", "the unarmed retry hands the whole batch");
                        }
                    }
                }
                panic!("fetch_payloads still failing after 32 injected faults");
            }

            #[test]
            fn save_is_fallible_throughout_and_prepayment_holds() {
                // A dirty machine with a nested spine: the dirt
                // sits on the innermost leaf, so save walks both
                // passes and the emit staging through three spine
                // levels. Every reservation (sizing scratch, the
                // compiled script, the output block) must be
                // reportable; an abort here would falsify either
                // SaveFault::Resource or the per-edge booking.
                let doc = h("12 07 12 05 12 03 08 96 01 089601");
                let _guard = arm_window();
                for nth in 0..64 {
                    let mut s = Machine::open(SliceSource::new(&doc))
                        .map_err(|(_, fault)| fault)
                        .expect("probe doc opens");
                    let mut cur = s.top().next().unwrap();
                    for _ in 0..3 {
                        let opened = s.descend(cur).expect("spine level opens");
                        assert!(matches!(opened, Descent::Opened { .. }));
                        cur = s.children(cur).unwrap().next().unwrap();
                    }
                    s.set_varint(cur, 9).unwrap();
                    arm(nth);
                    let outcome = s.save();
                    disarm();
                    match outcome {
                        Ok(bytes) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(&bytes[..1], &[0x12]);
                            return;
                        }
                        Err(fault) => {
                            assert!(
                                matches!(fault, SaveFault::Resource),
                                "unexpected save fault at allocation {nth}: {fault:?}"
                            );
                        }
                    }
                }
                panic!("save still failing after 64 injected faults");
            }

            #[test]
            fn save_into_reports_refusals_with_the_buffer_untouched() {
                // The Vec face's fault contract: every Err leaves
                // the caller's buffer at its incoming length and
                // content.
                let doc = h("12 07 12 05 12 03 08 96 01 089601");
                let _guard = arm_window();
                for nth in 0..64 {
                    let mut s = Machine::open(SliceSource::new(&doc))
                        .map_err(|(_, fault)| fault)
                        .expect("probe doc opens");
                    let mut cur = s.top().next().unwrap();
                    for _ in 0..3 {
                        let opened = s.descend(cur).expect("spine level opens");
                        assert!(matches!(opened, Descent::Opened { .. }));
                        cur = s.children(cur).unwrap().next().unwrap();
                    }
                    s.set_varint(cur, 9).unwrap();
                    let mut out = vec![0xAA, 0xBB];
                    arm(nth);
                    let outcome = s.save_into(&mut out);
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(&out[..2], &[0xAA, 0xBB], "the prefix is untouched");
                            assert_eq!(out[2..], *s.save().expect("saved bytes"));
                            return;
                        }
                        Err(fault) => {
                            assert!(
                                matches!(fault, SaveFault::Resource),
                                "unexpected save fault at allocation {nth}: {fault:?}"
                            );
                            assert_eq!(out, [0xAA, 0xBB], "Err leaves the buffer untouched");
                        }
                    }
                }
                panic!("save_into still failing after 64 injected faults");
            }
        }
    };
}

replay_probe!(
    maintain_grouped,
    protobuf_edit::maintain::grouped::Maintain,
    protobuf_edit::maintain::Handle,
    protobuf_edit::maintain::InsertAt,
    protobuf_edit::maintain::EditStatus,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::maintain::grouped::Descent,
    protobuf_edit::maintain::grouped::OpenFault,
    protobuf_edit::maintain::grouped::EditFault,
    protobuf_edit::maintain::grouped::DescendFault,
    protobuf_edit::maintain::grouped::FetchFault,
    protobuf_edit::maintain::grouped::SaveFault
);

replay_probe!(
    maintain_groupless,
    protobuf_edit::maintain::groupless::Maintain,
    protobuf_edit::maintain::Handle,
    protobuf_edit::maintain::InsertAt,
    protobuf_edit::maintain::EditStatus,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::maintain::groupless::Descent,
    protobuf_edit::maintain::groupless::OpenFault,
    protobuf_edit::maintain::groupless::EditFault,
    protobuf_edit::maintain::groupless::DescendFault,
    protobuf_edit::maintain::groupless::FetchFault,
    protobuf_edit::maintain::groupless::SaveFault
);

// The commission is the maintain pattern under canonical
// admission: every probe document is minimal wire, so the
// canonical door admits them all, and the growth edges past the
// door are the same strata's.
replay_probe!(
    commission_grouped,
    protobuf_edit::commission::grouped::Commission,
    protobuf_edit::commission::Handle,
    protobuf_edit::commission::InsertAt,
    protobuf_edit::commission::EditStatus,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::commission::grouped::Descent,
    protobuf_edit::commission::grouped::OpenFault,
    protobuf_edit::commission::grouped::EditFault,
    protobuf_edit::commission::grouped::DescendFault,
    protobuf_edit::commission::grouped::FetchFault,
    protobuf_edit::commission::grouped::SaveFault
);

replay_probe!(
    commission_groupless,
    protobuf_edit::commission::groupless::Commission,
    protobuf_edit::commission::Handle,
    protobuf_edit::commission::InsertAt,
    protobuf_edit::commission::EditStatus,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::commission::groupless::Descent,
    protobuf_edit::commission::groupless::OpenFault,
    protobuf_edit::commission::groupless::EditFault,
    protobuf_edit::commission::groupless::DescendFault,
    protobuf_edit::commission::groupless::FetchFault,
    protobuf_edit::commission::groupless::SaveFault
);

/// The grouped-only replay faces: group authoring books rows and
/// log like the other inserts, and a dirty group routes the save
/// through the group-frame staging.
mod replay_grouped_only {
    use super::*;

    use protobuf_edit::replay_source::SliceSource;

    #[test]
    fn maintain_insert_group_is_atomic_under_allocator_faults() {
        let f9 = protobuf_edit::FieldNumber::new(9).unwrap();
        maintain_grouped::probe_all(
            |_| {},
            |s| {
                let t = s.top().next().unwrap();
                s.insert_group(protobuf_edit::maintain::InsertAt::After(t), f9).map(drop)
            },
            |_| {},
            &h("089601 12026869"),
        );
    }

    #[test]
    fn commission_insert_group_is_atomic_under_allocator_faults() {
        let f9 = protobuf_edit::FieldNumber::new(9).unwrap();
        commission_grouped::probe_all(
            |_| {},
            |s| {
                let t = s.top().next().unwrap();
                s.insert_group(protobuf_edit::commission::InsertAt::After(t), f9).map(drop)
            },
            |_| {},
            &h("089601 12026869"),
        );
    }

    #[test]
    fn maintain_save_with_groups_is_fallible_throughout() {
        use protobuf_edit::maintain::grouped::{Maintain, SaveFault};
        let doc = h("0B 089601 0C");
        let _guard = arm_window();
        for nth in 0..64 {
            let mut s = Maintain::open(SliceSource::new(&doc))
                .map_err(|(_, fault)| fault)
                .expect("probe doc opens");
            let group = s.top().next().unwrap();
            let child = s.children(group).unwrap().next().unwrap();
            s.set_varint(child, 9).unwrap();
            arm(nth);
            let outcome = s.save();
            disarm();
            match outcome {
                Ok(bytes) => {
                    assert!(nth > 0, "probe enumerated zero allocation points");
                    assert_eq!(bytes, h("0B 0809 0C"), "the dirty group re-emits framed");
                    return;
                }
                Err(fault) => {
                    assert!(
                        matches!(fault, SaveFault::Resource),
                        "unexpected save fault at allocation {nth}: {fault:?}"
                    );
                }
            }
        }
        panic!("grouped save still failing after 64 injected faults");
    }

    #[test]
    fn commission_save_with_groups_is_fallible_throughout() {
        use protobuf_edit::commission::grouped::{Commission, SaveFault};
        let doc = h("0B 089601 0C");
        let _guard = arm_window();
        for nth in 0..64 {
            let mut s = Commission::open(SliceSource::new(&doc))
                .map_err(|(_, fault)| fault)
                .expect("probe doc opens");
            let group = s.top().next().unwrap();
            let child = s.children(group).unwrap().next().unwrap();
            s.set_varint(child, 9).unwrap();
            arm(nth);
            let outcome = s.save();
            disarm();
            match outcome {
                Ok(bytes) => {
                    assert!(nth > 0, "probe enumerated zero allocation points");
                    assert_eq!(bytes, h("0B 0809 0C"), "the dirty group re-emits framed");
                    return;
                }
                Err(fault) => {
                    assert!(
                        matches!(fault, SaveFault::Resource),
                        "unexpected save fault at allocation {nth}: {fault:?}"
                    );
                }
            }
        }
        panic!("grouped save still failing after 64 injected faults");
    }
}

/// The canonical re-emit face is maintain's alone (the commission
/// door refuses the padding that gives it work): the canonical
/// compile stages every re-encoded word, and each staging edge
/// books its own reservation.
mod maintain_canonical_saves {
    use super::*;

    use protobuf_edit::replay_source::SliceSource;

    #[test]
    fn grouped_save_canonical_is_fallible_throughout() {
        use protobuf_edit::maintain::grouped::{Maintain, SaveFault};
        // A padded varint value: 150 spelled over three bytes.
        let doc = h("08 96 81 00");
        let _guard = arm_window();
        for nth in 0..64 {
            let mut s = Maintain::open(SliceSource::new(&doc))
                .map_err(|(_, fault)| fault)
                .expect("probe doc opens");
            arm(nth);
            let outcome = s.save_canonical();
            disarm();
            match outcome {
                Ok(bytes) => {
                    assert!(nth > 0, "probe enumerated zero allocation points");
                    assert_eq!(bytes, h("089601"), "the padded value re-emits minimal");
                    return;
                }
                Err(fault) => {
                    assert!(
                        matches!(fault, SaveFault::Resource),
                        "unexpected save fault at allocation {nth}: {fault:?}"
                    );
                }
            }
        }
        panic!("save_canonical still failing after 64 injected faults");
    }

    #[test]
    fn groupless_save_canonical_is_fallible_throughout() {
        use protobuf_edit::maintain::groupless::{Maintain, SaveFault};
        // A padded varint value: 150 spelled over three bytes.
        let doc = h("08 96 81 00");
        let _guard = arm_window();
        for nth in 0..64 {
            let mut s = Maintain::open(SliceSource::new(&doc))
                .map_err(|(_, fault)| fault)
                .expect("probe doc opens");
            arm(nth);
            let outcome = s.save_canonical();
            disarm();
            match outcome {
                Ok(bytes) => {
                    assert!(nth > 0, "probe enumerated zero allocation points");
                    assert_eq!(bytes, h("089601"), "the padded value re-emits minimal");
                    return;
                }
                Err(fault) => {
                    assert!(
                        matches!(fault, SaveFault::Resource),
                        "unexpected save fault at allocation {nth}: {fault:?}"
                    );
                }
            }
        }
        panic!("save_canonical still failing after 64 injected faults");
    }
}

/// A fresh open performs zero store allocations: every store
/// column defers to its first real push, so opening an empty
/// document — no rows, no runs, no faults — touches the allocator
/// not at all. One pin per revisable cell, copy and borrowed
/// payload forms alike.
#[test]
fn a_fresh_open_performs_zero_store_allocations() {
    use protobuf_edit::session::DocBytes;

    // Sealed carriers and buffers are built outside the counted
    // window; the pin is on open alone.
    let load = || DocBytes::load(&[]).unwrap();
    let (d0, d1, d2, d3) = (load(), load(), load(), load());

    let (_, grew) = counted(|| protobuf_edit::session::grouped::Session::open(d0).unwrap());
    assert_eq!(grew, 0, "session grouped open allocated");
    let (_, grew) = counted(|| protobuf_edit::session::groupless::Session::open(d1).unwrap());
    assert_eq!(grew, 0, "session groupless open allocated");
    let (_, grew) = counted(|| protobuf_edit::session::grouped::BorrowSession::open(d2).unwrap());
    assert_eq!(grew, 0, "borrow-session grouped open allocated");
    let (_, grew) = counted(|| protobuf_edit::session::groupless::BorrowSession::open(d3).unwrap());
    assert_eq!(grew, 0, "borrow-session groupless open allocated");

    let (_, grew) = counted(|| protobuf_edit::draft::grouped::Draft::open(Vec::new()).unwrap());
    assert_eq!(grew, 0, "draft grouped open allocated");
    let (_, grew) = counted(|| protobuf_edit::draft::groupless::Draft::open(Vec::new()).unwrap());
    assert_eq!(grew, 0, "draft groupless open allocated");
    let (_, grew) =
        counted(|| protobuf_edit::draft::grouped::BorrowDraft::open(Vec::new()).unwrap());
    assert_eq!(grew, 0, "borrow-draft grouped open allocated");
    let (_, grew) =
        counted(|| protobuf_edit::draft::groupless::BorrowDraft::open(Vec::new()).unwrap());
    assert_eq!(grew, 0, "borrow-draft groupless open allocated");

    let (_, grew) = counted(|| protobuf_edit::markup::grouped::Markup::open(&[]).unwrap());
    assert_eq!(grew, 0, "markup grouped open allocated");
    let (_, grew) = counted(|| protobuf_edit::markup::grouped::BorrowMarkup::open(&[]).unwrap());
    assert_eq!(grew, 0, "borrow-markup grouped open allocated");
    let (_, grew) = counted(|| protobuf_edit::markup::groupless::BorrowMarkup::open(&[]).unwrap());
    assert_eq!(grew, 0, "borrow-markup groupless open allocated");
    let (_, grew) = counted(|| protobuf_edit::review::grouped::BorrowReview::open(&[]).unwrap());
    assert_eq!(grew, 0, "borrow-review grouped open allocated");
    let (_, grew) = counted(|| protobuf_edit::review::groupless::BorrowReview::open(&[]).unwrap());
    assert_eq!(grew, 0, "borrow-review groupless open allocated");
    let (_, grew) = counted(|| protobuf_edit::markup::groupless::Markup::open(&[]).unwrap());
    assert_eq!(grew, 0, "markup groupless open allocated");
    let (_, grew) = counted(|| protobuf_edit::review::grouped::Review::open(&[]).unwrap());
    assert_eq!(grew, 0, "review grouped open allocated");
    let (_, grew) = counted(|| protobuf_edit::review::groupless::Review::open(&[]).unwrap());
    assert_eq!(grew, 0, "review groupless open allocated");

    // The replay cells: an empty source walks to zero rows, zero
    // runs, zero banked words — the door books nothing.
    use protobuf_edit::replay_source::SliceSource;
    let (_, grew) = counted(|| {
        protobuf_edit::maintain::grouped::Maintain::open(SliceSource::new(&[]))
            .map_err(|(_, fault)| fault)
            .unwrap()
    });
    assert_eq!(grew, 0, "maintain grouped open allocated");
    let (_, grew) = counted(|| {
        protobuf_edit::maintain::groupless::Maintain::open(SliceSource::new(&[]))
            .map_err(|(_, fault)| fault)
            .unwrap()
    });
    assert_eq!(grew, 0, "maintain groupless open allocated");
    let (_, grew) = counted(|| {
        protobuf_edit::maintain::grouped::BorrowMaintain::open(SliceSource::new(&[]))
            .map_err(|(_, fault)| fault)
            .unwrap()
    });
    assert_eq!(grew, 0, "borrow-maintain grouped open allocated");
    let (_, grew) = counted(|| {
        protobuf_edit::maintain::groupless::BorrowMaintain::open(SliceSource::new(&[]))
            .map_err(|(_, fault)| fault)
            .unwrap()
    });
    assert_eq!(grew, 0, "borrow-maintain groupless open allocated");
    let (_, grew) = counted(|| {
        protobuf_edit::commission::grouped::Commission::open(SliceSource::new(&[]))
            .map_err(|(_, fault)| fault)
            .unwrap()
    });
    assert_eq!(grew, 0, "commission grouped open allocated");
    let (_, grew) = counted(|| {
        protobuf_edit::commission::groupless::Commission::open(SliceSource::new(&[]))
            .map_err(|(_, fault)| fault)
            .unwrap()
    });
    assert_eq!(grew, 0, "commission groupless open allocated");
    let (_, grew) = counted(|| {
        protobuf_edit::commission::grouped::BorrowCommission::open(SliceSource::new(&[]))
            .map_err(|(_, fault)| fault)
            .unwrap()
    });
    assert_eq!(grew, 0, "borrow-commission grouped open allocated");
    let (_, grew) = counted(|| {
        protobuf_edit::commission::groupless::BorrowCommission::open(SliceSource::new(&[]))
            .map_err(|(_, fault)| fault)
            .unwrap()
    });
    assert_eq!(grew, 0, "borrow-commission groupless open allocated");
}

/// The mutation faces without a groupless twin.
mod grouped_only {
    use super::grouped::probe_all;
    use super::*;
    use protobuf_edit::session::grouped::InsertAt;

    #[test]
    fn insert_group_is_atomic_under_allocator_faults() {
        let f9 = protobuf_edit::FieldNumber::new(9).unwrap();
        probe_all(
            |_| {},
            |s| s.insert_group(InsertAt::TailOf(None), f9).is_ok(),
            |s| {
                let t = s.top().next().unwrap();
                s.set_varint(t, 1).unwrap();
            },
            &h("089601"),
        );
    }

    #[test]
    fn nested_insert_group_is_atomic_under_allocator_faults() {
        let f9 = protobuf_edit::FieldNumber::new(9).unwrap();
        probe_all(
            // Three groups drive the row arena to len == cap == 4
            // (a `Vec` doubling boundary), so the command's own
            // row reservation must allocate; the zero-point assert
            // in `probe_all` goes red if the growth policy drifts.
            |s| {
                for _ in 0..3 {
                    let _ = s.insert_group(InsertAt::TailOf(None), f9).expect("setup group");
                }
            },
            |s| {
                let g = s.top().last().unwrap();
                s.insert_group(InsertAt::TailOf(Some(g)), f9).is_ok()
            },
            |s| {
                let t = s.top().next().unwrap();
                s.set_varint(t, 1).unwrap();
            },
            &h("089601"),
        );
    }

    #[test]
    fn descend_with_groups_is_atomic_under_allocator_faults() {
        // The payload scans a group: the scan mints an interior
        // layer mid-flight, and a fault must discard rows, layers
        // and runs together.
        probe_all(
            |_| {},
            |s| {
                let t = s.top().next().unwrap();
                s.descend(t).is_ok()
            },
            |s| {
                let t = s.top().nth(1).unwrap();
                s.set_varint(t, 1).unwrap();
            },
            &h("1A05 0B0896010C 089601"),
        );
    }
}

/// The draft's grouped-only mutation faces, same probes as the
/// session's.
mod draft_grouped_only {
    use super::draft_grouped::probe_all;
    use super::*;
    use protobuf_edit::draft::grouped::InsertAt;

    #[test]
    fn insert_group_is_atomic_under_allocator_faults() {
        let f9 = protobuf_edit::FieldNumber::new(9).unwrap();
        probe_all(
            |_| {},
            |s| s.insert_group(InsertAt::TailOf(None), f9).is_ok(),
            |s| {
                let t = s.top().next().unwrap();
                s.set_varint(t, 1).unwrap();
            },
            &h("089601"),
        );
    }

    #[test]
    fn descend_with_groups_is_atomic_under_allocator_faults() {
        // The payload scans a group over padded framing: the scan
        // mints an interior layer mid-flight and stores framing
        // widths, and a fault must discard rows, layers and runs
        // together.
        probe_all(
            |_| {},
            |s| {
                let t = s.top().next().unwrap();
                s.descend(t).is_ok()
            },
            |s| {
                let t = s.top().nth(1).unwrap();
                s.set_varint(t, 1).unwrap();
            },
            &h("1A06 0B 8800 9601 0C 089601"),
        );
    }
}

/// The priced session typestate, both dialects: every mutating face
/// must either succeed or return `Err` with the machine AND its
/// settled prices unchanged — the fingerprint extends the plain
/// battery's by `save_len()`, so a half-settled ledger cannot hide
/// behind an untouched tree.
macro_rules! priced_probe {
    ($mod_name:ident, $session:path, $priced:path, $insert_at:path, $status:path, $kind:path, $descent:path) => {
        mod $mod_name {
            use super::*;

            use $descent as Descent;
            use $insert_at as InsertAt;
            use $kind as RecordKind;
            use $priced as PricedSession;
            use $session as Session;
            use protobuf_edit::session::Handle;
            use $status as EditStatus;

            fn admitted(doc: &[u8]) -> PricedSession {
                Session::open_copy(doc)
                    .expect("probe doc opens")
                    .into_priced()
                    .map_err(|(_, fault)| fault)
                    .expect("probe doc admits")
            }

            /// One row's observable identity, in topological order.
            type RowPrint = (usize, RecordKind, u32, EditStatus);

            fn shape(s: &PricedSession, handle: Handle, depth: usize, out: &mut Vec<RowPrint>) {
                out.push((
                    depth,
                    s.kind(handle).unwrap(),
                    s.field(handle).unwrap().as_inner(),
                    s.status(handle).unwrap(),
                ));
                for kid in s.children(handle).unwrap() {
                    shape(s, kid, depth + 1, out);
                }
            }

            /// The plain battery's fingerprint extended by the settled
            /// price: tree shape, log depth, the reverse index, the
            /// saved bytes, and `save_len()`.
            #[allow(clippy::type_complexity, reason = "a probe digest, not a public face")]
            fn fingerprint(
                s: &PricedSession,
            ) -> (Vec<RowPrint>, usize, Vec<Option<Handle>>, Vec<u8>, Result<u32, String>) {
                let mut tree = Vec::new();
                for top in s.top() {
                    shape(s, top, 0, &mut tree);
                }
                let sweep = u32::try_from(s.doc()[..].len()).unwrap() + 2;
                let index: Vec<Option<Handle>> = (0..sweep).map(|pos| s.narrowest(pos)).collect();
                (
                    tree,
                    s.pending(),
                    index,
                    s.save().unwrap().as_slice().to_vec(),
                    s.save_len().map_err(|fault| format!("{fault:?}")),
                )
            }

            /// Runs `cmd` under allocation fault `nth` after an unarmed
            /// `setup`; `true` from `cmd` means the command succeeded
            /// (stop scanning). On success the sweep must have injected
            /// at least one fault, and `follow` runs one unarmed
            /// mutation so the in-crate price oracle judges the state
            /// the command published.
            pub fn probe_all(
                setup: impl Fn(&mut PricedSession),
                mut cmd: impl FnMut(&mut PricedSession) -> bool,
                follow: impl Fn(&mut PricedSession),
                doc: &[u8],
            ) {
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut s = admitted(doc);
                    setup(&mut s);
                    let before = fingerprint(&s);
                    arm(nth);
                    let ok = cmd(&mut s);
                    disarm();
                    if ok {
                        assert!(nth > 0, "probe enumerated zero allocation points");
                        follow(&mut s);
                        return;
                    }
                    let after = fingerprint(&s);
                    assert_eq!(before, after, "state changed on Err at allocation {nth}");
                }
                panic!("command still failing after 32 injected faults");
            }

            // The probe documents put every target inside a descended
            // container, so the ledger's chain reservation is a live
            // allocation edge beside the machine's own.
            #[test]
            fn priced_set_varint_is_atomic_under_allocator_faults() {
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        s.set_varint(kid, 7).is_ok()
                    },
                    |_| {},
                    &h("1A03 089601 089601"),
                );
            }

            #[test]
            fn priced_set_i32_is_atomic_under_allocator_faults() {
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        s.set_i32(kid, 0xAB).is_ok()
                    },
                    |_| {},
                    &h("1A05 15AABBCCDD 089601"),
                );
            }

            #[test]
            fn priced_set_i64_is_atomic_under_allocator_faults() {
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        s.set_i64(kid, 0xCD).is_ok()
                    },
                    |_| {},
                    &h("1A09 19AABBCCDD11223344 089601"),
                );
            }

            #[test]
            fn priced_set_payload_is_atomic_under_allocator_faults() {
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        s.set_payload(kid, b"world").is_ok()
                    },
                    |_| {},
                    &h("1A04 12026869 089601"),
                );
            }

            #[test]
            fn priced_insert_varint_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_varint(InsertAt::TailOf(Some(t)), f9, 1).is_ok()
                    },
                    |_| {},
                    &h("1A03 089601 089601"),
                );
            }

            #[test]
            fn priced_insert_i32_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_i32(InsertAt::After(t), f9, 0xAB).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn priced_insert_i64_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_i64(InsertAt::After(t), f9, 0xCD).is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn priced_insert_payload_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        s.insert_payload(InsertAt::TailOf(Some(t)), f9, b"xyz").is_ok()
                    },
                    |_| {},
                    &h("1A03 089601 089601"),
                );
            }

            #[test]
            fn priced_delete_is_atomic_under_allocator_faults() {
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        s.delete(kid).is_ok()
                    },
                    |_| {},
                    &h("1A03 089601 089601"),
                );
            }

            #[test]
            fn priced_undelete_is_atomic_under_allocator_faults() {
                probe_all(
                    // 63 replacements and one delete leave the log at a
                    // doubling boundary, so the undo reservation must
                    // allocate beside the ledger's chain reservation.
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                        let kid = s.children(t).unwrap().next().unwrap();
                        for i in 0..63 {
                            s.set_varint(kid, i).expect("setup replace");
                        }
                        s.delete(kid).expect("setup delete");
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        s.undelete(kid).is_ok()
                    },
                    |_| {},
                    &h("1A03 089601 089601"),
                );
            }

            #[test]
            fn priced_clear_edit_is_atomic_under_allocator_faults() {
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                        let kid = s.children(t).unwrap().next().unwrap();
                        for i in 0..64 {
                            s.set_varint(kid, i).expect("setup replace");
                        }
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        s.clear_edit(kid).is_ok()
                    },
                    |_| {},
                    &h("1A03 089601 089601"),
                );
            }

            #[test]
            fn priced_descend_is_atomic_under_allocator_faults() {
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        s.descend(t).is_ok()
                    },
                    |s| {
                        let t = s.top().nth(1).unwrap();
                        s.set_varint(t, 1).unwrap();
                    },
                    &h("1A03 089601 089601"),
                );
            }

            #[test]
            fn priced_payload_frame_set_is_atomic_under_allocator_faults() {
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        let Ok(mut frame) = s.begin_set_payload(kid) else {
                            return false;
                        };
                        if frame.write(b"wor").is_err() || frame.write(b"ld!").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("1A04 12026869 089601"),
                );
            }

            #[test]
            fn priced_payload_frame_insert_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let Ok(mut frame) = s.begin_insert_payload(InsertAt::TailOf(Some(t)), f9)
                        else {
                            return false;
                        };
                        if frame.write(b"xy").is_err() || frame.write(b"z").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("1A03 089601 089601"),
                );
            }

            #[test]
            fn priced_sized_frame_set_is_atomic_under_allocator_faults() {
                probe_all(
                    |s| {
                        let t = s.top().next().unwrap();
                        assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                    },
                    |s| {
                        let t = s.top().next().unwrap();
                        let kid = s.children(t).unwrap().next().unwrap();
                        let Ok(mut frame) = s.begin_set_payload_sized(kid, 6) else {
                            return false;
                        };
                        if frame.write(b"wor").is_err() || frame.write(b"ld!").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("1A04 12026869 089601"),
                );
            }

            #[test]
            fn priced_sized_frame_insert_is_atomic_under_allocator_faults() {
                use protobuf_edit::FieldNumber;
                let f9 = FieldNumber::new(9).unwrap();
                probe_all(
                    |_| {},
                    |s| {
                        let t = s.top().next().unwrap();
                        let Ok(mut frame) = s.begin_insert_payload_sized(InsertAt::After(t), f9, 3)
                        else {
                            return false;
                        };
                        if frame.write(b"xy").is_err() || frame.write(b"z").is_err() {
                            return false;
                        }
                        frame.finish().is_ok()
                    },
                    |_| {},
                    &h("089601 12026869"),
                );
            }

            #[test]
            fn priced_admission_returns_the_session_intact_per_injected_fault() {
                // A dirty machine with entries to build at two depths:
                // the admission walk's ledger growth is the one
                // fallible edge, and a refusal hands the session back
                // untouched.
                let doc = h("1A05 1A03 089601 089601");
                let _guard = arm_window();
                for nth in 0..32 {
                    let mut base = Session::open_copy(&doc).expect("probe doc opens");
                    let outer = base.top().next().unwrap();
                    assert!(matches!(base.descend(outer).unwrap(), Descent::Opened { .. }));
                    let mid = base.children(outer).unwrap().next().unwrap();
                    assert!(matches!(base.descend(mid).unwrap(), Descent::Opened { .. }));
                    let leaf = base.children(mid).unwrap().next().unwrap();
                    base.set_varint(leaf, 300).expect("setup dirt");
                    let expect = base.save_len().expect("in-class setup");
                    arm(nth);
                    let outcome = base.into_priced();
                    disarm();
                    match outcome {
                        Ok(priced) => {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            assert_eq!(priced.save_len(), Ok(expect));
                            return;
                        }
                        Err((back, fault)) => {
                            let d = format!("{fault:?}");
                            assert!(d.contains("Resource"), "unexpected admission fault: {d}");
                            assert_eq!(back.save_len(), Ok(expect), "the session came back moved");
                            // The returned session must admit cleanly
                            // once the pressure lifts.
                            let priced =
                                back.into_priced().map_err(|(_, fault)| fault).expect("retry");
                            assert_eq!(priced.save_len(), Ok(expect));
                        }
                    }
                }
                panic!("admission still failing after 32 injected faults");
            }

            #[test]
            fn priced_clean_admission_performs_zero_allocations() {
                let doc = h("089601 12026869");
                let base = Session::open_copy(&doc).expect("probe doc opens");
                let (outcome, grew) = counted(|| base.into_priced().map_err(|(_, fault)| fault));
                assert!(outcome.is_ok(), "clean admission refused");
                assert_eq!(grew, 0, "a clean admission touched the allocator");
            }

            #[test]
            fn priced_save_len_touches_no_allocator() {
                // The settled fast path answers from three words; with
                // the very next allocation armed to fail, the answer
                // must still land (an allocation would surface as an
                // abort here — nothing on this path can report one).
                let doc = h("1A03 089601 089601");
                let _guard = arm_window();
                let mut s = admitted(&doc);
                let t = s.top().next().unwrap();
                assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                let kid = s.children(t).unwrap().next().unwrap();
                s.set_varint(kid, 7).unwrap();
                arm(0);
                let priced = s.save_len();
                disarm();
                assert_eq!(priced, Ok(7));
            }

            #[test]
            fn priced_revert_touches_no_allocator() {
                // The reverse climb re-walks entries the forward path
                // seeded: with the very next allocation armed to fail,
                // the revert must still land whole.
                let doc = h("1A03 089601 089601");
                let _guard = arm_window();
                let mut s = admitted(&doc);
                let t = s.top().next().unwrap();
                assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
                let kid = s.children(t).unwrap().next().unwrap();
                s.set_varint(kid, 7).unwrap();
                let before = fingerprint(&s);
                s.set_varint(kid, 300).unwrap();
                arm(0);
                let reverted_row = s.revert();
                disarm();
                assert_eq!(reverted_row, Some(kid));
                assert_eq!(fingerprint(&s), before, "the revert left a trace");
            }
        }
    };
}

priced_probe!(
    priced_grouped,
    protobuf_edit::session::grouped::Session,
    protobuf_edit::session::grouped::PricedSession,
    protobuf_edit::session::grouped::InsertAt,
    protobuf_edit::session::grouped::EditStatus,
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::session::grouped::Descent
);

priced_probe!(
    priced_groupless,
    protobuf_edit::session::groupless::Session,
    protobuf_edit::session::groupless::PricedSession,
    protobuf_edit::session::groupless::InsertAt,
    protobuf_edit::session::groupless::EditStatus,
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::session::groupless::Descent
);

/// The priced mutation face without a groupless twin.
mod priced_grouped_only {
    use super::priced_grouped::probe_all;
    use super::*;
    use protobuf_edit::session::grouped::{Descent, InsertAt};

    #[test]
    fn priced_insert_group_is_atomic_under_allocator_faults() {
        let f9 = protobuf_edit::FieldNumber::new(9).unwrap();
        probe_all(
            |s| {
                let t = s.top().next().unwrap();
                assert!(matches!(s.descend(t).unwrap(), Descent::Opened { .. }));
            },
            |s| {
                let t = s.top().next().unwrap();
                s.insert_group(InsertAt::TailOf(Some(t)), f9).is_ok()
            },
            |s| {
                let t = s.top().nth(1).unwrap();
                s.set_varint(t, 1).unwrap();
            },
            &h("1A03 089601 089601"),
        );
    }
}

/// The one-shot editors' sized frames, both dialects: the family's
/// allocation policy is abort-side, so an armed refusal is not an
/// `Err` but a process abort — the probes passing IS the
/// no-allocation proof for the write path behind the door's
/// reservation.
mod patch_frames {
    use super::*;
    use protobuf_edit::DepthLimit;

    #[test]
    fn grouped_sized_door_refusals_touch_no_allocator() {
        use protobuf_edit::patch::grouped::{EditFault, Patch};
        let doc = h("089601 12026869");
        let _guard = arm_window();
        let mut p = Patch::open(&doc, DepthLimit::REFERENCE).expect("probe doc opens");
        let t = p.top().nth(1).unwrap();
        arm(0);
        let refused = p.begin_set_payload_sized(t, (i32::MAX as usize) + 1).err();
        disarm();
        assert!(
            matches!(refused, Some(EditFault::PayloadTooLarge { .. })),
            "over-class declaration must refuse without touching the allocator: {refused:?}"
        );
    }

    #[test]
    fn groupless_sized_door_refusals_touch_no_allocator() {
        use protobuf_edit::patch::groupless::{EditFault, Patch};
        let doc = h("089601 12026869");
        let _guard = arm_window();
        let mut p = Patch::open(&doc, DepthLimit::REFERENCE).expect("probe doc opens");
        let t = p.top().nth(1).unwrap();
        arm(0);
        let refused = p.begin_set_payload_sized(t, (i32::MAX as usize) + 1).err();
        disarm();
        assert!(
            matches!(refused, Some(EditFault::PayloadTooLarge { .. })),
            "over-class declaration must refuse without touching the allocator: {refused:?}"
        );
    }

    #[test]
    fn grouped_sized_frame_writes_spend_the_doors_reservation() {
        use protobuf_edit::patch::grouped::Patch;
        let doc = h("089601 12026869");
        let expected = h("089601 1206776F726C6421");
        let _guard = arm_window();
        let mut p = Patch::open(&doc, DepthLimit::REFERENCE).expect("probe doc opens");
        let t = p.top().nth(1).unwrap();
        let mut frame = p.begin_set_payload_sized(t, 6).unwrap();
        arm(0);
        let first = frame.write(b"wor");
        let second = frame.write(b"ld!");
        disarm();
        first.expect("a sized write refused after the door's reservation");
        second.expect("a sized write refused after the door's reservation");
        frame.finish().unwrap();
        assert_eq!(p.save().unwrap().as_slice(), expected.as_slice());
    }

    #[test]
    fn groupless_sized_frame_writes_spend_the_doors_reservation() {
        use protobuf_edit::patch::groupless::Patch;
        let doc = h("089601 12026869");
        let expected = h("089601 1206776F726C6421");
        let _guard = arm_window();
        let mut p = Patch::open(&doc, DepthLimit::REFERENCE).expect("probe doc opens");
        let t = p.top().nth(1).unwrap();
        let mut frame = p.begin_set_payload_sized(t, 6).unwrap();
        arm(0);
        let first = frame.write(b"wor");
        let second = frame.write(b"ld!");
        disarm();
        first.expect("a sized write refused after the door's reservation");
        second.expect("a sized write refused after the door's reservation");
        frame.finish().unwrap();
        assert_eq!(p.save().unwrap().as_slice(), expected.as_slice());
    }
}

/// The streaming rewirers' zero-buffering claim, allocation half:
/// content-heavy streams (large opaque payloads across many small
/// chunks) drive zero allocator traffic — the counting allocator
/// is the judge, no fault armed. The layout half (no content
/// buffer field exists) is the in-module struct-size pin.
mod rewire_holdings {
    use super::*;
    use protobuf_edit::path::{Program, Segment};
    use protobuf_edit::{DepthLimit, FieldNumber, Standard};

    /// One LEN f2 record whose 1 MiB payload arrives in 4 KiB
    /// chunks, plus scalar neighbors. Returns (head, chunk,
    /// chunks, tail).
    fn content_stream() -> (Vec<u8>, Vec<u8>, usize, Vec<u8>) {
        // LEN f2, length 0x100000 = 1 MiB.
        let head = h("08 01 12 80 80 40");
        let chunk = vec![0xAB_u8; 4096];
        (head, chunk, 256, h("08 02"))
    }

    // The fixture streams a mebibyte through the machine: under
    // Miri that is byte bulk without provenance value.
    #[cfg(not(miri))]
    #[test]
    fn the_groupless_rewirer_buffers_no_stream_content() {
        use protobuf_edit::rewire::groupless::{Actions, Rewirer};
        let f9 = [Segment::Field(FieldNumber::new(9).unwrap())];
        let paths: [&[Segment<'_>]; 1] = [&f9];
        let program = Program::over(&paths).unwrap();
        let acts = [protobuf_edit::rewire::Action::Delete];
        let actions = Actions::over(&program, &acts).unwrap();
        let mut machine = Rewirer::new(&actions, Standard::Tolerant, DepthLimit::REFERENCE);
        let (head, chunk, chunks, tail) = content_stream();
        let mut forwarded = 0usize;
        let ((), grew) = counted(|| {
            let mut sink = |bytes: &[u8]| forwarded += bytes.len();
            machine.feed(&head, &mut sink).unwrap();
            for _ in 0..chunks {
                machine.feed(&chunk, &mut sink).unwrap();
            }
            machine.feed(&tail, &mut sink).unwrap();
            machine.finish().unwrap();
        });
        assert_eq!(forwarded, head.len() + chunks * chunk.len() + tail.len());
        assert_eq!(grew, 0, "a content-heavy stream grew the rewirer's holdings");
    }

    // The fixture streams a mebibyte through the machine: under
    // Miri that is byte bulk without provenance value.
    #[cfg(not(miri))]
    #[test]
    fn the_grouped_rewirer_buffers_no_stream_content() {
        use protobuf_edit::rewire::grouped::{Actions, Rewirer};
        let f9 = [Segment::Field(FieldNumber::new(9).unwrap())];
        let paths: [&[Segment<'_>]; 1] = [&f9];
        let program = Program::over(&paths).unwrap();
        let acts = [protobuf_edit::rewire::Action::Delete];
        let actions = Actions::over(&program, &acts).unwrap();
        let mut machine = Rewirer::new(&actions, Standard::Tolerant, DepthLimit::REFERENCE);
        let (head, chunk, chunks, tail) = content_stream();
        let mut forwarded = 0usize;
        let ((), grew) = counted(|| {
            let mut sink = |bytes: &[u8]| forwarded += bytes.len();
            machine.feed(&head, &mut sink).unwrap();
            for _ in 0..chunks {
                machine.feed(&chunk, &mut sink).unwrap();
            }
            machine.feed(&tail, &mut sink).unwrap();
            machine.finish().unwrap();
        });
        assert_eq!(forwarded, head.len() + chunks * chunk.len() + tail.len());
        assert_eq!(grew, 0, "a content-heavy stream grew the rewirer's holdings");
    }
}

/// The splicers' identity shape: a job that edits nothing hands
/// the input through as one sealed window — the plan allocates no
/// root frame, no op list, and no staging, so the whole sink job
/// performs exactly one allocation: the walk's own root-layer
/// push, the buffered walk's ledgered price. The counting
/// allocator judges the exact count.
mod splice_identity {
    use super::*;
    use protobuf_edit::{DepthLimit, Standard};

    #[derive(Clone)]
    struct Identity;
    impl protobuf_edit::splice::groupless::Rule for Identity {}
    impl protobuf_edit::splice::grouped::Rule for Identity {}

    #[test]
    fn a_groupless_identity_sink_job_allocates_nothing() {
        use protobuf_edit::splice::groupless::splice_sink;
        let doc = h("089601 12026869 089701");
        let mut forwarded = 0usize;
        let (outcome, grew) = counted(|| {
            splice_sink(&doc, &mut Identity, Standard::Tolerant, DepthLimit::REFERENCE, |w| {
                forwarded += w.len();
            })
        });
        outcome.unwrap();
        assert_eq!(forwarded, doc.len());
        assert_eq!(grew, 1, "the identity job owes exactly the walk's root-layer push");
    }

    #[test]
    fn a_grouped_identity_sink_job_allocates_nothing() {
        use protobuf_edit::splice::grouped::splice_sink;
        let doc = h("089601 12026869 089701");
        let mut forwarded = 0usize;
        let (outcome, grew) = counted(|| {
            splice_sink(&doc, &mut Identity, Standard::Tolerant, DepthLimit::REFERENCE, |w| {
                forwarded += w.len();
            })
        });
        outcome.unwrap();
        assert_eq!(forwarded, doc.len());
        assert_eq!(grew, 1, "the identity job owes exactly the walk's root-layer push");
    }
}

/// The draft's tenure door under allocator pressure: a refused
/// open must hand the moved-in buffer back intact beside the
/// fault.
mod draft_doors {
    use super::*;

    #[test]
    fn a_faulted_open_returns_the_buffer_through_the_tenure_door() {
        // Padded framing: the width-carrying scan sits under the
        // injected faults.
        let doc = h("88 00 96 81 00 12 82 00 68 69");
        let _guard = arm_window();
        for nth in 0..32 {
            let source = doc.clone();
            arm(nth);
            let outcome = protobuf_edit::draft::groupless::Draft::open(source);
            disarm();
            match outcome {
                Ok(draft) => {
                    assert!(nth > 0, "probe enumerated zero allocation points");
                    assert_eq!(draft.save().unwrap(), doc);
                    return;
                }
                Err((back, fault)) => {
                    assert_eq!(back, doc, "the refusal returns the buffer intact");
                    let d = format!("{fault:?}");
                    assert!(d.contains("Resource"), "unexpected open fault: {d}");
                }
            }
        }
        panic!("open still failing after 32 injected faults");
    }
}

/// The canonical faces are reads with their own allocation profile:
/// a complete sizing walk (bodies + spine) precedes every
/// publication, so a clean machine — no dirt anywhere — still pays
/// canonical scratch the fidelity fast path never touches. Every
/// allocation must either succeed or surface `Resource` with the
/// machine's observable state untouched; the buffered face leaves
/// the caller's sentinel bytes alone and the sink face hands
/// nothing before the sizing pass settles.
macro_rules! canonical_read_probe {
    ($mod_name:ident, $machine:path, open: $open:ident, sig: [$($sig:tt)*],
     $kind:path, $descent:path) => {
        mod $mod_name {
            use super::*;

            use $descent as Descent;
            use $kind as RecordKind;
            use $machine as Machine;

            /// Deeply materialized, no dirt: the nested descents
            /// commit the LEN chain into the closure while fidelity
            /// keeps its clean fast path, so every canonical sizing
            /// allocation is live under the armed allocator. The
            /// innermost LEN's blob payload faults its descend —
            /// the resident verdict pins the opaque boundary too.
            const DOC: &str = "1A06 1A04 128100 61 12026869 089601";

            /// The canonical twin under that commitment schedule.
            const TWIN: &str = "1A05 1A03 1201 61 12026869 089601";

            fn deep_clean(doc: &[u8]) -> Machine<$($sig)*> {
                let mut s = Machine::$open(doc).expect("probe doc opens");
                let mut cur = Some(s.top().next().unwrap());
                while let Some(t) = cur {
                    if !matches!(s.kind(t).unwrap(), RecordKind::Len) {
                        break;
                    }
                    match s.descend(t).expect("descend judges") {
                        Descent::Opened { first } => cur = first,
                        // The dialects' resident-verdict alphabets
                        // differ; every non-opened verdict ends the
                        // schedule.
                        _ => break,
                    }
                }
                s
            }

            /// The observable state a read face must preserve: the
            /// pending log, every top status, the fidelity bytes,
            /// and the reverse index at every position.
            fn fingerprint(s: &Machine<$($sig)*>, sweep: u32) -> String {
                let tops: Vec<_> = s.top().collect();
                let statuses: Vec<_> = tops.iter().map(|&t| s.status(t).unwrap()).collect();
                let index: Vec<_> = (0..sweep).map(|pos| s.narrowest(pos)).collect();
                format!("{:?}", (s.pending(), statuses, s.save().unwrap(), index))
            }

            #[test]
            fn save_canonical_reports_refusals_with_state_untouched() {
                let doc = h(DOC);
                let _guard = arm_window();
                let s = deep_clean(&doc);
                let sweep = u32::try_from(doc.len()).unwrap() + 2;
                let baseline = s.save_canonical().unwrap();
                assert_eq!(baseline, h(TWIN), "the padded chain normalizes");
                let before = fingerprint(&s, sweep);
                let mut landed = 0;
                for nth in 0..64 {
                    arm(nth);
                    let outcome = s.save_canonical();
                    disarm();
                    match outcome {
                        Ok(bytes) => {
                            assert!(landed > 0, "probe enumerated zero allocation points");
                            assert_eq!(bytes, baseline, "the green retry matches");
                            assert_eq!(fingerprint(&s, sweep), before, "a read face moved state");
                            return;
                        }
                        Err(fault) => {
                            let d = format!("{fault:?}");
                            assert!(d.contains("Resource"), "unexpected canonical fault: {d}");
                            landed += 1;
                            assert_eq!(
                                fingerprint(&s, sweep),
                                before,
                                "state changed on Err at allocation {nth}"
                            );
                        }
                    }
                }
                panic!("save_canonical still failing after 64 injected faults");
            }

            #[test]
            fn save_canonical_into_leaves_the_sentinel_buffer_untouched() {
                let doc = h(DOC);
                let _guard = arm_window();
                let s = deep_clean(&doc);
                let baseline = s.save_canonical().unwrap();
                let mut landed = 0;
                for nth in 0..64 {
                    let mut out = vec![0xEE, 0xEE, 0xEE];
                    arm(nth);
                    let outcome = s.save_canonical_into(&mut out);
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(landed > 0, "probe enumerated zero allocation points");
                            assert_eq!(out[..3], [0xEE, 0xEE, 0xEE], "the sentinel prefix rides");
                            assert_eq!(out[3..], baseline[..], "the suffix is the canonical save");
                            return;
                        }
                        Err(fault) => {
                            let d = format!("{fault:?}");
                            assert!(d.contains("Resource"), "unexpected canonical fault: {d}");
                            landed += 1;
                            assert_eq!(
                                out,
                                [0xEE, 0xEE, 0xEE],
                                "the buffer changed on Err at allocation {nth}"
                            );
                        }
                    }
                }
                panic!("save_canonical_into still failing after 64 injected faults");
            }

            #[test]
            fn save_canonical_sink_hands_nothing_before_the_sizing_pass_settles() {
                let doc = h(DOC);
                let _guard = arm_window();
                let s = deep_clean(&doc);
                let baseline = s.save_canonical().unwrap();
                let mut landed = 0;
                for nth in 0..64 {
                    let mut handed = 0usize;
                    arm(nth);
                    let outcome = s.save_canonical_sink(|slice| handed += slice.len());
                    disarm();
                    match outcome {
                        Ok(()) => {
                            assert!(landed > 0, "probe enumerated zero allocation points");
                            assert_eq!(handed, baseline.len(), "the sink covers the save");
                            return;
                        }
                        Err(fault) => {
                            let d = format!("{fault:?}");
                            assert!(d.contains("Resource"), "unexpected canonical fault: {d}");
                            landed += 1;
                            assert_eq!(handed, 0, "bytes were handed on Err at allocation {nth}");
                        }
                    }
                }
                panic!("save_canonical_sink still failing after 64 injected faults");
            }
        }
    };
}

canonical_read_probe!(
    canonical_draft_grouped,
    protobuf_edit::draft::grouped::Draft,
    open: open_copy,
    sig: [],
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::draft::grouped::Descent
);

canonical_read_probe!(
    canonical_draft_groupless,
    protobuf_edit::draft::groupless::Draft,
    open: open_copy,
    sig: [],
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::draft::groupless::Descent
);

canonical_read_probe!(
    canonical_borrow_draft_grouped,
    protobuf_edit::draft::grouped::BorrowDraft,
    open: open_copy,
    sig: ['static],
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::draft::grouped::Descent
);

canonical_read_probe!(
    canonical_borrow_draft_groupless,
    protobuf_edit::draft::groupless::BorrowDraft,
    open: open_copy,
    sig: ['static],
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::draft::groupless::Descent
);

canonical_read_probe!(
    canonical_markup_grouped,
    protobuf_edit::markup::grouped::Markup,
    open: open,
    sig: ['_],
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::markup::grouped::Descent
);

canonical_read_probe!(
    canonical_markup_groupless,
    protobuf_edit::markup::groupless::Markup,
    open: open,
    sig: ['_],
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::markup::groupless::Descent
);

canonical_read_probe!(
    canonical_borrow_markup_grouped,
    protobuf_edit::markup::grouped::BorrowMarkup,
    open: open,
    sig: ['_, 'static],
    protobuf_edit::wire::grouped::RecordKind,
    protobuf_edit::markup::grouped::Descent
);

canonical_read_probe!(
    canonical_borrow_markup_groupless,
    protobuf_edit::markup::groupless::BorrowMarkup,
    open: open,
    sig: ['_, 'static],
    protobuf_edit::wire::groupless::RecordKind,
    protobuf_edit::markup::groupless::Descent
);

mod inplace_allocation {
    //! The in-place editor's allocation pins, on the byte-size
    //! observation: working memory is the matcher's tables plus the
    //! write list — caller-commanded, never document-keyed — and
    //! the write loop allocates nothing (which is what confines an
    //! allocator abort to the walk, where zero bytes are written).

    use protobuf_edit::inplace::groupless::apply;
    use protobuf_edit::inplace::{Action, Rule, RuleSet};
    use protobuf_edit::path::Segment;
    use protobuf_edit::{DepthLimit, FieldNumber};

    use super::measured;

    const fn f(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    /// A content-simple document: scalar neighbors around one
    /// opaque LEN payload of `len` bytes (record counts stay fixed
    /// while the byte size scales).
    fn doc_with_payload(len: usize) -> Vec<u8> {
        let mut doc = vec![0x08, 0x01, 0x12];
        let mut word = u32::try_from(len).expect("fixture payloads sit in the LEN class");
        loop {
            let byte = (word & 0x7F) as u8;
            word >>= 7;
            if word == 0 {
                doc.push(byte);
                break;
            }
            doc.push(byte | 0x80);
        }
        doc.extend(core::iter::repeat_n(0xA5, len));
        doc.extend_from_slice(&[0x18, 0x02]);
        doc
    }

    #[test]
    fn the_probe_observes_requested_bytes() {
        // Positive control: a known-size request must be seen by
        // the byte observation, or the pins below judge nothing.
        let (_kept, count, max, total) = measured(|| std::hint::black_box(vec![0u8; 4096]));
        assert!(count >= 1, "the probe saw no allocation");
        assert!(max >= 4096, "the probe missed the request size (max {max})");
        assert!(total >= 4096, "the probe missed the request size (total {total})");
    }

    #[test]
    fn allocation_is_independent_of_document_size() {
        // Zero-match rules over 1 KiB and 1 MiB documents of one
        // record shape: identical counts and identical bytes — the
        // job's working memory is keyed to rules and depth, never
        // to the document.
        let path = [Segment::Field(f(63))];
        let rules = [Rule { path: &path, action: Action::SetVarint(0) }];
        let set = RuleSet::over(&rules).unwrap();
        let mut small = doc_with_payload(1 << 10);
        let mut large = doc_with_payload(1 << 20);
        let (result, count_s, max_s, total_s) =
            measured(|| apply(&mut small, &set, DepthLimit::REFERENCE));
        result.unwrap();
        let (result, count_l, max_l, total_l) =
            measured(|| apply(&mut large, &set, DepthLimit::REFERENCE));
        result.unwrap();
        assert_eq!(
            (count_s, max_s, total_s),
            (count_l, max_l, total_l),
            "allocation scaled with document size"
        );
    }

    #[test]
    fn payload_overwrites_never_request_payload_sized_storage() {
        // One equal-length payload overwrite, 8 bytes vs 1 MiB:
        // the plan's metadata is identical, and no request ever
        // approaches the payload's size — the replacement bytes
        // ride borrowed to one copy inside the caller's buffer.
        let path = [Segment::Field(f(2))];
        let small_bytes = vec![0x5Au8; 8];
        let large_bytes = vec![0x5Au8; 1 << 20];
        let mut small = doc_with_payload(8);
        let mut large = doc_with_payload(1 << 20);

        let small_rules = [Rule { path: &path, action: Action::SetPayload(&small_bytes) }];
        let small_set = RuleSet::over(&small_rules).unwrap();
        let (result, count_s, max_s, total_s) =
            measured(|| apply(&mut small, &small_set, DepthLimit::REFERENCE));
        assert_eq!(result.unwrap().replaced(), 1);

        let large_rules = [Rule { path: &path, action: Action::SetPayload(&large_bytes) }];
        let large_set = RuleSet::over(&large_rules).unwrap();
        let (result, count_l, max_l, total_l) =
            measured(|| apply(&mut large, &large_set, DepthLimit::REFERENCE));
        assert_eq!(result.unwrap().replaced(), 1);

        assert_eq!(
            (count_s, max_s, total_s),
            (count_l, max_l, total_l),
            "overwrite metadata scaled with the payload"
        );
        assert!(max_l < (1 << 20), "a payload-sized request slipped through (max {max_l})");
        // Tag(1) + value(1) + LEN tag(1) + three-byte prefix: the
        // 1 MiB payload starts at byte six.
        assert_eq!(&large[6..14], &[0x5A; 8][..], "the overwrite landed");
    }

    #[test]
    fn the_write_loop_allocates_nothing() {
        // Two documents with identical record geometry up to the
        // last record: one ends in an unmatched field (the job
        // lands its writes), the other in a two-rule conflict (the
        // job faults after the whole plan was staged). Equal
        // accounts mean the difference between them — the write
        // loop itself — allocated zero (the abort-safety
        // constraint, judged from outside).
        let route = [f(9)];
        let p1 = [Segment::Field(f(1))];
        let p2 = [Segment::Field(f(2))];
        let wild2 = [Segment::AnyDepth { descend: &route }, Segment::Field(f(2))];
        let rules = [
            Rule { path: &p1, action: Action::SetVarint(0) },
            Rule { path: &p2, action: Action::SetVarint(0) },
            Rule { path: &wild2, action: Action::SetVarint(1) },
        ];
        let set = RuleSet::over(&rules).unwrap();

        let mut lands = vec![0x08, 0x00, 0x08, 0x00, 0x18, 0x00];
        let (result, count_ok, max_ok, total_ok) =
            measured(|| apply(&mut lands, &set, DepthLimit::REFERENCE));
        assert_eq!(result.unwrap().replaced(), 2, "the landing job wrote its plan");
        assert_eq!(lands[..4], [0x08, 0x00, 0x08, 0x00], "width-one zeros landed");

        let mut faults = vec![0x08, 0x00, 0x08, 0x00, 0x10, 0x00];
        let snapshot = faults.clone();
        let (result, count_err, max_err, total_err) =
            measured(|| apply(&mut faults, &set, DepthLimit::REFERENCE));
        assert!(result.is_err(), "the conflict fired after the plan was staged");
        assert_eq!(faults, snapshot, "the faulted buffer is untouched");

        assert_eq!(
            (count_ok, max_ok, total_ok),
            (count_err, max_err, total_err),
            "the write loop allocated"
        );
    }

    #[test]
    fn apply_keeps_the_callers_allocation() {
        // The buffer is the product: pointer, length, and capacity
        // are identical across apply — no reallocation, no copy.
        let mut buf = doc_with_payload(64);
        let (ptr, len, capacity) = (buf.as_ptr(), buf.len(), buf.capacity());
        let path = [Segment::Field(f(1))];
        let rules = [Rule { path: &path, action: Action::SetVarint(7) }];
        let set = RuleSet::over(&rules).unwrap();
        assert_eq!(apply(&mut buf, &set, DepthLimit::REFERENCE).unwrap().replaced(), 1);
        assert_eq!(
            (buf.as_ptr(), buf.len(), buf.capacity()),
            (ptr, len, capacity),
            "the caller's allocation moved"
        );
    }
}

/// The transfer faces' atomicity under injected allocator faults:
/// every new reserve point (the clone's counted rows and layers, the
/// transfer log slots, the import's staged bytes, and the priced
/// ledger's climb entries) either completes or leaves the observable
/// state untouched.
mod transfer_atomicity {
    use super::*;

    use protobuf_edit::FieldNumber;
    use protobuf_edit::session::Handle;

    macro_rules! transfer_probe {
        ($mod_name:ident, $machine:path, $insert_at:path, $payload_target:path, $doc:expr, $group_doc:expr) => {
            mod $mod_name {
                use super::*;

                use $insert_at as InsertAt;
                use $machine as Machine;
                use $payload_target as PayloadTarget;

                fn fingerprint(s: &Machine) -> (usize, Vec<u8>, Vec<Option<Handle>>) {
                    let sweep = u32::try_from(s.doc()[..].len()).unwrap() + 2;
                    let index = (0..sweep).map(|pos| s.narrowest(pos)).collect();
                    (s.pending(), s.save().unwrap().as_slice().to_vec(), index)
                }

                fn probe_all(mut cmd: impl FnMut(&mut Machine) -> bool, doc: &[u8]) {
                    let _guard = arm_window();
                    for nth in 0..32 {
                        let mut s = Machine::open_copy(doc).expect("probe doc opens");
                        let before = fingerprint(&s);
                        arm(nth);
                        let ok = cmd(&mut s);
                        disarm();
                        if ok {
                            assert!(nth > 0, "probe enumerated zero allocation points");
                            return;
                        }
                        let after = fingerprint(&s);
                        assert_eq!(before, after, "state changed on Err at allocation {nth}");
                    }
                    panic!("command still failing after 32 injected faults");
                }

                #[test]
                fn copy_record_is_atomic_under_allocator_faults() {
                    probe_all(
                        |s| {
                            let t = s.top().next().unwrap();
                            s.copy_record(t, InsertAt::TailOf(None)).is_ok()
                        },
                        &$group_doc,
                    );
                }

                #[test]
                fn move_record_is_atomic_under_allocator_faults() {
                    probe_all(
                        |s| {
                            let first = s.top().next().unwrap();
                            let second = s.top().nth(1).unwrap();
                            s.move_record(first, InsertAt::After(second)).is_ok()
                        },
                        &$group_doc,
                    );
                }

                #[test]
                fn payload_transfers_are_atomic_under_allocator_faults() {
                    let f9 = FieldNumber::new(9).unwrap();
                    probe_all(
                        |s| {
                            let len = s.top().nth(1).unwrap();
                            s.copy_payload(
                                len,
                                PayloadTarget::Insert { at: InsertAt::HeadOf(None), field: f9 },
                            )
                            .is_ok()
                        },
                        &$doc,
                    );
                    probe_all(
                        |s| {
                            let len = s.top().nth(1).unwrap();
                            s.move_payload(len, InsertAt::HeadOf(None), f9).is_ok()
                        },
                        &$doc,
                    );
                }

                #[test]
                fn imports_are_atomic_under_allocator_faults() {
                    let outside = Machine::open_copy(&$doc).expect("outside doc opens");
                    let source = outside.top().nth(1).unwrap();
                    probe_all(
                        |s| {
                            let record = outside.record_ref(source).unwrap();
                            let Ok(proof) = record.try_canonical() else { return false };
                            s.copy_record_from(proof, InsertAt::TailOf(None)).is_ok()
                        },
                        &h("089601"),
                    );
                }
            }
        };
    }

    transfer_probe!(
        session_groupless,
        protobuf_edit::session::groupless::TransferSession,
        protobuf_edit::session::groupless::transfer::InsertAt,
        protobuf_edit::session::groupless::transfer::PayloadTarget,
        h("089601 12026869"),
        h("089601 12026869")
    );

    transfer_probe!(
        session_grouped,
        protobuf_edit::session::grouped::TransferSession,
        protobuf_edit::session::grouped::transfer::InsertAt,
        protobuf_edit::session::grouped::transfer::PayloadTarget,
        h("089601 12026869"),
        // group f1 { varint f2 · group f3 { varint f2 } } · varint f4:
        // the closure clone reserves rows and layers together.
        h("0B 1005 1B 1001 1C 0C 2009")
    );

    /// The priced wrapper's transfer faces reserve the ledger's
    /// missing entries beside the machine obligations; a refusal at
    /// any point leaves prices, census, and total untouched.
    #[cfg(feature = "priced-transfer-session-groupless")]
    mod priced {
        use super::*;

        use protobuf_edit::session::groupless::TransferSession;
        use protobuf_edit::session::groupless::transfer::{InsertAt, PayloadTarget};

        fn fingerprint(
            p: &protobuf_edit::session::groupless::PricedTransferSession,
        ) -> (usize, Result<u32, protobuf_edit::session::groupless::transfer::SaveFault>, Vec<u8>)
        {
            (p.pending(), p.save_len(), p.save().unwrap().as_slice().to_vec())
        }

        fn probe_all(
            mut cmd: impl FnMut(&mut protobuf_edit::session::groupless::PricedTransferSession) -> bool,
            doc: &[u8],
        ) {
            let _guard = arm_window();
            for nth in 0..32 {
                let mut p = TransferSession::open_copy(doc)
                    .expect("probe doc opens")
                    .into_priced()
                    .map_err(|_| ())
                    .expect("clean admits");
                let before = fingerprint(&p);
                arm(nth);
                let ok = cmd(&mut p);
                disarm();
                if ok {
                    assert!(nth > 0, "probe enumerated zero allocation points");
                    return;
                }
                let after = fingerprint(&p);
                assert_eq!(before, after, "prices changed on Err at allocation {nth}");
            }
            panic!("command still failing after 32 injected faults");
        }

        #[test]
        fn priced_transfers_are_atomic_under_allocator_faults() {
            let doc = h("089601 12026869");
            let f9 = FieldNumber::new(9).unwrap();
            probe_all(
                |p| {
                    let len = p.top().nth(1).unwrap();
                    p.copy_record(len, InsertAt::HeadOf(None)).is_ok()
                },
                &doc,
            );
            probe_all(
                |p| {
                    let first = p.top().next().unwrap();
                    let second = p.top().nth(1).unwrap();
                    p.move_record(first, InsertAt::After(second)).is_ok()
                },
                &doc,
            );
            probe_all(
                |p| {
                    let len = p.top().nth(1).unwrap();
                    p.copy_payload(
                        len,
                        PayloadTarget::Insert { at: InsertAt::HeadOf(None), field: f9 },
                    )
                    .is_ok()
                },
                &doc,
            );
            probe_all(
                |p| {
                    let len = p.top().nth(1).unwrap();
                    p.move_payload(len, InsertAt::HeadOf(None), f9).is_ok()
                },
                &doc,
            );
        }
    }
}

/// The transfer copy-count rows: local and borrowed transfer faces
/// stage zero payload bytes (their slots are coordinates), while
/// the copy-backed external face stages exactly one record-length
/// extent. Judged on the armed thread's requested-bytes account —
/// a face that quietly staged the four-kilobyte payload would show
/// a payload-sized request.
mod transfer_copy_counts {
    use super::*;

    use protobuf_edit::DepthLimit;
    use protobuf_edit::patch::groupless::TransferPatch;
    use protobuf_edit::patch::groupless::transfer::{InsertAt, PayloadTarget};

    /// varint f1 · LEN f2 with a `len`-byte payload.
    fn doc(len: usize) -> Vec<u8> {
        let mut doc = vec![0x08, 0x07, 0x12];
        assert!((128..16384).contains(&len), "two-byte prefix fixture");
        doc.push(u8::try_from(len & 0x7F).unwrap() | 0x80);
        doc.push(u8::try_from(len >> 7).unwrap());
        doc.extend(core::iter::repeat_n(0xAB, len));
        doc
    }

    #[test]
    fn local_faces_stage_zero_payload_bytes() {
        let data = doc(4096);
        let mut patch = TransferPatch::open(&data, DepthLimit::REFERENCE).unwrap();
        let tops: Vec<_> = patch.top().collect();
        let ((), _, max, _) = measured(|| {
            patch.copy_record(tops[1], InsertAt::TailOf(None)).unwrap();
            patch.copy_payload(tops[1], PayloadTarget::Replace(tops[1])).unwrap();
            patch
                .copy_payload(
                    tops[1],
                    PayloadTarget::Insert {
                        at: InsertAt::TailOf(None),
                        field: protobuf_edit::FieldNumber::new(3).unwrap(),
                    },
                )
                .unwrap();
            patch.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
        });
        assert!(max < 4096, "a local transfer staged payload-scale bytes ({max})");

        // The copy-only sibling's local faces are coordinates too.
        let mut copy_only = TransferPatch::open(&data, DepthLimit::REFERENCE).unwrap();
        let tops: Vec<_> = copy_only.top().collect();
        let ((), _, max, _) = measured(|| {
            copy_only.copy_record(tops[1], InsertAt::TailOf(None)).unwrap();
            copy_only.copy_payload(tops[1], PayloadTarget::Replace(tops[1])).unwrap();
        });
        assert!(max < 4096, "a copy-only local transfer staged payload-scale bytes ({max})");
    }

    #[test]
    fn external_faces_follow_the_destination_backing() {
        use protobuf_edit::inspect::groupless::Tree;
        use protobuf_edit::inspect::{Admitted, NoAdvice};

        let foreign = doc(4096);
        let input = Admitted::new(&foreign).unwrap();
        let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
        let record = tree.record_ref(tree.top().nth(1).unwrap()).unwrap();
        let record_len = record.as_bytes().len();

        // The borrowed import retains the designation: zero staging.
        let base = [0x08u8, 0x07];
        let mut borrowed = TransferPatch::open(&base, DepthLimit::REFERENCE).unwrap();
        let (_, _, max, _) =
            measured(|| borrowed.copy_record_from(record, InsertAt::TailOf(None)).unwrap());
        assert!(max < record_len, "a borrowed import staged record-scale bytes ({max})");

        // The copying import stages exactly one record-length
        // extent: the staging request is the largest and covers the
        // record once.
        let mut copied = TransferPatch::open(&base, DepthLimit::REFERENCE).unwrap();
        let (_, _, max, total) =
            measured(|| copied.copy_record_from_copy(record, InsertAt::TailOf(None)).unwrap());
        assert!(max >= record_len, "the copying import staged less than the record ({max})");
        assert!(
            total < record_len * 2,
            "the copying import staged the record more than once ({total})"
        );
    }

    #[test]
    fn revisable_local_faces_stage_zero_payload_bytes() {
        use protobuf_edit::session::groupless::TransferSession;
        use protobuf_edit::session::groupless::transfer::{
            InsertAt as SessionAt, PayloadTarget as SessionTarget,
        };

        let data = doc(4096);
        let mut s = TransferSession::open_copy(&data).unwrap();
        let tops: Vec<_> = s.top().collect();
        let ((), _, max, _) = measured(|| {
            s.copy_payload(tops[1], SessionTarget::Replace(tops[1])).unwrap();
            s.clear_edit(tops[1]).unwrap();
            s.copy_record(tops[1], SessionAt::TailOf(None)).unwrap();
            s.copy_payload(
                tops[1],
                SessionTarget::Insert {
                    at: SessionAt::TailOf(None),
                    field: protobuf_edit::FieldNumber::new(3).unwrap(),
                },
            )
            .unwrap();
            s.move_record(tops[0], SessionAt::TailOf(None)).unwrap();
            s.move_payload(
                tops[1],
                SessionAt::TailOf(None),
                protobuf_edit::FieldNumber::new(4).unwrap(),
            )
            .unwrap();
        });
        assert!(max < 4096, "a revisable local transfer staged payload-scale bytes ({max})");
    }

    #[test]
    fn borrowed_imports_retain_without_staging() {
        use protobuf_edit::session::groupless::transfer::InsertAt as SessionAt;
        use protobuf_edit::session::groupless::{TransferBorrowSession, TransferSession};

        let foreign = doc(4096);
        let outside = TransferSession::open_copy(&foreign).unwrap();
        let source = outside.top().nth(1).unwrap();
        let record = outside.record_ref(source).unwrap();
        let record_len = record.as_bytes().len();
        let proof = record.try_canonical().unwrap();

        let mut s = TransferBorrowSession::open_copy(&[0x08, 0x07]).unwrap();
        let (_, _, max, _) =
            measured(|| s.copy_record_from(proof, SessionAt::TailOf(None)).unwrap());
        assert!(max < record_len, "the borrowed import staged record-scale bytes ({max})");
    }

    #[test]
    fn grouped_borrowed_imports_retain_without_staging() {
        use protobuf_edit::session::grouped::transfer::InsertAt as SessionAt;
        use protobuf_edit::session::grouped::{TransferBorrowSession, TransferSession};

        let foreign = doc(4096);
        let outside = TransferSession::open_copy(&foreign).unwrap();
        let source = outside.top().nth(1).unwrap();
        let record = outside.record_ref(source).unwrap();
        let record_len = record.as_bytes().len();
        let proof = record.try_canonical().unwrap();

        let mut s = TransferBorrowSession::open_copy(&[0x08, 0x07]).unwrap();
        let (_, _, max, _) =
            measured(|| s.copy_record_from(proof, SessionAt::TailOf(None)).unwrap());
        assert!(max < record_len, "the borrowed import staged record-scale bytes ({max})");
    }

    #[test]
    fn revisable_imports_stage_exactly_the_record() {
        use protobuf_edit::session::groupless::TransferSession;
        use protobuf_edit::session::groupless::transfer::InsertAt as SessionAt;

        let foreign = doc(4096);
        let outside = TransferSession::open_copy(&foreign).unwrap();
        let source = outside.top().nth(1).unwrap();
        let record = outside.record_ref(source).unwrap();
        let record_len = record.as_bytes().len();
        let proof = record.try_canonical().unwrap();

        let mut s = TransferSession::open_copy(&[0x08, 0x07]).unwrap();
        let (_, _, max, total) =
            measured(|| s.copy_record_from(proof, SessionAt::TailOf(None)).unwrap());
        assert!(max >= record_len, "the copying import staged less than the record ({max})");
        assert!(
            total < record_len * 2,
            "the copying import staged the record more than once ({total})"
        );
    }
}

/// The stream-ingest resource matrix and allocation-lineage judges:
/// every fallible growth edge of the stream drafts armed one
/// allocation at a time with exact chunk custody on every refusal,
/// and the counting rows that pin one source lineage, no
/// concatenation buffer, and a seal that allocates nothing
/// source-sized (row and layer allocations are the finished
/// editor's own parse products, accounted separately).
mod stream_ingest {
    use protobuf_edit::DepthLimit;
    use protobuf_edit::varint::push64;

    use super::*;

    /// Sweeps the whole groupless draft ingest under a failing
    /// allocator: per refusal, the site is named, the shell is
    /// spent, no editor is published, and the returned source is
    /// exactly the offered bytes minus an unabsorbed chunk.
    #[test]
    fn draft_groupless_ingest_is_transactional_under_allocator_faults() {
        use protobuf_edit::stream_draft::groupless::{
            ChunkDisposition, Ingest, IngestFaultKind, ResourceSite,
        };

        // varint · LEN "hi" · varint, fed byte-at-a-time so the
        // source reservations, every row publish, and the seal's
        // run reservation all sit inside the armed window.
        let doc = h("089601 12026869 1007");
        let mut sites_seen = std::vec::Vec::new();
        for nth in 0..64 {
            let _guard = arm_window();
            // The probe's own custody ledger must not allocate
            // inside the armed window.
            let mut offered = std::vec::Vec::with_capacity(doc.len());
            let mut job = Ingest::new();
            let mut failure = None;
            arm(nth);
            for &byte in &doc {
                offered.push(byte);
                if let Err(refused) = job.feed(&[byte]) {
                    failure = Some(refused);
                    break;
                }
            }
            let outcome = failure.map_or_else(|| job.finish().map(Some), Err);
            disarm();
            match outcome {
                Ok(Some(draft)) => {
                    assert!(nth > 0, "sweep enumerated zero allocation points");
                    assert!(
                        sites_seen.contains(&ResourceSite::Source)
                            && sites_seen.contains(&ResourceSite::Rows)
                            && sites_seen.contains(&ResourceSite::Run),
                        "the sweep must arm every growth edge: {sites_seen:?}"
                    );
                    assert_eq!(draft.source(), doc);
                    assert_eq!(draft.save().unwrap(), doc);
                    return;
                }
                Ok(None) => unreachable!("finish maps into Some"),
                Err(failure) => {
                    let IngestFaultKind::Resource(site) = failure.fault().kind() else {
                        panic!("armed refusal judged {:?}", failure.fault().kind());
                    };
                    sites_seen.push(site);
                    // Custody: a refused reservation leaves the
                    // chunk untouched; every later edge absorbs it
                    // whole (the suffix copy spends the reservation,
                    // never the allocator).
                    let expect: &[u8] = match (site, failure.chunk()) {
                        (ResourceSite::Source, ChunkDisposition::Unabsorbed) => {
                            &offered[..offered.len() - 1]
                        }
                        (ResourceSite::Rows | ResourceSite::Run, ChunkDisposition::Absorbed) => {
                            &offered
                        }
                        pair => panic!("site/custody disagree at allocation {nth}: {pair:?}"),
                    };
                    assert_eq!(failure.source(), expect, "custody at allocation {nth}");
                }
            }
        }
        panic!("ingest still failing after 64 injected faults");
    }

    /// The grouped twin's sweep adds the layer table to the armed
    /// edges: a group open mints its final layer descriptor
    /// fallibly.
    #[test]
    fn draft_grouped_ingest_is_transactional_under_allocator_faults() {
        use protobuf_edit::stream_draft::grouped::{
            ChunkDisposition, Ingest, IngestFaultKind, ResourceSite,
        };

        // varint · group f2 { varint f3 } · LEN "a", byte-at-a-time.
        let doc = h("089601 13 1809 14 120161");
        let mut sites_seen = std::vec::Vec::new();
        for nth in 0..64 {
            let _guard = arm_window();
            // The probe's own custody ledger must not allocate
            // inside the armed window.
            let mut offered = std::vec::Vec::with_capacity(doc.len());
            let mut job = Ingest::new();
            let mut failure = None;
            arm(nth);
            for &byte in &doc {
                offered.push(byte);
                if let Err(refused) = job.feed(&[byte]) {
                    failure = Some(refused);
                    break;
                }
            }
            let outcome = failure.map_or_else(|| job.finish().map(Some), Err);
            disarm();
            match outcome {
                Ok(Some(draft)) => {
                    assert!(nth > 0, "sweep enumerated zero allocation points");
                    assert!(
                        sites_seen.contains(&ResourceSite::Source)
                            && sites_seen.contains(&ResourceSite::Rows)
                            && sites_seen.contains(&ResourceSite::Layers)
                            && sites_seen.contains(&ResourceSite::Run),
                        "the sweep must arm every growth edge: {sites_seen:?}"
                    );
                    assert_eq!(draft.source(), doc);
                    assert_eq!(draft.save().unwrap(), doc);
                    return;
                }
                Ok(None) => unreachable!("finish maps into Some"),
                Err(failure) => {
                    let IngestFaultKind::Resource(site) = failure.fault().kind() else {
                        panic!("armed refusal judged {:?}", failure.fault().kind());
                    };
                    sites_seen.push(site);
                    let expect: &[u8] = match (site, failure.chunk()) {
                        (ResourceSite::Source, ChunkDisposition::Unabsorbed) => {
                            &offered[..offered.len() - 1]
                        }
                        (
                            ResourceSite::Rows | ResourceSite::Layers | ResourceSite::Run,
                            ChunkDisposition::Absorbed,
                        ) => &offered,
                        pair => panic!("site/custody disagree at allocation {nth}: {pair:?}"),
                    };
                    assert_eq!(failure.source(), expect, "custody at allocation {nth}");
                }
            }
        }
        panic!("ingest still failing after 64 injected faults");
    }

    /// An opaque-heavy document: one LEN wrapping `body` bytes.
    fn opaque_doc(body: usize) -> Vec<u8> {
        let mut doc = std::vec![0x22];
        push64(&mut doc, body as u64);
        doc.extend(std::iter::repeat_n(0xAB, body));
        doc
    }

    /// The known-capacity lineage row: one exact source allocation,
    /// no second document-sized buffer, and a seal that allocates
    /// nothing at all.
    #[test]
    fn adopt_ingest_holds_one_source_lineage_and_seals_allocation_free() {
        use protobuf_edit::stream_adopt::groupless::Ingest;

        let doc = opaque_doc(4096);
        let (job, _, max, total) = measured(|| {
            let mut job = Ingest::with_capacity(DepthLimit::REFERENCE, doc.len()).unwrap();
            job.feed(&doc).unwrap();
            job
        });
        assert!(max <= doc.len(), "a request outgrew the document: {max}");
        assert!(
            total <= doc.len() + 256,
            "a second document-sized buffer would show here: {total}"
        );
        let (adopt, count, _, _) = measured(|| job.finish().unwrap());
        assert_eq!(count, 0, "the one-shot seal allocates: {count} calls");
        assert_eq!(adopt.source(), doc);
    }

    /// The over-capacity control for the capacity-hint contract:
    /// cumulative feeds past the reservation stay lawful and regrow
    /// the backing — the single-allocation sentence holds exactly
    /// within `capacity`, and this row pins the lawful side beyond
    /// it.
    #[test]
    fn adopt_ingest_regrows_lawfully_past_its_capacity_hint() {
        use protobuf_edit::stream_adopt::groupless::Ingest;

        let doc = opaque_doc(4096);
        let (job, count, _, _) = measured(|| {
            let mut job = Ingest::with_capacity(DepthLimit::REFERENCE, 8).unwrap();
            job.feed(&doc).unwrap();
            job
        });
        assert!(count >= 2, "the overfed backing regrew: {count} calls");
        let adopt = job.finish().unwrap();
        assert_eq!(adopt.source(), doc);
    }

    /// The canonical twin's known-capacity lineage row: the fused
    /// width judgment rides the same single source allocation, no
    /// second document-sized buffer beside it, and the one-shot
    /// seal allocates nothing at all.
    #[test]
    fn intake_ingest_holds_one_source_lineage_and_seals_allocation_free() {
        use protobuf_edit::stream_intake::groupless::Ingest;

        let doc = opaque_doc(4096);
        let (job, _, max, total) = measured(|| {
            let mut job = Ingest::with_capacity(DepthLimit::REFERENCE, doc.len()).unwrap();
            job.feed(&doc).unwrap();
            job
        });
        assert!(max <= doc.len(), "a request outgrew the document: {max}");
        assert!(
            total <= doc.len() + 256,
            "a second document-sized buffer would show here: {total}"
        );
        let (intake, count, _, _) = measured(|| job.finish().unwrap());
        assert_eq!(count, 0, "the one-shot seal allocates: {count} calls");
        assert_eq!(intake.source(), doc);
    }

    /// The canonical twin's over-capacity control: cumulative feeds
    /// past the reservation stay lawful and regrow the backing —
    /// the single-allocation sentence holds exactly within
    /// `capacity`, and this row pins the lawful side beyond it.
    #[test]
    fn intake_ingest_regrows_lawfully_past_its_capacity_hint() {
        use protobuf_edit::stream_intake::groupless::Ingest;

        let doc = opaque_doc(4096);
        let (job, count, _, _) = measured(|| {
            let mut job = Ingest::with_capacity(DepthLimit::REFERENCE, 8).unwrap();
            job.feed(&doc).unwrap();
            job
        });
        assert!(count >= 2, "the overfed backing regrew: {count} calls");
        let intake = job.finish().unwrap();
        assert_eq!(intake.source(), doc);
    }

    /// The unknown-capacity lineage row: geometric growth is one
    /// reallocation chain, never a second logical source buffer,
    /// and the revisable seal allocates only its run entry.
    #[test]
    fn draft_ingest_growth_is_one_lineage_and_the_seal_is_flat() {
        use protobuf_edit::stream_draft::groupless::Ingest;

        let doc = opaque_doc(4096);
        let (job, _, max, total) = measured(|| {
            let mut job = Ingest::new();
            for chunk in doc.chunks(64) {
                job.feed(chunk).unwrap();
            }
            job
        });
        assert!(
            max <= doc.len() * 2,
            "a doubling chain tops out under twice the document; more \
             means a second lineage: {max}"
        );
        assert!(
            total <= doc.len() * 4 + 256,
            "a doubling chain totals under four documents (the row \
             arena rides in the slack); more means a second lineage \
             beside it: {total}"
        );
        let (draft, count, max, _) = measured(|| job.finish().unwrap());
        assert!(count <= 1, "the revisable seal owes one run entry at most: {count}");
        assert!(max <= 64, "the seal's one reservation is a run entry, not a buffer: {max}");
        assert_eq!(draft.source(), doc);
    }
}

/// The stream collector's allocation-lineage rows: one logical
/// source lineage (pre-sized exact and geometric growth as
/// distinct rows), no concatenation buffer beside it, and a seal
/// whose only allocation is the row box — never source-sized. The
/// working allocations beside the source are the row-arena seed
/// (an eighth of the stream length in 24-byte rows, capped), the
/// frame reserve, and the lazy advisor path; the bounds below give
/// each its named slack and nothing more, so a second
/// document-sized buffer cannot hide inside them.
mod collect_lineage {
    use protobuf_edit::collect::NoAdvice;
    use protobuf_edit::varint::push64;
    use protobuf_edit::{DepthLimit, Standard};

    use super::*;

    /// An opaque-heavy document: one LEN wrapping `body` bytes
    /// (the finished index holds one row, so the row box is tiny
    /// and a source-sized seal allocation cannot masquerade as
    /// it).
    fn opaque_doc(body: usize) -> Vec<u8> {
        let mut doc = std::vec![0x22];
        push64(&mut doc, body as u64);
        doc.extend(std::iter::repeat_n(0xAB, body));
        doc
    }

    /// The known-capacity row: one exact source allocation, the
    /// row seed beside it, and a seal that allocates the row box
    /// alone.
    #[test]
    fn collect_with_capacity_holds_one_source_lineage_and_seals_by_row_box() {
        use protobuf_edit::collect::groupless::Collector;

        let doc = opaque_doc(4096);
        let mut advice = NoAdvice;
        let (collector, count, max, total) = measured(|| {
            let mut collector = Collector::with_capacity(
                Standard::Tolerant,
                DepthLimit::REFERENCE,
                &mut advice,
                doc.len(),
            )
            .unwrap();
            collector.feed(&doc).unwrap();
            collector
        });
        // Construction plus the whole feed: the exact source
        // reservation, the row seed (len/8 rows at 24 bytes), the
        // frame floor, and at most one lazy path materialization.
        assert!(count <= 4, "construction and one feed hold four allocations: {count}");
        assert!(
            max <= doc.len() * 3 + 64,
            "the largest request is the row seed (three bytes per stream byte): {max}"
        );
        assert!(
            total <= doc.len() * 4 + 1024,
            "a second document-sized lineage would show here: {total}"
        );
        let (tree, count, max, _) = measured(|| collector.finish());
        assert!(count <= 1, "the seal owes the row box alone: {count} calls");
        assert!(max <= 32, "the seal's one allocation is the one-row box, not a buffer: {max}");
        assert_eq!(tree.bytes(), doc);
        assert_eq!(tree.node_count(), 1);
    }

    /// The unknown-capacity row: geometric growth is one
    /// reallocation chain — never a second logical source buffer —
    /// and the seal stays the row box. Judged on allocation
    /// identity: realloc events chain by address, and exactly two
    /// lineages may reach source scale — the source backing and
    /// the row arena (frames, path, and the working stacks stay
    /// under the floor) — so one extra document-sized buffer is a
    /// third lineage and a red verdict, not slack inside a byte
    /// total.
    #[test]
    fn collect_growth_is_one_source_lineage() {
        use protobuf_edit::collect::groupless::Collector;

        let doc = opaque_doc(4096);
        let mut advice = NoAdvice;
        let (collector, events, max, total) = traced(|| {
            let mut collector =
                Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
            for chunk in doc.chunks(64) {
                collector.feed(chunk).unwrap();
            }
            collector
        });
        let peaks = lineage_peaks(&events);
        let large: Vec<usize> = peaks.iter().copied().filter(|&peak| peak >= 1024).collect();
        assert_eq!(
            large.len(),
            2,
            "exactly the source chain and the row-arena chain reach \
             source scale; a third is a second logical source buffer \
             (peaks {large:?})"
        );
        assert!(
            max <= doc.len() * 3 + 64,
            "the largest request is a doubling step or the row seed: {max}"
        );
        assert!(
            total <= doc.len() * 12 + 2048,
            "one source doubling chain (topping at twice the next power \
             of two) plus the row-seed chain (three bytes per stream \
             byte, doubling); more means a second lineage beside \
             them: {total}"
        );
        let (tree, count, max, _) = measured(|| collector.finish());
        assert!(count <= 1, "the seal owes the row box alone: {count} calls");
        assert!(max <= 32, "the seal's one allocation is the one-row box, not a buffer: {max}");
        assert_eq!(tree.bytes(), doc);
    }

    /// The deep-advice attribution row: a 16-deep committed LEN
    /// chain materializes the advisor path and one frame per level,
    /// and neither may reach source scale — the traced window still
    /// holds exactly two source-scale lineages (the source chain and
    /// the row arena), so path and frame growth cannot masquerade as
    /// a second logical source buffer, and the seal still allocates
    /// the row box alone.
    #[test]
    fn deep_committed_descent_adds_no_source_scale_lineage() {
        use protobuf_edit::FieldNumber;
        use protobuf_edit::collect::groupless::Collector;
        use protobuf_edit::collect::{Advice, Advisor, Ancestry};

        struct CommitAll;
        impl Advisor for CommitAll {
            fn advise(&mut self, _: Ancestry<'_>, _: FieldNumber) -> Advice {
                Advice::Commit
            }
        }

        // varint f2 wrapped in 16 nested LEN messages on f4, the
        // chain repeated as siblings until the source clears the
        // lineage floor.
        let chain = {
            let mut record = std::vec![0x10, 0x05];
            for _ in 0..16 {
                let mut wrapped = std::vec![0x22];
                push64(&mut wrapped, record.len() as u64);
                wrapped.extend_from_slice(&record);
                record = wrapped;
            }
            record
        };
        let mut doc = std::vec::Vec::new();
        for _ in 0..64 {
            doc.extend_from_slice(&chain);
        }

        let mut advice = CommitAll;
        let (collector, events, _, _) = traced(|| {
            let mut collector = Collector::with_capacity(
                Standard::Tolerant,
                DepthLimit::REFERENCE,
                &mut advice,
                doc.len(),
            )
            .unwrap();
            for chunk in doc.chunks(64) {
                collector.feed(chunk).unwrap();
            }
            collector
        });
        let peaks = lineage_peaks(&events);
        let large: Vec<usize> = peaks.iter().copied().filter(|&peak| peak >= 1024).collect();
        assert_eq!(
            large.len(),
            2,
            "the committed descent adds no source-scale lineage beside \
             the source and row chains (peaks {large:?})"
        );
        let (tree, count, max, _) = measured(|| collector.finish());
        assert!(count <= 1, "the seal owes the row box alone: {count} calls");
        assert!(
            max <= tree.node_count() as usize * 24 + 64,
            "the seal's one allocation is the row box, not a buffer: {max}"
        );
        assert!(tree.is_complete(), "the committed chains parse clean");
        assert_eq!(tree.node_count(), 64 * 17, "every level of every chain is indexed");
        assert_eq!(tree.bytes(), doc);
    }

    /// The grouped twin's row: frames and group rows ride the same
    /// lineage discipline.
    #[test]
    fn grouped_collect_holds_the_same_lineage() {
        use protobuf_edit::collect::grouped::Collector;

        // A group wrapping the opaque LEN, closed at the end.
        let mut doc = std::vec![0x0B];
        doc.extend(opaque_doc(4096));
        doc.push(0x0C);
        let mut advice = NoAdvice;
        let (collector, _, max, total) = measured(|| {
            let mut collector = Collector::with_capacity(
                Standard::Tolerant,
                DepthLimit::REFERENCE,
                &mut advice,
                doc.len(),
            )
            .unwrap();
            for chunk in doc.chunks(64) {
                collector.feed(chunk).unwrap();
            }
            collector
        });
        assert!(max <= doc.len() * 3 + 64, "the largest request is the row seed: {max}");
        assert!(total <= doc.len() * 4 + 1024, "a second lineage would show here: {total}");
        let (tree, count, max, _) = measured(|| collector.finish());
        assert!(count <= 1, "the seal owes the row box alone: {count} calls");
        assert!(max <= 64, "the two-row box is not a buffer: {max}");
        assert_eq!(tree.bytes(), doc);
        assert_eq!(tree.node_count(), 2);
    }
}
