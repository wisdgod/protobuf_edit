//! The fixed patch cell's judge set.
//!
//! The carve, capacity, and pricing rows compile with the fixed
//! cell alone; the twin, allocator-window, and heap-comparison rows
//! additionally require the heap patch cell (`patch-*`).
//!
//! - Armed-allocator zero-count rows: whole jobs (open → descend →
//!   commands → saves) on every sibling of both dialects book
//!   exactly zero armed-thread allocations, with two controls — a
//!   planted allocation reddens the window, and the heap twin's
//!   allocating path books nonzero — so a zero is never a blind
//!   harness result.
//! - Exhaustion-refusal enumeration: for every plan role, a
//!   capacity one short of measured demand refuses at the judged
//!   site with the named lane, the machine's observable fingerprint
//!   is unchanged, and a smaller lawful command still succeeds (no
//!   capacity leaks). Every sweep asserts a refusal actually
//!   landed.
//! - Carve honesty: the door carves at `bytes()` and refuses at
//!   `bytes() - 1`, both repeated on a deliberately misaligned
//!   slab; a plan tightened to `budget()`'s high-water re-runs the
//!   same job.
//! - Transposition refusal: the ladder's one same-typed lane pair
//!   (scalar words / body words) is pinned to its own requirements
//!   at every door of every sibling — the word column refuses at
//!   exactly the declared word count while the row-derived body
//!   requirement sits elsewhere, and the body table runs at exactly
//!   its full row-derived occupancy while the word count sits
//!   elsewhere — so a carve that hands either position the other's
//!   capacity cannot pass.
//! - Runtime pricing mirror: over a spread of document shapes, a
//!   plan tightened to measured demand re-runs its whole job inside
//!   a slab of exactly `bytes()` at any address, one byte fewer
//!   refuses with the priced figure named, and one compile-time
//!   evaluation of the figure equals the runtime door's answer.
//! - Twin identity: seeded documents and command scripts drive a
//!   fixed machine and its heap twin in lockstep — verdicts, fault
//!   values, handle order, priced lengths, and every save byte must
//!   agree within plan.

#![cfg(all(feature = "fixed-patch-grouped", feature = "fixed-patch-groupless"))]
#![cfg_attr(all(feature = "patch-grouped", feature = "patch-groupless"), feature(thread_id_value))]

use core::mem::MaybeUninit;
#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
use std::sync::Mutex;
#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use protobuf_edit::{DepthLimit, FieldNumber};

// ─── the armed allocator (tests/alloc_fault.rs's counted face) ───

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
struct Armed;

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
static COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
static ARMED_THREAD: AtomicU64 = AtomicU64::new(0);

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
fn on_armed_thread() -> bool {
    std::thread::current().id().as_u64().get() == ARMED_THREAD.load(Ordering::Relaxed)
}

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
unsafe impl GlobalAlloc for Armed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if on_armed_thread() {
            COUNT.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if on_armed_thread() {
            COUNT.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
#[global_allocator]
static ALLOCATOR: Armed = Armed;

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
static ARM_LOCK: Mutex<()> = Mutex::new(());

/// Counts armed-thread allocations across `job`.
#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
fn counted<T>(job: impl FnOnce() -> T) -> (T, usize) {
    let _guard = ARM_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    ARMED_THREAD.store(std::thread::current().id().as_u64().get(), Ordering::Relaxed);
    let before = COUNT.load(Ordering::Relaxed);
    let out = job();
    let grew = COUNT.load(Ordering::Relaxed) - before;
    ARMED_THREAD.store(0, Ordering::Relaxed);
    (out, grew)
}

// ─── fixtures ───

/// Deterministic xorshift; no external RNG dependency.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

const fn f(n: u64) -> FieldNumber {
    FieldNumber::new(1 + (n % 24) as u32).expect("small field numbers are in class")
}

/// A hand emitter for seeded documents: minimal or continuation-
/// padded framing, so the twin corpora exercise the fidelity
/// contract's padded arm too.
struct Emitter {
    out: Vec<u8>,
}

impl Emitter {
    fn varint(&mut self, value: u64, pad: bool) {
        let mut v = value;
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                if pad && self.out.len().is_multiple_of(3) && value < (1 << 49) {
                    // One lawful continuation pad: tolerant wire.
                    self.out.push(byte | 0x80);
                    self.out.push(0x00);
                } else {
                    self.out.push(byte);
                }
                return;
            }
            self.out.push(byte | 0x80);
        }
    }

    fn tag(&mut self, field: FieldNumber, low3: u32, pad: bool) {
        self.varint(u64::from((field.as_inner() << 3) | low3), pad);
    }

    fn push_varint(&mut self, field: FieldNumber, value: u64, pad: bool) {
        self.tag(field, 0, pad);
        self.varint(value, pad);
    }

    fn push_i64(&mut self, field: FieldNumber, bits: u64, pad: bool) {
        self.tag(field, 1, pad);
        self.out.extend_from_slice(&bits.to_le_bytes());
    }

    fn push_i32(&mut self, field: FieldNumber, bits: u32, pad: bool) {
        self.tag(field, 5, pad);
        self.out.extend_from_slice(&bits.to_le_bytes());
    }

    fn push_len(&mut self, field: FieldNumber, body: &[u8], pad: bool) {
        self.tag(field, 2, pad);
        self.varint(body.len() as u64, pad);
        self.out.extend_from_slice(body);
    }

    fn open_group(&mut self, field: FieldNumber, pad: bool) {
        self.tag(field, 3, pad);
    }

    fn close_group(&mut self, field: FieldNumber, pad: bool) {
        self.tag(field, 4, pad);
    }
}

/// One seeded layer of records; `depth` admits nested LEN bodies
/// (parsable messages, so descend commits them), `groups` admits
/// group frames.
fn grow(rng: &mut Rng, e: &mut Emitter, depth: u32, budget: &mut u32, groups: bool) {
    while *budget > 0 {
        *budget -= 1;
        let pad = rng.next().is_multiple_of(4);
        match rng.next() % if groups { 8 } else { 7 } {
            0 | 1 => e.push_varint(f(rng.next()), rng.next() >> (rng.next() % 60), pad),
            2 => e.push_i32(f(rng.next()), rng.next() as u32, pad),
            3 => e.push_i64(f(rng.next()), rng.next(), pad),
            4 => {
                let len = (rng.next() % 12) as usize;
                let body: Vec<u8> = (0..len).map(|i| 0xA0 | (i as u8 & 0x0F)).collect();
                e.push_len(f(rng.next()), &body, pad);
            }
            5 | 6 if depth > 0 => {
                let field = f(rng.next());
                let mut inner = Emitter { out: Vec::new() };
                let mut inner_budget = (rng.next() % 4 + 1) as u32;
                grow(rng, &mut inner, depth - 1, &mut inner_budget, false);
                e.push_len(field, &inner.out, pad);
            }
            7 if depth > 0 => {
                let field = f(rng.next());
                e.open_group(field, pad);
                let mut inner_budget = (rng.next() % 3 + 1) as u32;
                grow(rng, e, depth - 1, &mut inner_budget, groups);
                e.close_group(field, pad);
            }
            _ => e.push_varint(f(rng.next()), rng.next(), pad),
        }
    }
}

/// One seeded document.
fn document(seed: u64, groups: bool) -> Vec<u8> {
    let mut rng = Rng(seed | 1);
    let mut e = Emitter { out: Vec::new() };
    let mut budget = (rng.next() % 12 + 3) as u32;
    grow(&mut rng, &mut e, 3, &mut budget, groups);
    e.out
}

/// A generous plan for the seeded corpora: roomy enough that no
/// twin run can exhaust it.
#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
const GENEROUS: (u32, u32, u32, u32, u32) = (512, 64, 64, 4096, 16);

fn slab_for(bytes: u64) -> Vec<MaybeUninit<u8>> {
    vec![MaybeUninit::uninit(); usize::try_from(bytes).unwrap()]
}

// ─── the mirrored twin scripts, one macro per dialect ───
//
// The runner drives the heap twin and the fixed twin through the
// same seeded command script and compares every observable: command
// verdicts (`Debug`-rendered), descend verdicts, handle order,
// priced lengths, and every save byte. One text per dialect because
// the grouped script also authors groups; the sibling variations
// (which payload faces exist) ride flags.

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
macro_rules! twin_script {
    ($name:ident, $dialect:ident, $groups:expr) => {
        mod $name {
            use super::*;
            use protobuf_edit::fixed_patch::$dialect as fixed;
            use protobuf_edit::patch::$dialect as host;

            /// Drives one op on both machines and compares the
            /// verdict shape.
            macro_rules! mirror {
                ($h:expr, $x:expr) => {{
                    let host_out = $h;
                    let fixed_out = $x;
                    assert_eq!(
                        format!("{host_out:?}"),
                        format!("{fixed_out:?}"),
                        "twin verdicts diverge"
                    );
                }};
            }

            /// The full mirrored job over the mixed siblings.
            pub fn run(seed: u64) {
                let doc = document(seed, $groups);
                let mut rng = Rng(seed ^ 0x9E37_79B9_7F4A_7C15);
                // Payload owners outliving both machines.
                let pool: Vec<Vec<u8>> = (0..8)
                    .map(|i| (0..(rng.next() % 20) as usize).map(|j| (i * 31 + j) as u8).collect())
                    .collect();
                let piece_a: Vec<u8> = vec![0x08, 0x01];
                let piece_b: Vec<u8> = vec![0xFF; 3];
                let parts: Vec<&[u8]> = vec![&piece_a, &piece_b];

                let mut host = host::Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
                let plan =
                    fixed::Plan::new(GENEROUS.0, GENEROUS.1, GENEROUS.2, GENEROUS.3, GENEROUS.4)
                        .unwrap();
                let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
                let mut fixed =
                    fixed::Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();

                // The command script: forty seeded ops over the
                // top layer and one descended level.
                for _ in 0..40 {
                    let host_tops: Vec<_> = host.top().collect();
                    let fixed_tops: Vec<_> = fixed.top().collect();
                    assert_eq!(host_tops.len(), fixed_tops.len(), "top chains diverge");
                    if host_tops.is_empty() {
                        let field = f(rng.next());
                        mirror!(
                            host.insert_varint(host::InsertAt::TailOf(None), field, 7),
                            fixed.insert_varint(fixed::InsertAt::TailOf(None), field, 7)
                        );
                        continue;
                    }
                    let at = (rng.next() % host_tops.len() as u64) as usize;
                    let (h, x) = (host_tops[at], fixed_tops[at]);
                    match rng.next() % 13 {
                        0 => {
                            let v = rng.next();
                            mirror!(host.set_varint(h, v), fixed.set_varint(x, v));
                        }
                        1 => {
                            let bits = rng.next() as u32;
                            mirror!(host.set_i32(h, bits), fixed.set_i32(x, bits));
                        }
                        2 => {
                            let bits = rng.next();
                            mirror!(host.set_i64(h, bits), fixed.set_i64(x, bits));
                        }
                        3 => {
                            let p = &pool[(rng.next() % pool.len() as u64) as usize];
                            mirror!(host.set_payload(h, p), fixed.set_payload(x, p));
                        }
                        4 => {
                            let p = &pool[(rng.next() % pool.len() as u64) as usize];
                            mirror!(host.set_payload_copy(h, p), fixed.set_payload_copy(x, p));
                        }
                        5 => {
                            mirror!(
                                host.set_payload_parts(h, &parts),
                                fixed.set_payload_parts(x, &parts)
                            );
                        }
                        6 => mirror!(host.delete(h), fixed.delete(x)),
                        7 => {
                            let field = f(rng.next());
                            let v = rng.next();
                            mirror!(
                                host.insert_varint(host::InsertAt::After(h), field, v),
                                fixed.insert_varint(fixed::InsertAt::After(x), field, v)
                            );
                        }
                        8 => {
                            let field = f(rng.next());
                            let p = &pool[(rng.next() % pool.len() as u64) as usize];
                            mirror!(
                                host.insert_payload(host::InsertAt::HeadOf(None), field, p),
                                fixed.insert_payload(fixed::InsertAt::HeadOf(None), field, p)
                            );
                        }
                        9 => {
                            // Descend, then edit the first interior
                            // record when one exists.
                            let hv = host.descend(h);
                            let xv = fixed.descend(x);
                            mirror!(&hv, &xv);
                            if let (
                                Ok(host::Descent::Opened { first: Some(hf) }),
                                Ok(fixed::Descent::Opened { first: Some(xf) }),
                            ) = (hv, xv)
                            {
                                let v = rng.next();
                                mirror!(host.set_varint(hf, v), fixed.set_varint(xf, v));
                            }
                        }
                        10 => {
                            // A sized staged frame, exact.
                            let p = &pool[(rng.next() % pool.len() as u64) as usize];
                            let hr = host.begin_set_payload_sized(h, p.len()).and_then(|mut fr| {
                                fr.write(p).map_err(|_| host::EditFault::DeletedTarget)?;
                                fr.finish().map_err(|_| host::EditFault::DeletedTarget)
                            });
                            let xr =
                                fixed.begin_set_payload_sized(x, p.len()).and_then(|mut fr| {
                                    fr.write(p).map_err(|_| fixed::EditFault::DeletedTarget)?;
                                    fr.finish().map_err(|_| fixed::EditFault::DeletedTarget)
                                });
                            mirror!(&hr.is_ok(), &xr.is_ok());
                            mirror!(
                                &hr.err().map(|e| format!("{e:?}")),
                                &xr.err().map(|e| format!("{e:?}"))
                            );
                        }
                        11 => {
                            // An undeclared staged frame, written in
                            // two chunks.
                            let p = &pool[(rng.next() % pool.len() as u64) as usize];
                            let hr = host.begin_set_payload(h).and_then(|mut fr| {
                                fr.write(p)?;
                                fr.write(b"!")?;
                                fr.finish()
                            });
                            let xr = fixed.begin_set_payload(x).and_then(|mut fr| {
                                fr.write(p)?;
                                fr.write(b"!")?;
                                fr.finish()
                            });
                            mirror!(&hr.is_ok(), &xr.is_ok());
                        }
                        _ => {
                            let v = rng.next();
                            mirror!(host.set_varint(h, v), fixed.set_varint(x, v));
                        }
                    }
                }

                // The identity faces, compared whole.
                let host_len = host.save_len();
                let fixed_len = fixed.save_len();
                mirror!(&host_len, &fixed_len);
                let mut host_out = Vec::new();
                host.save_into(&mut host_out).unwrap();
                let mut fixed_out = vec![0u8; host_out.len()];
                let written = fixed.save_into(&mut fixed_out).unwrap();
                assert_eq!(usize::try_from(written).unwrap(), host_out.len());
                assert_eq!(fixed_out, host_out, "fidelity saves diverge");

                let mut host_sink = Vec::new();
                host.save_sink(|bytes| host_sink.extend_from_slice(bytes)).unwrap();
                let mut fixed_sink = Vec::new();
                fixed.save_sink(|bytes| fixed_sink.extend_from_slice(bytes)).unwrap();
                assert_eq!(fixed_sink, host_out, "sink saves diverge");
                assert_eq!(host_sink, host_out);

                let host_canon = host.save_canonical().unwrap();
                let mut fixed_canon = vec![0u8; host_canon.len()];
                let cwritten = fixed.save_canonical_into(&mut fixed_canon).unwrap();
                assert_eq!(usize::try_from(cwritten).unwrap(), host_canon.len());
                assert_eq!(fixed_canon, host_canon, "canonical saves diverge");
                let mut fixed_canon_sink = Vec::new();
                fixed
                    .save_canonical_sink(|bytes| fixed_canon_sink.extend_from_slice(bytes))
                    .unwrap();
                assert_eq!(fixed_canon_sink, host_canon, "canonical sinks diverge");

                // Read-face parity over the whole top chain.
                let host_tops: Vec<_> = host.top().collect();
                let fixed_tops: Vec<_> = fixed.top().collect();
                for (h, x) in host_tops.iter().zip(&fixed_tops) {
                    assert_eq!(format!("{:?}", host.status(*h)), format!("{:?}", fixed.status(*x)));
                    assert_eq!(host.kind(*h) as u8, fixed.kind(*x) as u8);
                    assert_eq!(host.field(*h), fixed.field(*x));
                    assert_eq!(host.span(*h), fixed.span(*x));
                    assert_eq!(
                        format!("{:?}", host.source_spans(*h)),
                        format!("{:?}", fixed.source_spans(*x))
                    );
                    assert_eq!(host.varint_word(*h), fixed.varint_word(*x));
                    assert_eq!(host.i32_bits(*h), fixed.i32_bits(*x));
                    assert_eq!(host.i64_bits(*h), fixed.i64_bits(*x));
                    assert_eq!(host.payload_bytes(*h), fixed.payload_bytes(*x));
                    // The designation face: minted values (bytes,
                    // proved columns, group depth) and refusals
                    // must agree whole.
                    assert_eq!(host.record_ref(*h), fixed.record_ref(*x), "designations diverge");
                }
                for pos in 0..u32::try_from(doc.len()).unwrap() {
                    assert_eq!(
                        host.narrowest(pos).map(|h| format!("{h:?}")),
                        fixed.narrowest(pos).map(|x| format!("{x:?}")),
                        "narrowest diverges at {pos}"
                    );
                }
                for probe in 1..=8u32 {
                    let field = FieldNumber::new(probe).unwrap();
                    assert_eq!(
                        host.top().by_field(field).count(),
                        fixed.top().by_field(field).count(),
                        "by_field diverges on field {probe}"
                    );
                }
            }

            /// The borrowed-only twin pair over the same corpora.
            pub fn run_borrow(seed: u64) {
                let doc = document(seed, $groups);
                let mut rng = Rng(seed ^ 0xD1B5_4A32_D192_ED03);
                let pool: Vec<Vec<u8>> = (0..6)
                    .map(|i| (0..(rng.next() % 16) as usize).map(|j| (i * 17 + j) as u8).collect())
                    .collect();
                let mut host = host::BorrowPatch::open(&doc, DepthLimit::REFERENCE).unwrap();
                let plan =
                    fixed::BorrowPlan::new(GENEROUS.0, GENEROUS.1, GENEROUS.2, GENEROUS.4).unwrap();
                let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
                let mut fixed =
                    fixed::BorrowPatch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab)
                        .unwrap();
                for _ in 0..24 {
                    let host_tops: Vec<_> = host.top().collect();
                    let fixed_tops: Vec<_> = fixed.top().collect();
                    assert_eq!(host_tops.len(), fixed_tops.len());
                    if host_tops.is_empty() {
                        break;
                    }
                    let at = (rng.next() % host_tops.len() as u64) as usize;
                    let (h, x) = (host_tops[at], fixed_tops[at]);
                    match rng.next() % 4 {
                        0 => {
                            let v = rng.next();
                            mirror!(host.set_varint(h, v), fixed.set_varint(x, v));
                        }
                        1 => {
                            let p = &pool[(rng.next() % pool.len() as u64) as usize];
                            mirror!(host.set_payload(h, p), fixed.set_payload(x, p));
                        }
                        2 => mirror!(host.delete(h), fixed.delete(x)),
                        _ => {
                            mirror!(&host.descend(h), &fixed.descend(x));
                        }
                    }
                }
                let mut host_out = Vec::new();
                host.save_into(&mut host_out).unwrap();
                let mut fixed_out = vec![0u8; host_out.len()];
                fixed.save_into(&mut fixed_out).unwrap();
                assert_eq!(fixed_out, host_out, "borrowed-sibling saves diverge");

                // The sibling's own designation face, minted values
                // and refusals whole.
                let host_tops: Vec<_> = host.top().collect();
                let fixed_tops: Vec<_> = fixed.top().collect();
                for (h, x) in host_tops.iter().zip(&fixed_tops) {
                    assert_eq!(host.record_ref(*h), fixed.record_ref(*x), "designations diverge");
                }
            }

            /// The copy-only twin pair over the same corpora.
            pub fn run_copy(seed: u64) {
                let doc = document(seed, $groups);
                let mut rng = Rng(seed ^ 0x94D0_49BB_1331_11EB);
                let mut host = host::CopyPatch::open(&doc, DepthLimit::REFERENCE).unwrap();
                let plan = fixed::CopyPlan::new(
                    GENEROUS.0, GENEROUS.1, GENEROUS.2, GENEROUS.3, GENEROUS.4,
                )
                .unwrap();
                let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
                let mut fixed =
                    fixed::CopyPatch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
                for _ in 0..24 {
                    let host_tops: Vec<_> = host.top().collect();
                    let fixed_tops: Vec<_> = fixed.top().collect();
                    assert_eq!(host_tops.len(), fixed_tops.len());
                    if host_tops.is_empty() {
                        break;
                    }
                    let at = (rng.next() % host_tops.len() as u64) as usize;
                    let (h, x) = (host_tops[at], fixed_tops[at]);
                    match rng.next() % 4 {
                        0 => {
                            let v = rng.next();
                            mirror!(host.set_varint(h, v), fixed.set_varint(x, v));
                        }
                        1 => {
                            let p: Vec<u8> =
                                (0..(rng.next() % 10) as usize).map(|j| j as u8).collect();
                            mirror!(host.set_payload(h, &p), fixed.set_payload(x, &p));
                        }
                        2 => mirror!(host.delete(h), fixed.delete(x)),
                        _ => {
                            let p: Vec<u8> = vec![0x5A; (rng.next() % 6) as usize];
                            let hr = host
                                .begin_set_payload_sized(h, p.len())
                                .and_then(|mut fr| {
                                    fr.write(&p).ok();
                                    fr.finish().map_err(|_| host::EditFault::DeletedTarget)
                                })
                                .is_ok();
                            let xr = fixed
                                .begin_set_payload_sized(x, p.len())
                                .and_then(|mut fr| {
                                    fr.write(&p).ok();
                                    fr.finish().map_err(|_| fixed::EditFault::DeletedTarget)
                                })
                                .is_ok();
                            assert_eq!(hr, xr);
                        }
                    }
                }
                let mut host_out = Vec::new();
                host.save_into(&mut host_out).unwrap();
                let mut fixed_out = vec![0u8; host_out.len()];
                fixed.save_into(&mut fixed_out).unwrap();
                assert_eq!(fixed_out, host_out, "copy-sibling saves diverge");

                // The sibling's own designation face, minted values
                // and refusals whole.
                let host_tops: Vec<_> = host.top().collect();
                let fixed_tops: Vec<_> = fixed.top().collect();
                for (h, x) in host_tops.iter().zip(&fixed_tops) {
                    assert_eq!(host.record_ref(*h), fixed.record_ref(*x), "designations diverge");
                }
            }
        }
    };
}

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
twin_script!(twin_groupless, groupless, false);
#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
twin_script!(twin_grouped, grouped, true);

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
#[test]
fn twin_identity_groupless() {
    for seed in 1..=48u64 {
        twin_groupless::run(seed);
        twin_groupless::run_borrow(seed);
        twin_groupless::run_copy(seed);
    }
}

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
#[test]
fn twin_identity_grouped() {
    for seed in 1..=48u64 {
        twin_grouped::run(seed);
        twin_grouped::run_borrow(seed);
        twin_grouped::run_copy(seed);
    }
}

// ─── the designation face (record_ref) ───

/// The face law on the groupless siblings: a scanned row designates
/// its exact source bytes at their met framing (a pending value
/// replacement does not ride), and authored and deleted rows refuse
/// `NotSourceBacked` — on all three payload-backing forms.
#[test]
fn record_ref_face_groupless() {
    use protobuf_edit::fixed_patch::groupless::{
        BorrowPatch, BorrowPlan, CopyPatch, CopyPlan, InsertAt, Patch, Plan,
    };
    use protobuf_edit::source::groupless::Fault;

    // varint f1=150 (value padded to three bytes) · LEN f2 "hi"
    let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
    let plan = Plan::new(8, 4, 4, 64, 2).unwrap();
    let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
    let mut p = Patch::open(&msg, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
    let tops: Vec<_> = p.top().collect();

    // The scanned varint designates its met spelling whole; the
    // padded framing rides, so the canonical proof refuses.
    let varint = p.record_ref(tops[0]).unwrap();
    assert_eq!(varint.as_bytes(), &msg[..4]);
    assert_eq!(varint.field().as_inner(), 1);
    assert!(varint.try_canonical().is_err());

    // The LEN designates framing plus the payload projection.
    let len = p.record_ref(tops[1]).unwrap();
    assert_eq!(len.as_bytes(), &msg[4..]);
    assert_eq!(len.payload().unwrap().as_bytes(), b"hi");

    // A pending replacement does not ride the designation.
    p.set_varint(tops[0], 7).unwrap();
    assert_eq!(p.record_ref(tops[0]).unwrap().as_bytes(), &msg[..4]);

    // Authored rows refuse; deleted rows refuse.
    let authored = p.insert_varint(InsertAt::TailOf(None), f(3), 9).unwrap();
    assert_eq!(p.record_ref(authored), Err(Fault::NotSourceBacked));
    p.delete(tops[1]).unwrap();
    assert_eq!(p.record_ref(tops[1]), Err(Fault::NotSourceBacked));

    // The borrowed-only and copy-only siblings carry the same face.
    let bplan = BorrowPlan::new(8, 4, 4, 2).unwrap();
    let mut bslab = slab_for(bplan.bytes(DepthLimit::REFERENCE));
    let mut b = BorrowPatch::open(&msg, DepthLimit::REFERENCE, &bplan, &mut bslab).unwrap();
    let btop = b.top().next().unwrap();
    assert_eq!(b.record_ref(btop).unwrap().as_bytes(), &msg[..4]);
    let bauthored = b.insert_varint(InsertAt::TailOf(None), f(3), 9).unwrap();
    assert_eq!(b.record_ref(bauthored), Err(Fault::NotSourceBacked));

    let cplan = CopyPlan::new(8, 4, 4, 64, 2).unwrap();
    let mut cslab = slab_for(cplan.bytes(DepthLimit::REFERENCE));
    let mut c = CopyPatch::open(&msg, DepthLimit::REFERENCE, &cplan, &mut cslab).unwrap();
    let ctop = c.top().next().unwrap();
    assert_eq!(c.record_ref(ctop).unwrap().as_bytes(), &msg[..4]);
    let cauthored = c.insert_varint(InsertAt::TailOf(None), f(3), 9).unwrap();
    assert_eq!(c.record_ref(cauthored), Err(Fault::NotSourceBacked));
}

/// The grouped face adds the closure and its structural depth: a
/// group designates head-through-end-tag at its source-derived
/// nesting, and authored structure under the closure neither rides
/// nor moves the measured depth.
#[test]
fn record_ref_face_grouped() {
    use protobuf_edit::fixed_patch::grouped::{InsertAt, Patch, Plan};
    use protobuf_edit::source::grouped::Fault;

    // varint f1=1 · group f2 { group f3 { varint f4=5 } }
    let msg = [0x08, 0x01, 0x13, 0x1B, 0x20, 0x05, 0x1C, 0x14];
    let plan = Plan::new(8, 4, 4, 64, 2).unwrap();
    let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
    let mut p = Patch::open(&msg, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
    let tops: Vec<_> = p.top().collect();

    // A scalar designates at depth zero.
    let scalar = p.record_ref(tops[0]).unwrap();
    assert_eq!(scalar.as_bytes(), &msg[..2]);
    assert_eq!(scalar.group_depth(), 0);

    // The group designates its whole closure, end tag included, at
    // its measured structural nesting.
    let group = p.record_ref(tops[1]).unwrap();
    assert_eq!(group.as_bytes(), &msg[2..]);
    assert_eq!(group.group_depth(), 2);

    // Authored structure under the closure does not move the
    // source-derived depth, and the authored group itself refuses.
    let inner = p.children(tops[1]).next().unwrap();
    let authored = p.insert_group(InsertAt::HeadOf(Some(inner)), f(5)).unwrap();
    assert_eq!(p.record_ref(tops[1]).unwrap().group_depth(), 2);
    assert_eq!(p.record_ref(authored), Err(Fault::NotSourceBacked));
}

// ─── the armed-allocator zero-count rows ───

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
mod zero_count {
    use super::*;

    /// One whole job over the groupless mixed machine: open,
    /// descend (committed and faulted), every command class, both
    /// frames, every save face, budget. Everything the job touches
    /// is prepared before the window arms.
    fn groupless_job(
        doc: &[u8],
        slab: &mut [MaybeUninit<u8>],
        payload: &[u8],
        parts: &[&[u8]],
        out: &mut [u8],
    ) -> usize {
        use protobuf_edit::fixed_patch::groupless::{Descent, InsertAt, Patch, Plan};
        let plan = Plan::new(64, 16, 16, 256, 4).unwrap();
        let field = FieldNumber::new(9).unwrap();
        let ((), count) = counted(|| {
            let mut patch = Patch::open(doc, DepthLimit::REFERENCE, &plan, slab).unwrap();
            // Handles land in a fixed window: the armed job may not
            // allocate on its own behalf either.
            let mut tops = [None; 64];
            let mut filled = 0;
            for (n, h) in patch.top().enumerate() {
                tops[n] = Some(h);
                filled = n + 1;
            }
            for &top in tops.iter().flatten() {
                let _ = patch.descend(top);
            }
            let a = tops[0].unwrap();
            let _ = patch.set_varint(a, 7);
            let _ = patch.set_i32(a, 5);
            let _ = patch.set_i64(a, 5);
            let _ = patch.insert_varint(InsertAt::TailOf(None), field, 3);
            let mut opaque = None;
            for &h in tops.iter().flatten() {
                if patch.payload_bytes(h).is_some()
                    && !matches!(patch.descend(h), Ok(Descent::Opened { .. }))
                {
                    opaque = Some(h);
                    break;
                }
            }
            if let Some(len) = opaque {
                patch.set_payload(len, payload).unwrap();
                patch.set_payload_copy(len, payload).unwrap();
                patch.set_payload_parts(len, parts).unwrap();
                let mut frame = patch.begin_set_payload(len).unwrap();
                frame.write(payload).unwrap();
                frame.finish().unwrap();
                let mut sized = patch.begin_set_payload_sized(len, payload.len()).unwrap();
                sized.write(payload).unwrap();
                sized.finish().unwrap();
            }
            let _ = patch.insert_payload(InsertAt::HeadOf(None), field, payload).unwrap();
            let _ = patch.delete(tops[filled - 1].unwrap());
            let need = patch.save_len().unwrap();
            let written = patch.save_into(out).unwrap();
            assert_eq!(written, need);
            let mut sunk = 0usize;
            patch.save_sink(|bytes| sunk += bytes.len()).unwrap();
            assert_eq!(sunk, usize::try_from(need).unwrap());
            let _ = patch.save_canonical_into(out).unwrap();
            patch
                .save_canonical_sink(|bytes| {
                    core::hint::black_box(bytes.len());
                })
                .unwrap();
            core::hint::black_box(patch.budget());
        });
        count
    }

    /// The grouped mixed machine's whole job, group insertion
    /// included.
    fn grouped_job(
        doc: &[u8],
        slab: &mut [MaybeUninit<u8>],
        payload: &[u8],
        out: &mut [u8],
    ) -> usize {
        use protobuf_edit::fixed_patch::grouped::{InsertAt, Patch, Plan};
        let plan = Plan::new(64, 16, 16, 256, 4).unwrap();
        let field = FieldNumber::new(9).unwrap();
        let ((), count) = counted(|| {
            let mut patch = Patch::open(doc, DepthLimit::REFERENCE, &plan, slab).unwrap();
            let mut tops = [None; 64];
            for (n, h) in patch.top().enumerate() {
                tops[n] = Some(h);
            }
            for &top in tops.iter().flatten() {
                let _ = patch.descend(top);
            }
            let group = patch.insert_group(InsertAt::TailOf(None), field).unwrap();
            patch.insert_varint(InsertAt::TailOf(Some(group)), field, 3).unwrap();
            patch.insert_payload(InsertAt::HeadOf(Some(group)), field, payload).unwrap();
            let _ = patch.set_varint(tops[0].unwrap(), 7);
            let need = patch.save_len().unwrap();
            let written = patch.save_into(out).unwrap();
            assert_eq!(written, need);
            patch
                .save_sink(|bytes| {
                    core::hint::black_box(bytes.len());
                })
                .unwrap();
            let _ = patch.save_canonical_into(out).unwrap();
            core::hint::black_box(patch.budget());
        });
        count
    }

    /// Whole jobs over every sibling book zero armed allocations;
    /// the two controls prove the harness sees.
    #[test]
    fn whole_jobs_book_zero() {
        let doc = document(11, false);
        let payload = vec![0x08u8, 0x01, 0x08, 0x02];
        let piece: Vec<u8> = vec![0x99];
        let parts: Vec<&[u8]> = vec![&piece, &payload];
        let mut out = vec![0u8; 4096];
        let mut slab = slab_for(1 << 16);
        let count = groupless_job(&doc, &mut slab, &payload, &parts, &mut out);
        assert_eq!(count, 0, "the groupless fixed job allocated");

        let gdoc = document(11, true);
        let mut gslab = slab_for(1 << 16);
        let gcount = grouped_job(&gdoc, &mut gslab, &payload, &mut out);
        assert_eq!(gcount, 0, "the grouped fixed job allocated");

        // The thin siblings' jobs.
        {
            use protobuf_edit::fixed_patch::groupless::{BorrowPatch, BorrowPlan, CopyPatch, CopyPlan};
            let plan = BorrowPlan::new(64, 16, 16, 4).unwrap();
            let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
            let ((), count) = counted(|| {
                let mut patch =
                    BorrowPatch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
                let top = patch.top().next().unwrap();
                let _ = patch.set_varint(top, 1);
                let _ = patch.save_into(&mut out).unwrap();
            });
            assert_eq!(count, 0, "the borrowed-only fixed job allocated");
            let plan = CopyPlan::new(64, 16, 16, 256, 4).unwrap();
            let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
            let ((), count) = counted(|| {
                let mut patch =
                    CopyPatch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
                let top = patch.top().next().unwrap();
                let _ = patch.set_varint(top, 1);
                let _ = patch.save_into(&mut out).unwrap();
            });
            assert_eq!(count, 0, "the copy-only fixed job allocated");
        }
        {
            use protobuf_edit::fixed_patch::grouped::{BorrowPatch, BorrowPlan, CopyPatch, CopyPlan};
            let plan = BorrowPlan::new(64, 16, 16, 4).unwrap();
            let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
            let ((), count) = counted(|| {
                let mut patch =
                    BorrowPatch::open(&gdoc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
                let top = patch.top().next().unwrap();
                let _ = patch.set_varint(top, 1);
                let _ = patch.save_into(&mut out).unwrap();
            });
            assert_eq!(count, 0, "the grouped borrowed-only fixed job allocated");
            let plan = CopyPlan::new(64, 16, 16, 256, 4).unwrap();
            let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
            let ((), count) = counted(|| {
                let mut patch =
                    CopyPatch::open(&gdoc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
                let top = patch.top().next().unwrap();
                let _ = patch.set_varint(top, 1);
                let _ = patch.save_into(&mut out).unwrap();
            });
            assert_eq!(count, 0, "the grouped copy-only fixed job allocated");
        }

        // Control one: a planted allocation reddens the window.
        let ((), planted) = counted(|| {
            core::hint::black_box(vec![1u8, 2, 3]);
        });
        assert!(planted > 0, "the harness is blind to allocations");

        // Control two: the heap twin's allocating path books nonzero.
        let ((), heap) = counted(|| {
            use protobuf_edit::patch::groupless::Patch;
            let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
            let top = patch.top().next().unwrap();
            let _ = patch.set_varint(top, 1);
            core::hint::black_box(patch.save().unwrap());
        });
        assert!(heap > 0, "the heap twin's allocating path books zero");
    }
}

// ─── exhaustion-refusal enumeration ───

mod exhaustion {
    use super::*;
    use protobuf_edit::fixed_patch::ScratchRole;
    use protobuf_edit::fixed_patch::groupless::{
        Descent, EditFault, FrameFault, InsertAt, OpenFault, Patch, Plan, SaveFault,
    };

    /// The observable fingerprint the refusal contract preserves:
    /// per-record identity, geometry, and values, plus the exact
    /// save bytes. Capacity accounting (`budget()`) sits outside it.
    fn fingerprint(patch: &mut Patch<'_, '_, '_>) -> (Vec<String>, Vec<u8>) {
        let tops: Vec<_> = patch.top().collect();
        let mut rows = Vec::new();
        for &h in &tops {
            rows.push(format!(
                "{:?}/{:?}/{:?}/{:?}/{:?}/{:?}/{:?}",
                patch.status(h),
                patch.kind(h),
                patch.field(h),
                patch.span(h),
                patch.varint_word(h),
                patch.payload_bytes(h).map(<[u8]>::to_vec),
                patch.source_spans(h),
            ));
        }
        let need = patch.save_len().unwrap();
        let mut out = vec![0u8; usize::try_from(need).unwrap()];
        patch.save_into(&mut out).unwrap();
        (rows, out)
    }

    /// Rows exhaust at the open door: the root scan's demand, one
    /// short.
    #[test]
    fn rows_exhaust_at_open() {
        // varint f1 · varint f1 · varint f1 — three rows.
        let doc = [0x08, 0x01, 0x08, 0x02, 0x08, 0x03];
        let full = Plan::new(3, 0, 0, 0, 0).unwrap();
        let mut slab = slab_for(full.bytes(DepthLimit::REFERENCE));
        assert!(Patch::open(&doc, DepthLimit::REFERENCE, &full, &mut slab).is_ok());
        let short = Plan::new(2, 0, 0, 0, 0).unwrap();
        let mut slab = slab_for(short.bytes(DepthLimit::REFERENCE));
        assert!(matches!(
            Patch::open(&doc, DepthLimit::REFERENCE, &short, &mut slab),
            Err(OpenFault::ScratchExhausted { role: ScratchRole::Rows })
        ));
    }

    /// Rows exhaust at descend: the interior scan's demand, one
    /// short; the machine is unchanged, no verdict parks, and a
    /// smaller lawful command still lands.
    #[test]
    fn rows_exhaust_at_descend() {
        // LEN f2 { varint f1 · varint f1 } · varint f3 — the
        // descend needs two more rows.
        let doc = [0x12, 0x04, 0x08, 0x01, 0x08, 0x02, 0x18, 0x05];
        let plan = Plan::new(3, 1, 0, 0, 1).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let tops: Vec<_> = patch.top().collect();
        let before = fingerprint(&mut patch);
        assert!(matches!(
            patch.descend(tops[0]),
            Err(EditFault::ScratchExhausted { role: ScratchRole::Rows })
        ));
        // Not parked: the same refusal repeats rather than a
        // resident verdict projecting.
        assert!(matches!(
            patch.descend(tops[0]),
            Err(EditFault::ScratchExhausted { role: ScratchRole::Rows })
        ));
        assert_eq!(fingerprint(&mut patch), before, "a refused descend moved observable state");
        // No capacity leaked: one row is still free for an insert.
        patch.insert_varint(InsertAt::TailOf(None), FieldNumber::new(4).unwrap(), 9).unwrap();
        assert!(matches!(
            patch.insert_varint(InsertAt::TailOf(None), FieldNumber::new(4).unwrap(), 9),
            Err(EditFault::ScratchExhausted { role: ScratchRole::Rows })
        ));
    }

    /// Words exhaust at the first fresh replacement past capacity;
    /// re-sets of an already-replaced record stay infallible.
    #[test]
    fn words_exhaust_and_resets_ride() {
        let doc = [0x08, 0x01, 0x08, 0x02];
        let plan = Plan::new(2, 1, 0, 0, 0).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let tops: Vec<_> = patch.top().collect();
        patch.set_varint(tops[0], 7).unwrap();
        let before = fingerprint(&mut patch);
        assert!(matches!(
            patch.set_varint(tops[1], 8),
            Err(EditFault::ScratchExhausted { role: ScratchRole::Words })
        ));
        assert_eq!(fingerprint(&mut patch), before, "a refused set moved observable state");
        patch.set_varint(tops[0], 9).unwrap();
    }

    /// Payload slots exhaust at the first fresh payload past
    /// capacity; the staged pool exhausts by bytes, and an
    /// abandoned frame reclaims them.
    #[test]
    fn payload_lanes_exhaust() {
        // LEN f2 "a" · LEN f2 "b"
        let doc = [0x12, 0x01, 0x61, 0x12, 0x01, 0x62];
        let plan = Plan::new(2, 0, 1, 4, 0).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let tops: Vec<_> = patch.top().collect();
        patch.set_payload(tops[0], b"xyz").unwrap();
        let before = fingerprint(&mut patch);
        assert!(matches!(
            patch.set_payload(tops[1], b"q"),
            Err(EditFault::ScratchExhausted { role: ScratchRole::PayloadSlots })
        ));
        assert_eq!(fingerprint(&mut patch), before);
        // The staged pool: four bytes fit, five refuse — judged
        // before anything lands.
        patch.set_payload_copy(tops[0], b"abcd").unwrap();
        let before = fingerprint(&mut patch);
        assert!(matches!(
            patch.set_payload_copy(tops[0], b"e"),
            Err(EditFault::ScratchExhausted { role: ScratchRole::StagedBytes })
        ));
        assert_eq!(fingerprint(&mut patch), before);
        // The sized door judges the whole declaration.
        assert!(matches!(
            patch.begin_set_payload_sized(tops[0], 1),
            Err(EditFault::ScratchExhausted { role: ScratchRole::StagedBytes })
        ));
        assert_eq!(fingerprint(&mut patch), before);
    }

    /// An abandoned undeclared frame returns its staged bytes —
    /// the no-leak clause over the byte pool.
    #[test]
    fn abandoned_frames_reclaim_bytes() {
        let doc = [0x12, 0x01, 0x61];
        let plan = Plan::new(1, 0, 1, 4, 0).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let top = patch.top().next().unwrap();
        {
            let mut frame = patch.begin_set_payload(top).unwrap();
            frame.write(b"abcd").unwrap();
            assert!(matches!(
                frame.write(b"e"),
                Err(EditFault::ScratchExhausted { role: ScratchRole::StagedBytes })
            ));
            // Dropped unfinished: the pool returns whole.
        }
        assert_eq!(patch.budget().staged_bytes.used, 4, "high-water keeps the abandoned demand");
        patch.set_payload_copy(top, b"wxyz").unwrap();
        let mut out = vec![0u8; 16];
        let written = patch.save_into(&mut out).unwrap();
        assert_eq!(&out[..usize::try_from(written).unwrap()], [0x12, 0x04, b'w', b'x', b'y', b'z']);
    }

    /// The verdict table exhausts without parking: the refusal
    /// repeats and the machine is unchanged.
    #[test]
    fn faults_exhaust_without_parking() {
        // LEN f2 whose payload cuts a record short.
        let doc = [0x12, 0x01, 0x08];
        let plan = Plan::new(1, 0, 0, 0, 0).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let top = patch.top().next().unwrap();
        let before = fingerprint(&mut patch);
        for _ in 0..2 {
            assert!(matches!(
                patch.descend(top),
                Err(EditFault::ScratchExhausted { role: ScratchRole::Faults })
            ));
        }
        assert_eq!(fingerprint(&mut patch), before);
        // With one verdict slot the same descend parks and projects.
        let plan = Plan::new(1, 0, 0, 0, 1).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let top = patch.top().next().unwrap();
        assert!(matches!(patch.descend(top), Ok(Descent::Faulted(_))));
        assert!(matches!(patch.descend(top), Ok(Descent::Faulted(_))));
    }

    /// The output faces refuse a short buffer with zero bytes
    /// written, and the exact buffer then succeeds.
    #[test]
    fn output_short_writes_nothing() {
        let doc = [0x08, 0x01, 0x10, 0x2A];
        let plan = Plan::new(2, 1, 0, 0, 0).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let top = patch.top().next().unwrap();
        patch.set_varint(top, 300).unwrap();
        let need = usize::try_from(patch.save_len().unwrap()).unwrap();
        let mut out = vec![0xAAu8; need];
        assert!(matches!(
            patch.save_into(&mut out[..need - 1]),
            Err(SaveFault::OutputShort { .. })
        ));
        assert!(out.iter().all(|&b| b == 0xAA), "a refused save touched the buffer");
        let written = patch.save_into(&mut out).unwrap();
        assert_eq!(usize::try_from(written).unwrap(), need);
        assert!(matches!(
            patch.save_canonical_into(&mut out[..1]),
            Err(SaveFault::OutputShort { .. })
        ));
    }

    /// A sized frame is held to its declaration on both sides.
    #[test]
    fn sized_frames_hold_their_word() {
        let doc = [0x12, 0x01, 0x61];
        let plan = Plan::new(1, 0, 1, 8, 0).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let top = patch.top().next().unwrap();
        let mut frame = patch.begin_set_payload_sized(top, 2).unwrap();
        assert!(matches!(frame.write(b"abc"), Err(FrameFault::OverDeclared { .. })));
        frame.write(b"a").unwrap();
        assert!(matches!(frame.finish(), Err(FrameFault::UnderDeclared { .. })));
        let mut frame = patch.begin_set_payload_sized(top, 2).unwrap();
        frame.write(b"ab").unwrap();
        frame.finish().unwrap();
        let mut out = vec![0u8; 8];
        let written = patch.save_into(&mut out).unwrap();
        assert_eq!(&out[..usize::try_from(written).unwrap()], [0x12, 0x02, b'a', b'b']);
    }
}

// ─── carve honesty ───

mod carve_honesty {
    use super::*;
    use protobuf_edit::fixed_patch::groupless::{OpenFault, Patch, Plan};

    /// `bytes()` carves at any address; `bytes() - 1` refuses as a
    /// pure length compare; both repeat on a misaligned slab.
    #[test]
    fn bytes_is_the_exact_boundary() {
        let doc = document(23, false);
        let plan = Plan::new(64, 8, 8, 128, 4).unwrap();
        let need = usize::try_from(plan.bytes(DepthLimit::REFERENCE)).unwrap();

        // An 8-aligned backing, sliced at +0 and +1: both must
        // carve at `need` and refuse at `need - 1`.
        let mut backing = vec![0u64; need / 8 + 2];
        let bytes: &mut [MaybeUninit<u8>] = unsafe {
            core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast(), backing.len() * 8)
        };
        for offset in [0usize, 1] {
            let (aligned, misaligned) = bytes.split_at_mut(offset);
            let _ = aligned;
            let slab = &mut misaligned[..need];
            assert!(
                Patch::open(&doc, DepthLimit::REFERENCE, &plan, slab).is_ok(),
                "the priced demand refused to carve at offset {offset}"
            );
            let slab = &mut misaligned[..need - 1];
            assert!(
                matches!(
                    Patch::open(&doc, DepthLimit::REFERENCE, &plan, slab),
                    Err(OpenFault::SlabShort { .. })
                ),
                "one byte under the price carved at offset {offset}"
            );
        }
    }

    /// `budget()` is the sizing loop: a plan tightened to the
    /// high-water re-runs the same job; one less anywhere refuses.
    #[test]
    fn budget_closes_the_sizing_loop() {
        fn job(patch: &mut Patch<'_, '_, '_>, payload: &[u8]) {
            let tops: Vec<_> = patch.top().collect();
            for &h in &tops {
                let _ = patch.descend(h);
            }
            for &h in &tops {
                let _ = patch.set_varint(h, 300);
            }
            if let Some(&len) = tops.iter().find(|&&h| patch.payload_bytes(h).is_some()) {
                let _ = patch.set_payload_copy(len, payload);
            }
            let need = patch.save_len().unwrap();
            let mut out = vec![0u8; usize::try_from(need).unwrap()];
            patch.save_into(&mut out).unwrap();
        }

        let doc = document(37, false);
        let payload = vec![0x77u8; 24];
        let generous = Plan::new(256, 64, 64, 1024, 8).unwrap();
        let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &generous, &mut slab).unwrap();
        job(&mut patch, &payload);
        let budget = patch.budget();
        let _ = patch;

        let tight = Plan::new(
            budget.rows.used,
            budget.words.used,
            budget.payload_slots.used,
            budget.staged_bytes.used,
            budget.faults.used,
        )
        .unwrap();
        let mut slab = slab_for(tight.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &tight, &mut slab).unwrap();
        job(&mut patch, &payload);
        let tight_budget = patch.budget();
        assert_eq!(tight_budget.rows.used, tight_budget.rows.capacity);
        assert_eq!(tight_budget.words.used, tight_budget.words.capacity);
        let _ = patch;

        // One row less refuses somewhere in the same job — the
        // measured demand was demand, not slack.
        if budget.rows.used > 0 {
            let short = Plan::new(
                budget.rows.used - 1,
                budget.words.used,
                budget.payload_slots.used,
                budget.staged_bytes.used,
                budget.faults.used,
            )
            .unwrap();
            let mut slab = slab_for(short.bytes(DepthLimit::REFERENCE));
            match Patch::open(&doc, DepthLimit::REFERENCE, &short, &mut slab) {
                Err(OpenFault::ScratchExhausted { .. }) => {}
                Ok(mut patch) => {
                    let tops: Vec<_> = patch.top().collect();
                    let refused = tops.iter().any(|&h| patch.descend(h).is_err());
                    assert!(refused, "a one-short row plan refused nowhere");
                }
                Err(other) => panic!("unexpected open fault: {other:?}"),
            }
        }
    }
}

// ─── transposition refusal ───
//
// Every carve ladder opens with `words: u64, bodies: u64` — the one
// same-typed lane pair, which the type checker cannot tell apart if
// a transposition enters anywhere on the capacity path (the plans'
// `caps()` literals, the ladder emission, a door body). These rows
// pin each position to its own requirement through the public
// faces, on fixtures whose two requirements differ, so a carve that
// hands either position the other's capacity fails an assert
// instead of passing silently.
//
// The word column's pin is a named refusal: the first fresh mint
// past the declared word count answers `ScratchRole::Words` while
// the row-derived body requirement sits at a different value. The
// body table cannot refuse — no `ScratchRole` names it, because its
// capacity is derived at the row count and the save walks occupy at
// most one body slot per opened-LEN row, a distinct arena row each,
// so exhaustion is proven unreachable. Its pin is therefore the
// exact-occupancy success: a canonical walk over a document whose
// every row is an opened-LEN container fills the position's whole
// row-derived extent, which a transposed carve (handed the smaller
// word count) cannot survive.

/// Four intact varint records: the fixtures' declared word
/// requirement (two) and the row-derived body requirement (four)
/// sit at distinguishable exact boundaries.
const FLAT_SCALARS: [u8; 8] = [0x08, 0x01, 0x08, 0x02, 0x08, 0x03, 0x08, 0x04];

/// Three nested LEN containers, the innermost empty: after a full
/// descent every arena row is an opened-LEN container, so the
/// canonical walk occupies every row-derived body slot.
const LEN_CHAIN: [u8; 6] = [0x12, 0x04, 0x12, 0x02, 0x12, 0x00];

/// One door's word-position pin over [`FLAT_SCALARS`]: the carved
/// column answers the declared word count (not the row count), two
/// fresh mints fill it exactly, and the third refuses naming the
/// words lane at the declared boundary — two, not the row-derived
/// four a transposed carve would answer.
macro_rules! words_position_pin {
    ($Machine:ident, $plan:expr) => {{
        let plan = $plan;
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch =
            $Machine::open(&FLAT_SCALARS, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        assert_eq!(patch.budget().words.capacity, 2, "the word column answers its own capacity");
        assert_eq!(patch.budget().rows.capacity, 4, "the row arena answers its own capacity");
        assert_eq!(patch.budget().rows.used, 4, "the scan filled the rows exactly");
        let tops: Vec<_> = patch.top().collect();
        patch.set_varint(tops[0], 700).unwrap();
        patch.set_varint(tops[1], 800).unwrap();
        assert!(
            matches!(
                patch.set_varint(tops[2], 900),
                Err(EditFault::ScratchExhausted { role: ScratchRole::Words })
            ),
            "the third fresh mint must refuse at the declared word count, naming the words lane"
        );
        // The refusal spent nothing and re-sets ride the minted
        // word: the column sits at its exact boundary.
        patch.set_varint(tops[0], 1).unwrap();
        assert_eq!(patch.budget().words.used, 2);
    }};
}

/// One door's body-position pin over [`LEN_CHAIN`]: with a zero
/// word count declared, the carved column answers zero while the
/// full descent fills the rows exactly, and the canonical walk then
/// occupies all three row-derived body slots and re-encodes the
/// minimal chain byte-identically.
macro_rules! bodies_position_pin {
    ($Machine:ident, $plan:expr) => {{
        let plan = $plan;
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch =
            $Machine::open(&LEN_CHAIN, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        assert_eq!(patch.budget().words.capacity, 0, "no word was declared");
        assert_eq!(patch.budget().rows.capacity, 3, "the row arena answers its own capacity");
        let mut cur = patch.top().next();
        while let Some(handle) = cur {
            let Ok(Descent::Opened { first }) = patch.descend(handle) else {
                panic!("the chain descends committed");
            };
            cur = first;
        }
        assert_eq!(patch.budget().rows.used, 3, "every arena row is an opened container");
        let mut out = [0u8; 6];
        let written = patch.save_canonical_into(&mut out).unwrap();
        assert_eq!(written, 6);
        assert_eq!(out, LEN_CHAIN, "the minimal chain re-encodes verbatim");
    }};
}

macro_rules! transposition_rows {
    ($name:ident, $dialect:ident) => {
        mod $name {
            use protobuf_edit::fixed_patch::ScratchRole;
            use protobuf_edit::fixed_patch::$dialect::{
                BorrowPatch, BorrowPlan, CopyPatch, CopyPlan, Descent, EditFault, Patch, Plan,
            };

            use super::*;

            #[test]
            fn mixed_door_pins_both_positions() {
                words_position_pin!(Patch, Plan::new(4, 2, 0, 0, 0).unwrap());
                bodies_position_pin!(Patch, Plan::new(3, 0, 0, 0, 0).unwrap());
            }

            #[test]
            fn borrowed_door_pins_both_positions() {
                words_position_pin!(BorrowPatch, BorrowPlan::new(4, 2, 0, 0).unwrap());
                bodies_position_pin!(BorrowPatch, BorrowPlan::new(3, 0, 0, 0).unwrap());
            }

            #[test]
            fn copy_door_pins_both_positions() {
                words_position_pin!(CopyPatch, CopyPlan::new(4, 2, 0, 0, 0).unwrap());
                bodies_position_pin!(CopyPatch, CopyPlan::new(3, 0, 0, 0, 0).unwrap());
            }
        }
    };
}

transposition_rows!(transposition_groupless, groupless);
transposition_rows!(transposition_grouped, grouped);

// ─── the runtime pricing mirror ───
//
// `Plan::bytes` is a `const fn` over the ladder's term list; the
// door's length judgment and the carve are its runtime half. These
// rows pin the two halves to each other over a spread of document
// shapes: a plan tightened to measured demand re-runs its whole job
// inside a slab of exactly `bytes()` at any address with every lane
// run to its full planned figure, one byte fewer refuses before
// anything is touched with the priced figure named in the fault,
// and one compile-time evaluation of the figure equals the number
// the runtime door reports.

/// The document spread: empty, flat scalars, nested containers, and
/// payload-heavy (fat opaque payloads, a parsable fat payload, and
/// a truncated interior that parks a verdict) — across the spread
/// every declared plan term is nonzero somewhere.
fn document_spread() -> [Vec<u8>; 4] {
    let flat = vec![
        0x08, 0x01, // varint f1 = 1
        0x08, 0xAC, 0x02, // varint f1 = 300
        0x15, 0x01, 0x02, 0x03, 0x04, // i32 f2
        0x19, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // i64 f3
        0x12, 0x02, b'a', b'b', // LEN f2 "ab"
    ];
    let nested = vec![0x12, 0x04, 0x12, 0x02, 0x12, 0x00, 0x08, 0x05];
    let mut heavy = vec![0x08, 0x2A];
    heavy.extend([0x12, 40]);
    heavy.extend([0xAA; 40]); // opaque: descending it parks a verdict
    heavy.extend([0x1A, 40]);
    heavy.extend([0x55; 40]); // parsable: descending it commits eight rows
    heavy.extend([0x12, 0x01, 0x08]); // truncated interior: parks a verdict
    heavy.extend([0x08, 0x07]);
    [Vec::new(), flat, nested, heavy]
}

/// The deterministic job the mirror measures and re-runs: descend
/// every first-link chain, author a word and a payload wherever the
/// record kind admits one, and run the fidelity and canonical save
/// faces. Evaluates to the top handles so a sibling with further
/// faces can extend the same job.
macro_rules! spread_job {
    ($patch:ident) => {{
        let tops: Vec<_> = $patch.top().collect();
        for &handle in &tops {
            let mut cur = Some(handle);
            while let Some(record) = cur {
                cur = match $patch.descend(record) {
                    Ok(Descent::Opened { first }) => first,
                    _ => None,
                };
            }
        }
        for &handle in &tops {
            let _ = $patch.set_varint(handle, 300);
            let _ = $patch.set_payload(handle, b"replaced");
        }
        tops
    }};
}

/// The job's save faces, shared by the measuring and re-running
/// legs.
macro_rules! spread_saves {
    ($patch:ident) => {{
        let need = usize::try_from($patch.save_len().unwrap()).unwrap();
        let mut out = vec![0u8; need];
        assert_eq!(usize::try_from($patch.save_into(&mut out).unwrap()).unwrap(), need);
        let mut canon = vec![0u8; need + 64];
        $patch.save_canonical_into(&mut canon).unwrap();
    }};
}

/// One door's boundary probes for one tight plan: at slab offsets
/// zero and one, a slab of exactly the priced figure carves and the
/// whole job re-runs inside it, and one byte fewer refuses with the
/// figure named in the fault's own fields.
macro_rules! priced_boundary {
    ($Machine:ident, $tight:expr, $doc:expr, |$patch:ident| $rerun:expr) => {{
        let doc: &[u8] = $doc;
        let tight = $tight;
        let need64 = tight.bytes(DepthLimit::REFERENCE);
        let need = usize::try_from(need64).unwrap();
        let mut backing = vec![0u64; need / 8 + 2];
        // SAFETY: `u64` re-viewed as raw bytes — same allocation,
        // every byte initialized, and `backing` is not read again.
        let bytes: &mut [MaybeUninit<u8>] = unsafe {
            core::slice::from_raw_parts_mut(backing.as_mut_ptr().cast(), backing.len() * 8)
        };
        for offset in [0usize, 1] {
            let (_, misaligned) = bytes.split_at_mut(offset);
            {
                let slab = &mut misaligned[..need];
                let mut $patch = $Machine::open(doc, DepthLimit::REFERENCE, &tight, slab)
                    .expect("the priced slab must carve at any address");
                $rerun;
            }
            let slab = &mut misaligned[..need - 1];
            assert!(
                matches!(
                    $Machine::open(doc, DepthLimit::REFERENCE, &tight, slab),
                    Err(OpenFault::SlabShort { need: priced, have })
                        if priced == need64 && have == need64 - 1
                ),
                "one byte under the priced figure must refuse naming the figure"
            );
        }
    }};
}

macro_rules! pricing_rows {
    ($name:ident, $dialect:ident) => {
        mod $name {
            use protobuf_edit::fixed_patch::$dialect::{
                BorrowPatch, BorrowPlan, CopyPatch, CopyPlan, Descent, OpenFault, Patch, Plan,
            };

            use super::*;

            /// The mixed door: the job also stages copied payloads,
            /// so every declared term of its plan is measured.
            #[test]
            fn priced_boundary_covers_the_spread_mixed() {
                for doc in document_spread() {
                    let generous = Plan::new(64, 32, 16, 512, 8).unwrap();
                    let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));
                    let mut patch =
                        Patch::open(&doc, DepthLimit::REFERENCE, &generous, &mut slab).unwrap();
                    let tops = spread_job!(patch);
                    for &handle in &tops {
                        let _ = patch.set_payload_copy(handle, b"staged-copy");
                    }
                    spread_saves!(patch);
                    let measured = patch.budget();
                    let tight = Plan::new(
                        measured.rows.used,
                        measured.words.used,
                        measured.payload_slots.used,
                        measured.staged_bytes.used,
                        measured.faults.used,
                    )
                    .unwrap();
                    priced_boundary!(Patch, tight, &doc, |patch| {
                        let tops = spread_job!(patch);
                        for &handle in &tops {
                            let _ = patch.set_payload_copy(handle, b"staged-copy");
                        }
                        spread_saves!(patch);
                        let after = patch.budget();
                        for (used, capacity) in [
                            (after.rows.used, after.rows.capacity),
                            (after.words.used, after.words.capacity),
                            (after.payload_slots.used, after.payload_slots.capacity),
                            (after.staged_bytes.used, after.staged_bytes.capacity),
                            (after.faults.used, after.faults.capacity),
                        ] {
                            assert_eq!(used, capacity, "every lane ran to its planned figure");
                        }
                    });
                }
            }

            /// The borrowed door: no staged pool exists, so the
            /// plan's remaining terms carry the whole figure.
            #[test]
            fn priced_boundary_covers_the_spread_borrowed() {
                for doc in document_spread() {
                    let generous = BorrowPlan::new(64, 32, 16, 8).unwrap();
                    let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));
                    let mut patch =
                        BorrowPatch::open(&doc, DepthLimit::REFERENCE, &generous, &mut slab)
                            .unwrap();
                    let _ = spread_job!(patch);
                    spread_saves!(patch);
                    let measured = patch.budget();
                    let tight = BorrowPlan::new(
                        measured.rows.used,
                        measured.words.used,
                        measured.payload_slots.used,
                        measured.faults.used,
                    )
                    .unwrap();
                    priced_boundary!(BorrowPatch, tight, &doc, |patch| {
                        let _ = spread_job!(patch);
                        spread_saves!(patch);
                        let after = patch.budget();
                        for (used, capacity) in [
                            (after.rows.used, after.rows.capacity),
                            (after.words.used, after.words.capacity),
                            (after.payload_slots.used, after.payload_slots.capacity),
                            (after.faults.used, after.faults.capacity),
                        ] {
                            assert_eq!(used, capacity, "every lane ran to its planned figure");
                        }
                    });
                }
            }

            /// The copy door: its payload face stages at the
            /// command, so the shared job already fills the pool.
            #[test]
            fn priced_boundary_covers_the_spread_copy() {
                for doc in document_spread() {
                    let generous = CopyPlan::new(64, 32, 16, 512, 8).unwrap();
                    let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));
                    let mut patch =
                        CopyPatch::open(&doc, DepthLimit::REFERENCE, &generous, &mut slab)
                            .unwrap();
                    let _ = spread_job!(patch);
                    spread_saves!(patch);
                    let measured = patch.budget();
                    let tight = CopyPlan::new(
                        measured.rows.used,
                        measured.words.used,
                        measured.payload_slots.used,
                        measured.staged_bytes.used,
                        measured.faults.used,
                    )
                    .unwrap();
                    priced_boundary!(CopyPatch, tight, &doc, |patch| {
                        let _ = spread_job!(patch);
                        spread_saves!(patch);
                        let after = patch.budget();
                        for (used, capacity) in [
                            (after.rows.used, after.rows.capacity),
                            (after.words.used, after.words.capacity),
                            (after.payload_slots.used, after.payload_slots.capacity),
                            (after.staged_bytes.used, after.staged_bytes.capacity),
                            (after.faults.used, after.faults.capacity),
                        ] {
                            assert_eq!(used, capacity, "every lane ran to its planned figure");
                        }
                    });
                }
            }

            /// The pricing face is a `const fn`: one figure,
            /// evaluated at compile time, is the number the runtime
            /// door reports.
            #[test]
            fn const_priced_figure_matches_the_door() {
                const PLAN: Plan = match Plan::new(5, 3, 2, 64, 1) {
                    Some(plan) => plan,
                    None => panic!("the literal plan sits in class"),
                };
                const NEED: u64 = PLAN.bytes(DepthLimit::REFERENCE);
                let mut slab = slab_for(NEED - 1);
                assert!(matches!(
                    Patch::open(&[], DepthLimit::REFERENCE, &PLAN, &mut slab),
                    Err(OpenFault::SlabShort { need, have }) if need == NEED && have == NEED - 1
                ));
                let mut slab = slab_for(NEED);
                assert!(Patch::open(&[], DepthLimit::REFERENCE, &PLAN, &mut slab).is_ok());
            }
        }
    };
}

pricing_rows!(pricing_groupless, groupless);
pricing_rows!(pricing_grouped, grouped);

// ─── scoped batteries ───

mod batteries {
    use super::*;

    /// The empty document over a zero plan and a pad-only slab.
    #[test]
    fn empty_document_zero_plan() {
        use protobuf_edit::fixed_patch::groupless::{Patch, Plan};
        let plan = Plan::new(0, 0, 0, 0, 0).unwrap();
        let need = plan.bytes(DepthLimit::MIN);
        assert_eq!(need, 7, "an all-zero plan prices the alignment pad alone");
        let mut slab = slab_for(need);
        let mut patch = Patch::open(&[], DepthLimit::MIN, &plan, &mut slab).unwrap();
        assert_eq!(patch.top().count(), 0);
        assert_eq!(patch.save_len().unwrap(), 0);
        let written = patch.save_into(&mut []).unwrap();
        assert_eq!(written, 0);
        patch.save_sink(|_| panic!("an empty save handed the sink bytes")).unwrap();
    }

    /// Authored groups nest freely and the twins agree — insertion
    /// coverage the mirrored script leaves to its own battery.
    #[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
    #[test]
    fn authored_groups_agree_with_the_twin() {
        use protobuf_edit::fixed_patch::grouped as fixed;
        use protobuf_edit::patch::grouped as host;
        let f1 = FieldNumber::new(1).unwrap();
        let f2 = FieldNumber::new(2).unwrap();

        let mut host = host::Patch::open(&[], DepthLimit::REFERENCE).unwrap();
        let plan = fixed::Plan::new(8, 2, 2, 8, 0).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut fixed = fixed::Patch::open(&[], DepthLimit::REFERENCE, &plan, &mut slab).unwrap();

        let hg = host.insert_group(host::InsertAt::TailOf(None), f1).unwrap();
        let xg = fixed.insert_group(fixed::InsertAt::TailOf(None), f1).unwrap();
        let hg2 = host.insert_group(host::InsertAt::TailOf(Some(hg)), f2).unwrap();
        let xg2 = fixed.insert_group(fixed::InsertAt::TailOf(Some(xg)), f2).unwrap();
        host.insert_varint(host::InsertAt::TailOf(Some(hg2)), f2, 3).unwrap();
        fixed.insert_varint(fixed::InsertAt::TailOf(Some(xg2)), f2, 3).unwrap();
        host.insert_payload(host::InsertAt::After(hg2), f2, b"hi").unwrap();
        fixed.insert_payload(fixed::InsertAt::After(xg2), f2, b"hi").unwrap();

        let mut host_out = Vec::new();
        host.save_into(&mut host_out).unwrap();
        let mut fixed_out = vec![0u8; host_out.len()];
        fixed.save_into(&mut fixed_out).unwrap();
        assert_eq!(fixed_out, host_out);

        let host_canon = host.save_canonical().unwrap();
        let mut fixed_canon = vec![0u8; host_canon.len()];
        fixed.save_canonical_into(&mut fixed_canon).unwrap();
        assert_eq!(fixed_canon, host_canon);
    }

    /// A machine that took no edit saves the source as one copy —
    /// twin-identical on both faces.
    #[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
    #[test]
    fn clean_saves_are_the_source() {
        use protobuf_edit::fixed_patch::groupless::{Patch, Plan};
        let doc = document(41, false);
        let host =
            protobuf_edit::patch::groupless::Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
        let plan = Plan::new(64, 0, 0, 0, 0).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut fixed = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        assert_eq!(fixed.save_len().unwrap(), host.save_len().unwrap());
        assert_eq!(usize::try_from(fixed.save_len().unwrap()).unwrap(), doc.len());
        let mut out = vec![0u8; doc.len()];
        fixed.save_into(&mut out).unwrap();
        assert_eq!(out, doc);
        let mut host_out = Vec::new();
        host.save_into(&mut host_out).unwrap();
        assert_eq!(out, host_out);
    }

    /// The plan's row judgment: the row-id domain is the ceiling.
    #[test]
    fn plans_judge_their_classes() {
        use protobuf_edit::fixed_patch::groupless::Plan;
        assert!(Plan::new(0x7FFF_FFFF, 0, 0, 0, 0).is_some());
        assert!(Plan::new(0x8000_0000, 0, 0, 0, 0).is_none());
    }

    /// Group depth refuses at scan under the grouped dialect, and
    /// the refusal names the depth bound — twin-identical.
    #[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
    #[test]
    fn grouped_depth_refuses_at_scan() {
        use protobuf_edit::fixed_patch::grouped::{OpenFault, Patch, Plan, Refusal};
        // group f1 { group f1 { } } under a depth bound of one.
        let doc = [0x0B, 0x0B, 0x0C, 0x0C];
        let plan = Plan::new(4, 0, 0, 0, 0).unwrap();
        let limit = DepthLimit::MIN;
        let mut slab = slab_for(plan.bytes(limit));
        assert!(matches!(
            Patch::open(&doc, limit, &plan, &mut slab),
            Err(OpenFault::Refused(Refusal::DepthExceeded { at: 1, .. }))
        ));
        let heap = protobuf_edit::patch::grouped::Patch::open(&doc, limit);
        assert!(matches!(
            heap,
            Err(protobuf_edit::patch::grouped::OpenFault::Refused(
                protobuf_edit::patch::grouped::Refusal::DepthExceeded { at: 1, .. }
            ))
        ));
    }

    /// The groupless dialect refuses group codes as a capability
    /// judgment, twin-identical at the root and resident inside a
    /// payload.
    #[test]
    fn groupless_group_code_refusals_match() {
        use protobuf_edit::fixed_patch::groupless::{Descent, OpenFault, Patch, Plan, Refusal};
        let root = [0x0B, 0x0C];
        let plan = Plan::new(4, 0, 0, 0, 2).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        assert!(matches!(
            Patch::open(&root, DepthLimit::REFERENCE, &plan, &mut slab),
            Err(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
        ));
        // Inside a payload: resident, machine lives on.
        let doc = [0x12, 0x02, 0x0B, 0x0C];
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let mut patch = Patch::open(&doc, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
        let top = patch.top().next().unwrap();
        assert!(matches!(patch.descend(top), Ok(Descent::Refused(Refusal::GroupCode { .. }))));
        assert!(matches!(patch.descend(top), Ok(Descent::Refused(Refusal::GroupCode { .. }))));
        assert_eq!(patch.payload_bytes(top).unwrap(), [0x0B, 0x0C]);
    }
}
