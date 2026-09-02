//! The fixed inspect cell's judge set.
//!
//! The carve, pricing, capacity, and boundary rows compile with the
//! fixed cell alone; the twin, allocator-window, and heap-comparison
//! rows additionally require the heap inspect cell (`inspect-*`).
//!
//! - Twin differential: seeded documents — padded and minimal
//!   framing, succeeding and unwinding speculation, every advisor
//!   pole plus a pinning advisor, both standards, faulted documents
//!   of every class, group frames including clipped groups — parsed
//!   by both twins; every query face must agree **NodeId for
//!   NodeId** (the ids are one reused type, so equality is direct).
//! - Carve honesty: the door parses at exactly `bytes()` and
//!   refuses at `bytes() - 1` naming both figures, repeated on a
//!   deliberately misaligned slab; one compile-time evaluation of
//!   the priced figure equals the runtime door's answer.
//! - The priced reference is **derived**, not copied: the suite's
//!   own formula rebuilds the price from the ladder laws (4-byte
//!   head alignment → pad 3, 24-byte rows, 20 bytes per derived
//!   stack slot at `min(rows, limit)`), so a pricing regression in
//!   the cell cannot bless itself.
//! - Exhaustion enumeration and peak honesty: a plan one row short
//!   of measured demand refuses `RowsExhausted` (the sweep asserts
//!   a refusal actually landed); a document whose speculation peak
//!   exceeds its final row count refuses under a final-count plan
//!   and succeeds under the high-water — evaporated rows occupied
//!   the arena.
//! - Budget boundary and derived sufficiency: tightening every
//!   declared role to `budget()`'s high-water reproduces the
//!   product id-for-id; the derived stacks never refuse
//!   (`used <= capacity` across the corpus).
//! - Refusal fingerprint: after any door refusal the slab is
//!   reusable and nothing was published.
//! - Armed-allocator zero-count: whole jobs (parse → full query
//!   sweep) book zero armed-thread allocations, with both controls
//!   (a planted allocation reddens the window; the heap twin books
//!   nonzero).

#![cfg(all(feature = "fixed-inspect-grouped", feature = "fixed-inspect-groupless"))]
#![cfg_attr(
    all(feature = "inspect-grouped", feature = "inspect-groupless"),
    feature(thread_id_value)
)]

use core::mem::MaybeUninit;
#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
use std::alloc::{GlobalAlloc, Layout, System};
#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
use std::sync::Mutex;
#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use protobuf_edit::inspect::{Admitted, Advice, Advisor, Ancestry, NoAdvice};
use protobuf_edit::{DepthLimit, FieldNumber};

// ─── the armed allocator (tests/alloc_fault.rs's counted face) ───

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
struct Armed;

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
static COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
static ARMED_THREAD: AtomicU64 = AtomicU64::new(0);

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
fn on_armed_thread() -> bool {
    std::thread::current().id().as_u64().get() == ARMED_THREAD.load(Ordering::Relaxed)
}

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
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

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
#[global_allocator]
static ALLOCATOR: Armed = Armed;

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
static ARM_LOCK: Mutex<()> = Mutex::new(());

/// Counts armed-thread allocations across `job`.
#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
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
    #[allow(clippy::cast_possible_truncation, reason = "n % 24 fits u32")]
    FieldNumber::new(1 + (n % 24) as u32).expect("small field numbers are in class")
}

/// A hand emitter for seeded documents: minimal or continuation-
/// padded framing, so the twin corpora exercise the fidelity
/// contract's padded arm too.
struct Emitter {
    out: Vec<u8>,
}

impl Emitter {
    #[allow(clippy::cast_possible_truncation, reason = "seven-bit groups fit u8")]
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
/// (parsable messages, so speculation commits them) and opaque
/// byte bodies (speculation unwinds), `groups` admits group frames.
fn grow(rng: &mut Rng, e: &mut Emitter, depth: u32, budget: &mut u32, groups: bool) {
    while *budget > 0 {
        *budget -= 1;
        let pad = rng.next().is_multiple_of(4);
        match rng.next() % if groups { 8 } else { 7 } {
            0 | 1 => e.push_varint(f(rng.next()), rng.next() >> (rng.next() % 60), pad),
            #[allow(clippy::cast_possible_truncation, reason = "seeded bits")]
            2 => e.push_i32(f(rng.next()), rng.next() as u32, pad),
            3 => e.push_i64(f(rng.next()), rng.next(), pad),
            4 => {
                // An opaque-looking body: 0xA0-headed bytes fault as
                // wire, so a speculating parse unwinds here.
                let len = (rng.next() % 12) as usize;
                #[allow(clippy::cast_possible_truncation, reason = "small indices")]
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

/// Hand-picked boundary documents beside the seeded ones: every
/// fault class, clipped containers, demotions.
fn boundary_documents(groups: bool) -> Vec<Vec<u8>> {
    let mut docs: Vec<Vec<u8>> = vec![
        vec![],                             // the empty message
        vec![0x08, 0x96, 0x01],             // one varint
        vec![0x08],                         // truncated value
        vec![0x80],                         // truncated tag
        vec![0x05, 0x01],                   // field zero
        vec![0x0E, 0x01],                   // unassigned code 6
        vec![0x12, 0x7F, 0x01],             // LEN overrun
        vec![0x15, 0x01, 0x02],             // I32 truncated
        vec![0x12, 0x03, 0x08, 0x96, 0x01], // LEN body parses (commit)
        vec![0x12, 0x02, 0xA0, 0xA1],       // LEN body faults (unwind)
        vec![0x12, 0x00],                   // empty LEN
        vec![0x08, 0x96, 0x81, 0x00],       // padded value (canonical red)
        vec![0x92, 0x80, 0x00, 0x01, 0x33], // padded tag + LEN
        // Nested speculation that succeeds twice, then a sibling.
        vec![0x12, 0x06, 0x12, 0x04, 0x12, 0x02, 0x08, 0x01, 0x08, 0x02],
        // Deep nesting for the demotion arm (depth limit reached).
        {
            let mut deep = vec![0x08, 0x01];
            for _ in 0..12 {
                let mut wrapped = vec![0x12];
                #[allow(clippy::cast_possible_truncation, reason = "small bodies")]
                wrapped.push(deep.len() as u8);
                wrapped.extend_from_slice(&deep);
                deep = wrapped;
            }
            deep
        },
    ];
    // Both dialects meet the same first pair: an empty group under
    // grouped, the group-code refusal under groupless.
    docs.push(vec![0x0B, 0x0C]);
    if groups {
        docs.push(vec![0x0B, 0x10, 0x05, 0x0C]); // group { varint }
        docs.push(vec![0x0B, 0x10, 0x05]); // unclosed group (clip)
        docs.push(vec![0x0C]); // orphan end
        docs.push(vec![0x0B, 0x14]); // mismatched end
        docs.push(vec![0x0B, 0x0B, 0x08, 0x01, 0x0C, 0x0C]); // nested groups
        docs.push(vec![0x12, 0x02, 0x0B, 0x0C]); // group inside LEN
    }
    docs
}

/// A deterministic pinning advisor: a pure function of
/// (ancestry, field) mixing every enclosing field, so twin runs
/// answer identically while Commit/Opaque/Speculate all occur.
struct Pinning {
    salt: u64,
}

impl Advisor for Pinning {
    fn advise(&mut self, ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
        let mut h = self.salt ^ (u64::from(field.as_inner())).wrapping_mul(0x9E37_79B9);
        for enclosing in ancestry.fields() {
            h = h.wrapping_mul(31).wrapping_add(u64::from(enclosing.as_inner()));
        }
        match h % 4 {
            0 => Advice::Commit,
            1 => Advice::Opaque,
            _ => Advice::Speculate,
        }
    }
}

/// The member's priced formula, rebuilt from the ladder laws — the
/// 4-byte head alignment (worst-case pad 3), the 24-byte row, and
/// the 20 bytes per derived stack slot (16-byte frame + 4-byte path
/// entry) at `min(rows, limit)`. Derived here, never read back from
/// `Plan::bytes`, so a pricing regression cannot bless itself.
const fn reference_bytes(rows: u64, limit: u64) -> u64 {
    let stacks = if rows < limit { rows } else { limit };
    3 + rows * 24 + stacks * 20
}

fn slab_for(bytes: u64) -> Vec<MaybeUninit<u8>> {
    vec![MaybeUninit::uninit(); usize::try_from(bytes).unwrap()]
}

/// Unwraps a door refusal (the tree, like its heap twin, carries
/// no `Debug`, so `unwrap_err` cannot).
#[track_caller]
fn refusal<T>(
    result: Result<T, protobuf_edit::fixed_inspect::OpenFault>,
) -> protobuf_edit::fixed_inspect::OpenFault {
    match result {
        Err(fault) => fault,
        Ok(_) => panic!("the door accepted where a refusal was demanded"),
    }
}

/// A generous row plan for the seeded corpora: roomy enough that no
/// twin run can exhaust it.
const GENEROUS: u32 = 512;

// ─── the mirrored twin walks, one macro per dialect ───
//
// The runner drives the heap twin and the fixed twin over the same
// document, standard, and advisor, then compares every observable
// NodeId for NodeId — the ids are one reused type, so the equality
// is direct, which is the reuse decision's own judge.

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
macro_rules! twin_suite {
    ($name:ident, $dialect:ident, $groups:expr) => {
        mod $name {
            use protobuf_edit::Standard;
            use protobuf_edit::inspect::NodeId;
            use protobuf_edit::inspect::$dialect as host;
            use protobuf_edit::fixed_inspect::$dialect as fixed;

            use super::*;

            /// Parses both twins and compares the whole query
            /// surface. Returns the fixed tree's peak row demand.
            pub fn mirror(doc: &[u8], standard: Standard, depth: DepthLimit, salt: u64) -> u32 {
                let input = Admitted::new(doc).unwrap();
                let heap =
                    host::Tree::parse_standard(input, standard, depth, &mut Pinning { salt });
                let plan = fixed::Plan::new(GENEROUS).unwrap();
                let mut slab = slab_for(plan.bytes(depth));
                let tree = fixed::Tree::parse_standard(
                    input,
                    standard,
                    depth,
                    &mut Pinning { salt },
                    &plan,
                    &mut slab,
                )
                .expect("the generous plan covers every corpus document");

                assert_eq!(heap.node_count(), tree.node_count(), "row counts diverge");
                assert_eq!(heap.is_empty(), tree.is_empty());
                assert_eq!(heap.is_complete(), tree.is_complete());
                assert_eq!(heap.indexed_end(), tree.indexed_end());
                assert_eq!(
                    format!("{:?}", heap.fault()),
                    format!("{:?}", tree.fault()),
                    "fault values diverge"
                );
                assert_eq!(heap.bytes(), tree.bytes());

                let heap_top: Vec<NodeId> = heap.top().collect();
                let fixed_top: Vec<NodeId> = tree.top().collect();
                assert_eq!(heap_top, fixed_top, "top layers diverge id-for-id");
                assert_eq!(heap.nodes().collect::<Vec<_>>(), tree.nodes().collect::<Vec<_>>());

                for id in heap.nodes() {
                    assert_eq!(heap.field(id), tree.field(id));
                    assert_eq!(format!("{:?}", heap.kind(id)), format!("{:?}", tree.kind(id)));
                    assert_eq!(heap.span(id), tree.span(id));
                    assert_eq!(
                        format!("{:?}", heap.source_spans(id)),
                        format!("{:?}", tree.source_spans(id))
                    );
                    assert_eq!(heap.parent(id), tree.parent(id));
                    assert_eq!(
                        heap.children(id).collect::<Vec<_>>(),
                        tree.children(id).collect::<Vec<_>>()
                    );
                    assert_eq!(
                        heap.descendants(id).collect::<Vec<_>>(),
                        tree.descendants(id).collect::<Vec<_>>()
                    );
                    assert_eq!(
                        heap.ancestors(id).collect::<Vec<_>>(),
                        tree.ancestors(id).collect::<Vec<_>>()
                    );
                    assert_eq!(
                        heap.children(id).by_field(f(7)).collect::<Vec<_>>(),
                        tree.children(id).by_field(f(7)).collect::<Vec<_>>()
                    );
                    assert_eq!(heap.varint_word(id), tree.varint_word(id));
                    assert_eq!(heap.i64_bits(id), tree.i64_bits(id));
                    assert_eq!(heap.i32_bits(id), tree.i32_bits(id));
                    assert_eq!(heap.payload_bytes(id), tree.payload_bytes(id));
                    assert_eq!(heap.record_bytes(id), tree.record_bytes(id));
                    assert_eq!(heap.record_ref(id), tree.record_ref(id));
                }

                // The hex-view reverse index, swept over every byte
                // position and one past the end.
                for pos in 0..=u32::try_from(doc.len()).unwrap() {
                    assert_eq!(heap.narrowest(pos), tree.narrowest(pos), "narrowest({pos})");
                }

                // Derived lanes never refuse: the door's bound holds.
                let budget = tree.budget();
                assert!(budget.frames.used <= budget.frames.capacity);
                assert!(budget.path.used <= budget.path.capacity);
                assert!(budget.rows.used <= budget.rows.capacity);
                budget.rows.used
            }

            #[test]
            fn twin_identity() {
                for seed in 1..=24u64 {
                    let doc = document(seed, $groups);
                    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
                        mirror(&doc, standard, DepthLimit::REFERENCE, seed);
                        mirror(&doc, standard, DepthLimit::new(2).unwrap(), seed ^ 0xFF);
                    }
                }
                for (i, doc) in boundary_documents($groups).iter().enumerate() {
                    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
                        mirror(doc, standard, DepthLimit::REFERENCE, i as u64);
                        mirror(doc, standard, DepthLimit::new(3).unwrap(), i as u64 ^ 0x55);
                    }
                }
            }

            /// The budget boundary: tightening the one declared
            /// role to its high-water reproduces the product
            /// id-for-id and byte-for-byte.
            #[test]
            fn budget_closes_the_sizing_loop() {
                for seed in [3u64, 7, 11, 19] {
                    let doc = document(seed, $groups);
                    let input = Admitted::new(&doc).unwrap();
                    let generous = fixed::Plan::new(GENEROUS).unwrap();
                    let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));
                    let first = fixed::Tree::parse(
                        input,
                        DepthLimit::REFERENCE,
                        &mut NoAdvice,
                        &generous,
                        &mut slab,
                    )
                    .unwrap();
                    let used = first.budget().rows.used;
                    let first_rows: Vec<NodeId> = first.nodes().collect();
                    let first_spans: Vec<_> = first_rows.iter().map(|&id| first.span(id)).collect();
                    let first_end = first.indexed_end();
                    let _ = first;

                    let tight = fixed::Plan::new(used).unwrap();
                    let mut tight_slab = slab_for(tight.bytes(DepthLimit::REFERENCE));
                    let second = fixed::Tree::parse(
                        input,
                        DepthLimit::REFERENCE,
                        &mut NoAdvice,
                        &tight,
                        &mut tight_slab,
                    )
                    .expect("the high-water plan re-runs the same job");
                    assert_eq!(second.budget().rows.used, used, "high-water is stable");
                    assert_eq!(second.nodes().collect::<Vec<_>>(), first_rows);
                    let second_spans: Vec<_> = second.nodes().map(|id| second.span(id)).collect();
                    assert_eq!(second_spans, first_spans);
                    assert_eq!(second.indexed_end(), first_end);
                }
            }
        }
    };
}

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
twin_suite!(twin_groupless, groupless, false);
#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
twin_suite!(twin_grouped, grouped, true);

// ─── the allocator window ───

/// Whole jobs book zero armed-thread allocations, with both
/// controls: a planted allocation reddens the window, and the heap
/// twin's parse books nonzero.
#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
#[test]
fn whole_jobs_book_zero() {
    use protobuf_edit::fixed_inspect::{grouped, groupless};

    let doc = document(5, false);
    let grouped_doc = document(9, true);

    let (_, grew) = counted(|| {
        let input = Admitted::new(&doc).unwrap();
        let plan = groupless::Plan::new(GENEROUS).unwrap();
        let mut slab = [MaybeUninit::<u8>::uninit(); 23_000];
        assert!(plan.bytes(DepthLimit::REFERENCE) <= slab.len() as u64);
        let tree =
            groupless::Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, &mut slab)
                .unwrap();
        let mut sum = 0u64;
        for id in tree.nodes() {
            sum = sum
                .wrapping_add(u64::from(tree.span(id).len()))
                .wrapping_add(tree.varint_word(id).unwrap_or(1))
                .wrapping_add(tree.record_bytes(id).len() as u64)
                .wrapping_add(u64::from(tree.record_ref(id).is_ok()));
        }
        for pos in 0..=u32::try_from(doc.len()).unwrap() {
            sum = sum.wrapping_add(tree.narrowest(pos).map_or(0, |id| u64::from(id.as_inner())));
        }
        sum
    });
    assert_eq!(grew, 0, "a fixed groupless job allocated");

    let (_, grew) = counted(|| {
        let input = Admitted::new(&grouped_doc).unwrap();
        let plan = grouped::Plan::new(GENEROUS).unwrap();
        let mut slab = [MaybeUninit::<u8>::uninit(); 23_000];
        assert!(plan.bytes(DepthLimit::REFERENCE) <= slab.len() as u64);
        let tree =
            grouped::Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, &mut slab)
                .unwrap();
        let mut sum = 0u64;
        for id in tree.nodes() {
            sum = sum
                .wrapping_add(u64::from(tree.span(id).len()))
                .wrapping_add(tree.payload_bytes(id).len() as u64);
        }
        sum
    });
    assert_eq!(grew, 0, "a fixed grouped job allocated");

    // Control 1: the window sees a planted allocation.
    let (_, planted) = counted(|| std::hint::black_box(vec![1u8, 2, 3]).len());
    assert!(planted > 0, "the armed window missed a planted allocation");

    // Control 2: the heap twin's parse books nonzero on the same
    // document.
    let (_, heap_grew) = counted(|| {
        let input = Admitted::new(&doc).unwrap();
        let tree = protobuf_edit::inspect::groupless::Tree::parse(
            input,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        );
        tree.node_count()
    });
    assert!(heap_grew > 0, "the heap twin stopped allocating — the control is stale");
}

// ─── carve honesty and the derived price ───

mod carve_honesty {
    use protobuf_edit::fixed_inspect::groupless::{Plan, Tree};
    use protobuf_edit::fixed_inspect::{OpenFault, grouped};

    use super::*;

    /// The priced figure equals the suite's derived reference over
    /// a spread of plans and limits, in both dialects (one formula
    /// for the member).
    #[test]
    fn the_price_is_the_derived_reference() {
        for rows in [0u32, 1, 2, 7, 100, 10_000, 0x7FFF_FFFF] {
            for limit in [1u16, 2, 100, 10_000] {
                let limit = DepthLimit::new(limit).unwrap();
                let reference = reference_bytes(u64::from(rows), u64::from(limit.as_inner()));
                assert_eq!(
                    Plan::new(rows).unwrap().bytes(limit),
                    reference,
                    "groupless price drifted from the ladder laws at rows={rows}"
                );
                assert_eq!(
                    grouped::Plan::new(rows).unwrap().bytes(limit),
                    reference,
                    "grouped price drifted from the ladder laws at rows={rows}"
                );
            }
        }
    }

    /// One compile-time evaluation of the priced figure equals the
    /// runtime door's refusal answer.
    #[test]
    fn const_priced_figure_matches_the_door() {
        const PLAN: Plan = Plan::new(7).unwrap();
        const NEED: u64 = PLAN.bytes(DepthLimit::REFERENCE);
        assert_eq!(NEED, reference_bytes(7, 100));
        let mut slab = slab_for(NEED - 1);
        let refused = Tree::parse(
            Admitted::new(&[0x08, 0x01]).unwrap(),
            DepthLimit::REFERENCE,
            &mut NoAdvice,
            &PLAN,
            &mut slab,
        );
        assert_eq!(refusal(refused), OpenFault::SlabShort { need: NEED, have: NEED - 1 });
    }

    /// The door parses at exactly `bytes()` and refuses at
    /// `bytes() - 1` naming both figures, repeated on a
    /// deliberately misaligned slab.
    #[test]
    fn bytes_is_the_exact_boundary() {
        let doc = [0x08u8, 0x96, 0x01, 0x12, 0x02, 0x08, 0x01];
        let input = Admitted::new(&doc).unwrap();
        let plan = Plan::new(4).unwrap();
        let need = plan.bytes(DepthLimit::REFERENCE);

        // Exactly priced: parses at any address.
        let mut backing = slab_for(need + 1);
        for offset in [0usize, 1] {
            let slab = &mut backing[offset..offset + usize::try_from(need).unwrap()];
            let tree =
                Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, slab).unwrap();
            assert!(tree.is_complete());
            assert_eq!(tree.node_count(), 3);
        }

        // One byte fewer: refuses naming both figures, at any
        // address, before anything is read.
        for offset in [0usize, 1] {
            let short = &mut backing[offset..offset + usize::try_from(need).unwrap() - 1];
            let refused = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, short);
            assert_eq!(
                refusal(refused),
                OpenFault::SlabShort { need, have: need - 1 },
                "the refusal names the priced figure and the supplied length"
            );
        }
    }

    /// After any door refusal the slab is reusable and nothing was
    /// published — the refusal fingerprint.
    #[test]
    fn refusals_leave_the_slab_reusable() {
        let doc = [0x08u8, 0x01, 0x10, 0x02, 0x18, 0x03];
        let input = Admitted::new(&doc).unwrap();
        let generous = Plan::new(8).unwrap();
        let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));

        // A rows refusal mid-parse…
        let tight = Plan::new(1).unwrap();
        let refused = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &tight, &mut slab);
        assert_eq!(refusal(refused), OpenFault::RowsExhausted);

        // …and a length refusal pre-read both leave the same slab
        // serving a following well-planned parse.
        let huge = Plan::new(1_000_000).unwrap();
        let refused = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &huge, &mut slab);
        assert!(matches!(refusal(refused), OpenFault::SlabShort { .. }));

        let tree =
            Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &generous, &mut slab).unwrap();
        assert!(tree.is_complete());
        assert_eq!(tree.node_count(), 3);
    }
}

// ─── exhaustion and the peak law ───

mod exhaustion {
    use protobuf_edit::fixed_inspect::OpenFault;
    use protobuf_edit::fixed_inspect::groupless::{Plan, Tree};

    use super::*;

    /// For a spread of documents, a plan one row short of measured
    /// demand refuses `RowsExhausted`; re-running at measured
    /// demand succeeds. The sweep asserts refusals actually landed.
    #[test]
    fn one_short_refuses_at_the_peak() {
        let mut refusals = 0u32;
        for seed in 1..=16u64 {
            let doc = document(seed, false);
            let input = Admitted::new(&doc).unwrap();
            let generous = Plan::new(GENEROUS).unwrap();
            let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));
            let tree =
                Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &generous, &mut slab)
                    .unwrap();
            let peak = tree.budget().rows.used;
            let _ = tree;

            if peak == 0 {
                continue;
            }
            let short = Plan::new(peak - 1).unwrap();
            let refused =
                Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &short, &mut slab);
            assert_eq!(refusal(refused), OpenFault::RowsExhausted, "seed {seed}");
            refusals += 1;

            let exact = Plan::new(peak).unwrap();
            let mut exact_slab = slab_for(exact.bytes(DepthLimit::REFERENCE));
            let again =
                Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &exact, &mut exact_slab)
                    .expect("the measured peak is sufficient");
            assert_eq!(again.budget().rows.used, peak);
        }
        assert!(refusals >= 8, "the sweep landed only {refusals} refusals");
    }
}

// ─── the speculation-peak law ───

mod peak {
    use protobuf_edit::fixed_inspect::OpenFault;
    use protobuf_edit::fixed_inspect::groupless::{Plan, Tree};

    use super::*;

    /// A document whose speculation peak exceeds its final row
    /// count: the plan must cover the peak — evaporated rows
    /// occupied the arena — so the final-count plan refuses and
    /// the high-water plan succeeds.
    #[test]
    fn speculation_peak_governs_the_plan() {
        // LEN f2 [ three parsing varints, then a wire fault ]: the
        // speculation pushes four rows (the LEN and three inner),
        // unwinds, and concludes bytes — one final row.
        let doc = [0x12u8, 0x07, 0x08, 0x01, 0x08, 0x02, 0x08, 0x03, 0xFF];
        let input = Admitted::new(&doc).unwrap();

        let generous = Plan::new(GENEROUS).unwrap();
        let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));
        let tree =
            Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &generous, &mut slab).unwrap();
        assert!(tree.is_complete(), "the unwind concluded the payload as bytes");
        let finals = tree.node_count();
        let peak = tree.budget().rows.used;
        assert_eq!((finals, peak), (1, 4), "the fixture's shape drifted");
        let _ = tree;

        // Sized to the final count: refuses — the tempting sizing
        // is wrong by law.
        let final_plan = Plan::new(finals).unwrap();
        let refused =
            Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &final_plan, &mut slab);
        assert_eq!(refusal(refused), OpenFault::RowsExhausted);

        // Sized to the peak: succeeds and answers identically.
        let peak_plan = Plan::new(peak).unwrap();
        let mut peak_slab = slab_for(peak_plan.bytes(DepthLimit::REFERENCE));
        let again =
            Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &peak_plan, &mut peak_slab)
                .unwrap();
        assert_eq!(again.node_count(), finals);
        assert!(again.is_complete());

        // Sequential abandoned speculations reuse slots: two such
        // siblings peak at 5 (the survivor plus the second
        // speculation's four), not at the sum of all pushes.
        let two = [
            0x12u8, 0x07, 0x08, 0x01, 0x08, 0x02, 0x08, 0x03, 0xFF, // first speculation
            0x12, 0x07, 0x08, 0x01, 0x08, 0x02, 0x08, 0x03, 0xFF, // second speculation
        ];
        let input = Admitted::new(&two).unwrap();
        let mut slab = slab_for(generous.bytes(DepthLimit::REFERENCE));
        let tree =
            Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &generous, &mut slab).unwrap();
        assert_eq!(tree.node_count(), 2);
        assert_eq!(tree.budget().rows.used, 5, "abandoned slots are reused, not summed");
    }
}

// ─── the declared-domain and zero-plan boundaries ───

mod batteries {
    use protobuf_edit::fixed_inspect::OpenFault;
    use protobuf_edit::fixed_inspect::{grouped, groupless};

    use super::*;

    /// The plan domain's edges: the row-id domain top admits (a
    /// full plan's top minted index is the id class top) and the
    /// next value refuses, in both dialects.
    #[test]
    fn plans_judge_the_row_domain() {
        assert!(groupless::Plan::new(0x7FFF_FFFF).is_some());
        assert!(groupless::Plan::new(0x8000_0000).is_none());
        assert!(grouped::Plan::new(0x7FFF_FFFF).is_some());
        assert!(grouped::Plan::new(0x8000_0000).is_none());
    }

    /// A zero-row plan is lawful: it parses exactly the empty
    /// document (in a three-byte slab — the priced pad alone), and
    /// one lawful record refuses `RowsExhausted`.
    #[test]
    fn zero_plan_parses_exactly_the_empty_document() {
        let zero = groupless::Plan::new(0).unwrap();
        assert_eq!(zero.bytes(DepthLimit::REFERENCE), 3);
        let mut slab = slab_for(3);
        let empty = Admitted::new(&[]).unwrap();
        let tree =
            groupless::Tree::parse(empty, DepthLimit::REFERENCE, &mut NoAdvice, &zero, &mut slab)
                .unwrap();
        assert!(tree.is_empty() && tree.is_complete());
        assert_eq!(tree.node_count(), 0);
        assert_eq!(tree.budget().rows.used, 0);
        assert_eq!(tree.narrowest(0), None);

        let one_record = Admitted::new(&[0x08, 0x01]).unwrap();
        let refused = groupless::Tree::parse(
            one_record,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
            &zero,
            &mut slab,
        );
        assert_eq!(refusal(refused), OpenFault::RowsExhausted);

        let grouped_zero = grouped::Plan::new(0).unwrap();
        let tree = grouped::Tree::parse(
            empty,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
            &grouped_zero,
            &mut slab,
        )
        .unwrap();
        assert!(tree.is_empty() && tree.is_complete());
    }

    /// Derived stacks under pathological width: a rows-1 plan
    /// derives one-slot stacks and still answers the flat document;
    /// the depth bound caps the derivation under deep plans.
    #[test]
    fn derived_stacks_ride_the_tighter_bound() {
        let one = groupless::Plan::new(1).unwrap();
        assert_eq!(one.bytes(DepthLimit::REFERENCE), reference_bytes(1, 100));
        let mut slab = slab_for(one.bytes(DepthLimit::REFERENCE));
        let input = Admitted::new(&[0x08, 0x2A]).unwrap();
        let tree =
            groupless::Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &one, &mut slab)
                .unwrap();
        let budget = tree.budget();
        assert_eq!((budget.frames.capacity, budget.path.capacity), (1, 1));
        assert!(budget.frames.used <= budget.frames.capacity);

        // Depth-capped: a deep plan's stacks stop at the limit.
        let deep = groupless::Plan::new(1_000).unwrap();
        assert_eq!(deep.bytes(DepthLimit::MIN), reference_bytes(1_000, 1));
    }

    /// The grouped clip case: an unclosed group faults at the
    /// extent end and the clipped row geometry matches the twin's
    /// contract (interior to the cut, no end tag in the type).
    #[test]
    fn grouped_clip_survives_the_boundary() {
        // group f1 { varint f2=5 } with the end tag missing.
        let doc = [0x0Bu8, 0x10, 0x05];
        let input = Admitted::new(&doc).unwrap();
        let plan = grouped::Plan::new(4).unwrap();
        let mut slab = slab_for(plan.bytes(DepthLimit::REFERENCE));
        let tree =
            grouped::Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, &mut slab)
                .unwrap();
        assert!(!tree.is_complete());
        let fault = tree.fault().unwrap();
        assert!(matches!(fault.kind(), grouped::FaultKind::GroupUnclosed { .. }));
        let group = tree.top().next().unwrap();
        assert!(matches!(tree.source_spans(group), grouped::RecordSpans::ClippedGroup { .. }));
        assert!(tree.record_ref(group).is_err(), "a clipped group never designates");
        let inner = tree.children(group).next().unwrap();
        assert_eq!(tree.varint_word(inner), Some(5));
    }

    /// The shared-layer fault vocabulary renders and classifies:
    /// both refusals display their figures and stand as errors.
    #[test]
    fn open_fault_faces_hold() {
        let short = OpenFault::SlabShort { need: 40, have: 12 };
        assert_eq!(short.to_string(), "slab of 12 bytes falls short of the plan's 40");
        assert_eq!(OpenFault::RowsExhausted.to_string(), "the plan's row capacity is spent");
        let dynamic: &dyn core::error::Error = &OpenFault::RowsExhausted;
        assert!(dynamic.source().is_none());
    }
}
