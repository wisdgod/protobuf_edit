//! The fixed in-place cells' judges: armed-allocator zero-count
//! rows over whole jobs (with the planted and heap-twin controls),
//! exhaustion-refusal enumeration with the byte-unchanged buffer
//! fingerprint, carve honesty at the exact demand and at
//! misaligned addresses, budget-equals-measured-demand rows, and
//! the seeded twin-identity differential against the heap in-place
//! cells.

#![cfg(all(
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless"
))]
#![feature(thread_id_value)]

use core::mem::MaybeUninit;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use protobuf_edit::inplace::{Action, Rule, RuleSet};
use protobuf_edit::path::Segment;
use protobuf_edit::{DepthLimit, FieldNumber, Standard, fixed_inplace, inplace};

// ─── the armed allocator (count face, armed-thread scoped) ───

struct Armed;

static COUNT: AtomicUsize = AtomicUsize::new(0);
static ARMED_THREAD: AtomicU64 = AtomicU64::new(0);

fn on_armed_thread() -> bool {
    std::thread::current().id().as_u64().get() == ARMED_THREAD.load(Ordering::Relaxed)
}

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

#[global_allocator]
static ALLOCATOR: Armed = Armed;

/// Serializes armed windows across test threads.
static ARM_LOCK: Mutex<()> = Mutex::new(());

/// Counts armed-thread allocations across `job`: inputs, rules,
/// slabs, and expectations are prepared before the window opens.
fn counted<T>(job: impl FnOnce() -> T) -> (T, usize) {
    let guard = ARM_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    ARMED_THREAD.store(std::thread::current().id().as_u64().get(), Ordering::Relaxed);
    let before = COUNT.load(Ordering::Relaxed);
    let out = job();
    let grew = COUNT.load(Ordering::Relaxed) - before;
    ARMED_THREAD.store(0, Ordering::Relaxed);
    drop(guard);
    (out, grew)
}

// ─── fixtures ───

const fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

/// A heap slab allocated outside every armed window.
fn slab(bytes: usize) -> Vec<MaybeUninit<u8>> {
    vec![MaybeUninit::uninit(); bytes]
}

/// A groupless document exercising every action class: scalars, an
/// equal-length payload, a renumber, a tombstone, a replacement,
/// and one committed descent.
const GROUPLESS_DOC: [u8; 39] = [
    0x08, 0x96, 0x01, // varint f1 = 150 (SetVarint)
    0x12, 0x02, 0x68, 0x69, // LEN f2 "hi" (SetPayload)
    0x1D, 0x00, 0x00, 0x00, 0x00, // i32 f3 (SetI32)
    0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // i64 f4 (SetI64)
    0x28, 0x01, // varint f5 (Renumber -> f6)
    0x3A, 0x02, 0x68, 0x69, // LEN f7 "hi" (Tombstone f9)
    0x42, 0x01, 0x68, // LEN f8 "h" (ReplaceRecord, 3 bytes)
    0x5A, 0x05, 0x50, 0x96, 0x01, 0x10, 0x07, // LEN f11 { f10=150 (wild), f2=7 }
    0x60, 0x00, // varint f12 (unmatched)
];

/// The wildcard route the groupless corpus descends.
static ROUTE_F11: [FieldNumber; 1] = [f(11)];
/// The groupless corpus rules, one per action class.
static GROUPLESS_PATHS: [&[Segment<'static>]; 8] = [
    &[Segment::Field(f(1))],
    &[Segment::Field(f(2))],
    &[Segment::Field(f(3))],
    &[Segment::Field(f(4))],
    &[Segment::Field(f(5))],
    &[Segment::Field(f(7))],
    &[Segment::Field(f(8))],
    &[Segment::AnyDepth { descend: &ROUTE_F11 }, Segment::Field(f(10))],
];

fn groupless_rules() -> Vec<Rule<'static>> {
    vec![
        Rule { path: GROUPLESS_PATHS[0], action: Action::SetVarint(200) },
        Rule { path: GROUPLESS_PATHS[1], action: Action::SetPayload(b"no") },
        Rule { path: GROUPLESS_PATHS[2], action: Action::SetI32(0xAABB_CCDD) },
        Rule { path: GROUPLESS_PATHS[3], action: Action::SetI64(0x0102_0304_0506_0708) },
        Rule { path: GROUPLESS_PATHS[4], action: Action::Renumber(f(6)) },
        Rule { path: GROUPLESS_PATHS[5], action: Action::Tombstone { field: f(9) } },
        Rule { path: GROUPLESS_PATHS[6], action: Action::ReplaceRecord(&[0x08, 0x96, 0x01]) },
        Rule { path: GROUPLESS_PATHS[7], action: Action::SetVarint(9) },
    ]
}

/// Matched writes in [`GROUPLESS_DOC`]: seven top-level landings
/// plus the nested wildcard hit.
const GROUPLESS_WRITES: u32 = 8;

/// group f1 { varint f2 } (renumbered pair) · group f3 { varint
/// f2 } (tombstoned) · group f5 { i32 f2 } (replaced whole) ·
/// group f7 { varint f2 = 150, landed via the route } · varint f8
/// (unmatched) · varint f1 (the renumber rule's scalar arm).
const GROUPED_DOC: [u8; 25] = [
    0x0B, 0x10, 0x96, 0x01, 0x0C, // group f1 { varint f2=150 }
    0x1B, 0x10, 0x00, 0x1C, // group f3 { varint f2=0 }
    0x2B, 0x15, 0x00, 0x00, 0x00, 0x00, 0x2C, // group f5 { i32 f2 }
    0x3B, 0x10, 0x96, 0x01, 0x3C, // group f7 { varint f2=150 }
    0x40, 0x07, // varint f8 = 7
    0x08, 0x01, // varint f1 = 1
];

/// The route through group f7.
static ROUTE_F7: [FieldNumber; 1] = [f(7)];
/// The grouped corpus rules.
static GROUPED_PATHS: [&[Segment<'static>]; 4] = [
    &[Segment::Field(f(1))],
    &[Segment::Field(f(3))],
    &[Segment::Field(f(5))],
    &[Segment::AnyDepth { descend: &ROUTE_F7 }, Segment::Field(f(2))],
];

fn grouped_rules() -> Vec<Rule<'static>> {
    vec![
        Rule { path: GROUPED_PATHS[0], action: Action::Renumber(f(15)) },
        Rule { path: GROUPED_PATHS[1], action: Action::Tombstone { field: f(9) } },
        Rule {
            // The candidate is one balanced group of equal extent
            // (seven bytes), canonical throughout.
            path: GROUPED_PATHS[2],
            action: Action::ReplaceRecord(&[0x2B, 0x22, 0x03, 0x68, 0x69, 0x6A, 0x2C]),
        },
        // The routed value's minimal width equals its met slot, so
        // the canonical instance lands the same corpus.
        Rule { path: GROUPED_PATHS[3], action: Action::SetVarint(200) },
    ]
}

/// Matched writes in [`GROUPED_DOC`]: the pair's two tags, the
/// tombstone, the replacement, the routed interior landing, and
/// the trailing scalar's renumber tag.
const GROUPED_WRITES: u32 = 6;

// ─── judge 1: armed-allocator zero rows with two controls ───

#[test]
fn the_probe_counts_a_planted_allocation() {
    // Positive control: the instrument sees a heap event inside
    // the window, or every zero below is blind.
    let ((), grew) = counted(|| {
        std::hint::black_box(Vec::<u8>::with_capacity(64));
    });
    assert!(grew >= 1, "the armed allocator missed a planted allocation");
}

#[test]
fn the_heap_twin_allocates_on_the_same_corpus() {
    // Positive control: the host twin books at least one armed
    // allocation over the corpus the fixed rows run at zero.
    let rules = groupless_rules();
    let set = RuleSet::over(&rules).unwrap();
    let mut buf = GROUPLESS_DOC;
    let (result, grew) =
        counted(|| inplace::groupless::apply(&mut buf, &set, DepthLimit::REFERENCE));
    assert_eq!(result.unwrap().replaced(), 5);
    assert!(grew >= 1, "the heap twin allocated nothing — the zero rows judge nothing");
}

#[test]
fn groupless_jobs_run_at_exactly_zero_allocations() {
    let rules = groupless_rules();
    let set = RuleSet::over(&rules).unwrap();
    let plan = fixed_inplace::groupless::Plan::new(GROUPLESS_WRITES).unwrap();
    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        let mut storage = slab(plan.bytes(&set, DepthLimit::REFERENCE));
        let mut buf = GROUPLESS_DOC;
        let (result, grew) = counted(|| {
            fixed_inplace::groupless::apply_standard(
                &mut buf,
                &set,
                standard,
                DepthLimit::REFERENCE,
                &plan,
                &mut storage,
            )
        });
        match standard {
            // The corpus is tolerant wire: the canonical instance
            // refuses a padded width — at zero allocations too.
            Standard::Tolerant => {
                let stats = result.unwrap();
                assert_eq!(
                    (stats.replaced(), stats.renumbered(), stats.tombstoned(), stats.substituted()),
                    (5, 1, 1, 1)
                );
            }
            Standard::CanonicalMinimal => {
                result.unwrap_err();
                assert_eq!(buf, GROUPLESS_DOC, "the refused buffer moved");
            }
        }
        assert_eq!(grew, 0, "a fixed groupless job allocated under {standard:?}");
    }
}

#[test]
fn grouped_jobs_run_at_exactly_zero_allocations() {
    let rules = grouped_rules();
    let set = RuleSet::over(&rules).unwrap();
    let plan = fixed_inplace::grouped::Plan::new(GROUPED_WRITES).unwrap();
    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        let mut storage = slab(plan.bytes(&set, DepthLimit::REFERENCE));
        let mut buf = GROUPED_DOC;
        let (result, grew) = counted(|| {
            fixed_inplace::grouped::apply_standard(
                &mut buf,
                &set,
                standard,
                DepthLimit::REFERENCE,
                &plan,
                &mut storage,
            )
        });
        // The corpus and every authored word are canonical-minimal
        // at their met widths: both instances land the same job.
        let stats = result.unwrap();
        assert_eq!(
            (stats.replaced(), stats.renumbered(), stats.tombstoned(), stats.substituted()),
            (1, 2, 1, 1),
            "under {standard:?}"
        );
        assert_eq!(grew, 0, "a fixed grouped job allocated under {standard:?}");
    }
}

#[test]
fn refusals_run_at_exactly_zero_allocations() {
    // The refusal paths — slab short, write list full, wire fault,
    // conflict — allocate nothing either.
    let rules = groupless_rules();
    let set = RuleSet::over(&rules).unwrap();
    let plan = fixed_inplace::groupless::Plan::new(1).unwrap();
    let need = plan.bytes(&set, DepthLimit::REFERENCE);
    let mut short = slab(need - 1);
    let mut full = slab(need);
    let mut buf = GROUPLESS_DOC;
    let snapshot = buf;
    let ((slab_short, list_full), grew) = counted(|| {
        let slab_short = fixed_inplace::groupless::apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut short,
        )
        .unwrap_err();
        let list_full = fixed_inplace::groupless::apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut full,
        )
        .unwrap_err();
        (slab_short, list_full)
    });
    assert_eq!(grew, 0, "a refusal path allocated");
    assert!(matches!(slab_short.kind(), fixed_inplace::groupless::FaultKind::SlabShort { .. }));
    assert!(matches!(
        list_full.kind(),
        fixed_inplace::groupless::FaultKind::WriteListFull { need: 2, have: 1 }
    ));
    assert_eq!(buf, snapshot, "a refused buffer moved");
}

// ─── judge 2: exhaustion-refusal enumeration ───

#[test]
fn the_write_lane_sweep_refuses_every_short_plan_and_lands_the_exact_one() {
    let rules = groupless_rules();
    let set = RuleSet::over(&rules).unwrap();
    let mut refusals = 0;
    for declared in 0..=GROUPLESS_WRITES {
        let plan = fixed_inplace::groupless::Plan::new(declared).unwrap();
        let mut storage = slab(plan.bytes(&set, DepthLimit::REFERENCE));
        let mut buf = GROUPLESS_DOC;
        let outcome = fixed_inplace::groupless::apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut storage,
        );
        if declared < GROUPLESS_WRITES {
            let fault = outcome.unwrap_err();
            assert!(
                matches!(
                    fault.kind(),
                    fixed_inplace::groupless::FaultKind::WriteListFull { need, have }
                        if need == declared + 1 && have == declared
                ),
                "plan {declared}: wrong refusal {fault:?}"
            );
            assert_eq!(buf, GROUPLESS_DOC, "plan {declared}: the refused buffer moved");
            refusals += 1;
        } else {
            outcome.unwrap();
            assert_ne!(buf, GROUPLESS_DOC, "the exact plan landed nothing");
        }
    }
    assert_eq!(refusals, GROUPLESS_WRITES, "the sweep landed no refusals");
}

#[test]
fn the_grouped_write_lane_sweep_covers_the_pair() {
    let rules = grouped_rules();
    let set = RuleSet::over(&rules).unwrap();
    let mut refusals = 0;
    for declared in 0..=GROUPED_WRITES {
        let plan = fixed_inplace::grouped::Plan::new(declared).unwrap();
        let mut storage = slab(plan.bytes(&set, DepthLimit::REFERENCE));
        let mut buf = GROUPED_DOC;
        let outcome = fixed_inplace::grouped::apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut storage,
        );
        if declared < GROUPED_WRITES {
            let fault = outcome.unwrap_err();
            assert!(
                matches!(
                    fault.kind(),
                    fixed_inplace::grouped::FaultKind::WriteListFull { need, have }
                        if need == declared + 1 && have == declared
                ),
                "plan {declared}: wrong refusal {fault:?}"
            );
            assert_eq!(buf, GROUPED_DOC, "plan {declared}: the refused buffer moved");
            refusals += 1;
        } else {
            outcome.unwrap();
        }
    }
    assert_eq!(refusals, GROUPED_WRITES, "the sweep landed no refusals");
}

// ─── judge 3: carve honesty and the budget face ───

#[test]
fn carve_honesty_holds_at_the_boundary_and_any_address() {
    let rules = groupless_rules();
    let set = RuleSet::over(&rules).unwrap();
    let plan = fixed_inplace::groupless::Plan::new(GROUPLESS_WRITES).unwrap();
    let need = plan.bytes(&set, DepthLimit::REFERENCE);
    let mut backing = slab(need + 8);
    for offset in 0..8 {
        // Exactly the demand carves and lands, at every address.
        let mut buf = GROUPLESS_DOC;
        fixed_inplace::groupless::apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut backing[offset..offset + need],
        )
        .unwrap();
        // One byte fewer refuses deterministically, at every
        // address, with the exact need quoted.
        let mut buf = GROUPLESS_DOC;
        let fault = fixed_inplace::groupless::apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut backing[offset..offset + need - 1],
        )
        .unwrap_err();
        assert!(matches!(
            fault.kind(),
            fixed_inplace::groupless::FaultKind::SlabShort { need: n, have }
                if n == need && have == need - 1
        ));
        assert_eq!(buf, GROUPLESS_DOC);
    }
}

#[test]
fn the_budget_equals_the_measured_demand() {
    // The sizing loop, run mechanically: a generous prototype
    // reports the tight write count, and the tight plan lands the
    // job at exactly its own demand.
    let rules = groupless_rules();
    let set = RuleSet::over(&rules).unwrap();
    let generous = fixed_inplace::groupless::Plan::new(1024).unwrap();
    let mut storage = slab(generous.bytes(&set, DepthLimit::REFERENCE));
    let mut buf = GROUPLESS_DOC;
    let (result, budget) = fixed_inplace::groupless::apply_budget(
        &mut buf,
        &set,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &generous,
        &mut storage,
    );
    result.unwrap();
    assert_eq!(budget.writes().used, GROUPLESS_WRITES as usize);
    assert_eq!(budget.writes().capacity, 1024);
    for gauge in [
        budget.layers(),
        budget.levels(),
        budget.targets(),
        budget.stages(),
        budget.wilds(),
        budget.staged(),
    ] {
        assert!(gauge.used <= gauge.capacity, "a derived bound was undersized: {gauge:?}");
    }
    // Ship the tight plan.
    let tight = fixed_inplace::groupless::Plan::new(GROUPLESS_WRITES).unwrap();
    let mut storage = slab(tight.bytes(&set, DepthLimit::REFERENCE));
    let mut buf = GROUPLESS_DOC;
    fixed_inplace::groupless::apply(&mut buf, &set, DepthLimit::REFERENCE, &tight, &mut storage)
        .unwrap();
}

/// The adversarial descend sets: adjacent, incomparable, sharing
/// the chain field.
static OUTER: [FieldNumber; 2] = [f(1), f(2)];
static INNER: [FieldNumber; 2] = [f(1), f(3)];
/// A run of two wildcards before the terminal (the quadratic-risk
/// shape the flatten dedup bounds), plus a staged hop under a
/// field the documents never carry.
static ADVERSARIAL_PATHS: [&[Segment<'static>]; 2] = [
    &[
        Segment::AnyDepth { descend: &OUTER },
        Segment::AnyDepth { descend: &INNER },
        Segment::Field(f(4)),
    ],
    &[Segment::Field(f(9)), Segment::Field(f(4))],
];
/// The grouped adversary's route: self-similar group nesting.
static GROUP_ROUTE: [FieldNumber; 1] = [f(1)];
static GROUP_RENUMBER_PATH: [&[Segment<'static>]; 1] =
    [&[Segment::AnyDepth { descend: &GROUP_ROUTE }, Segment::Field(f(1))]];

#[test]
fn adversarial_shapes_stay_inside_the_derived_bounds() {
    // The derivation's worst cases: an adjacent wildcard run over
    // incomparable sets, self-similar nesting that keeps every
    // run state live, and (grouped) pending pairs at depth. The
    // budget face proves occupancy never crossed a derived
    // capacity; the lanes' own debug assertions arm the same claim
    // under this build.
    let rules = vec![
        Rule { path: ADVERSARIAL_PATHS[0], action: Action::SetVarint(0) },
        Rule { path: ADVERSARIAL_PATHS[1], action: Action::SetI32(0) },
    ];
    let set = RuleSet::over(&rules).unwrap();
    // Self-similar document: f1-LEN chains, every level landing a
    // varint f4 = 0. Level shape: varint f4 · LEN f1 { ... }.
    fn nest(depth: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&[0x20, 0x00]); // varint f4 = 0
        if depth > 0 {
            let mut body = Vec::new();
            nest(depth - 1, &mut body);
            out.push(0x0A); // LEN f1
            out.push(u8::try_from(body.len()).expect("fixture bodies stay one byte long"));
            out.extend_from_slice(&body);
        }
    }
    let mut doc = Vec::new();
    nest(20, &mut doc);
    let plan = fixed_inplace::groupless::Plan::new(64).unwrap();
    let mut storage = slab(plan.bytes(&set, DepthLimit::REFERENCE));
    let (result, budget) = fixed_inplace::groupless::apply_budget(
        &mut doc,
        &set,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &plan,
        &mut storage,
    );
    // The wildcard run's chains land the hit at all 21 levels.
    assert_eq!(result.unwrap().replaced(), 21);
    for gauge in [
        budget.layers(),
        budget.levels(),
        budget.targets(),
        budget.stages(),
        budget.wilds(),
        budget.staged(),
    ] {
        assert!(gauge.used <= gauge.capacity, "a derived bound was undersized: {gauge:?}");
    }

    // The grouped mirror: group chains with a renumber at every
    // level — pending pairs and opens climb together.
    let grouped_rules = vec![Rule { path: GROUP_RENUMBER_PATH[0], action: Action::Renumber(f(8)) }];
    let gset = RuleSet::over(&grouped_rules).unwrap();
    // group f1 { group f1 { ... } } nesting: every enter matches
    // the renumber rule at its own level (the wildcard also
    // matches zero crossings).
    let mut gdoc = vec![0x0B; 30];
    gdoc.resize(60, 0x0C);
    let gplan = fixed_inplace::grouped::Plan::new(64).unwrap();
    let mut gstorage = slab(gplan.bytes(&gset, DepthLimit::REFERENCE));
    let (result, budget) = fixed_inplace::grouped::apply_budget(
        &mut gdoc,
        &gset,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &gplan,
        &mut gstorage,
    );
    assert_eq!(result.unwrap().renumbered(), 30);
    assert_eq!(budget.opens().used, 30);
    assert_eq!(budget.pending().used, 30);
    for gauge in [
        budget.layers(),
        budget.levels(),
        budget.targets(),
        budget.stages(),
        budget.wilds(),
        budget.staged(),
        budget.opens(),
        budget.pending(),
    ] {
        assert!(gauge.used <= gauge.capacity, "a derived bound was undersized: {gauge:?}");
    }
}

// ─── judge 4: the twin-identity differential ───

/// The seeded generator (xorshift): documents and rule subsets.
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

    const fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// One random document: records over fields 1..=6, nesting through
/// LEN f5 (and, when `groups` is set, group f6), depth-bounded.
fn gen_doc(rng: &mut Rng, groups: bool, depth: usize, out: &mut Vec<u8>) {
    let records = 1 + rng.below(4);
    for _ in 0..records {
        match rng.below(if groups && depth > 0 {
            6
        } else if depth > 0 {
            5
        } else {
            4
        }) {
            0 => {
                // varint f1, occasionally padded (tolerant wire).
                if rng.below(4) == 0 {
                    out.extend_from_slice(&[0x08, 0x96, 0x81, 0x00]);
                } else {
                    out.extend_from_slice(&[0x08, 0x96, 0x01]);
                }
            }
            1 => {
                out.push(0x15); // i32 f2
                out.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
            }
            2 => {
                out.push(0x19); // i64 f3
                out.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
            }
            3 => {
                // LEN f4, opaque payload of 0..=4 bytes.
                let len = rng.below(5);
                out.push(0x22);
                out.push(u8::try_from(len).expect("bounded above"));
                for _ in 0..len {
                    out.push(0x41);
                }
            }
            4 => {
                // LEN f5: a nested message.
                let mut body = Vec::new();
                gen_doc(rng, groups, depth - 1, &mut body);
                out.push(0x2A);
                out.push(u8::try_from(body.len().min(255)).unwrap_or(255));
                out.extend_from_slice(&body[..body.len().min(255)]);
            }
            _ => {
                // group f6.
                out.push(0x33);
                gen_doc(rng, groups, depth - 1, out);
                out.push(0x34);
            }
        }
    }
}

/// The differential's path pool: plain targets, hops, and
/// wildcards over the containers.
static POOL_ROUTE_LEN: [FieldNumber; 1] = [f(5)];
static POOL_ROUTE_BOTH: [FieldNumber; 2] = [f(5), f(6)];
static POOL_PATHS: [&[Segment<'static>]; 7] = [
    &[Segment::Field(f(1))],
    &[Segment::Field(f(2))],
    &[Segment::Field(f(4))],
    &[Segment::Field(f(5)), Segment::Field(f(1))],
    &[Segment::AnyDepth { descend: &POOL_ROUTE_LEN }, Segment::Field(f(2))],
    &[Segment::AnyDepth { descend: &POOL_ROUTE_BOTH }, Segment::Field(f(3))],
    &[Segment::Field(f(6))],
];

/// One random action per pick, over the whole vocabulary.
fn gen_action(rng: &mut Rng) -> Action<'static> {
    match rng.below(7) {
        0 => Action::SetVarint(rng.next() >> (rng.below(60) + 1)),
        1 => Action::SetI32(0xAABB_CCDD),
        2 => Action::SetI64(0x1122_3344_5566_7788),
        3 => Action::SetPayload(match rng.below(3) {
            0 => b"",
            1 => b"xy",
            _ => b"xyzw",
        }),
        4 => Action::Renumber(f(u32::try_from(rng.below(14)).expect("bounded") + 1)),
        5 => Action::Tombstone { field: f(u32::try_from(rng.below(14)).expect("bounded") + 1) },
        _ => Action::ReplaceRecord(match rng.below(3) {
            0 => &[0x08, 0x00],
            1 => &[0x08, 0x96, 0x01],
            _ => &[0x22, 0x02, 0x68, 0x69],
        }),
    }
}

/// Equivalence of the twins' groupless fault vocabularies.
fn same_groupless_fault(
    host: inplace::groupless::Fault,
    fixed: fixed_inplace::groupless::Fault,
) -> bool {
    use fixed_inplace::groupless::{FaultKind as F, WireBreach as FW};
    use inplace::groupless::{FaultKind as H, WireBreach as HW};
    let breach_eq = |h: HW, x: FW| {
        matches!(
            (h, x),
            (HW::Varint, FW::Varint)
                | (HW::Tag, FW::Tag)
                | (HW::Truncated, FW::Truncated)
                | (HW::Depth, FW::Depth)
                | (HW::NonMinimal, FW::NonMinimal)
                | (HW::GroupCode, FW::GroupCode)
        )
    };
    if host.at() != fixed.at() {
        return false;
    }
    match (host.kind(), fixed.kind()) {
        (H::Oversize, F::Oversize) => true,
        (H::Wire(h), F::Wire(x)) => breach_eq(h, x),
        (H::Conflict { first: a, second: b }, F::Conflict { first: c, second: d }) => {
            (a, b) == (c, d)
        }
        (H::KindMismatch { rule: a }, F::KindMismatch { rule: b }) => a == b,
        (
            H::ValueWidth { rule: a, need: b, have: c },
            F::ValueWidth { rule: d, need: e, have: g },
        )
        | (H::TagWidth { rule: a, need: b, have: c }, F::TagWidth { rule: d, need: e, have: g })
        | (
            H::PayloadLength { rule: a, need: b, have: c },
            F::PayloadLength { rule: d, need: e, have: g },
        )
        | (
            H::FillerUnfit { rule: a, need: b, have: c },
            F::FillerUnfit { rule: d, need: e, have: g },
        )
        | (
            H::ReplacementLength { rule: a, need: b, have: c },
            F::ReplacementLength { rule: d, need: e, have: g },
        ) => (a, b, c) == (d, e, g),
        (
            H::ReplacementWire { rule: a, at: b, breach: c },
            F::ReplacementWire { rule: d, at: e, breach: g },
        ) => (a, b) == (d, e) && breach_eq(c, g),
        (H::ReplacementShape { rule: a }, F::ReplacementShape { rule: b }) => a == b,
        _ => false,
    }
}

/// Equivalence of the twins' grouped fault vocabularies.
fn same_grouped_fault(host: inplace::grouped::Fault, fixed: fixed_inplace::grouped::Fault) -> bool {
    use fixed_inplace::grouped::{FaultKind as F, WireBreach as FW};
    use inplace::grouped::{FaultKind as H, WireBreach as HW};
    let breach_eq = |h: HW, x: FW| {
        matches!(
            (h, x),
            (HW::Varint, FW::Varint)
                | (HW::Tag, FW::Tag)
                | (HW::Truncated, FW::Truncated)
                | (HW::Grouping, FW::Grouping)
                | (HW::Depth, FW::Depth)
                | (HW::NonMinimal, FW::NonMinimal)
        )
    };
    if host.at() != fixed.at() {
        return false;
    }
    match (host.kind(), fixed.kind()) {
        (H::Oversize, F::Oversize) => true,
        (H::Wire(h), F::Wire(x)) => breach_eq(h, x),
        (H::Conflict { first: a, second: b }, F::Conflict { first: c, second: d }) => {
            (a, b) == (c, d)
        }
        (H::KindMismatch { rule: a }, F::KindMismatch { rule: b }) => a == b,
        (
            H::ValueWidth { rule: a, need: b, have: c },
            F::ValueWidth { rule: d, need: e, have: g },
        )
        | (H::TagWidth { rule: a, need: b, have: c }, F::TagWidth { rule: d, need: e, have: g })
        | (
            H::PayloadLength { rule: a, need: b, have: c },
            F::PayloadLength { rule: d, need: e, have: g },
        )
        | (
            H::FillerUnfit { rule: a, need: b, have: c },
            F::FillerUnfit { rule: d, need: e, have: g },
        )
        | (
            H::ReplacementLength { rule: a, need: b, have: c },
            F::ReplacementLength { rule: d, need: e, have: g },
        ) => (a, b, c) == (d, e, g),
        (
            H::ReplacementWire { rule: a, at: b, breach: c },
            F::ReplacementWire { rule: d, at: e, breach: g },
        ) => (a, b) == (d, e) && breach_eq(c, g),
        (H::ReplacementShape { rule: a }, F::ReplacementShape { rule: b }) => a == b,
        _ => false,
    }
}

#[test]
fn the_groupless_twins_are_byte_identical_within_plan() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut landed = 0;
    let mut faulted = 0;
    for round in 0..512 {
        let mut doc = Vec::new();
        gen_doc(&mut rng, false, 3, &mut doc);
        // A random distinct subset of the pool, random actions.
        let mut rules = Vec::new();
        for (i, path) in POOL_PATHS.iter().enumerate() {
            if i != 6 && rng.below(2) == 0 {
                rules.push(Rule { path, action: gen_action(&mut rng) });
            }
        }
        if rules.is_empty() {
            rules.push(Rule { path: POOL_PATHS[0], action: gen_action(&mut rng) });
        }
        let set = RuleSet::over(&rules).unwrap();
        let standard =
            if rng.below(2) == 0 { Standard::Tolerant } else { Standard::CanonicalMinimal };
        // Every fourth round runs under a tight depth budget, so
        // the depth-refusal parity is differential fact, not just
        // a hand-checked row.
        let limit = if round % 4 == 0 { DepthLimit::MIN } else { DepthLimit::REFERENCE };

        let mut host_buf = doc.clone();
        let host = inplace::groupless::apply_standard(&mut host_buf, &set, standard, limit);

        let plan = fixed_inplace::groupless::Plan::new(1024).unwrap();
        let mut storage = slab(plan.bytes(&set, limit));
        let mut fixed_buf = doc.clone();
        let fixed = fixed_inplace::groupless::apply_standard(
            &mut fixed_buf,
            &set,
            standard,
            limit,
            &plan,
            &mut storage,
        );

        match (host, fixed) {
            (Ok(h), Ok(x)) => {
                landed += 1;
                assert_eq!(
                    (h.replaced(), h.renumbered(), h.tombstoned(), h.substituted()),
                    (x.replaced(), x.renumbered(), x.tombstoned(), x.substituted()),
                    "round {round}: receipts diverged"
                );
            }
            (Err(h), Err(x)) => {
                faulted += 1;
                assert!(
                    same_groupless_fault(h, x),
                    "round {round}: faults diverged: {h:?} vs {x:?}"
                );
            }
            (h, x) => panic!("round {round}: verdicts diverged: {h:?} vs {x:?}"),
        }
        assert_eq!(host_buf, fixed_buf, "round {round}: buffers diverged");
    }
    // The generator really generated both sides of the space.
    assert!(landed >= 64, "only {landed} landing jobs seen");
    assert!(faulted >= 64, "only {faulted} faulting jobs seen");
}

#[test]
fn the_grouped_twins_are_byte_identical_within_plan() {
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    let mut landed = 0;
    let mut faulted = 0;
    for round in 0..512 {
        let mut doc = Vec::new();
        gen_doc(&mut rng, true, 3, &mut doc);
        let mut rules = Vec::new();
        for (i, path) in POOL_PATHS.iter().enumerate() {
            if rng.below(2) == 0 {
                let _ = i;
                rules.push(Rule { path, action: gen_action(&mut rng) });
            }
        }
        if rules.is_empty() {
            rules.push(Rule { path: POOL_PATHS[6], action: gen_action(&mut rng) });
        }
        let set = RuleSet::over(&rules).unwrap();
        let standard =
            if rng.below(2) == 0 { Standard::Tolerant } else { Standard::CanonicalMinimal };
        // Every fourth round runs under a tight depth budget, so
        // the depth-refusal parity — the walk's checks and the
        // stepper's own — is differential fact, not just a
        // hand-checked row.
        let limit =
            if round % 4 == 0 { DepthLimit::new(2).unwrap() } else { DepthLimit::REFERENCE };

        let mut host_buf = doc.clone();
        let host = inplace::grouped::apply_standard(&mut host_buf, &set, standard, limit);

        let plan = fixed_inplace::grouped::Plan::new(1024).unwrap();
        let mut storage = slab(plan.bytes(&set, limit));
        let mut fixed_buf = doc.clone();
        let fixed = fixed_inplace::grouped::apply_standard(
            &mut fixed_buf,
            &set,
            standard,
            limit,
            &plan,
            &mut storage,
        );

        match (host, fixed) {
            (Ok(h), Ok(x)) => {
                landed += 1;
                assert_eq!(
                    (h.replaced(), h.renumbered(), h.tombstoned(), h.substituted()),
                    (x.replaced(), x.renumbered(), x.tombstoned(), x.substituted()),
                    "round {round}: receipts diverged"
                );
            }
            (Err(h), Err(x)) => {
                faulted += 1;
                assert!(same_grouped_fault(h, x), "round {round}: faults diverged: {h:?} vs {x:?}");
            }
            (h, x) => panic!("round {round}: verdicts diverged: {h:?} vs {x:?}"),
        }
        assert_eq!(host_buf, fixed_buf, "round {round}: buffers diverged");
    }
    assert!(landed >= 64, "only {landed} landing jobs seen");
    assert!(faulted >= 64, "only {faulted} faulting jobs seen");
}

/// `LEN f5 { group f6 { group f1 … } }`: under limit 2 the
/// committed descent spends one account and the f6 crossing the
/// other, so the f1 enter arrives with the layer's own budget
/// spent — the shape where the walk's matcher judgment and its
/// depth judgment compete, and only the group tags after the
/// fault site keep the document well formed.
const SPENT_BUDGET_DOC: [u8; 6] = [0x2A, 0x04, 0x33, 0x0B, 0x0C, 0x34];

/// The wildcard's route through both containers to the enter.
static SPENT_BUDGET_ROUTE: [FieldNumber; 2] = [f(5), f(6)];
/// The two paths landing on the same enter: direct and routed.
static SPENT_BUDGET_PATHS: [&[Segment<'static>]; 2] = [
    &[Segment::Field(f(5)), Segment::Field(f(6)), Segment::Field(f(1))],
    &[Segment::AnyDepth { descend: &SPENT_BUDGET_ROUTE }, Segment::Field(f(1))],
];

/// A conflicted group enter at a spent layer budget delivers the
/// matcher fault, not `Wire(Depth)`: the walk probes the matcher
/// before any depth judgment at a walked enter, exactly as the
/// heap twin — whose stepper holds no depth account — always
/// does. A stepper guard tightened to the layer's own remaining
/// budget would refuse this enter first and flip the fault kind;
/// this row is the difference's judge.
#[test]
fn a_conflicted_enter_at_a_spent_budget_delivers_the_matcher_fault() {
    let rules = [
        Rule { path: SPENT_BUDGET_PATHS[0], action: Action::Renumber(f(2)) },
        Rule { path: SPENT_BUDGET_PATHS[1], action: Action::Tombstone { field: f(9) } },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let limit = DepthLimit::new(2).unwrap();

    let mut host_buf = SPENT_BUDGET_DOC;
    let host = inplace::grouped::apply(&mut host_buf, &set, limit).unwrap_err();

    let plan = fixed_inplace::grouped::Plan::new(4).unwrap();
    let mut storage = slab(plan.bytes(&set, limit));
    let mut fixed_buf = SPENT_BUDGET_DOC;
    let fixed = fixed_inplace::grouped::apply(&mut fixed_buf, &set, limit, &plan, &mut storage)
        .unwrap_err();

    assert_eq!(fixed.at(), 3, "the fault names the enter tag");
    assert!(
        matches!(fixed.kind(), fixed_inplace::grouped::FaultKind::Conflict { first: 0, second: 1 }),
        "the depth judgment displaced the matcher's: {fixed:?}"
    );
    assert!(same_grouped_fault(host, fixed), "the twins diverged: {host:?} vs {fixed:?}");
    assert_eq!(host_buf, SPENT_BUDGET_DOC, "the refused host buffer moved");
    assert_eq!(fixed_buf, SPENT_BUDGET_DOC, "the refused fixed buffer moved");
}

/// The kind-mismatched sibling of the conflicted row: one scalar
/// rule landing on the same spent-budget group enter delivers
/// `KindMismatch`, not `Wire(Depth)`, byte- and coordinate-
/// identical to the heap twin.
#[test]
fn a_kind_mismatched_enter_at_a_spent_budget_delivers_the_matcher_fault() {
    let rules = [Rule { path: SPENT_BUDGET_PATHS[0], action: Action::SetVarint(1) }];
    let set = RuleSet::over(&rules).unwrap();
    let limit = DepthLimit::new(2).unwrap();

    let mut host_buf = SPENT_BUDGET_DOC;
    let host = inplace::grouped::apply(&mut host_buf, &set, limit).unwrap_err();

    let plan = fixed_inplace::grouped::Plan::new(4).unwrap();
    let mut storage = slab(plan.bytes(&set, limit));
    let mut fixed_buf = SPENT_BUDGET_DOC;
    let fixed = fixed_inplace::grouped::apply(&mut fixed_buf, &set, limit, &plan, &mut storage)
        .unwrap_err();

    assert_eq!(fixed.at(), 3, "the fault names the enter tag");
    assert!(
        matches!(fixed.kind(), fixed_inplace::grouped::FaultKind::KindMismatch { rule: 0 }),
        "the depth judgment displaced the matcher's: {fixed:?}"
    );
    assert!(same_grouped_fault(host, fixed), "the twins diverged: {host:?} vs {fixed:?}");
    assert_eq!(host_buf, SPENT_BUDGET_DOC, "the refused host buffer moved");
    assert_eq!(fixed_buf, SPENT_BUDGET_DOC, "the refused fixed buffer moved");
}
