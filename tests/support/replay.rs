//! The replay judge batteries' shared instruments: the armed
//! allocator (byte observation beside the call count), the
//! counting and refusing sources, and the seeded corpora.
//!
//! The armed allocator observes requested bytes beside the call
//! count — a call count alone cannot refute a document-sized
//! allocation — and observation covers only the armed thread, so
//! sibling tests never pollute a fingerprint.
#![allow(dead_code, reason = "each battery binary uses its own subset")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use protobuf_edit::FieldNumber;
use protobuf_edit::replay_source::{Chunk, ReplayWalk, SliceFault, StableReplaySource, SupplyFault};

// ─── the armed allocator (byte observation) ───

pub struct Armed;

static COUNT: AtomicUsize = AtomicUsize::new(0);
static BYTES_TOTAL: AtomicUsize = AtomicUsize::new(0);
static BYTES_MAX: AtomicUsize = AtomicUsize::new(0);
static ARMED_THREAD: AtomicU64 = AtomicU64::new(0);

fn on_armed_thread() -> bool {
    std::thread::current().id().as_u64().get() == ARMED_THREAD.load(Ordering::Relaxed)
}

unsafe impl GlobalAlloc for Armed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if on_armed_thread() {
            COUNT.fetch_add(1, Ordering::Relaxed);
            BYTES_TOTAL.fetch_add(layout.size(), Ordering::Relaxed);
            BYTES_MAX.fetch_max(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if on_armed_thread() {
            COUNT.fetch_add(1, Ordering::Relaxed);
            BYTES_TOTAL.fetch_add(new_size, Ordering::Relaxed);
            BYTES_MAX.fetch_max(new_size, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Armed = Armed;

/// Serializes armed windows across test threads.
static ARM_LOCK: Mutex<()> = Mutex::new(());

/// One job's whole allocation account: call count, largest single
/// requested layout, and total requested bytes.
pub fn measured<T>(job: impl FnOnce() -> T) -> (T, usize, usize, usize) {
    let guard = ARM_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    ARMED_THREAD.store(std::thread::current().id().as_u64().get(), Ordering::Relaxed);
    let count_before = COUNT.load(Ordering::Relaxed);
    let total_before = BYTES_TOTAL.load(Ordering::Relaxed);
    BYTES_MAX.store(0, Ordering::Relaxed);
    let out = job();
    let count = COUNT.load(Ordering::Relaxed) - count_before;
    let total = BYTES_TOTAL.load(Ordering::Relaxed) - total_before;
    let max = BYTES_MAX.load(Ordering::Relaxed);
    ARMED_THREAD.store(0, Ordering::Relaxed);
    drop(guard);
    (out, count, max, total)
}

/// The armed thread's running allocation-call count — a mid-job
/// probe (the pass-two zero-allocation row reads it at the first
/// handoff and again at the job's end).
pub fn alloc_count_now() -> usize {
    COUNT.load(Ordering::Relaxed)
}

// ─── the counting source (pass-count honesty) ───

/// Exterior tallies the counting source writes: the judge keeps
/// them while the source moves into the machine.
#[derive(Default, Debug)]
pub struct WalkStats {
    pub begins: Cell<u32>,
    pub lent: Cell<u64>,
    pub skipped: Cell<u64>,
}

/// Wraps a byte slice, lending views of at most `step` bytes and
/// tallying every `begin`, every lent-and-consumed byte, and
/// every seeked-past byte — the pass-count and byte-budget
/// instrument. `step` may differ per walk (chunk partitioning
/// carries no meaning).
#[derive(Debug)]
pub struct Counting<'a> {
    pub bytes: &'a [u8],
    pub steps: &'a [usize],
    pub stats: &'a WalkStats,
}

#[derive(Debug)]
pub struct CountingWalk<'a> {
    rest: &'a [u8],
    step: usize,
    stats: &'a WalkStats,
}

impl StableReplaySource for Counting<'_> {
    type Error = SliceFault;

    type Walk<'s>
        = CountingWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        let nth = self.stats.begins.get();
        self.stats.begins.set(nth + 1);
        let step = self.steps
            [usize::try_from(nth).expect("test walk counts fit usize") % self.steps.len()];
        Ok(CountingWalk { rest: self.bytes, step, stats: self.stats })
    }
}

impl ReplayWalk for CountingWalk<'_> {
    type Error = SliceFault;

    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<Self::Error>> {
        Ok(Chunk::new(&self.rest[..self.step.min(self.rest.len())]))
    }

    fn consume(&mut self, n: usize) {
        self.stats.lent.set(self.stats.lent.get() + n as u64);
        self.rest = &self.rest[n..];
    }

    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<Self::Error>> {
        let take = n.min(self.rest.len() as u64);
        self.stats.skipped.set(self.stats.skipped.get() + take);
        self.rest = &self.rest[usize::try_from(take).expect("test extents fit usize")..];
        Ok(take)
    }
}

// ─── the refusing source (supply-fault custody rows) ───

/// Scripted refusals: `begin` refuses on walk `refuse_begin`, and
/// fills refuse once the walk has lent `refuse_after` bytes.
#[derive(Debug)]
pub struct Refusing<'a> {
    pub bytes: &'a [u8],
    pub begun: Cell<u32>,
    pub refuse_begin: Option<u32>,
    pub refuse_after: Option<u64>,
}

#[derive(Debug)]
pub struct RefusingWalk<'a> {
    rest: &'a [u8],
    lent: u64,
    refuse_after: Option<u64>,
}

impl StableReplaySource for Refusing<'_> {
    type Error = SliceFault;

    type Walk<'s>
        = RefusingWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        let nth = self.begun.get();
        self.begun.set(nth + 1);
        if self.refuse_begin == Some(nth) {
            return Err(SupplyFault::Changed);
        }
        Ok(RefusingWalk { rest: self.bytes, lent: 0, refuse_after: self.refuse_after })
    }
}

impl ReplayWalk for RefusingWalk<'_> {
    type Error = SliceFault;

    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<Self::Error>> {
        if let Some(cap) = self.refuse_after
            && self.lent >= cap
        {
            return Err(SupplyFault::Changed);
        }
        Ok(Chunk::new(self.rest))
    }

    fn consume(&mut self, n: usize) {
        self.lent += n as u64;
        self.rest = &self.rest[n..];
    }

    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<Self::Error>> {
        let take = n.min(self.rest.len() as u64);
        self.rest = &self.rest[usize::try_from(take).expect("test extents fit usize")..];
        Ok(take)
    }
}

// ─── corpora ───

/// Deterministic xorshift; no external RNG dependency.
pub struct Rng(u64);

impl Rng {
    pub const fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

pub fn f(n: u64) -> FieldNumber {
    FieldNumber::new(1 + u32::try_from(n % 24).expect("small residues fit u32"))
        .expect("small field numbers are in class")
}

/// Grows one seeded layer: scalars, LEN blobs, nested messages,
/// and (when `groups` is set) group frames.
fn grow(
    rng: &mut Rng,
    body: &mut protobuf_edit::construct::grouped::BodyBuilder<'_, '_>,
    depth: u32,
    budget: &mut u32,
    groups: bool,
) {
    let arms = if groups { 10 } else { 8 };
    while *budget > 0 {
        *budget -= 1;
        match rng.next() % arms {
            0..=2 => body.push_varint(f(rng.next()), rng.next() >> (rng.next() % 60)),
            3 => body.push_i32(f(rng.next()), u32::try_from(rng.next() >> 32).expect("high half")),
            4 => body.push_i64(f(rng.next()), rng.next()),
            5 => {
                let len = usize::try_from(rng.next() % 24).expect("small residues fit usize");
                body.push_len_copy(f(rng.next()), &vec![0xA5u8; len]);
            }
            6 | 7 if depth > 0 => {
                let field = f(rng.next());
                body.message(field, |m| grow(rng, m, depth - 1, budget, groups));
            }
            8 | 9 if depth > 0 => {
                let field = f(rng.next());
                body.group(field, |m| grow(rng, m, depth - 1, budget, groups));
            }
            _ => body.push_varint(f(rng.next()), rng.next()),
        }
    }
}

/// One seeded document: a few resident top-layer records around a
/// seeded interior.
pub fn document(seed: u64, budget: u32, groups: bool) -> Vec<u8> {
    let mut rng = Rng(seed | 1);
    let mut builder = protobuf_edit::construct::grouped::Builder::new();
    builder.push_varint(f(seed), seed);
    let mut budget = budget;
    builder.message(f(seed ^ 1), |m| grow(&mut rng, m, 4, &mut budget, groups));
    if groups {
        let mut extra = 8u32;
        builder.group(f(seed ^ 2), |g| grow(&mut rng, g, 2, &mut extra, true));
    }
    builder.push_len(f(3), b"tail-blob");
    builder.finish().expect("seeded documents stay in the LEN class")
}

/// The seeded corpus one dialect's differentials share.
pub fn corpus(groups: bool) -> Vec<Vec<u8>> {
    (0..48u64)
        .map(|seed| {
            document(
                seed.wrapping_mul(if groups { 0xC2B2_AE35 } else { 0x9E37_79B9 }),
                24 + u32::try_from(seed % 40).expect("small residues fit u32"),
                groups,
            )
        })
        .collect()
}

/// A document whose record structure is fixed while its payload
/// sizes scale — the zero-retention pair's generator.
pub fn payload_scaled(payload: usize) -> Vec<u8> {
    let blob = vec![0x5Au8; payload];
    let nested = vec![0xA5u8; payload];
    let mut builder = protobuf_edit::construct::grouped::Builder::new();
    builder.push_varint(f(0), 150);
    builder.push_len(f(1), &blob);
    builder.push_i64(f(2), 7);
    builder.message(f(3), |m| {
        m.push_len_copy(f(4), &nested);
        m.push_varint(f(5), 3);
    });
    builder.finish().expect("the scaled documents stay in the LEN class")
}
