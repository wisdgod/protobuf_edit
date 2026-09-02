//! Dependency-free micro-benchmarks: `cargo bench`.
//!
//! Each benchmark reports the median of timed batches after a
//! warmup, as ns/iter plus MiB/s over the input size. Inputs are
//! deterministic, so numbers are comparable across runs on the same
//! machine. The reference points recorded in the old core's README
//! (cursor walk ~1.0 GiB/s, one-edit save ~4.9 GiB/s, chunky saves
//! converging on memcpy) are the same-machine baselines the
//! rewritten modules answer to.

use std::hint::black_box;
use std::time::Instant;

use protobuf_edit::construct::grouped::Builder;
use protobuf_edit::inspect::{Admitted, NoAdvice};
use protobuf_edit::session::grouped::{Descent, InsertAt, Session};
use protobuf_edit::scan::Standard;
use protobuf_edit::traverse::GroupDepth;
use protobuf_edit::varint::slice;
use protobuf_edit::{DepthLimit, FieldNumber};

const SAMPLES: usize = 25;
const MIN_SAMPLE_NANOS: u128 = 2_000_000;

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

const fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("bench field numbers are static")
}

/// Mixed-field message of at least `target_len` bytes: varints,
/// I32s, small LEN payloads, and an occasional nested message —
/// the field-dense shape where per-record overhead dominates.
fn build_mixed(target_len: usize) -> Vec<u8> {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut b = Builder::new();
    let mut approx = 0usize;
    let mut i = 0u64;
    while approx < target_len {
        b.push_varint(f(1), rng.next());
        approx += 10;
        if i.is_multiple_of(3) {
            b.push_i32(f(2), rng.next() as u32);
            approx += 5;
        }
        if i.is_multiple_of(2) {
            let len = 16 + (rng.next() % 48) as usize;
            b.push_len_copy(f(3), &vec![0xA5u8; len]);
            approx += len + 2;
        }
        if i.is_multiple_of(8) {
            b.message(f(4), |m| {
                m.push_varint(f(1), 42);
                m.push_string(f(2), "nested");
            });
            approx += 12;
        }
        i += 1;
    }
    b.finish().expect("bench input under cap")
}

/// The mixed message with groups in place of nested messages — the
/// conversion corpus: every eighth record is a group wrapping the
/// nested pair.
fn build_grouped_mixed(target_len: usize) -> Vec<u8> {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut b = Builder::new();
    let mut approx = 0usize;
    let mut i = 0u64;
    while approx < target_len {
        b.push_varint(f(1), rng.next());
        approx += 10;
        if i.is_multiple_of(3) {
            b.push_i32(f(2), rng.next() as u32);
            approx += 5;
        }
        if i.is_multiple_of(2) {
            let len = 16 + (rng.next() % 48) as usize;
            b.push_len_copy(f(3), &vec![0xA5u8; len]);
            approx += len + 2;
        }
        if i.is_multiple_of(8) {
            b.group(f(4), |m| {
                m.push_varint(f(1), 42);
                m.push_string(f(2), "nested");
            });
            approx += 12;
        }
        i += 1;
    }
    b.finish().expect("bench input under cap")
}

/// The mixed message with an extra nested layer under every eighth
/// record: the designation corpus — f16 targets under crossed f4
/// containers, so a grouped-out conversion re-frames each f16 and
/// re-settles its crossing's prefix.
fn build_designated_mixed(target_len: usize) -> Vec<u8> {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut b = Builder::new();
    let mut approx = 0usize;
    let mut i = 0u64;
    while approx < target_len {
        b.push_varint(f(1), rng.next());
        approx += 10;
        if i.is_multiple_of(3) {
            b.push_i32(f(2), rng.next() as u32);
            approx += 5;
        }
        if i.is_multiple_of(2) {
            let len = 16 + (rng.next() % 48) as usize;
            b.push_len_copy(f(3), &vec![0xA5u8; len]);
            approx += len + 2;
        }
        if i.is_multiple_of(8) {
            b.message(f(4), |m| {
                m.push_varint(f(1), 42);
                m.message(f(16), |mm| {
                    mm.push_varint(f(1), 7);
                });
            });
            approx += 16;
        }
        i += 1;
    }
    b.finish().expect("bench input under cap")
}

/// Few large fields (~4 KiB each): the control input where
/// per-record overhead vanishes and every model approaches memcpy.
fn build_chunky(target_len: usize) -> Vec<u8> {
    let mut b = Builder::new();
    let payload = vec![0x5Au8; 4096];
    let mut approx = 0usize;
    while approx < target_len {
        b.push_len(f(3), &payload);
        approx += 4096 + 3;
    }
    b.finish().expect("bench input under cap")
}

/// Flat one-byte varints (a tag byte and one payload byte per
/// record): the parse-dense shape where nearly every byte decides
/// a word.
fn build_varint_flat(target_len: usize) -> Vec<u8> {
    let mut rng = Rng(0x51ED_2701_A3B5_C897);
    let mut b = Builder::new();
    let mut approx = 0usize;
    while approx < target_len {
        b.push_varint(f(1), rng.next() % 128);
        approx += 2;
    }
    b.finish().expect("bench input under cap")
}

/// The flat corpus re-spelled with every value continuation-padded
/// by one byte: lawful tolerant input whose value widths are all
/// non-minimal.
fn build_varint_padded(target_len: usize) -> Vec<u8> {
    let mut rng = Rng(0x51ED_2701_A3B5_C897);
    let mut out = Vec::with_capacity(target_len + 3);
    while out.len() < target_len {
        out.push(0x08);
        out.push((rng.next() % 128) as u8 | 0x80);
        out.push(0x00);
    }
    out
}

/// Fixed-width records only (alternating I32/I64): extents are
/// proven arithmetically, so no payload byte decides anything.
fn build_fixed_dense(target_len: usize) -> Vec<u8> {
    let mut rng = Rng(0xB5F0_92C4_11D7_663E);
    let mut b = Builder::new();
    let mut approx = 0usize;
    while approx < target_len {
        b.push_i32(f(2), rng.next() as u32);
        b.push_i64(f(6), rng.next());
        approx += 14;
    }
    b.finish().expect("bench input under cap")
}

/// Shallow-wide groups: every record one top-level group wrapping a
/// scalar pair.
fn build_groups_wide(target_len: usize) -> Vec<u8> {
    let mut rng = Rng(0x7A3D_5E91_04C6_28BF);
    let mut b = Builder::new();
    let mut approx = 0usize;
    while approx < target_len {
        b.group(f(4), |g| {
            g.push_varint(f(1), rng.next() >> (rng.next() % 60));
            g.push_i32(f(2), rng.next() as u32);
        });
        approx += 12;
    }
    b.finish().expect("bench input under cap")
}

/// Depth-heavy groups: sibling chains of groups nested 16 deep, one
/// varint per level.
fn build_groups_deep(target_len: usize) -> Vec<u8> {
    fn nest(g: &mut protobuf_edit::construct::grouped::BodyBuilder<'_, '_>, depth: u32) {
        g.push_varint(f(1), 5);
        if depth > 1 {
            g.group(f(4), |inner| nest(inner, depth - 1));
        }
    }
    let mut b = Builder::new();
    let mut approx = 0usize;
    while approx < target_len {
        b.group(f(4), |g| nest(g, 16));
        approx += 16 * 4 + 2;
    }
    b.finish().expect("bench input under cap")
}

/// Nested LEN chains 16 deep with a varint per level: the shape
/// whose committed descent materializes a long advisor path.
fn build_len_deep(target_len: usize) -> Vec<u8> {
    fn nest(m: &mut protobuf_edit::construct::grouped::BodyBuilder<'_, '_>, depth: u32) {
        m.push_varint(f(2), 5);
        if depth > 1 {
            m.message(f(4), |inner| nest(inner, depth - 1));
        }
    }
    let mut b = Builder::new();
    let mut approx = 0usize;
    while approx < target_len {
        b.message(f(4), |m| nest(m, 16));
        approx += 16 * 5 + 2;
    }
    b.finish().expect("bench input under cap")
}

// ─── named row bodies ───
//
// Each session-complexity row body lives in its own never-inlined
// function so an instruction-count profiler can anchor collection on
// the row's symbol; the harness closures stay thin calls.

#[inline(never)]
fn row_session_save_one_edit(s: &Session) -> protobuf_edit::session::DocBytes {
    s.save().unwrap()
}

#[inline(never)]
fn row_session_set_varint_x64(s: &mut Session, targets: &[protobuf_edit::session::Handle]) {
    for _ in 0..16 {
        for &t in targets {
            s.set_varint(t, 7).unwrap();
        }
    }
    black_box(s.pending());
}

#[inline(never)]
fn row_session_tail_append_x256(small: &[u8]) -> usize {
    let mut s = Session::open_copy(small).unwrap();
    for i in 0..256u64 {
        s.insert_varint(InsertAt::TailOf(None), f(5), i).unwrap();
    }
    s.pending()
}

#[inline(never)]
fn row_session_save_len_dirty(s: &Session) -> u32 {
    s.save_len().unwrap()
}

#[inline(never)]
fn row_borrow_session_set_x64_save(
    s: &mut protobuf_edit::session::grouped::BorrowSession<'static>,
    targets: &[protobuf_edit::session::Handle],
    payload: &'static [u8],
    out: &mut Vec<u8>,
) {
    for &t in targets {
        s.set_payload(t, payload).unwrap();
    }
    out.clear();
    s.save_into(out).unwrap();
}

#[inline(never)]
fn row_borrow_session_save_dirty(
    s: &protobuf_edit::session::grouped::BorrowSession<'static>,
    out: &mut Vec<u8>,
) {
    out.clear();
    s.save_into(out).unwrap();
}

#[cfg(feature = "priced-session-grouped")]
#[inline(never)]
fn row_priced_save_one_edit(
    p: &protobuf_edit::session::grouped::PricedSession,
) -> protobuf_edit::session::DocBytes {
    p.save().unwrap()
}

#[cfg(feature = "priced-session-grouped")]
#[inline(never)]
fn row_priced_save_len_dirty_10k(p: &protobuf_edit::session::grouped::PricedSession) -> u32 {
    black_box(10u32);
    p.save_len().unwrap()
}

#[cfg(feature = "priced-session-grouped")]
#[inline(never)]
fn row_priced_save_len_dirty_100k(p: &protobuf_edit::session::grouped::PricedSession) -> u32 {
    black_box(100u32);
    p.save_len().unwrap()
}

/// The transfer profile's O(1) save-price pair: the claim is
/// flatness across the two document sizes, mirroring the plain
/// priced rows above.
#[cfg(feature = "priced-transfer-session-grouped")]
#[inline(never)]
fn row_priced_transfer_save_len_dirty_10k(
    p: &protobuf_edit::session::grouped::PricedTransferSession,
) {
    black_box(10u32);
    black_box(p.save_len().unwrap());
}

#[cfg(feature = "priced-transfer-session-grouped")]
#[inline(never)]
fn row_priced_transfer_save_len_dirty_100k(
    p: &protobuf_edit::session::grouped::PricedTransferSession,
) {
    black_box(100u32);
    black_box(p.save_len().unwrap());
}

/// 64 sets alternating a one-byte and a two-byte word, so every set
/// carries a nonzero delta through the whole ancestor chain. The
/// black-boxed depth constant keeps the otherwise-identical twins
/// from merging into one symbol — the grid rows must stay separately
/// attributable to an instruction-count profiler.
macro_rules! priced_set_row {
    ($($name:ident, $depth:literal;)*) => {$(
        #[cfg(feature = "priced-session-grouped")]
        #[inline(never)]
        fn $name(
            p: &mut protobuf_edit::session::grouped::PricedSession,
            t: protobuf_edit::session::Handle,
        ) {
            black_box($depth);
            for _ in 0..32 {
                p.set_varint(t, 300).unwrap();
                p.set_varint(t, 7).unwrap();
            }
            black_box(p.pending());
        }
    )*};
}

priced_set_row! {
    row_priced_set_varint_x64_deep0, 0u32;
    row_priced_set_varint_x64_deep8, 8u32;
    row_priced_set_varint_x64_deep16, 16u32;
}

#[cfg(feature = "priced-session-grouped")]
#[inline(never)]
fn row_priced_revert_x64_deep16(
    p: &mut protobuf_edit::session::grouped::PricedSession,
    t: protobuf_edit::session::Handle,
) {
    for _ in 0..32 {
        p.set_varint(t, 300).unwrap();
        p.set_varint(t, 7).unwrap();
    }
    for _ in 0..64 {
        black_box(p.revert());
    }
}

#[cfg(feature = "priced-session-grouped")]
#[inline(never)]
fn row_priced_into_priced_dirty_100k(s: Session) -> Session {
    s.into_priced().map_err(|(_, fault)| fault).expect("bench machine admits").into_session()
}

/// The zero-delta rows: fixed-width sets delegate straight to the
/// base commit and an equal-width varint re-set short-circuits
/// before the ledger, so every set below is a real edit that moves
/// no price — none of the bodies should carry the settle climb the
/// two-width grid rows pay per level.
#[cfg(feature = "priced-session-grouped")]
#[inline(never)]
fn row_priced_set_i32_x64_deep16(
    p: &mut protobuf_edit::session::grouped::PricedSession,
    t: protobuf_edit::session::Handle,
) {
    for _ in 0..32 {
        p.set_i32(t, 0x7FFF_FFFF).unwrap();
        p.set_i32(t, 7).unwrap();
    }
    black_box(p.pending());
}

#[cfg(feature = "priced-session-grouped")]
#[inline(never)]
fn row_priced_set_i64_x64_deep16(
    p: &mut protobuf_edit::session::grouped::PricedSession,
    t: protobuf_edit::session::Handle,
) {
    for _ in 0..32 {
        p.set_i64(t, u64::MAX).unwrap();
        p.set_i64(t, 7).unwrap();
    }
    black_box(p.pending());
}

#[cfg(feature = "priced-session-grouped")]
#[inline(never)]
fn row_priced_set_varint_x64_equal_deep16(
    p: &mut protobuf_edit::session::grouped::PricedSession,
    t: protobuf_edit::session::Handle,
) {
    for _ in 0..32 {
        p.set_varint(t, 8).unwrap();
        p.set_varint(t, 7).unwrap();
    }
    black_box(p.pending());
}

/// The in-place rows: one never-inlined body per line, each
/// black-boxing a distinguishing constant so otherwise-identical
/// twins stay separately attributable to an instruction-count
/// profiler. Scripts are idempotent by construction (identity
/// renumbers, zero values into met slots, equal payloads), so
/// every iteration performs the same walk and the same writes over
/// the same geometry.
#[cfg(all(feature = "inplace-grouped", feature = "inplace-groupless"))]
mod inplace_rows {
    use std::hint::black_box;

    use protobuf_edit::DepthLimit;
    use protobuf_edit::inplace::{RuleSet, Stats};

    #[inline(never)]
    pub fn row_inplace_walk_clean_10k(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(10u32);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_walk_clean_100k(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(100u32);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_apply_sparse_100k(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(4u32);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_apply_dense_100k(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(u32::MAX);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_apply_payload_1m(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(1u32);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_apply_payload_1k(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(2u32);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_apply_deep9(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(9u32);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_apply_deep12(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(12u32);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_apply_deep15(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(15u32);
        protobuf_edit::inplace::groupless::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    /// The canonical twin of the clean walk: the same keep-only rule
    /// set judged under the minimal-width standard, so the
    /// per-construct minimality judgment is the row's whole delta.
    #[inline(never)]
    pub fn row_inplace_walk_canonical_100k(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        black_box(0xCAu32);
        protobuf_edit::inplace::groupless::apply_standard(
            buf,
            set,
            protobuf_edit::Standard::CanonicalMinimal,
            DepthLimit::REFERENCE,
        )
        .expect("bench input is lawful")
    }

    #[inline(never)]
    pub fn row_inplace_grouped_renumber_100k(buf: &mut [u8], set: &RuleSet<'_>) -> Stats {
        protobuf_edit::inplace::grouped::apply(buf, set, DepthLimit::REFERENCE)
            .expect("bench input is lawful")
    }

    /// The direct equal-size copy the 1 MiB payload overwrite is
    /// banded against.
    #[inline(never)]
    pub const fn row_memcpy_1m(dst: &mut [u8], src: &[u8]) {
        dst.copy_from_slice(src);
    }

    /// The zero-match rewrite twin: the same matcher shape over the
    /// same bytes, plus the second (emit) pass and the output
    /// buffer — the composition arc `walk_clean` is banded against.
    #[cfg(feature = "rewrite-groupless")]
    #[inline(never)]
    pub fn row_rewrite_zero_match_100k(
        doc: &[u8],
        set: &protobuf_edit::rewrite::RuleSet<'_>,
        out: &mut Vec<u8>,
    ) {
        out.clear();
        black_box(
            protobuf_edit::rewrite::groupless::rewrite_into(doc, set, DepthLimit::REFERENCE, out)
                .expect("bench input is lawful"),
        );
    }

    /// The composition the sparse row beats: patch open, the same
    /// four edits, save into a reused buffer, copy back into the
    /// source allocation.
    #[cfg(feature = "patch-groupless")]
    #[inline(never)]
    pub fn row_patch_copyback_sparse_100k(src: &mut [u8], out: &mut Vec<u8>) {
        use protobuf_edit::patch::groupless::Patch;
        use protobuf_edit::wire::groupless::RecordKind;
        let mut patch = Patch::open(src, DepthLimit::REFERENCE).expect("bench input is lawful");
        let targets: Vec<_> = patch
            .top()
            .filter(|&handle| {
                patch.field(handle).as_inner() == 60
                    && matches!(patch.kind(handle), RecordKind::Varint)
            })
            .collect();
        for handle in targets {
            patch.set_varint(handle, 0).expect("the slot holds zero");
        }
        out.clear();
        patch.save_into(out).expect("bench output stays in class");
        src.copy_from_slice(out);
    }
}

/// Runs `func` in timed batches and reports the median batch cost,
/// returning the median ns/iter for derived per-record lines.
///
/// `BENCH_IR` (comma-separated substring filters) switches the
/// harness into its fixed-iteration profiler shape: matching lines
/// run exactly `BENCH_IR_ITERS` times (default 10) with no timing
/// loop and everything else is skipped, so one full-collection
/// callgrind pass attributes equal-call-count Ir to every selected
/// row symbol at once. Wall clock is not printed in that shape —
/// it would judge nothing.
fn bench(name: &str, input_len: usize, mut func: impl FnMut()) -> f64 {
    if let Ok(filter) = std::env::var("BENCH_IR") {
        if !filter.split(',').any(|needle| name.contains(needle)) {
            return 0.0;
        }
        let iters: u32 =
            std::env::var("BENCH_IR_ITERS").ok().and_then(|raw| raw.parse().ok()).unwrap_or(10);
        for _ in 0..iters {
            func();
        }
        println!("{name:<36} {iters} fixed iterations (BENCH_IR)");
        return 0.0;
    }
    let mut iters = 1u32;
    loop {
        let t = Instant::now();
        for _ in 0..iters {
            func();
        }
        if t.elapsed().as_nanos() >= MIN_SAMPLE_NANOS || iters >= 1 << 20 {
            break;
        }
        iters *= 2;
    }

    let mut samples = [0u128; SAMPLES];
    for slot in &mut samples {
        let t = Instant::now();
        for _ in 0..iters {
            func();
        }
        *slot = t.elapsed().as_nanos();
    }
    samples.sort_unstable();
    let median = samples[SAMPLES / 2];
    let ns_per_iter = median as f64 / f64::from(iters);
    let mib_per_s = if input_len == 0 {
        0.0
    } else {
        input_len as f64 / (ns_per_iter / 1e9) / (1024.0 * 1024.0)
    };
    println!("{name:<36} {ns_per_iter:>12.1} ns/iter {mib_per_s:>10.1} MiB/s");
    ns_per_iter
}

/// Borrowed single-pass walk with nested descent — the old core's
/// `cursor_walk` counterpart (~1.0 GiB/s reference).
fn traverse_walk(data: &[u8]) -> u64 {
    use protobuf_edit::traverse::grouped::{Cursor, EntryKind};
    fn walk(data: &[u8], acc: &mut u64) {
        let cursor = Cursor::over(data, GroupDepth::REFERENCE).expect("bench input admitted");
        for entry in cursor {
            let entry = entry.expect("bench input is lawful");
            match entry.kind() {
                EntryKind::Varint(v) => *acc = acc.wrapping_add(v),
                EntryKind::Len(payload) if entry.field() == f(4) => walk(payload, acc),
                _ => {}
            }
        }
    }
    let mut acc = 0;
    walk(data, &mut acc);
    acc
}

/// Counts delivered records (all layers) — the per-record
/// denominator, printed so nobody hand-derives it.
fn traverse_count(data: &[u8]) -> u64 {
    use protobuf_edit::traverse::grouped::{Cursor, EntryKind};
    fn walk(data: &[u8], n: &mut u64) {
        let cursor = Cursor::over(data, GroupDepth::REFERENCE).expect("bench input admitted");
        for entry in cursor {
            let entry = entry.expect("bench input is lawful");
            *n += 1;
            if let EntryKind::Len(payload) = entry.kind()
                && entry.field() == f(4)
            {
                walk(payload, n);
            }
        }
    }
    let mut n = 0;
    walk(data, &mut n);
    n
}

fn varint_kernel(data: &[u8]) -> u64 {
    let mut acc = 0u64;
    let mut at = 0usize;
    while at < data.len() {
        let (value, width) = slice::value64(data, at, data.len()).expect("dense varints");
        acc = acc.wrapping_add(value);
        at += width as usize;
    }
    acc
}

/// One-pass extraction: every LEN payload is disposed
/// `OpaqueBytes`, so fragments ride the delivery arm (the
/// validator's differential twin — same wire law, plus the
/// counted forwarding path and the segment events).
fn scan_extract(data: &[u8]) -> u64 {
    use core::ops::ControlFlow;
    use protobuf_edit::PayloadLen;
    use protobuf_edit::scan::LenDisposition;
    use protobuf_edit::scan::grouped::{Parser, Sink};

    struct Extract(u64);
    impl Sink for Extract {
        fn on_len(
            &mut self,
            _field: FieldNumber,
            _len: PayloadLen,
            _at: u64,
        ) -> ControlFlow<(), LenDisposition> {
            ControlFlow::Continue(LenDisposition::OpaqueBytes)
        }
        fn on_segment(&mut self, bytes: &[u8]) -> ControlFlow<()> {
            self.0 = self.0.wrapping_add(bytes.len() as u64);
            ControlFlow::Continue(())
        }
    }

    let mut sink = Extract(0);
    let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
    let flow = parser.feed(data, &mut sink).expect("bench input is lawful");
    assert!(matches!(flow, protobuf_edit::scan::Flow::More), "the extract sink never stops");
    parser.finish().expect("bench input is lawful");
    sink.0
}

fn main() {
    let small = build_mixed(10 * 1024);
    let large = build_mixed(100 * 1024);
    let chunky = build_chunky(100 * 1024);
    println!(
        "input sizes: small={} bytes, large={} bytes, chunky={} bytes",
        small.len(),
        large.len(),
        chunky.len()
    );

    // Dense varint stream for the kernel baseline (SWAR ledger item).
    let dense: Vec<u8> = {
        let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
        let mut out = Vec::new();
        for _ in 0..16384 {
            protobuf_edit::varint::push64(&mut out, rng.next() >> (rng.next() % 60));
        }
        out
    };
    bench("varint_kernel_dense_16k", dense.len(), || {
        black_box(varint_kernel(black_box(&dense)));
    });

    for (label, data) in [("10k", &small), ("100k", &large)] {
        let ns = bench(&format!("traverse_walk_{label}"), data.len(), || {
            black_box(traverse_walk(black_box(data)));
        });
        let records = traverse_count(data);
        println!(
            "  traverse_walk_{label}/record        {:>10.1} ns ({records} records)",
            ns / records as f64
        );
        bench(&format!("inspect_parse_{label}"), data.len(), || {
            use protobuf_edit::inspect::grouped::Tree;
            let admitted = Admitted::new(black_box(data)).unwrap();
            black_box(Tree::parse(admitted, DepthLimit::REFERENCE, &mut NoAdvice));
        });
        bench(&format!("session_open_{label}"), data.len(), || {
            black_box(Session::open_copy(black_box(data)).unwrap());
        });
        bench(&format!("scan_validate_{label}"), data.len(), || {
            use protobuf_edit::scan::grouped::Validator;
            let mut v = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
            v.feed(black_box(data)).unwrap();
            v.finish().unwrap();
        });
        // The same verdict fed 4 KiB at a time: chunk boundaries cut
        // constructs, so the carry/resume path — the machine's whole
        // reason to exist — is on the clock, not just the one-chunk
        // sprint.
        bench(&format!("scan_validate_chunked_{label}"), data.len(), || {
            use protobuf_edit::scan::grouped::Validator;
            let mut v = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
            for chunk in black_box(&data[..]).chunks(4096) {
                v.feed(chunk).unwrap();
            }
            v.finish().unwrap();
        });
        bench(&format!("scan_extract_{label}"), data.len(), || {
            black_box(scan_extract(black_box(data)));
        });
    }

    // The scan family's dialect twin, one line: the mixed input
    // carries no groups, so both dialects read the same wire and
    // the line prices the groupless machine itself (the grouped
    // lines above stand as the module-family representative, not
    // as a dialect-cell projection).
    bench("scan_validate_groupless_100k", large.len(), || {
        use protobuf_edit::scan::groupless::Validator;
        let mut v = Validator::new(Standard::Tolerant);
        v.feed(black_box(&large)).unwrap();
        v.finish().unwrap();
    });

    // A custom all-default sink through the generic parser face:
    // behaviorally the validator's twin (every LEN skipped, no
    // events), so the difference against scan_validate is the
    // named price of sink-generic dispatch at zero delivery.
    bench("scan_skip_all_100k", large.len(), || {
        use protobuf_edit::scan::Flow;
        use protobuf_edit::scan::grouped::{Parser, Sink};
        struct SkipAll;
        impl Sink for SkipAll {}
        let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let flow = parser.feed(black_box(&large), &mut SkipAll).unwrap();
        assert!(matches!(flow, Flow::More), "the skip-all sink never stops");
        parser.finish().unwrap();
    });

    // Mixed-disposition lines: a sink that takes a deterministic
    // fraction of the LEN payloads (by field number) and skips the
    // rest — the selection-program shape real extractors have.
    // They run over their own input whose LEN fields cycle through
    // ten balanced buckets (the shared corpus carries LENs on two
    // fields only, which would degenerate a percent selector to
    // the poles), and each line asserts its realized take ratio
    // outside the timed body — the named percentage is a measured
    // fact, not a label.
    {
        use protobuf_edit::scan::grouped::{Parser, Sink};
        use protobuf_edit::scan::{Flow, LenDisposition};
        use protobuf_edit::{FieldNumber, PayloadLen};

        // Varint-interleaved LEN records on fields 11..=20: the
        // `% 10` residues run 1..=9 and 0, one field per bucket.
        let buckets = {
            let mut rng = Rng(0x5851_F42D_4C95_7F2D);
            let mut b = Builder::new();
            let mut approx = 0usize;
            while approx < 100 * 1024 {
                // Whole ten-bucket rounds keep every realized take
                // ratio exactly at its named percentage.
                for k in 0..10u32 {
                    b.push_varint(f(1), rng.next() >> (rng.next() % 60));
                    let len = 8 + (rng.next() % 24) as usize;
                    b.push_len_copy(f(11 + k), &vec![0x5Au8; len]);
                    approx += len + 6;
                }
            }
            b.finish().expect("bench input under cap")
        };

        struct Mixed<const PERCENT: u32> {
            bytes: u64,
            seen: u32,
            taken: u32,
        }
        impl<const PERCENT: u32> Sink for Mixed<PERCENT> {
            fn on_len(
                &mut self,
                field: FieldNumber,
                _: PayloadLen,
                _: u64,
            ) -> core::ops::ControlFlow<(), LenDisposition> {
                self.seen += 1;
                core::ops::ControlFlow::Continue(if field.as_inner() % 10 < PERCENT / 10 {
                    self.taken += 1;
                    LenDisposition::OpaqueBytes
                } else {
                    LenDisposition::OpaqueSkip
                })
            }
            fn on_segment(&mut self, bytes: &[u8]) -> core::ops::ControlFlow<()> {
                #[allow(clippy::as_conversions, reason = "segment lengths fit u64")]
                {
                    self.bytes = self.bytes.wrapping_add(bytes.len() as u64);
                }
                core::ops::ControlFlow::Continue(())
            }
        }
        fn line<const PERCENT: u32>(name: &'static str, input: &[u8]) {
            // The realized ratio is the line's contract: judged
            // once, outside the timed body.
            let mut probe = Mixed::<PERCENT> { bytes: 0, seen: 0, taken: 0 };
            let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
            let _flow = parser.feed(input, &mut probe).unwrap();
            let realized = probe.taken * 100 / probe.seen;
            assert!(
                realized == PERCENT,
                "{name}: realized take ratio {realized}% (took {} of {}), wanted {PERCENT}%",
                probe.taken,
                probe.seen,
            );
            bench(name, input.len(), || {
                let mut sink = Mixed::<PERCENT> { bytes: 0, seen: 0, taken: 0 };
                let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
                let flow = parser.feed(black_box(input), &mut sink).unwrap();
                assert!(matches!(flow, Flow::More), "the mixed sink never stops");
                parser.finish().unwrap();
                black_box(sink.bytes);
            });
        }
        // The poles ride the same input and the same selector shape
        // (0% and 100% are just the constant ends of the same
        // predicate), and the sink-free validator anchors the
        // no-dispatch floor — five points and a floor, one
        // workload.
        {
            use protobuf_edit::scan::grouped::Validator;
            bench("scan_buckets_validate_100k", buckets.len(), || {
                let mut v = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
                v.feed(black_box(&buckets)).unwrap();
                v.finish().unwrap();
            });
        }
        line::<0>("scan_mixed_0_100k", &buckets);
        line::<10>("scan_mixed_10_100k", &buckets);
        line::<50>("scan_mixed_50_100k", &buckets);
        line::<90>("scan_mixed_90_100k", &buckets);
        line::<100>("scan_mixed_100_100k", &buckets);
    }

    // One-edit save over the field-dense input (old core: ~4.9 GiB/s).
    {
        let mut s = Session::open_copy(&large).unwrap();
        let t0 = s.top().next().unwrap();
        s.set_varint(t0, 1).unwrap();
        bench("session_save_one_edit_100k", large.len(), || {
            black_box(row_session_save_one_edit(&s));
        });

        // The portable twin: the caller's buffer persists across
        // iters, so the fresh-Vec allocation in `save` drops out
        // and the walk-plus-copy cost is what remains.
        let mut out = Vec::with_capacity(large.len() + 16);
        bench("session_save_into_100k", large.len(), || {
            out.clear();
            s.save_into(&mut out).unwrap();
            black_box(out.len());
        });
    }

    // Chunky control (old core: both models converge on memcpy).
    {
        let mut s = Session::open_copy(&chunky).unwrap();
        let t0 = s.top().next().unwrap();
        s.set_payload(t0, b"edited").unwrap();
        bench("session_save_one_edit_chunky", chunky.len(), || {
            black_box(s.save().unwrap());
        });
    }

    // The borrowed-payload session profiles: installs append borrow
    // slots and every save copies the installed bytes into the owned
    // product. The set-heavy body prices 64 installs against one
    // save; the save-heavy body prices the recurring per-save copy
    // over a standing 64-install machine (the setup installs keep
    // both rows independent of run order). Equal-length payloads
    // hold the tree geometry fixed across iterations.
    {
        use protobuf_edit::session::grouped::BorrowSession;
        use protobuf_edit::wire::grouped::RecordKind;
        static PAYLOAD: [u8; 32] = [0x6B; 32];
        let mut s: BorrowSession<'static> = BorrowSession::open_copy(&large).unwrap();
        let targets: Vec<_> =
            s.top().filter(|&h| matches!(s.kind(h), Ok(RecordKind::Len))).take(64).collect();
        assert_eq!(targets.len(), 64, "the corpus carries 64 top-level LEN targets");
        for &t in &targets {
            s.set_payload(t, &PAYLOAD).unwrap();
        }
        let mut out = Vec::with_capacity(large.len() + 64);
        bench("borrow_session_set_x64_save_100k", large.len(), || {
            row_borrow_session_set_x64_save(&mut s, &targets, &PAYLOAD, &mut out);
            black_box(out.len());
        });
        bench("borrow_session_save_dirty_100k", large.len(), || {
            row_borrow_session_save_dirty(&s, &mut out);
            black_box(out.len());
        });
    }

    // The one-shot patch, same table as the session lines: the
    // borrowed open (zero copy) and the one-edit fidelity save.
    {
        use protobuf_edit::patch::grouped::Patch;
        bench("patch_open_100k", large.len(), || {
            black_box(Patch::open(black_box(&large), DepthLimit::REFERENCE).unwrap());
        });
        let mut p = Patch::open(&large, DepthLimit::REFERENCE).unwrap();
        let t0 = p.top().next().unwrap();
        p.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("patch_edit_save_100k", large.len(), || {
            out.clear();
            p.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });

        // The sink twin of the line above, collected into the same
        // buffer so both sides pay the copy: the delta is the
        // portable face's pre-flight pricing walk (the fused save
        // sizes as it emits; a sink cannot be truncated, so
        // `save_sink` prices everything first) plus per-run closure
        // dispatch.
        bench("patch_save_sink_100k", large.len(), || {
            out.clear();
            p.save_sink(|run| out.extend_from_slice(run)).unwrap();
            black_box(out.len());
        });

        // The edit latch and the per-row dirty witness: a clean
        // save is one copy of the source, and an edit amid opened
        // containers leaves the untouched ones on their walkless
        // verbatim arm.
        let pc = Patch::open(&large, DepthLimit::REFERENCE).unwrap();
        let mut out = Vec::new();
        bench("patch_save_clean_100k", large.len(), || {
            out.clear();
            pc.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
        let mut pd = Patch::open(&large, DepthLimit::REFERENCE).unwrap();
        let opened: Vec<_> = pd.top().collect();
        for h in opened {
            use protobuf_edit::wire::grouped::RecordKind;
            if matches!(pd.kind(h), RecordKind::Len) {
                let _ = pd.descend(h);
            }
        }
        let t0 = pd.top().next().unwrap();
        pd.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("patch_edit_save_descended_100k", large.len(), || {
            out.clear();
            pd.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });

        // The payload channel pair: replace one LEN with a 1 MiB
        // payload and save. The borrowed face pays one copy (at
        // save); the staging twin pays two (command, then save) —
        // the gap is the copy the borrow elides.
        let doc = [0x12, 0x02, 0x68, 0x69, 0x08, 0x01];
        let payload = vec![0x7Eu8; 1 << 20];
        let mut out = Vec::with_capacity(payload.len() + 16);
        bench("patch_set_payload_borrowed_1m", payload.len(), || {
            let mut p = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
            let target = p.top().next().unwrap();
            p.set_payload(target, &payload).unwrap();
            out.clear();
            p.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
        bench("patch_set_payload_copy_1m", payload.len(), || {
            let mut p = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
            let target = p.top().next().unwrap();
            p.set_payload_copy(target, &payload).unwrap();
            out.clear();
            p.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // Adopt: the owned twin of the patch line — the same one-edit
    // save over a moved-in source. The family shares its machinery
    // at the source-holder boundary, so this line should shadow
    // patch_edit_save_100k.
    {
        use protobuf_edit::adopt::grouped::Adopt;
        let mut a = Adopt::open(large.clone(), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
        let t0 = a.top().next().unwrap();
        a.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("adopt_edit_save_100k", large.len(), || {
            out.clear();
            a.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // Overhaul: the replay-source sibling of the patch line — the
    // same corpus and the same one edit, addressed over a slice
    // source instead of a resident buffer, so the buffered
    // re-emission and the replay save walk sit on the same clock.
    {
        use protobuf_edit::overhaul::grouped::Overhaul;
        use protobuf_edit::replay_source::SliceSource;
        let mut o = Overhaul::open(SliceSource::new(&large), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
        let t0 = o.top().next().unwrap();
        o.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("overhaul_edit_save_100k", large.len(), || {
            out.clear();
            o.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // Maintain: the revisable replay sibling of the overhaul line
    // — the same corpus and the same one edit over a slice source,
    // so the commit-only and revisable replay save pipelines sit
    // on the same clock.
    {
        use protobuf_edit::maintain::grouped::Maintain;
        use protobuf_edit::replay_source::SliceSource;
        let mut m = Maintain::open(SliceSource::new(&large))
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
        let t0 = m.top().next().unwrap();
        m.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("maintain_grouped_edit_save_100k", large.len(), || {
            out.clear();
            m.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // The groupless maintain twin on the same corpus (group-free
    // by construction), so the dialect delta reads directly.
    {
        use protobuf_edit::maintain::groupless::Maintain;
        use protobuf_edit::replay_source::SliceSource;
        let mut m = Maintain::open(SliceSource::new(&large))
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
        let t0 = m.top().next().unwrap();
        m.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("maintain_groupless_edit_save_100k", large.len(), || {
            out.clear();
            m.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // Refit: the canonical replay sibling of the overhaul line —
    // the same corpus (minimal by construction, so both admission
    // standards accept it) and the same one edit over a slice
    // source, so the tolerant and canonical one-shot replay save
    // pipelines sit on the same clock.
    {
        use protobuf_edit::refit::grouped::Refit;
        use protobuf_edit::replay_source::SliceSource;
        let mut r = Refit::open(SliceSource::new(&large), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
        let t0 = r.top().next().unwrap();
        r.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("refit_grouped_edit_save_100k", large.len(), || {
            out.clear();
            r.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // The groupless refit twin on the same corpus (group-free by
    // construction), so the dialect delta reads directly.
    {
        use protobuf_edit::refit::groupless::Refit;
        use protobuf_edit::replay_source::SliceSource;
        let mut r = Refit::open(SliceSource::new(&large), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
        let t0 = r.top().next().unwrap();
        r.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("refit_groupless_edit_save_100k", large.len(), || {
            out.clear();
            r.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // Commission: the canonical revisable replay sibling — the
    // same corpus and the same one edit over a slice source, so
    // the tolerant and canonical revisable replay save pipelines
    // sit on the same clock.
    {
        use protobuf_edit::commission::grouped::Commission;
        use protobuf_edit::replay_source::SliceSource;
        let mut c = Commission::open(SliceSource::new(&large))
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
        let t0 = c.top().next().unwrap();
        c.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("commission_grouped_edit_save_100k", large.len(), || {
            out.clear();
            c.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // The groupless commission twin on the same corpus (group-free
    // by construction), so the dialect delta reads directly.
    {
        use protobuf_edit::commission::groupless::Commission;
        use protobuf_edit::replay_source::SliceSource;
        let mut c = Commission::open(SliceSource::new(&large))
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
        let t0 = c.top().next().unwrap();
        c.set_varint(t0, 1).unwrap();
        let mut out = Vec::new();
        bench("commission_groupless_edit_save_100k", large.len(), || {
            out.clear();
            c.save_into(black_box(&mut out)).unwrap();
            black_box(out.len());
        });
    }

    // Retain: the owned inspection product — parse and release in a
    // round trip, so the buffer is reused across iters and the line
    // prices the parse alone (queries are O(1) table reads).
    {
        use protobuf_edit::retain::grouped::Retained;
        use protobuf_edit::retain::NoAdvice as RetainNoAdvice;
        let mut buf = large.clone();
        bench("retain_parse_100k", large.len(), || {
            let r = Retained::parse(
                core::mem::take(&mut buf),
                DepthLimit::REFERENCE,
                &mut RetainNoAdvice,
            )
            .map_err(|(_, fault)| fault)
            .expect("bench input admits");
            black_box(r.bytes().len());
            buf = r.into_bytes();
        });
    }

    // Collect: the stream twin of retain, against buffering first
    // and parsing once. Every pair runs the same corpus, standard,
    // advice, and chunking with a presized source on both sides, so
    // the pair's delta is the buffered pipeline's second read. The
    // flat ladder varies feed size alone; the padded/canonical pair
    // prices the width judgment; the fault rows price the rollback,
    // deferral, and fault-tail copy shapes a success-only row
    // misses; the grown and deep-advice rows price geometric source
    // growth and the materialized advisor path. Each fault corpus
    // seals once outside the timed body and its product shape is
    // the row's judged contract.
    {
        use protobuf_edit::collect::NoAdvice as CollectNoAdvice;
        use protobuf_edit::collect::{Advice, Advisor, Ancestry};
        use protobuf_edit::retain::NoAdvice as RetainNoAdvice;
        use protobuf_edit::varint::push64;

        /// Commits every LEN payload (lawful over corpora whose LEN
        /// records are all real messages).
        struct CollectCommit;
        impl Advisor for CollectCommit {
            fn advise(&mut self, _: Ancestry<'_>, _: FieldNumber) -> Advice {
                Advice::Commit
            }
        }
        /// Never parses a LEN payload.
        struct CollectOpaque;
        impl Advisor for CollectOpaque {
            fn advise(&mut self, _: Ancestry<'_>, _: FieldNumber) -> Advice {
                Advice::Opaque
            }
        }
        /// The mixed corpus's schema: field 4 carries real nested
        /// messages, every other LEN is opaque payload.
        struct CollectSchema;
        impl Advisor for CollectSchema {
            fn advise(&mut self, _: Ancestry<'_>, field: FieldNumber) -> Advice {
                if field.as_inner() == 4 { Advice::Commit } else { Advice::Opaque }
            }
        }
        struct RetainOpaque;
        impl protobuf_edit::retain::Advisor for RetainOpaque {
            fn advise(
                &mut self,
                _: protobuf_edit::retain::Ancestry<'_>,
                _: FieldNumber,
            ) -> protobuf_edit::retain::Advice {
                protobuf_edit::retain::Advice::Opaque
            }
        }
        struct RetainSchema;
        impl protobuf_edit::retain::Advisor for RetainSchema {
            fn advise(
                &mut self,
                _: protobuf_edit::retain::Ancestry<'_>,
                field: FieldNumber,
            ) -> protobuf_edit::retain::Advice {
                if field.as_inner() == 4 {
                    protobuf_edit::retain::Advice::Commit
                } else {
                    protobuf_edit::retain::Advice::Opaque
                }
            }
        }

        /// One sealed groupless product over `corpus` fed in
        /// `feed`-byte chunks.
        fn seal_gl<A: Advisor>(
            corpus: &[u8],
            feed: usize,
            standard: Standard,
            advice: &mut A,
            presized: bool,
        ) -> protobuf_edit::collect::groupless::Retained {
            use protobuf_edit::collect::groupless::Collector;
            let mut collector = if presized {
                Collector::with_capacity(standard, DepthLimit::REFERENCE, advice, corpus.len())
                    .expect("bench capacity admits")
            } else {
                Collector::new(standard, DepthLimit::REFERENCE, advice)
            };
            for chunk in corpus.chunks(feed) {
                collector.feed(chunk).expect("bench chunks admit");
            }
            collector.finish()
        }

        /// The grouped twin of [`seal_gl`].
        fn seal_gr<A: Advisor>(
            corpus: &[u8],
            feed: usize,
            standard: Standard,
            advice: &mut A,
            presized: bool,
        ) -> protobuf_edit::collect::grouped::Retained {
            use protobuf_edit::collect::grouped::Collector;
            let mut collector = if presized {
                Collector::with_capacity(standard, DepthLimit::REFERENCE, advice, corpus.len())
                    .expect("bench capacity admits")
            } else {
                Collector::new(standard, DepthLimit::REFERENCE, advice)
            };
            for chunk in corpus.chunks(feed) {
                collector.feed(chunk).expect("bench chunks admit");
            }
            collector.finish()
        }

        /// The buffered pipeline: extend a presized Vec chunk by
        /// chunk, then parse it once.
        fn buffered_gl<A: protobuf_edit::retain::Advisor>(
            corpus: &[u8],
            feed: usize,
            standard: Standard,
            advice: &mut A,
        ) -> protobuf_edit::retain::groupless::Retained {
            let mut owned = Vec::with_capacity(corpus.len());
            for chunk in corpus.chunks(feed) {
                owned.extend_from_slice(chunk);
            }
            protobuf_edit::retain::groupless::Retained::parse_standard(
                owned,
                standard,
                DepthLimit::REFERENCE,
                advice,
            )
            .map_err(|(_, oversize)| oversize)
            .expect("bench input admits")
        }

        /// The grouped twin of [`buffered_gl`].
        fn buffered_gr<A: protobuf_edit::retain::Advisor>(
            corpus: &[u8],
            feed: usize,
            standard: Standard,
            advice: &mut A,
        ) -> protobuf_edit::retain::grouped::Retained {
            let mut owned = Vec::with_capacity(corpus.len());
            for chunk in corpus.chunks(feed) {
                owned.extend_from_slice(chunk);
            }
            protobuf_edit::retain::grouped::Retained::parse_standard(
                owned,
                standard,
                DepthLimit::REFERENCE,
                advice,
            )
            .map_err(|(_, oversize)| oversize)
            .expect("bench input admits")
        }

        // The flat-varint feed ladder.
        let flat = build_varint_flat(96 * 1024);
        {
            let sealed = seal_gl(&flat, 4096, Standard::Tolerant, &mut CollectNoAdvice, true);
            assert!(sealed.is_complete(), "the flat corpus seals complete");
        }
        for (name, feed) in [
            ("collect_varints_96k_feed1", 1usize),
            ("collect_varints_96k_feed7", 7),
            ("collect_varints_96k_feed4k", 4096),
            ("collect_varints_96k_feed64k", 65536),
        ] {
            bench(name, flat.len(), || {
                black_box(seal_gl(&flat, feed, Standard::Tolerant, &mut CollectNoAdvice, true));
            });
        }
        for (name, feed) in [
            ("extend_retain_varints_96k_feed1", 1usize),
            ("extend_retain_varints_96k_feed7", 7),
            ("extend_retain_varints_96k_feed4k", 4096),
            ("extend_retain_varints_96k_feed64k", 65536),
        ] {
            bench(name, flat.len(), || {
                black_box(buffered_gl(&flat, feed, Standard::Tolerant, &mut RetainNoAdvice));
            });
        }

        // The mixed grouped corpus under a committing schema and
        // under zero schema.
        let mixed = build_grouped_mixed(100 * 1024);
        {
            let sealed = seal_gr(&mixed, 4096, Standard::Tolerant, &mut CollectSchema, true);
            assert!(sealed.is_complete(), "the mixed corpus seals complete under the schema");
        }
        bench("collect_mixed_commit_100k", mixed.len(), || {
            black_box(seal_gr(&mixed, 4096, Standard::Tolerant, &mut CollectSchema, true));
        });
        bench("collect_mixed_noadvice_100k", mixed.len(), || {
            black_box(seal_gr(&mixed, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });
        bench("extend_retain_mixed_commit_100k", mixed.len(), || {
            black_box(buffered_gr(&mixed, 4096, Standard::Tolerant, &mut RetainSchema));
        });
        bench("extend_retain_mixed_noadvice_100k", mixed.len(), || {
            black_box(buffered_gr(&mixed, 4096, Standard::Tolerant, &mut RetainNoAdvice));
        });

        // One giant opaque LEN: the copy-dominated pole.
        let opaque = {
            let payload = vec![0xABu8; 1 << 20];
            let mut b = Builder::new();
            b.push_len(f(3), &payload);
            b.finish().expect("bench input under cap")
        };
        bench("collect_opaque_1m", opaque.len(), || {
            black_box(seal_gl(&opaque, 4096, Standard::Tolerant, &mut CollectOpaque, true));
        });
        bench("extend_retain_opaque_1m", opaque.len(), || {
            black_box(buffered_gl(&opaque, 4096, Standard::Tolerant, &mut RetainOpaque));
        });

        // Fixed-width-dense input: arithmetic extents, no deciding
        // payload bytes.
        let fixed = build_fixed_dense(96 * 1024);
        bench("collect_fixed_dense_96k", fixed.len(), || {
            black_box(seal_gl(&fixed, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });
        bench("extend_retain_fixed_dense_96k", fixed.len(), || {
            black_box(buffered_gl(&fixed, 4096, Standard::Tolerant, &mut RetainNoAdvice));
        });

        // Shallow-wide against depth-heavy grouped input.
        let wide = build_groups_wide(64 * 1024);
        let deep = build_groups_deep(64 * 1024);
        bench("collect_groups_wide_64k", wide.len(), || {
            black_box(seal_gr(&wide, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });
        bench("collect_groups_deep_64k", deep.len(), || {
            black_box(seal_gr(&deep, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });
        bench("extend_retain_groups_wide_64k", wide.len(), || {
            black_box(buffered_gr(&wide, 4096, Standard::Tolerant, &mut RetainNoAdvice));
        });
        bench("extend_retain_groups_deep_64k", deep.len(), || {
            black_box(buffered_gr(&deep, 4096, Standard::Tolerant, &mut RetainNoAdvice));
        });

        // The standards pair: padded input under the tolerant
        // standard, minimal input under the canonical one.
        let padded = build_varint_padded(96 * 1024);
        {
            let sealed = seal_gl(&padded, 4096, Standard::Tolerant, &mut CollectNoAdvice, true);
            assert!(sealed.is_complete(), "the padded corpus is lawful tolerant input");
            let sealed =
                seal_gl(&flat, 4096, Standard::CanonicalMinimal, &mut CollectNoAdvice, true);
            assert!(sealed.is_complete(), "the flat corpus is canonical-minimal input");
        }
        bench("collect_varints_padded_96k", padded.len(), || {
            black_box(seal_gl(&padded, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });
        bench("collect_varints_canonical_96k", flat.len(), || {
            black_box(seal_gl(&flat, 4096, Standard::CanonicalMinimal, &mut CollectNoAdvice, true));
        });
        bench("extend_retain_varints_padded_96k", padded.len(), || {
            black_box(buffered_gl(&padded, 4096, Standard::Tolerant, &mut RetainNoAdvice));
        });
        bench("extend_retain_varints_canonical_96k", flat.len(), || {
            black_box(buffered_gl(&flat, 4096, Standard::CanonicalMinimal, &mut RetainNoAdvice));
        });

        // The fault shapes. 0x0F is a lawful-looking record head
        // whose wire class is refused, so it faults exactly at its
        // first byte.
        let underfill = {
            let body = build_varint_flat(96 * 1024);
            let mut doc = vec![0x12];
            push64(&mut doc, 2 * body.len() as u64);
            doc.extend_from_slice(&body);
            doc
        };
        let deferred = {
            let mut doc = vec![0x12];
            push64(&mut doc, (96 * 1024 + 1) as u64);
            doc.push(0x0F);
            doc.extend(core::iter::repeat_n(0xABu8, 96 * 1024));
            doc
        };
        let demote_tail = {
            let mut body = build_varint_flat(96 * 1024);
            body.push(0x0F);
            let mut doc = vec![0x12];
            push64(&mut doc, body.len() as u64);
            doc.extend_from_slice(&body);
            doc
        };
        let fault_tail = {
            let mut doc = vec![0x0F];
            doc.extend(core::iter::repeat_n(0xABu8, 96 * 1024));
            doc
        };
        {
            let sealed = seal_gl(&underfill, 4096, Standard::Tolerant, &mut CollectNoAdvice, true);
            assert!(sealed.fault().is_some(), "the underfilled root LEN faults at finish");
            assert_eq!(sealed.bytes().len(), underfill.len(), "custody keeps every fed byte");
            let sealed = seal_gl(&deferred, 4096, Standard::Tolerant, &mut CollectCommit, true);
            assert!(sealed.fault().is_some(), "the committed inner fault lands at the proof");
            let sealed = seal_gl(&deferred, 4096, Standard::Tolerant, &mut CollectNoAdvice, true);
            assert!(sealed.fault().is_none(), "the speculated head fault demotes");
            assert_eq!(sealed.node_count(), 1, "the demoted LEN is one opaque leaf");
            let sealed =
                seal_gl(&demote_tail, 4096, Standard::Tolerant, &mut CollectNoAdvice, true);
            assert!(sealed.fault().is_none(), "the tail fault demotes the speculative parse");
            assert_eq!(sealed.node_count(), 1, "the demoted LEN is one opaque leaf");
            let sealed = seal_gl(&fault_tail, 4096, Standard::Tolerant, &mut CollectNoAdvice, true);
            assert!(sealed.fault().is_some(), "the first record head faults");
            assert_eq!(sealed.bytes().len(), fault_tail.len(), "the fault tail is collected");
        }
        bench("collect_root_underfill_96k", underfill.len(), || {
            black_box(seal_gl(&underfill, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });
        bench("collect_root_deferred_96k", deferred.len(), || {
            black_box(seal_gl(&deferred, 4096, Standard::Tolerant, &mut CollectCommit, true));
        });
        bench("collect_demote_head_96k", deferred.len(), || {
            black_box(seal_gl(&deferred, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });
        bench("collect_demote_tail_96k", demote_tail.len(), || {
            black_box(seal_gl(&demote_tail, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });
        bench("collect_fault_tail_96k", fault_tail.len(), || {
            black_box(seal_gl(&fault_tail, 4096, Standard::Tolerant, &mut CollectNoAdvice, true));
        });

        // Growth and advisor-path pricing: the mixed job again with
        // an unseeded source, and a 16-deep committed LEN chain
        // whose advisor path materializes per level.
        bench("collect_mixed_grown_100k", mixed.len(), || {
            black_box(seal_gr(&mixed, 4096, Standard::Tolerant, &mut CollectSchema, false));
        });
        let advice_deep = build_len_deep(64 * 1024);
        {
            let sealed = seal_gl(&advice_deep, 4096, Standard::Tolerant, &mut CollectCommit, true);
            assert!(sealed.is_complete(), "the deep chain corpus seals complete");
        }
        bench("collect_deep_advice_64k", advice_deep.len(), || {
            black_box(seal_gl(&advice_deep, 4096, Standard::Tolerant, &mut CollectCommit, true));
        });
    }

    // Convert: grouped input with every group re-framed as a LEN —
    // the dialect-crossing job over a group-rich corpus.
    {
        use protobuf_edit::convert::groupless::Converter;
        let grouped_input = build_grouped_mixed(100 * 1024);
        let conv = Converter::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let mut out = Vec::with_capacity(grouped_input.len() + 64);
        bench("convert_groups_100k", grouped_input.len(), || {
            out.clear();
            black_box(
                conv.convert_into(black_box(&grouped_input), &mut out).expect("bench job accepts"),
            );
        });
    }

    // Replay convert: the dialect-crossing jobs over walks — one
    // line per direction on a seeking slice source.
    {
        use protobuf_edit::path::{Program, Segment};
        use protobuf_edit::replay_convert::{grouped as to_grouped, groupless as to_groupless};
        use protobuf_edit::replay_source::SliceSource;

        let grouped_input = build_grouped_mixed(100 * 1024);
        let mut out = Vec::with_capacity(grouped_input.len() + 64);
        bench("replay_convert_groups_100k", grouped_input.len(), || {
            out.clear();
            let mut source = SliceSource::new(black_box(&grouped_input));
            black_box(
                to_groupless::convert_into(
                    &mut source,
                    Standard::Tolerant,
                    DepthLimit::REFERENCE,
                    &mut out,
                )
                .expect("bench job accepts"),
            );
        });

        let designated_input = build_designated_mixed(100 * 1024);
        let route: [Segment<'_>; 2] = [Segment::Field(f(4)), Segment::Field(f(16))];
        let paths: [&[Segment<'_>]; 1] = [&route];
        let program = Program::over(&paths).expect("bench paths admit");
        let mut out = Vec::with_capacity(designated_input.len() + 64);
        bench("replay_convert_designations_100k", designated_input.len(), || {
            out.clear();
            let mut source = SliceSource::new(black_box(&designated_input));
            black_box(
                to_grouped::convert_into(
                    &mut source,
                    program,
                    Standard::Tolerant,
                    DepthLimit::REFERENCE,
                    &mut out,
                )
                .expect("bench job accepts"),
            );
        });
    }

    // Construct: small nested build and 64-deep nesting (the old
    // forward encoder re-measured per level; the event replay is
    // single-pass, so depth should be near-free here).
    {
        fn small_nested() -> Vec<u8> {
            let mut b = Builder::new();
            b.message(f(3), |m| {
                m.push_varint(f(1), 150);
                m.push_len(f(2), b"payload bytes");
            });
            b.push_i64(f(4), 0x1122_3344_5566_7788);
            b.push_varint(f(5), u64::MAX);
            b.finish().unwrap()
        }
        let built_len = small_nested().len();
        bench("construct_small_nested", built_len, || {
            black_box(small_nested());
        });

        fn nest(b: &mut protobuf_edit::construct::grouped::BodyBuilder<'_, '_>, depth: u32) {
            if depth == 0 {
                b.push_varint(f(4), 1);
                return;
            }
            b.message(f(1), |m| nest(m, depth - 1));
            b.push_varint(f(2), 0x3FFF);
            b.push_len(f(3), b"depth payload");
        }
        fn deep64() -> Vec<u8> {
            let mut b = Builder::new();
            b.message(f(1), |m| nest(m, 63));
            b.finish().unwrap()
        }
        let deep_len = deep64().len();
        bench("construct_deep64", deep_len, || {
            black_box(deep64());
        });

        // The reuse form: the output buffer persists across iters
        // (finish_into appends into retained capacity) and the
        // builder pre-sizes its stores, so first-allocation cost
        // drops out and the steady per-push cost is what remains.
        let mut out = Vec::with_capacity(built_len);
        bench("construct_small_nested_reuse", built_len, || {
            out.clear();
            let mut b = Builder::with_capacity(64);
            b.message(f(3), |m| {
                m.push_varint(f(1), 150);
                m.push_len(f(2), b"payload bytes");
            });
            b.push_i64(f(4), 0x1122_3344_5566_7788);
            b.push_varint(f(5), u64::MAX);
            b.finish_into(&mut out).unwrap();
            black_box(out.as_slice());
        });

        // The payload channel pair: one 1 MiB payload framed and
        // finished. The borrowed face pays one copy (at emission);
        // the staging twin pays two (push, then emission) — the
        // gap is the copy the borrow elides.
        let payload = vec![0xC3u8; 1 << 20];
        let mut out = Vec::with_capacity(payload.len() + 8);
        bench("construct_payload_borrowed_1m", payload.len(), || {
            out.clear();
            let mut b = Builder::new();
            b.push_len(f(1), &payload);
            b.finish_into(&mut out).unwrap();
            black_box(out.as_slice());
        });
        bench("construct_payload_copy_1m", payload.len(), || {
            out.clear();
            let mut b = Builder::new();
            b.push_len_copy(f(1), &payload);
            b.finish_into(&mut out).unwrap();
            black_box(out.as_slice());
        });

        // The chunked-arrival twin of the borrowed line: the same
        // payload supplied as 4 KiB borrowed frames. Chunks are
        // accounted as they arrive and never re-measured, so the
        // cost target is the borrowed wholesale line, not the copy
        // line.
        bench("construct_payload_frames_1m", payload.len(), || {
            out.clear();
            let mut b = Builder::new();
            b.bytes_frame(f(1), |bytes| {
                for chunk in payload.chunks(4096) {
                    bytes.write_borrowed(chunk);
                }
            });
            b.finish_into(&mut out).unwrap();
            black_box(out.as_slice());
        });
    }

    // Select: the read twin of the rewrite line — the same
    // two-path program shape over the same input, delivering
    // borrowed matches instead of writing. The wildcard path
    // routes through the nested-message field, so committed
    // descents (layer compilation, the walk stack) are on the
    // clock alongside the per-record probes; traverse_walk_100k
    // above (same input, hand recursion into the same field) is
    // the substrate baseline the selector's residual is judged
    // against. Reported per record because MiB/s misleads on
    // short records.
    {
        use protobuf_edit::path::{Program, Segment};
        use protobuf_edit::select::grouped::Matches;
        let route = [f(4)];
        let paths: [&[Segment<'_>]; 2] = [
            &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
            &[Segment::Field(f(2))],
        ];
        let program = Program::over(&paths).expect("bench paths admit");
        let records = {
            use protobuf_edit::traverse::grouped::Cursor;
            Cursor::over(&large, GroupDepth::REFERENCE).expect("bench input admitted").fold(
                0usize,
                |n, entry| {
                    entry.expect("bench input is lawful");
                    n + 1
                },
            )
        };
        let ns = bench("select_two_paths_100k", large.len(), || {
            let mut hits = 0u64;
            let mut acc = 0u64;
            for found in Matches::over(black_box(&large), &program, DepthLimit::REFERENCE)
                .expect("bench input admitted")
            {
                let found = found.expect("bench input is lawful");
                hits += 1;
                acc = acc.wrapping_add(u64::from(found.span().start()));
            }
            black_box((hits, acc));
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  select_two_paths_100k/record",
            ns / records as f64
        );
    }

    // Route: the selector's stream twin — the same two-path program
    // over the same input, delivered as PathId-tagged events from
    // one feed (and from 4 KiB feeds, where the carry/resume seam
    // and the suspension modes are on the clock). select's line
    // above is the buffered reference; scan_validate_100k is the
    // sink-free stream floor — the gap between them locates the
    // delivery tax. Reported per record because MiB/s misleads on
    // short records.
    {
        use core::ops::ControlFlow;
        use protobuf_edit::path::{PathId, Program, Segment};
        use protobuf_edit::route::grouped::{Router, Sink};

        struct Count {
            hits: u64,
            acc: u64,
        }
        impl Sink for Count {
            fn on_varint(
                &mut self,
                _path: PathId,
                _field: FieldNumber,
                at: u64,
                value: u64,
            ) -> ControlFlow<()> {
                self.hits += 1;
                self.acc = self.acc.wrapping_add(at ^ value);
                ControlFlow::Continue(())
            }
            fn on_i32(
                &mut self,
                _path: PathId,
                _field: FieldNumber,
                at: u64,
                bits: u32,
            ) -> ControlFlow<()> {
                self.hits += 1;
                self.acc = self.acc.wrapping_add(at ^ u64::from(bits));
                ControlFlow::Continue(())
            }
        }

        let route = [f(4)];
        let paths: [&[Segment<'_>]; 2] = [
            &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
            &[Segment::Field(f(2))],
        ];
        let program = Program::over(&paths).expect("bench paths admit");
        let records = {
            use protobuf_edit::traverse::grouped::Cursor;
            Cursor::over(&large, GroupDepth::REFERENCE).expect("bench input admitted").fold(
                0usize,
                |n, entry| {
                    entry.expect("bench input is lawful");
                    n + 1
                },
            )
        };
        let ns = bench("route_two_paths_100k", large.len(), || {
            use protobuf_edit::route::Flow;
            let mut sink = Count { hits: 0, acc: 0 };
            let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::REFERENCE);
            let flow = router.feed(black_box(&large), &mut sink).unwrap();
            assert!(matches!(flow, Flow::More), "the counting sink never stops");
            router.finish().unwrap();
            black_box((sink.hits, sink.acc));
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  route_two_paths_100k/record",
            ns / records as f64
        );
        let ns = bench("route_two_paths_chunked_100k", large.len(), || {
            use protobuf_edit::route::Flow;
            let mut sink = Count { hits: 0, acc: 0 };
            let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::REFERENCE);
            for chunk in black_box(&large[..]).chunks(4096) {
                let flow = router.feed(chunk, &mut sink).unwrap();
                assert!(matches!(flow, Flow::More), "the counting sink never stops");
            }
            router.finish().unwrap();
            black_box((sink.hits, sink.acc));
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  route_two_paths_chunked_100k/rec",
            ns / records as f64
        );
    }

    // Rewire: the write twin of the route line — the same two-path
    // program carrying rewrite_two_rules' actions, emitting through
    // a caller sink. The delta against rewrite_two_rules_100k is
    // the streaming delivery model on the same job.
    {
        use protobuf_edit::path::{Program, Segment};
        use protobuf_edit::rewire::grouped::{Actions, Rewirer};
        use protobuf_edit::rewire::{Action, Value};
        let route = [f(4)];
        let paths: [&[Segment<'_>]; 2] = [
            &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
            &[Segment::Field(f(2))],
        ];
        let program = Program::over(&paths).expect("bench paths admit");
        let acts = [Action::Rewrite(Value::Varint(7)), Action::Delete];
        let actions = Actions::over(&program, &acts).expect("bench actions admit");
        let records = {
            use protobuf_edit::traverse::grouped::Cursor;
            Cursor::over(&large, GroupDepth::REFERENCE).expect("bench input admitted").fold(
                0usize,
                |n, entry| {
                    entry.expect("bench input is lawful");
                    n + 1
                },
            )
        };
        let mut out = Vec::with_capacity(large.len() + 16);
        let ns = bench("rewire_two_paths_100k", large.len(), || {
            out.clear();
            let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
            let mut rw = Rewirer::new(&actions, Standard::Tolerant, DepthLimit::REFERENCE);
            rw.feed(black_box(&large), &mut sink).unwrap();
            rw.finish().unwrap();
            black_box(out.len());
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  rewire_two_paths_100k/record",
            ns / records as f64
        );
    }

    // Rewrite: one replace rule and one delete rule over the mixed
    // input — the batch-editing shape where the matcher judges every
    // record. The replace rule routes through the nested-message
    // field, so committed descents (the slot table and the layer
    // machinery) are on the clock too. Reported per record because
    // MiB/s misleads on short records.
    {
        use protobuf_edit::path::Segment;
        use protobuf_edit::rewrite::{Action, Rule, RuleSet, Value};
        let route = [f(4)];
        let rules = [
            Rule {
                path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
                action: Action::Replace(Value::Varint(7)),
            },
            Rule { path: &[Segment::Field(f(2))], action: Action::Delete },
        ];
        let set = RuleSet::over(&rules).expect("bench rules admit");
        let records = {
            use protobuf_edit::traverse::grouped::Cursor;
            Cursor::over(&large, GroupDepth::REFERENCE).expect("bench input admitted").fold(
                0usize,
                |n, entry| {
                    entry.expect("bench input is lawful");
                    n + 1
                },
            )
        };
        let ns = bench("rewrite_two_rules_100k", large.len(), || {
            black_box(
                protobuf_edit::rewrite::grouped::rewrite(
                    black_box(&large),
                    &set,
                    DepthLimit::REFERENCE,
                )
                .expect("bench job accepts"),
            );
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  rewrite_two_rules_100k/record",
            ns / records as f64
        );

        // The insert-bearing partner: the same two rules compiled
        // through the gap-capable plan type, plus one insertion into
        // every routed container — the gap lane the insert-free plan
        // omits by type is on the clock over the same corpus. The
        // realized insertion count is judged once, outside the timed
        // body.
        use protobuf_edit::rewrite::{Gap, InsertRule, InsertRuleSet};
        let head = InsertRule { gap: Gap::HeadOf, field: f(9), value: Value::Varint(7) };
        let insert_rules = [
            Rule {
                path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
                action: Action::Replace(Value::Varint(7)),
            },
            Rule { path: &[Segment::Field(f(2))], action: Action::Delete },
            Rule { path: &[Segment::Field(f(4))], action: Action::Insert(&head) },
        ];
        let insert_set = InsertRuleSet::over(&insert_rules).expect("bench rules admit");
        let (_, stats) =
            protobuf_edit::rewrite::grouped::rewrite(&large, &insert_set, DepthLimit::REFERENCE)
                .expect("bench job accepts");
        assert!(stats.inserted() > 0, "the insert lane fires on the corpus");
        let ns = bench("rewrite_two_rules_insert_100k", large.len(), || {
            black_box(
                protobuf_edit::rewrite::grouped::rewrite(
                    black_box(&large),
                    &insert_set,
                    DepthLimit::REFERENCE,
                )
                .expect("bench job accepts"),
            );
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  rewrite_two_rules_insert_100k/rec",
            ns / records as f64
        );
    }

    // The in-place rows: the judge walk's pure cost at two sizes
    // (linearity), the sparse headline against the patch+copy-back
    // composition it replaces, write-list saturation, the grouped
    // pair, and the 1 MiB payload overwrite against a bare memcpy.
    // Scripts are idempotent, so every iteration does identical
    // work over identical geometry.
    #[cfg(all(
        feature = "inplace-grouped",
        feature = "inplace-groupless",
        feature = "rewrite-groupless",
        feature = "patch-groupless"
    ))]
    {
        use inplace_rows::{
            row_inplace_apply_deep9, row_inplace_apply_deep12, row_inplace_apply_deep15,
            row_inplace_apply_dense_100k, row_inplace_apply_payload_1k,
            row_inplace_apply_payload_1m, row_inplace_apply_sparse_100k,
            row_inplace_grouped_renumber_100k, row_inplace_walk_canonical_100k,
            row_inplace_walk_clean_10k, row_inplace_walk_clean_100k, row_memcpy_1m,
            row_patch_copyback_sparse_100k, row_rewrite_zero_match_100k,
        };
        use protobuf_edit::inplace::{Action, Rule, RuleSet};
        use protobuf_edit::path::Segment;

        // f60 never occurs in the generated corpus (fields cycle
        // 1..=4), so its rule is the zero-match probe; the sparse
        // doc appends four f60 records for the four-edit headline.
        let f60 = f(60);
        let clean_rules = [Rule { path: &[Segment::Field(f60)], action: Action::SetVarint(0) }];
        let clean_set = RuleSet::over(&clean_rules).unwrap();
        let dense_rules = [Rule { path: &[Segment::Field(f(1))], action: Action::SetVarint(0) }];
        let dense_set = RuleSet::over(&dense_rules).unwrap();
        let renumber_rules =
            [Rule { path: &[Segment::Field(f(4))], action: Action::Renumber(f(4)) }];
        let renumber_set = RuleSet::over(&renumber_rules).unwrap();

        let mut sparse_doc = large.clone();
        for _ in 0..4 {
            sparse_doc.extend_from_slice(&[0xE0, 0x03, 0x05]); // varint f60=5
        }
        let mut clean_small = small.clone();
        let mut clean_large = large.clone();
        let mut grouped_doc = build_grouped_mixed(100 * 1024);

        let payload_new = vec![0x5Au8; 1 << 20];
        let mut payload_doc = {
            let mut b = Builder::new();
            b.push_varint(f(1), 1);
            b.push_len(f(2), &payload_new);
            b.push_varint(f(3), 2);
            b.finish().expect("bench input under cap")
        };
        let payload_rules =
            [Rule { path: &[Segment::Field(f(2))], action: Action::SetPayload(&payload_new) }];
        let payload_set = RuleSet::over(&payload_rules).unwrap();

        for (label, buf) in [("10k", &mut clean_small), ("100k", &mut clean_large)] {
            let records = traverse_count(buf);
            let run = if label == "10k" {
                row_inplace_walk_clean_10k
            } else {
                row_inplace_walk_clean_100k
            };
            let len = buf.len();
            let ns = bench(&format!("inplace_walk_clean_{label}"), len, || {
                black_box(run(black_box(&mut buf[..]), &clean_set));
            });
            println!(
                "  inplace_walk_clean_{label}/record  {:>10.2} ns ({records} records)",
                ns / records as f64
            );
        }

        // The canonical keep-only absolute row: the clean walk's
        // twin under the minimal-width standard over the same
        // corpus, so the per-construct minimality judgment is the
        // whole delta against inplace_walk_clean_100k.
        {
            let records = traverse_count(&clean_large);
            let ns = bench("inplace_walk_canonical_100k", clean_large.len(), || {
                black_box(row_inplace_walk_canonical_100k(
                    black_box(&mut clean_large[..]),
                    &clean_set,
                ));
            });
            println!(
                "  inplace_walk_canonical_100k/rec  {:>12.2} ns ({records} records)",
                ns / records as f64
            );
        }

        // The depth grid: 512 chains per corpus, nesting 9, 12, and
        // 15 containers with one leaf edit each — depth is the only
        // mover across the three rows, so the per-level walk cost is
        // their affine slope.
        fn build_deep_chains(chains: usize, depth: u32) -> Vec<u8> {
            let mut b = Builder::new();
            fn nest(b: &mut protobuf_edit::construct::grouped::BodyBuilder<'_, '_>, depth: u32) {
                b.push_varint(f(2), 5);
                if depth > 1 {
                    b.message(f(4), |m| nest(m, depth - 1));
                } else {
                    b.push_varint(f(1), 0);
                }
            }
            for _ in 0..chains {
                b.message(f(4), |m| nest(m, depth));
            }
            b.finish().expect("bench input under cap")
        }
        let deep_route = [f(4)];
        let deep_rules = [Rule {
            path: &[Segment::AnyDepth { descend: &deep_route }, Segment::Field(f(1))],
            action: Action::SetVarint(0),
        }];
        let deep_set = RuleSet::over(&deep_rules).unwrap();
        let mut deep9 = build_deep_chains(512, 9);
        let mut deep12 = build_deep_chains(512, 12);
        let mut deep15 = build_deep_chains(512, 15);
        bench("inplace_apply_deep9", deep9.len(), || {
            let stats = row_inplace_apply_deep9(black_box(&mut deep9[..]), &deep_set);
            assert_eq!(stats.replaced(), 512, "every chain leaf fires");
        });
        bench("inplace_apply_deep12", deep12.len(), || {
            let stats = row_inplace_apply_deep12(black_box(&mut deep12[..]), &deep_set);
            assert_eq!(stats.replaced(), 512, "every chain leaf fires");
        });
        bench("inplace_apply_deep15", deep15.len(), || {
            let stats = row_inplace_apply_deep15(black_box(&mut deep15[..]), &deep_set);
            assert_eq!(stats.replaced(), 512, "every chain leaf fires");
        });

        let rewrite_rules = [protobuf_edit::rewrite::Rule {
            path: &[Segment::Field(f60)],
            action: protobuf_edit::rewrite::Action::Delete,
        }];
        let rewrite_set = protobuf_edit::rewrite::RuleSet::over(&rewrite_rules).unwrap();
        let mut zero_out = Vec::new();
        bench("rewrite_zero_match_100k", large.len(), || {
            row_rewrite_zero_match_100k(black_box(&large), &rewrite_set, &mut zero_out);
        });

        bench("inplace_apply_sparse_100k", sparse_doc.len(), || {
            let stats = row_inplace_apply_sparse_100k(black_box(&mut sparse_doc[..]), &clean_set);
            assert_eq!(stats.replaced(), 4, "the four sparse edits fire");
        });

        let mut copyback_doc = large.clone();
        for _ in 0..4 {
            copyback_doc.extend_from_slice(&[0xE0, 0x03, 0x05]);
        }
        let mut copyback_out = Vec::new();
        bench("patch_copyback_sparse_100k", copyback_doc.len(), || {
            row_patch_copyback_sparse_100k(black_box(&mut copyback_doc[..]), &mut copyback_out);
        });

        let mut dense_doc = large.clone();
        bench("inplace_apply_dense_100k", dense_doc.len(), || {
            black_box(row_inplace_apply_dense_100k(black_box(&mut dense_doc[..]), &dense_set));
        });

        bench("inplace_grouped_renumber_100k", grouped_doc.len(), || {
            black_box(row_inplace_grouped_renumber_100k(
                black_box(&mut grouped_doc[..]),
                &renumber_set,
            ));
        });

        bench("inplace_apply_payload_1m", payload_doc.len(), || {
            black_box(row_inplace_apply_payload_1m(black_box(&mut payload_doc[..]), &payload_set));
        });
        let payload_at = payload_doc.len() - payload_new.len() - 2;
        let mut memcpy_dst = payload_doc;
        bench("memcpy_1m", payload_new.len(), || {
            row_memcpy_1m(
                black_box(&mut memcpy_dst[payload_at..payload_at + payload_new.len()]),
                black_box(&payload_new),
            );
        });

        // The 1 KiB twin of the payload overwrite: the same job over
        // a three-orders-smaller document, so the apply cost's
        // size-independence shape has both ends on record.
        let payload_new_1k = vec![0x5Au8; 1 << 10];
        let mut payload_doc_1k = {
            let mut b = Builder::new();
            b.push_varint(f(1), 1);
            b.push_len(f(2), &payload_new_1k);
            b.push_varint(f(3), 2);
            b.finish().expect("bench input under cap")
        };
        let payload_rules_1k =
            [Rule { path: &[Segment::Field(f(2))], action: Action::SetPayload(&payload_new_1k) }];
        let payload_set_1k = RuleSet::over(&payload_rules_1k).unwrap();
        bench("inplace_apply_payload_1k", payload_doc_1k.len(), || {
            black_box(row_inplace_apply_payload_1k(
                black_box(&mut payload_doc_1k[..]),
                &payload_set_1k,
            ));
        });
    }

    // Splice: the online twin of the rewrite line — the same job
    // decided per record by consumer code instead of compiled
    // rules; the cross-machine differential pins the byte
    // equivalence, this line prices the ask dispatch against the
    // matcher.
    {
        use protobuf_edit::splice::grouped::{splice_into, Rule};
        use protobuf_edit::splice::{Len, Scalar};
        struct TwoRules;
        impl Rule for TwoRules {
            fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
                if field == f(1) { Scalar::Rewrite(7) } else { Scalar::Keep }
            }
            fn on_i32(&mut self, _at: u32, field: FieldNumber, _bits: u32) -> Scalar<'_, u32> {
                if field == f(2) { Scalar::Drop } else { Scalar::Keep }
            }
            fn on_len<'a>(
                &'a mut self,
                _at: u32,
                field: FieldNumber,
                _payload: &'a [u8],
            ) -> Len<'a> {
                if field == f(4) { Len::Commit { tail: None } } else { Len::Pass }
            }
        }
        let records = {
            use protobuf_edit::traverse::grouped::Cursor;
            Cursor::over(&large, GroupDepth::REFERENCE).expect("bench input admitted").fold(
                0usize,
                |n, entry| {
                    entry.expect("bench input is lawful");
                    n + 1
                },
            )
        };
        let mut out = Vec::with_capacity(large.len() + 16);
        let ns = bench("splice_two_rules_100k", large.len(), || {
            out.clear();
            splice_into(
                black_box(&large),
                &mut TwoRules,
                Standard::Tolerant,
                DepthLimit::REFERENCE,
                &mut out,
            )
            .expect("bench job accepts");
            black_box(out.len());
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  splice_two_rules_100k/record",
            ns / records as f64
        );
    }

    // Transcode: the identity job over the mixed input — the
    // byte-true pass-through where the whole cost is the machine's
    // judging overhead. Reported per record because MiB/s misleads
    // on short records.
    {
        use protobuf_edit::transcode::grouped::Transcoder;
        let records = {
            use protobuf_edit::traverse::grouped::Cursor;
            Cursor::over(&large, GroupDepth::REFERENCE).expect("bench input admitted").fold(
                0usize,
                |n, entry| {
                    entry.expect("bench input is lawful");
                    n + 1
                },
            )
        };
        let mut out = Vec::with_capacity(large.len());
        let ns = bench("transcode_identity_100k", large.len(), || {
            out.clear();
            let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
            let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
            t.feed(black_box(&large), &mut (), &mut sink).unwrap();
            t.finish(&mut (), &mut sink).unwrap();
            black_box(out.as_slice());
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  transcode_identity_100k/record",
            ns / records as f64
        );

        // The canonical-minimal standard adds a per-construct
        // minimality judgment on top of the tolerant walk; the
        // builder emits minimal widths, so the identity job accepts.
        let ns = bench("transcode_identity_canonical_100k", large.len(), || {
            out.clear();
            let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
            let mut t = Transcoder::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
            t.feed(black_box(&large), &mut (), &mut sink).unwrap();
            t.finish(&mut (), &mut sink).unwrap();
            black_box(out.as_slice());
        });
        println!(
            "{:<36} {:>12.2} ns/record ({records} top-level records)",
            "  transcode_canonical_100k/record",
            ns / records as f64
        );
    }

    // The complexity targets on record (texture plan T6): the log
    // append under a long history, the tail append off the layer's
    // tail anchor, the interior-history gate, and the hex-view
    // reverse index.
    {
        let mut s = Session::open_copy(&large).unwrap();
        use protobuf_edit::wire::grouped::RecordKind;
        let targets: Vec<_> =
            s.top().filter(|&h| matches!(s.kind(h), Ok(RecordKind::Varint))).take(64).collect();
        bench("session_set_varint_x64_after_1k_log", 0, || {
            row_session_set_varint_x64(&mut s, &targets);
        });
    }
    {
        bench("session_tail_append_x256", 0, || {
            black_box(row_session_tail_append_x256(&small));
        });
    }

    // The sizing walk against the settled answer: the base pays the
    // whole visible tree per ask, the priced typestate answers from
    // its settled words while every body sits in the length class.
    {
        let mut s = Session::open_copy(&large).unwrap();
        let t0 = s.top().next().unwrap();
        s.set_varint(t0, 1).unwrap();
        bench("session_save_len_dirty_100k", large.len(), || {
            black_box(row_session_save_len_dirty(&s));
        });
    }
    #[cfg(feature = "priced-session-grouped")]
    {
        use protobuf_edit::session::grouped::PricedSession;

        let dirty_priced = |data: &[u8]| -> PricedSession {
            let mut s = Session::open_copy(data).unwrap();
            let t0 = s.top().next().unwrap();
            s.set_varint(t0, 1).unwrap();
            s.into_priced().map_err(|(_, fault)| fault).expect("bench machine admits")
        };
        let p10 = dirty_priced(&small);
        bench("priced_save_len_dirty_10k", small.len(), || {
            black_box(row_priced_save_len_dirty_10k(&p10));
        });
        let p100 = dirty_priced(&large);
        bench("priced_save_len_dirty_100k", large.len(), || {
            black_box(row_priced_save_len_dirty_100k(&p100));
        });

        // The priced save cycle over the same one-edit 100k machine —
        // `session_save_one_edit_100k`'s twin through the wrapper.
        bench("priced_save_one_edit_100k", large.len(), || {
            black_box(row_priced_save_one_edit(&p100));
        });

        // The settle climb priced by depth: one document carries a
        // varint target under 0, 8, and 16 ancestor containers, and
        // each row alternates a two-width pair so every set moves the
        // price (an equal-width re-set takes the zero-delta exit).
        let deep = {
            let mut b = Builder::new();
            b.push_varint(f(1), 5);
            fn nest(b: &mut protobuf_edit::construct::grouped::BodyBuilder<'_, '_>, depth: u32) {
                b.push_varint(f(2), 5);
                if depth > 1 {
                    b.message(f(4), |m| nest(m, depth - 1));
                }
            }
            b.message(f(4), |m| nest(m, 16));
            b.finish().expect("bench input under cap")
        };
        let mut p = Session::open_copy(&deep)
            .unwrap()
            .into_priced()
            .map_err(|(_, fault)| fault)
            .expect("bench machine admits");
        let mut ladder = Vec::new();
        {
            use protobuf_edit::session::grouped::Descent;
            use protobuf_edit::wire::grouped::RecordKind;
            let tops: Vec<_> = p.top().collect();
            ladder.push(tops[0]);
            let mut container = tops[1];
            loop {
                let Descent::Opened { first: Some(first) } = p.descend(container).unwrap() else {
                    unreachable!("bench chain descends clean");
                };
                ladder.push(first);
                let Some(next) = p
                    .children(container)
                    .unwrap()
                    .find(|&h| matches!(p.kind(h), Ok(RecordKind::Len)))
                else {
                    break;
                };
                container = next;
            }
        }
        let (d0, d8, d16) = (ladder[0], ladder[8], ladder[16]);
        // Pre-pay every capacity the measured calls could touch: the
        // grid rows mutate one shared machine, and an in-window Vec
        // doubling would smear a megabyte copy across one row's
        // per-call average. The unwinding leaves lengths at their
        // starting points with the capacities retained.
        for _ in 0..65_536 {
            p.set_varint(d16, 300).unwrap();
            p.set_varint(d16, 7).unwrap();
        }
        p.revert_all();
        bench("priced_set_varint_x64_deep0", 0, || {
            row_priced_set_varint_x64_deep0(&mut p, d0);
        });
        bench("priced_set_varint_x64_deep8", 0, || {
            row_priced_set_varint_x64_deep8(&mut p, d8);
        });
        bench("priced_set_varint_x64_deep16", 0, || {
            row_priced_set_varint_x64_deep16(&mut p, d16);
        });
        bench("priced_revert_x64_deep16", 0, || {
            row_priced_revert_x64_deep16(&mut p, d16);
        });

        // The zero-delta fast paths at depth 16: one document carries
        // a varint, an I32, and an I64 leaf under 16 containers, and
        // every set alternates two same-width values — real edits
        // that move no price, so no row pays the per-level climb the
        // grid above prices. Capacity is pre-paid through the same
        // unwinding discipline as the grid machine.
        use protobuf_edit::wire::grouped::RecordKind;
        let zd = {
            let mut b = Builder::new();
            fn nest(b: &mut protobuf_edit::construct::grouped::BodyBuilder<'_, '_>, depth: u32) {
                if depth == 0 {
                    b.push_varint(f(2), 7);
                    b.push_i32(f(3), 7);
                    b.push_i64(f(5), 7);
                    return;
                }
                b.push_varint(f(2), 5);
                b.message(f(4), |m| nest(m, depth - 1));
            }
            b.message(f(4), |m| nest(m, 15));
            b.finish().expect("bench input under cap")
        };
        let mut zp = Session::open_copy(&zd)
            .unwrap()
            .into_priced()
            .map_err(|(_, fault)| fault)
            .expect("bench machine admits");
        let mut container = zp.top().next().expect("the chain top");
        loop {
            let Descent::Opened { .. } = zp.descend(container).unwrap() else {
                unreachable!("bench chain descends clean");
            };
            let Some(next) = zp
                .children(container)
                .unwrap()
                .find(|&h| matches!(zp.kind(h), Ok(RecordKind::Len)))
            else {
                break;
            };
            container = next;
        }
        let (mut zv, mut z32, mut z64) = (None, None, None);
        for h in zp.children(container).unwrap() {
            match zp.kind(h) {
                Ok(RecordKind::Varint) => zv = Some(h),
                Ok(RecordKind::I32) => z32 = Some(h),
                Ok(RecordKind::I64) => z64 = Some(h),
                _ => {}
            }
        }
        let zv = zv.expect("the varint leaf exists");
        let z32 = z32.expect("the I32 leaf exists");
        let z64 = z64.expect("the I64 leaf exists");
        for _ in 0..65_536 {
            zp.set_varint(zv, 300).unwrap();
            zp.set_varint(zv, 7).unwrap();
        }
        zp.revert_all();
        bench("priced_set_i32_x64_deep16", 0, || {
            row_priced_set_i32_x64_deep16(&mut zp, z32);
        });
        bench("priced_set_i64_x64_deep16", 0, || {
            row_priced_set_i64_x64_deep16(&mut zp, z64);
        });
        bench("priced_set_varint_x64_equal_deep16", 0, || {
            row_priced_set_varint_x64_equal_deep16(&mut zp, zv);
        });

        // The admission walk, amortized over the whole dirty machine:
        // one door round trip per iteration.
        let mut slot = Some(dirty_priced(&large).into_session());
        bench("priced_into_priced_dirty_100k", large.len(), || {
            let session = slot.take().expect("the round trip always returns");
            slot = Some(row_priced_into_priced_dirty_100k(session));
        });
    }

    // The transfer profile's settled save price: the same dirty
    // one-edit machines as the priced pair above, so the O(1)
    // save_len claim on the transfer siblings has its own flatness
    // pair.
    #[cfg(feature = "priced-transfer-session-grouped")]
    {
        use protobuf_edit::session::grouped::{PricedTransferSession, TransferSession};
        let dirty = |data: &[u8]| -> PricedTransferSession {
            let mut s = TransferSession::open_copy(data).unwrap();
            let t0 = s.top().next().unwrap();
            s.set_varint(t0, 1).unwrap();
            s.into_priced().map_err(|(_, fault)| fault).expect("bench machine admits")
        };
        let p10 = dirty(&small);
        bench("priced_transfer_save_len_dirty_10k", small.len(), || {
            row_priced_transfer_save_len_dirty_10k(&p10);
        });
        let p100 = dirty(&large);
        bench("priced_transfer_save_len_dirty_100k", large.len(), || {
            row_priced_transfer_save_len_dirty_100k(&p100);
        });
    }

    // The interior-history gate: set_payload reads the target
    // layer's history count. Differenced — the setup line builds a
    // 1024-entry history at depth 16, the gated line adds 64
    // payload writes on an unrelated top-level LEN; the per-write
    // cost is the difference over 64.
    {
        use protobuf_edit::wire::grouped::RecordKind;
        let deep = {
            let mut b = Builder::new();
            b.push_len(f(9), &[0xA5u8; 64]);
            fn nest(b: &mut protobuf_edit::construct::grouped::BodyBuilder<'_, '_>, depth: u32) {
                if depth == 0 {
                    b.push_varint(f(1), 5);
                    return;
                }
                b.message(f(4), |m| nest(m, depth - 1));
            }
            b.message(f(4), |m| nest(m, 15));
            b.finish().expect("bench input under cap")
        };
        let build_history = |s: &mut Session| {
            let mut cur = s.top().nth(1).expect("deep doc has the chain top");
            let leaf = loop {
                let Descent::Opened { first } = s.descend(cur).expect("chain descends") else {
                    unreachable!("bench chain descends clean");
                };
                let kid = first.expect("chain layers have one child");
                if matches!(s.kind(kid), Ok(RecordKind::Len)) {
                    cur = kid;
                } else {
                    break kid;
                }
            };
            for i in 0..1024u64 {
                s.set_varint(leaf, i).expect("leaf accepts values");
            }
        };
        let ns_setup = bench("session_gate_setup_1k_log_deep16", 0, || {
            let mut s = Session::open_copy(&deep).unwrap();
            build_history(&mut s);
            black_box(s.pending());
        });
        let ns_gated = bench("session_gate_setup_plus_x64_payload", 0, || {
            let mut s = Session::open_copy(&deep).unwrap();
            build_history(&mut s);
            let target = s.top().next().expect("deep doc has the target LEN");
            for _ in 0..64 {
                s.set_payload(target, b"edited-payload-bytes").unwrap();
            }
            black_box(s.pending());
        });
        println!(
            "{:<36} {:>12.1} ns/op (log=1024, depth=16, diff over 64)",
            "  session_set_payload_gated/op",
            (ns_gated - ns_setup) / 64.0
        );
    }

    // The hex-view reverse index: narrowest bisects source runs,
    // descending as far as layers have materialized. One layer of
    // nested messages is materialized first, then 64 scattered
    // positions per iteration.
    {
        let mut s = Session::open_copy(&large).unwrap();
        let tops: Vec<_> = s.top().collect();
        let mut materialized = 0u32;
        for h in tops {
            if s.field(h) == Ok(f(4)) && matches!(s.descend(h), Ok(Descent::Opened { .. })) {
                materialized += 1;
            }
        }
        let mut rng = Rng(0x0123_4567_89AB_CDEF);
        let positions: Vec<u32> =
            (0..64).map(|_| (rng.next() % large.len() as u64) as u32).collect();
        let ns = bench("session_narrowest_x64_100k", 0, || {
            for &p in &positions {
                black_box(s.narrowest(black_box(p)));
            }
        });
        println!(
            "{:<36} {:>12.1} ns/query ({materialized} nested layers materialized)",
            "  session_narrowest/query",
            ns / 64.0
        );
    }
}
