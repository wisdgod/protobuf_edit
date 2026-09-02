//! The replay splice cell's in-lane judge battery: zero-retention
//! allocation rows (the identity job's coalesced overlay
//! included), the pass-two zero-allocation row, pass-count and
//! ask-phase honesty over a counting source, supply-refusal and
//! torn rows (the pinned equal-length residual included), and the
//! differentials against the buffered splicer over the slice
//! source.

#![cfg(all(
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "construct-grouped"
))]
#![feature(thread_id_value)]

#[path = "support/replay.rs"]
mod replay;

use std::cell::Cell;

use protobuf_edit::replay_source::{
    Chunk, ReplayFault, ReplayPhase, ReplayWalk, SliceFault, SliceSource, StableReplaySource,
    SupplyFault,
};
use protobuf_edit::{DepthLimit, FieldNumber, Standard, replay_splice, splice};
use replay::{Counting, Refusing, WalkStats, alloc_count_now, corpus, f, measured, payload_scaled};

// ─── the swapping source (torn and residual rows) ───

/// Serves `walks[n]` to the nth walk (the last entry repeats):
/// the instrument for sources whose bytes move between the
/// measuring and the emission walk.
struct Swapping<'a> {
    walks: &'a [&'a [u8]],
    begun: Cell<u32>,
}

struct SwappingWalk<'a> {
    rest: &'a [u8],
}

impl StableReplaySource for Swapping<'_> {
    type Error = SliceFault;

    type Walk<'s>
        = SwappingWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        let nth = usize::try_from(self.begun.get()).expect("test walk counts fit usize");
        self.begun.set(self.begun.get() + 1);
        Ok(SwappingWalk { rest: self.walks[nth.min(self.walks.len() - 1)] })
    }
}

impl ReplayWalk for SwappingWalk<'_> {
    type Error = SliceFault;

    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<Self::Error>> {
        Ok(Chunk::new(self.rest))
    }

    fn consume(&mut self, n: usize) {
        self.rest = &self.rest[n..];
    }

    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<Self::Error>> {
        let take = n.min(self.rest.len() as u64);
        self.rest = &self.rest[usize::try_from(take).expect("test extents fit usize")..];
        Ok(take)
    }
}

// ─── fixtures ───

/// The grouped twin of [`payload_scaled`]: fixed record structure
/// with a group frame around the nested blob, payload sizes
/// scaling.
fn payload_scaled_grouped(payload: usize) -> Vec<u8> {
    let blob = vec![0x5Au8; payload];
    let nested = vec![0xA5u8; payload];
    let mut builder = protobuf_edit::construct::grouped::Builder::new();
    builder.push_varint(f(0), 150);
    builder.push_len(f(1), &blob);
    builder.push_i64(f(2), 7);
    builder.group(f(6), |g| {
        g.push_len_copy(f(4), &nested);
        g.push_varint(f(5), 3);
    });
    builder.finish().expect("the scaled documents stay in the LEN class")
}

/// The identity rule: every default.
struct Silence;
impl replay_splice::groupless::Rule for Silence {}
impl replay_splice::grouped::Rule for Silence {}

/// The scaled documents' editing rule: commit field 4 (the
/// message frame), rewrite the varint inside it, drop the i64,
/// ride both blobs opaque — allocation must not see their bytes.
struct ScaledEdit;

impl replay_splice::groupless::Rule for ScaledEdit {
    fn on_varint(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _value: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        if field.as_inner() == 6 {
            replay_splice::Scalar::Rewrite(9)
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_i64(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _bits: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        if field.as_inner() == 3 {
            replay_splice::Scalar::Drop
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_len(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _len: protobuf_edit::PayloadLen,
    ) -> replay_splice::Head<'_> {
        if field.as_inner() == 4 {
            replay_splice::Head::Commit { tail: None }
        } else {
            replay_splice::Head::Opaque
        }
    }
}

/// The grouped scaled documents' editing rule: commit the group,
/// rewrite the varint inside it, drop the i64, blobs opaque.
struct ScaledEditGrouped;

impl replay_splice::grouped::Rule for ScaledEditGrouped {
    fn on_varint(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _value: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        if field.as_inner() == 6 {
            replay_splice::Scalar::Rewrite(9)
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_i64(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _bits: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        if field.as_inner() == 3 {
            replay_splice::Scalar::Drop
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_group_enter(
        &mut self,
        _at: u64,
        field: FieldNumber,
    ) -> replay_splice::grouped::Group<'_> {
        if field.as_inner() == 7 {
            replay_splice::grouped::Group::Commit
        } else {
            replay_splice::grouped::Group::Pass
        }
    }
}

// ─── zero-retention rows ───

/// Zero-retention row: payload-×1000 structure-identical
/// documents must produce identical machine allocation
/// fingerprints through the sink face; and the identity job's
/// overlay is one coalesced range — its whole allocation account
/// stays within a handful of machine vectors.
#[test]
fn splice_allocation_is_structure_proportional() {
    let identity = |bytes: &[u8]| {
        let (sunk, count, max, total) = measured(|| {
            let mut sunk = 0u64;
            replay_splice::groupless::splice_sink(
                &mut SliceSource::new(bytes),
                &mut Silence,
                Standard::Tolerant,
                DepthLimit::REFERENCE,
                |view| sunk += view.len() as u64,
            )
            .unwrap();
            sunk
        });
        assert_eq!(sunk, bytes.len() as u64, "the identity job republishes every byte");
        (count, max, total)
    };
    let small = identity(&payload_scaled(64));
    assert_eq!(
        small,
        identity(&payload_scaled(64_000)),
        "the identity splice's allocation moved with payload bytes"
    );
    assert!(small.0 <= 4, "the identity overlay is one coalesced range, not a per-record ledger");

    let edited = |bytes: &[u8]| {
        let (sunk, count, max, total) = measured(|| {
            let mut sunk = 0u64;
            replay_splice::groupless::splice_sink(
                &mut SliceSource::new(bytes),
                &mut ScaledEdit,
                Standard::Tolerant,
                DepthLimit::REFERENCE,
                |view| sunk += view.len() as u64,
            )
            .unwrap();
            sunk
        });
        assert!(sunk > bytes.len() as u64 / 2, "the output flowed through the sink");
        (count, max, total)
    };
    assert_eq!(
        edited(&payload_scaled(64)),
        edited(&payload_scaled(64_000)),
        "the groupless splice's allocation moved with payload bytes"
    );

    let grouped = |bytes: &[u8]| {
        let (sunk, count, max, total) = measured(|| {
            let mut sunk = 0u64;
            replay_splice::grouped::splice_sink(
                &mut SliceSource::new(bytes),
                &mut ScaledEditGrouped,
                Standard::Tolerant,
                DepthLimit::REFERENCE,
                |view| sunk += view.len() as u64,
            )
            .unwrap();
            sunk
        });
        assert!(sunk > bytes.len() as u64 / 2, "the output flowed through the sink");
        (count, max, total)
    };
    assert_eq!(
        grouped(&payload_scaled_grouped(64)),
        grouped(&payload_scaled_grouped(64_000)),
        "the grouped splice's allocation moved with payload bytes"
    );
}

/// Pass-two zero-allocation row: from the first handoff to the
/// job's end, the armed thread's allocation count must not move —
/// the splicing pump owns no allocation (the script and its arena
/// are compiled before any view is handed).
#[test]
fn splice_pass_two_allocates_nothing() {
    let doc = payload_scaled(4_000);
    measured(|| {
        let at_first = Cell::new(None);
        replay_splice::groupless::splice_sink(
            &mut SliceSource::new(&doc),
            &mut ScaledEdit,
            Standard::Tolerant,
            DepthLimit::REFERENCE,
            |_| {
                if at_first.get().is_none() {
                    at_first.set(Some(alloc_count_now()));
                }
            },
        )
        .unwrap();
        assert_eq!(at_first.get(), Some(alloc_count_now()), "the groupless pump allocated");
    });

    let doc = payload_scaled_grouped(4_000);
    measured(|| {
        let at_first = Cell::new(None);
        replay_splice::grouped::splice_sink(
            &mut SliceSource::new(&doc),
            &mut ScaledEditGrouped,
            Standard::Tolerant,
            DepthLimit::REFERENCE,
            |_| {
                if at_first.get().is_none() {
                    at_first.set(Some(alloc_count_now()));
                }
            },
        )
        .unwrap();
        assert_eq!(at_first.get(), Some(alloc_count_now()), "the grouped pump allocated");
    });
}

// ─── pass-count and ask-phase rows ───

/// A rule that witnesses the walk counter at every ask: the rule
/// is called during the first walk alone (the emitter carries no
/// rule reference — this row pins the runtime shadow of that
/// type-level fact).
struct Phased<'s> {
    stats: &'s WalkStats,
    asks: Cell<u32>,
}

impl Phased<'_> {
    fn witness(&self) {
        assert_eq!(self.stats.begins.get(), 1, "an ask fired outside the measuring walk");
        self.asks.set(self.asks.get() + 1);
    }
}

impl replay_splice::groupless::Rule for Phased<'_> {
    fn on_varint(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _value: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        self.witness();
        if field.as_inner() == 6 {
            replay_splice::Scalar::Rewrite(9)
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_i64(
        &mut self,
        _at: u64,
        _field: FieldNumber,
        _bits: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        self.witness();
        replay_splice::Scalar::Drop
    }
    fn on_len(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _len: protobuf_edit::PayloadLen,
    ) -> replay_splice::Head<'_> {
        self.witness();
        if field.as_inner() == 4 {
            replay_splice::Head::Commit { tail: None }
        } else {
            replay_splice::Head::Opaque
        }
    }
    fn on_close(&mut self, _at: u64, _field: FieldNumber) -> replay_splice::Close<'_> {
        self.witness();
        replay_splice::Close::Pass
    }
}

/// Pass-count honesty: a splice is exactly two walks, each walk
/// touches every byte at most once (lent + sought == 2 × length),
/// opaque LEN payloads ride the seek in the measuring walk, and
/// every ask fires during walk one. Chunk partitions differ per
/// walk — the output may not (the slice-source truth pins it).
#[test]
fn splice_pass_counts_and_byte_budgets_hold() {
    let doc = payload_scaled(4_000);
    let stats = WalkStats::default();
    let steps = [97usize, 3, 33, 5];
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    let mut rule = Phased { stats: &stats, asks: Cell::new(0) };
    let out = replay_splice::groupless::splice(
        &mut source,
        &mut rule,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(stats.begins.get(), 2, "a splice is exactly two walks");
    assert_eq!(
        stats.lent.get() + stats.skipped.get(),
        2 * doc.len() as u64,
        "each walk touches every byte exactly once"
    );
    assert!(
        stats.skipped.get() >= 8_000,
        "opaque LEN payloads ride the seek in the measuring walk"
    );
    // One ask per record: two varints, one i64, three LEN heads,
    // two closes (the blobs; the committed frame settles without
    // one).
    assert_eq!(rule.asks.get(), 8);

    // The slice-source baseline under the same edits (the phased
    // rule and the scaled rule agree on this document).
    let expected = replay_splice::groupless::splice(
        &mut SliceSource::new(&doc),
        &mut ScaledEdit,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(out, expected, "chunk partitioning changed the output");

    // The grouped face under the same instrument.
    let doc = payload_scaled_grouped(4_000);
    let stats = WalkStats::default();
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    let out = replay_splice::grouped::splice(
        &mut source,
        &mut ScaledEditGrouped,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(stats.begins.get(), 2, "a grouped splice is exactly two walks");
    assert_eq!(
        stats.lent.get() + stats.skipped.get(),
        2 * doc.len() as u64,
        "each walk touches every byte exactly once"
    );
    assert!(stats.skipped.get() >= 8_000, "both opaque blobs ride the seek");
    let expected = replay_splice::grouped::splice(
        &mut SliceSource::new(&doc),
        &mut ScaledEditGrouped,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(out, expected, "chunk partitioning changed the output");
}

// ─── torn and refusal rows ───

/// The pinned residual row: an equal-length content tear does NOT
/// fault — the emission walk republishes whatever bytes ride its
/// copied extents, so the output differs from the measuring
/// walk's view. The contract's edge, kept on record.
#[test]
fn an_equal_length_content_tear_is_the_pinned_residual() {
    struct DropF2;
    impl replay_splice::groupless::Rule for DropF2 {
        fn on_varint(
            &mut self,
            _at: u64,
            field: FieldNumber,
            _value: u64,
        ) -> replay_splice::Scalar<'_, u64> {
            if field.as_inner() == 2 {
                replay_splice::Scalar::Drop
            } else {
                replay_splice::Scalar::Keep
            }
        }
    }
    let full: &[u8] = &[0x08, 0x96, 0x01, 0x10, 0x2A];

    // The tear lands in a copied extent: no fault, the output
    // carries the emission walk's bytes.
    let torn_copied: &[u8] = &[0x08, 0x97, 0x01, 0x10, 0x2A];
    let mut source = Swapping { walks: &[full, torn_copied], begun: Cell::new(0) };
    let out = replay_splice::groupless::splice(
        &mut source,
        &mut DropF2,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(out, [0x08, 0x97, 0x01], "the copied extent republishes the second walk's bytes");

    // The tear lands in a dropped extent: no fault, and the
    // output cannot see it.
    let torn_dropped: &[u8] = &[0x08, 0x96, 0x01, 0x10, 0x2B];
    let mut source = Swapping { walks: &[full, torn_dropped], begun: Cell::new(0) };
    let out = replay_splice::groupless::splice(
        &mut source,
        &mut DropF2,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(out, [0x08, 0x96, 0x01]);
}

/// A grouped length-shape tear between walks is refused against
/// the measured coordinates (the fold is dialect-shared; this row
/// pins the grouped face's custody of it).
#[test]
fn a_grouped_torn_source_is_refused_between_walks() {
    let full: &[u8] = &[0x13, 0x08, 0x2A, 0x14, 0x08, 0x07];
    let mut source = Swapping { walks: &[full, &full[..3]], begun: Cell::new(0) };
    let fault = replay_splice::grouped::splice(
        &mut source,
        &mut Silence,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap_err();
    assert!(matches!(fault, replay_splice::grouped::JobFault::Torn { .. }));
}

/// Supply refusals carry the emit phase and honest custody: the
/// append face truncates back to its mark, the sink face names
/// the exact handed prefix.
#[test]
fn splice_supply_refusals_carry_phase_and_custody() {
    let doc = payload_scaled(4_000);

    // Refused at the emission walk's begin.
    let mut source =
        Refusing { bytes: &doc, begun: Cell::new(0), refuse_begin: Some(1), refuse_after: None };
    let mut out = vec![0xEE];
    let fault = replay_splice::groupless::splice_into(
        &mut source,
        &mut ScaledEdit,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &mut out,
    )
    .unwrap_err();
    assert!(matches!(
        fault,
        replay_splice::groupless::JobFault::Source(ReplayFault::Rewind {
            phase: ReplayPhase::Emit,
            ..
        })
    ));
    assert_eq!(out, [0xEE], "the append face truncated back to its mark");

    // Refused mid-emission: the measuring walk stays under the
    // lend cap (the blobs ride its seek), the emission walk
    // crosses it copying them.
    let mut source =
        Refusing { bytes: &doc, begun: Cell::new(0), refuse_begin: None, refuse_after: Some(200) };
    let mut handed_total = 0u64;
    let refusal = replay_splice::groupless::splice_sink(
        &mut source,
        &mut ScaledEdit,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        |view| handed_total += view.len() as u64,
    )
    .unwrap_err();
    assert!(matches!(
        refusal.fault,
        replay_splice::groupless::JobFault::Source(ReplayFault::Read {
            phase: ReplayPhase::Emit,
            ..
        })
    ));
    assert!(refusal.handed > 0, "the refusal followed real handoffs");
    assert_eq!(refusal.handed, handed_total, "the sink face names the exact handed prefix");
}

// ─── the differentials against the buffered splicer ───

/// The declared answer bytes both twins share.
const REP: [u8; 3] = [0xCA, 0xFE, 0x42];
const INS: [u8; 2] = [0x78, 0x01];
const TAIL: [u8; 2] = [0x18, 0x07];
const GINS: [u8; 2] = [0x08, 0x05];

/// The buffered leg of the shared program: rewrite varint field
/// 1, drop varint field 8 and i64 field 9, insert before varint
/// field 5, rewrite i32 field 2, replace LEN field 6, drop LEN
/// field 3, commit LEN field 12 with a tail, and re-author LEN
/// field 7 from its own payload (the buffered privilege, straight
/// from the handed slice).
#[derive(Default)]
struct BufferedTwin {
    scratch: Vec<u8>,
}

impl BufferedTwin {
    const fn varint(field: FieldNumber) -> splice::Scalar<'static, u64> {
        match field.as_inner() {
            1 => splice::Scalar::Rewrite(777),
            8 => splice::Scalar::Drop,
            5 => splice::Scalar::Insert(&INS),
            _ => splice::Scalar::Keep,
        }
    }

    fn len<'a>(&'a mut self, field: FieldNumber, payload: &'a [u8]) -> splice::Len<'a> {
        match field.as_inner() {
            6 => splice::Len::Replace(&REP),
            3 => splice::Len::Drop,
            12 => splice::Len::Commit { tail: Some(&TAIL) },
            7 => {
                self.scratch = payload.to_ascii_uppercase();
                splice::Len::Replace(&self.scratch)
            }
            _ => splice::Len::Pass,
        }
    }
}

impl splice::groupless::Rule for BufferedTwin {
    fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> splice::Scalar<'_, u64> {
        Self::varint(field)
    }
    fn on_i32(&mut self, _at: u32, field: FieldNumber, _bits: u32) -> splice::Scalar<'_, u32> {
        if field.as_inner() == 2 {
            splice::Scalar::Rewrite(0xDEAD_BEEF)
        } else {
            splice::Scalar::Keep
        }
    }
    fn on_i64(&mut self, _at: u32, field: FieldNumber, _bits: u64) -> splice::Scalar<'_, u64> {
        if field.as_inner() == 9 { splice::Scalar::Drop } else { splice::Scalar::Keep }
    }
    fn on_len<'a>(
        &'a mut self,
        _at: u32,
        field: FieldNumber,
        payload: &'a [u8],
    ) -> splice::Len<'a> {
        self.len(field, payload)
    }
}

impl splice::grouped::Rule for BufferedTwin {
    fn on_varint(&mut self, _at: u32, field: FieldNumber, _value: u64) -> splice::Scalar<'_, u64> {
        Self::varint(field)
    }
    fn on_i32(&mut self, _at: u32, field: FieldNumber, _bits: u32) -> splice::Scalar<'_, u32> {
        if field.as_inner() == 2 {
            splice::Scalar::Rewrite(0xDEAD_BEEF)
        } else {
            splice::Scalar::Keep
        }
    }
    fn on_i64(&mut self, _at: u32, field: FieldNumber, _bits: u64) -> splice::Scalar<'_, u64> {
        if field.as_inner() == 9 { splice::Scalar::Drop } else { splice::Scalar::Keep }
    }
    fn on_len<'a>(
        &'a mut self,
        _at: u32,
        field: FieldNumber,
        payload: &'a [u8],
    ) -> splice::Len<'a> {
        self.len(field, payload)
    }
    fn on_group_enter(&mut self, _at: u32, field: FieldNumber) -> splice::grouped::Group<'_> {
        match field.as_inner() {
            9 => splice::grouped::Group::Drop,
            10 => splice::grouped::Group::Commit,
            11 => splice::grouped::Group::Insert(&GINS),
            _ => splice::grouped::Group::Pass,
        }
    }
}

/// The replay leg of the same program: field 7's payload arrives
/// as observed fragments instead of a handed slice.
#[derive(Default)]
struct ReplayTwin {
    scratch: Vec<u8>,
}

impl ReplayTwin {
    const fn varint(field: FieldNumber) -> replay_splice::Scalar<'static, u64> {
        match field.as_inner() {
            1 => replay_splice::Scalar::Rewrite(777),
            8 => replay_splice::Scalar::Drop,
            5 => replay_splice::Scalar::Insert(&INS),
            _ => replay_splice::Scalar::Keep,
        }
    }

    fn head(&mut self, field: FieldNumber) -> replay_splice::Head<'static> {
        match field.as_inner() {
            12 => replay_splice::Head::Commit { tail: Some(&TAIL) },
            7 => {
                self.scratch.clear();
                replay_splice::Head::Observe
            }
            _ => replay_splice::Head::Opaque,
        }
    }

    fn close(&mut self, field: FieldNumber) -> replay_splice::Close<'_> {
        match field.as_inner() {
            6 => replay_splice::Close::Replace(&REP),
            3 => replay_splice::Close::Drop,
            7 => {
                self.scratch.make_ascii_uppercase();
                replay_splice::Close::Replace(&self.scratch)
            }
            _ => replay_splice::Close::Pass,
        }
    }
}

impl replay_splice::groupless::Rule for ReplayTwin {
    fn on_varint(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _value: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        Self::varint(field)
    }
    fn on_i32(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _bits: u32,
    ) -> replay_splice::Scalar<'_, u32> {
        if field.as_inner() == 2 {
            replay_splice::Scalar::Rewrite(0xDEAD_BEEF)
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_i64(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _bits: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        if field.as_inner() == 9 {
            replay_splice::Scalar::Drop
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_len(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _len: protobuf_edit::PayloadLen,
    ) -> replay_splice::Head<'_> {
        self.head(field)
    }
    fn on_fragment(&mut self, _at: u64, view: &[u8]) {
        self.scratch.extend_from_slice(view);
    }
    fn on_close(&mut self, _at: u64, field: FieldNumber) -> replay_splice::Close<'_> {
        self.close(field)
    }
}

impl replay_splice::grouped::Rule for ReplayTwin {
    fn on_varint(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _value: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        Self::varint(field)
    }
    fn on_i32(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _bits: u32,
    ) -> replay_splice::Scalar<'_, u32> {
        if field.as_inner() == 2 {
            replay_splice::Scalar::Rewrite(0xDEAD_BEEF)
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_i64(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _bits: u64,
    ) -> replay_splice::Scalar<'_, u64> {
        if field.as_inner() == 9 {
            replay_splice::Scalar::Drop
        } else {
            replay_splice::Scalar::Keep
        }
    }
    fn on_len(
        &mut self,
        _at: u64,
        field: FieldNumber,
        _len: protobuf_edit::PayloadLen,
    ) -> replay_splice::Head<'_> {
        self.head(field)
    }
    fn on_fragment(&mut self, _at: u64, view: &[u8]) {
        self.scratch.extend_from_slice(view);
    }
    fn on_close(&mut self, _at: u64, field: FieldNumber) -> replay_splice::Close<'_> {
        self.close(field)
    }
    fn on_group_enter(
        &mut self,
        _at: u64,
        field: FieldNumber,
    ) -> replay_splice::grouped::Group<'_> {
        match field.as_inner() {
            9 => replay_splice::grouped::Group::Drop,
            10 => replay_splice::grouped::Group::Commit,
            11 => replay_splice::grouped::Group::Insert(&GINS),
            _ => replay_splice::grouped::Group::Pass,
        }
    }
}

#[test]
fn splice_matches_the_buffered_twin_over_the_groupless_corpus() {
    for (nth, doc) in corpus(false).iter().enumerate() {
        compare_groupless(nth, doc);
        // The one-short prefix: both machines must refuse the
        // truncation at the same coordinate.
        if doc.len() > 1 {
            compare_groupless(nth, &doc[..doc.len() - 1]);
        }
    }
}

fn compare_groupless(nth: usize, doc: &[u8]) {
    let buffered_out = splice::groupless::splice(
        doc,
        &mut BufferedTwin::default(),
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    );
    let replay_out = replay_splice::groupless::splice(
        &mut SliceSource::new(doc),
        &mut ReplayTwin::default(),
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    );
    match (buffered_out, replay_out) {
        (Ok(b_bytes), Ok(r_bytes)) => {
            assert_eq!(r_bytes, b_bytes, "doc {nth}: output bytes diverged");
        }
        (Err(b_fault), Err(r_fault)) => {
            let replay_splice::groupless::JobFault::Document(fault) = r_fault else {
                panic!("doc {nth}: the slice source cannot fault the supply, got {r_fault:?}");
            };
            assert_eq!(fault.at(), u64::from(b_fault.at()), "doc {nth}: coordinates diverged");
            assert_eq!(fault.trail().len(), b_fault.trail().len(), "doc {nth}: trails diverged");
            for (mine, theirs) in fault.trail().iter().zip(b_fault.trail()) {
                assert_eq!(mine.field(), theirs.field(), "doc {nth}");
                assert_eq!(mine.at(), u64::from(theirs.at()), "doc {nth}");
            }
        }
        (buffered_out, replay_out) => panic!(
            "doc {nth}: verdicts diverged (buffered ok: {}, replay ok: {})",
            buffered_out.is_ok(),
            replay_out.is_ok()
        ),
    }
}

#[test]
fn splice_matches_the_buffered_twin_over_the_grouped_corpus() {
    for (nth, doc) in corpus(true).iter().enumerate() {
        compare_grouped(nth, doc);
        if doc.len() > 1 {
            compare_grouped(nth, &doc[..doc.len() - 1]);
        }
    }
}

fn compare_grouped(nth: usize, doc: &[u8]) {
    let buffered_out = splice::grouped::splice(
        doc,
        &mut BufferedTwin::default(),
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    );
    let replay_out = replay_splice::grouped::splice(
        &mut SliceSource::new(doc),
        &mut ReplayTwin::default(),
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    );
    match (buffered_out, replay_out) {
        (Ok(b_bytes), Ok(r_bytes)) => {
            assert_eq!(r_bytes, b_bytes, "doc {nth}: output bytes diverged");
        }
        (Err(b_fault), Err(r_fault)) => {
            let replay_splice::grouped::JobFault::Document(fault) = r_fault else {
                panic!("doc {nth}: the slice source cannot fault the supply, got {r_fault:?}");
            };
            assert_eq!(fault.at(), u64::from(b_fault.at()), "doc {nth}: coordinates diverged");
            assert_eq!(fault.trail().len(), b_fault.trail().len(), "doc {nth}: trails diverged");
            for (mine, theirs) in fault.trail().iter().zip(b_fault.trail()) {
                assert_eq!(mine.field(), theirs.field(), "doc {nth}");
                assert_eq!(mine.at(), u64::from(theirs.at()), "doc {nth}");
            }
        }
        (buffered_out, replay_out) => panic!(
            "doc {nth}: verdicts diverged (buffered ok: {}, replay ok: {})",
            buffered_out.is_ok(),
            replay_out.is_ok()
        ),
    }
}
