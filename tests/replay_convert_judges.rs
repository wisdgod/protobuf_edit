//! The replay convert cells' in-lane judge battery: pass-count and
//! byte-budget honesty over a counting source (every face's
//! two-walk claim gets the landed instrument), the pass-two
//! zero-allocation row, rollback custody on both fault phases,
//! supply-refusal and torn rows (the pinned equal-length residual
//! included), per-direction nested-cascade and fidelity fixtures,
//! and the domain-split differentials against the buffered
//! converter over the slice source.

#![cfg(all(
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "construct-grouped"
))]
#![feature(thread_id_value)]

#[path = "support/replay.rs"]
mod replay;

use std::cell::Cell;

use protobuf_edit::path::{Program, Segment};
use protobuf_edit::replay_convert::{grouped as to_grouped, groupless as to_groupless};
use protobuf_edit::replay_source::{
    Chunk, ReplayFault, ReplayPhase, ReplayWalk, SliceFault, SliceSource, StableReplaySource,
    SupplyFault,
};
use protobuf_edit::{DepthLimit, FieldNumber, Standard, convert};
use replay::{Counting, Refusing, WalkStats, alloc_count_now, corpus, measured, payload_scaled};

const D: DepthLimit = DepthLimit::REFERENCE;

const fn fld(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

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

/// A grouped document with fixed record structure and scaling
/// opaque payloads: one top-level blob, and a group wrapping a
/// nested blob beside a scalar — the byte-budget and allocation
/// instrument for the groupless-out direction.
fn scaled_grouped(payload: usize) -> Vec<u8> {
    let blob = vec![0x5Au8; payload];
    let nested = vec![0xA5u8; payload];
    let mut builder = protobuf_edit::construct::grouped::Builder::new();
    builder.push_varint(fld(1), 150);
    builder.push_len(fld(2), &blob);
    builder.group(fld(6), |g| {
        g.push_len_copy(fld(4), &nested);
        g.push_varint(fld(5), 3);
    });
    builder.finish().expect("the scaled documents stay in the LEN class")
}

/// The routed-f1/targeted-f16 groupless twin: a routed crossing
/// (f1) holding a designated container (f16) and an opaque blob,
/// beside a top-level opaque blob — the grouped-out direction's
/// byte-budget instrument.
fn routed_targeted(payload: usize) -> Vec<u8> {
    let blob = vec![0x5Au8; payload];
    let mut builder = protobuf_edit::construct::grouped::Builder::new();
    builder.push_varint(fld(2), 150);
    builder.push_len(fld(2), &blob);
    builder.message(fld(1), |m| {
        m.message(fld(16), |mm| {
            mm.push_varint(fld(2), 5);
        });
        m.push_len_copy(fld(2), &blob);
    });
    builder.finish().expect("the scaled documents stay in the LEN class")
}

/// The grouped-out designation: f16 targeted through f1 — f1
/// occurrences become routed crossings, f16 occurrences inside
/// them convert.
const fn crossing_paths() -> [[Segment<'static>; 2]; 1] {
    [[Segment::Field(fld(1)), Segment::Field(fld(16))]]
}

// ─── pass-count and byte-budget rows ───

/// Pass-count honesty: a sink-face conversion is exactly two
/// walks, each walk touches every byte at most once
/// (lent + sought == 2 × length), opaque LEN payloads ride the
/// seek in the measuring walk, and chunk partitions differ per
/// walk while the output may not (the slice-source truth pins it).
#[test]
fn replay_convert_sink_pass_counts_and_byte_budgets_hold() {
    // The groupless-out direction over a group-bearing document.
    let doc = scaled_grouped(4_000);
    let stats = WalkStats::default();
    let steps = [97usize, 3, 33, 5];
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    let mut out = Vec::new();
    let receipt = to_groupless::convert_sink(&mut source, Standard::Tolerant, D, |view| {
        out.extend_from_slice(view)
    })
    .unwrap();
    assert_eq!(stats.begins.get(), 2, "a sink conversion is exactly two walks");
    assert_eq!(
        stats.lent.get() + stats.skipped.get(),
        2 * doc.len() as u64,
        "each walk touches every byte exactly once"
    );
    assert!(
        stats.skipped.get() >= 8_000,
        "opaque LEN payloads ride the seek in the measuring walk"
    );
    assert_eq!(receipt.converted(), 1);
    let (expected, expected_stats) =
        to_groupless::convert(&mut SliceSource::new(&doc), Standard::Tolerant, D).unwrap();
    assert_eq!(out, expected, "chunk partitioning changed the output");
    assert_eq!(receipt, expected_stats);

    // The grouped-out direction over the routed-f1/targeted-f16
    // fixture.
    let doc = routed_targeted(4_000);
    let paths = crossing_paths();
    let slices: [&[Segment<'_>]; 1] = [&paths[0]];
    let program = Program::over(&slices).unwrap();
    let stats = WalkStats::default();
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    let mut out = Vec::new();
    let receipt = to_grouped::convert_sink(&mut source, program, Standard::Tolerant, D, |view| {
        out.extend_from_slice(view)
    })
    .unwrap();
    assert_eq!(stats.begins.get(), 2, "a grouped-out sink conversion is exactly two walks");
    assert_eq!(
        stats.lent.get() + stats.skipped.get(),
        2 * doc.len() as u64,
        "each walk touches every byte exactly once"
    );
    assert!(stats.skipped.get() >= 8_000, "both unrouted blobs ride the seek");
    assert_eq!((receipt.converted(), receipt.descended()), (1, 1));
    let (expected, expected_stats) =
        to_grouped::convert(&mut SliceSource::new(&doc), program, Standard::Tolerant, D).unwrap();
    assert_eq!(out, expected, "chunk partitioning changed the output");
    assert_eq!(receipt, expected_stats);
}

/// The Vec faces hold the same two-walk contract as the sink:
/// every face is measure/compile then zero-parse fold, so the
/// fresh and append faces' begin counts pin at exactly two, both
/// directions.
#[test]
fn replay_convert_vec_faces_walk_exactly_twice() {
    let steps = [97usize, 3, 33, 5];

    let doc = scaled_grouped(4_000);
    let stats = WalkStats::default();
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    to_groupless::convert(&mut source, Standard::Tolerant, D).unwrap();
    assert_eq!(stats.begins.get(), 2, "a fresh-buffer conversion is exactly two walks");

    let stats = WalkStats::default();
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    let mut out = Vec::new();
    to_groupless::convert_into(&mut source, Standard::Tolerant, D, &mut out).unwrap();
    assert_eq!(stats.begins.get(), 2, "an append conversion is exactly two walks");

    let doc = routed_targeted(4_000);
    let paths = crossing_paths();
    let slices: [&[Segment<'_>]; 1] = [&paths[0]];
    let program = Program::over(&slices).unwrap();

    let stats = WalkStats::default();
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    to_grouped::convert(&mut source, program, Standard::Tolerant, D).unwrap();
    assert_eq!(stats.begins.get(), 2, "a grouped-out fresh conversion is exactly two walks");

    let stats = WalkStats::default();
    let mut source = Counting { bytes: &doc, steps: &steps, stats: &stats };
    let mut out = Vec::new();
    to_grouped::convert_into(&mut source, program, Standard::Tolerant, D, &mut out).unwrap();
    assert_eq!(stats.begins.get(), 2, "a grouped-out append conversion is exactly two walks");
}

/// Pass-two zero-allocation row: from the first handoff to the
/// job's end, the armed thread's allocation count must not move —
/// the splicing pump owns no allocation (the script and its slots
/// are compiled before any view is handed).
#[test]
fn replay_convert_pass_two_allocates_nothing() {
    let doc = scaled_grouped(4_000);
    measured(|| {
        let at_first = Cell::new(None);
        to_groupless::convert_sink(&mut SliceSource::new(&doc), Standard::Tolerant, D, |_| {
            if at_first.get().is_none() {
                at_first.set(Some(alloc_count_now()));
            }
        })
        .unwrap();
        assert_eq!(at_first.get(), Some(alloc_count_now()), "the groupless-out pump allocated");
    });

    let doc = routed_targeted(4_000);
    let paths = crossing_paths();
    let slices: [&[Segment<'_>]; 1] = [&paths[0]];
    let program = Program::over(&slices).unwrap();
    measured(|| {
        let at_first = Cell::new(None);
        to_grouped::convert_sink(
            &mut SliceSource::new(&doc),
            program,
            Standard::Tolerant,
            D,
            |_| {
                if at_first.get().is_none() {
                    at_first.set(Some(alloc_count_now()));
                }
            },
        )
        .unwrap();
        assert_eq!(at_first.get(), Some(alloc_count_now()), "the grouped-out pump allocated");
    });
}

// ─── rollback custody (fault-class independent) ───

/// The append faces' untouched-buffer law on a small pass-one
/// document fault, and truncate-to-mark on a small pass-two tear —
/// rollback is fault-class independent (Growth is a pass-one
/// refusal and can never observe an appended byte).
#[test]
fn replay_convert_append_faces_roll_back_to_their_marks() {
    let paths = crossing_paths();
    let slices: [&[Segment<'_>]; 1] = [&paths[0]];
    let program = Program::over(&slices).unwrap();

    // A pass-one document fault (field zero): the buffer is
    // byte-untouched.
    let broken = [0x00, 0x01];
    let mut out = vec![0xEE];
    assert!(
        to_groupless::convert_into(&mut SliceSource::new(&broken), Standard::Tolerant, D, &mut out)
            .is_err()
    );
    assert_eq!(out, [0xEE]);
    assert!(
        to_grouped::convert_into(
            &mut SliceSource::new(&broken),
            program,
            Standard::Tolerant,
            D,
            &mut out
        )
        .is_err()
    );
    assert_eq!(out, [0xEE]);

    // A pass-two length-shape tear: appended bytes truncate back
    // to the entry mark.
    let full: &[u8] = &[0x08, 0x96, 0x01, 0x10, 0x2A];
    let mut source = Swapping { walks: &[full, &full[..4]], begun: Cell::new(0) };
    let fault =
        to_groupless::convert_into(&mut source, Standard::Tolerant, D, &mut out).unwrap_err();
    assert!(matches!(fault, to_groupless::JobFault::Torn { .. }));
    assert_eq!(out, [0xEE], "the buffer is back at its entry mark");

    let mut source = Swapping { walks: &[full, &full[..4]], begun: Cell::new(0) };
    let fault = to_grouped::convert_into(&mut source, program, Standard::Tolerant, D, &mut out)
        .unwrap_err();
    assert!(matches!(fault, to_grouped::JobFault::Torn { .. }));
    assert_eq!(out, [0xEE]);
}

/// Supply refusals carry the emit phase and honest custody: the
/// append face truncates back to its mark, the sink face names
/// the exact handed prefix.
#[test]
fn replay_convert_supply_refusals_carry_phase_and_custody() {
    let doc = scaled_grouped(4_000);

    // Refused at the emission walk's begin.
    let mut source =
        Refusing { bytes: &doc, begun: Cell::new(0), refuse_begin: Some(1), refuse_after: None };
    let mut out = vec![0xEE];
    let fault =
        to_groupless::convert_into(&mut source, Standard::Tolerant, D, &mut out).unwrap_err();
    assert!(matches!(
        fault,
        to_groupless::JobFault::Source(ReplayFault::Rewind { phase: ReplayPhase::Emit, .. })
    ));
    assert_eq!(out, [0xEE], "the append face truncated back to its mark");

    // Refused mid-emission: the measuring walk stays under the
    // lend cap (the blobs ride its seek), the emission walk
    // crosses it copying them.
    let mut source =
        Refusing { bytes: &doc, begun: Cell::new(0), refuse_begin: None, refuse_after: Some(200) };
    let mut handed_total = 0u64;
    let refusal = to_groupless::convert_sink(&mut source, Standard::Tolerant, D, |view| {
        handed_total += view.len() as u64
    })
    .unwrap_err();
    assert!(matches!(
        refusal.fault,
        to_groupless::JobFault::Source(ReplayFault::Read { phase: ReplayPhase::Emit, .. })
    ));
    assert!(refusal.handed > 0, "the refusal followed real handoffs");
    assert_eq!(refusal.handed, handed_total, "the sink face names the exact handed prefix");

    // A pass-one document fault hands the sink nothing.
    let mut handed = Vec::new();
    let refusal =
        to_groupless::convert_sink(&mut SliceSource::new(&[0x00]), Standard::Tolerant, D, |view| {
            handed.extend_from_slice(view)
        })
        .unwrap_err();
    assert_eq!(refusal.handed, 0);
    assert!(handed.is_empty());
}

// ─── torn and residual rows ───

/// The pinned residual row: an equal-length content tear does NOT
/// fault — the emission walk republishes whatever bytes ride its
/// copied extents, and a tear inside a dropped extent (the group
/// framing conversion discards) is invisible. The contract's
/// edge, kept on record.
#[test]
fn replay_convert_an_equal_length_content_tear_is_the_pinned_residual() {
    // The tear lands in a copied extent: no fault, the output
    // carries the emission walk's bytes.
    let full: &[u8] = &[0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let torn_copied: &[u8] = &[0x08, 0x97, 0x01, 0x13, 0x18, 0x01, 0x14];
    let mut source = Swapping { walks: &[full, torn_copied], begun: Cell::new(0) };
    let (out, _) = to_groupless::convert(&mut source, Standard::Tolerant, D).unwrap();
    assert_eq!(
        out,
        [0x08, 0x97, 0x01, 0x12, 0x02, 0x18, 0x01],
        "the copied extent republishes the second walk's bytes"
    );

    // The tear lands in a dropped extent (the group's end tag):
    // no fault, and the output cannot see it.
    let torn_dropped: &[u8] = &[0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x0C];
    let mut source = Swapping { walks: &[full, torn_dropped], begun: Cell::new(0) };
    let (out, _) = to_groupless::convert(&mut source, Standard::Tolerant, D).unwrap();
    assert_eq!(out, [0x08, 0x96, 0x01, 0x12, 0x02, 0x18, 0x01]);
}

/// A length-shape tear between walks is refused against the
/// measured coordinates, in both directions.
#[test]
fn replay_convert_a_torn_source_is_refused_between_walks() {
    let full: &[u8] = &[0x13, 0x08, 0x2A, 0x14, 0x08, 0x07];
    let mut source = Swapping { walks: &[full, &full[..3]], begun: Cell::new(0) };
    let fault = to_groupless::convert(&mut source, Standard::Tolerant, D).unwrap_err();
    assert!(matches!(fault, to_groupless::JobFault::Torn { .. }));

    let paths = crossing_paths();
    let slices: [&[Segment<'_>]; 1] = [&paths[0]];
    let program = Program::over(&slices).unwrap();
    let full: &[u8] = &[0x0A, 0x05, 0x82, 0x01, 0x02, 0x08, 0x01, 0x08, 0x07];
    let mut source = Swapping { walks: &[full, &full[..5]], begun: Cell::new(0) };
    let fault = to_grouped::convert(&mut source, program, Standard::Tolerant, D).unwrap_err();
    assert!(matches!(fault, to_grouped::JobFault::Torn { .. }));
}

// ─── per-direction cascades and fidelity ───

/// One small nested cascade per direction, byte-pinned: prefixes
/// settle bottom-up in the groupless-out direction, and a crossed
/// prefix re-settles around a nested conversion in the grouped-out
/// direction.
#[test]
fn replay_convert_nested_cascades_settle_per_direction() {
    // group f2 { group f3 { varint f1=1 } · varint f1=2 }:
    // the inner body settles before the outer prefix is knowable.
    let msg = [0x13, 0x1B, 0x08, 0x01, 0x1C, 0x08, 0x02, 0x14];
    let (out, stats) =
        to_groupless::convert(&mut SliceSource::new(&msg), Standard::Tolerant, D).unwrap();
    assert_eq!(out, [0x12, 0x06, 0x1A, 0x02, 0x08, 0x01, 0x08, 0x02]);
    assert_eq!(stats.converted(), 2);

    // LEN f1 [ LEN f16 [ varint f2=5 ] ]: f16 converts (framing
    // grows one byte), and the crossed f1 prefix re-settles.
    let paths = crossing_paths();
    let slices: [&[Segment<'_>]; 1] = [&paths[0]];
    let program = Program::over(&slices).unwrap();
    let msg = [0x0A, 0x05, 0x82, 0x01, 0x02, 0x10, 0x05, 0x08, 0x07];
    let (out, stats) =
        to_grouped::convert(&mut SliceSource::new(&msg), program, Standard::Tolerant, D).unwrap();
    assert_eq!(out, [0x0A, 0x06, 0x83, 0x01, 0x10, 0x05, 0x84, 0x01, 0x08, 0x07]);
    assert_eq!((stats.converted(), stats.descended()), (1, 1));
}

/// Fidelity fixtures: padded spellings ride byte-verbatim under
/// `Tolerant` — outside and inside converted bodies — and
/// wire-type re-authoring rewrites multi-byte tags at high field
/// numbers minimally.
#[test]
fn replay_convert_fidelity_rides_padded_words_and_reauthors_wide_tags() {
    // groupless-out: a padded value outside every group, a padded
    // value inside a converted body, and a padded opaque-LEN
    // prefix all ride verbatim; only the group framing is
    // re-authored.
    let msg = [
        0x08, 0x96, 0x81, 0x00, // varint f1, value 150 padded to three bytes
        0x13, 0x18, 0x81, 0x00, 0x14, // group f2 { varint f3, value 1 padded }
        0x12, 0x82, 0x00, 0x68, 0x69, // LEN f2, prefix 2 padded to two bytes
    ];
    let (out, _) =
        to_groupless::convert(&mut SliceSource::new(&msg), Standard::Tolerant, D).unwrap();
    assert_eq!(
        out,
        [0x08, 0x96, 0x81, 0x00, 0x12, 0x03, 0x18, 0x81, 0x00, 0x12, 0x82, 0x00, 0x68, 0x69]
    );

    // The canonical standard refuses the first padded word it
    // walks instead.
    let fault = to_groupless::convert(&mut SliceSource::new(&msg), Standard::CanonicalMinimal, D)
        .unwrap_err();
    let to_groupless::JobFault::Document(fault) = fault else { panic!("document fault expected") };
    assert_eq!(fault.at(), 1);
    assert!(matches!(
        fault.kind(),
        to_groupless::FaultKind::Wire(to_groupless::WireBreach::NonMinimal)
    ));

    // High field numbers re-author multi-byte tags: group f300000
    // becomes LEN f300000 (four-byte tags both ways), byte-pinned
    // against the buffered twin.
    let wide = fld(300_000);
    let mut builder = protobuf_edit::construct::grouped::Builder::new();
    builder.group(wide, |g| {
        g.push_varint(fld(1), 7);
    });
    let msg = builder.finish().unwrap();
    let (out, _) =
        to_groupless::convert(&mut SliceSource::new(&msg), Standard::Tolerant, D).unwrap();
    let (expected, _) =
        convert::groupless::Converter::new(Standard::Tolerant, D).convert(&msg).unwrap();
    assert_eq!(out, expected);

    // grouped-out: the same wide field converts back, and padded
    // words the conversion does not touch ride verbatim.
    let wide_paths: [&[Segment<'_>]; 1] = [&[Segment::Field(wide)]];
    let wide_program = Program::over(&wide_paths).unwrap();
    let (back, _) =
        to_grouped::convert(&mut SliceSource::new(&out), wide_program, Standard::Tolerant, D)
            .unwrap();
    assert_eq!(back, msg, "the round trip through the wide tag is the identity");

    let padded = [0x08, 0x96, 0x81, 0x00, 0x12, 0x00];
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(fld(2))]];
    let program = Program::over(&paths).unwrap();
    let (out, _) =
        to_grouped::convert(&mut SliceSource::new(&padded), program, Standard::Tolerant, D)
            .unwrap();
    assert_eq!(out, [0x08, 0x96, 0x81, 0x00, 0x13, 0x14], "the untouched padded word rides");
}

/// Opacity under group-punctuation payloads: a LEN payload whose
/// bytes spell group codes stays opaque in the groupless-out walk
/// and under an unrouted grouped-out designation — the machine
/// never guesses messageness.
#[test]
fn replay_convert_opaque_payloads_spelling_group_punctuation_stay_opaque() {
    // LEN f2 carrying exactly a group open/end pair's spelling.
    let msg = [0x12, 0x02, 0x0B, 0x0C];
    let (out, stats) =
        to_groupless::convert(&mut SliceSource::new(&msg), Standard::Tolerant, D).unwrap();
    assert_eq!(out, msg);
    assert_eq!(stats.converted(), 0);

    // Unrouted under the grouped-out program: the payload's group
    // spelling would refuse the groupless walk if it were entered;
    // riding verbatim proves opacity.
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(fld(9))]];
    let program = Program::over(&paths).unwrap();
    let (out, stats) =
        to_grouped::convert(&mut SliceSource::new(&msg), program, Standard::Tolerant, D).unwrap();
    assert_eq!(out, msg);
    assert_eq!((stats.converted(), stats.descended()), (0, 0));
}

// ─── the differentials against the buffered converter ───

const fn same_groupless_breach(
    b: convert::groupless::WireBreach,
    r: to_groupless::WireBreach,
) -> bool {
    use convert::groupless::WireBreach as B;
    use to_groupless::WireBreach as R;
    matches!(
        (b, r),
        (B::Varint, R::Varint)
            | (B::Tag, R::Tag)
            | (B::Truncated, R::Truncated)
            | (B::Grouping, R::Grouping)
            | (B::Depth, R::Depth)
            | (B::NonMinimal, R::NonMinimal)
    )
}

const fn same_grouped_breach(b: convert::grouped::WireBreach, r: to_grouped::WireBreach) -> bool {
    use convert::grouped::WireBreach as B;
    use to_grouped::WireBreach as R;
    matches!(
        (b, r),
        (B::Varint, R::Varint)
            | (B::Tag, R::Tag)
            | (B::Truncated, R::Truncated)
            | (B::Depth, R::Depth)
            | (B::NonMinimal, R::NonMinimal)
            | (B::GroupCode, R::GroupCode)
    )
}

/// One groupless-out comparison: dual success pins fresh bytes,
/// append-after-sentinel bytes, collected-sink bytes, and every
/// `Stats` field; dual refusal pins the kind and the widened
/// coordinate.
fn compare_groupless(nth: usize, doc: &[u8], standard: Standard) {
    let buffered = convert::groupless::Converter::new(standard, D).convert(doc);
    let fresh = to_groupless::convert(&mut SliceSource::new(doc), standard, D);
    match (buffered, fresh) {
        (Ok((b_bytes, b_stats)), Ok((r_bytes, r_stats))) => {
            assert_eq!(r_bytes, b_bytes, "doc {nth}: fresh bytes diverged");
            assert_eq!(r_stats.converted(), b_stats.converted(), "doc {nth}");

            let mut appended = vec![0xEE];
            let stats =
                to_groupless::convert_into(&mut SliceSource::new(doc), standard, D, &mut appended)
                    .unwrap();
            assert_eq!(appended[0], 0xEE, "doc {nth}");
            assert_eq!(&appended[1..], b_bytes, "doc {nth}: appended bytes diverged");
            assert_eq!(stats, r_stats, "doc {nth}");

            let mut collected = Vec::new();
            let stats = to_groupless::convert_sink(&mut SliceSource::new(doc), standard, D, |v| {
                collected.extend_from_slice(v)
            })
            .unwrap();
            assert_eq!(collected, b_bytes, "doc {nth}: sink bytes diverged");
            assert_eq!(stats, r_stats, "doc {nth}");
        }
        (Err(b_fault), Err(r_fault)) => {
            let to_groupless::JobFault::Document(fault) = r_fault else {
                panic!("doc {nth}: the slice source cannot fault the supply, got {r_fault:?}");
            };
            assert_eq!(fault.at(), u64::from(b_fault.at()), "doc {nth}: coordinates diverged");
            match (b_fault.kind(), fault.kind()) {
                (convert::groupless::FaultKind::Wire(b), to_groupless::FaultKind::Wire(r)) => {
                    assert!(same_groupless_breach(b, r), "doc {nth}: {b:?} vs {r:?}");
                }
                (
                    convert::groupless::FaultKind::Growth { len: b },
                    to_groupless::FaultKind::Growth { len: r },
                ) => assert_eq!(b, r, "doc {nth}"),
                (b, r) => panic!("doc {nth}: kinds diverged ({b:?} vs {r:?})"),
            }
        }
        (buffered, fresh) => panic!(
            "doc {nth}: verdicts diverged (buffered ok: {}, replay ok: {})",
            buffered.is_ok(),
            fresh.is_ok()
        ),
    }
}

#[test]
fn replay_convert_groupless_matches_the_buffered_twin_over_the_grouped_corpus() {
    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        for (nth, doc) in corpus(true).iter().enumerate() {
            compare_groupless(nth, doc, standard);
            // The one-short prefix: both machines must refuse the
            // truncation at the same coordinate.
            if doc.len() > 1 {
                compare_groupless(nth, &doc[..doc.len() - 1], standard);
            }
        }
    }
}

/// One grouped-out comparison under a shared program: dual success
/// pins all three faces' bytes and both `Stats` fields; dual
/// refusal pins the kind, the widened coordinate, and the mapped
/// trail.
fn compare_grouped(nth: usize, doc: &[u8], program: Program<'_>, standard: Standard) {
    let buffered = convert::grouped::Converter::new(standard, D, program).convert(doc);
    let fresh = to_grouped::convert(&mut SliceSource::new(doc), program, standard, D);
    match (buffered, fresh) {
        (Ok((b_bytes, b_stats)), Ok((r_bytes, r_stats))) => {
            assert_eq!(r_bytes, b_bytes, "doc {nth}: fresh bytes diverged");
            assert_eq!(r_stats.converted(), b_stats.converted(), "doc {nth}");
            assert_eq!(r_stats.descended(), b_stats.descended(), "doc {nth}");

            let mut appended = vec![0xEE];
            let stats = to_grouped::convert_into(
                &mut SliceSource::new(doc),
                program,
                standard,
                D,
                &mut appended,
            )
            .unwrap();
            assert_eq!(appended[0], 0xEE, "doc {nth}");
            assert_eq!(&appended[1..], b_bytes, "doc {nth}: appended bytes diverged");
            assert_eq!(stats, r_stats, "doc {nth}");

            let mut collected = Vec::new();
            let stats =
                to_grouped::convert_sink(&mut SliceSource::new(doc), program, standard, D, |v| {
                    collected.extend_from_slice(v)
                })
                .unwrap();
            assert_eq!(collected, b_bytes, "doc {nth}: sink bytes diverged");
            assert_eq!(stats, r_stats, "doc {nth}");
        }
        (Err(b_fault), Err(r_fault)) => {
            let to_grouped::JobFault::Document(fault) = r_fault else {
                panic!("doc {nth}: the slice source cannot fault the supply, got {r_fault:?}");
            };
            assert_eq!(fault.at(), u64::from(b_fault.at()), "doc {nth}: coordinates diverged");
            assert_eq!(fault.trail().len(), b_fault.trail().len(), "doc {nth}: trails diverged");
            for (mine, theirs) in fault.trail().iter().zip(b_fault.trail()) {
                assert_eq!(mine.field(), theirs.field(), "doc {nth}");
                assert_eq!(mine.at(), u64::from(theirs.at()), "doc {nth}");
            }
            match (b_fault.kind(), fault.kind()) {
                (convert::grouped::FaultKind::Wire(b), to_grouped::FaultKind::Wire(r)) => {
                    assert!(same_grouped_breach(b, r), "doc {nth}: {b:?} vs {r:?}");
                }
                (
                    convert::grouped::FaultKind::KindMismatch { path: b },
                    to_grouped::FaultKind::KindMismatch { path: r },
                ) => assert_eq!(b, r, "doc {nth}: designating paths diverged"),
                (
                    convert::grouped::FaultKind::Growth { len: b },
                    to_grouped::FaultKind::Growth { len: r },
                ) => assert_eq!(b, r, "doc {nth}"),
                (b, r) => panic!("doc {nth}: kinds diverged ({b:?} vs {r:?})"),
            }
        }
        (buffered, fresh) => panic!(
            "doc {nth}: verdicts diverged (buffered ok: {}, replay ok: {})",
            buffered.is_ok(),
            fresh.is_ok()
        ),
    }
}

#[test]
fn replay_convert_grouped_matches_the_buffered_twin_over_the_groupless_corpus() {
    // A top-level target (whose scalar occurrences exercise the
    // KindMismatch rows), and a deep target through a wildcard
    // over the whole corpus alphabet (routing every container).
    let all: Vec<FieldNumber> = (1..=24).map(fld).collect();
    let deep: [Segment<'_>; 2] = [Segment::AnyDepth { descend: &all }, Segment::Field(fld(16))];
    let top: [Segment<'_>; 1] = [Segment::Field(fld(2))];
    let slices: [&[Segment<'_>]; 2] = [&top, &deep];
    let program = Program::over(&slices).unwrap();

    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        for (nth, doc) in corpus(false).iter().enumerate() {
            compare_grouped(nth, doc, program, standard);
            if doc.len() > 1 {
                compare_grouped(nth, &doc[..doc.len() - 1], program, standard);
            }
        }
    }

    // The scaled shape with the crossing program keeps the same
    // agreement (the counting fixture's own document).
    let paths = crossing_paths();
    let slices: [&[Segment<'_>]; 1] = [&paths[0]];
    let program = Program::over(&slices).unwrap();
    compare_grouped(usize::MAX, &routed_targeted(64), program, Standard::Tolerant);
    compare_grouped(usize::MAX, &payload_scaled(64), program, Standard::Tolerant);
}
