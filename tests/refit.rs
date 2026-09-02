//! The refit cells' member battery: differentials against the
//! buffered amend twins over the slice source (the honest
//! comparison set — the faces both machines carry with the
//! coordinates widened), the canonical-gate matrix (door and
//! descend × all three refusal sites, grouped end tags included),
//! pass-count honesty over a counting source, torn fixtures over
//! a swapping source, and boundary documents.

#![cfg(all(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "construct-grouped"
))]
#![feature(thread_id_value)]

#[path = "support/replay.rs"]
mod replay;

use std::cell::Cell;

use protobuf_edit::DepthLimit;
use protobuf_edit::replay_source::{
    Chunk, NonMinimalSite, ReplayWalk, SliceFault, SliceSource, StableReplaySource, SupplyFault,
};
use replay::{Counting, WalkStats, corpus, f};

/// An exact field number (the corpus helper `f` shifts by one).
const fn field(n: u32) -> protobuf_edit::FieldNumber {
    protobuf_edit::FieldNumber::new(n).unwrap()
}

// ─── the swapping source (torn and growth rows) ───

/// Serves `walks[n]` to the nth walk (the last entry repeats):
/// the instrument for sources whose bytes move between the index
/// walk and a later walk.
#[derive(Debug)]
struct Swapping<'a> {
    walks: &'a [&'a [u8]],
    begun: Cell<u32>,
}

#[derive(Debug)]
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

/// One deterministic edit program over interchangeable one-shot
/// faces — the differential's shared script. Each op names its
/// target by top-layer position so the twins stay aligned.
#[derive(Clone, Copy, Debug)]
enum Op {
    SetVarint(usize, u64),
    SetI32(usize, u32),
    SetI64(usize, u64),
    SetPayload(usize, &'static [u8]),
    SetPayloadParts(usize),
    Delete(usize),
    InsertVarint(u32, u64),
    InsertPayload(u32, &'static [u8]),
    Descend(usize),
}

/// Deterministic xorshift for the op scripts; no external RNG
/// dependency.
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

/// A seeded op script: value edits, deletions, inserts, scatter
/// installs, and descents interleaved — every arm of the shared
/// commit-only algebra.
fn script(seed: u64, tops: usize) -> Vec<Op> {
    let mut rng = Rng(seed | 1);
    let mut ops = Vec::new();
    for _ in 0..24 {
        let target = usize::try_from(rng.next() % tops.max(1) as u64).unwrap();
        ops.push(match rng.next() % 9 {
            0 => Op::SetVarint(target, rng.next()),
            1 => Op::SetI32(target, u32::try_from(rng.next() >> 32).unwrap()),
            2 => Op::SetI64(target, rng.next()),
            3 => Op::SetPayload(target, b"replaced-payload"),
            4 => Op::SetPayloadParts(target),
            5 => Op::Delete(target),
            6 => Op::InsertVarint(1 + u32::try_from(rng.next() % 20).unwrap(), rng.next()),
            7 => Op::InsertPayload(1 + u32::try_from(rng.next() % 20).unwrap(), b"inserted"),
            _ => Op::Descend(target),
        });
    }
    ops
}

/// The scatter pieces every `SetPayloadParts` op installs on the
/// refit side, concatenating to the bytes the buffered twin
/// installs whole.
const PARTS: [&[u8]; 3] = [b"scat", b"", b"tered"];
const PARTS_WHOLE: &[u8] = b"scattered";

/// Drives one op against both twins and compares the observable
/// outcome; the macro spells the same body for both dialect
/// pairs (the twins' faces are textually identical).
macro_rules! differential_pair {
    ($doc:expr, $seed:expr, $Amend:ty, $Refit:ty) => {{
        let doc: &[u8] = $doc;
        let mut amend = <$Amend>::open(doc, DepthLimit::REFERENCE).expect("corpus documents admit");
        let mut refit = <$Refit>::open(SliceSource::new(doc), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .unwrap();
        assert_eq!(refit.source_len(), doc.len() as u64);
        let amend_tops: Vec<_> = amend.top().collect();
        let refit_tops: Vec<_> = refit.top().collect();
        assert_eq!(amend_tops.len(), refit_tops.len(), "top-layer parity");
        let ops = script($seed, amend_tops.len());
        for op in ops {
            match op {
                Op::SetVarint(target, value) => {
                    let a = amend.set_varint(amend_tops[target], value).is_ok();
                    let b = refit.set_varint(refit_tops[target], value).is_ok();
                    assert_eq!(a, b, "set_varint admission parity at {op:?}");
                }
                Op::SetI32(target, bits) => {
                    let a = amend.set_i32(amend_tops[target], bits).is_ok();
                    let b = refit.set_i32(refit_tops[target], bits).is_ok();
                    assert_eq!(a, b, "set_i32 admission parity at {op:?}");
                }
                Op::SetI64(target, bits) => {
                    let a = amend.set_i64(amend_tops[target], bits).is_ok();
                    let b = refit.set_i64(refit_tops[target], bits).is_ok();
                    assert_eq!(a, b, "set_i64 admission parity at {op:?}");
                }
                Op::SetPayload(target, payload) => {
                    let a = amend.set_payload(amend_tops[target], payload).is_ok();
                    let b = refit.set_payload(refit_tops[target], payload).is_ok();
                    assert_eq!(a, b, "set_payload admission parity at {op:?}");
                }
                Op::SetPayloadParts(target) => {
                    let a = amend.set_payload_parts(amend_tops[target], &PARTS).is_ok();
                    let b = refit.set_payload_parts(refit_tops[target], &PARTS).is_ok();
                    assert_eq!(a, b, "set_payload_parts admission parity at {op:?}");
                }
                Op::Delete(target) => {
                    let a = amend.delete(amend_tops[target]).is_ok();
                    let b = refit.delete(refit_tops[target]).is_ok();
                    assert_eq!(a, b, "delete admission parity at {op:?}");
                }
                Op::InsertVarint(field, value) => {
                    let field = f(u64::from(field));
                    let a = amend.insert_varint(AmendAt::TailOf(None), field, value).is_ok();
                    let b = refit.insert_varint(RefitAt::TailOf(None), field, value).is_ok();
                    assert_eq!(a, b, "insert_varint admission parity at {op:?}");
                }
                Op::InsertPayload(field, payload) => {
                    let field = f(u64::from(field));
                    let a = amend.insert_payload(AmendAt::TailOf(None), field, payload).is_ok();
                    let b = refit.insert_payload(RefitAt::TailOf(None), field, payload).is_ok();
                    assert_eq!(a, b, "insert_payload admission parity at {op:?}");
                }
                Op::Descend(target) => {
                    let a = amend.descend(amend_tops[target]).is_ok();
                    let b = refit.descend(refit_tops[target]).is_ok();
                    assert_eq!(a, b, "descend outcome parity at {op:?}");
                }
            }
            // Observable state matches after every step.
            for (a, b) in amend_tops.iter().zip(&refit_tops) {
                assert_eq!(
                    format!("{:?}", amend.status(*a)),
                    format!("{:?}", refit.status(*b)),
                    "status parity after {op:?}"
                );
            }
            let saved_amend = amend.save().expect("buffered save admits");
            let saved_refit = refit.save().expect("replay save admits");
            assert_eq!(saved_amend, saved_refit, "byte-identical saves after {op:?}");
        }
        // Widened-coordinate parity: price, spans, and the
        // per-record geometry.
        assert_eq!(
            u64::from(amend.save_len().unwrap()),
            refit.save_len().unwrap(),
            "save_len parity"
        );
        let spans_amend = amend.save_spans().unwrap();
        let spans_refit = refit.save_spans().unwrap();
        assert_eq!(spans_amend.len(), spans_refit.len(), "save_spans length parity");
        for ((_, a), (_, b)) in spans_amend.iter().zip(spans_refit.iter()) {
            assert_eq!(u64::from(a.start()), b.start(), "span start parity");
            assert_eq!(u64::from(a.end()), b.end(), "span end parity");
        }
        // The sink faces agree with the owned product.
        let mut streamed = Vec::new();
        refit.save_sink(|view| streamed.extend_from_slice(view)).unwrap();
        assert_eq!(streamed, refit.save().unwrap(), "sink agrees with the owned product");
        // Value reads and payload bytes on the current state.
        for (a, b) in amend_tops.iter().zip(&refit_tops) {
            let kind = format!("{:?}", amend.kind(*a));
            assert_eq!(kind, format!("{:?}", refit.kind(*b)), "kind parity");
            assert_eq!(amend.field(*a), refit.field(*b), "field parity");
            if kind == "Varint" {
                assert_eq!(amend.varint_word(*a), refit.varint_word(*b), "varint word parity");
            }
            if kind == "Len" {
                let mut fetched = Vec::new();
                refit.read_payload(*b, &mut fetched).unwrap();
                match amend.payload_bytes(*a) {
                    Some(expected) => assert_eq!(expected, fetched, "payload byte parity"),
                    // The buffered mixed form answers `None` for a
                    // scatter install; the concatenation is the
                    // fetch contract on both sides of the save.
                    None => assert_eq!(fetched, PARTS_WHOLE, "scatter fetch concatenates"),
                }
            }
            match (amend.span(*a), refit.span(*b)) {
                (Some(a), Some(b)) => {
                    assert_eq!(u64::from(a.start()), b.start(), "record span start parity");
                    assert_eq!(u64::from(a.end()), b.end(), "record span end parity");
                }
                (None, None) => {}
                (a, b) => panic!("span presence parity: {a:?} vs {b:?}"),
            }
        }
        // The batch fetch face hands each live LEN its whole
        // payload, tagged.
        let lens: Vec<_> = refit_tops
            .iter()
            .copied()
            .filter(|&h| {
                format!("{:?}", refit.kind(h)) == "Len"
                    && format!("{:?}", refit.status(h)) != "Deleted"
            })
            .collect();
        let mut whole = vec![Vec::new(); lens.len()];
        refit
            .fetch_payloads(&lens, |handle, view| {
                let at = lens.iter().position(|&h| h == handle).unwrap();
                whole[at].extend_from_slice(view);
            })
            .unwrap();
        for (at, &handle) in lens.iter().enumerate() {
            let mut single = Vec::new();
            refit.read_payload(handle, &mut single).unwrap();
            assert_eq!(whole[at], single, "batch fetch agrees with the single fetch");
        }
        // The reverse index agrees at every byte of the source.
        for pos in 0..doc.len() {
            let a = amend.narrowest(u32::try_from(pos).unwrap()).is_some();
            let b = refit.narrowest(pos as u64).is_some();
            assert_eq!(a, b, "narrowest presence parity at {pos}");
        }
    }};
}

mod groupless_member {
    use protobuf_edit::amend::groupless::{Amend, InsertAt as AmendAt};
    use protobuf_edit::refit::InsertAt as RefitAt;
    use protobuf_edit::refit::groupless::{Descent, FaultKind, OpenFault, Refit};

    use super::*;

    #[test]
    fn the_differential_holds_over_the_seeded_corpus() {
        for (index, doc) in corpus(false).iter().enumerate() {
            differential_pair!(
                doc,
                0x0F17_0000 + index as u64,
                Amend<'_, '_>,
                Refit<'_, SliceSource<'_>>
            );
        }
    }

    #[test]
    fn the_canonical_gate_matrix_holds_at_door_and_descend() {
        // Door × the three sites: the buffered twin refuses the
        // same bytes with its width-bearing refusal trio.
        let padded_tag = [0x88, 0x00, 0x2A];
        let padded_prefix = [0x12, 0x81, 0x00, 0x61];
        let padded_value = [0x08, 0x96, 0x81, 0x00];
        for (doc, site, width) in [
            (&padded_tag[..], NonMinimalSite::Tag, 2),
            (&padded_prefix[..], NonMinimalSite::LenPrefix, 2),
            (&padded_value[..], NonMinimalSite::Value, 3),
        ] {
            assert!(
                matches!(Amend::open(doc, DepthLimit::REFERENCE), Err(AmendOpen::Refused(_))),
                "the buffered canonical door refuses {site:?}"
            );
            let Err((_, OpenFault::Wire(fault))) =
                Refit::open(SliceSource::new(doc), DepthLimit::REFERENCE)
            else {
                panic!("the replay canonical door refuses {site:?}")
            };
            let FaultKind::NonMinimal(refusal) = fault.kind() else {
                panic!("the refusal names the padded construct at {site:?}")
            };
            assert_eq!(format!("{:?}", refusal.site()), format!("{site:?}"));
            assert_eq!(refusal.width(), width, "met width at {site:?}");
            assert!(matches!(fault.kind().class(), protobuf_edit::FaultClass::Policy));
        }

        // Source-descend × the same sites: the refusal parks
        // resident.
        let in_tag = [0x12, 0x03, 0x88, 0x00, 0x2A];
        let in_prefix = [0x12, 0x04, 0x12, 0x81, 0x00, 0x61];
        let in_value = [0x12, 0x04, 0x08, 0x96, 0x81, 0x00];
        for (doc, site) in [
            (&in_tag[..], NonMinimalSite::Tag),
            (&in_prefix[..], NonMinimalSite::LenPrefix),
            (&in_value[..], NonMinimalSite::Value),
        ] {
            let mut refit = Refit::open(SliceSource::new(doc), DepthLimit::REFERENCE)
                .map_err(|(_, fault)| fault)
                .unwrap();
            let top = refit.top().next().unwrap();
            let Descent::Parked(fault) = refit.descend(top).unwrap() else {
                panic!("the padded interior parks at {site:?}")
            };
            let FaultKind::NonMinimal(refusal) = fault.kind() else {
                panic!("the parked refusal names the padded construct at {site:?}")
            };
            assert_eq!(format!("{:?}", refusal.site()), format!("{site:?}"));
            // The verdict is resident.
            assert!(matches!(refit.descend(top).unwrap(), Descent::Parked(_)));
        }
    }

    use protobuf_edit::amend::groupless::OpenFault as AmendOpen;
}

mod grouped_member {
    use protobuf_edit::amend::grouped::{Amend, InsertAt as AmendAt, OpenFault as AmendOpen};
    use protobuf_edit::refit::InsertAt as RefitAt;
    use protobuf_edit::refit::grouped::{FaultKind, OpenFault, Refit};

    use super::*;

    #[test]
    fn the_differential_holds_over_the_seeded_corpus() {
        for (index, doc) in corpus(true).iter().enumerate() {
            differential_pair!(
                doc,
                0x0F17_6000 + index as u64,
                Amend<'_, '_>,
                Refit<'_, SliceSource<'_>>
            );
        }
    }

    #[test]
    fn a_padded_group_end_tag_refuses_in_both_twins() {
        // group f1 { } with its end tag padded to two bytes: the
        // grouped canonical doors judge end tags through the tag
        // site, at the end tag's own offset.
        let padded = [0x0B, 0x8C, 0x00];
        assert!(
            matches!(Amend::open(&padded, DepthLimit::REFERENCE), Err(AmendOpen::Refused(_))),
            "the buffered grouped door refuses the padded end tag"
        );
        let Err((_, OpenFault::Wire(fault))) =
            Refit::open(SliceSource::new(&padded), DepthLimit::REFERENCE)
        else {
            panic!("the replay grouped door refuses the padded end tag")
        };
        assert_eq!(fault.at(), 1);
        let FaultKind::NonMinimal(refusal) = fault.kind() else { panic!("the site is typed") };
        assert!(matches!(refusal.site(), NonMinimalSite::Tag));
        assert_eq!((refusal.width(), refusal.field()), (2, None));
    }

    #[test]
    fn insert_group_matches_the_buffered_twin() {
        let doc = [0x10, 0x2A];
        let mut amend = Amend::open(&doc, DepthLimit::REFERENCE).unwrap();
        let mut refit = Refit::open(SliceSource::new(&doc), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .unwrap();
        let group_field = field(3);
        let a_group = amend.insert_group(AmendAt::TailOf(None), group_field).unwrap();
        let b_group = refit.insert_group(RefitAt::TailOf(None), group_field).unwrap();
        amend.insert_varint(AmendAt::TailOf(Some(a_group)), field(1), 7).unwrap();
        refit.insert_varint(RefitAt::TailOf(Some(b_group)), field(1), 7).unwrap();
        assert_eq!(amend.save().unwrap(), refit.save().unwrap());
    }
}

// ─── walk budgets (pass-count honesty) ───

mod walk_budgets {
    use protobuf_edit::refit::InsertAt;
    use protobuf_edit::refit::groupless::{Descent, Refit};

    use super::*;

    /// varint f1=150 · LEN f2 { varint f1=7 } · LEN f3 "" ·
    /// LEN f2 { varint f1=9 }
    const DOC: [u8; 13] =
        [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07, 0x1A, 0x00, 0x12, 0x02, 0x08, 0x09];

    const fn counted<'a>(stats: &'a WalkStats, steps: &'a [usize]) -> Counting<'a> {
        Counting { bytes: &DOC, steps, stats }
    }

    #[test]
    fn the_budget_table_holds_per_face() {
        let stats = WalkStats::default();
        let mut editor = Refit::open(counted(&stats, &[3, 5, 64]), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .unwrap();
        assert_eq!(stats.begins.get(), 1, "open is one walk");
        let tops: Vec<_> = editor.top().collect();
        // Observation, values, spans, and the reverse index are
        // walk-free.
        for &top in &tops {
            let _ = editor.kind(top);
            let _ = editor.status(top);
            let _ = editor.span(top);
            let _ = editor.source_spans(top);
        }
        let _ = editor.varint_word(tops[0]);
        let _ = editor.narrowest(4);
        assert_eq!(stats.begins.get(), 1, "observation spends no walk");
        // Commands are walk-free.
        editor.set_varint(tops[0], 7).unwrap();
        editor.insert_varint(InsertAt::TailOf(None), field(9), 1).unwrap();
        assert_eq!(stats.begins.get(), 1, "commands spend no walk");
        // save_len and save_spans are walk-free.
        let _ = editor.save_len().unwrap();
        let _ = editor.save_spans().unwrap();
        assert_eq!(stats.begins.get(), 1, "sizing spends no walk");
        // An empty extent opens walk-free.
        assert!(matches!(editor.descend(tops[2]).unwrap(), Descent::Opened { first: None }));
        assert_eq!(stats.begins.get(), 1, "an empty extent opens walk-free");
        // A fresh source descend is one walk; its resident verdict
        // projects walk-free.
        assert!(matches!(editor.descend(tops[1]).unwrap(), Descent::Opened { .. }));
        assert_eq!(stats.begins.get(), 2, "a fresh descend is one walk");
        assert!(matches!(editor.descend(tops[1]).unwrap(), Descent::Opened { .. }));
        assert_eq!(stats.begins.get(), 2, "a resident verdict projects walk-free");
        // Each byte-producing save is one walk; repeated saves are
        // lawful.
        let _ = editor.save().unwrap();
        assert_eq!(stats.begins.get(), 3, "a save is one walk");
        let _ = editor.save().unwrap();
        assert_eq!(stats.begins.get(), 4, "repeated saves cost one walk each");
    }

    #[test]
    fn materialize_and_batch_fetch_settle_in_at_most_one_walk() {
        let stats = WalkStats::default();
        let mut editor = Refit::open(counted(&stats, &[7, 64]), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .unwrap();
        let tops: Vec<_> = editor.top().collect();
        // Two fresh source extents resolve in one source-ordered
        // walk (scattered descents would cost one each).
        editor.materialize(&[tops[3], tops[1]]).unwrap();
        assert_eq!(stats.begins.get(), 2, "a fresh batch is one walk");
        // No fresh source extent remains: resident verdicts and
        // the empty extent settle without mounting a walk.
        editor.materialize(&[tops[1], tops[2], tops[3]]).unwrap();
        assert_eq!(stats.begins.get(), 2, "a settled batch mounts no walk");
        // The batch fetch answers k handles in one walk; each
        // single-handle fetch walks afresh.
        let mut out = Vec::new();
        editor.read_payload(tops[1], &mut out).unwrap();
        assert_eq!(stats.begins.get(), 3, "a scanned fetch is one walk");
        editor.fetch_payloads(&[tops[1], tops[3]], |_, _| {}).unwrap();
        assert_eq!(stats.begins.get(), 4, "a batch fetch is one walk");
    }

    #[test]
    fn authored_payloads_fetch_walk_free() {
        let stats = WalkStats::default();
        let mut editor = Refit::open(counted(&stats, &[9, 64]), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .unwrap();
        let tops: Vec<_> = editor.top().collect();
        // Authored payloads answer from the store (the replacement
        // lands while the target is unopened — commit-only refuses
        // a wholesale replacement of an opened interior).
        editor.set_payload(tops[1], b"zz").unwrap();
        let mut out = Vec::new();
        editor.read_payload(tops[1], &mut out).unwrap();
        assert_eq!(out, b"zz");
        assert_eq!(stats.begins.get(), 1, "authored payloads fetch walk-free");
        editor.fetch_payloads(&[tops[1]], |_, _| {}).unwrap();
        assert_eq!(stats.begins.get(), 1, "an all-authored batch mounts no walk");
    }
}

// ─── torn, growth, and custody rows ───

mod torn_rows {
    use protobuf_edit::refit::SaveFault;
    use protobuf_edit::refit::groupless::{DescendFault, FetchFault, Refit};

    use super::*;

    /// varint f1=150 · LEN f2 { varint f1=7 }
    const DOC: [u8; 7] = [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07];

    fn open(source: Swapping<'_>) -> Refit<'static, Swapping<'_>> {
        Refit::open(source, DepthLimit::REFERENCE).map_err(|(_, fault)| fault).unwrap()
    }

    #[test]
    fn a_shrunk_source_tears_the_descend_and_the_editor_stands() {
        let source = Swapping { walks: &[&DOC, &DOC[..4]], begun: Cell::new(0) };
        let mut editor = open(source);
        let tops: Vec<_> = editor.top().collect();
        match editor.descend(tops[1]) {
            Err(DescendFault::Torn { at }) => assert_eq!(at, 5, "the tear names the extent start"),
            other => panic!("a shrunk source tears: {other:?}"),
        }
        // The slot stayed unopened: a later walk over restored
        // bytes may retry.
        assert_eq!(editor.children(tops[1]).count(), 0);
    }

    #[test]
    fn a_shrunk_source_tears_the_fetch_and_restores_the_buffer() {
        let source = Swapping { walks: &[&DOC, &DOC[..5]], begun: Cell::new(0) };
        let mut editor = open(source);
        let tops: Vec<_> = editor.top().collect();
        let mut out = vec![0xAA];
        match editor.read_payload(tops[1], &mut out) {
            Err(FetchFault::Torn { .. }) => {}
            other => panic!("a shrunk source tears the fetch: {other:?}"),
        }
        assert_eq!(out, [0xAA], "the buffer is byte-identical to entry");
    }

    #[test]
    fn the_save_walk_anchors_the_measured_total() {
        // Shrunk: the copy step runs short.
        let source = Swapping { walks: &[&DOC, &DOC[..6]], begun: Cell::new(0) };
        let mut editor = open(source);
        let mut out = vec![0xEE];
        match editor.save_into(&mut out) {
            Err(SaveFault::Torn { .. }) => {}
            other => panic!("a shrunk source tears the save: {other:?}"),
        }
        assert_eq!(out, [0xEE], "the owned product restores on Err");

        // Grown: the end probe refuses at the measured total.
        const GROWN: [u8; 9] = [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07, 0x08, 0x01];
        let source = Swapping { walks: &[&DOC, &GROWN], begun: Cell::new(0) };
        let mut editor = open(source);
        let mut handed = Vec::new();
        match editor.save_sink(|view| handed.extend_from_slice(view)) {
            Err(handed_fault) => {
                assert!(matches!(handed_fault.fault, SaveFault::Torn { at: 7 }));
                assert_eq!(
                    handed_fault.handed,
                    handed.len() as u64,
                    "the sink names its exact handed prefix"
                );
            }
            Ok(()) => panic!("a grown source refuses at the end probe"),
        }
    }

    #[test]
    fn a_changed_snapshot_surfaces_and_returns_custody_at_open() {
        struct Refusing;
        impl StableReplaySource for Refusing {
            type Error = SliceFault;
            type Walk<'s> = SwappingWalk<'s>;
            fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<SliceFault>> {
                Err(SupplyFault::Changed)
            }
        }
        match Refit::open(Refusing, DepthLimit::REFERENCE) {
            Err((_source, fault)) => {
                assert!(matches!(fault, protobuf_edit::refit::groupless::OpenFault::Source(_)));
            }
            Ok(_) => panic!("a refused begin returns custody beside the mark"),
        }
    }
}

// ─── boundary documents ───

mod boundaries {
    use protobuf_edit::refit::InsertAt;
    use protobuf_edit::refit::groupless::{Descent, EditFault, FrameFault, Refit};

    use super::*;

    fn open(doc: &[u8]) -> Refit<'_, SliceSource<'_>> {
        Refit::open(SliceSource::new(doc), DepthLimit::REFERENCE)
            .map_err(|(_, fault)| fault)
            .unwrap()
    }

    #[test]
    fn the_empty_document_round_trips() {
        let mut editor = open(&[]);
        assert_eq!(editor.source_len(), 0);
        assert_eq!(editor.top().count(), 0);
        assert_eq!(editor.save_len().unwrap(), 0);
        assert_eq!(editor.save().unwrap(), Vec::<u8>::new());
        assert_eq!(editor.narrowest(0), None);
        // Insertion into the empty document authors from nothing.
        editor.insert_varint(InsertAt::TailOf(None), field(1), 1).unwrap();
        assert_eq!(editor.save().unwrap(), [0x08, 0x01]);
    }

    #[test]
    fn the_payload_class_gate_judges_before_any_push() {
        let doc = [0x12, 0x00];
        let mut editor = open(&doc);
        let top = editor.top().next().unwrap();
        let oversized = vec![0u8; usize::try_from(i32::MAX).unwrap() + 1];
        assert!(matches!(
            editor.set_payload(top, &oversized),
            Err(EditFault::PayloadTooLarge { .. })
        ));
        assert_eq!(editor.save().unwrap(), doc, "the refused command changed nothing");
    }

    #[test]
    fn an_empty_payload_descends_and_accepts_insertions() {
        let doc = [0x12, 0x00];
        let mut editor = open(&doc);
        let top = editor.top().next().unwrap();
        assert!(matches!(editor.descend(top).unwrap(), Descent::Opened { first: None }));
        editor.insert_varint(InsertAt::HeadOf(Some(top)), field(1), 5).unwrap();
        assert_eq!(editor.save().unwrap(), [0x12, 0x02, 0x08, 0x05]);
    }

    #[test]
    fn staged_frames_install_exactly_one_command() {
        let doc = [0x12, 0x02, 0x68, 0x69];
        let mut editor = open(&doc);
        let top = editor.top().next().unwrap();
        let mut frame = editor.begin_set_payload(top).unwrap();
        frame.write(&[0x61]).unwrap();
        frame.write(&[0x62, 0x63]).unwrap();
        frame.finish().unwrap();
        assert_eq!(editor.save().unwrap(), [0x12, 0x03, 0x61, 0x62, 0x63]);
        // An abandoned frame installs nothing.
        let mut frame = editor.begin_set_payload(top).unwrap();
        frame.write(b"zzzz").unwrap();
        drop(frame);
        assert_eq!(editor.save().unwrap(), [0x12, 0x03, 0x61, 0x62, 0x63]);
        // The sized twin is held to its declaration.
        let mut frame = editor.begin_set_payload_sized(top, 5).unwrap();
        frame.write(b"wor").unwrap();
        assert!(matches!(frame.write(b"ldX"), Err(FrameFault::OverDeclared { .. })));
        frame.write(b"ld").unwrap();
        frame.finish().unwrap();
        assert_eq!(editor.save().unwrap(), [0x12, 0x05, 0x77, 0x6F, 0x72, 0x6C, 0x64]);
    }

    #[test]
    fn scatter_parts_and_batch_fetch_compose() {
        let doc = [0x12, 0x02, 0x68, 0x69, 0x12, 0x01, 0x61];
        let mut editor = open(&doc);
        let tops: Vec<_> = editor.top().collect();
        let parts: [&[u8]; 2] = [b"he", b"llo"];
        editor.set_payload_parts(tops[0], &parts).unwrap();
        let mut views = Vec::new();
        editor.fetch_payloads(&tops, |handle, view| views.push((handle, view.to_vec()))).unwrap();
        // The scatter answers piece by piece, the scanned extent
        // as the walk lends it; concatenation per handle is the
        // contract.
        let joined: Vec<u8> = views
            .iter()
            .filter(|(h, _)| *h == tops[0])
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect();
        assert_eq!(joined, b"hello");
        assert_eq!(
            editor.save().unwrap(),
            [0x12, 0x05, b'h', b'e', b'l', b'l', b'o', 0x12, 0x01, 0x61]
        );
    }
}
