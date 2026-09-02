//! The maintain cells' member battery: differentials against the
//! buffered markup twins over the slice source (the honest
//! comparison set — the faces both machines carry with the
//! coordinates widened), revision-log replay parity after every
//! step of interleaved edit/revert scripts, pass-count honesty
//! over a counting source (the materialize zero-walk row
//! included), torn fixtures over a swapping source, and boundary
//! documents.

#![cfg(all(
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "construct-grouped"
))]
#![feature(thread_id_value)]

#[path = "support/replay.rs"]
mod replay;

use std::cell::Cell;

use protobuf_edit::replay_source::{
    Chunk, ReplayWalk, SliceFault, SliceSource, StableReplaySource, SupplyFault,
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

/// One deterministic edit program over interchangeable editor
/// faces — the differential's shared script. Each op names its
/// target by top-layer position so the twins stay aligned.
#[derive(Clone, Copy, Debug)]
enum Op {
    SetVarint(usize, u64),
    SetI32(usize, u32),
    SetI64(usize, u64),
    SetPayload(usize, &'static [u8]),
    Delete(usize),
    Undelete(usize),
    ClearEdit(usize),
    InsertVarint(u32, u64),
    InsertPayload(u32, &'static [u8]),
    Descend(usize),
    Revert,
    RevertAll,
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

/// A seeded op script: value edits, shrouds, inserts, descents,
/// and reverts interleaved — every arm of the shared algebra.
fn script(seed: u64, tops: usize) -> Vec<Op> {
    let mut rng = Rng(seed | 1);
    let mut ops = Vec::new();
    for _ in 0..24 {
        let target = usize::try_from(rng.next() % tops.max(1) as u64).unwrap();
        ops.push(match rng.next() % 12 {
            0 => Op::SetVarint(target, rng.next()),
            1 => Op::SetI32(target, u32::try_from(rng.next() >> 32).unwrap()),
            2 => Op::SetI64(target, rng.next()),
            3 => Op::SetPayload(target, b"replaced-payload"),
            4 => Op::Delete(target),
            5 => Op::Undelete(target),
            6 => Op::ClearEdit(target),
            7 => Op::InsertVarint(1 + u32::try_from(rng.next() % 20).unwrap(), rng.next()),
            8 => Op::InsertPayload(1 + u32::try_from(rng.next() % 20).unwrap(), b"inserted"),
            9 => Op::Descend(target),
            10 => Op::Revert,
            _ => Op::RevertAll,
        });
    }
    ops
}

/// Drives one op against both twins and compares the observable
/// outcome; the macro spells the same body for both dialect
/// pairs (the twins' faces are textually identical).
macro_rules! differential_pair {
    ($doc:expr, $seed:expr, $Markup:ty, $Maintain:ty) => {{
        let doc: &[u8] = $doc;
        let mut markup = <$Markup>::open(doc).expect("corpus documents admit");
        let mut maintain =
            <$Maintain>::open(SliceSource::new(doc)).map_err(|(_, fault)| fault).unwrap();
        assert_eq!(maintain.source_len(), doc.len() as u64);
        let markup_tops: Vec<_> = markup.top().collect();
        let maintain_tops: Vec<_> = maintain.top().collect();
        assert_eq!(markup_tops.len(), maintain_tops.len(), "top-layer parity");
        let ops = script($seed, markup_tops.len());
        for op in ops {
            match op {
                Op::SetVarint(target, value) => {
                    let a = markup.set_varint(markup_tops[target], value).is_ok();
                    let b = maintain.set_varint(maintain_tops[target], value).is_ok();
                    assert_eq!(a, b, "set_varint admission parity at {op:?}");
                }
                Op::SetI32(target, bits) => {
                    let a = markup.set_i32(markup_tops[target], bits).is_ok();
                    let b = maintain.set_i32(maintain_tops[target], bits).is_ok();
                    assert_eq!(a, b, "set_i32 admission parity at {op:?}");
                }
                Op::SetI64(target, bits) => {
                    let a = markup.set_i64(markup_tops[target], bits).is_ok();
                    let b = maintain.set_i64(maintain_tops[target], bits).is_ok();
                    assert_eq!(a, b, "set_i64 admission parity at {op:?}");
                }
                Op::SetPayload(target, payload) => {
                    let a = markup.set_payload(markup_tops[target], payload).is_ok();
                    let b = maintain.set_payload(maintain_tops[target], payload).is_ok();
                    assert_eq!(a, b, "set_payload admission parity at {op:?}");
                }
                Op::Delete(target) => {
                    let a = markup.delete(markup_tops[target]).is_ok();
                    let b = maintain.delete(maintain_tops[target]).is_ok();
                    assert_eq!(a, b, "delete admission parity at {op:?}");
                }
                Op::Undelete(target) => {
                    let a = markup.undelete(markup_tops[target]).is_ok();
                    let b = maintain.undelete(maintain_tops[target]).is_ok();
                    assert_eq!(a, b, "undelete admission parity at {op:?}");
                }
                Op::ClearEdit(target) => {
                    let a = markup.clear_edit(markup_tops[target]).is_ok();
                    let b = maintain.clear_edit(maintain_tops[target]).is_ok();
                    assert_eq!(a, b, "clear_edit admission parity at {op:?}");
                }
                Op::InsertVarint(field, value) => {
                    // The dialect modules re-export one shared
                    // InsertAt shape; the caller's aliases name
                    // the same gap on both twins.
                    let field = f(u64::from(field));
                    let a = markup.insert_varint(MarkupAt::TailOf(None), field, value).is_ok();
                    let b = maintain.insert_varint(MaintainAt::TailOf(None), field, value).is_ok();
                    assert_eq!(a, b, "insert_varint admission parity at {op:?}");
                }
                Op::InsertPayload(field, payload) => {
                    let field = f(u64::from(field));
                    let a = markup.insert_payload(MarkupAt::TailOf(None), field, payload).is_ok();
                    let b =
                        maintain.insert_payload(MaintainAt::TailOf(None), field, payload).is_ok();
                    assert_eq!(a, b, "insert_payload admission parity at {op:?}");
                }
                Op::Descend(target) => {
                    let a = markup.descend(markup_tops[target]).is_ok();
                    let b = maintain.descend(maintain_tops[target]).is_ok();
                    assert_eq!(a, b, "descend outcome parity at {op:?}");
                }
                Op::Revert => {
                    let a = markup.revert().is_some();
                    let b = maintain.revert().is_some();
                    assert_eq!(a, b, "revert parity at {op:?}");
                }
                Op::RevertAll => {
                    markup.revert_all();
                    maintain.revert_all();
                }
            }
            // Revision-log replay parity: the observable state
            // matches after every step.
            assert_eq!(markup.pending(), maintain.pending(), "pending parity after {op:?}");
            for (a, b) in markup_tops.iter().zip(&maintain_tops) {
                assert_eq!(
                    format!("{:?}", markup.status(*a)),
                    format!("{:?}", maintain.status(*b)),
                    "status parity after {op:?}"
                );
                assert_eq!(
                    markup.dirty(*a).is_ok_and(|dirty| dirty),
                    maintain.dirty(*b).is_ok_and(|dirty| dirty),
                    "dirty parity after {op:?}"
                );
            }
            let saved_markup = markup.save().expect("buffered save admits");
            let saved_maintain = maintain.save().expect("replay save admits");
            assert_eq!(saved_markup, saved_maintain, "byte-identical saves after {op:?}");
        }
        // Widened-coordinate parity: price, spans, and the
        // per-record geometry.
        assert_eq!(
            u64::from(markup.save_len().unwrap()),
            maintain.save_len().unwrap(),
            "save_len parity"
        );
        let spans_markup = markup.save_spans().unwrap();
        let spans_maintain = maintain.save_spans().unwrap();
        assert_eq!(spans_markup.len(), spans_maintain.len(), "save_spans length parity");
        for ((_, a), (_, b)) in spans_markup.iter().zip(spans_maintain.iter()) {
            assert_eq!(u64::from(a.start()), b.start(), "span start parity");
            assert_eq!(u64::from(a.end()), b.end(), "span end parity");
        }
        // The sink faces agree with the owned product.
        let mut streamed = Vec::new();
        maintain.save_sink(|view| streamed.extend_from_slice(view)).unwrap();
        assert_eq!(streamed, maintain.save().unwrap(), "sink agrees with the owned product");
        // Canonical byte-parity.
        assert_eq!(
            markup.save_canonical().unwrap(),
            maintain.save_canonical().unwrap(),
            "canonical save parity"
        );
        // Value reads and payload bytes on the current state.
        for (a, b) in markup_tops.iter().zip(&maintain_tops) {
            let kind = format!("{:?}", markup.kind(*a).unwrap());
            assert_eq!(kind, format!("{:?}", maintain.kind(*b).unwrap()), "kind parity");
            assert_eq!(markup.field(*a).unwrap(), maintain.field(*b).unwrap(), "field parity");
            if kind == "Varint" {
                assert_eq!(
                    markup.varint_word(*a).unwrap(),
                    maintain.varint_word(*b).unwrap(),
                    "varint word parity"
                );
            }
            if kind == "Len" {
                let expected = markup.payload_bytes(*a).unwrap().to_vec();
                let mut fetched = Vec::new();
                maintain.read_payload(*b, &mut fetched).unwrap();
                assert_eq!(expected, fetched, "payload byte parity");
            }
            match (markup.span(*a).unwrap(), maintain.span(*b).unwrap()) {
                (Some(a), Some(b)) => {
                    assert_eq!(u64::from(a.start()), b.start(), "record span start parity");
                    assert_eq!(u64::from(a.end()), b.end(), "record span end parity");
                }
                (None, None) => {}
                (a, b) => panic!("span presence parity: {a:?} vs {b:?}"),
            }
        }
        // The reverse index agrees at every byte of the source.
        for pos in 0..doc.len() {
            let a = markup.narrowest(u32::try_from(pos).unwrap()).map(|h| format!("{h:?}"));
            let b = maintain.narrowest(pos as u64).map(|h| format!("{h:?}"));
            assert_eq!(a.is_some(), b.is_some(), "narrowest presence parity at {pos}");
        }
        // Reverting everything restores the source, padding
        // included, on both sides.
        markup.revert_all();
        maintain.revert_all();
        assert_eq!(markup.save().unwrap(), doc, "buffered revert_all restores the source");
        assert_eq!(maintain.save().unwrap(), doc, "replay revert_all restores the source");
    }};
}

mod groupless_member {
    use protobuf_edit::maintain::InsertAt as MaintainAt;
    use protobuf_edit::maintain::groupless::{Descent, Maintain};
    use protobuf_edit::markup::groupless::{InsertAt as MarkupAt, Markup};

    use super::*;

    #[test]
    fn the_differential_holds_over_the_seeded_corpus() {
        for (index, doc) in corpus(false).iter().enumerate() {
            differential_pair!(
                doc,
                0x51CE_D000 + index as u64,
                Markup<'_>,
                Maintain<SliceSource<'_>>
            );
        }
    }

    #[test]
    fn parked_verdicts_match_the_buffered_refusal_classes() {
        // LEN f2 wrapping an empty group of field 1: lawful wire
        // outside the groupless language — the buffered twin
        // refuses it as a capability judgment, the replay twin
        // parks the same class.
        let doc = [0x12, 0x02, 0x0B, 0x0C];
        let mut markup = Markup::open(&doc).unwrap();
        let mut maintain =
            Maintain::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let a = markup.top().next().unwrap();
        let b = maintain.top().next().unwrap();
        assert!(matches!(
            markup.descend(a).unwrap(),
            protobuf_edit::markup::groupless::Descent::Refused(_)
        ));
        let Descent::Parked(fault) = maintain.descend(b).unwrap() else {
            panic!("the group code parks")
        };
        assert!(matches!(fault.kind().class(), protobuf_edit::FaultClass::Capability));
        assert_eq!(fault.at().source_at(), Some(2));
        // The verdict is resident: no further walk re-judges it.
        assert!(matches!(maintain.descend(b).unwrap(), Descent::Parked(_)));

        // A wire-grammar fault inside a payload parks as grammar.
        let doc = [0x12, 0x01, 0x00];
        let mut markup = Markup::open(&doc).unwrap();
        let mut maintain =
            Maintain::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let a = markup.top().next().unwrap();
        let b = maintain.top().next().unwrap();
        assert!(matches!(
            markup.descend(a).unwrap(),
            protobuf_edit::markup::groupless::Descent::Faulted(_)
        ));
        let Descent::Parked(fault) = maintain.descend(b).unwrap() else {
            panic!("field zero parks")
        };
        assert!(matches!(fault.kind().class(), protobuf_edit::FaultClass::Grammar));
    }

    #[test]
    fn authored_zone_rows_are_browse_only_in_both_twins() {
        // Replace a LEN payload with a parsable message, descend
        // the authored bytes, and hold both twins to the same
        // browse-only law.
        let doc = [0x12, 0x02, 0x08, 0x01];
        let mut markup = Markup::open(&doc).unwrap();
        let mut maintain =
            Maintain::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let a = markup.top().next().unwrap();
        let b = maintain.top().next().unwrap();
        markup.set_payload(a, &[0x08, 0x07]).unwrap();
        maintain.set_payload(b, &[0x08, 0x07]).unwrap();
        let protobuf_edit::markup::groupless::Descent::Opened { first: Some(inner_a) } =
            markup.descend(a).unwrap()
        else {
            panic!("the authored payload parses")
        };
        let Descent::Opened { first: Some(inner_b) } = maintain.descend(b).unwrap() else {
            panic!("the authored payload parses")
        };
        assert_eq!(markup.varint_word(inner_a).unwrap(), 7);
        assert_eq!(maintain.varint_word(inner_b).unwrap(), 7);
        assert!(markup.set_varint(inner_a, 9).is_err());
        assert!(maintain.set_varint(inner_b, 9).is_err());
        // Reverting the replacement orphans the authored interior
        // in both twins.
        maintain.revert();
        markup.revert();
        assert!(markup.varint_word(inner_a).is_err());
        assert!(maintain.varint_word(inner_b).is_err());
        assert_eq!(maintain.save().unwrap(), doc);
    }
}

mod grouped_member {
    use protobuf_edit::maintain::InsertAt as MaintainAt;
    use protobuf_edit::maintain::grouped::Maintain;
    use protobuf_edit::markup::grouped::{InsertAt as MarkupAt, Markup};

    use super::*;

    #[test]
    fn the_differential_holds_over_the_seeded_corpus() {
        for (index, doc) in corpus(true).iter().enumerate() {
            differential_pair!(
                doc,
                0x6E0F_F000 + index as u64,
                Markup<'_>,
                Maintain<SliceSource<'_>>
            );
        }
    }

    #[test]
    fn group_interiors_edit_and_revert_in_both_twins() {
        // group f1 { varint f2=3 · LEN f3 "ab" } · varint f2=42
        let doc = [0x0B, 0x10, 0x03, 0x1A, 0x02, 0x61, 0x62, 0x0C, 0x10, 0x2A];
        let mut markup = Markup::open(&doc).unwrap();
        let mut maintain =
            Maintain::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let a_group = markup.top().next().unwrap();
        let b_group = maintain.top().next().unwrap();
        let a_kids: Vec<_> = markup.children(a_group).unwrap().collect();
        let b_kids: Vec<_> = maintain.children(b_group).unwrap().collect();
        assert_eq!(a_kids.len(), b_kids.len());
        markup.set_varint(a_kids[0], 300).unwrap();
        maintain.set_varint(b_kids[0], 300).unwrap();
        markup.set_payload(a_kids[1], b"zz").unwrap();
        maintain.set_payload(b_kids[1], b"zz").unwrap();
        assert_eq!(markup.save().unwrap(), maintain.save().unwrap());
        assert_eq!(
            markup.save_canonical().unwrap(),
            maintain.save_canonical().unwrap(),
            "canonical parity around group framing"
        );
        maintain.revert_all();
        markup.revert_all();
        assert_eq!(maintain.save().unwrap(), doc);
    }

    #[test]
    fn insert_group_matches_the_buffered_twin() {
        let doc = [0x10, 0x2A];
        let mut markup = Markup::open(&doc).unwrap();
        let mut maintain =
            Maintain::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let group_field = field(3);
        let a_group = markup
            .insert_group(protobuf_edit::markup::grouped::InsertAt::TailOf(None), group_field)
            .unwrap();
        let b_group = maintain
            .insert_group(protobuf_edit::maintain::InsertAt::TailOf(None), group_field)
            .unwrap();
        markup
            .insert_varint(
                protobuf_edit::markup::grouped::InsertAt::TailOf(Some(a_group)),
                field(1),
                7,
            )
            .unwrap();
        maintain
            .insert_varint(protobuf_edit::maintain::InsertAt::TailOf(Some(b_group)), field(1), 7)
            .unwrap();
        assert_eq!(markup.save().unwrap(), maintain.save().unwrap());
        assert_eq!(markup.save_canonical().unwrap(), maintain.save_canonical().unwrap());
        // Reverting the interior insert then the group birth
        // restores the source in both twins.
        maintain.revert_all();
        markup.revert_all();
        assert_eq!(maintain.save().unwrap(), doc);
        assert_eq!(markup.save().unwrap(), doc);
    }

    #[test]
    fn trailing_group_bytes_answer_the_covering_group() {
        // group f1 { varint f2=3 } — byte 3 is the end tag.
        let doc = [0x0B, 0x10, 0x03, 0x0C];
        let maintain = Maintain::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let group = maintain.top().next().unwrap();
        let inner = maintain.children(group).unwrap().next().unwrap();
        assert_eq!(maintain.narrowest(0), Some(group));
        assert_eq!(maintain.narrowest(2), Some(inner));
        assert_eq!(maintain.narrowest(3), Some(group));
        assert_eq!(maintain.narrowest(4), None);
    }
}

// ─── walk budgets (pass-count honesty) ───

mod walk_budgets {
    use protobuf_edit::maintain::groupless::{Descent, Maintain};

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
        let mut editor = Maintain::open(counted(&stats, &[3, 5, 64])).unwrap();
        assert_eq!(stats.begins.get(), 1, "open is one walk");
        let tops: Vec<_> = editor.top().collect();
        // Observation, values, spans, and the reverse index are
        // walk-free.
        for &top in &tops {
            let _ = editor.kind(top).unwrap();
            let _ = editor.status(top).unwrap();
            let _ = editor.span(top).unwrap();
            let _ = editor.source_spans(top).unwrap();
        }
        let _ = editor.varint_word(tops[0]).unwrap();
        let _ = editor.narrowest(4);
        assert_eq!(stats.begins.get(), 1, "observation spends no walk");
        // Commands and the revision log are walk-free.
        editor.set_varint(tops[0], 7).unwrap();
        editor.delete(tops[0]).unwrap();
        editor.undelete(tops[0]).unwrap();
        editor.revert();
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
        // An authored payload descends walk-free (the store is
        // addressable memory).
        editor.set_payload(tops[3], &[0x08, 0x01]).unwrap();
        assert!(matches!(editor.descend(tops[3]).unwrap(), Descent::Opened { .. }));
        assert_eq!(stats.begins.get(), 2, "authored payloads descend walk-free");
        // Each byte-producing save is one walk; repeated saves are
        // lawful.
        let _ = editor.save().unwrap();
        assert_eq!(stats.begins.get(), 3, "a save is one walk");
        let _ = editor.save().unwrap();
        assert_eq!(stats.begins.get(), 4, "repeated saves cost one walk each");
        let _ = editor.save_canonical().unwrap();
        assert_eq!(stats.begins.get(), 5, "a canonical save is one walk");
    }

    #[test]
    fn materialize_settles_in_zero_or_one_walk() {
        let stats = WalkStats::default();
        let mut editor = Maintain::open(counted(&stats, &[7, 64])).unwrap();
        let tops: Vec<_> = editor.top().collect();
        // Two fresh source extents resolve in one source-ordered
        // walk (scattered descents would cost one each).
        editor.materialize(&[tops[3], tops[1]]).unwrap();
        assert_eq!(stats.begins.get(), 2, "a fresh batch is one walk");
        // The A6 zero-walk row: no fresh source extent remains —
        // resident verdicts, the empty extent, and authored
        // payloads settle without mounting a walk.
        editor.set_payload(tops[2], &[0x08, 0x03]).unwrap();
        editor.materialize(&[tops[1], tops[2], tops[3]]).unwrap();
        assert_eq!(stats.begins.get(), 2, "a settled batch mounts no walk");
    }

    #[test]
    fn each_single_handle_fetch_is_one_fresh_walk() {
        let stats = WalkStats::default();
        let mut editor = Maintain::open(counted(&stats, &[9, 64])).unwrap();
        let tops: Vec<_> = editor.top().collect();
        let mut out = Vec::new();
        editor.read_payload(tops[1], &mut out).unwrap();
        assert_eq!(stats.begins.get(), 2, "a scanned fetch is one walk");
        out.clear();
        editor.read_payload(tops[1], &mut out).unwrap();
        assert_eq!(stats.begins.get(), 3, "every single-handle fetch walks afresh");
        // The batch face answers k handles in one walk.
        editor.fetch_payloads(&[tops[1], tops[3]], |_, _| {}).unwrap();
        assert_eq!(stats.begins.get(), 4, "a batch fetch is one walk");
        // Authored payloads answer from the store.
        editor.set_payload(tops[1], b"zz").unwrap();
        out.clear();
        editor.read_payload(tops[1], &mut out).unwrap();
        assert_eq!(out, b"zz");
        assert_eq!(stats.begins.get(), 4, "authored payloads fetch walk-free");
        editor.fetch_payloads(&[tops[1]], |_, _| {}).unwrap();
        assert_eq!(stats.begins.get(), 4, "an all-authored batch mounts no walk");
    }

    #[test]
    fn a_flipped_and_reverted_container_re_descends_in_one_walk() {
        let stats = WalkStats::default();
        let mut editor = Maintain::open(counted(&stats, &[11, 64])).unwrap();
        let tops: Vec<_> = editor.top().collect();
        assert!(matches!(editor.descend(tops[1]).unwrap(), Descent::Opened { .. }));
        assert_eq!(stats.begins.get(), 2);
        // The flip orphans the interior; the revert restores the
        // coordinate claim walk-free.
        editor.set_payload(tops[1], b"xx").unwrap();
        editor.revert();
        assert_eq!(stats.begins.get(), 2, "flip and revert spend no walk");
        // Re-descending the re-sealed source container is the
        // revision log's one walk-visible consequence.
        assert!(matches!(editor.descend(tops[1]).unwrap(), Descent::Opened { .. }));
        assert_eq!(stats.begins.get(), 3, "a re-sealed container re-descends in one walk");
        // Chunk partitioning carries no meaning: the same edits
        // over radically different partitions land the same save.
        let saved = editor.save().unwrap();
        assert_eq!(saved, DOC, "the clean tree saves the source verbatim");
    }
}

// ─── torn, growth, and custody rows ───

mod torn_rows {
    use protobuf_edit::maintain::groupless::{DescendFault, FetchFault, Maintain, SaveFault};

    use super::*;

    /// varint f1=150 · LEN f2 { varint f1=7 }
    const DOC: [u8; 7] = [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07];

    #[test]
    fn a_shrunk_source_tears_the_descend_and_the_editor_stands() {
        let source = Swapping { walks: &[&DOC, &DOC[..4]], begun: Cell::new(0) };
        let mut editor = Maintain::open(source).map_err(|(_, fault)| fault).unwrap();
        let tops: Vec<_> = editor.top().collect();
        let before = editor.pending();
        match editor.descend(tops[1]) {
            Err(DescendFault::Torn { at }) => assert_eq!(at, 5, "the tear names the extent start"),
            other => panic!("a shrunk source tears: {other:?}"),
        }
        assert_eq!(editor.pending(), before, "the editor's edit state is unchanged");
        // The slot stayed unopened: a later walk over restored
        // bytes may retry.
        assert_eq!(editor.children(tops[1]).unwrap().count(), 0);
    }

    #[test]
    fn a_shrunk_source_tears_the_fetch_and_restores_the_buffer() {
        let source = Swapping { walks: &[&DOC, &DOC[..5]], begun: Cell::new(0) };
        let mut editor = Maintain::open(source).map_err(|(_, fault)| fault).unwrap();
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
        let mut editor = Maintain::open(source).map_err(|(_, fault)| fault).unwrap();
        let mut out = vec![0xEE];
        match editor.save_into(&mut out) {
            Err(SaveFault::Torn { .. }) => {}
            other => panic!("a shrunk source tears the save: {other:?}"),
        }
        assert_eq!(out, [0xEE], "the owned product restores on Err");

        // Grown: the end probe refuses at the measured total.
        const GROWN: [u8; 9] = [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07, 0x08, 0x01];
        let source = Swapping { walks: &[&DOC, &GROWN], begun: Cell::new(0) };
        let mut editor = Maintain::open(source).map_err(|(_, fault)| fault).unwrap();
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
    fn growth_beneath_a_fetch_is_undetectable_and_hands_current_bytes() {
        // The fetch walk judges only that the source still reaches
        // the extent's end: displaced bytes beneath unchanged
        // coordinates are handed as they now read — the provider's
        // byte-identity obligation, judged nowhere (D11-2's
        // boundary, a fact from birth).
        const MOVED: [u8; 7] = [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x63];
        let source = Swapping { walks: &[&DOC, &MOVED], begun: Cell::new(0) };
        let mut editor = Maintain::open(source).map_err(|(_, fault)| fault).unwrap();
        let tops: Vec<_> = editor.top().collect();
        let mut out = Vec::new();
        editor.read_payload(tops[1], &mut out).unwrap();
        assert_eq!(out, [0x08, 0x63], "wrong bytes, memory-safe — warranty void");
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
        match Maintain::open(Refusing) {
            Err((_source, fault)) => {
                assert!(matches!(fault, protobuf_edit::maintain::groupless::OpenFault::Source(_)));
            }
            Ok(_) => panic!("a refused begin returns custody beside the mark"),
        }
    }
}

// ─── boundary documents ───

mod boundaries {
    use protobuf_edit::maintain::grouped::Maintain as GroupedMaintain;
    use protobuf_edit::maintain::groupless::{Descent, Maintain};

    use super::*;

    #[test]
    fn the_empty_document_round_trips() {
        let mut editor = Maintain::open(SliceSource::new(&[])).map_err(|(_, f)| f).unwrap();
        assert_eq!(editor.source_len(), 0);
        assert_eq!(editor.top().count(), 0);
        assert_eq!(editor.save_len().unwrap(), 0);
        assert_eq!(editor.save().unwrap(), Vec::<u8>::new());
        assert_eq!(editor.narrowest(0), None);
        // Insertion into the empty document authors from nothing.
        editor.insert_varint(protobuf_edit::maintain::InsertAt::TailOf(None), field(1), 1).unwrap();
        assert_eq!(editor.save().unwrap(), [0x08, 0x01]);
        editor.revert_all();
        assert_eq!(editor.save().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn the_payload_class_gate_judges_before_any_push() {
        let doc = [0x12, 0x00];
        let mut editor = Maintain::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        let oversized = vec![0u8; usize::try_from(i32::MAX).unwrap() + 1];
        assert!(matches!(
            editor.set_payload(top, &oversized),
            Err(protobuf_edit::maintain::groupless::EditFault::PayloadTooLarge { .. })
        ));
        assert_eq!(editor.pending(), 0, "the refused command changed nothing");
    }

    #[test]
    fn an_empty_payload_descends_and_accepts_insertions() {
        let doc = [0x12, 0x00];
        let mut editor = Maintain::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        assert!(matches!(editor.descend(top).unwrap(), Descent::Opened { first: None }));
        editor
            .insert_varint(protobuf_edit::maintain::InsertAt::HeadOf(Some(top)), field(1), 5)
            .unwrap();
        assert_eq!(editor.save().unwrap(), [0x12, 0x02, 0x08, 0x05]);
    }

    #[test]
    fn an_empty_group_round_trips_and_accepts_insertions() {
        let doc = [0x0B, 0x0C];
        let mut editor = GroupedMaintain::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let group = editor.top().next().unwrap();
        assert_eq!(editor.children(group).unwrap().count(), 0);
        assert_eq!(editor.save().unwrap(), doc);
        editor
            .insert_varint(protobuf_edit::maintain::InsertAt::TailOf(Some(group)), field(2), 3)
            .unwrap();
        assert_eq!(editor.save().unwrap(), [0x0B, 0x10, 0x03, 0x0C]);
        editor.revert();
        assert_eq!(editor.save().unwrap(), doc);
    }

    #[test]
    fn the_undo_bracket_recipe_unwinds_to_its_mark() {
        let doc = [0x08, 0x2A];
        let mut editor = Maintain::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        editor.set_varint(top, 7).unwrap();
        let mark = editor.pending();
        editor.insert_varint(protobuf_edit::maintain::InsertAt::TailOf(None), field(2), 1).unwrap();
        editor.insert_varint(protobuf_edit::maintain::InsertAt::TailOf(None), field(2), 2).unwrap();
        while editor.pending() > mark {
            editor.revert();
        }
        assert_eq!(editor.save().unwrap(), [0x08, 0x07]);
    }

    #[test]
    fn the_edited_interior_gate_protects_undo_history() {
        let doc = [0x12, 0x02, 0x08, 0x07];
        let mut editor = Maintain::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        let Descent::Opened { first: Some(inner) } = editor.descend(top).unwrap() else {
            panic!("the payload parses")
        };
        editor.set_varint(inner, 9).unwrap();
        // The interior carries history: a wholesale replacement
        // would orphan the rows precise undo still points into.
        assert!(matches!(
            editor.set_payload(top, b"xx"),
            Err(protobuf_edit::maintain::groupless::EditFault::EditedInterior)
        ));
        editor.revert();
        editor.set_payload(top, b"xx").unwrap();
        assert!(editor.varint_word(inner).is_err(), "the flip orphans the interior");
        assert_eq!(editor.save().unwrap(), [0x12, 0x02, 0x78, 0x78]);
    }

    #[test]
    fn staged_frames_install_exactly_one_logged_step() {
        let doc = [0x12, 0x02, 0x68, 0x69];
        let mut editor = Maintain::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        let mut frame = editor.begin_set_payload(top).unwrap();
        frame.write(&[0x61]).unwrap();
        frame.write(&[0x62, 0x63]).unwrap();
        frame.finish().unwrap();
        assert_eq!(editor.pending(), 1);
        assert_eq!(editor.save().unwrap(), [0x12, 0x03, 0x61, 0x62, 0x63]);
        // An abandoned frame installs nothing.
        let mut frame = editor.begin_set_payload(top).unwrap();
        frame.write(b"zzzz").unwrap();
        drop(frame);
        assert_eq!(editor.pending(), 1);
        // The sized twin is held to its declaration.
        let mut frame = editor.begin_set_payload_sized(top, 5).unwrap();
        frame.write(b"wor").unwrap();
        frame.write(b"ld").unwrap();
        frame.finish().unwrap();
        assert_eq!(editor.pending(), 2);
        assert_eq!(editor.save().unwrap(), [0x12, 0x05, 0x77, 0x6F, 0x72, 0x6C, 0x64]);
        editor.revert();
        assert_eq!(editor.save().unwrap(), [0x12, 0x03, 0x61, 0x62, 0x63]);
    }
}
