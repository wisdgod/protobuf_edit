//! The commission cells' member battery: differentials against
//! the buffered review twins over the slice source (the honest
//! comparison set — the faces both machines carry with the
//! coordinates widened), the canonical-gate matrix (door and
//! descend × all three refusal sites, grouped end tags included),
//! revision-log replay parity after every step of interleaved
//! edit/revert scripts, pass-count honesty over a counting source
//! (the materialize zero-walk row included), torn fixtures over a
//! swapping source, and boundary documents.

#![cfg(all(
    feature = "commission-grouped",
    feature = "commission-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "construct-grouped"
))]
#![feature(thread_id_value)]

#[path = "support/replay.rs"]
mod replay;

use std::cell::Cell;

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
/// pairs (the twins' faces are textually identical). No canonical
/// save family exists on either side: admission proved the source
/// minimal, so the fidelity save already emits `CanonicalMinimal`.
macro_rules! differential_pair {
    ($doc:expr, $seed:expr, $Review:ty, $Commission:ty) => {{
        let doc: &[u8] = $doc;
        let mut review = <$Review>::open(doc).expect("corpus documents admit");
        let mut commission =
            <$Commission>::open(SliceSource::new(doc)).map_err(|(_, fault)| fault).unwrap();
        assert_eq!(commission.source_len(), doc.len() as u64);
        let review_tops: Vec<_> = review.top().collect();
        let commission_tops: Vec<_> = commission.top().collect();
        assert_eq!(review_tops.len(), commission_tops.len(), "top-layer parity");
        let ops = script($seed, review_tops.len());
        for op in ops {
            match op {
                Op::SetVarint(target, value) => {
                    let a = review.set_varint(review_tops[target], value).is_ok();
                    let b = commission.set_varint(commission_tops[target], value).is_ok();
                    assert_eq!(a, b, "set_varint admission parity at {op:?}");
                }
                Op::SetI32(target, bits) => {
                    let a = review.set_i32(review_tops[target], bits).is_ok();
                    let b = commission.set_i32(commission_tops[target], bits).is_ok();
                    assert_eq!(a, b, "set_i32 admission parity at {op:?}");
                }
                Op::SetI64(target, bits) => {
                    let a = review.set_i64(review_tops[target], bits).is_ok();
                    let b = commission.set_i64(commission_tops[target], bits).is_ok();
                    assert_eq!(a, b, "set_i64 admission parity at {op:?}");
                }
                Op::SetPayload(target, payload) => {
                    let a = review.set_payload(review_tops[target], payload).is_ok();
                    let b = commission.set_payload(commission_tops[target], payload).is_ok();
                    assert_eq!(a, b, "set_payload admission parity at {op:?}");
                }
                Op::Delete(target) => {
                    let a = review.delete(review_tops[target]).is_ok();
                    let b = commission.delete(commission_tops[target]).is_ok();
                    assert_eq!(a, b, "delete admission parity at {op:?}");
                }
                Op::Undelete(target) => {
                    let a = review.undelete(review_tops[target]).is_ok();
                    let b = commission.undelete(commission_tops[target]).is_ok();
                    assert_eq!(a, b, "undelete admission parity at {op:?}");
                }
                Op::ClearEdit(target) => {
                    let a = review.clear_edit(review_tops[target]).is_ok();
                    let b = commission.clear_edit(commission_tops[target]).is_ok();
                    assert_eq!(a, b, "clear_edit admission parity at {op:?}");
                }
                Op::InsertVarint(field, value) => {
                    // The dialect modules re-export one shared
                    // InsertAt shape; the caller's aliases name
                    // the same gap on both twins.
                    let field = f(u64::from(field));
                    let a = review.insert_varint(ReviewAt::TailOf(None), field, value).is_ok();
                    let b =
                        commission.insert_varint(CommissionAt::TailOf(None), field, value).is_ok();
                    assert_eq!(a, b, "insert_varint admission parity at {op:?}");
                }
                Op::InsertPayload(field, payload) => {
                    let field = f(u64::from(field));
                    let a = review.insert_payload(ReviewAt::TailOf(None), field, payload).is_ok();
                    let b = commission
                        .insert_payload(CommissionAt::TailOf(None), field, payload)
                        .is_ok();
                    assert_eq!(a, b, "insert_payload admission parity at {op:?}");
                }
                Op::Descend(target) => {
                    let a = review.descend(review_tops[target]).is_ok();
                    let b = commission.descend(commission_tops[target]).is_ok();
                    assert_eq!(a, b, "descend outcome parity at {op:?}");
                }
                Op::Revert => {
                    let a = review.revert().is_some();
                    let b = commission.revert().is_some();
                    assert_eq!(a, b, "revert parity at {op:?}");
                }
                Op::RevertAll => {
                    review.revert_all();
                    commission.revert_all();
                }
            }
            // Revision-log replay parity: the observable state
            // matches after every step.
            assert_eq!(review.pending(), commission.pending(), "pending parity after {op:?}");
            for (a, b) in review_tops.iter().zip(&commission_tops) {
                assert_eq!(
                    format!("{:?}", review.status(*a)),
                    format!("{:?}", commission.status(*b)),
                    "status parity after {op:?}"
                );
                assert_eq!(
                    review.dirty(*a).is_ok_and(|dirty| dirty),
                    commission.dirty(*b).is_ok_and(|dirty| dirty),
                    "dirty parity after {op:?}"
                );
            }
            let saved_review = review.save().expect("buffered save admits");
            let saved_commission = commission.save().expect("replay save admits");
            assert_eq!(saved_review, saved_commission, "byte-identical saves after {op:?}");
        }
        // Widened-coordinate parity: price, spans, and the
        // per-record geometry.
        assert_eq!(
            u64::from(review.save_len().unwrap()),
            commission.save_len().unwrap(),
            "save_len parity"
        );
        let spans_review = review.save_spans().unwrap();
        let spans_commission = commission.save_spans().unwrap();
        assert_eq!(spans_review.len(), spans_commission.len(), "save_spans length parity");
        for ((_, a), (_, b)) in spans_review.iter().zip(spans_commission.iter()) {
            assert_eq!(u64::from(a.start()), b.start(), "span start parity");
            assert_eq!(u64::from(a.end()), b.end(), "span end parity");
        }
        // The sink faces agree with the owned product.
        let mut streamed = Vec::new();
        commission.save_sink(|view| streamed.extend_from_slice(view)).unwrap();
        assert_eq!(streamed, commission.save().unwrap(), "sink agrees with the owned product");
        // Value reads and payload bytes on the current state.
        for (a, b) in review_tops.iter().zip(&commission_tops) {
            let kind = format!("{:?}", review.kind(*a).unwrap());
            assert_eq!(kind, format!("{:?}", commission.kind(*b).unwrap()), "kind parity");
            assert_eq!(review.field(*a).unwrap(), commission.field(*b).unwrap(), "field parity");
            if kind == "Varint" {
                assert_eq!(
                    review.varint_word(*a).unwrap(),
                    commission.varint_word(*b).unwrap(),
                    "varint word parity"
                );
            }
            if kind == "Len" {
                let expected = review.payload_bytes(*a).unwrap().to_vec();
                let mut fetched = Vec::new();
                commission.read_payload(*b, &mut fetched).unwrap();
                assert_eq!(expected, fetched, "payload byte parity");
            }
            match (review.span(*a).unwrap(), commission.span(*b).unwrap()) {
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
            let a = review.narrowest(u32::try_from(pos).unwrap()).map(|h| format!("{h:?}"));
            let b = commission.narrowest(pos as u64).map(|h| format!("{h:?}"));
            assert_eq!(a.is_some(), b.is_some(), "narrowest presence parity at {pos}");
        }
        // Reverting everything restores the source, byte for byte,
        // on both sides.
        review.revert_all();
        commission.revert_all();
        assert_eq!(review.save().unwrap(), doc, "buffered revert_all restores the source");
        assert_eq!(commission.save().unwrap(), doc, "replay revert_all restores the source");
    }};
}

mod groupless_member {
    use protobuf_edit::commission::InsertAt as CommissionAt;
    use protobuf_edit::commission::groupless::{Commission, Descent, FaultKind, OpenFault};
    use protobuf_edit::review::groupless::{InsertAt as ReviewAt, Review};

    use super::*;

    #[test]
    fn the_differential_holds_over_the_seeded_corpus() {
        for (index, doc) in corpus(false).iter().enumerate() {
            differential_pair!(
                doc,
                0xC0AA_0000 + index as u64,
                Review<'_>,
                Commission<SliceSource<'_>>
            );
        }
    }

    #[test]
    fn the_canonical_gate_matrix_holds_at_door_and_descend() {
        // Door × the three sites: the buffered twin refuses the
        // same bytes; the replay refusal projects its typed site
        // and met width through the shared opaque carrier.
        let padded_tag = [0x88, 0x00, 0x2A];
        let padded_prefix = [0x12, 0x81, 0x00, 0x61];
        let padded_value = [0x08, 0x96, 0x81, 0x00];
        for (doc, site, width, at) in [
            (&padded_tag[..], NonMinimalSite::Tag, 2, 0),
            (&padded_prefix[..], NonMinimalSite::LenPrefix, 2, 1),
            (&padded_value[..], NonMinimalSite::Value, 3, 1),
        ] {
            assert!(Review::open(doc).is_err(), "the buffered canonical door refuses {site:?}");
            let Err((_, OpenFault::Wire(fault))) = Commission::open(SliceSource::new(doc)) else {
                panic!("the replay canonical door refuses {site:?}")
            };
            let FaultKind::NonMinimal(refusal) = fault.kind() else {
                panic!("the refusal names the padded construct at {site:?}")
            };
            assert_eq!(format!("{:?}", refusal.site()), format!("{site:?}"));
            assert_eq!(refusal.width(), width, "met width at {site:?}");
            assert_eq!(fault.at().source_at(), Some(at), "refusal offset at {site:?}");
            assert!(matches!(fault.kind().class(), protobuf_edit::FaultClass::Policy));
        }

        // Source-descend × the same sites: the refusal parks
        // resident, and the editor's revision state stands.
        let in_tag = [0x12, 0x03, 0x88, 0x00, 0x2A];
        let in_prefix = [0x12, 0x04, 0x12, 0x81, 0x00, 0x61];
        let in_value = [0x12, 0x04, 0x08, 0x96, 0x81, 0x00];
        for (doc, site) in [
            (&in_tag[..], NonMinimalSite::Tag),
            (&in_prefix[..], NonMinimalSite::LenPrefix),
            (&in_value[..], NonMinimalSite::Value),
        ] {
            let mut commission =
                Commission::open(SliceSource::new(doc)).map_err(|(_, fault)| fault).unwrap();
            let top = commission.top().next().unwrap();
            let Descent::Parked(fault) = commission.descend(top).unwrap() else {
                panic!("the padded interior parks at {site:?}")
            };
            let FaultKind::NonMinimal(refusal) = fault.kind() else {
                panic!("the parked refusal names the padded construct at {site:?}")
            };
            assert_eq!(format!("{:?}", refusal.site()), format!("{site:?}"));
            // The verdict is resident and the log untouched.
            assert!(matches!(commission.descend(top).unwrap(), Descent::Parked(_)));
            assert_eq!(commission.pending(), 0);
        }
    }

    #[test]
    fn parked_verdicts_match_the_buffered_refusal_classes() {
        // LEN f2 wrapping an empty group of field 1: lawful wire
        // outside the groupless language — the buffered twin
        // refuses it as a capability judgment, the replay twin
        // parks the same class.
        let doc = [0x12, 0x02, 0x0B, 0x0C];
        let mut review = Review::open(&doc).unwrap();
        let mut commission =
            Commission::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let a = review.top().next().unwrap();
        let b = commission.top().next().unwrap();
        assert!(matches!(
            review.descend(a).unwrap(),
            protobuf_edit::review::groupless::Descent::Refused(_)
        ));
        let Descent::Parked(fault) = commission.descend(b).unwrap() else {
            panic!("the group code parks")
        };
        assert!(matches!(fault.kind().class(), protobuf_edit::FaultClass::Capability));
        assert_eq!(fault.at().source_at(), Some(2));
        // The verdict is resident: no further walk re-judges it.
        assert!(matches!(commission.descend(b).unwrap(), Descent::Parked(_)));

        // A wire-grammar fault inside a payload parks as grammar.
        let doc = [0x12, 0x01, 0x00];
        let mut review = Review::open(&doc).unwrap();
        let mut commission =
            Commission::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let a = review.top().next().unwrap();
        let b = commission.top().next().unwrap();
        assert!(matches!(
            review.descend(a).unwrap(),
            protobuf_edit::review::groupless::Descent::Faulted(_)
        ));
        let Descent::Parked(fault) = commission.descend(b).unwrap() else {
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
        let mut review = Review::open(&doc).unwrap();
        let mut commission =
            Commission::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let a = review.top().next().unwrap();
        let b = commission.top().next().unwrap();
        review.set_payload(a, &[0x08, 0x07]).unwrap();
        commission.set_payload(b, &[0x08, 0x07]).unwrap();
        let protobuf_edit::review::groupless::Descent::Opened { first: Some(inner_a) } =
            review.descend(a).unwrap()
        else {
            panic!("the authored payload parses")
        };
        let Descent::Opened { first: Some(inner_b) } = commission.descend(b).unwrap() else {
            panic!("the authored payload parses")
        };
        assert_eq!(review.varint_word(inner_a).unwrap(), 7);
        assert_eq!(commission.varint_word(inner_b).unwrap(), 7);
        assert!(review.set_varint(inner_a, 9).is_err());
        assert!(commission.set_varint(inner_b, 9).is_err());
        // Reverting the replacement orphans the authored interior
        // in both twins.
        commission.revert();
        review.revert();
        assert!(review.varint_word(inner_a).is_err());
        assert!(commission.varint_word(inner_b).is_err());
        assert_eq!(commission.save().unwrap(), doc);
    }

    #[test]
    fn a_padded_authored_payload_parks_at_the_resident_scan() {
        // The resident scan of an authored payload judges the
        // same canonical standard as a source walk: a padded
        // varint value inside authored bytes parks Policy.
        let doc = [0x12, 0x02, 0x08, 0x01];
        let mut commission =
            Commission::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let top = commission.top().next().unwrap();
        commission.set_payload(top, &[0x08, 0x96, 0x81, 0x00]).unwrap();
        let Descent::Parked(fault) = commission.descend(top).unwrap() else {
            panic!("the padded authored interior parks")
        };
        let FaultKind::NonMinimal(refusal) = fault.kind() else {
            panic!("the parked refusal names the padded construct")
        };
        assert!(matches!(refusal.site(), NonMinimalSite::Value));
        assert!(matches!(fault.kind().class(), protobuf_edit::FaultClass::Policy));
    }
}

mod grouped_member {
    use protobuf_edit::commission::InsertAt as CommissionAt;
    use protobuf_edit::commission::grouped::{Commission, FaultKind, OpenFault};
    use protobuf_edit::review::grouped::{InsertAt as ReviewAt, Review};

    use super::*;

    #[test]
    fn the_differential_holds_over_the_seeded_corpus() {
        for (index, doc) in corpus(true).iter().enumerate() {
            differential_pair!(
                doc,
                0xC0AA_6000 + index as u64,
                Review<'_>,
                Commission<SliceSource<'_>>
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
            Review::open(&padded).is_err(),
            "the buffered grouped door refuses the padded end tag"
        );
        let Err((_, OpenFault::Wire(fault))) = Commission::open(SliceSource::new(&padded)) else {
            panic!("the replay grouped door refuses the padded end tag")
        };
        assert_eq!(fault.at().source_at(), Some(1));
        let FaultKind::NonMinimal(refusal) = fault.kind() else { panic!("the site is typed") };
        assert!(matches!(refusal.site(), NonMinimalSite::Tag));
        assert_eq!((refusal.width(), refusal.field()), (2, None));
    }

    #[test]
    fn group_interiors_edit_and_revert_in_both_twins() {
        // group f1 { varint f2=3 · LEN f3 "ab" } · varint f2=42
        let doc = [0x0B, 0x10, 0x03, 0x1A, 0x02, 0x61, 0x62, 0x0C, 0x10, 0x2A];
        let mut review = Review::open(&doc).unwrap();
        let mut commission =
            Commission::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let a_group = review.top().next().unwrap();
        let b_group = commission.top().next().unwrap();
        let a_kids: Vec<_> = review.children(a_group).unwrap().collect();
        let b_kids: Vec<_> = commission.children(b_group).unwrap().collect();
        assert_eq!(a_kids.len(), b_kids.len());
        review.set_varint(a_kids[0], 300).unwrap();
        commission.set_varint(b_kids[0], 300).unwrap();
        review.set_payload(a_kids[1], b"zz").unwrap();
        commission.set_payload(b_kids[1], b"zz").unwrap();
        assert_eq!(review.save().unwrap(), commission.save().unwrap());
        commission.revert_all();
        review.revert_all();
        assert_eq!(commission.save().unwrap(), doc);
    }

    #[test]
    fn insert_group_matches_the_buffered_twin() {
        let doc = [0x10, 0x2A];
        let mut review = Review::open(&doc).unwrap();
        let mut commission =
            Commission::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let group_field = field(3);
        let a_group = review.insert_group(ReviewAt::TailOf(None), group_field).unwrap();
        let b_group = commission.insert_group(CommissionAt::TailOf(None), group_field).unwrap();
        review.insert_varint(ReviewAt::TailOf(Some(a_group)), field(1), 7).unwrap();
        commission.insert_varint(CommissionAt::TailOf(Some(b_group)), field(1), 7).unwrap();
        assert_eq!(review.save().unwrap(), commission.save().unwrap());
        // Reverting the interior insert then the group birth
        // restores the source in both twins.
        commission.revert_all();
        review.revert_all();
        assert_eq!(commission.save().unwrap(), doc);
        assert_eq!(review.save().unwrap(), doc);
    }

    #[test]
    fn trailing_group_bytes_answer_the_covering_group() {
        // group f1 { varint f2=3 } — byte 3 is the end tag.
        let doc = [0x0B, 0x10, 0x03, 0x0C];
        let commission =
            Commission::open(SliceSource::new(&doc)).map_err(|(_, fault)| fault).unwrap();
        let group = commission.top().next().unwrap();
        let inner = commission.children(group).unwrap().next().unwrap();
        assert_eq!(commission.narrowest(0), Some(group));
        assert_eq!(commission.narrowest(2), Some(inner));
        assert_eq!(commission.narrowest(3), Some(group));
        assert_eq!(commission.narrowest(4), None);
    }
}

// ─── walk budgets (pass-count honesty) ───

mod walk_budgets {
    use protobuf_edit::commission::groupless::{Commission, Descent};

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
        let mut editor = Commission::open(counted(&stats, &[3, 5, 64])).unwrap();
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
        // addressable memory; the resident scan judges the same
        // canonical standard).
        editor.set_payload(tops[3], &[0x08, 0x01]).unwrap();
        assert!(matches!(editor.descend(tops[3]).unwrap(), Descent::Opened { .. }));
        assert_eq!(stats.begins.get(), 2, "authored payloads descend walk-free");
        // Each byte-producing save is one walk; repeated saves are
        // lawful.
        let _ = editor.save().unwrap();
        assert_eq!(stats.begins.get(), 3, "a save is one walk");
        let _ = editor.save().unwrap();
        assert_eq!(stats.begins.get(), 4, "repeated saves cost one walk each");
    }

    #[test]
    fn materialize_settles_in_zero_or_one_walk() {
        let stats = WalkStats::default();
        let mut editor = Commission::open(counted(&stats, &[7, 64])).unwrap();
        let tops: Vec<_> = editor.top().collect();
        // Two fresh source extents resolve in one source-ordered
        // walk (scattered descents would cost one each).
        editor.materialize(&[tops[3], tops[1]]).unwrap();
        assert_eq!(stats.begins.get(), 2, "a fresh batch is one walk");
        // The zero-walk row: no fresh source extent remains —
        // resident verdicts, the empty extent, and authored
        // payloads settle without mounting a walk.
        editor.set_payload(tops[2], &[0x08, 0x03]).unwrap();
        editor.materialize(&[tops[1], tops[2], tops[3]]).unwrap();
        assert_eq!(stats.begins.get(), 2, "a settled batch mounts no walk");
    }

    #[test]
    fn each_single_handle_fetch_is_one_fresh_walk() {
        let stats = WalkStats::default();
        let mut editor = Commission::open(counted(&stats, &[9, 64])).unwrap();
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
        let mut editor = Commission::open(counted(&stats, &[11, 64])).unwrap();
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
    use protobuf_edit::commission::groupless::{Commission, DescendFault, FetchFault, SaveFault};

    use super::*;

    /// varint f1=150 · LEN f2 { varint f1=7 }
    const DOC: [u8; 7] = [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07];

    #[test]
    fn a_shrunk_source_tears_the_descend_and_the_editor_stands() {
        let source = Swapping { walks: &[&DOC, &DOC[..4]], begun: Cell::new(0) };
        let mut editor = Commission::open(source).map_err(|(_, fault)| fault).unwrap();
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
        let mut editor = Commission::open(source).map_err(|(_, fault)| fault).unwrap();
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
        let mut editor = Commission::open(source).map_err(|(_, fault)| fault).unwrap();
        let mut out = vec![0xEE];
        match editor.save_into(&mut out) {
            Err(SaveFault::Torn { .. }) => {}
            other => panic!("a shrunk source tears the save: {other:?}"),
        }
        assert_eq!(out, [0xEE], "the owned product restores on Err");

        // Grown: the end probe refuses at the measured total.
        const GROWN: [u8; 9] = [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07, 0x08, 0x01];
        let source = Swapping { walks: &[&DOC, &GROWN], begun: Cell::new(0) };
        let mut editor = Commission::open(source).map_err(|(_, fault)| fault).unwrap();
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
        match Commission::open(Refusing) {
            Err((_source, fault)) => {
                assert!(matches!(
                    fault,
                    protobuf_edit::commission::groupless::OpenFault::Source(_)
                ));
            }
            Ok(_) => panic!("a refused begin returns custody beside the mark"),
        }
    }
}

// ─── boundary documents ───

mod boundaries {
    use protobuf_edit::commission::grouped::Commission as GroupedCommission;
    use protobuf_edit::commission::groupless::{Commission, Descent};

    use super::*;

    #[test]
    fn the_empty_document_round_trips() {
        let mut editor = Commission::open(SliceSource::new(&[])).map_err(|(_, f)| f).unwrap();
        assert_eq!(editor.source_len(), 0);
        assert_eq!(editor.top().count(), 0);
        assert_eq!(editor.save_len().unwrap(), 0);
        assert_eq!(editor.save().unwrap(), Vec::<u8>::new());
        assert_eq!(editor.narrowest(0), None);
        // Insertion into the empty document authors from nothing.
        editor
            .insert_varint(protobuf_edit::commission::InsertAt::TailOf(None), field(1), 1)
            .unwrap();
        assert_eq!(editor.save().unwrap(), [0x08, 0x01]);
        editor.revert_all();
        assert_eq!(editor.save().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn the_payload_class_gate_judges_before_any_push() {
        let doc = [0x12, 0x00];
        let mut editor = Commission::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        let oversized = vec![0u8; usize::try_from(i32::MAX).unwrap() + 1];
        assert!(matches!(
            editor.set_payload(top, &oversized),
            Err(protobuf_edit::commission::groupless::EditFault::PayloadTooLarge { .. })
        ));
        assert_eq!(editor.pending(), 0, "the refused command changed nothing");
    }

    #[test]
    fn an_empty_payload_descends_and_accepts_insertions() {
        let doc = [0x12, 0x00];
        let mut editor = Commission::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        assert!(matches!(editor.descend(top).unwrap(), Descent::Opened { first: None }));
        editor
            .insert_varint(protobuf_edit::commission::InsertAt::HeadOf(Some(top)), field(1), 5)
            .unwrap();
        assert_eq!(editor.save().unwrap(), [0x12, 0x02, 0x08, 0x05]);
    }

    #[test]
    fn an_empty_group_round_trips_and_accepts_insertions() {
        let doc = [0x0B, 0x0C];
        let mut editor =
            GroupedCommission::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let group = editor.top().next().unwrap();
        assert_eq!(editor.children(group).unwrap().count(), 0);
        assert_eq!(editor.save().unwrap(), doc);
        editor
            .insert_varint(protobuf_edit::commission::InsertAt::TailOf(Some(group)), field(2), 3)
            .unwrap();
        assert_eq!(editor.save().unwrap(), [0x0B, 0x10, 0x03, 0x0C]);
        editor.revert();
        assert_eq!(editor.save().unwrap(), doc);
    }

    #[test]
    fn the_undo_bracket_recipe_unwinds_to_its_mark() {
        let doc = [0x08, 0x2A];
        let mut editor = Commission::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        editor.set_varint(top, 7).unwrap();
        let mark = editor.pending();
        editor
            .insert_varint(protobuf_edit::commission::InsertAt::TailOf(None), field(2), 1)
            .unwrap();
        editor
            .insert_varint(protobuf_edit::commission::InsertAt::TailOf(None), field(2), 2)
            .unwrap();
        while editor.pending() > mark {
            editor.revert();
        }
        assert_eq!(editor.save().unwrap(), [0x08, 0x07]);
    }

    #[test]
    fn the_edited_interior_gate_protects_undo_history() {
        let doc = [0x12, 0x02, 0x08, 0x07];
        let mut editor = Commission::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
        let top = editor.top().next().unwrap();
        let Descent::Opened { first: Some(inner) } = editor.descend(top).unwrap() else {
            panic!("the payload parses")
        };
        editor.set_varint(inner, 9).unwrap();
        // The interior carries history: a wholesale replacement
        // would orphan the rows precise undo still points into.
        assert!(matches!(
            editor.set_payload(top, b"xx"),
            Err(protobuf_edit::commission::groupless::EditFault::EditedInterior)
        ));
        editor.revert();
        editor.set_payload(top, b"xx").unwrap();
        assert!(editor.varint_word(inner).is_err(), "the flip orphans the interior");
        assert_eq!(editor.save().unwrap(), [0x12, 0x02, 0x78, 0x78]);
    }

    #[test]
    fn staged_frames_install_exactly_one_logged_step() {
        let doc = [0x12, 0x02, 0x68, 0x69];
        let mut editor = Commission::open(SliceSource::new(&doc)).map_err(|(_, f)| f).unwrap();
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
