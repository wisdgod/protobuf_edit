use alloc::vec::Vec;

use super::*;
use crate::replay_source::{Chunk, SliceFault, SliceSource, discard_skip};

/// A rewind-only walk over one slice: the shared walk shape for
/// the counting and shifting fixtures.
#[derive(Debug)]
struct FixtureWalk<'a> {
    rest: &'a [u8],
}

impl ReplayWalk for FixtureWalk<'_> {
    type Error = SliceFault;

    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<Self::Error>> {
        Ok(Chunk::new(self.rest))
    }

    fn consume(&mut self, n: usize) {
        self.rest = &self.rest[n..];
    }

    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<Self::Error>> {
        discard_skip(self, n)
    }
}

/// A source that counts its walks — the walk-count honesty lever.
#[derive(Debug)]
struct Counting<'a> {
    bytes: &'a [u8],
    begun: u32,
}

impl<'a> Counting<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, begun: 0 }
    }
}

impl StableReplaySource for Counting<'_> {
    type Error = SliceFault;

    type Walk<'s>
        = FixtureWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        self.begun += 1;
        Ok(FixtureWalk { rest: self.bytes })
    }
}

/// A source whose second and later walks yield a different byte
/// sequence — the contract-breaking fixture the torn-detection
/// rows drive.
#[derive(Debug)]
struct Shifting<'a> {
    full: &'a [u8],
    later: &'a [u8],
    begun: u32,
}

impl StableReplaySource for Shifting<'_> {
    type Error = SliceFault;

    type Walk<'s>
        = FixtureWalk<'s>
    where
        Self: 's;

    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>> {
        let bytes = if self.begun == 0 { self.full } else { self.later };
        self.begun += 1;
        Ok(FixtureWalk { rest: bytes })
    }
}

fn editor(bytes: &[u8]) -> Overhaul<'static, SliceSource<'_>> {
    match Overhaul::open(SliceSource::new(bytes), DepthLimit::REFERENCE) {
        Ok(editor) => editor,
        Err((_, fault)) => panic!("the fixture opens lawfully, got {fault:?}"),
    }
}

// varint f1=150 · varint f2=42
const FLAT: [u8; 5] = [0x08, 0x96, 0x01, 0x10, 0x2A];

// LEN f3 { varint f1=1 } · varint f1=42
const NEST: [u8; 6] = [0x1A, 0x02, 0x08, 0x01, 0x08, 0x2A];

#[test]
fn an_editor_with_no_edits_saves_the_source_bytes() {
    let mut editor = editor(&NEST);
    assert_eq!(editor.save_len().unwrap(), NEST.len() as u64);
    assert_eq!(editor.save().unwrap(), NEST);

    let mut empty = self::editor(&[]);
    assert!(empty.top().next().is_none());
    assert!(empty.save().unwrap().is_empty());
}

#[test]
fn scalar_words_are_banked_at_the_scan() {
    // varint f1=150 · I32 f3 · I64 f4
    let doc = [
        0x08, 0x96, 0x01, //
        0x1D, 0x01, 0x02, 0x03, 0x04, //
        0x21, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];
    let editor = editor(&doc);
    let tops: Vec<_> = editor.top().collect();
    assert_eq!(tops.len(), 3);
    assert_eq!(editor.varint_word(tops[0]), Some(150));
    assert_eq!(editor.i32_bits(tops[1]), Some(0x0403_0201));
    assert_eq!(editor.i64_bits(tops[2]), Some(0x0807_0605_0403_0201));
    assert_eq!(editor.varint_word(tops[1]), None, "the word faces are kind-gated");
    assert_eq!(editor.field(tops[2]).as_inner(), 4);
    assert_eq!(editor.kind(tops[1]), RecordKind::I32);
    assert_eq!(editor.status(tops[0]), EditStatus::Intact);

    let Some(RecordSpans::Varint { tag, value }) = editor.source_spans(tops[0]) else {
        panic!("a varint geometry was expected");
    };
    assert_eq!((tag.start(), tag.end()), (0, 1));
    assert_eq!((value.start(), value.end()), (1, 3));
}

#[test]
fn padded_framing_is_measured_and_rides_verbatim() {
    // varint f1=1 with a three-byte padded tag and the padded
    // value word for 1: tolerance is type-level, and untouched
    // records reproduce byte for byte.
    let doc = [0x88, 0x80, 0x80, 0x00, 0x81, 0x00];
    let mut editor = editor(&doc);
    let tops: Vec<_> = editor.top().collect();
    let Some(RecordSpans::Varint { tag, value }) = editor.source_spans(tops[0]) else {
        panic!("a varint geometry was expected");
    };
    assert_eq!((tag.start(), tag.end()), (0, 4));
    assert_eq!((value.start(), value.end()), (4, 6));
    assert_eq!(editor.varint_word(tops[0]), Some(1));
    assert_eq!(editor.save().unwrap(), doc);

    // A replacement re-emits the value minimally under the
    // verbatim padded tag.
    editor.set_varint(tops[0], 7).unwrap();
    assert_eq!(editor.status(tops[0]), EditStatus::Replaced);
    assert_eq!(editor.save().unwrap(), [0x88, 0x80, 0x80, 0x00, 0x07]);
}

#[test]
fn a_payload_replacement_settles_the_prefix_by_length() {
    // An equal-length replacement rides the padded prefix
    // verbatim.
    let padded = [0x1A, 0x82, 0x80, 0x00, 0x08, 0x01];
    let mut editor = editor(&padded);
    let tops: Vec<_> = editor.top().collect();
    editor.set_payload(tops[0], &[0xAA, 0xBB]).unwrap();
    assert_eq!(editor.save().unwrap(), [0x1A, 0x82, 0x80, 0x00, 0xAA, 0xBB]);

    // A moved length re-authors the prefix minimally.
    let mut editor = self::editor(&NEST);
    let tops: Vec<_> = editor.top().collect();
    editor.set_payload_copy(tops[0], &[0xFF]).unwrap();
    assert_eq!(editor.save().unwrap(), [0x1A, 0x01, 0xFF, 0x08, 0x2A]);
}

#[test]
fn a_deletion_vanishes_the_record_whole() {
    let mut editor = editor(&NEST);
    let tops: Vec<_> = editor.top().collect();

    // Interior insertions vanish with the deleted subtree.
    let Descent::Opened { first } = editor.descend(tops[0]).unwrap() else {
        panic!("a lawful interior opens");
    };
    let inner = first.unwrap();
    editor.set_varint(inner, 9).unwrap();
    editor.insert_varint(InsertAt::TailOf(Some(tops[0])), FieldNumber::new(2).unwrap(), 7).unwrap();
    editor.delete(tops[0]).unwrap();
    assert_eq!(editor.status(tops[0]), EditStatus::Deleted);
    assert_eq!(editor.delete(tops[0]).unwrap_err(), EditFault::DeletedTarget);
    assert_eq!(editor.save().unwrap(), [0x08, 0x2A]);
}

#[test]
fn insertions_land_in_their_named_gaps() {
    let mut editor = editor(&FLAT);
    let tops: Vec<_> = editor.top().collect();
    let f7 = FieldNumber::new(7).unwrap();
    editor.insert_varint(InsertAt::HeadOf(None), f7, 1).unwrap();
    editor.insert_varint(InsertAt::TailOf(None), f7, 2).unwrap();
    let mid = editor.insert_varint(InsertAt::After(tops[0]), f7, 3).unwrap();
    assert_eq!(editor.status(mid), EditStatus::Inserted);
    assert_eq!(
        editor.save().unwrap(),
        [0x38, 0x01, 0x08, 0x96, 0x01, 0x38, 0x03, 0x10, 0x2A, 0x38, 0x02]
    );
}

#[test]
fn an_interior_edit_cascades_the_length_prefixes() {
    // LEN f5 { LEN f3 { varint f1=1 } }
    let doc = [0x2A, 0x04, 0x1A, 0x02, 0x08, 0x01];
    let mut editor = editor(&doc);
    let tops: Vec<_> = editor.top().collect();
    let Descent::Opened { first: Some(outer_kid) } = editor.descend(tops[0]).unwrap() else {
        panic!("the outer interior opens");
    };
    let Descent::Opened { first: Some(leaf) } = editor.descend(outer_kid).unwrap() else {
        panic!("the inner interior opens");
    };
    editor.set_varint(leaf, 300).unwrap();
    // The value grew a byte; both prefixes re-author.
    let expected = [0x2A, 0x05, 0x1A, 0x03, 0x08, 0xAC, 0x02];
    assert_eq!(editor.save_len().unwrap(), expected.len() as u64);
    assert_eq!(editor.save().unwrap(), expected);
}

#[test]
fn the_open_walk_never_speculates_into_payloads() {
    // The LEN payload is garbage wire (field zero); the top layer
    // is lawful, so the editor opens and an unedited save
    // reproduces the bytes — payload judgment waits for an
    // explicit descend.
    let doc = [0x1A, 0x02, 0x00, 0x01, 0x08, 0x2A];
    let mut editor = editor(&doc);
    assert_eq!(editor.top().count(), 2);
    assert_eq!(editor.save().unwrap(), doc);
}

#[test]
fn a_descend_verdict_is_resident_and_the_payload_stays_readable() {
    // LEN f3 whose payload opens with a zero field tag.
    let doc = [0x1A, 0x02, 0x00, 0x01];
    let mut editor =
        Overhaul::open(Counting::new(&doc), DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();

    let Descent::Parked(fault) = editor.descend(tops[0]).unwrap() else {
        panic!("the garbage interior parks");
    };
    let kind = fault.kind();
    assert_eq!(fault.at(), 2);
    assert!(matches!(kind, FaultKind::FieldZero { .. }));
    assert_eq!(kind.class(), FaultClass::Grammar);

    // The verdict projects with no further walk.
    let Descent::Parked(again) = editor.descend(tops[0]).unwrap() else {
        panic!("the parked verdict is resident");
    };
    assert_eq!((again.at(), again.kind()), (2, kind));

    // The payload stays readable as bytes.
    let mut out = Vec::new();
    editor.read_payload(tops[0], &mut out).unwrap();
    assert_eq!(out, [0x00, 0x01]);

    // A replacement supersedes the parked verdict.
    editor.set_payload(tops[0], &[0x08, 0x07]).unwrap();
    assert_eq!(editor.save().unwrap(), [0x1A, 0x02, 0x08, 0x07]);

    // open + descend (parked) + read_payload + save; the second
    // descend projected the resident verdict walk-free.
    assert_eq!(editor.into_source().begun, 4);
}

#[test]
fn a_depth_refusal_parks_walk_free() {
    // LEN f3 { LEN f3 { varint f1=1 } }
    let doc = [0x1A, 0x04, 0x1A, 0x02, 0x08, 0x01];
    let mut editor =
        Overhaul::open(Counting::new(&doc), DepthLimit::new(1).unwrap()).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    let Descent::Opened { first: Some(inner) } = editor.descend(tops[0]).unwrap() else {
        panic!("the bound admits one layer");
    };
    let Descent::Parked(fault) = editor.descend(inner).unwrap() else {
        panic!("the bound refuses the second layer");
    };
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::DepthExceeded { .. }));
    assert_eq!(fault.kind().class(), FaultClass::Policy);
    assert_eq!(editor.into_source().begun, 2, "a policy refusal costs no walk");
}

#[test]
fn materialize_resolves_a_batch_in_one_walk() {
    // LEN f3 { varint f1=1 } · LEN f4 { varint f1=2 }
    let doc = [0x1A, 0x02, 0x08, 0x01, 0x22, 0x02, 0x08, 0x02];
    let mut editor =
        Overhaul::open(Counting::new(&doc), DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    editor.materialize(&tops).unwrap();
    let first: Vec<_> = editor.children(tops[0]).collect();
    let second: Vec<_> = editor.children(tops[1]).collect();
    assert_eq!(editor.varint_word(first[0]), Some(1));
    assert_eq!(editor.varint_word(second[0]), Some(2));

    // The batch is idempotent: settled handles spend nothing.
    editor.materialize(&tops).unwrap();
    assert_eq!(editor.into_source().begun, 2, "open + one batch walk");
}

#[test]
fn a_batch_parks_one_bad_extent_and_keeps_walking() {
    // LEN f3 { field-zero garbage } · LEN f4 { varint f1=2 }
    let doc = [0x1A, 0x02, 0x00, 0x01, 0x22, 0x02, 0x08, 0x02];
    let mut editor = editor(&doc);
    let tops: Vec<_> = editor.top().collect();
    editor.materialize(&tops).unwrap();

    let Descent::Parked(fault) = editor.descend(tops[0]).unwrap() else {
        panic!("the garbage extent parks");
    };
    assert_eq!(fault.at(), 2);
    let ok: Vec<_> = editor.children(tops[1]).collect();
    assert_eq!(editor.varint_word(ok[0]), Some(2), "the walk continued past the parked extent");
}

#[test]
fn open_refuses_an_unlawful_root_layer_whole() {
    fn refusal(bytes: &[u8]) -> (SliceSource<'_>, Fault) {
        match Overhaul::open(SliceSource::new(bytes), DepthLimit::REFERENCE) {
            Ok(_) => panic!("the unlawful root layer must refuse"),
            Err((source, OpenFault::Wire(fault))) => (source, fault),
            Err((_, fault)) => panic!("a wire refusal was expected, got {fault:?}"),
        }
    }

    // Field zero at the root.
    let (source, fault) = refusal(&[0x00, 0x01]);
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::FieldZero { .. }));
    assert_eq!(source.bytes(), [0x00, 0x01], "the source rides back beside the mark");

    // A group code is this dialect's capability refusal.
    let (_, fault) = refusal(&[0x0B, 0x0C]);
    assert!(matches!(fault.kind(), FaultKind::GroupCode { .. }));
    assert_eq!(fault.kind().class(), FaultClass::Capability);

    // A LEN declaring past the source end.
    let (_, fault) = refusal(&[0x1A, 0x05, 0x08]);
    assert!(matches!(fault.kind(), FaultKind::LenOverrun { zone_left: 1, .. }));
}

#[test]
fn fetch_faces_answer_authored_and_scanned_payloads() {
    let mut editor = editor(&NEST);
    let tops: Vec<_> = editor.top().collect();

    // Scanned: one fetch walk hands the source extent.
    let mut out = alloc::vec![0xEE];
    editor.read_payload(tops[0], &mut out).unwrap();
    assert_eq!(out, [0xEE, 0x08, 0x01]);

    // Scalars are row-resident; the fetch faces refuse them.
    assert!(matches!(
        editor.read_payload(tops[1], &mut out),
        Err(FetchFault::KindMismatch { have: RecordKind::Varint })
    ));
    assert_eq!(out, [0xEE, 0x08, 0x01], "a refusal hands nothing");

    // Authored: answered from the store, sink face included.
    editor.set_payload(tops[0], &[0xAA]).unwrap();
    let mut sunk = Vec::new();
    editor.payload_sink(tops[0], |view| sunk.extend_from_slice(view)).unwrap();
    assert_eq!(sunk, [0xAA]);
}

#[test]
fn a_fetch_truncates_to_its_mark_on_a_tear() {
    // The fetch walk sees a source shorter than the measured
    // payload extent.
    let source = Shifting { full: &NEST, later: &NEST[..3], begun: 0 };
    let mut editor = Overhaul::open(source, DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    let mut out = alloc::vec![0xEE];
    let fault = editor.read_payload(tops[0], &mut out).unwrap_err();
    assert!(matches!(fault, FetchFault::Torn { .. }));
    assert_eq!(out, [0xEE], "the buffer is back at its entry mark");
}

#[test]
fn growth_before_an_extent_is_invisible_to_fetch_and_descend() {
    // Two bytes prepended before every measured coordinate: the
    // fetch and descend walks seek to the measured start and stay
    // inside the measured extent, both satisfied by the longer
    // source — no tear is visible to either face.
    let grown: [u8; 8] = [0xEE, 0xEE, 0x1A, 0x02, 0x08, 0x01, 0x08, 0x2A];
    let source = Shifting { full: &NEST, later: &grown, begun: 0 };
    let mut editor = Overhaul::open(source, DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();

    // The fetch hands the displaced bytes, faultless.
    let mut out = Vec::new();
    editor.read_payload(tops[0], &mut out).unwrap();
    assert_eq!(out, [0x1A, 0x02], "the displaced bytes ride out, not the scanned payload");

    // The descend judges the displaced bytes as the document's
    // own: a parked fault the true payload (varint f1=1) never
    // spelled, its coordinate the displaced prefix's offset.
    let Descent::Parked(fault) = editor.descend(tops[0]).unwrap() else {
        panic!("the displaced interior parks a fabricated verdict");
    };
    assert_eq!(fault.at(), 3);
    assert!(matches!(fault.kind(), FaultKind::LenOverrun { .. }));
}

#[test]
fn an_equal_length_content_tear_is_the_pinned_residual() {
    // Same length, different payload bytes on the later walks:
    // the fetch does NOT fault — the output differs. Byte
    // identity across walks is the provider's obligation, not a
    // machine judgment; this row pins the contract's edge.
    let flipped: [u8; 6] = [0x1A, 0x02, 0x58, 0x59, 0x08, 0x2A];
    let source = Shifting { full: &NEST, later: &flipped, begun: 0 };
    let mut editor = Overhaul::open(source, DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    let mut out = Vec::new();
    editor.read_payload(tops[0], &mut out).unwrap();
    assert_eq!(out, [0x58, 0x59], "the fetch hands the flipped bytes, faultless");
    assert_ne!(out, [0x08, 0x01]);
}

#[test]
fn a_torn_source_is_refused_at_save() {
    let source = Shifting { full: &FLAT, later: &FLAT[..4], begun: 0 };
    let mut editor = Overhaul::open(source, DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    editor.set_varint(tops[0], 7).unwrap();

    let mut out = alloc::vec![0xEE];
    let fault = editor.save_into(&mut out).unwrap_err();
    assert!(matches!(fault, SaveFault::Torn { .. }));
    assert_eq!(out, [0xEE], "the buffer is back at its entry mark");
}

#[test]
fn a_grown_source_is_refused_at_save() {
    // The save walk is the one face anchored to the measured
    // total: its end probe finds the grown source still holding
    // bytes at the measured end and refuses — the contrast to the
    // fetch and descend faces, which cannot see growth.
    let grown: [u8; 8] = [0xEE, 0xEE, 0x1A, 0x02, 0x08, 0x01, 0x08, 0x2A];
    let source = Shifting { full: &NEST, later: &grown, begun: 0 };
    let mut editor = Overhaul::open(source, DepthLimit::REFERENCE).map_err(|_| ()).unwrap();

    let mut out = alloc::vec![0xEE];
    let fault = editor.save_into(&mut out).unwrap_err();
    assert!(matches!(fault, SaveFault::Torn { at: 6 }), "the measured total is the anchor");
    assert_eq!(out, [0xEE], "the buffer is back at its entry mark");
}

#[test]
fn save_sink_names_the_handed_prefix() {
    let source = Shifting { full: &FLAT, later: &FLAT[..4], begun: 0 };
    let mut editor = Overhaul::open(source, DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    editor.set_varint(tops[1], 7).unwrap();

    let mut handed = Vec::new();
    let fault = editor.save_sink(|view| handed.extend_from_slice(view)).unwrap_err();
    assert!(matches!(fault.fault, SaveFault::Torn { .. }));
    assert_eq!(fault.handed, handed.len() as u64, "the prefix is named exactly");
}

#[test]
fn saves_are_repeatable_walks_and_sizing_walks_nothing() {
    let mut editor =
        Overhaul::open(Counting::new(&FLAT), DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    editor.set_varint(tops[0], 300).unwrap();

    let expected = [0x08, 0xAC, 0x02, 0x10, 0x2A];
    assert_eq!(editor.save_len().unwrap(), expected.len() as u64);
    assert_eq!(editor.save().unwrap(), expected);
    assert_eq!(editor.save().unwrap(), expected, "a repeated save is one more lawful walk");
    assert_eq!(editor.into_source().begun, 3, "open + two saves; the sizing pass walked nothing");
}

#[cfg(feature = "patch-groupless")]
#[test]
fn the_replay_editor_matches_its_buffered_twin() {
    use crate::patch::groupless::{Descent as PatchDescent, InsertAt as PatchAt, Patch};

    // LEN f5 { LEN f3 { varint f1=1 } } · varint f2=42 · I32 f6
    let doc = [
        0x2A, 0x04, 0x1A, 0x02, 0x08, 0x01, //
        0x10, 0x2A, //
        0x35, 0x0D, 0x0C, 0x0B, 0x0A,
    ];
    let f7 = FieldNumber::new(7).unwrap();

    let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    let PatchDescent::Opened { first: Some(kid) } = patch.descend(tops[0]).unwrap() else {
        panic!("the buffered twin opens the interior");
    };
    let PatchDescent::Opened { first: Some(leaf) } = patch.descend(kid).unwrap() else {
        panic!("the buffered twin opens the inner layer");
    };
    patch.set_varint(leaf, 300).unwrap();
    patch.set_i32(tops[2], 0xAABB_CCDD).unwrap();
    patch.delete(tops[1]).unwrap();
    patch.insert_varint(PatchAt::TailOf(None), f7, 7).unwrap();
    let buffered = patch.save().unwrap();

    let mut replay = editor(&doc);
    let tops: Vec<_> = replay.top().collect();
    let Descent::Opened { first: Some(kid) } = replay.descend(tops[0]).unwrap() else {
        panic!("the replay editor opens the interior");
    };
    let Descent::Opened { first: Some(leaf) } = replay.descend(kid).unwrap() else {
        panic!("the replay editor opens the inner layer");
    };
    replay.set_varint(leaf, 300).unwrap();
    replay.set_i32(tops[2], 0xAABB_CCDD).unwrap();
    replay.delete(tops[1]).unwrap();
    replay.insert_varint(InsertAt::TailOf(None), f7, 7).unwrap();

    assert_eq!(replay.save().unwrap(), buffered, "one edit sequence, byte-equal products");
}

#[test]
fn the_borrowed_and_copy_siblings_share_the_contract() {
    // LEN f2 "hi" · varint f1=7
    let msg = [0x12, 0x02, 0x68, 0x69, 0x08, 0x07];
    let payload = [0x61u8, 0x62, 0x63];

    let mut mixed = editor(&msg);
    let top = mixed.top().next().unwrap();
    mixed.set_payload(top, &payload).unwrap();
    let expected = mixed.save().unwrap();

    let mut borrowed = BorrowOverhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let top = borrowed.top().next().unwrap();
    borrowed.set_payload(top, &payload).unwrap();
    assert_eq!(borrowed.save().unwrap(), expected);

    let mut copied = CopyOverhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let top = copied.top().next().unwrap();
    {
        let transient = alloc::vec![0x61, 0x62, 0x63];
        copied.set_payload(top, &transient).unwrap();
    } // the temporary's owner dies; the copied install keeps its bytes
    assert_eq!(copied.save().unwrap(), expected);
    assert_eq!(expected, [0x12, 0x03, 0x61, 0x62, 0x63, 0x08, 0x07]);
}

#[test]
fn the_siblings_insert_and_fetch_through_their_own_backings() {
    let msg = [0x08, 0x07];
    let f2 = FieldNumber::new(2).unwrap();
    let template = [0x10u8, 0x2A];

    let mut borrowed = BorrowOverhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let record = borrowed.insert_payload(InsertAt::TailOf(None), f2, &template).unwrap();
    let mut fetched = Vec::new();
    borrowed.read_payload(record, &mut fetched).unwrap();
    // The borrowed slot retains the caller's slice: pointer
    // identity through the sink face.
    borrowed
        .payload_sink(record, |view| {
            assert!(core::ptr::eq(view.as_ptr(), template.as_ptr()));
        })
        .unwrap();
    assert_eq!(fetched, template);
    assert_eq!(borrowed.save().unwrap(), [0x08, 0x07, 0x12, 0x02, 0x10, 0x2A]);

    let mut copied = CopyOverhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let record = copied.insert_payload(InsertAt::TailOf(None), f2, &template).unwrap();
    fetched.clear();
    copied.read_payload(record, &mut fetched).unwrap();
    assert_eq!(fetched, template);
    assert_eq!(copied.save().unwrap(), [0x08, 0x07, 0x12, 0x02, 0x10, 0x2A]);
}

#[test]
fn a_tail_insert_leaves_an_unopened_len_sibling_verbatim() {
    // The insertion's edit witness climbs from the container, not
    // the previous sibling: the unopened LEN before the insertion
    // must ride the save verbatim (a falsely touched one would
    // settle as a bodiless spine and drop its payload).
    let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07];
    let mut editor = editor(&msg);
    let f9 = FieldNumber::new(9).unwrap();
    editor.insert_varint(InsertAt::TailOf(None), f9, 1).unwrap();
    assert_eq!(editor.save_len().unwrap(), msg.len() as u64 + 2);
    assert_eq!(editor.save().unwrap(), [0x08, 0x96, 0x01, 0x12, 0x02, 0x08, 0x07, 0x48, 0x01]);
}
