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

fn refusal(bytes: &[u8]) -> Fault {
    match Overhaul::open(SliceSource::new(bytes), DepthLimit::REFERENCE) {
        Ok(_) => panic!("the unlawful root layer must refuse"),
        Err((_, OpenFault::Wire(fault))) => fault,
        Err((_, fault)) => panic!("a wire refusal was expected, got {fault:?}"),
    }
}

// group f1 { varint f2=1 } · varint f2=42
const GROUPED: [u8; 6] = [0x0B, 0x10, 0x01, 0x0C, 0x10, 0x2A];

// LEN f3 { varint f1=1 } · varint f1=42 — the torn rows' fixture.
const NEST: [u8; 6] = [0x1A, 0x02, 0x08, 0x01, 0x08, 0x2A];

#[test]
fn an_editor_with_no_edits_saves_the_source_bytes() {
    let mut editor = editor(&GROUPED);
    assert_eq!(editor.save_len().unwrap(), GROUPED.len() as u64);
    assert_eq!(editor.save().unwrap(), GROUPED);
}

#[test]
fn group_interiors_are_standing_from_the_open_walk() {
    let mut editor =
        Overhaul::open(Counting::new(&GROUPED), DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    assert_eq!(editor.kind(tops[0]), RecordKind::Group);

    // Children answer immediately, and a group descend is
    // walk-free — the batch face settles it walk-free too.
    let inner = editor.children(tops[0]).next().unwrap();
    assert_eq!(editor.varint_word(inner), Some(1));
    assert_eq!(editor.parent(inner), Some(tops[0]));
    let Descent::Opened { first: Some(first) } = editor.descend(tops[0]).unwrap() else {
        panic!("a group's interior is standing");
    };
    assert_eq!(first, inner);
    editor.materialize(&[tops[0]]).unwrap();
    assert_eq!(editor.into_source().begun, 1, "open alone; no interior walk exists");
}

#[test]
fn a_mixed_batch_settles_groups_free_and_walks_the_lens() {
    // group f1 {} · LEN f3 { varint f1=1 } · LEN f4 { varint f1=2 }
    let doc = [0x0B, 0x0C, 0x1A, 0x02, 0x08, 0x01, 0x22, 0x02, 0x08, 0x02];
    let mut editor =
        Overhaul::open(Counting::new(&doc), DepthLimit::REFERENCE).map_err(|_| ()).unwrap();
    let tops: Vec<_> = editor.top().collect();
    editor.materialize(&tops).unwrap();
    let first: Vec<_> = editor.children(tops[1]).collect();
    let second: Vec<_> = editor.children(tops[2]).collect();
    assert_eq!(editor.varint_word(first[0]), Some(1));
    assert_eq!(editor.varint_word(second[0]), Some(2));
    assert_eq!(editor.into_source().begun, 2, "open + one batch walk; the group cost none");
}

#[test]
fn group_geometry_is_measured_with_padded_framing() {
    // group f1 with two-byte padded start and end tags.
    let doc = [0x8B, 0x00, 0x10, 0x01, 0x8C, 0x00];
    let mut editor = editor(&doc);
    let tops: Vec<_> = editor.top().collect();
    let Some(RecordSpans::Group { tag, interior, end }) = editor.source_spans(tops[0]) else {
        panic!("a group geometry was expected");
    };
    assert_eq!((tag.start(), tag.end()), (0, 2));
    assert_eq!((interior.start(), interior.end()), (2, 4));
    assert_eq!((end.start(), end.end()), (4, 6));
    assert_eq!(editor.save().unwrap(), doc);

    // An interior edit re-emits its record; both padded group
    // tags still ride verbatim.
    let inner = editor.children(tops[0]).next().unwrap();
    editor.set_varint(inner, 7).unwrap();
    assert_eq!(editor.save().unwrap(), [0x8B, 0x00, 0x10, 0x07, 0x8C, 0x00]);
}

#[test]
fn open_refuses_broken_group_framing_whole() {
    // An orphaned end tag.
    let fault = refusal(&[0x0C]);
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::GroupEndOrphan { .. }));
    assert_eq!(fault.kind().class(), FaultClass::Grammar);

    // A mismatched end tag (group f1 closed as f2).
    let fault = refusal(&[0x0B, 0x14]);
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::GroupEndMismatch { .. }));

    // A group the source ends around.
    let fault = refusal(&[0x0B, 0x10, 0x01]);
    assert_eq!(fault.at(), 3);
    assert!(matches!(fault.kind(), FaultKind::GroupUnclosed { .. }));
}

#[test]
fn source_groups_spend_the_depth_budget_at_open() {
    // group f1 { group f1 {} } against a bound of one.
    let doc = [0x0B, 0x0B, 0x0C, 0x0C];
    let fault = match Overhaul::open(SliceSource::new(&doc), DepthLimit::new(1).unwrap()) {
        Ok(_) => panic!("the nesting must refuse at the bound"),
        Err((_, OpenFault::Wire(fault))) => fault,
        Err((_, fault)) => panic!("a depth refusal was expected, got {fault:?}"),
    };
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::DepthExceeded { .. }));
    assert_eq!(fault.kind().class(), FaultClass::Policy);

    // The same nesting is lawful one bound up.
    drop(editor(&doc));
}

#[test]
fn an_edit_inside_a_group_inside_a_len_cascades_the_prefix() {
    // LEN f3 { group f1 { varint f2=1 } }
    let doc = [0x1A, 0x04, 0x0B, 0x10, 0x01, 0x0C];
    let mut editor = editor(&doc);
    let tops: Vec<_> = editor.top().collect();
    let Descent::Opened { first: Some(group) } = editor.descend(tops[0]).unwrap() else {
        panic!("the LEN interior opens");
    };
    assert_eq!(editor.kind(group), RecordKind::Group);
    let inner = editor.children(group).next().unwrap();
    editor.set_varint(inner, 300).unwrap();
    // The value grew a byte; the LEN prefix re-prices, the group
    // tags ride verbatim (no prefix of their own).
    let expected = [0x1A, 0x05, 0x0B, 0x10, 0xAC, 0x02, 0x0C];
    assert_eq!(editor.save_len().unwrap(), expected.len() as u64);
    assert_eq!(editor.save().unwrap(), expected);
}

#[test]
fn an_unclosed_group_inside_a_len_parks_at_descend() {
    // LEN f3 { group start alone } · varint f2=42
    let doc = [0x1A, 0x01, 0x0B, 0x10, 0x2A];
    let mut editor = editor(&doc);
    let tops: Vec<_> = editor.top().collect();
    let Descent::Parked(fault) = editor.descend(tops[0]).unwrap() else {
        panic!("the unclosed interior group parks");
    };
    assert_eq!(fault.at(), 3);
    assert!(matches!(fault.kind(), FaultKind::GroupUnclosed { .. }));

    // The record beside it is untouched; the save reproduces.
    assert_eq!(editor.save().unwrap(), doc);
}

#[test]
fn a_group_deletion_vanishes_the_record_whole() {
    let mut editor = editor(&GROUPED);
    let tops: Vec<_> = editor.top().collect();
    editor.delete(tops[0]).unwrap();
    assert_eq!(editor.save().unwrap(), [0x10, 0x2A], "start tag, interior, and end tag vanish");
}

#[test]
fn an_authored_group_emits_minimal_tags_around_its_interior() {
    let mut editor = editor(&[0x10, 0x2A]);
    let f1 = FieldNumber::new(1).unwrap();
    let f2 = FieldNumber::new(2).unwrap();
    let group = editor.insert_group(InsertAt::HeadOf(None), f1).unwrap();
    assert_eq!(editor.status(group), EditStatus::Inserted);
    assert_eq!(editor.span(group), None, "authored records carry no source geometry");
    editor.insert_varint(InsertAt::TailOf(Some(group)), f2, 7).unwrap();
    assert_eq!(editor.save().unwrap(), [0x0B, 0x10, 0x07, 0x0C, 0x10, 0x2A]);

    // An empty authored group is two adjacent tags.
    let mut editor = self::editor(&[]);
    editor.insert_group(InsertAt::TailOf(None), f1).unwrap();
    assert_eq!(editor.save().unwrap(), [0x0B, 0x0C]);
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
fn group_payload_faces_refuse_by_kind() {
    let mut editor = editor(&GROUPED);
    let tops: Vec<_> = editor.top().collect();
    let mut out = Vec::new();
    assert!(matches!(
        editor.read_payload(tops[0], &mut out),
        Err(FetchFault::KindMismatch { have: RecordKind::Group })
    ));
    assert_eq!(
        editor.set_payload(tops[0], &[0x00]).unwrap_err(),
        EditFault::KindMismatch { have: RecordKind::Group }
    );
}

#[cfg(feature = "patch-grouped")]
#[test]
fn the_replay_editor_matches_its_buffered_twin() {
    use crate::patch::grouped::{InsertAt as PatchAt, Patch};

    // group f5 { varint f1=1 · LEN f3 "hi" } · varint f2=42
    let doc = [
        0x2B, 0x08, 0x01, 0x1A, 0x02, 0x68, 0x69, 0x2C, //
        0x10, 0x2A,
    ];
    let f7 = FieldNumber::new(7).unwrap();

    let mut patch = Patch::open(&doc, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    let kids: Vec<_> = patch.children(tops[0]).collect();
    patch.set_varint(kids[0], 300).unwrap();
    patch.set_payload(kids[1], b"world").unwrap();
    patch.delete(tops[1]).unwrap();
    let group = patch.insert_group(PatchAt::TailOf(None), f7).unwrap();
    patch.insert_varint(PatchAt::TailOf(Some(group)), f7, 7).unwrap();
    let buffered = patch.save().unwrap();

    let mut replay = editor(&doc);
    let tops: Vec<_> = replay.top().collect();
    let kids: Vec<_> = replay.children(tops[0]).collect();
    replay.set_varint(kids[0], 300).unwrap();
    replay.set_payload(kids[1], b"world").unwrap();
    replay.delete(tops[1]).unwrap();
    let group = replay.insert_group(InsertAt::TailOf(None), f7).unwrap();
    replay.insert_varint(InsertAt::TailOf(Some(group)), f7, 7).unwrap();

    assert_eq!(replay.save().unwrap(), buffered, "one edit sequence, byte-equal products");
}

#[test]
fn the_borrowed_and_copy_siblings_share_the_contract() {
    // group f1 { LEN f2 "hi" } · varint f2=42
    let msg = [0x0B, 0x12, 0x02, 0x68, 0x69, 0x0C, 0x10, 0x2A];
    let payload = [0x61u8, 0x62, 0x63];

    let mut mixed = editor(&msg);
    let group = mixed.top().next().unwrap();
    let inner = mixed.children(group).next().unwrap();
    mixed.set_payload(inner, &payload).unwrap();
    let expected = mixed.save().unwrap();

    let mut borrowed = BorrowOverhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let group = borrowed.top().next().unwrap();
    let inner = borrowed.children(group).next().unwrap();
    borrowed.set_payload(inner, &payload).unwrap();
    assert_eq!(borrowed.save().unwrap(), expected);

    let mut copied = CopyOverhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let group = copied.top().next().unwrap();
    let inner = copied.children(group).next().unwrap();
    {
        let transient = alloc::vec![0x61, 0x62, 0x63];
        copied.set_payload(inner, &transient).unwrap();
    } // the temporary's owner dies; the copied install keeps its bytes
    assert_eq!(copied.save().unwrap(), expected);
    assert_eq!(expected, [0x0B, 0x12, 0x03, 0x61, 0x62, 0x63, 0x0C, 0x10, 0x2A]);
}

#[test]
fn the_siblings_author_groups_through_their_own_backings() {
    let msg = [0x10, 0x2A];
    let f3 = FieldNumber::new(3).unwrap();
    let f1 = FieldNumber::new(1).unwrap();

    let mut borrowed = BorrowOverhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let group = borrowed.insert_group(InsertAt::TailOf(None), f3).unwrap();
    borrowed.insert_varint(InsertAt::TailOf(Some(group)), f1, 7).unwrap();
    assert_eq!(borrowed.save().unwrap(), [0x10, 0x2A, 0x1B, 0x08, 0x07, 0x1C]);

    let mut copied = CopyOverhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let group = copied.insert_group(InsertAt::TailOf(None), f3).unwrap();
    copied.insert_varint(InsertAt::TailOf(Some(group)), f1, 7).unwrap();
    assert_eq!(copied.save().unwrap(), [0x10, 0x2A, 0x1B, 0x08, 0x07, 0x1C]);
}

#[test]
fn a_tail_insert_leaves_an_unopened_len_sibling_verbatim() {
    // The insertion's edit witness climbs from the container, not
    // the previous sibling: the unopened LEN before the insertion
    // must ride the save verbatim (a falsely touched one would
    // settle as a bodiless spine and drop its payload).
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x12, 0x02, 0x08, 0x07];
    let mut editor = editor(&msg);
    let f9 = FieldNumber::new(9).unwrap();
    editor.insert_varint(InsertAt::TailOf(None), f9, 1).unwrap();
    assert_eq!(editor.save_len().unwrap(), msg.len() as u64 + 2);
    assert_eq!(
        editor.save().unwrap(),
        [0x0B, 0x10, 0x03, 0x0C, 0x12, 0x02, 0x08, 0x07, 0x48, 0x01]
    );
}
