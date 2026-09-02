use alloc::vec::Vec;

use super::*;
use crate::DepthLimit;
use crate::replay_source::{NonMinimalSite, SliceSource};

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

fn open(msg: &[u8]) -> Refit<'_, SliceSource<'_>> {
    Refit::open(SliceSource::new(msg), DepthLimit::REFERENCE).map_err(|(_, fault)| fault).unwrap()
}

#[test]
fn opens_materializes_groups_eagerly() {
    // group f1 { varint f2=3 } · varint f2=42
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
    let editor = open(&msg);
    assert_eq!(editor.source_len(), msg.len() as u64);
    let tops: Vec<_> = editor.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(editor.kind(tops[0]), RecordKind::Group);
    assert_eq!(editor.field(tops[0]), f(1));
    let inner = editor.children(tops[0]).next().unwrap();
    assert_eq!(editor.varint_word(inner), Some(3));
    assert_eq!(editor.parent(inner), Some(tops[0]));
}

#[test]
fn a_clean_save_is_the_source_verbatim() {
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
    let mut editor = open(&msg);
    assert_eq!(editor.save_len().unwrap(), msg.len() as u64);
    assert_eq!(editor.save().unwrap(), msg);
}

#[test]
fn group_framing_tags_ride_saves_verbatim_around_interior_edits() {
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
    let mut editor = open(&msg);
    let group = editor.top().next().unwrap();
    let inner = editor.children(group).next().unwrap();
    editor.set_varint(inner, 7).unwrap();
    assert_eq!(editor.save().unwrap(), [0x0B, 0x10, 0x07, 0x0C, 0x10, 0x2A]);
}

#[test]
fn a_padded_group_end_tag_refuses_at_the_door() {
    // group f1 { } with its end tag padded to two bytes.
    let padded = [0x0B, 0x8C, 0x00];
    let Err((_, OpenFault::Wire(fault))) =
        Refit::open(SliceSource::new(&padded), DepthLimit::REFERENCE)
    else {
        panic!("the padded end tag refuses at the canonical door")
    };
    assert_eq!(fault.at(), 1);
    let FaultKind::NonMinimal(refusal) = fault.kind() else { panic!("the site is typed") };
    assert!(matches!(refusal.site(), NonMinimalSite::Tag));
    assert_eq!((refusal.width(), refusal.field()), (2, None));
}

#[test]
fn a_padded_word_inside_a_payload_parks_at_descend() {
    // LEN f2 wrapping a group whose end tag is padded.
    let msg = [0x12, 0x03, 0x0B, 0x8C, 0x00];
    let mut editor = open(&msg);
    let top = editor.top().next().unwrap();
    let Descent::Parked(fault) = editor.descend(top).unwrap() else {
        panic!("the padded interior parks")
    };
    assert!(matches!(fault.kind(), FaultKind::NonMinimal(_)));
    assert!(matches!(fault.kind().class(), crate::FaultClass::Policy));
}

#[test]
fn inserted_groups_emit_minimal_framing_and_span() {
    let msg = [0x10, 0x2A];
    let mut editor = open(&msg);
    let group = editor.insert_group(InsertAt::TailOf(None), f(3)).unwrap();
    editor.insert_varint(InsertAt::TailOf(Some(group)), f(1), 7).unwrap();
    assert_eq!(editor.save().unwrap(), [0x10, 0x2A, 0x1B, 0x08, 0x07, 0x1C]);
    let spans = editor.save_spans().unwrap();
    let entries: Vec<_> = spans.iter().collect();
    // varint · group (enclosing) · interior varint.
    assert_eq!(entries.len(), 3);
    assert_eq!((entries[1].0, entries[1].1.start(), entries[1].1.end()), (group, 2, 6));
    assert_eq!((entries[2].1.start(), entries[2].1.end()), (3, 5));
}

#[test]
fn group_nesting_spends_the_depth_budget_at_the_open_walk() {
    // group f1 { group f1 { } } against a bound of one.
    let msg = [0x0B, 0x0B, 0x0C, 0x0C];
    let Err((_, OpenFault::Wire(fault))) =
        Refit::open(SliceSource::new(&msg), DepthLimit::new(1).unwrap())
    else {
        panic!("nesting past the bound refuses the open")
    };
    assert!(matches!(fault.kind(), FaultKind::DepthExceeded { .. }));
    assert_eq!(fault.at(), 1);
}

#[test]
fn trailing_group_bytes_answer_the_covering_group() {
    // group f1 { varint f2=3 } — byte 3 is the end tag.
    let msg = [0x0B, 0x10, 0x03, 0x0C];
    let editor = open(&msg);
    let group = editor.top().next().unwrap();
    let inner = editor.children(group).next().unwrap();
    assert_eq!(editor.narrowest(0), Some(group));
    assert_eq!(editor.narrowest(2), Some(inner));
    assert_eq!(editor.narrowest(3), Some(group));
    assert_eq!(editor.narrowest(4), None);
}
