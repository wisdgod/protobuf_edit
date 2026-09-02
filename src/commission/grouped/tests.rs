use alloc::vec::Vec;

use super::*;
use crate::replay_source::{NonMinimalSite, SliceSource};

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

#[test]
fn opens_materializes_groups_eagerly() {
    // group f1 { varint f2=3 } · varint f2=42
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
    let editor = Commission::open(SliceSource::new(&msg)).unwrap();
    assert_eq!(editor.source_len(), msg.len() as u64);
    let tops: Vec<_> = editor.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(editor.kind(tops[0]).unwrap(), RecordKind::Group);
    assert_eq!(editor.field(tops[0]).unwrap(), f(1));
    let inner = editor.children(tops[0]).unwrap().next().unwrap();
    assert_eq!(editor.varint_word(inner).unwrap(), 3);
    assert_eq!(editor.parent(inner).unwrap(), Some(tops[0]));
}

#[test]
fn a_clean_save_is_the_source_verbatim() {
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
    let mut editor = Commission::open(SliceSource::new(&msg)).unwrap();
    assert_eq!(editor.save_len().unwrap(), msg.len() as u64);
    assert_eq!(editor.save().unwrap(), msg);
}

#[test]
fn group_framing_tags_ride_saves_verbatim_around_interior_edits() {
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
    let mut editor = Commission::open(SliceSource::new(&msg)).unwrap();
    let group = editor.top().next().unwrap();
    let inner = editor.children(group).unwrap().next().unwrap();
    editor.set_varint(inner, 7).unwrap();
    assert_eq!(editor.save().unwrap(), [0x0B, 0x10, 0x07, 0x0C, 0x10, 0x2A]);
    editor.revert();
    assert_eq!(editor.save().unwrap(), msg);
}

#[test]
fn a_padded_group_end_tag_refuses_at_the_door() {
    // group f1 { } with its end tag padded to two bytes.
    let padded = [0x0B, 0x8C, 0x00];
    let Err((_, OpenFault::Wire(fault))) = Commission::open(SliceSource::new(&padded)) else {
        panic!("the padded end tag refuses at the canonical door")
    };
    assert_eq!(fault.at().source_at(), Some(1));
    let FaultKind::NonMinimal(refusal) = fault.kind() else { panic!("the site is typed") };
    assert!(matches!(refusal.site(), NonMinimalSite::Tag));
    assert_eq!((refusal.width(), refusal.field()), (2, None));
}

#[test]
fn a_padded_end_tag_inside_an_authored_payload_parks_resident() {
    let msg = [0x12, 0x01, 0x61];
    let mut editor = Commission::open(SliceSource::new(&msg)).unwrap();
    let top = editor.top().next().unwrap();
    editor.set_payload(top, &[0x0B, 0x8C, 0x00]).unwrap();
    let Descent::Parked(fault) = editor.descend(top).unwrap() else {
        panic!("the padded authored interior parks")
    };
    let FaultKind::NonMinimal(refusal) = fault.kind() else { panic!("the site is typed") };
    assert!(matches!(refusal.site(), NonMinimalSite::Tag));
    assert_eq!((fault.at().slot(), fault.at().authored_at()), (Some(0), Some(1)));
}

#[test]
fn insert_group_births_and_reverts_exactly() {
    let msg = [0x10, 0x2A];
    let mut editor = Commission::open(SliceSource::new(&msg)).unwrap();
    let group = editor.insert_group(InsertAt::TailOf(None), f(3)).unwrap();
    editor.insert_varint(InsertAt::TailOf(Some(group)), f(1), 7).unwrap();
    assert_eq!(editor.save().unwrap(), [0x10, 0x2A, 0x1B, 0x08, 0x07, 0x1C]);
    editor.revert_all();
    assert_eq!(editor.save().unwrap(), msg);
}
