use alloc::vec::Vec;

use super::*;
use crate::replay_source::SliceSource;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

#[test]
fn opens_materializes_groups_eagerly() {
    // group f1 { varint f2=3 } · varint f2=42
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
    let editor = Maintain::open(SliceSource::new(&msg)).unwrap();
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
    let mut editor = Maintain::open(SliceSource::new(&msg)).unwrap();
    assert_eq!(editor.save_len().unwrap(), msg.len() as u64);
    assert_eq!(editor.save().unwrap(), msg);
}

#[test]
fn group_framing_tags_ride_saves_verbatim_around_interior_edits() {
    let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
    let mut editor = Maintain::open(SliceSource::new(&msg)).unwrap();
    let group = editor.top().next().unwrap();
    let inner = editor.children(group).unwrap().next().unwrap();
    editor.set_varint(inner, 7).unwrap();
    assert_eq!(editor.save().unwrap(), [0x0B, 0x10, 0x07, 0x0C, 0x10, 0x2A]);
    editor.revert();
    assert_eq!(editor.save().unwrap(), msg);
}
