use alloc::vec::Vec;

use super::*;
use crate::replay_source::SliceSource;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

#[test]
fn opens_scans_the_top_layer_and_measures_the_total() {
    // varint f1=150 (padded) · LEN f2 "hi"
    let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
    let editor = Maintain::open(SliceSource::new(&msg)).unwrap();
    assert_eq!(editor.source_len(), msg.len() as u64);
    let tops: Vec<_> = editor.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(editor.varint_word(tops[0]).unwrap(), 150);
    assert_eq!(editor.kind(tops[1]).unwrap(), RecordKind::Len);
    assert_eq!(editor.field(tops[1]).unwrap(), f(2));
}

#[test]
fn a_clean_save_is_the_source_verbatim() {
    let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
    let mut editor = Maintain::open(SliceSource::new(&msg)).unwrap();
    assert_eq!(editor.save_len().unwrap(), msg.len() as u64);
    assert_eq!(editor.save().unwrap(), msg);
}
