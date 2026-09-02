use alloc::vec::Vec;

use super::*;
use crate::replay_source::{NonMinimalSite, SliceSource};

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

#[test]
fn opens_scans_the_top_layer_and_measures_the_total() {
    // varint f1=150 · LEN f2 "hi"
    let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let editor = Commission::open(SliceSource::new(&msg)).unwrap();
    assert_eq!(editor.source_len(), msg.len() as u64);
    let tops: Vec<_> = editor.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(editor.varint_word(tops[0]).unwrap(), 150);
    assert_eq!(editor.kind(tops[1]).unwrap(), RecordKind::Len);
    assert_eq!(editor.field(tops[1]).unwrap(), f(2));
}

#[test]
fn a_clean_save_is_the_source_verbatim() {
    let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let mut editor = Commission::open(SliceSource::new(&msg)).unwrap();
    assert_eq!(editor.save_len().unwrap(), msg.len() as u64);
    assert_eq!(editor.save().unwrap(), msg);
}

#[test]
fn a_padded_root_value_refuses_at_the_door() {
    // varint f1=150 padded to three bytes.
    let padded = [0x08, 0x96, 0x81, 0x00];
    let Err((_, OpenFault::Wire(fault))) = Commission::open(SliceSource::new(&padded)) else {
        panic!("padding refuses at the canonical door")
    };
    assert_eq!(fault.at().source_at(), Some(1));
    let FaultKind::NonMinimal(refusal) = fault.kind() else { panic!("the site is typed") };
    assert!(matches!(refusal.site(), NonMinimalSite::Value));
    assert_eq!((refusal.width(), refusal.field()), (3, Some(f(1))));
    assert!(matches!(fault.kind().class(), crate::FaultClass::Policy));
}

#[test]
fn a_padded_word_inside_an_authored_payload_parks_resident() {
    // The install lands opaque; the descend judges the resident
    // bytes under the same canonical standard, in the slot's own
    // zone coordinates.
    let msg = [0x12, 0x01, 0x61];
    let mut editor = Commission::open(SliceSource::new(&msg)).unwrap();
    let top = editor.top().next().unwrap();
    editor.set_payload(top, &[0x08, 0x87, 0x00]).unwrap();
    let Descent::Parked(fault) = editor.descend(top).unwrap() else {
        panic!("the padded authored interior parks")
    };
    let FaultKind::NonMinimal(refusal) = fault.kind() else { panic!("the site is typed") };
    assert!(matches!(refusal.site(), NonMinimalSite::Value));
    assert_eq!(fault.at().slot(), Some(0));
    assert_eq!(fault.at().authored_at(), Some(1));
}

#[test]
fn revert_restores_the_scanned_reading_walk_free() {
    let msg = [0x08, 0x96, 0x01];
    let mut editor = Commission::open(SliceSource::new(&msg)).unwrap();
    let top = editor.top().next().unwrap();
    editor.set_varint(top, 7).unwrap();
    assert_eq!(editor.save().unwrap(), [0x08, 0x07]);
    editor.revert();
    assert_eq!(editor.varint_word(top).unwrap(), 150);
    assert_eq!(editor.save().unwrap(), msg);
}
