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
fn opens_scans_the_top_layer_and_measures_the_total() {
    // varint f1=150 · LEN f2 "hi"
    let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let editor = open(&msg);
    assert_eq!(editor.source_len(), msg.len() as u64);
    let tops: Vec<_> = editor.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(editor.varint_word(tops[0]), Some(150));
    assert_eq!(editor.kind(tops[1]), RecordKind::Len);
    assert_eq!(editor.field(tops[1]), f(2));
}

#[test]
fn a_clean_save_is_the_source_verbatim() {
    let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let mut editor = open(&msg);
    assert_eq!(editor.save_len().unwrap(), msg.len() as u64);
    assert_eq!(editor.save().unwrap(), msg);
}

#[test]
fn a_padded_root_value_refuses_at_the_door() {
    // varint f1=150 padded to three bytes.
    let padded = [0x08, 0x96, 0x81, 0x00];
    let Err((_, OpenFault::Wire(fault))) =
        Refit::open(SliceSource::new(&padded), DepthLimit::REFERENCE)
    else {
        panic!("padding refuses at the canonical door")
    };
    assert_eq!(fault.at(), 1);
    let FaultKind::NonMinimal(refusal) = fault.kind() else { panic!("the site is typed") };
    assert!(matches!(refusal.site(), NonMinimalSite::Value));
    assert_eq!((refusal.width(), refusal.field()), (3, Some(f(1))));
    assert!(matches!(fault.kind().class(), crate::FaultClass::Policy));
}

#[test]
fn a_padded_payload_word_parks_at_descend() {
    // LEN f2 wrapping varint f1 with a two-byte padded value.
    let msg = [0x12, 0x03, 0x08, 0x87, 0x00];
    let mut editor = open(&msg);
    let top = editor.top().next().unwrap();
    let Descent::Parked(fault) = editor.descend(top).unwrap() else {
        panic!("the padded interior parks")
    };
    assert!(matches!(fault.kind(), FaultKind::NonMinimal(_)));
    // The verdict is resident.
    assert!(matches!(editor.descend(top).unwrap(), Descent::Parked(_)));
}

#[test]
fn scatter_parts_emit_as_one_payload() {
    let msg = [0x12, 0x02, 0x68, 0x69];
    let mut editor = open(&msg);
    let top = editor.top().next().unwrap();
    let parts: [&[u8]; 3] = [b"ab", b"", b"cde"];
    editor.set_payload_parts(top, &parts).unwrap();
    assert_eq!(editor.save().unwrap(), [0x12, 0x05, b'a', b'b', b'c', b'd', b'e']);
    let mut fetched = Vec::new();
    editor.read_payload(top, &mut fetched).unwrap();
    assert_eq!(fetched, b"abcde");
}

#[test]
fn staged_frames_install_exactly_one_command() {
    let msg = [0x12, 0x02, 0x68, 0x69];
    let mut editor = open(&msg);
    let top = editor.top().next().unwrap();
    let mut frame = editor.begin_set_payload(top).unwrap();
    frame.write(b"wor").unwrap();
    frame.write(b"ld").unwrap();
    frame.finish().unwrap();
    assert_eq!(editor.save().unwrap(), [0x12, 0x05, b'w', b'o', b'r', b'l', b'd']);
    // An abandoned frame installs nothing.
    let mut frame = editor.begin_set_payload(top).unwrap();
    frame.write(b"zzzz").unwrap();
    drop(frame);
    assert_eq!(editor.save().unwrap(), [0x12, 0x05, b'w', b'o', b'r', b'l', b'd']);
    // The sized twin is held to its declaration.
    let mut frame = editor.begin_set_payload_sized(top, 2).unwrap();
    assert!(matches!(frame.write(b"abc"), Err(FrameFault::OverDeclared { .. })));
    frame.write(b"a").unwrap();
    assert!(matches!(frame.finish(), Err(FrameFault::UnderDeclared { .. })));
    let mut frame = editor.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), 2).unwrap();
    frame.write(b"ok").unwrap();
    frame.finish().unwrap();
    assert_eq!(
        editor.save().unwrap(),
        [0x12, 0x05, b'w', b'o', b'r', b'l', b'd', 0x1A, 0x02, b'o', b'k']
    );
}

#[test]
fn save_spans_price_the_save_in_output_order() {
    // varint f1=7 · LEN f2 { varint f1=1 }
    let msg = [0x08, 0x07, 0x12, 0x02, 0x08, 0x01];
    let mut editor = open(&msg);
    let tops: Vec<_> = editor.top().collect();
    editor.set_varint(tops[0], 300).unwrap();
    let spans = editor.save_spans().unwrap();
    let entries: Vec<_> = spans.iter().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!((entries[0].1.start(), entries[0].1.end()), (0, 3));
    assert_eq!((entries[1].1.start(), entries[1].1.end()), (3, 7));
    assert_eq!(spans.iter().map(|(_, span)| span.end()).max(), Some(editor.save_len().unwrap()));
    assert_eq!(editor.save().unwrap().len() as u64, editor.save_len().unwrap());
}

#[test]
fn narrowest_answers_the_covering_record() {
    let msg = [0x08, 0x07, 0x12, 0x02, 0x08, 0x01];
    let mut editor = open(&msg);
    let tops: Vec<_> = editor.top().collect();
    assert_eq!(editor.narrowest(0), Some(tops[0]));
    assert_eq!(editor.narrowest(2), Some(tops[1]));
    assert_eq!(editor.narrowest(6), None);
    // The interior narrows once committed.
    let Descent::Opened { first: Some(inner) } = editor.descend(tops[1]).unwrap() else {
        panic!("the payload parses")
    };
    assert_eq!(editor.narrowest(4), Some(inner));
}

#[test]
fn the_borrowed_and_copy_forms_share_the_contract() {
    let msg = [0x12, 0x02, 0x68, 0x69];
    let payload = [0x61u8, 0x62, 0x63];

    let mut borrowed = BorrowRefit::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let top = borrowed.top().next().unwrap();
    borrowed.set_payload(top, &payload).unwrap();
    let saved = borrowed.save().unwrap();

    let mut copied = CopyRefit::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
        .map_err(|(_, fault)| fault)
        .unwrap();
    let top = copied.top().next().unwrap();
    {
        let transient = alloc::vec![0x61, 0x62, 0x63];
        copied.set_payload(top, &transient).unwrap();
    } // the temporary's owner dies; the copied install keeps its bytes
    assert_eq!(copied.save().unwrap(), saved);
    assert_eq!(saved, [0x12, 0x03, 0x61, 0x62, 0x63]);
}
