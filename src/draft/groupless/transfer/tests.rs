//! The transfer siblings' behavioral rows.

use alloc::vec::Vec;

use super::{EditFault, Handle, InsertAt, PayloadTarget, TransferBorrowDraft, TransferDraft};
use crate::wire::FieldNumber;

#[track_caller]
fn h(s: &str) -> Vec<u8> {
    let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "odd hex literal");
    hex.chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap();
            let lo = (pair[1] as char).to_digit(16).unwrap();
            (hi * 16 + lo) as u8
        })
        .collect()
}

#[track_caller]
fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

/// Every output face of one draft, cross-checked: `save`,
/// `save_into`, `save_sink` concatenation, and `save_len` all
/// answer the same bytes.
#[track_caller]
fn all_saves(draft: &TransferDraft) -> Vec<u8> {
    let saved = draft.save().expect("save succeeds");
    assert_eq!(
        draft.save_len().expect("save_len succeeds") as usize,
        saved.len(),
        "save_len prices the save"
    );
    let mut into = h("BEEF");
    draft.save_into(&mut into).expect("save_into succeeds");
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    draft.save_sink(|chunk| streamed.extend_from_slice(chunk)).expect("save_sink succeeds");
    assert_eq!(streamed, saved, "the sink concatenation is the save");
    saved
}

#[test]
fn transfers_preserve_padded_source_framing_byte_exact() {
    // varint f1 (padded tag+value) · LEN f2 (padded prefix) "hi".
    let data = h("88 00 81 00 12 82 00 68 69");
    let mut d = TransferDraft::open(data.clone()).unwrap();
    let t: Vec<Handle> = d.top().collect();
    d.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    d.move_record(t[1], InsertAt::HeadOf(None)).unwrap();
    assert_eq!(all_saves(&d)[..], h("12 82 00 68 69 88 00 81 00 88 00 81 00")[..]);
    d.revert_all();
    assert_eq!(all_saves(&d)[..], data[..]);
}

#[test]
fn a_replaced_designation_keeps_the_target_prefix_while_lengths_match() {
    // LEN f1 "no" · LEN f2 (padded prefix) "hi" · LEN f3 "abc" —
    // designating a same-length payload keeps the padded target
    // prefix; a longer one re-derives it minimally. Authored rows
    // refuse designation outright.
    let data = h("0A 02 6E 6F 12 82 00 68 69 1A 03 61 62 63");
    let mut d = TransferDraft::open(data.clone()).unwrap();
    let t: Vec<Handle> = d.top().collect();
    d.copy_payload(t[0], PayloadTarget::Replace(t[1])).unwrap();
    assert_eq!(all_saves(&d)[..], h("0A 02 6E 6F 12 82 00 6E 6F 1A 03 61 62 63")[..]);
    d.revert();
    d.copy_payload(t[2], PayloadTarget::Replace(t[1])).unwrap();
    assert_eq!(all_saves(&d)[..], h("0A 02 6E 6F 12 03 61 62 63 1A 03 61 62 63")[..]);
    d.revert();
    let authored = d.insert_payload(InsertAt::TailOf(None), f(4), b"zz").unwrap();
    assert!(matches!(
        d.copy_payload(authored, PayloadTarget::Replace(t[1])),
        Err(EditFault::SourceNotBacked)
    ));
    d.revert_all();
    assert_eq!(all_saves(&d)[..], data[..]);
}

#[test]
fn a_move_is_one_command_one_pending_one_revert() {
    let data = h("08 05 12 02 68 69");
    let mut d = TransferDraft::open(data.clone()).unwrap();
    let t: Vec<Handle> = d.top().collect();
    assert_eq!(d.pending(), 0);
    d.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(d.pending(), 1);
    assert_eq!(all_saves(&d)[..], h("12 02 68 69 08 05")[..]);
    d.revert();
    assert_eq!(d.pending(), 0);
    assert_eq!(all_saves(&d)[..], data[..]);
}

#[test]
fn a_padded_import_lands_first_class_and_rides_byte_exact() {
    // The outside record carries a padded prefix; the import keeps
    // it byte-exact, and its interior is first-class after descent.
    let outside_doc = h("12 82 00 68 69");
    let outside = TransferDraft::open(outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = h("08 05");
    let mut d = TransferDraft::open(data.clone()).unwrap();
    let import =
        d.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(d.payload_bytes(import).unwrap(), b"hi");
    assert_eq!(all_saves(&d)[..], h("08 05 12 82 00 68 69")[..]);
    d.revert_all();
    assert_eq!(all_saves(&d)[..], data[..]);
}

#[test]
fn the_borrow_twin_retains_imports_as_slots() {
    // The borrowed twin retains the designated record's bytes; the
    // owner outlives the machine by scope order here.
    let outside_doc = h("12 02 68 69");
    let outside = TransferBorrowDraft::open(outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = h("08 05");
    let mut d = TransferBorrowDraft::open(data.clone()).unwrap();
    let import =
        d.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(d.payload_bytes(import).unwrap(), b"hi");
    assert_eq!(d.save().unwrap()[..], h("08 05 12 02 68 69")[..]);
    d.revert();
    assert_eq!(d.save().unwrap()[..], data[..]);
}
