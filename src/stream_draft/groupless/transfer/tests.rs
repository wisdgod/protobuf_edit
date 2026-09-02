//! The transfer siblings' behavioral rows.

use alloc::vec::Vec;

use super::super::Ingest;
use super::{Handle, InsertAt, PayloadTarget, TransferBorrowDraft, TransferDraft};

#[track_caller]
fn sealed(chunks: &[&[u8]]) -> TransferDraft {
    let mut ingest = Ingest::new();
    for chunk in chunks {
        ingest.feed(chunk).expect("test chunk feeds");
    }
    ingest.finish_transfer().expect("test stream seals")
}

#[test]
fn the_seal_door_publishes_the_transfer_faces_over_the_fed_source() {
    // varint f1 (padded value, cut mid-word by a chunk edge) ·
    // LEN f2 "hi": the ingest grammar and custody are the base
    // cell's; the sealed machine relocates and reverts.
    let mut d = sealed(&[&[0x08, 0x96], &[0x81, 0x00, 0x12, 0x02, 0x68, 0x69]]);
    let t: Vec<Handle> = d.top().collect();
    d.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(d.pending(), 1);
    assert_eq!(d.save().unwrap(), [0x12, 0x02, 0x68, 0x69, 0x08, 0x96, 0x81, 0x00]);
    // A designated payload rides byte-exact behind the target's own
    // framing while the lengths match.
    d.copy_payload(t[1], PayloadTarget::Replace(t[1])).unwrap();
    assert_eq!(d.save().unwrap(), [0x12, 0x02, 0x68, 0x69, 0x08, 0x96, 0x81, 0x00]);
    d.revert();
    d.revert();
    assert_eq!(d.save().unwrap(), [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69]);
}

#[test]
fn an_import_lands_first_class_on_the_sealed_machine() {
    let outside = sealed(&[&[0x12, 0x82, 0x00, 0x68, 0x69]]);
    let source = outside.top().next().unwrap();

    let mut d = sealed(&[&[0x08, 0x05]]);
    let import =
        d.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(d.payload_bytes(import).unwrap(), b"hi");
    // The met padded prefix rides byte-exact.
    assert_eq!(d.save().unwrap(), [0x08, 0x05, 0x12, 0x82, 0x00, 0x68, 0x69]);
    d.revert_all();
    assert_eq!(d.save().unwrap(), [0x08, 0x05]);
}

#[test]
fn the_borrow_door_seals_the_same_parts_under_the_borrowed_supply() {
    let payload = [0x08u8, 0x07];
    let mut ingest = Ingest::new();
    ingest.feed(&[0x12, 0x01, 0x61]).unwrap();
    let mut d: TransferBorrowDraft<'_> = ingest.finish_transfer_borrow().unwrap();
    let record = d.top().next().unwrap();
    d.set_payload(record, &payload).unwrap();
    assert_eq!(d.save().unwrap(), [0x12, 0x02, 0x08, 0x07]);
    d.revert();
    assert_eq!(d.save().unwrap(), [0x12, 0x01, 0x61]);
}
