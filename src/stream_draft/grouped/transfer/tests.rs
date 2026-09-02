//! The transfer siblings' behavioral rows.

use alloc::vec::Vec;

use super::super::Ingest;
use super::{Descent, Handle, InsertAt, TransferBorrowDraft, TransferDraft};

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
    // group f1 (padded open tag, cut by a chunk edge) { varint f2 }
    // · varint f3: the sealed group closure moves whole and reverts
    // whole, every met width intact.
    let mut d = sealed(&[&[0x8B, 0x00, 0x10], &[0x81, 0x00, 0x0C, 0x18, 0x07]]);
    let t: Vec<Handle> = d.top().collect();
    d.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(d.pending(), 1);
    assert_eq!(d.save().unwrap(), [0x18, 0x07, 0x8B, 0x00, 0x10, 0x81, 0x00, 0x0C]);
    d.revert();
    assert_eq!(d.save().unwrap(), [0x8B, 0x00, 0x10, 0x81, 0x00, 0x0C, 0x18, 0x07]);
}

#[test]
fn an_imported_group_closure_is_first_class_on_the_sealed_machine() {
    // Group f1 with a two-byte open tag and a three-byte end tag —
    // the interior extent and close window come from the zone's own
    // words, and descent parses the import into editable rows.
    let outside = sealed(&[&[0x8B, 0x00, 0x10, 0x05, 0x8C, 0x80, 0x00]]);
    let source = outside.top().next().unwrap();

    let mut d = sealed(&[&[0x08, 0x2A]]);
    let imported =
        d.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(d.save().unwrap(), [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x05, 0x8C, 0x80, 0x00]);

    let Descent::Opened { first: Some(kid) } = d.descend(imported).unwrap() else { unreachable!() };
    d.set_varint(kid, 9).unwrap();
    // The met tags ride verbatim around the walked interior.
    assert_eq!(d.save().unwrap(), [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x09, 0x8C, 0x80, 0x00]);
    d.revert_all();
    assert_eq!(d.save().unwrap(), [0x08, 0x2A]);
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
