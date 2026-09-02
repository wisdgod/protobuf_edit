//! The transfer siblings' behavioral rows.

use alloc::vec::Vec;

use super::{Descent, Handle, InsertAt, TransferBorrowMarkup, TransferMarkup};
use crate::wire::FieldNumber;

#[test]
fn a_group_closure_moves_whole_and_reverts_whole() {
    // Group f1 { varint f2=5 } · varint f3=7.
    let data = [0x0Bu8, 0x10, 0x05, 0x0C, 0x18, 0x07];
    let mut m = TransferMarkup::open(&data).unwrap();
    let t: Vec<Handle> = m.top().collect();
    m.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(m.pending(), 1);
    assert_eq!(m.save().unwrap(), [0x18, 0x07, 0x0B, 0x10, 0x05, 0x0C]);
    m.revert();
    assert_eq!(m.save().unwrap(), data);
}

#[test]
fn a_padded_group_import_keeps_its_met_framing() {
    // Group f1 with a two-byte open tag and a three-byte end tag —
    // the two met widths differ, so the interior extent and the
    // close window both come from the zone's own words.
    let outside_doc = [0x8Bu8, 0x00, 0x10, 0x05, 0x8C, 0x80, 0x00];
    let outside = TransferMarkup::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = [0x08u8, 0x2A];
    let mut m = TransferMarkup::open(&data).unwrap();
    let imported =
        m.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(m.save().unwrap(), [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x05, 0x8C, 0x80, 0x00]);

    let Descent::Opened { first: Some(kid) } = m.descend(imported).unwrap() else { unreachable!() };
    m.set_varint(kid, 9).unwrap();
    // The met tags ride verbatim around the walked interior.
    assert_eq!(m.save().unwrap(), [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x09, 0x8C, 0x80, 0x00]);
    // The canonical save normalizes the materialized closure whole.
    assert_eq!(m.save_canonical().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x09, 0x0C]);
    m.revert_all();
    assert_eq!(m.save().unwrap(), data);
}

#[test]
fn the_borrow_twin_walks_the_import_arc_over_its_slot_zone() {
    // Group f1 with a two-byte open tag and a three-byte end tag
    // nesting a canonical group f3, retained as a borrowed slot:
    // the interior parses at slot-relative offsets between the met
    // tags, every step's save re-derives both met widths byte-exact,
    // and the canonical save normalizes the closure whole.
    let outside_doc = [0x8Bu8, 0x00, 0x10, 0x05, 0x1B, 0x10, 0x01, 0x1C, 0x8C, 0x80, 0x00];
    let outside = TransferBorrowMarkup::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = [0x08u8, 0x2A];
    let mut m = TransferBorrowMarkup::open(&data).unwrap();
    let import =
        m.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(
        m.save().unwrap(),
        [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x05, 0x1B, 0x10, 0x01, 0x1C, 0x8C, 0x80, 0x00]
    );

    let Descent::Opened { first: Some(kid) } = m.descend(import).unwrap() else { unreachable!() };
    assert_eq!(m.varint_word(kid).unwrap(), 5);
    m.set_varint(kid, 9).unwrap();
    assert_eq!(
        m.save().unwrap(),
        [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x09, 0x1B, 0x10, 0x01, 0x1C, 0x8C, 0x80, 0x00]
    );
    m.insert_varint(InsertAt::TailOf(Some(import)), FieldNumber::new(2).unwrap(), 1).unwrap();
    assert_eq!(
        m.save().unwrap(),
        [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x09, 0x1B, 0x10, 0x01, 0x1C, 0x10, 0x01, 0x8C, 0x80, 0x00]
    );
    let interior: Vec<Handle> = m.children(import).unwrap().collect();
    m.delete(interior[1]).unwrap();
    assert_eq!(
        m.save().unwrap(),
        [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x09, 0x10, 0x01, 0x8C, 0x80, 0x00]
    );
    m.undelete(interior[1]).unwrap();
    assert_eq!(
        m.save().unwrap(),
        [0x08, 0x2A, 0x8B, 0x00, 0x10, 0x09, 0x1B, 0x10, 0x01, 0x1C, 0x10, 0x01, 0x8C, 0x80, 0x00]
    );
    assert_eq!(
        m.save_canonical().unwrap(),
        [0x08, 0x2A, 0x0B, 0x10, 0x09, 0x1B, 0x10, 0x01, 0x1C, 0x10, 0x01, 0x0C]
    );
    m.revert_all();
    assert_eq!(m.save().unwrap(), data);
}

#[test]
fn an_imported_group_closure_is_first_class() {
    // Group f1 { varint f2=5 }, designated on an outside machine;
    // the descent parses the import zone into first-class rows.
    let outside_doc = [0x0Bu8, 0x10, 0x05, 0x0C];
    let outside = TransferMarkup::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = [0x08u8, 0x2A];
    let mut m = TransferMarkup::open(&data).unwrap();
    let imported =
        m.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    let Descent::Opened { first: Some(kid) } = m.descend(imported).unwrap() else { unreachable!() };
    m.set_varint(kid, 9).unwrap();
    assert_eq!(m.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x09, 0x0C]);
    m.revert_all();
    assert_eq!(m.save().unwrap(), data);
}
