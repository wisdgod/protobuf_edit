//! The transfer siblings' behavioral rows.

use alloc::vec::Vec;

use super::{Handle, InsertAt, TransferBorrowMarkup, TransferMarkup};

#[test]
fn transfers_ride_the_borrowed_source_and_imports_land_first_class() {
    let data = [0x08u8, 0x05, 0x12, 0x02, 0x68, 0x69];
    let outside_doc = [0x1Au8, 0x03, 0x78, 0x79, 0x7A];
    let outside = TransferMarkup::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let mut m = TransferMarkup::open(&data).unwrap();
    let t: Vec<Handle> = m.top().collect();
    m.copy_record(t[1], InsertAt::HeadOf(None)).unwrap();
    m.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    let import =
        m.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(m.payload_bytes(import).unwrap(), b"xyz");
    assert_eq!(
        m.save().unwrap(),
        [0x12, 0x02, 0x68, 0x69, 0x12, 0x02, 0x68, 0x69, 0x08, 0x05, 0x1A, 0x03, 0x78, 0x79, 0x7A]
    );
    m.revert_all();
    assert_eq!(m.save().unwrap(), data);
}

#[test]
fn a_move_is_one_command_one_pending_one_revert() {
    let data = [0x08u8, 0x05, 0x12, 0x02, 0x68, 0x69];
    let mut m = TransferMarkup::open(&data).unwrap();
    let t: Vec<Handle> = m.top().collect();
    assert_eq!(m.pending(), 0);
    m.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(m.pending(), 1);
    assert_eq!(m.save().unwrap(), [0x12, 0x02, 0x68, 0x69, 0x08, 0x05]);
    m.revert();
    assert_eq!(m.pending(), 0);
    assert_eq!(m.save().unwrap(), data);
}

#[test]
fn the_borrow_twin_retains_imports_as_slots() {
    // The borrowed twin retains the designated record's bytes; the
    // owner outlives the machine by scope order here.
    let outside_doc = [0x12u8, 0x02, 0x68, 0x69];
    let outside = TransferBorrowMarkup::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = [0x08u8, 0x05];
    let mut m = TransferBorrowMarkup::open(&data).unwrap();
    let import =
        m.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(m.payload_bytes(import).unwrap(), b"hi");
    assert_eq!(m.save().unwrap(), [0x08, 0x05, 0x12, 0x02, 0x68, 0x69]);
    m.revert();
    assert_eq!(m.save().unwrap(), data);
}
