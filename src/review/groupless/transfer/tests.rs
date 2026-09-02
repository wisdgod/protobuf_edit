//! The transfer siblings' behavioral rows.

use alloc::vec::Vec;

use super::{Handle, InsertAt, TransferBorrowReview, TransferReview};

#[test]
fn canonical_imports_demand_the_proof_and_ride_first_class() {
    let data = [0x08u8, 0x05];
    let outside_doc = [0x12u8, 0x02, 0x68, 0x69];
    let outside = TransferReview::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let mut r = TransferReview::open(&data).unwrap();
    let import = r
        .copy_record_from(
            outside.record_ref(source).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    assert_eq!(r.payload_bytes(import).unwrap(), b"hi");
    assert_eq!(r.save().unwrap(), [0x08, 0x05, 0x12, 0x02, 0x68, 0x69]);
    // Local faces ride the same machine.
    let t: Vec<Handle> = r.top().collect();
    r.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(r.save().unwrap(), [0x12, 0x02, 0x68, 0x69, 0x08, 0x05]);
    r.revert_all();
    assert_eq!(r.save().unwrap(), data);
}

#[test]
fn a_move_is_one_command_one_pending_one_revert() {
    let data = [0x08u8, 0x05, 0x12, 0x02, 0x68, 0x69];
    let mut r = TransferReview::open(&data).unwrap();
    let t: Vec<Handle> = r.top().collect();
    assert_eq!(r.pending(), 0);
    r.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(r.pending(), 1);
    assert_eq!(r.save().unwrap(), [0x12, 0x02, 0x68, 0x69, 0x08, 0x05]);
    r.revert();
    assert_eq!(r.pending(), 0);
    assert_eq!(r.save().unwrap(), data);
}

#[test]
fn the_borrow_twin_retains_canonical_imports_as_slots() {
    let outside_doc = [0x12u8, 0x02, 0x68, 0x69];
    let outside = TransferBorrowReview::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = [0x08u8, 0x05];
    let mut r = TransferBorrowReview::open(&data).unwrap();
    let import = r
        .copy_record_from(
            outside.record_ref(source).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    assert_eq!(r.payload_bytes(import).unwrap(), b"hi");
    assert_eq!(r.save().unwrap(), [0x08, 0x05, 0x12, 0x02, 0x68, 0x69]);
    r.revert();
    assert_eq!(r.save().unwrap(), data);
}
