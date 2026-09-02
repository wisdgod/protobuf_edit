//! The transfer siblings' behavioral rows.

use alloc::vec::Vec;

use super::{Descent, Handle, InsertAt, TransferBorrowReview, TransferReview};
use crate::wire::FieldNumber;

#[test]
fn a_group_closure_moves_whole_and_reverts_whole() {
    // Group f1 { varint f2=5 } · varint f3=7, canonical-minimal.
    let data = [0x0Bu8, 0x10, 0x05, 0x0C, 0x18, 0x07];
    let mut r = TransferReview::open(&data).unwrap();
    let t: Vec<Handle> = r.top().collect();
    r.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(r.pending(), 1);
    assert_eq!(r.save().unwrap(), [0x18, 0x07, 0x0B, 0x10, 0x05, 0x0C]);
    r.revert();
    assert_eq!(r.save().unwrap(), data);
}

#[test]
fn an_imported_group_closure_rides_the_canonical_proof() {
    // Group f1 { varint f2=5 }, minimal by admission; the descent
    // parses the import zone into first-class rows.
    let outside_doc = [0x0Bu8, 0x10, 0x05, 0x0C];
    let outside = TransferReview::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = [0x08u8, 0x2A];
    let mut r = TransferReview::open(&data).unwrap();
    let imported = r
        .copy_record_from(
            outside.record_ref(source).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    let Descent::Opened { first: Some(kid) } = r.descend(imported).unwrap() else { unreachable!() };
    r.set_varint(kid, 9).unwrap();
    assert_eq!(r.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x09, 0x0C]);
    r.revert_all();
    assert_eq!(r.save().unwrap(), data);
}

#[test]
fn the_borrow_twin_walks_the_canonical_import_arc_over_its_slot_zone() {
    // Group f1 { varint f2=5 · group f3 { varint f2=1 } }, minimal
    // by admission and imported under the canonical proof, retained
    // as a borrowed slot: the interior parses at slot-relative
    // offsets between the group tags, and every step's save
    // re-derives both tags byte-exact.
    let outside_doc = [0x0Bu8, 0x10, 0x05, 0x1B, 0x10, 0x01, 0x1C, 0x0C];
    let outside = TransferBorrowReview::open(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = [0x08u8, 0x2A];
    let mut r = TransferBorrowReview::open(&data).unwrap();
    let import = r
        .copy_record_from(
            outside.record_ref(source).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    assert_eq!(r.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x05, 0x1B, 0x10, 0x01, 0x1C, 0x0C]);

    let Descent::Opened { first: Some(kid) } = r.descend(import).unwrap() else { unreachable!() };
    assert_eq!(r.varint_word(kid).unwrap(), 5);
    r.set_varint(kid, 9).unwrap();
    assert_eq!(r.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x09, 0x1B, 0x10, 0x01, 0x1C, 0x0C]);
    r.insert_varint(InsertAt::TailOf(Some(import)), FieldNumber::new(2).unwrap(), 1).unwrap();
    assert_eq!(
        r.save().unwrap(),
        [0x08, 0x2A, 0x0B, 0x10, 0x09, 0x1B, 0x10, 0x01, 0x1C, 0x10, 0x01, 0x0C]
    );
    let interior: Vec<Handle> = r.children(import).unwrap().collect();
    r.delete(interior[1]).unwrap();
    assert_eq!(r.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x09, 0x10, 0x01, 0x0C]);
    r.undelete(interior[1]).unwrap();
    assert_eq!(
        r.save().unwrap(),
        [0x08, 0x2A, 0x0B, 0x10, 0x09, 0x1B, 0x10, 0x01, 0x1C, 0x10, 0x01, 0x0C]
    );
    r.revert_all();
    assert_eq!(r.save().unwrap(), data);
}
