//! The transfer sibling's behavioral rows.

use alloc::vec::Vec;

use super::{Descent, EditStatus, InsertAt, TransferAmend};
use crate::DepthLimit;

#[test]
fn an_imported_group_closure_rides_the_canonical_proof() {
    // Group f1 { varint f2=5 }, minimal by admission; the canonical
    // host admits the designation only through its proven form.
    let outer = [0x0Bu8, 0x10, 0x05, 0x0C];
    let outside = TransferAmend::open(&outer, DepthLimit::REFERENCE).unwrap();
    let source = outside.top().next().unwrap();
    let record = outside.record_ref(source).unwrap().try_canonical().unwrap();

    let msg = [0x08u8, 0x2A];
    let mut amend = TransferAmend::open(&msg, DepthLimit::REFERENCE).unwrap();
    let imported = amend.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    assert_eq!(amend.status(imported), EditStatus::Inserted);
    assert_eq!(amend.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x05, 0x0C]);

    // The descent parses the slot's closure into first-class rows;
    // interior rows take ordinary commands and the edit stays on
    // the import.
    let Descent::Opened { first: Some(inner) } = amend.descend(imported).unwrap() else {
        unreachable!()
    };
    amend.set_varint(inner, 7).unwrap();
    assert_eq!(amend.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x07, 0x0C]);
}

#[test]
fn local_group_transfers_relocate_the_whole_closure() {
    // Group f1 { varint f2=5 } · varint f3=7.
    let msg = [0x0Bu8, 0x10, 0x05, 0x0C, 0x18, 0x07];
    let mut amend = TransferAmend::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = amend.top().collect();
    amend.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(amend.save().unwrap(), [0x18, 0x07, 0x0B, 0x10, 0x05, 0x0C]);
}
