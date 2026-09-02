//! The transfer sibling's behavioral rows.

use alloc::vec::Vec;

use super::{Descent, EditStatus, InsertAt, TransferAdopt};
use crate::DepthLimit;

#[test]
fn an_imported_group_closure_is_first_class() {
    // Group f1 { varint f2=5 }, designated on an outside machine.
    let outside =
        TransferAdopt::open(alloc::vec![0x0B, 0x10, 0x05, 0x0C], DepthLimit::REFERENCE).unwrap();
    let source = outside.top().next().unwrap();
    let record = outside.record_ref(source).unwrap();

    let mut adopt = TransferAdopt::open(alloc::vec![0x08, 0x2A], DepthLimit::REFERENCE).unwrap();
    let imported = adopt.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    assert_eq!(adopt.status(imported), EditStatus::Inserted);
    assert_eq!(adopt.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x05, 0x0C]);

    // The descent parses the slot's closure into first-class rows;
    // interior rows take ordinary commands and the edit stays on
    // the import.
    let Descent::Opened { first: Some(inner) } = adopt.descend(imported).unwrap() else {
        unreachable!()
    };
    adopt.set_varint(inner, 7).unwrap();
    assert_eq!(adopt.save().unwrap(), [0x08, 0x2A, 0x0B, 0x10, 0x07, 0x0C]);
    assert_eq!(outside.save().unwrap(), [0x0B, 0x10, 0x05, 0x0C]);
}

#[test]
fn local_group_transfers_relocate_the_whole_closure() {
    // Group f1 { varint f2=5 } · varint f3=7.
    let mut adopt =
        TransferAdopt::open(alloc::vec![0x0B, 0x10, 0x05, 0x0C, 0x18, 0x07], DepthLimit::REFERENCE)
            .unwrap();
    let tops: Vec<_> = adopt.top().collect();
    adopt.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(adopt.save().unwrap(), [0x18, 0x07, 0x0B, 0x10, 0x05, 0x0C]);
}
