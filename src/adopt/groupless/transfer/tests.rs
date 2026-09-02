//! The transfer sibling's behavioral rows.

use alloc::vec::Vec;

use super::{Descent, EditStatus, InsertAt, PayloadTarget, TransferAdopt};
use crate::DepthLimit;
use crate::wire::FieldNumber;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

#[test]
fn local_transfers_use_coordinates_never_a_self_borrow() {
    // The owned source cannot be borrowed into its own store; the
    // local faces run on coordinates, so the whole arc works on a
    // machine that owns its buffer.
    let mut adopt =
        TransferAdopt::open(alloc::vec![0x08, 0x05, 0x12, 0x02, 0x68, 0x69], DepthLimit::REFERENCE)
            .unwrap();
    let tops: Vec<_> = adopt.top().collect();
    adopt.copy_record(tops[1], InsertAt::HeadOf(None)).unwrap();
    adopt
        .copy_payload(tops[1], PayloadTarget::Insert { at: InsertAt::TailOf(None), field: f(3) })
        .unwrap();
    adopt.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(
        adopt.save().unwrap(),
        [0x12, 0x02, 0x68, 0x69, 0x12, 0x02, 0x68, 0x69, 0x1A, 0x02, 0x68, 0x69, 0x08, 0x05]
    );
    // The buffer releases untouched: commands stage a plan.
    assert_eq!(adopt.into_source(), [0x08, 0x05, 0x12, 0x02, 0x68, 0x69]);
}

#[test]
fn an_imported_record_is_first_class_over_its_slot() {
    // LEN f2 wrapping varint f1=1, designated on an outside machine.
    let outside =
        TransferAdopt::open(alloc::vec![0x12, 0x02, 0x08, 0x01], DepthLimit::REFERENCE).unwrap();
    let source = outside.top().next().unwrap();
    let record = outside.record_ref(source).unwrap();

    let mut adopt = TransferAdopt::open(alloc::vec![0x08, 0x2A], DepthLimit::REFERENCE).unwrap();
    let imported = adopt.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    assert_eq!(adopt.status(imported), EditStatus::Inserted);
    assert_eq!(adopt.span(imported), None);
    assert_eq!(adopt.save().unwrap(), [0x08, 0x2A, 0x12, 0x02, 0x08, 0x01]);

    // First-class: the imported LEN descends and its interior rows
    // take ordinary commands.
    let Descent::Opened { first: Some(inner) } = adopt.descend(imported).unwrap() else {
        unreachable!()
    };
    adopt.set_varint(inner, 7).unwrap();
    assert_eq!(adopt.save().unwrap(), [0x08, 0x2A, 0x12, 0x02, 0x08, 0x07]);
}

#[test]
fn a_copied_import_survives_its_designating_machine() {
    // The _copy face stages one exact record-length copy, so the
    // designating machine may die before the save.
    let mut adopt = TransferAdopt::open(alloc::vec![0x08, 0x2A], DepthLimit::REFERENCE).unwrap();
    {
        let outside =
            TransferAdopt::open(alloc::vec![0x12, 0x02, 0x68, 0x69], DepthLimit::REFERENCE)
                .unwrap();
        let source = outside.top().next().unwrap();
        adopt
            .copy_record_from_copy(outside.record_ref(source).unwrap(), InsertAt::HeadOf(None))
            .unwrap();
    }
    assert_eq!(adopt.save().unwrap(), [0x12, 0x02, 0x68, 0x69, 0x08, 0x2A]);
}
