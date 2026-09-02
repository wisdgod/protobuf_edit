//! The transfer sibling's behavioral rows.

use alloc::vec::Vec;

use super::{Descent, EditStatus, InsertAt, TransferIntake};
use crate::DepthLimit;

#[test]
fn local_transfers_ride_the_canonical_owned_host() {
    // The owned canonical host runs the same local-transfer laws;
    // the buffer releases untouched because commands stage a plan.
    let mut intake = TransferIntake::open(
        alloc::vec![0x08, 0x2A, 0x12, 0x02, 0x68, 0x69],
        DepthLimit::REFERENCE,
    )
    .unwrap();
    let tops: Vec<_> = intake.top().collect();
    intake.copy_record(tops[1], InsertAt::HeadOf(None)).unwrap();
    intake.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(
        intake.save().unwrap(),
        [0x12, 0x02, 0x68, 0x69, 0x12, 0x02, 0x68, 0x69, 0x08, 0x2A]
    );
    assert_eq!(intake.into_source(), [0x08, 0x2A, 0x12, 0x02, 0x68, 0x69]);
}

#[test]
fn an_import_needs_the_canonical_proof_and_is_first_class() {
    // copy_record_from takes CanonicalRecordRef, minted through
    // try_canonical on the designating side.
    let outside =
        TransferIntake::open(alloc::vec![0x12, 0x02, 0x08, 0x01], DepthLimit::REFERENCE).unwrap();
    let source = outside.top().next().unwrap();
    let record = outside.record_ref(source).unwrap().try_canonical().unwrap();

    let mut intake = TransferIntake::open(alloc::vec![0x08, 0x2A], DepthLimit::REFERENCE).unwrap();
    let imported = intake.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    assert_eq!(intake.status(imported), EditStatus::Inserted);

    // First-class: the imported LEN descends and its interior rows
    // take ordinary commands.
    let Descent::Opened { first: Some(inner) } = intake.descend(imported).unwrap() else {
        unreachable!()
    };
    intake.set_varint(inner, 7).unwrap();
    assert_eq!(intake.save().unwrap(), [0x08, 0x2A, 0x12, 0x02, 0x08, 0x07]);
}
