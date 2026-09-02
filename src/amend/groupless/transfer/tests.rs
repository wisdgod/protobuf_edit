//! The transfer sibling's behavioral rows.

use alloc::vec::Vec;

use super::{Descent, EditStatus, InsertAt, TransferAmend};
use crate::DepthLimit;

#[test]
fn local_transfers_ride_the_canonical_host() {
    // The local faces run on canonical machines with the same laws;
    // canonical admission makes every source minimal already.
    let msg = [0x08u8, 0x2A, 0x12, 0x02, 0x68, 0x69];
    let mut amend = TransferAmend::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = amend.top().collect();
    amend.copy_record(tops[1], InsertAt::HeadOf(None)).unwrap();
    amend.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(amend.save().unwrap(), [0x12, 0x02, 0x68, 0x69, 0x12, 0x02, 0x68, 0x69, 0x08, 0x2A]);
}

#[test]
fn an_import_needs_the_canonical_proof_and_is_first_class() {
    // The canonical host admits only proven-minimal designations:
    // copy_record_from takes CanonicalRecordRef, minted through
    // try_canonical on the designating side.
    let outer = [0x12u8, 0x02, 0x08, 0x01];
    let outside = TransferAmend::open(&outer, DepthLimit::REFERENCE).unwrap();
    let source = outside.top().next().unwrap();
    let record = outside.record_ref(source).unwrap().try_canonical().unwrap();

    let msg = [0x08u8, 0x2A];
    let mut amend = TransferAmend::open(&msg, DepthLimit::REFERENCE).unwrap();
    let imported = amend.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    assert_eq!(amend.status(imported), EditStatus::Inserted);

    // First-class: the imported LEN descends and its interior rows
    // take ordinary commands.
    let Descent::Opened { first: Some(inner) } = amend.descend(imported).unwrap() else {
        unreachable!()
    };
    amend.set_varint(inner, 7).unwrap();
    assert_eq!(amend.save().unwrap(), [0x08, 0x2A, 0x12, 0x02, 0x08, 0x07]);
}
