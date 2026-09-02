//! The transfer sibling's behavioral rows.

use alloc::vec::Vec;

use super::super::Ingest;
use super::{Descent, InsertAt, TransferIntake};
use crate::DepthLimit;

/// Feeds chunks byte by byte and seals through the transfer door.
fn ingest_transfer(bytes: &[u8]) -> TransferIntake<'static> {
    let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    for byte in bytes {
        ingest.feed(core::slice::from_ref(byte)).unwrap();
    }
    ingest.finish_transfer().unwrap()
}

#[test]
fn the_seal_door_re_tags_rows_and_moves_the_source() {
    // Chunk edges never show in the product: the transfer sibling
    // seals from per-byte feeds and runs the local-transfer arc.
    let mut intake = ingest_transfer(&[0x08, 0x05, 0x12, 0x02, 0x68, 0x69]);
    let tops: Vec<_> = intake.top().collect();
    intake.copy_record(tops[1], InsertAt::HeadOf(None)).unwrap();
    intake.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(
        intake.save().unwrap(),
        [0x12, 0x02, 0x68, 0x69, 0x12, 0x02, 0x68, 0x69, 0x08, 0x05]
    );
    assert_eq!(intake.into_source(), [0x08, 0x05, 0x12, 0x02, 0x68, 0x69]);
}

#[test]
fn an_imported_record_is_first_class_over_the_sealed_source() {
    // An import into the sealed editor takes the canonical proof
    // and descends and edits like the buffered sibling's.
    let outside = ingest_transfer(&[0x12, 0x02, 0x08, 0x01]);
    let source = outside.top().next().unwrap();
    let record = outside.record_ref(source).unwrap().try_canonical().unwrap();

    let mut intake = ingest_transfer(&[0x08, 0x2A]);
    let imported = intake.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    let Descent::Opened { first: Some(inner) } = intake.descend(imported).unwrap() else {
        unreachable!()
    };
    intake.set_varint(inner, 7).unwrap();
    assert_eq!(intake.save().unwrap(), [0x08, 0x2A, 0x12, 0x02, 0x08, 0x07]);
}
