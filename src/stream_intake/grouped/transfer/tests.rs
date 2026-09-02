//! The transfer sibling's behavioral rows.

use alloc::vec::Vec;

use super::super::Ingest;
use super::{EditFault, InsertAt, TransferIntake};
use crate::DepthLimit;

/// Feeds one chunk and seals through the transfer door.
fn ingest_transfer(bytes: &[u8]) -> TransferIntake<'static> {
    let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    ingest.feed(bytes).unwrap();
    ingest.finish_transfer().unwrap()
}

#[test]
fn transfers_spend_the_finished_hosts_depth_account() {
    // Two sibling depth-1 closures sealed at the minimum bound: the
    // stream lawfully admits them, and the finished editor's
    // transfer refuses past the bound instead of saving a document
    // the same limit cannot re-open.
    let mut ingest = Ingest::new(DepthLimit::MIN);
    ingest.feed(&[0x0B, 0x0C, 0x13, 0x14]).unwrap();
    let mut intake = ingest.finish_transfer().unwrap();
    let t: Vec<_> = intake.top().collect();
    assert!(matches!(
        intake.copy_record(t[0], InsertAt::TailOf(Some(t[1]))),
        Err(EditFault::DepthExceeded { limit: 1, need: 2 })
    ));
    // The refusal left the seal intact.
    assert_eq!(intake.save().unwrap(), [0x0B, 0x0C, 0x13, 0x14]);
}

#[test]
fn the_seal_door_re_tags_rows_and_moves_the_source() {
    // A chunk-cut group closure seals into the transfer sibling;
    // the re-tagged rows carry the same geometry, so a local move
    // relocates the whole closure byte-exactly.
    let mut intake = ingest_transfer(&[0x0B, 0x10, 0x05, 0x0C, 0x18, 0x07]);
    let tops: Vec<_> = intake.top().collect();
    intake.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(intake.save().unwrap(), [0x18, 0x07, 0x0B, 0x10, 0x05, 0x0C]);
    assert_eq!(intake.into_source(), [0x0B, 0x10, 0x05, 0x0C, 0x18, 0x07]);
}
