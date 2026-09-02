//! The transfer sibling's behavioral rows.

use alloc::vec::Vec;

use super::{InsertAt, TransferIntake};
use crate::DepthLimit;

#[cfg(feature = "inspect-grouped")]
#[test]
fn a_canonical_group_import_needs_the_closure_proof() {
    use crate::inspect::grouped::Tree;
    use crate::inspect::{Admitted, NoAdvice};
    use crate::source::grouped::Fault;

    // A minimal foreign group closure proves and imports; a padded
    // one refuses at the proof.
    let foreign = [0x0Bu8, 0x10, 0x05, 0x0C, 0x8B, 0x00, 0x0C];
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let ids: Vec<_> = tree.top().collect();
    let minimal = tree.record_ref(ids[0]).unwrap().try_canonical().unwrap();
    assert!(matches!(
        tree.record_ref(ids[1]).unwrap().try_canonical(),
        Err(Fault::StandardMismatch { at: 0, .. })
    ));

    let mut intake = TransferIntake::open(alloc::vec![0x18, 0x07], DepthLimit::REFERENCE).unwrap();
    intake.copy_record_from(minimal, InsertAt::TailOf(None)).unwrap();
    let out = intake.save().unwrap();
    assert_eq!(out, [0x18, 0x07, 0x0B, 0x10, 0x05, 0x0C]);
    // Re-ingest under the promised standard — the base machine
    // reads the transfer sibling's product.
    assert!(super::super::Intake::open(out, DepthLimit::REFERENCE).is_ok());
}

#[test]
fn local_group_transfers_relocate_the_whole_closure() {
    // Group f1 { varint f2=5 } · varint f3=7, canonical-minimal.
    let mut intake = TransferIntake::open(
        alloc::vec![0x0B, 0x10, 0x05, 0x0C, 0x18, 0x07],
        DepthLimit::REFERENCE,
    )
    .unwrap();
    let tops: Vec<_> = intake.top().collect();
    intake.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(intake.save().unwrap(), [0x18, 0x07, 0x0B, 0x10, 0x05, 0x0C]);
}
