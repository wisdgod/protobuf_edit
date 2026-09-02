use super::super::super::transfer::{Claim, TransferBreach, TransferTable};
use super::super::super::{
    Action, CopyPairing, Gap, PayloadCopyRule, PayloadCopyTarget, PayloadMoveRule, RecordTransfer,
    RecordTransferRule, Rule, TransferRuleSet,
};
use super::super::{FaultKind, WireBreach};
use super::{TransferFaultKind, rewrite_transfers, rewrite_transfers_sink};
use crate::path::Segment;
use crate::wire::FieldNumber;
use crate::{DepthLimit, Standard};
use alloc::vec::Vec;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

fn run(msg: &[u8], set: &TransferRuleSet<'_>) -> (Vec<u8>, super::TransferStats) {
    rewrite_transfers(msg, set, DepthLimit::REFERENCE).unwrap()
}

#[test]
fn a_group_copy_is_the_whole_structural_closure() {
    // The span runs open tag through the verified end tag, padded
    // interior words included.
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    // group f1 { varint f2=150 padded } · varint f3=5
    let msg = [0x0B, 0x10, 0x96, 0x81, 0x00, 0x0C, 0x18, 0x05];
    let (out, stats) = run(&msg, &set);
    assert_eq!(
        out,
        [0x0B, 0x10, 0x96, 0x81, 0x00, 0x0C, 0x18, 0x05, 0x0B, 0x10, 0x96, 0x81, 0x00, 0x0C]
    );
    assert_eq!(stats.records_copied(), 1);
}

#[test]
fn a_group_move_relocates_the_closure_and_suppresses_the_origin() {
    let moves = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::HeadOf,
        transfer: RecordTransfer::MoveZip,
    }];
    let set = TransferRuleSet::over(&[], &moves, &[], &[]).unwrap();
    // varint f3=5 · group f1 { group f1 {} } — nested same-field
    // groups ride whole with the closure.
    let msg = [0x18, 0x05, 0x0B, 0x0B, 0x0C, 0x0C];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x0B, 0x0B, 0x0C, 0x0C, 0x18, 0x05]);
    assert_eq!(stats.records_moved(), 1);
}

#[test]
fn a_group_anchor_takes_head_and_tail_gaps() {
    let copies = [
        RecordTransferRule {
            source: &[Segment::Field(f(2))],
            anchor: &[Segment::Field(f(1))],
            gap: Gap::HeadOf,
            transfer: RecordTransfer::Copy(CopyPairing::Zip),
        },
        RecordTransferRule {
            source: &[Segment::Field(f(3))],
            anchor: &[Segment::Field(f(1))],
            gap: Gap::TailOf,
            transfer: RecordTransfer::Copy(CopyPairing::Zip),
        },
    ];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    // group f1 { varint f4=1 } · varint f2=2 · varint f3=3
    let msg = [0x0B, 0x20, 0x01, 0x0C, 0x10, 0x02, 0x18, 0x03];
    let (out, stats) = run(&msg, &set);
    // Head copy lands past the open tag, tail copy before the end
    // tag.
    assert_eq!(out, [0x0B, 0x10, 0x02, 0x20, 0x01, 0x18, 0x03, 0x0C, 0x10, 0x02, 0x18, 0x03]);
    assert_eq!(stats.records_copied(), 2);
}

#[test]
fn a_copied_group_origin_still_takes_interior_edits() {
    // The copy designates the original bytes; an ordinary rule
    // edits the origin's interior — both apply, independently.
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2))],
        action: Action::Replace(super::super::super::Value::Varint(9)),
    }];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&rules, &copies, &[], &[]).unwrap();
    // group f1 { varint f2=2 }
    let msg = [0x0B, 0x10, 0x02, 0x0C];
    let (out, stats) = run(&msg, &set);
    // Origin edited, appended copy byte-exact original.
    assert_eq!(out, [0x0B, 0x10, 0x09, 0x0C, 0x0B, 0x10, 0x02, 0x0C]);
    assert_eq!((stats.replaced(), stats.records_copied()), (1, 1));
}

#[test]
fn a_deleted_group_still_designates_for_a_copy() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&rules, &copies, &[], &[]).unwrap();
    // group f1 { varint f2=1 } · varint f3=5
    let msg = [0x0B, 0x10, 0x01, 0x0C, 0x18, 0x05];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x18, 0x05, 0x0B, 0x10, 0x01, 0x0C]);
    assert_eq!((stats.deleted(), stats.records_copied()), (1, 1));
}

#[test]
fn a_group_under_a_payload_source_refuses_with_its_kind() {
    let moves = [PayloadMoveRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        field: f(9),
    }];
    let set = TransferRuleSet::over(&[], &[], &[], &moves).unwrap();
    let msg = [0x0B, 0x0C];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::SourceKind {
            table: TransferTable::PayloadMoves,
            rule: 0,
        })
    ));
}

#[test]
fn a_group_under_a_replace_target_refuses_with_its_kind() {
    let copies = [PayloadCopyRule {
        source: &[Segment::Field(f(2))],
        target: PayloadCopyTarget::Replace { target: &[Segment::Field(f(1))] },
        pairing: CopyPairing::Zip,
    }];
    let set = TransferRuleSet::over(&[], &[], &copies, &[]).unwrap();
    // LEN f2 "x" · group f1 {}
    let msg = [0x12, 0x01, 0x78, 0x0B, 0x0C];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::TargetKind { rule: 0 })
    ));
}

#[test]
fn a_moved_group_under_an_action_rule_is_contested() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Normalize }];
    let moves = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::MoveZip,
    }];
    let set = TransferRuleSet::over(&rules, &moves, &[], &[]).unwrap();
    let msg = [0x0B, 0x0C];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::Contested {
            first: Claim::Action { rule: 0 },
            second: Claim::RecordMove { rule: 0 },
        })
    ));
}

#[test]
fn transfer_gaps_compose_with_a_normalized_group_owner() {
    // Normalize re-authors the group's framing minimally; its
    // interior stays with the walk, so a transfer gap inside it
    // fires — the dialect asymmetry the host documents for
    // inserts.
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Normalize }];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(2))],
        anchor: &[Segment::Field(f(1))],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&rules, &copies, &[], &[]).unwrap();
    // group f1 (padded open tag) { varint f4=1 } · varint f2=2
    let msg = [0x8B, 0x80, 0x00, 0x20, 0x01, 0x0C, 0x10, 0x02];
    let (out, stats) = run(&msg, &set);
    // Open tag re-authors minimal; the copy lands before the end
    // tag; the end tag re-authors minimal.
    assert_eq!(out, [0x0B, 0x20, 0x01, 0x10, 0x02, 0x0C, 0x10, 0x02]);
    assert_eq!((stats.normalized(), stats.records_copied()), (1, 1));
}

#[test]
fn designations_inside_a_moved_group_never_fire() {
    // The moved group's interior leaves the walk: a source path
    // into it designates nothing, and the zip equation quotes the
    // mismatch loudly.
    let moves = [
        RecordTransferRule {
            source: &[Segment::Field(f(1))],
            anchor: &[],
            gap: Gap::TailOf,
            transfer: RecordTransfer::MoveZip,
        },
        RecordTransferRule {
            source: &[Segment::Field(f(1)), Segment::Field(f(2))],
            anchor: &[],
            gap: Gap::HeadOf,
            transfer: RecordTransfer::MoveZip,
        },
    ];
    let set = TransferRuleSet::over(&[], &moves, &[], &[]).unwrap();
    // group f1 { varint f2=1 } · varint f3=5 — rule 1 wants the
    // interior varint, but rule 0 moved the whole group, so rule 1
    // designates zero sources against its one root-head gap: the
    // loud zip refusal, not a silent half-move.
    let msg = [0x0B, 0x10, 0x01, 0x0C, 0x18, 0x05];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::Cardinality {
            table: TransferTable::Records,
            rule: 1,
            sources: 0,
            destinations: 1,
        })
    ));
}

#[test]
fn payload_copy_into_a_group_tail_authors_a_len_record() {
    let copies = [PayloadCopyRule {
        source: &[Segment::Field(f(2))],
        target: PayloadCopyTarget::Insert {
            anchor: &[Segment::Field(f(1))],
            gap: Gap::TailOf,
            field: f(3),
        },
        pairing: CopyPairing::Zip,
    }];
    let set = TransferRuleSet::over(&[], &[], &copies, &[]).unwrap();
    // group f1 {} · LEN f2 [ 0xFF ] — an opaque interior byte.
    let msg = [0x0B, 0x0C, 0x12, 0x01, 0xFF];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x0B, 0x1A, 0x01, 0xFF, 0x0C, 0x12, 0x01, 0xFF]);
    assert_eq!(stats.payloads_copied(), 1);
}

#[test]
fn the_sink_face_matches_the_buffered_face() {
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(4)), Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    // LEN f4 { group f1 { varint f2=1 } } · group f1 {} — the
    // nested group is the one source (the top-level twin is not on
    // the path).
    let msg = [0x22, 0x04, 0x0B, 0x10, 0x01, 0x0C, 0x0B, 0x0C];
    let (buffered, _) = run(&msg, &set);
    let mut handed = Vec::new();
    rewrite_transfers_sink(&msg, &set, DepthLimit::REFERENCE, |bytes| {
        handed.extend_from_slice(bytes);
    })
    .unwrap();
    assert_eq!(handed, buffered);
}

#[test]
fn a_canonical_job_refuses_padded_group_framing_on_the_source() {
    use super::rewrite_transfers_standard;
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    // group f1 with a padded end tag.
    let msg = [0x0B, 0x8C, 0x80, 0x00];
    let fault =
        rewrite_transfers_standard(&msg, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
            .unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Job(FaultKind::Wire(WireBreach::NonMinimal))
    ));
    let (out, _) =
        rewrite_transfers_standard(&msg, &set, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    assert_eq!(out, [0x0B, 0x8C, 0x80, 0x00, 0x0B, 0x8C, 0x80, 0x00]);
}
