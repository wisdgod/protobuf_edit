use super::super::super::transfer::{Claim, TransferBreach, TransferTable};
use super::super::super::{
    Action, CopyPairing, Gap, PayloadCopyRule, PayloadCopyTarget, PayloadMoveRule, RecordTransfer,
    RecordTransferRule, Rule, TransferRuleSet,
};
use super::super::{FaultKind, WireBreach};
use super::{TransferFaultKind, rewrite_transfers, rewrite_transfers_into, rewrite_transfers_sink};
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
fn a_record_copy_is_byte_exact_including_padding() {
    // varint f1=150 padded to three bytes · varint f2=42: the copy
    // preserves the met spelling at the destination.
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let msg = [0x08, 0x96, 0x81, 0x00, 0x10, 0x2A];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x08, 0x96, 0x81, 0x00, 0x10, 0x2A, 0x08, 0x96, 0x81, 0x00]);
    assert_eq!(stats.records_copied(), 1);
    assert_eq!(stats.records_moved(), 0);
}

#[test]
fn a_record_move_suppresses_the_origin() {
    // The move relocates the exact bytes; nothing remains at the
    // origin.
    let moves = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::HeadOf,
        transfer: RecordTransfer::MoveZip,
    }];
    let set = TransferRuleSet::over(&[], &moves, &[], &[]).unwrap();
    // varint f2=1 · LEN f1 "hi" (padded prefix) — the padded
    // prefix rides with the moved record.
    let msg = [0x10, 0x01, 0x0A, 0x82, 0x80, 0x00, 0x68, 0x69];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x0A, 0x82, 0x80, 0x00, 0x68, 0x69, 0x10, 0x01]);
    assert_eq!(stats.records_moved(), 1);
}

#[test]
fn zip_pairs_sources_and_destinations_in_walk_order() {
    // Two sources, two anchor occurrences: first source into the
    // first container, second into the second.
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[Segment::Field(f(3))],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    // varint f1=1 · varint f1=2 · LEN f3 {} · LEN f3 {}
    let msg = [0x08, 0x01, 0x08, 0x02, 0x1A, 0x00, 0x1A, 0x00];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x08, 0x01, 0x08, 0x02, 0x1A, 0x02, 0x08, 0x01, 0x1A, 0x02, 0x08, 0x02]);
    assert_eq!(stats.records_copied(), 2);
    assert_eq!(stats.descended(), 2);
}

#[test]
fn broadcast_copies_one_source_to_every_destination() {
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[Segment::Field(f(3))],
        gap: Gap::HeadOf,
        transfer: RecordTransfer::Copy(CopyPairing::BroadcastOne),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let msg = [0x08, 0x07, 0x1A, 0x00, 0x1A, 0x00];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x08, 0x07, 0x1A, 0x02, 0x08, 0x07, 0x1A, 0x02, 0x08, 0x07]);
    assert_eq!(stats.records_copied(), 2);
}

#[test]
fn zip_count_mismatch_faults_before_output() {
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[Segment::Field(f(3))],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    // Two sources, one destination.
    let msg = [0x08, 0x01, 0x08, 0x02, 0x1A, 0x00];
    let mut out = alloc::vec![0xAA];
    let fault = rewrite_transfers_into(&msg, &set, DepthLimit::REFERENCE, &mut out).unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::Cardinality {
            table: TransferTable::Records,
            rule: 0,
            sources: 2,
            destinations: 1,
        })
    ));
    // The reuse buffer is untouched on refusal.
    assert_eq!(out, [0xAA]);
}

#[test]
fn a_payload_copy_replaces_the_target_interior_byte_exactly() {
    // Source LEN f1 carries a padded varint inside: the interior
    // is opaque and rides exact; the target's tag is verbatim and
    // its prefix re-authors minimally.
    let copies = [PayloadCopyRule {
        source: &[Segment::Field(f(1))],
        target: PayloadCopyTarget::Replace { target: &[Segment::Field(f(2))] },
        pairing: CopyPairing::Zip,
    }];
    let set = TransferRuleSet::over(&[], &[], &copies, &[]).unwrap();
    // LEN f1 [ 0x96 0x81 0x00 ] · LEN f2 "xy"
    let msg = [0x0A, 0x03, 0x96, 0x81, 0x00, 0x12, 0x02, 0x78, 0x79];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x0A, 0x03, 0x96, 0x81, 0x00, 0x12, 0x03, 0x96, 0x81, 0x00]);
    assert_eq!(stats.payloads_copied(), 1);
}

#[test]
fn a_payload_move_authors_the_destination_and_suppresses_the_whole_source_record() {
    let moves = [PayloadMoveRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        field: f(9),
    }];
    let set = TransferRuleSet::over(&[], &[], &[], &moves).unwrap();
    // LEN f1 "hi" · varint f2=1
    let msg = [0x0A, 0x02, 0x68, 0x69, 0x10, 0x01];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x10, 0x01, 0x4A, 0x02, 0x68, 0x69]);
    assert_eq!(stats.payloads_moved(), 1);
}

#[test]
fn a_scalar_payload_source_refuses_with_its_kind() {
    let copies = [PayloadCopyRule {
        source: &[Segment::Field(f(1))],
        target: PayloadCopyTarget::Replace { target: &[Segment::Field(f(2))] },
        pairing: CopyPairing::Zip,
    }];
    let set = TransferRuleSet::over(&[], &[], &copies, &[]).unwrap();
    // varint f1 — not a LEN.
    let msg = [0x08, 0x01, 0x12, 0x00];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::SourceKind {
            table: TransferTable::PayloadCopies,
            rule: 0,
        })
    ));
}

#[test]
fn a_scalar_anchor_occurrence_refuses_with_its_kind() {
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[Segment::Field(f(2))],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    // f2 occurs as a varint: anchors commit containerhood.
    let msg = [0x08, 0x01, 0x10, 0x02];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::AnchorKind {
            table: TransferTable::Records,
            rule: 0,
        })
    ));
}

#[test]
fn a_moved_source_under_an_action_rule_is_contested() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let moves = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::MoveZip,
    }];
    let set = TransferRuleSet::over(&rules, &moves, &[], &[]).unwrap();
    let msg = [0x08, 0x01];
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
fn two_moves_of_one_occurrence_are_contested() {
    let moves = [
        RecordTransferRule {
            source: &[Segment::Field(f(1))],
            anchor: &[],
            gap: Gap::TailOf,
            transfer: RecordTransfer::MoveZip,
        },
        RecordTransferRule {
            source: &[Segment::Field(f(1))],
            anchor: &[],
            gap: Gap::HeadOf,
            transfer: RecordTransfer::MoveZip,
        },
    ];
    let set = TransferRuleSet::over(&[], &moves, &[], &[]).unwrap();
    let msg = [0x08, 0x01];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::Contested {
            first: Claim::RecordMove { rule: 0 },
            second: Claim::RecordMove { rule: 1 },
        })
    ));
}

#[test]
fn copying_an_action_owned_record_is_lawful_and_reads_the_original() {
    // Replace rewrites the origin; the copy still emits the
    // original designation.
    let rules = [Rule {
        path: &[Segment::Field(f(1))],
        action: Action::Replace(super::super::super::Value::Varint(9)),
    }];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&rules, &copies, &[], &[]).unwrap();
    let msg = [0x08, 0x01, 0x10, 0x02];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x08, 0x09, 0x10, 0x02, 0x08, 0x01]);
    assert_eq!((stats.replaced(), stats.records_copied()), (1, 1));
}

#[test]
fn destinations_inside_an_unwalked_interior_die_with_it() {
    // The anchor lives inside a deleted container: the gap never
    // fires, and the zip equation sees zero destinations for zero
    // sources inside the same dead interior.
    let rules = [Rule { path: &[Segment::Field(f(3))], action: Action::Delete }];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(3)), Segment::Field(f(1))],
        anchor: &[Segment::Field(f(3)), Segment::Field(f(2))],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&rules, &copies, &[], &[]).unwrap();
    // LEN f3 { varint f1=1 · LEN f2 {} } · varint f4=5
    let msg = [0x1A, 0x04, 0x08, 0x01, 0x12, 0x00, 0x20, 0x05];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, [0x20, 0x05]);
    assert_eq!((stats.deleted(), stats.records_copied()), (1, 0));
}

#[test]
fn same_gap_emissions_follow_insert_then_transfer_order() {
    use super::super::super::{InsertRule, Value};
    let tail = InsertRule { gap: Gap::TailOf, field: f(5), value: Value::Varint(1) };
    let rules = [Rule { path: &[], action: Action::Insert(&tail) }];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&rules, &copies, &[], &[]).unwrap();
    let msg = [0x08, 0x07];
    let (out, stats) = run(&msg, &set);
    // Insert (f5=1) first, then the record copy.
    assert_eq!(out, [0x08, 0x07, 0x28, 0x01, 0x08, 0x07]);
    assert_eq!((stats.inserted(), stats.records_copied()), (1, 1));
}

#[test]
fn the_sink_face_matches_the_buffered_face_and_hands_nothing_on_err() {
    let moves = [PayloadMoveRule {
        source: &[Segment::Field(f(1))],
        anchor: &[Segment::Field(f(3))],
        gap: Gap::HeadOf,
        field: f(9),
    }];
    let set = TransferRuleSet::over(&[], &[], &[], &moves).unwrap();
    // LEN f1 "abc" · LEN f3 { varint f2=1 }
    let msg = [0x0A, 0x03, 0x61, 0x62, 0x63, 0x1A, 0x02, 0x10, 0x01];
    let (buffered, _) = run(&msg, &set);
    let mut handed = Vec::new();
    rewrite_transfers_sink(&msg, &set, DepthLimit::REFERENCE, |bytes| {
        handed.extend_from_slice(bytes);
    })
    .unwrap();
    assert_eq!(handed, buffered);

    // A faulting job hands nothing: the zip equation breaks when
    // the destination container vanishes from the walk.
    let bad = [0x0A, 0x03, 0x61, 0x62, 0x63];
    let mut count = 0usize;
    let fault =
        rewrite_transfers_sink(&bad, &set, DepthLimit::REFERENCE, |_| count += 1).unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::Cardinality { .. })
    ));
    assert_eq!(count, 0);
}

#[test]
fn a_canonical_job_refuses_the_padded_source_a_tolerant_job_copies() {
    use super::rewrite_transfers_standard;
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let msg = [0x08, 0x96, 0x81, 0x00];
    let fault =
        rewrite_transfers_standard(&msg, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
            .unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Job(FaultKind::Wire(WireBreach::NonMinimal))
    ));
    let (out, _) =
        rewrite_transfers_standard(&msg, &set, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    assert_eq!(out, [0x08, 0x96, 0x81, 0x00, 0x08, 0x96, 0x81, 0x00]);
}

#[test]
fn an_opaque_len_interior_never_blocks_a_canonical_job() {
    use super::rewrite_transfers_standard;
    // The source LEN's interior carries a padded word; the framing
    // is minimal. A canonical job accepts: interiors are the
    // source's declaration.
    let copies = [PayloadCopyRule {
        source: &[Segment::Field(f(1))],
        target: PayloadCopyTarget::Insert { anchor: &[], gap: Gap::TailOf, field: f(9) },
        pairing: CopyPairing::Zip,
    }];
    let set = TransferRuleSet::over(&[], &[], &copies, &[]).unwrap();
    let msg = [0x0A, 0x03, 0x96, 0x81, 0x00];
    let (out, stats) =
        rewrite_transfers_standard(&msg, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
            .unwrap();
    assert_eq!(out, [0x0A, 0x03, 0x96, 0x81, 0x00, 0x4A, 0x03, 0x96, 0x81, 0x00]);
    assert_eq!(stats.payloads_copied(), 1);
}

#[test]
fn moving_into_the_moved_subtree_is_structurally_dead() {
    // The anchor lives inside the moved record: the interior
    // leaves the walk, the gap never fires, and the mismatch is
    // the loud cardinality refusal.
    let moves = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[Segment::Field(f(1)), Segment::Field(f(2))],
        gap: Gap::TailOf,
        transfer: RecordTransfer::MoveZip,
    }];
    let set = TransferRuleSet::over(&[], &moves, &[], &[]).unwrap();
    // LEN f1 { LEN f2 {} }
    let msg = [0x0A, 0x02, 0x12, 0x00];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Transfer(TransferBreach::Cardinality {
            table: TransferTable::Records,
            rule: 0,
            sources: 1,
            destinations: 0,
        })
    ));
}

#[test]
fn group_codes_stay_the_dialect_refusal() {
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let msg = [0x0B, 0x0C];
    let fault = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(fault.kind(), TransferFaultKind::Job(FaultKind::Wire(WireBreach::GroupCode))));
}

#[test]
fn an_inapplicable_rule_is_silent_and_counts_zero() {
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(7))],
        anchor: &[Segment::Field(f(8))],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let msg = [0x08, 0x01];
    let (out, stats) = run(&msg, &set);
    assert_eq!(out, msg);
    assert_eq!(stats.records_copied(), 0);
}
