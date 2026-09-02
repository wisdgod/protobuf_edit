//! The static-transfer composition judge: every transfer form the
//! rewrite plan spells is compared against the equivalent
//! handle-driven editor commands over the same document — two
//! independent engines, one output law. Fixtures carry padded
//! framing everywhere the fidelity laws bite, and the one place
//! the hosts' framing laws lawfully diverge (a replaced payload's
//! length prefix) is pinned as a divergence, not averaged away.
//!
//! Re-ingestion rides every row: a tolerant transfer output must
//! reopen under the tolerant standard byte-identically through an
//! identity job.

#![cfg(all(
    feature = "transfer-rewrite-grouped",
    feature = "transfer-rewrite-groupless",
    feature = "patch-grouped",
    feature = "transfer-patch-grouped",
    feature = "transfer-patch-groupless",
    feature = "patch-groupless"
))]

use protobuf_edit::path::Segment;
use protobuf_edit::rewrite::{
    CopyPairing, Gap, PayloadCopyRule, PayloadCopyTarget, PayloadMoveRule, RecordTransfer,
    RecordTransferRule, RuleSet, TransferRuleSet,
};
use protobuf_edit::{DepthLimit, FieldNumber, Standard};

const fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

/// The identity re-ingest law: the output walks whole under the
/// tolerant standard and re-emits byte-identically.
fn reingests_tolerant_groupless(bytes: &[u8]) {
    let set = RuleSet::over(&[]).unwrap();
    let (echo, _) = protobuf_edit::rewrite::groupless::rewrite_standard(
        bytes,
        &set,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(echo, bytes, "the transfer output re-ingests tolerantly");
}

fn reingests_tolerant_grouped(bytes: &[u8]) {
    let set = RuleSet::over(&[]).unwrap();
    let (echo, _) = protobuf_edit::rewrite::grouped::rewrite_standard(
        bytes,
        &set,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(echo, bytes, "the transfer output re-ingests tolerantly");
}

#[test]
fn a_record_copy_matches_the_editor_composition_groupless() {
    use protobuf_edit::patch::groupless::{InsertAt, TransferPatch};
    use protobuf_edit::rewrite::groupless::rewrite_transfers;

    // varint f1=150 padded · LEN f2 (padded prefix) "hi" · varint
    // f3=1: both f1 and f2 copy to the tail, walk order.
    let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x82, 0x80, 0x00, 0x68, 0x69, 0x18, 0x01];
    let copies = [
        RecordTransferRule {
            source: &[Segment::Field(f(1))],
            anchor: &[],
            gap: Gap::TailOf,
            transfer: RecordTransfer::Copy(CopyPairing::Zip),
        },
        RecordTransferRule {
            source: &[Segment::Field(f(2))],
            anchor: &[],
            gap: Gap::TailOf,
            transfer: RecordTransfer::Copy(CopyPairing::Zip),
        },
    ];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.records_copied(), 2);

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    // Rule order at one gap: rule 0's copy (f1), then rule 1's
    // (f2) — the sequential command order.
    patch.copy_record(tops[0], InsertAt::TailOf(None)).unwrap();
    patch.copy_record(tops[1], InsertAt::TailOf(None)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "the plan engine matches the handle engine");
    reingests_tolerant_groupless(&out);
}

#[test]
fn a_record_move_matches_the_editor_composition_groupless() {
    use protobuf_edit::patch::groupless::{InsertAt, TransferPatch};
    use protobuf_edit::rewrite::groupless::rewrite_transfers;

    // LEN f1 (padded prefix, padded interior word) · varint f2=1.
    let msg = [0x0A, 0x83, 0x80, 0x00, 0x96, 0x81, 0x00, 0x10, 0x01];
    let moves = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::MoveZip,
    }];
    let set = TransferRuleSet::over(&[], &moves, &[], &[]).unwrap();
    let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.records_moved(), 1);

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one move law across both engines");
    reingests_tolerant_groupless(&out);
}

#[test]
fn a_payload_move_matches_the_editor_composition_groupless() {
    use protobuf_edit::patch::groupless::{InsertAt, TransferPatch};
    use protobuf_edit::rewrite::groupless::rewrite_transfers;

    // LEN f1 [ nested padding 0x96 0x81 0x00 ] · varint f2=1: the
    // interior relocates under field 9, the whole source record
    // leaves.
    let msg = [0x0A, 0x03, 0x96, 0x81, 0x00, 0x10, 0x01];
    let moves = [PayloadMoveRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        field: f(9),
    }];
    let set = TransferRuleSet::over(&[], &[], &[], &moves).unwrap();
    let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.payloads_moved(), 1);

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.move_payload(tops[0], InsertAt::TailOf(None), f(9)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one payload-move law across both engines");
    reingests_tolerant_groupless(&out);
}

#[test]
fn a_payload_copy_into_a_gap_matches_the_editor_composition_groupless() {
    use protobuf_edit::patch::groupless::transfer::PayloadTarget;
    use protobuf_edit::patch::groupless::{InsertAt, TransferPatch};
    use protobuf_edit::rewrite::groupless::rewrite_transfers;

    let msg = [0x0A, 0x03, 0x96, 0x81, 0x00, 0x10, 0x01];
    let copies = [PayloadCopyRule {
        source: &[Segment::Field(f(1))],
        target: PayloadCopyTarget::Insert { anchor: &[], gap: Gap::HeadOf, field: f(7) },
        pairing: CopyPairing::Zip,
    }];
    let set = TransferRuleSet::over(&[], &[], &copies, &[]).unwrap();
    let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.payloads_copied(), 1);

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch
        .copy_payload(tops[0], PayloadTarget::Insert { at: InsertAt::HeadOf(None), field: f(7) })
        .unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one payload-copy law across both engines");
    reingests_tolerant_groupless(&out);
}

#[test]
fn replace_framing_is_the_hosts_lawful_divergence() {
    use protobuf_edit::patch::groupless::transfer::PayloadTarget;
    use protobuf_edit::patch::groupless::TransferPatch;
    use protobuf_edit::rewrite::groupless::rewrite_transfers;

    // Source LEN f1 "ab" · target LEN f2 with a PADDED prefix and
    // an equal-length payload "xy". The byte-fidelity editor keeps
    // the target's padded prefix (unchanged length); the rewriter
    // re-frames replacements minimally — the two host laws, pinned
    // side by side.
    let msg = [0x0A, 0x02, 0x61, 0x62, 0x12, 0x82, 0x80, 0x00, 0x78, 0x79];
    let copies = [PayloadCopyRule {
        source: &[Segment::Field(f(1))],
        target: PayloadCopyTarget::Replace { target: &[Segment::Field(f(2))] },
        pairing: CopyPairing::Zip,
    }];
    let set = TransferRuleSet::over(&[], &[], &copies, &[]).unwrap();
    let (out, _) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
    // Minimal re-framed prefix at the rewriter.
    assert_eq!(out, [0x0A, 0x02, 0x61, 0x62, 0x12, 0x02, 0x61, 0x62]);

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.copy_payload(tops[0], PayloadTarget::Replace(tops[1])).unwrap();
    let expected = patch.save().unwrap();
    // The fidelity editor keeps the padded prefix: unchanged
    // length, tolerant save.
    assert_eq!(expected, [0x0A, 0x02, 0x61, 0x62, 0x12, 0x82, 0x80, 0x00, 0x61, 0x62]);

    // The interiors agree byte-for-byte — the payload fidelity law
    // both hosts share; only destination framing differs.
    assert_eq!(out[6..8], expected[8..10]);
    reingests_tolerant_groupless(&out);
    reingests_tolerant_groupless(&expected);
}

#[test]
fn a_group_copy_matches_the_editor_composition_grouped() {
    use protobuf_edit::patch::grouped::{InsertAt, TransferPatch};
    use protobuf_edit::rewrite::grouped::rewrite_transfers;

    // group f1 { varint f2=150 padded · group f1 {} } · varint
    // f3=1: the whole closure copies, nested twin included.
    let msg = [0x0B, 0x10, 0x96, 0x81, 0x00, 0x0B, 0x0C, 0x0C, 0x18, 0x01];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.records_copied(), 1);

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.copy_record(tops[0], InsertAt::TailOf(None)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one closure-copy law across both engines");
    reingests_tolerant_grouped(&out);
}

#[test]
fn a_group_move_matches_the_editor_composition_grouped() {
    use protobuf_edit::patch::grouped::{InsertAt, TransferPatch};
    use protobuf_edit::rewrite::grouped::rewrite_transfers;

    // varint f3=1 · group f1 { LEN f2 (padded prefix) "z" }: the
    // group moves to the head.
    let msg = [0x18, 0x01, 0x0B, 0x12, 0x81, 0x80, 0x00, 0x7A, 0x0C];
    let moves = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::HeadOf,
        transfer: RecordTransfer::MoveZip,
    }];
    let set = TransferRuleSet::over(&[], &moves, &[], &[]).unwrap();
    let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.records_moved(), 1);

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.move_record(tops[1], InsertAt::HeadOf(None)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one closure-move law across both engines");
    reingests_tolerant_grouped(&out);
}

#[test]
fn interior_gap_transfers_match_the_editor_composition_groupless() {
    use protobuf_edit::patch::groupless::{InsertAt, TransferPatch};
    use protobuf_edit::rewrite::groupless::rewrite_transfers;

    // varint f1=7 · LEN f3 { varint f2=1 }: copy f1 into the
    // container's head gap.
    let msg = [0x08, 0x07, 0x1A, 0x02, 0x10, 0x01];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[Segment::Field(f(3))],
        gap: Gap::HeadOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let (out, stats) = rewrite_transfers(&msg, &set, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.records_copied(), 1);

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    // The editor descends the container to own its interior gap; the
    // opened head is irrelevant, the tail anchor below names its spot.
    let _ = patch.descend(tops[1]).unwrap();
    patch.copy_record(tops[0], InsertAt::HeadOf(Some(tops[1]))).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one interior-gap law across both engines");
    reingests_tolerant_groupless(&out);
}

#[test]
fn a_canonical_job_admits_what_the_canonical_law_promises() {
    use protobuf_edit::rewrite::groupless::rewrite_transfers_standard;

    // Minimal framing everywhere, a padded word only inside an
    // opaque LEN interior: the canonical job admits, transfers,
    // and its output re-walks under the canonical standard.
    let msg = [0x0A, 0x03, 0x96, 0x81, 0x00, 0x10, 0x01];
    let copies = [RecordTransferRule {
        source: &[Segment::Field(f(1))],
        anchor: &[],
        gap: Gap::TailOf,
        transfer: RecordTransfer::Copy(CopyPairing::Zip),
    }];
    let set = TransferRuleSet::over(&[], &copies, &[], &[]).unwrap();
    let (out, _) =
        rewrite_transfers_standard(&msg, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
            .unwrap();
    assert_eq!(out, [0x0A, 0x03, 0x96, 0x81, 0x00, 0x10, 0x01, 0x0A, 0x03, 0x96, 0x81, 0x00]);

    let echo_set = RuleSet::over(&[]).unwrap();
    let (echo, _) = protobuf_edit::rewrite::groupless::rewrite_standard(
        &out,
        &echo_set,
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
    )
    .unwrap();
    assert_eq!(echo, out, "the canonical output re-ingests canonically");
}
