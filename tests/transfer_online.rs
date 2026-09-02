//! The online-transfer custody judge: the source-aware splicer's
//! verdicts are compared against the equivalent handle-driven
//! editor commands — two independent engines, one output law — and
//! the sealed-overlay custody is pinned across all three faces on
//! one nested document: identical bytes buffered, appended, and
//! handed, with zero handoff on a fault injected after transfer
//! decisions were already taken.

#![cfg(all(
    feature = "transfer-splice-grouped",
    feature = "transfer-splice-groupless",
    feature = "patch-grouped",
    feature = "transfer-patch-grouped",
    feature = "transfer-patch-groupless",
    feature = "patch-groupless"
))]

use protobuf_edit::splice::{Len, OnlineGap, Scalar, SourceLen, SourceScalar};
use protobuf_edit::wire::FieldNumber;
use protobuf_edit::{DepthLimit, Standard};

const fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

/// A field-dispatched groupless verdict table.
struct Table {
    scalar: fn(u32, u64) -> SourceScalar<'static, u64>,
    len: fn(u32) -> SourceLen<'static>,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            scalar: |_, _| SourceScalar::Current(Scalar::Keep),
            len: |_| SourceLen::Current(Len::Pass),
        }
    }
}

impl protobuf_edit::splice::groupless::SourceRule for Table {
    fn on_varint(&mut self, _at: u32, field: FieldNumber, value: u64) -> SourceScalar<'_, u64> {
        (self.scalar)(field.as_inner(), value)
    }

    fn on_len<'a>(&'a mut self, _at: u32, field: FieldNumber, _payload: &'a [u8]) -> SourceLen<'a> {
        (self.len)(field.as_inner())
    }
}

#[test]
fn a_record_move_matches_the_editor_composition_groupless() {
    use protobuf_edit::patch::groupless::{InsertAt, TransferPatch};
    use protobuf_edit::splice::groupless::splice_sources;

    // varint f9=150 padded · LEN f1 "hi" · varint f2=1: the padded
    // record moves to the document tail on both engines.
    let msg = [0x48, 0x96, 0x81, 0x00, 0x0A, 0x02, 0x68, 0x69, 0x10, 0x01];
    let mut rule = Table {
        scalar: |field, _| {
            if field == 9 {
                SourceScalar::MoveRecord(OnlineGap::TailOfCurrentLayer)
            } else {
                SourceScalar::Current(Scalar::Keep)
            }
        },
        ..Table::default()
    };
    let out = splice_sources(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one move law across both engines");
}

#[test]
fn a_record_copy_before_itself_matches_the_editor_composition_groupless() {
    use protobuf_edit::patch::groupless::{InsertAt, TransferPatch};
    use protobuf_edit::splice::groupless::splice_sources;

    let msg = [0x48, 0x96, 0x81, 0x00, 0x10, 0x01];
    let mut rule = Table {
        scalar: |field, _| {
            if field == 9 {
                SourceScalar::CopyRecord(OnlineGap::BeforeCurrent)
            } else {
                SourceScalar::Current(Scalar::Keep)
            }
        },
        ..Table::default()
    };
    let out = splice_sources(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.copy_record(tops[0], InsertAt::HeadOf(None)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one copy law across both engines");
}

#[test]
fn a_payload_move_matches_the_editor_composition_groupless() {
    use protobuf_edit::patch::groupless::{InsertAt, TransferPatch};
    use protobuf_edit::splice::groupless::splice_sources;

    // LEN f1 [ padded interior 0x96 0x81 0x00 ] · varint f2=1.
    let msg = [0x0A, 0x03, 0x96, 0x81, 0x00, 0x10, 0x01];
    let mut rule = Table {
        len: |field| {
            if field == 1 {
                SourceLen::MovePayload { to: OnlineGap::TailOfCurrentLayer, field: f(9) }
            } else {
                SourceLen::Current(Len::Pass)
            }
        },
        ..Table::default()
    };
    let out = splice_sources(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.move_payload(tops[0], InsertAt::TailOf(None), f(9)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one payload-move law across both engines");
}

#[test]
fn a_group_move_matches_the_editor_composition_grouped() {
    use protobuf_edit::patch::grouped::{InsertAt, TransferPatch};
    use protobuf_edit::splice::grouped::{SourceGroup, SourceRule, splice_sources};

    struct MoveGroup;
    impl SourceRule for MoveGroup {
        fn on_group_enter(&mut self, _at: u32, field: FieldNumber) -> SourceGroup<'_> {
            if field.as_inner() == 1 {
                SourceGroup::MoveRecord(OnlineGap::TailOfCurrentLayer)
            } else {
                SourceGroup::Current(protobuf_edit::splice::grouped::Group::Pass)
            }
        }
    }

    // group f1 { varint f2=150 padded } · varint f3=5.
    let msg = [0x0B, 0x10, 0x96, 0x81, 0x00, 0x0C, 0x18, 0x05];
    let out =
        splice_sources(&msg, &mut MoveGroup, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();

    let mut patch = TransferPatch::open(&msg, DepthLimit::REFERENCE).unwrap();
    let tops: Vec<_> = patch.top().collect();
    patch.move_record(tops[0], InsertAt::TailOf(None)).unwrap();
    let expected = patch.save().unwrap();

    assert_eq!(out, expected, "one closure-move law across both engines");
}

#[test]
fn custody_is_identical_across_the_three_faces() {
    use protobuf_edit::splice::groupless::{splice_sources, splice_sources_into, splice_sources_sink};

    let make = || Table {
        scalar: |field, _| match field {
            9 => SourceScalar::MoveRecord(OnlineGap::TailOfAncestor(1)),
            8 => SourceScalar::CopyRecord(OnlineGap::AfterCurrent),
            _ => SourceScalar::Current(Scalar::Keep),
        },
        len: |field| match field {
            1 => SourceLen::Current(Len::Commit { tail: None }),
            2 => SourceLen::CopyPayload { to: OnlineGap::TailOfCurrentLayer, field: f(7) },
            _ => SourceLen::Current(Len::Pass),
        },
    };
    // LEN f1 { varint f9=7 · LEN f2 "ab" · varint f8=1 } · varint f3=5
    let msg = [0x0A, 0x08, 0x48, 0x07, 0x12, 0x02, 0x61, 0x62, 0x40, 0x01, 0x18, 0x05];
    let buffered =
        splice_sources(&msg, &mut make(), Standard::Tolerant, DepthLimit::REFERENCE).unwrap();

    let mut appended = vec![0xEE];
    splice_sources_into(
        &msg,
        &mut make(),
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &mut appended,
    )
    .unwrap();
    assert_eq!(appended[0], 0xEE);
    assert_eq!(appended[1..], buffered[..]);

    let mut handed = Vec::new();
    splice_sources_sink(&msg, &mut make(), Standard::Tolerant, DepthLimit::REFERENCE, |bytes| {
        handed.extend_from_slice(bytes);
    })
    .unwrap();
    assert_eq!(handed, buffered);

    // The nested moves and copies landed where the gaps name:
    // f9 out to the root tail, f2's interior re-framed at the
    // container tail, f8 doubled in place.
    assert_eq!(
        buffered,
        [
            0x0A, 0x0C, 0x12, 0x02, 0x61, 0x62, 0x40, 0x01, 0x40, 0x01, 0x3A, 0x02, 0x61, 0x62,
            0x18, 0x05, 0x48, 0x07,
        ]
    );
}

#[test]
fn a_fault_after_a_transfer_decision_hands_and_appends_nothing() {
    use protobuf_edit::splice::groupless::{
        TransferFaultKind, splice_sources_into, splice_sources_sink,
    };

    // The move decision lands, then the walk faults on unlawful
    // wire: custody says nothing was appended or handed.
    let make = || Table {
        scalar: |field, _| {
            if field == 9 {
                SourceScalar::MoveRecord(OnlineGap::TailOfCurrentLayer)
            } else {
                SourceScalar::Current(Scalar::Keep)
            }
        },
        ..Table::default()
    };
    // varint f9=7 · a lone continuation byte (no lawful head).
    let msg = [0x48, 0x07, 0xFF];
    let mut out = vec![0xAB];
    let fault =
        splice_sources_into(&msg, &mut make(), Standard::Tolerant, DepthLimit::REFERENCE, &mut out)
            .unwrap_err();
    assert!(matches!(fault.kind(), TransferFaultKind::Job(_)));
    assert_eq!(out, [0xAB], "the reuse buffer is untouched");

    let mut count = 0usize;
    splice_sources_sink(&msg, &mut make(), Standard::Tolerant, DepthLimit::REFERENCE, |_| {
        count += 1;
    })
    .unwrap_err();
    assert_eq!(count, 0, "zero handoff on any fault");
}

#[test]
fn transfer_output_reingests_tolerantly() {
    use protobuf_edit::splice::groupless::{Rule, splice, splice_sources};

    let mut rule = Table {
        scalar: |field, _| {
            if field == 9 {
                SourceScalar::MoveRecord(OnlineGap::TailOfCurrentLayer)
            } else {
                SourceScalar::Current(Scalar::Keep)
            }
        },
        len: |field| {
            if field == 1 {
                SourceLen::Current(Len::Commit { tail: None })
            } else {
                SourceLen::Current(Len::Pass)
            }
        },
    };
    // LEN f1 { varint f9=7 } · varint f2=1.
    let msg = [0x0A, 0x02, 0x48, 0x07, 0x10, 0x01];
    let out = splice_sources(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();

    // An identity job over the output re-emits it byte-identically.
    struct Identity;
    impl Rule for Identity {}
    let echo = splice(&out, &mut Identity, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    assert_eq!(echo, out, "the transfer output re-ingests tolerantly");
}
