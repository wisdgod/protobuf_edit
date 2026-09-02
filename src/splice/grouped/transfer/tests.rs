use super::super::super::{Len, OnlineGap, Scalar, SourceLen, SourceScalar};
use super::super::Group;
use super::{SourceGroup, SourceRule, TransferFaultKind, splice_sources, splice_sources_sink};
use crate::wire::FieldNumber;
use crate::{DepthLimit, Standard};
use alloc::vec::Vec;

/// A field-dispatched verdict table.
struct Table {
    scalar: fn(u32, u64) -> SourceScalar<'static, u64>,
    len: fn(u32) -> SourceLen<'static>,
    group: fn(u32) -> SourceGroup<'static>,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            scalar: |_, _| SourceScalar::Current(Scalar::Keep),
            len: |_| SourceLen::Current(Len::Pass),
            group: |_| SourceGroup::Current(Group::Pass),
        }
    }
}

impl SourceRule for Table {
    fn on_varint(&mut self, _at: u32, field: FieldNumber, value: u64) -> SourceScalar<'_, u64> {
        (self.scalar)(field.as_inner(), value)
    }

    fn on_len<'a>(&'a mut self, _at: u32, field: FieldNumber, _payload: &'a [u8]) -> SourceLen<'a> {
        (self.len)(field.as_inner())
    }

    fn on_group_enter(&mut self, _at: u32, field: FieldNumber) -> SourceGroup<'_> {
        (self.group)(field.as_inner())
    }
}

fn run(msg: &[u8], rule: &mut impl SourceRule) -> Vec<u8> {
    splice_sources(msg, rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap()
}

#[test]
fn a_group_copy_before_itself_settles_at_the_exit() {
    // The window's end is unknown at the ask; the sealed overlay
    // holds its place and the fold emits the whole closure —
    // padded interior words included — before the origin.
    let mut rule = Table {
        group: |field| {
            if field == 1 {
                SourceGroup::CopyRecord(OnlineGap::BeforeCurrent)
            } else {
                SourceGroup::Current(Group::Pass)
            }
        },
        ..Table::default()
    };
    // group f1 { varint f2=150 padded } · varint f3=5
    let msg = [0x0B, 0x10, 0x96, 0x81, 0x00, 0x0C, 0x18, 0x05];
    let out = run(&msg, &mut rule);
    assert_eq!(
        out,
        [0x0B, 0x10, 0x96, 0x81, 0x00, 0x0C, 0x0B, 0x10, 0x96, 0x81, 0x00, 0x0C, 0x18, 0x05]
    );
}

#[test]
fn a_group_copy_after_itself_emits_at_the_exit() {
    let mut rule = Table {
        group: |field| {
            if field == 1 {
                SourceGroup::CopyRecord(OnlineGap::AfterCurrent)
            } else {
                SourceGroup::Current(Group::Pass)
            }
        },
        ..Table::default()
    };
    // group f1 { group f1 {} } · varint f3=5 — nested same-field
    // groups ride whole with the closure (the inner ask is
    // silenced).
    let msg = [0x0B, 0x0B, 0x0C, 0x0C, 0x18, 0x05];
    let out = run(&msg, &mut rule);
    assert_eq!(out, [0x0B, 0x0B, 0x0C, 0x0C, 0x0B, 0x0B, 0x0C, 0x0C, 0x18, 0x05]);
}

#[test]
fn a_group_move_to_an_ancestor_tail_leaves_the_container() {
    let mut rule = Table {
        group: |field| {
            if field == 1 {
                SourceGroup::MoveRecord(OnlineGap::TailOfAncestor(1))
            } else {
                SourceGroup::Current(Group::Pass)
            }
        },
        len: |_| SourceLen::Current(Len::Commit { tail: None }),
        ..Table::default()
    };
    // LEN f4 { group f1 { varint f2=1 } · varint f3=7 } · varint f5=9:
    // the group leaves the container for the root tail; the
    // container's prefix shrinks at its close.
    let msg = [0x22, 0x06, 0x0B, 0x10, 0x01, 0x0C, 0x18, 0x07, 0x28, 0x09];
    let out = run(&msg, &mut rule);
    assert_eq!(out, [0x22, 0x02, 0x18, 0x07, 0x28, 0x09, 0x0B, 0x10, 0x01, 0x0C]);
}

#[test]
fn a_committed_group_is_an_open_container_on_the_ancestor_chain() {
    // A scalar inside a committed group moves to the group's own
    // tail (the current layer) and another to the group's
    // container (one level up): both settle before the end tag or
    // at the outer close respectively.
    let mut rule = Table {
        scalar: |field, _| match field {
            2 => SourceScalar::MoveRecord(OnlineGap::TailOfCurrentLayer),
            3 => SourceScalar::MoveRecord(OnlineGap::TailOfAncestor(1)),
            _ => SourceScalar::Current(Scalar::Keep),
        },
        group: |_| SourceGroup::Current(Group::Commit),
        ..Table::default()
    };
    // group f1 { varint f2=1 · varint f3=2 · varint f4=3 } ·
    // varint f5=9
    let msg = [0x0B, 0x10, 0x01, 0x18, 0x02, 0x20, 0x03, 0x0C, 0x28, 0x09];
    let out = run(&msg, &mut rule);
    // f2 re-lands before the end tag (after f4); f3 lands at the
    // document tail (the group's container is the root).
    assert_eq!(out, [0x0B, 0x20, 0x03, 0x10, 0x01, 0x0C, 0x28, 0x09, 0x18, 0x02]);
}

#[test]
fn payload_transfers_ride_inside_committed_groups() {
    let mut rule = Table {
        len: |field| {
            if field == 2 {
                SourceLen::MovePayload {
                    to: OnlineGap::TailOfCurrentLayer,
                    field: FieldNumber::new(9).unwrap(),
                }
            } else {
                SourceLen::Current(Len::Pass)
            }
        },
        group: |_| SourceGroup::Current(Group::Commit),
        ..Table::default()
    };
    // group f1 { LEN f2 "hi" · varint f3=1 } · varint f5=9
    let msg = [0x0B, 0x12, 0x02, 0x68, 0x69, 0x18, 0x01, 0x0C, 0x28, 0x09];
    let out = run(&msg, &mut rule);
    // The interior re-frames under f9 at the group's tail.
    assert_eq!(out, [0x0B, 0x18, 0x01, 0x4A, 0x02, 0x68, 0x69, 0x0C, 0x28, 0x09]);
}

#[test]
fn an_unavailable_ancestor_counts_only_open_containers() {
    // Inside one committed group the chain is root + group: two
    // levels up is past it.
    let mut rule = Table {
        scalar: |field, _| {
            if field == 2 {
                SourceScalar::CopyRecord(OnlineGap::TailOfAncestor(2))
            } else {
                SourceScalar::Current(Scalar::Keep)
            }
        },
        group: |_| SourceGroup::Current(Group::Commit),
        ..Table::default()
    };
    let msg = [0x0B, 0x10, 0x01, 0x0C];
    let fault =
        splice_sources(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap_err();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), TransferFaultKind::AnchorUnavailable { levels: 2 }));
}

#[test]
fn the_sink_face_matches_the_buffered_face_and_hands_nothing_on_a_fault() {
    let make = || Table {
        group: |field| {
            if field == 1 {
                SourceGroup::MoveRecord(OnlineGap::TailOfCurrentLayer)
            } else {
                SourceGroup::Current(Group::Pass)
            }
        },
        ..Table::default()
    };
    let msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x05];
    let buffered = run(&msg, &mut make());
    assert_eq!(buffered, [0x18, 0x05, 0x0B, 0x10, 0x96, 0x01, 0x0C]);
    let mut handed = Vec::new();
    splice_sources_sink(&msg, &mut make(), Standard::Tolerant, DepthLimit::REFERENCE, |bytes| {
        handed.extend_from_slice(bytes);
    })
    .unwrap();
    assert_eq!(handed, buffered);

    // A fault after the group's destination decision still hands
    // nothing: the deferred settle is inside the sealed overlay.
    let mut faulting = Table {
        group: |field| {
            if field == 1 {
                SourceGroup::CopyRecord(OnlineGap::TailOfCurrentLayer)
            } else {
                SourceGroup::Current(Group::Pass)
            }
        },
        scalar: |field, _| {
            if field == 3 {
                SourceScalar::CopyRecord(OnlineGap::TailOfAncestor(7))
            } else {
                SourceScalar::Current(Scalar::Keep)
            }
        },
        ..Table::default()
    };
    let mut count = 0usize;
    let fault =
        splice_sources_sink(&msg, &mut faulting, Standard::Tolerant, DepthLimit::REFERENCE, |_| {
            count += 1
        })
        .unwrap_err();
    assert!(matches!(fault.kind(), TransferFaultKind::AnchorUnavailable { levels: 7 }));
    assert_eq!(count, 0, "zero handoff on any fault");
}

#[test]
fn a_canonical_job_refuses_padded_group_framing_before_transfers_resolve() {
    let mut rule = Table {
        group: |_| SourceGroup::CopyRecord(OnlineGap::TailOfCurrentLayer),
        ..Table::default()
    };
    // group f1 with a padded end tag.
    let msg = [0x0B, 0x8C, 0x80, 0x00];
    let fault = splice_sources(&msg, &mut rule, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
        .unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Job(super::FaultKind::Wire(super::WireBreach::NonMinimal))
    ));
}
