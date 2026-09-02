use super::super::super::{Len, OnlineGap, Scalar, SourceLen, SourceScalar};
use super::{SourceRule, TransferFaultKind, splice_sources, splice_sources_into, splice_sources_sink};
use crate::wire::FieldNumber;
use crate::{DepthLimit, Standard};
use alloc::vec::Vec;

fn f(field: FieldNumber) -> u32 {
    field.as_inner()
}

/// A field-dispatched verdict table: scalar and LEN verdicts by
/// field number, everything else identity.
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

impl SourceRule for Table {
    fn on_varint(&mut self, _at: u32, field: FieldNumber, value: u64) -> SourceScalar<'_, u64> {
        (self.scalar)(f(field), value)
    }

    fn on_len<'a>(&'a mut self, _at: u32, field: FieldNumber, _payload: &'a [u8]) -> SourceLen<'a> {
        (self.len)(f(field))
    }
}

fn run(msg: &[u8], rule: &mut impl SourceRule) -> Vec<u8> {
    splice_sources(msg, rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap()
}

#[test]
fn before_and_after_current_resolve_at_the_ask() {
    // Copy f1 before itself and f2 after itself: three spellings
    // of adjacency, byte-exact with the padded value riding.
    let mut rule = Table {
        scalar: |field, _| match field {
            1 => SourceScalar::CopyRecord(OnlineGap::BeforeCurrent),
            2 => SourceScalar::CopyRecord(OnlineGap::AfterCurrent),
            _ => SourceScalar::Current(Scalar::Keep),
        },
        ..Table::default()
    };
    // varint f1=150 padded · varint f2=1
    let msg = [0x08, 0x96, 0x81, 0x00, 0x10, 0x01];
    let out = run(&msg, &mut rule);
    assert_eq!(out, [0x08, 0x96, 0x81, 0x00, 0x08, 0x96, 0x81, 0x00, 0x10, 0x01, 0x10, 0x01]);
}

#[test]
fn a_move_to_the_current_tail_relocates_across_the_layer() {
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
    // varint f9=7 · varint f1=1 · varint f9=8: both nines relocate
    // past the tail, ask order.
    let msg = [0x48, 0x07, 0x08, 0x01, 0x48, 0x08];
    let out = run(&msg, &mut rule);
    assert_eq!(out, [0x08, 0x01, 0x48, 0x07, 0x48, 0x08]);
}

#[test]
fn a_move_out_of_a_committed_container_settles_its_prefix() {
    // The record leaves the container for the root tail: the
    // container's prefix shrinks at its close, before the claim
    // emits — the suppression-before-settle law.
    let mut rule = Table {
        scalar: |field, _| {
            if field == 9 {
                SourceScalar::MoveRecord(OnlineGap::TailOfAncestor(1))
            } else {
                SourceScalar::Current(Scalar::Keep)
            }
        },
        len: |_| SourceLen::Current(Len::Commit { tail: None }),
    };
    // LEN f1 { varint f9=7 · varint f2=1 } · varint f3=5
    let msg = [0x0A, 0x04, 0x48, 0x07, 0x10, 0x01, 0x18, 0x05];
    let out = run(&msg, &mut rule);
    assert_eq!(out, [0x0A, 0x02, 0x10, 0x01, 0x18, 0x05, 0x48, 0x07]);
}

#[test]
fn a_copy_into_an_emptied_container_tail_still_lands_inside() {
    // The container's only record moves out to the root and the
    // sibling copies in: claims settle at their own layers.
    let mut rule = Table {
        scalar: |field, _| match field {
            9 => SourceScalar::MoveRecord(OnlineGap::TailOfAncestor(1)),
            2 => SourceScalar::CopyRecord(OnlineGap::TailOfCurrentLayer),
            _ => SourceScalar::Current(Scalar::Keep),
        },
        len: |_| SourceLen::Current(Len::Commit { tail: None }),
    };
    // LEN f1 { varint f9=7 } · varint f2=1
    let msg = [0x0A, 0x02, 0x48, 0x07, 0x10, 0x01];
    let out = run(&msg, &mut rule);
    // f9 leaves the container (now empty), rides at the document
    // tail; f2 copies to the root tail after it (ask order).
    assert_eq!(out, [0x0A, 0x00, 0x10, 0x01, 0x48, 0x07, 0x10, 0x01]);
}

#[test]
fn a_payload_copy_authors_minimal_framing_over_the_exact_interior() {
    let mut rule = Table {
        len: |field| {
            if field == 1 {
                SourceLen::CopyPayload {
                    to: OnlineGap::TailOfCurrentLayer,
                    field: FieldNumber::new(9).unwrap(),
                }
            } else {
                SourceLen::Current(Len::Pass)
            }
        },
        ..Table::default()
    };
    // LEN f1 (padded prefix) [ 0x96 0x81 0x00 ] · varint f2=1: the
    // interior (nested padding) rides exact behind minimal new
    // framing; the origin rides verbatim with its padded prefix.
    let msg = [0x0A, 0x83, 0x80, 0x00, 0x96, 0x81, 0x00, 0x10, 0x01];
    let out = run(&msg, &mut rule);
    assert_eq!(
        out,
        [0x0A, 0x83, 0x80, 0x00, 0x96, 0x81, 0x00, 0x10, 0x01, 0x4A, 0x03, 0x96, 0x81, 0x00]
    );
}

#[test]
fn a_payload_move_suppresses_the_whole_source_record() {
    let mut rule = Table {
        len: |field| {
            if field == 1 {
                SourceLen::MovePayload {
                    to: OnlineGap::BeforeCurrent,
                    field: FieldNumber::new(9).unwrap(),
                }
            } else {
                SourceLen::Current(Len::Pass)
            }
        },
        ..Table::default()
    };
    // LEN f1 "hi" · varint f2=1: the interior re-frames under f9
    // at the record's own position, the source framing vanishes.
    let msg = [0x0A, 0x02, 0x68, 0x69, 0x10, 0x01];
    let out = run(&msg, &mut rule);
    assert_eq!(out, [0x4A, 0x02, 0x68, 0x69, 0x10, 0x01]);
}

#[test]
fn an_unavailable_ancestor_level_refuses_before_any_mutation() {
    let mut rule = Table {
        scalar: |field, _| {
            if field == 1 {
                SourceScalar::CopyRecord(OnlineGap::TailOfAncestor(2))
            } else {
                SourceScalar::Current(Scalar::Keep)
            }
        },
        ..Table::default()
    };
    // Top level: one open layer (the root); two levels up is past
    // the chain.
    let msg = [0x08, 0x01];
    let mut out = alloc::vec![0xAA];
    let fault =
        splice_sources_into(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE, &mut out)
            .unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), TransferFaultKind::AnchorUnavailable { levels: 2 }));
    assert_eq!(out, [0xAA], "the reuse buffer is untouched on refusal");

    // Zero never names a level: the current layer's tail has its
    // own spelling.
    let mut zero = Table {
        scalar: |_, _| SourceScalar::CopyRecord(OnlineGap::TailOfAncestor(0)),
        ..Table::default()
    };
    let fault =
        splice_sources(&msg, &mut zero, Standard::Tolerant, DepthLimit::REFERENCE).unwrap_err();
    assert!(matches!(fault.kind(), TransferFaultKind::AnchorUnavailable { levels: 0 }));
}

#[test]
fn the_sink_face_matches_the_buffered_face_and_hands_nothing_on_a_fault() {
    let make = || Table {
        scalar: |field, _| match field {
            9 => SourceScalar::MoveRecord(OnlineGap::TailOfAncestor(1)),
            _ => SourceScalar::Current(Scalar::Keep),
        },
        len: |_| SourceLen::Current(Len::Commit { tail: None }),
    };
    let msg = [0x0A, 0x04, 0x48, 0x07, 0x10, 0x01, 0x18, 0x05];
    let buffered = run(&msg, &mut make());
    let mut handed = Vec::new();
    splice_sources_sink(&msg, &mut make(), Standard::Tolerant, DepthLimit::REFERENCE, |bytes| {
        handed.extend_from_slice(bytes);
    })
    .unwrap();
    assert_eq!(handed, buffered);

    // The custody law: a fault mid-walk hands nothing — the same
    // move asked at the top level has no ancestor.
    let flat = [0x48, 0x07];
    let mut count = 0usize;
    let fault =
        splice_sources_sink(&flat, &mut make(), Standard::Tolerant, DepthLimit::REFERENCE, |_| {
            count += 1
        })
        .unwrap_err();
    assert!(matches!(fault.kind(), TransferFaultKind::AnchorUnavailable { levels: 1 }));
    assert_eq!(count, 0, "zero handoff on any fault");
}

#[test]
fn current_verdicts_keep_the_host_behavior_beside_transfers() {
    // A rewrite, a drop, a commit with a tail, and a transfer in
    // one job: the host verdicts behave exactly as at the plain
    // faces.
    struct Mixed;
    impl SourceRule for Mixed {
        fn on_varint(&mut self, _at: u32, field: FieldNumber, value: u64) -> SourceScalar<'_, u64> {
            match field.as_inner() {
                2 => SourceScalar::Current(Scalar::Rewrite(value + 1)),
                3 => SourceScalar::Current(Scalar::Drop),
                9 => SourceScalar::MoveRecord(OnlineGap::TailOfAncestor(1)),
                _ => SourceScalar::Current(Scalar::Keep),
            }
        }

        fn on_len<'a>(
            &'a mut self,
            _at: u32,
            _field: FieldNumber,
            _payload: &'a [u8],
        ) -> SourceLen<'a> {
            SourceLen::Current(Len::Commit { tail: Some(b"\x20\x05") })
        }
    }
    // LEN f1 { varint f2=1 · varint f3=7 · varint f9=8 } · varint f2=2
    let msg = [0x0A, 0x06, 0x10, 0x01, 0x18, 0x07, 0x48, 0x08, 0x10, 0x02];
    let out = run(&msg, &mut Mixed);
    // Inside the container: f2 rewritten, f3 dropped, f9 moved
    // out, the commit tail (varint f4=5) appended; then the outer
    // f2 rewritten; the moved record last.
    assert_eq!(out, [0x0A, 0x04, 0x10, 0x02, 0x20, 0x05, 0x10, 0x03, 0x48, 0x08]);
}

#[test]
fn a_canonical_job_judges_the_walked_words_transfers_included() {
    // The padded f9 value refuses under the canonical standard at
    // the walk, before its move could resolve.
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
    let msg = [0x48, 0x96, 0x81, 0x00];
    let fault = splice_sources(&msg, &mut rule, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
        .unwrap_err();
    assert!(matches!(
        fault.kind(),
        TransferFaultKind::Job(super::FaultKind::Wire(super::WireBreach::NonMinimal))
    ));
}
