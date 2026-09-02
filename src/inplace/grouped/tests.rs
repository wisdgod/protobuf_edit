use alloc::vec::Vec;

use super::*;
use crate::inplace::{Action, Rule, RuleSet, Stats};
use crate::path::Segment;
use crate::cursor::grouped::{Cursor, EntryKind};
use crate::{DepthLimit, FieldNumber, Standard};

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

/// One tolerant job over a fresh set (the plain door).
fn t(buf: &mut [u8], rules: &[Rule<'_>]) -> Result<Stats, Fault> {
    apply(buf, &RuleSet::over(rules).unwrap(), DepthLimit::REFERENCE)
}

/// One canonical job over a fresh set.
fn c(buf: &mut [u8], rules: &[Rule<'_>]) -> Result<Stats, Fault> {
    apply_standard(
        buf,
        &RuleSet::over(rules).unwrap(),
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
    )
}

// group f1 { varint f2=150 } — the five-byte workhorse.
const GROUP: [u8; 5] = [0x0B, 0x10, 0x96, 0x01, 0x0C];

// ─── the atomic renumber pair ───

#[test]
fn group_renumber_rewrites_both_tags_as_one_pair() {
    let one = [Segment::Field(f(1))];
    let mut msg = GROUP;
    let rules = [Rule { path: &one, action: Action::Renumber(f(2)) }];
    assert_eq!(t(&mut msg, &rules).unwrap().renumbered(), 1);
    assert_eq!(msg, [0x13, 0x10, 0x96, 0x01, 0x14]);

    // Canonical: minimal pair in, minimal pair out.
    let mut msg = GROUP;
    let rules = [Rule { path: &one, action: Action::Renumber(f(15)) }];
    assert_eq!(c(&mut msg, &rules).unwrap().renumbered(), 1);
    assert_eq!(msg, [0x7B, 0x10, 0x96, 0x01, 0x7C]);
}

#[test]
fn group_renumber_judges_each_tag_at_its_own_met_width() {
    // Mixed-width tolerant input: a padded start with a minimal
    // end — each tag pads (or not) to its own slot.
    let one = [Segment::Field(f(1))];
    let mut padded_start = [0x8B, 0x00, 0x10, 0x01, 0x0C];
    let rules = [Rule { path: &one, action: Action::Renumber(f(2)) }];
    assert_eq!(t(&mut padded_start, &rules).unwrap().renumbered(), 1);
    assert_eq!(padded_start, [0x93, 0x00, 0x10, 0x01, 0x14]);

    let mut padded_end = [0x0B, 0x10, 0x01, 0x8C, 0x00];
    assert_eq!(t(&mut padded_end, &rules).unwrap().renumbered(), 1);
    assert_eq!(padded_end, [0x13, 0x10, 0x01, 0x94, 0x00]);

    // The end width is an independent met fact: a start slot that
    // fits the new word proves nothing about the end slot, and the
    // end refusal quotes the end tag's own coordinate.
    let mut mixed = [0x8B, 0x00, 0x0C];
    let rules = [Rule { path: &one, action: Action::Renumber(f(16)) }];
    let fault = t(&mut mixed, &rules).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::TagWidth { rule: 0, need: 2, have: 1 }));
    assert_eq!(mixed, [0x8B, 0x00, 0x0C]);

    // A start refusal quotes the start tag.
    let mut msg = GROUP;
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::TagWidth { rule: 0, need: 2, have: 1 }));
}

#[test]
fn renumbered_group_interiors_stay_live() {
    let one = [Segment::Field(f(1))];
    let interior = [Segment::Field(f(1)), Segment::Field(f(2))];
    let mut msg = GROUP;
    let rules = [
        Rule { path: &one, action: Action::Renumber(f(5)) },
        Rule { path: &interior, action: Action::SetVarint(7) },
    ];
    let stats = t(&mut msg, &rules).unwrap();
    assert_eq!(msg, [0x2B, 0x10, 0x87, 0x00, 0x2C]);
    assert_eq!((stats.renumbered(), stats.replaced()), (1, 1));
}

// ─── whole-group ownership ───

#[test]
fn group_tombstones_cover_the_whole_extent_and_own_the_interior() {
    // The extent — start tag through end tag — refills whole, and
    // the interior rule fires nowhere (zero count is the signal).
    let one = [Segment::Field(f(1))];
    let interior = [Segment::Field(f(1)), Segment::Field(f(2))];
    let mut msg = GROUP;
    let rules = [
        Rule { path: &one, action: Action::Tombstone { field: f(9) } },
        Rule { path: &interior, action: Action::SetVarint(7) },
    ];
    let stats = t(&mut msg, &rules).unwrap();
    assert_eq!(msg, [0x48, 0x80, 0x80, 0x80, 0x00]);
    assert_eq!((stats.tombstoned(), stats.replaced()), (1, 0));

    // Canonical: the same extent takes the minimal LEN filler.
    let mut msg = GROUP;
    let rules = [Rule { path: &one, action: Action::Tombstone { field: f(1) } }];
    assert_eq!(c(&mut msg, &rules).unwrap().tombstoned(), 1);
    assert_eq!(msg, [0x0A, 0x03, 0x00, 0x00, 0x00]);

    // The empty group is the two-byte extent boundary.
    let mut empty = [0x0B, 0x0C];
    let rules = [Rule { path: &one, action: Action::Tombstone { field: f(1) } }];
    assert_eq!(t(&mut empty, &rules).unwrap().tombstoned(), 1);
    assert_eq!(empty, [0x08, 0x00]);

    // FillerUnfit is judged at the verified exit, against the
    // whole extent — and still precedes every write.
    let mut empty = [0x0B, 0x0C];
    let rules = [Rule { path: &one, action: Action::Tombstone { field: f(16) } }];
    let fault = t(&mut empty, &rules).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::FillerUnfit { rule: 0, need: 3, have: 2 }));
    assert_eq!(empty, [0x0B, 0x0C]);
}

#[test]
fn group_replacement_substitutes_the_whole_extent() {
    let one = [Segment::Field(f(1))];
    // Group → LEN record at equal extent (kind-crossing).
    let mut msg = GROUP;
    let rules =
        [Rule { path: &one, action: Action::ReplaceRecord(&[0x12, 0x03, 0x01, 0x02, 0x03]) }];
    assert_eq!(t(&mut msg, &rules).unwrap().substituted(), 1);
    assert_eq!(msg, [0x12, 0x03, 0x01, 0x02, 0x03]);

    // Group → group (renumbered wholesale, interior included).
    let mut msg = GROUP;
    let rules =
        [Rule { path: &one, action: Action::ReplaceRecord(&[0x13, 0x10, 0x96, 0x01, 0x14]) }];
    assert_eq!(c(&mut msg, &rules).unwrap().substituted(), 1);
    assert_eq!(msg, [0x13, 0x10, 0x96, 0x01, 0x14]);

    // LEN → group in the other direction.
    let two = [Segment::Field(f(2))];
    let mut msg = [0x12, 0x02, 0x68, 0x69];
    let rules = [Rule { path: &two, action: Action::ReplaceRecord(&[0x0B, 0x08, 0x01, 0x0C]) }];
    assert_eq!(t(&mut msg, &rules).unwrap().substituted(), 1);
    assert_eq!(msg, [0x0B, 0x08, 0x01, 0x0C]);

    // Interior rules under a replaced group fire nowhere.
    let interior = [Segment::Field(f(1)), Segment::Field(f(2))];
    let mut msg = GROUP;
    let rules = [
        Rule { path: &one, action: Action::ReplaceRecord(&[0x12, 0x03, 0x01, 0x02, 0x03]) },
        Rule { path: &interior, action: Action::SetVarint(7) },
    ];
    let stats = t(&mut msg, &rules).unwrap();
    assert_eq!((stats.substituted(), stats.replaced()), (1, 0));
}

#[test]
fn replacement_candidates_parse_under_the_remaining_depth_budget() {
    // At DepthLimit::MIN the target's own level leaves a budget of
    // one: the candidate may be a group, but not nest one.
    let one = [Segment::Field(f(1))];
    let source = [0x0B, 0x08, 0x01, 0x0C];

    let mut msg = source;
    let flat = [0x0B, 0x10, 0x01, 0x0C];
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&flat) }];
    let set = RuleSet::over(&rules).unwrap();
    assert_eq!(apply(&mut msg, &set, DepthLimit::MIN).unwrap().substituted(), 1);
    assert_eq!(msg, flat);

    let mut msg = source;
    let nested = [0x0B, 0x0B, 0x0C, 0x0C];
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&nested) }];
    let set = RuleSet::over(&rules).unwrap();
    let fault = apply(&mut msg, &set, DepthLimit::MIN).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(
        fault.kind(),
        FaultKind::ReplacementWire { rule: 0, at: 1, breach: WireBreach::Depth }
    ));
    assert_eq!(msg, source);
}

#[test]
fn replacement_refusals_cover_the_group_shapes() {
    let one = [Segment::Field(f(1))];
    let source = [0x0B, 0x10, 0x96, 0x01, 0x0C];

    // An unclosed candidate group is its own wire refusal, at the
    // candidate's window end.
    let mut msg = source;
    let rules =
        [Rule { path: &one, action: Action::ReplaceRecord(&[0x0B, 0x0B, 0x0C, 0x10, 0x01]) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert!(matches!(
        fault.kind(),
        FaultKind::ReplacementWire { rule: 0, at: 5, breach: WireBreach::Grouping }
    ));

    // Two complete records are not one.
    let mut msg = source;
    let rules =
        [Rule { path: &one, action: Action::ReplaceRecord(&[0x08, 0x01, 0x0B, 0x0C, 0x00]) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::ReplacementShape { rule: 0 }));

    // Length mismatch quotes both extents.
    let mut msg = source;
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&[0x0B, 0x0C]) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::ReplacementLength { rule: 0, need: 2, have: 5 }));
    assert_eq!(msg, source);
}

// ─── kind gates and per-record geometry inside groups ───

#[test]
fn groups_refuse_the_payload_and_scalar_actions() {
    // Groups have no single opaque payload extent (the LEN-only
    // law) and no scalar slot.
    let one = [Segment::Field(f(1))];
    for action in
        [Action::SetPayload(b"xy"), Action::SetVarint(1), Action::SetI32(1), Action::SetI64(1)]
    {
        let mut msg = GROUP;
        let fault = t(&mut msg, &[Rule { path: &one, action }]).unwrap_err();
        assert_eq!(fault.at(), 0, "{action:?}");
        assert!(matches!(fault.kind(), FaultKind::KindMismatch { rule: 0 }), "{action:?}");
        assert_eq!(msg, GROUP);
    }
}

#[test]
fn records_inside_groups_judge_exactly_as_at_top_level() {
    // Geometry is per-record: the met widths inside a group are
    // the same facts they are outside one.
    let inner = [Segment::Field(f(1)), Segment::Field(f(2))];
    let mut msg = GROUP;
    let rules = [Rule { path: &inner, action: Action::SetVarint(300) }];
    assert_eq!(t(&mut msg, &rules).unwrap().replaced(), 1);
    assert_eq!(msg, [0x0B, 0x10, 0xAC, 0x02, 0x0C]);

    // A LEN record inside a group takes the payload overwrite.
    let mut msg = [0x0B, 0x12, 0x02, 0x68, 0x69, 0x0C];
    let rules = [Rule { path: &inner, action: Action::SetPayload(b"no") }];
    assert_eq!(t(&mut msg, &rules).unwrap().replaced(), 1);
    assert_eq!(msg, [0x0B, 0x12, 0x02, b'n', b'o', 0x0C]);

    // And the same width refusal, at the record's own coordinate.
    let mut msg = GROUP;
    let rules = [Rule { path: &inner, action: Action::SetVarint(16_384) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::ValueWidth { rule: 0, need: 3, have: 2 }));
}

// ─── depth, pairing, and the wire faults ───

#[test]
fn groups_and_len_crossings_spend_one_depth_account() {
    // Two nested groups under a budget of one: the inner enter
    // refuses as depth, wherever the verdict fires (the walker's
    // own charge and the cursor's bound agree).
    let one = [Segment::Field(f(1))];
    let mut msg = [0x0B, 0x0B, 0x0C, 0x0C];
    let rules = [Rule { path: &one, action: Action::Renumber(f(2)) }];
    let set = RuleSet::over(&rules).unwrap();
    let fault = apply(&mut msg, &set, DepthLimit::MIN).unwrap_err();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));

    // A LEN committed inside a group charges the same account:
    // group (1) + LEN (2) fit a budget of two exactly, and the
    // interior edit lands.
    let deep = [Segment::Field(f(1)), Segment::Field(f(2)), Segment::Field(f(3))];
    let mut msg = [0x0B, 0x12, 0x02, 0x18, 0x01, 0x0C];
    let rules = [Rule { path: &deep, action: Action::SetVarint(9) }];
    let set = RuleSet::over(&rules).unwrap();
    let limit = DepthLimit::new(2).unwrap();
    assert_eq!(apply(&mut msg, &set, limit).unwrap().replaced(), 1);
    assert_eq!(msg, [0x0B, 0x12, 0x02, 0x18, 0x09, 0x0C]);
}

#[test]
fn suppressed_interiors_charge_the_same_depth_account() {
    // A committed LEN crossing plus the owned group leave zero
    // budget for the interior enter under a limit of two. The
    // cursor's own bound starts fresh inside the LEN window and
    // cannot see the crossing — this row pins the walk's positional
    // charge under suppression: admission never depends on which
    // rules the job carries.
    let own = [Segment::Field(f(1)), Segment::Field(f(1))];
    let doc = [0x0A, 0x04, 0x0B, 0x0B, 0x0C, 0x0C];
    let limit = DepthLimit::new(2).unwrap();

    let mut msg = doc;
    let rules = [Rule { path: &own, action: Action::Tombstone { field: f(15) } }];
    let set = RuleSet::over(&rules).unwrap();
    let fault = apply(&mut msg, &set, limit).unwrap_err();
    assert_eq!(fault.at(), 3);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));
    assert_eq!(msg, doc, "the refusal leaves the buffer untouched");

    // The non-owning twin refuses at the same coordinate with the
    // same class — the discriminating parity of the one account.
    let miss = [Segment::Field(f(1)), Segment::Field(f(9))];
    let rules = [Rule { path: &miss, action: Action::SetVarint(1) }];
    let set = RuleSet::over(&rules).unwrap();
    let twin = apply(&mut msg, &set, limit).unwrap_err();
    assert_eq!(twin.at(), 3);
    assert!(matches!(twin.kind(), FaultKind::Wire(WireBreach::Depth)));

    // One more level of budget admits the same owned job whole.
    let rules = [Rule { path: &own, action: Action::Tombstone { field: f(15) } }];
    let set = RuleSet::over(&rules).unwrap();
    let wider = DepthLimit::new(3).unwrap();
    assert_eq!(apply(&mut msg, &set, wider).unwrap().tombstoned(), 1);
}

#[test]
fn broken_group_framing_refuses_before_any_write() {
    // The rule targets an absent field: the walk's own wire
    // judgment is what refuses, not an action gate.
    let nine = [Segment::Field(f(9))];
    let rules = [Rule { path: &nine, action: Action::SetVarint(1) }];
    // Orphaned end, mismatched end, unclosed group — all the
    // grouping breach, each at its own coordinate.
    let cases: [(&[u8], u32); 3] = [(&[0x0C], 0), (&[0x0B, 0x1C], 1), (&[0x0B, 0x08, 0x01], 3)];
    for (doc, at) in cases {
        let mut buf = doc.to_vec();
        let fault = t(&mut buf, &rules).unwrap_err();
        assert_eq!(fault.at(), at, "{doc:02X?}");
        assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)), "{doc:02X?}");
        assert_eq!(buf, doc);
        let FaultKind::Wire(breach) = fault.kind() else { unreachable!() };
        assert_eq!(breach.class(), crate::FaultClass::Grammar);
    }
}

#[test]
fn two_rules_on_one_group_conflict() {
    let route = [f(3)];
    let direct = [Segment::Field(f(1))];
    let wild = [Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];
    let mut msg = GROUP;
    let rules = [
        Rule { path: &direct, action: Action::Renumber(f(2)) },
        Rule { path: &wild, action: Action::Tombstone { field: f(9) } },
    ];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::Conflict { first: 0, second: 1 }));
    assert_eq!(msg, GROUP);
}

// ─── doors, receipts, re-ingestion ───

#[test]
fn the_plain_door_is_the_tolerant_instance() {
    let one = [Segment::Field(f(1))];
    let rules = [Rule { path: &one, action: Action::Renumber(f(2)) }];
    let set = RuleSet::over(&rules).unwrap();
    let mut plain = GROUP;
    let mut declared = GROUP;
    let a = apply(&mut plain, &set, DepthLimit::REFERENCE).unwrap();
    let b = apply_standard(&mut declared, &set, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    assert_eq!(plain, declared);
    assert_eq!(a, b);
}

#[test]
fn outputs_re_ingest_under_the_declared_standard() {
    // One job touching every action class; the product re-parses
    // whole under the job's own standard.
    let one = [Segment::Field(f(1))];
    let two = [Segment::Field(f(2))];
    let three = [Segment::Field(f(3))];
    let four = [Segment::Field(f(4))];
    // group f1 {varint f2} · LEN f2 "hi" · varint f3 · group f4 {}
    let doc = [
        0x0B, 0x10, 0x96, 0x01, 0x0C, // group f1
        0x12, 0x02, 0x68, 0x69, // LEN f2
        0x18, 0x96, 0x01, // varint f3
        0x23, 0x24, // group f4, empty
    ];
    let rules = [
        Rule { path: &one, action: Action::Renumber(f(6)) },
        Rule { path: &two, action: Action::SetPayload(b"no") },
        Rule { path: &three, action: Action::SetVarint(200) },
        Rule { path: &four, action: Action::Tombstone { field: f(9) } },
    ];
    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        let mut buf = doc;
        let set = RuleSet::over(&rules).unwrap();
        let stats = apply_standard(&mut buf, &set, standard, DepthLimit::REFERENCE).unwrap();
        assert_eq!(
            (stats.replaced(), stats.renumbered(), stats.tombstoned()),
            (2, 1, 1),
            "{standard:?}"
        );
        // Each standard's engine instance through the crate-side
        // step face (the public canonical twin is the traverse
        // cell's own face).
        let depth = crate::cursor::GroupDepth::from(DepthLimit::REFERENCE);
        let mut cursor = Cursor::over(&buf, depth).unwrap();
        let mut walked = Vec::new();
        match standard {
            Standard::Tolerant => {
                while let Some(entry) = cursor.step::<false>() {
                    walked.push(entry.unwrap());
                }
            }
            Standard::CanonicalMinimal => {
                while let Some(entry) = cursor.step::<true>() {
                    walked.push(entry.unwrap());
                }
                assert!(
                    walked.iter().any(|entry| entry.field() == f(9)
                        && matches!(entry.kind(), EntryKind::Varint(0))),
                    "the canonical tombstone filler re-ingests"
                );
            }
        }
        assert!(walked.len() >= 5, "{standard:?}");
    }
}

#[test]
fn zero_match_jobs_leave_the_buffer_untouched_with_zero_counts() {
    let nine = [Segment::Field(f(9))];
    let rules = [Rule { path: &nine, action: Action::SetVarint(1) }];
    let mut buf = GROUP;
    let stats = t(&mut buf, &rules).unwrap();
    assert_eq!(buf, GROUP);
    assert_eq!(stats, Stats::default());
}
