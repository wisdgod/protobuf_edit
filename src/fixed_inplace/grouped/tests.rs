//! The grouped fixed cell's scoped battery: the pair law, owned
//! group extents, pairing verification over the carved lane,
//! exhaustion refusals, and carve honesty at odd slab addresses.
//! The cross-twin differential and the armed allocator rows live
//! in the integration judges.

use core::mem::MaybeUninit;

use super::*;
use crate::inplace::Rule;
use crate::path::Segment;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

/// A generously sized slab for rows that are not about capacity
/// (a wildcard rule under the reference depth budget prices about
/// fifteen kibibytes of derived tables and group lanes).
fn slab() -> [MaybeUninit<u8>; 32768] {
    [MaybeUninit::uninit(); 32768]
}

#[test]
fn a_group_renumber_rewrites_the_pair_atomically() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Renumber(f(2)) }];
    let set = RuleSet::over(&rules).unwrap();
    // group f1 { varint f2=150 } · varint f3=7
    let mut msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x07];
    let plan = Plan::new(2).unwrap();
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(msg, [0x13, 0x10, 0x96, 0x01, 0x14, 0x18, 0x07]);
    assert_eq!(stats.renumbered(), 1);
}

#[test]
fn an_owned_group_extent_tombstones_as_one() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Tombstone { field: f(9) } }];
    let set = RuleSet::over(&rules).unwrap();
    // group f1 { varint f2=150 } · varint f3=7
    let mut msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x07];
    let plan = Plan::new(1).unwrap();
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(msg, [0x48, 0x80, 0x80, 0x80, 0x00, 0x18, 0x07]);
    assert_eq!(stats.tombstoned(), 1);
}

#[test]
fn an_owned_group_replaces_whole_under_the_depth_budget() {
    // The candidate is itself a balanced group of equal extent.
    let candidate = [0x13, 0x10, 0x96, 0x01, 0x14];
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::ReplaceRecord(&candidate) }];
    let set = RuleSet::over(&rules).unwrap();
    let mut msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x07];
    let plan = Plan::new(1).unwrap();
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(msg, [0x13, 0x10, 0x96, 0x01, 0x14, 0x18, 0x07]);
    assert_eq!(stats.substituted(), 1);

    // A candidate nesting past the target's remaining budget
    // refuses with the candidate-relative coordinate: at the
    // document top the budget is the whole limit, so the probe's
    // second nested enter breaks a budget of one.
    let deep = [0x0B, 0x0B, 0x0C, 0x0C, 0x18];
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::ReplaceRecord(&deep) }];
    let set = RuleSet::over(&rules).unwrap();
    let mut msg = [0x12, 0x03, 0x08, 0x96, 0x01, 0x18, 0x07];
    let fault = apply(&mut msg, &set, DepthLimit::MIN, &plan, &mut slab()).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(
        fault.kind(),
        FaultKind::ReplacementWire { rule: 0, at: 1, breach: WireBreach::Depth }
    ));
    assert_eq!(msg, [0x12, 0x03, 0x08, 0x96, 0x01, 0x18, 0x07]);
}

#[test]
fn pairing_faults_surface_from_the_carved_lane() {
    let rules = [Rule { path: &[Segment::Field(f(63))], action: Action::SetVarint(0) }];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(0).unwrap();
    // An orphaned end tag.
    let mut orphan = [0x0C];
    let fault = apply(&mut orphan, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));
    // A mismatched end tag.
    let mut mismatch = [0x0B, 0x14];
    let fault = apply(&mut mismatch, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap_err();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));
    // An unclosed group at the window end.
    let mut unclosed = [0x0B, 0x10, 0x00];
    let fault = apply(&mut unclosed, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap_err();
    assert_eq!(fault.at(), 3);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));
    // A group nested past the declared budget.
    let mut deep = [0x0B, 0x0B, 0x0C, 0x0C];
    let fault = apply(&mut deep, &set, DepthLimit::MIN, &plan, &mut slab()).unwrap_err();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));
}

#[test]
fn suppressed_interiors_spend_the_depth_account() {
    // Tombstoning a group whose interior nests past the remaining
    // budget still refuses depth: admission never depends on which
    // rules the job carries.
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Tombstone { field: f(9) } }];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(1).unwrap();
    let mut msg = [0x0B, 0x0B, 0x0B, 0x0C, 0x0C, 0x0C];
    let fault = apply(&mut msg, &set, DepthLimit::new(2).unwrap(), &plan, &mut slab()).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));
}

#[test]
fn the_write_list_prices_the_pair_and_refuses_one_short() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Renumber(f(2)) }];
    let set = RuleSet::over(&rules).unwrap();
    let mut msg = [0x0B, 0x10, 0x96, 0x01, 0x0C];
    let snapshot = msg;
    // A pair plans two writes; a plan of one refuses at the pair's
    // completion with the buffer untouched.
    let plan = Plan::new(1).unwrap();
    let fault = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::WriteListFull { need: 2, have: 1 }));
    assert_eq!(fault.at(), 0, "the refusal names the pair's record");
    assert_eq!(msg, snapshot, "the refused buffer moved");
    // The exact plan lands the same job.
    let plan = Plan::new(2).unwrap();
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(stats.renumbered(), 1);
    assert_eq!(msg, [0x13, 0x10, 0x96, 0x01, 0x14]);
}

#[test]
fn the_slab_judgment_is_exact_at_any_address() {
    // The wildcard's descend set names both containers: the group
    // and the LEN inside it.
    let route = [f(1), f(3)];
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Renumber(f(2)) },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(4))],
            action: Action::SetVarint(0),
        },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(4).unwrap();
    let need = plan.bytes(&set, DepthLimit::REFERENCE);
    let mut backing = [MaybeUninit::<u8>::uninit(); 1 << 17];
    assert!(need + 8 <= backing.len(), "the fixture slab covers the demand");
    // group f1 { LEN f3 { varint f4 } } — a pair plus a nested
    // landing.
    let msg = [0x0B, 0x1A, 0x02, 0x20, 0x00, 0x0C];
    for offset in 0..8 {
        let mut buf = msg;
        let stats = apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut backing[offset..offset + need],
        )
        .unwrap();
        assert_eq!((stats.renumbered(), stats.replaced()), (1, 1));
        let mut buf = msg;
        let fault = apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut backing[offset..offset + need - 1],
        )
        .unwrap_err();
        assert!(matches!(
            fault.kind(),
            FaultKind::SlabShort { need: n, have } if n == need && have == need - 1
        ));
        assert_eq!(buf, msg, "the refused buffer moved");
    }
}

#[test]
fn the_budget_reports_the_group_lanes() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Renumber(f(2)) }];
    let set = RuleSet::over(&rules).unwrap();
    // group f1 { group f5 { } } — one renumbered pair, one plain
    // pair inside it.
    let mut msg = [0x0B, 0x2B, 0x2C, 0x0C];
    let plan = Plan::new(8).unwrap();
    let (result, budget) =
        apply_budget(&mut msg, &set, Standard::Tolerant, DepthLimit::REFERENCE, &plan, &mut slab());
    assert_eq!(result.unwrap().renumbered(), 1);
    assert_eq!(budget.writes().used, 2);
    assert_eq!(budget.opens().used, 2);
    assert_eq!(budget.pending().used, 1);
    assert_eq!(budget.levels().used, 2);
    for gauge in [
        budget.layers(),
        budget.levels(),
        budget.targets(),
        budget.stages(),
        budget.wilds(),
        budget.staged(),
        budget.opens(),
        budget.pending(),
    ] {
        assert!(gauge.used <= gauge.capacity, "a derived bound was undersized: {gauge:?}");
    }
}

#[test]
fn canonical_jobs_judge_group_tags_width_first() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Renumber(f(2)) }];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(2).unwrap();
    // A padded start tag refuses under the canonical standard,
    // ahead of any pairing judgment.
    let mut padded = [0x8B, 0x00, 0x0C];
    let fault = apply_standard(
        &mut padded,
        &set,
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
        &plan,
        &mut slab(),
    )
    .unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::NonMinimal)));
    assert_eq!(padded, [0x8B, 0x00, 0x0C]);

    // The tolerant instance renumbers the pair at its met widths.
    apply_standard(
        &mut padded,
        &set,
        Standard::Tolerant,
        DepthLimit::REFERENCE,
        &plan,
        &mut slab(),
    )
    .unwrap();
    assert_eq!(padded, [0x93, 0x00, 0x14]);
}

#[test]
fn scalar_and_len_records_judge_inside_groups() {
    let rules = [
        Rule {
            path: &[Segment::Field(f(1)), Segment::Field(f(2))],
            action: Action::SetVarint(200),
        },
        Rule {
            path: &[Segment::Field(f(1)), Segment::Field(f(3))],
            action: Action::SetPayload(b"xy"),
        },
    ];
    let set = RuleSet::over(&rules).unwrap();
    // group f1 { varint f2=150 · LEN f3 "hi" } — geometry is
    // per-record: the group scopes the matcher, so paths through
    // the group field land on its body records.
    let mut msg = [0x0B, 0x10, 0x96, 0x01, 0x1A, 0x02, 0x68, 0x69, 0x0C];
    let plan = Plan::new(2).unwrap();
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(stats.replaced(), 2);
    assert_eq!(msg, [0x0B, 0x10, 0xC8, 0x01, 0x1A, 0x02, b'x', b'y', 0x0C]);
}
