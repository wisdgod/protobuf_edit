//! The groupless fixed cell's scoped battery: door judgments,
//! per-action landings, exhaustion refusals, and carve honesty at
//! odd slab addresses. The cross-twin differential and the armed
//! allocator rows live in the integration judges.

use core::mem::MaybeUninit;

use super::*;
use crate::inplace::Rule;
use crate::path::Segment;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

/// A generously sized slab for rows that are not about capacity
/// (a wildcard rule under the reference depth budget prices about
/// ten kibibytes of derived tables).
fn slab() -> [MaybeUninit<u8>; 16384] {
    [MaybeUninit::uninit(); 16384]
}

#[test]
fn every_action_class_lands_in_place() {
    let (one, two, three, four, five) = (f(1), f(2), f(3), f(4), f(5));
    let rules = [
        Rule { path: &[Segment::Field(one)], action: Action::SetVarint(200) },
        Rule { path: &[Segment::Field(two)], action: Action::SetPayload(b"no") },
        Rule { path: &[Segment::Field(three)], action: Action::SetI32(0xAABB_CCDD) },
        Rule { path: &[Segment::Field(four)], action: Action::SetI64(0x1122_3344_5566_7788) },
        Rule { path: &[Segment::Field(five)], action: Action::Renumber(f(6)) },
    ];
    let set = RuleSet::over(&rules).unwrap();
    // varint f1=150 · LEN f2 "hi" · i32 f3 · i64 f4 · varint f5=1
    let mut msg = [
        0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x01,
    ];
    let plan = Plan::new(5).unwrap();
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!((stats.replaced(), stats.renumbered()), (4, 1));
    assert_eq!(
        msg,
        [
            0x08, 0xC8, 0x01, 0x12, 0x02, b'n', b'o', 0x1D, 0xDD, 0xCC, 0xBB, 0xAA, 0x21, 0x88,
            0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x30, 0x01,
        ]
    );
}

#[test]
fn wildcard_rules_descend_and_land_at_depth() {
    let route = [f(3)];
    let rules = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
        action: Action::SetVarint(9),
    }];
    let set = RuleSet::over(&rules).unwrap();
    // LEN f3 { varint f1=150 } · varint f1=150
    let mut msg = [0x1A, 0x03, 0x08, 0x96, 0x01, 0x08, 0x96, 0x01];
    let plan = Plan::new(2).unwrap();
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(msg, [0x1A, 0x03, 0x08, 0x89, 0x00, 0x08, 0x89, 0x00]);
    assert_eq!(stats.replaced(), 2);
}

#[test]
fn the_write_list_refuses_one_short_with_the_buffer_untouched() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::SetVarint(0) }];
    let set = RuleSet::over(&rules).unwrap();
    let mut msg = [0x08, 0x05, 0x08, 0x06, 0x08, 0x07];
    let snapshot = msg;
    // Three matches against a plan of two: the third landing
    // refuses at its own record head.
    let plan = Plan::new(2).unwrap();
    let fault = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap_err();
    assert_eq!(fault.at(), 4);
    assert!(matches!(fault.kind(), FaultKind::WriteListFull { need: 3, have: 2 }));
    assert_eq!(msg, snapshot, "the refused buffer moved");
    // The exact plan accepts the same job over the same slab.
    let plan = Plan::new(3).unwrap();
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(stats.replaced(), 3);
    assert_eq!(msg, [0x08, 0x00, 0x08, 0x00, 0x08, 0x00]);
}

#[test]
fn the_slab_judgment_is_exact_at_any_address() {
    let route = [f(3)];
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::SetVarint(0) },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
            action: Action::Tombstone { field: f(9) },
        },
    ];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(4).unwrap();
    let need = plan.bytes(&set, DepthLimit::REFERENCE);
    let mut backing = [MaybeUninit::<u8>::uninit(); 1 << 16];
    assert!(need + 8 <= backing.len(), "the fixture slab covers the demand");
    let msg = [0x08, 0x96, 0x01, 0x1A, 0x04, 0x12, 0x02, 0x68, 0x69];
    for offset in 0..8 {
        // Exactly the demand carves and lands, at every address.
        let mut buf = msg;
        let stats = apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut backing[offset..offset + need],
        )
        .unwrap();
        assert_eq!((stats.replaced(), stats.tombstoned()), (1, 1));
        // One byte fewer refuses before reading anything, at every
        // address.
        let mut buf = msg;
        let fault = apply(
            &mut buf,
            &set,
            DepthLimit::REFERENCE,
            &plan,
            &mut backing[offset..offset + need - 1],
        )
        .unwrap_err();
        assert_eq!(fault.at(), 0);
        assert!(matches!(
            fault.kind(),
            FaultKind::SlabShort { need: n, have } if n == need && have == need - 1
        ));
        assert_eq!(buf, msg, "the refused buffer moved");
    }
}

#[test]
fn the_budget_reports_used_against_capacity() {
    let route = [f(3)];
    let rules = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
        action: Action::SetVarint(9),
    }];
    let set = RuleSet::over(&rules).unwrap();
    // Two nested crossings, two landings.
    let mut msg = [0x1A, 0x05, 0x1A, 0x03, 0x08, 0x96, 0x01, 0x08, 0x96, 0x01];
    let plan = Plan::new(8).unwrap();
    let (result, budget) =
        apply_budget(&mut msg, &set, Standard::Tolerant, DepthLimit::REFERENCE, &plan, &mut slab());
    assert_eq!(result.unwrap().replaced(), 2);
    assert_eq!(budget.writes().used, 2);
    assert_eq!(budget.writes().capacity, 8);
    // Root + two committed layers.
    assert_eq!(budget.layers().used, 3);
    assert_eq!(budget.levels().used, 2);
    // Every derived lane held its proven bound.
    for gauge in [
        budget.layers(),
        budget.levels(),
        budget.targets(),
        budget.stages(),
        budget.wilds(),
        budget.staged(),
    ] {
        assert!(gauge.used <= gauge.capacity, "a derived bound was undersized: {gauge:?}");
    }
}

#[test]
fn faults_surface_with_the_host_vocabulary() {
    // A canonical job refuses a padded width; the tolerant one
    // lands it.
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::SetVarint(7) }];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(1).unwrap();
    let mut msg = [0x08, 0x96, 0x01];
    let fault = apply_standard(
        &mut msg,
        &set,
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
        &plan,
        &mut slab(),
    )
    .unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::ValueWidth { rule: 0, need: 1, have: 2 }));
    assert_eq!(msg, [0x08, 0x96, 0x01]);

    // A group code is the capability refusal.
    let mut grouped = [0x0B, 0x0C];
    let fault = apply(&mut grouped, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::GroupCode)));

    // Two rules on one record conflict.
    let route = [f(3)];
    let both = [
        Rule { path: &[Segment::Field(f(1))], action: Action::SetVarint(0) },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
            action: Action::SetVarint(1),
        },
    ];
    let both_set = RuleSet::over(&both).unwrap();
    let mut msg = [0x08, 0x05];
    let fault = apply(&mut msg, &both_set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::Conflict { first: 0, second: 1 }));
}

#[test]
fn zero_write_plans_serve_judge_only_jobs() {
    let rules = [Rule { path: &[Segment::Field(f(63))], action: Action::SetVarint(0) }];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(0).unwrap();
    let mut msg = [0x08, 0x05];
    let snapshot = msg;
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(stats, Stats::default());
    assert_eq!(msg, snapshot);
}

#[test]
fn replacement_judgments_ride_the_fixed_walk() {
    // A lawful whole-record replacement lands; a misshapen one
    // refuses with the candidate-relative coordinate.
    let rules = [Rule {
        path: &[Segment::Field(f(2))],
        action: Action::ReplaceRecord(&[0x08, 0x96, 0x01]),
    }];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(1).unwrap();
    // LEN f2 "h": three bytes, equal extent.
    let mut msg = [0x12, 0x01, 0x68];
    let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap();
    assert_eq!(stats.substituted(), 1);
    assert_eq!(msg, [0x08, 0x96, 0x01]);

    let torn = [Rule {
        path: &[Segment::Field(f(2))],
        action: Action::ReplaceRecord(&[0x08, 0x96, 0xFF]),
    }];
    let torn_set = RuleSet::over(&torn).unwrap();
    let mut msg = [0x12, 0x01, 0x68];
    let fault = apply(&mut msg, &torn_set, DepthLimit::REFERENCE, &plan, &mut slab()).unwrap_err();
    assert!(matches!(
        fault.kind(),
        FaultKind::ReplacementWire { rule: 0, at: 1, breach: WireBreach::Varint }
    ));
    assert_eq!(msg, [0x12, 0x01, 0x68]);
}

#[test]
fn depth_exhaustion_is_the_wire_refusal() {
    let route = [f(1)];
    let rules = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
        action: Action::SetVarint(0),
    }];
    let set = RuleSet::over(&rules).unwrap();
    let plan = Plan::new(1).unwrap();
    // f1 LEN { f1 LEN { varint f2 } }: two committed crossings
    // against a budget of one.
    let mut msg = [0x0A, 0x04, 0x0A, 0x02, 0x10, 0x00];
    let fault = apply(&mut msg, &set, DepthLimit::MIN, &plan, &mut slab()).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));
}
