//! Contract pins for the groupless rewriter: exhaustive on the
//! dialect clauses (capability refusal via the wire wrapper,
//! all-LEN slot density), representative on shared semantics.

use alloc::vec::Vec;

use super::*;
use crate::path::Segment;
use crate::wire::FieldNumber;
use crate::rewrite::{InsertRuleSet, Rule, RuleSet, Stats};

#[track_caller]
fn h(s: &str) -> Vec<u8> {
    let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(hex.len().is_multiple_of(2), "odd hex literal");
    hex.chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap();
            let lo = (pair[1] as char).to_digit(16).unwrap();
            (hi * 16 + lo) as u8
        })
        .collect()
}

#[track_caller]
fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

const D: DepthLimit = DepthLimit::REFERENCE;

#[track_caller]
fn run(input: &[u8], rules: &[Rule<'_>]) -> Result<(Vec<u8>, Stats), Fault> {
    rewrite(input, &RuleSet::over(rules).expect("test rules admit"), D)
}

// ─── the dialect's own clauses ───

#[test]
fn group_codes_fault_as_the_inherited_capability_refusal() {
    let fault = run(&h("0B"), &[]).unwrap_err();
    assert!(matches!(fault.kind, FaultKind::Wire(WireBreach::GroupCode)));

    // Inside a commitment too, with the trail.
    let rules =
        [Rule { path: &[Segment::Field(f(1)), Segment::Field(f(2))], action: Action::Delete }];
    let fault = run(&h("0A 01 0C"), &rules).unwrap_err();
    assert_eq!(fault.at, 2);
    assert_eq!(&fault.trail[..], &[Crossing::new(f(1), 0)]);
    assert!(matches!(fault.kind, FaultKind::Wire(WireBreach::GroupCode)));
}

#[test]
fn all_len_framing_slots_every_recursion_level() {
    // Three nested LENs, edit at the bottom: every ancestor is a
    // dirty slot (no group shortcuts exist).
    let input = h("0A 06 0A 04 0A 02 10 01");
    let route = [f(1)];
    let rules = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
        action: Action::Replace(Value::Varint(300)),
    }];
    let (out, stats) = run(&input, &rules).unwrap();
    // The bottom record grows by one byte; each ancestor prefix
    // re-emits one larger.
    assert_eq!(out, h("0A 07 0A 05 0A 03 10 AC 02"));
    assert_eq!(stats.descended, 3);
}

// ─── shared semantics, representative ───

#[test]
fn the_three_canonical_jobs_hold() {
    let (out, _) = run(
        &h("08 01 10 02 08 03"),
        &[Rule { path: &[Segment::Field(f(1))], action: Action::Delete }],
    )
    .unwrap();
    assert_eq!(out, h("10 02"));

    let (out, _) = run(
        &h("08 9601"),
        &[Rule { path: &[Segment::Field(f(1))], action: Action::Replace(Value::Varint(7)) }],
    )
    .unwrap();
    assert_eq!(out, h("08 07"));

    let route = [f(1)];
    let (out, _) = run(
        &h("0A 05 0A 00 12 01 61 12 01 62"),
        &[Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
            action: Action::Replace(Value::Len(b"X")),
        }],
    )
    .unwrap();
    assert_eq!(out, h("0A 05 0A 00 12 01 58 12 01 58"));
}

#[test]
fn a_ruleless_job_is_a_bit_true_identity_even_over_padding() {
    let input = h("88 00 01 0A 82 80 00 61 62 08 81 00");
    let (out, stats) = run(&input, &[]).unwrap();
    assert_eq!(out, input);
    assert_eq!(stats, Stats::default());
}

#[test]
fn a_same_length_dirty_interior_keeps_the_padded_prefix_verbatim() {
    let input = h("0A 82 00 08 07");
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(1))],
        action: Action::Replace(Value::Varint(9)),
    }];
    let (out, _) = run(&input, &rules).unwrap();
    assert_eq!(out, h("0A 82 00 08 09"));
}

#[test]
fn a_clean_sibling_before_a_dirty_one_is_copied_whole() {
    let input = h("0A 02 18 01 0A 02 10 01");
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2))],
        action: Action::Replace(Value::Varint(5)),
    }];
    let (out, _) = run(&input, &rules).unwrap();
    assert_eq!(out, h("0A 02 18 01 0A 02 10 05"));
}

#[test]
fn the_depth_budget_gates_len_recursion() {
    let one = DepthLimit::MIN;
    let deep_rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(1)), Segment::Field(f(1))],
        action: Action::Delete,
    }];
    let set = RuleSet::over(&deep_rules).unwrap();
    let fault = rewrite(&h("0A 04 0A 02 0A 00"), &set, one).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::Depth));
}

#[test]
fn a_kind_mismatched_replacement_is_the_authors_fault() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Replace(Value::I64(5)) }];
    let fault = run(&h("08 01"), &rules).unwrap_err();
    assert_eq!(fault.kind, FaultKind::KindMismatch { rule: 0 });
}

// ─── Normalize: the fidelity pole's opposite ───

#[test]
fn normalize_erases_the_padding_of_exactly_its_targets() {
    // f1 varint: tag and value both padded; f2 LEN "ab": tag and
    // prefix both padded; f3 I32: tag padded (fixed values have
    // one width).
    let input = h("88 00 81 00  92 80 00 82 80 00 61 62  9D 00 01020304");
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(3))], action: Action::Normalize },
    ];
    let (out, stats) = run(&input, &rules).unwrap();
    assert_eq!(out, h("08 01 12 02 61 62 1D 01020304"));
    assert_eq!(stats.normalized(), 3);

    // Untargeted padding survives: the same document under a
    // one-field set keeps the other records verbatim.
    let one = [Rule { path: &[Segment::Field(f(1))], action: Action::Normalize }];
    let (out, _) = run(&input, &one).unwrap();
    assert_eq!(out, h("08 01 92 80 00 82 80 00 61 62 9D 00 01020304"));
}

#[test]
fn normalize_of_a_minimal_record_is_byte_identity() {
    let input = h("08 01 12 01 61");
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
    ];
    let (out, stats) = run(&input, &rules).unwrap();
    assert_eq!(out, input);
    assert_eq!(stats.normalized(), 2);
}

#[test]
fn a_normalized_len_interior_is_the_declared_domain() {
    // The payload is a padded varint record — interior bytes ride
    // verbatim while the target's own tag and prefix re-author.
    let input = h("92 80 00 83 80 00 88 00 01");
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Normalize }];
    let (out, stats) = run(&input, &rules).unwrap();
    assert_eq!(out, h("12 03 88 00 01"));
    assert_eq!((stats.normalized(), stats.descended()), (1, 0));
}

#[test]
fn wildcard_paths_spell_nested_normalization() {
    // `**/f1` under a {f2} descend set: the padded record inside
    // the container normalizes, and the container's prefix
    // re-prices for the shrunken interior.
    let route = [f(2)];
    let rules = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
        action: Action::Normalize,
    }];
    let (out, stats) = run(&h("12 04 88 00 81 00"), &rules).unwrap();
    assert_eq!(out, h("12 02 08 01"));
    assert_eq!((stats.normalized(), stats.descended()), (1, 1));
}

#[cfg(feature = "scan-groupless")]
#[test]
fn a_fully_normalized_document_reingests_canonical_minimal() {
    use crate::scan::Standard;
    use crate::scan::groupless::Validator;

    #[track_caller]
    fn canonical(bytes: &[u8]) -> bool {
        let mut gate = Validator::new(Standard::CanonicalMinimal);
        if gate.feed(bytes).is_err() {
            return false;
        }
        gate.finish().is_ok()
    }

    let input = h("88 00 81 00 92 80 00 82 80 00 61 62");
    assert!(!canonical(&input), "the padded control must refuse");
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
    ];
    let (out, _) = run(&input, &rules).unwrap();
    assert!(canonical(&out), "every padded word fell under a target");
}

#[test]
fn a_normalize_target_conflicts_like_any_other_action() {
    let route = [f(9)];
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
            action: Action::Delete,
        },
    ];
    let fault = run(&h("08 01"), &rules).unwrap_err();
    assert!(matches!(fault.kind, FaultKind::Conflict { first: 0, second: 1 }));
}

// ─── the sink face ───

#[test]
fn the_sink_rewrite_concatenation_is_the_buffered_rewrite() {
    // Delete, replace, normalize, and a descent, over padding.
    let input = h("88 00 81 00  12 02 61 62  18 05  22 04 08 07 28 09");
    let route = [f(4)];
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(2))], action: Action::Replace(Value::Len(b"XY")) },
        Rule { path: &[Segment::Field(f(3))], action: Action::Delete },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(5))],
            action: Action::Replace(Value::Varint(300)),
        },
    ];
    let set = RuleSet::over(&rules).expect("test rules admit");
    let (expected, stats) = rewrite(&input, &set, D).unwrap();
    assert_eq!(expected, h("08 01 12 02 58 59 22 05 08 07 28 AC 02"));

    let mut streamed = Vec::new();
    let mut slices = 0usize;
    let sunk = rewrite_sink(&input, &set, D, |chunk| {
        assert!(!chunk.is_empty(), "sink slices are non-empty");
        slices += 1;
        streamed.extend_from_slice(chunk);
    })
    .unwrap();
    assert_eq!(streamed, expected);
    assert_eq!(sunk, stats);
    assert!(slices > 3, "runs and authored words hand out separately");
}

// ─── the scatter payload ───

#[test]
fn a_scatter_replacement_equals_its_whole_slice_twin() {
    // The same replacement supplied whole and as three pieces
    // (an empty middle included): byte-identical jobs through the
    // buffered and the sink face, and a wildcard rule hitting two
    // records re-reads the borrowed pieces at every hit.
    let input = h("12 02 61 62  0A 03 12 01 61  12 00");
    let route = [f(1)];
    let whole = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
        action: Action::Replace(Value::Len(b"world!")),
    }];
    let parts: [&[u8]; 3] = [b"wor", b"", b"ld!"];
    let scattered = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
        action: Action::Replace(Value::LenParts(&parts)),
    }];
    let whole_set = RuleSet::over(&whole).expect("test rules admit");
    let parts_set = RuleSet::over(&scattered).expect("test rules admit");

    let (expected, whole_stats) = rewrite(&input, &whole_set, D).unwrap();
    let (gathered, parts_stats) = rewrite(&input, &parts_set, D).unwrap();
    assert_eq!(gathered, expected);
    assert_eq!(parts_stats, whole_stats);
    assert_eq!(parts_stats.replaced(), 3, "the wildcard really hit thrice");

    let mut streamed = Vec::new();
    rewrite_sink(&input, &parts_set, D, |chunk| streamed.extend_from_slice(chunk)).unwrap();
    assert_eq!(streamed, expected);
}

#[test]
fn a_faulting_sink_job_hands_the_sink_nothing() {
    let mut calls = 0usize;
    let mut count = |_: &[u8]| calls += 1;

    // A capability refusal at the first record.
    let set = RuleSet::over(&[]).unwrap();
    assert!(rewrite_sink(&h("0B"), &set, D, &mut count).is_err());

    // A mid-document conflict: records were already measured, yet
    // nothing reached the sink (all faults precede the replay).
    let route = [f(1)];
    let conflicted = [
        Rule { path: &[Segment::Field(f(7))], action: Action::Delete },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(7))],
            action: Action::Replace(Value::Varint(0)),
        },
    ];
    let set2 = RuleSet::over(&conflicted).unwrap();
    assert!(rewrite_sink(&h("08 01 10 02 38 01"), &set2, D, &mut count).is_err());

    // The depth budget breach, mid-document again.
    let deep = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(1)), Segment::Field(f(1))],
        action: Action::Delete,
    }];
    let set3 = RuleSet::over(&deep).unwrap();
    assert!(
        rewrite_sink(&h("08 07 0A 04 0A 02 0A 00"), &set3, DepthLimit::MIN, &mut count).is_err()
    );

    assert_eq!(calls, 0, "Err hands the sink nothing");
}

#[test]
fn a_faulting_job_leaves_the_reuse_buffer_untouched() {
    let mut out = h("DE AD");
    let set = RuleSet::over(&[]).unwrap();
    let err = rewrite_into(&h("0B"), &set, D, &mut out).unwrap_err();
    assert!(matches!(err.kind, FaultKind::Wire(_)));
    assert_eq!(out, h("DE AD"));

    // A mid-document fault (records already measured): still
    // nothing published — length and content are unchanged.
    let route = [f(1)];
    let conflicted = [
        Rule { path: &[Segment::Field(f(7))], action: Action::Delete },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(7))],
            action: Action::Replace(Value::Varint(0)),
        },
    ];
    let set2 = RuleSet::over(&conflicted).unwrap();
    let err = rewrite_into(&h("08 01 10 02 38 01"), &set2, D, &mut out).unwrap_err();
    assert!(matches!(err.kind, FaultKind::Conflict { .. }));
    assert_eq!(out, h("DE AD"), "nothing published on a mid-measure fault");
}

// ─── insertion: the anchor contract ───

use crate::rewrite::{Gap, InsertRule};

/// Shorthand: one insert rule.
const fn ins(gap: Gap, field: u32, word: u64) -> InsertRule<'static> {
    InsertRule {
        gap,
        field: match FieldNumber::new(field) {
            Some(field) => field,
            None => panic!("test field in range"),
        },
        value: Value::Varint(word),
    }
}

/// [`run`]'s insert-door twin: same job, compiled through
/// [`InsertRuleSet::over`], yielding the receipt that carries the
/// inserted count.
#[track_caller]
fn run_ins(input: &[u8], rules: &[Rule<'_>]) -> Result<(Vec<u8>, InsertStats), Fault> {
    rewrite(input, &InsertRuleSet::over(rules).expect("test rules admit"), D)
}

#[test]
fn root_gaps_insert_into_the_empty_document() {
    // The 0→1 door: an empty document gains a head and a tail
    // record through the empty anchor path.
    let head = ins(Gap::HeadOf, 5, 1);
    let tail = ins(Gap::TailOf, 6, 2);
    let rules = [
        Rule { path: &[], action: Action::Insert(&head) },
        Rule { path: &[], action: Action::Insert(&tail) },
    ];
    let (out, stats) = run_ins(&[], &rules).unwrap();
    assert_eq!(out, h("28 01 30 02"));
    assert_eq!(stats.inserted(), 2);
}

#[test]
fn root_gaps_bracket_the_document_in_rule_order() {
    let tail = ins(Gap::TailOf, 6, 2);
    let head_five = ins(Gap::HeadOf, 5, 1);
    let head_seven = ins(Gap::HeadOf, 7, 3);
    let rules = [
        Rule { path: &[], action: Action::Insert(&tail) },
        Rule { path: &[], action: Action::Insert(&head_five) },
        Rule { path: &[], action: Action::Insert(&head_seven) },
    ];
    let (out, stats) = run_ins(&h("08 2A"), &rules).unwrap();
    // Heads in rule order at the front, the tail at the end.
    assert_eq!(out, h("28 01 38 03 08 2A 30 02"));
    assert_eq!(stats.inserted(), 3);
}

#[test]
fn interior_gaps_fire_once_per_occurrence_and_zero_is_silent() {
    let head = ins(Gap::HeadOf, 9, 1);
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) }];
    // Two container occurrences: one insert each, at each head.
    let (out, stats) = run_ins(&h("0A 02 10 02 0A 02 10 03"), &rules).unwrap();
    assert_eq!(out, h("0A 04 48 01 10 02 0A 04 48 01 10 03"));
    assert_eq!((stats.inserted(), stats.descended()), (2, 2));

    // Zero occurrences: silent, and the zero count is the signal.
    let (out, stats) = run_ins(&h("10 02"), &rules).unwrap();
    assert_eq!(out, h("10 02"));
    assert_eq!(stats.inserted(), 0);
}

#[test]
fn interior_gaps_walk_the_container_and_bracket_its_interior() {
    let head = ins(Gap::HeadOf, 2, 7);
    let tail = ins(Gap::TailOf, 3, 8);
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) },
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&tail) },
    ];
    // A populated container: head lands first inside, tail last —
    // and the prefix re-settles.
    let (out, stats) = run_ins(&h("0A 02 08 01"), &rules).unwrap();
    assert_eq!(out, h("0A 06 10 07 08 01 18 08"));
    assert_eq!((stats.inserted(), stats.descended()), (2, 1));

    // An empty container: the interior exists (one gap; head and
    // tail coincide), head-inserts precede tail-inserts.
    let (out, stats) = run_ins(&h("0A 00"), &rules).unwrap();
    assert_eq!(out, h("0A 04 10 07 18 08"));
    assert_eq!((stats.inserted(), stats.descended()), (2, 1));

    // No occurrence: no interior, no gap, silent.
    let (out, stats) = run_ins(&h("10 01"), &rules).unwrap();
    assert_eq!(out, h("10 01"));
    assert_eq!(stats.inserted(), 0);
}

#[test]
fn interior_gaps_commit_containerhood_and_fault_on_scalars() {
    let head = ins(Gap::HeadOf, 2, 7);
    let tail = ins(Gap::TailOf, 3, 8);
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&tail) },
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) },
    ];
    // The anchor commits: a scalar occurrence is the caller's
    // schema error, quoting the lowest-indexed anchoring rule.
    let fault = run_ins(&h("08 01"), &rules).unwrap_err();
    assert_eq!(fault.at, 0);
    assert!(matches!(fault.kind, FaultKind::KindMismatch { rule: 0 }));

    // A committed interior's wire faults are real, with the trail.
    let head_only = [Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) }];
    let fault = run_ins(&h("0A 01 FF"), &head_only).unwrap_err();
    assert_eq!(fault.at, 2);
    assert!(matches!(fault.kind, FaultKind::Wire(WireBreach::Varint)));
    assert_eq!(&fault.trail[..], &[Crossing::new(f(1), 0)]);
}

#[test]
fn interior_gaps_die_silently_with_their_owner() {
    let head = ins(Gap::HeadOf, 2, 7);
    // Delete owns the anchor: its interior is never walked, so the
    // head gap dies silently — the zero count is the exposure.
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) },
        Rule { path: &[Segment::Field(f(1))], action: Action::Delete },
    ];
    let (out, stats) = run_ins(&h("0A 02 08 01 10 05"), &rules).unwrap();
    assert_eq!(out, h("10 05"));
    assert_eq!((stats.deleted(), stats.inserted()), (1, 0));

    // A LEN Normalize rides its interior verbatim — no walk, so
    // interior gaps die with it too (the dialect asymmetry's
    // groupless half).
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) },
        Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
    ];
    let (out, stats) = run_ins(&h("0A 02 08 01"), &rules).unwrap();
    assert_eq!(out, h("0A 02 08 01"));
    assert_eq!((stats.normalized(), stats.inserted()), (1, 0));

    // A Replace owner re-authors the payload wholesale: the old
    // interior is never walked, so its gaps die silently too.
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) },
        Rule { path: &[Segment::Field(f(1))], action: Action::Replace(Value::Len(b"xy")) },
    ];
    let (out, stats) = run_ins(&h("0A 02 08 01"), &rules).unwrap();
    assert_eq!(out, h("0A 02 78 79"));
    assert_eq!((stats.replaced(), stats.inserted()), (1, 0));

    // Interior gaps under a deleted enclosing container die
    // wholesale: the owner's owner vanished.
    let inner_head = ins(Gap::HeadOf, 2, 7);
    let rules = [
        Rule {
            path: &[Segment::Field(f(1)), Segment::Field(f(1))],
            action: Action::Insert(&inner_head),
        },
        Rule { path: &[Segment::Field(f(1))], action: Action::Delete },
    ];
    let (out, stats) = run_ins(&h("0A 02 0A 00"), &rules).unwrap();
    assert_eq!(out, h(""));
    assert_eq!((stats.deleted(), stats.inserted()), (1, 0));
}

#[test]
fn insert_growth_cascades_through_every_enclosing_prefix() {
    // The Replace-growth path carries authored gap bytes at
    // arbitrary depth: both prefixes recompute.
    let head = ins(Gap::HeadOf, 2, 7);
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(1))],
        action: Action::Insert(&head),
    }];
    let (out, stats) = run_ins(&h("0A 04 0A 02 08 01"), &rules).unwrap();
    assert_eq!(out, h("0A 06 0A 04 10 07 08 01"));
    assert_eq!((stats.inserted(), stats.descended()), (1, 2));
}

#[test]
fn same_gap_inserts_all_emit_in_rule_order() {
    let first = ins(Gap::TailOf, 9, 1);
    let second = ins(Gap::TailOf, 9, 2);
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&first) },
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&second) },
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&first) },
    ];
    // Identical insert rules are lawful and emit per occurrence,
    // index order, at one coincident gap.
    let (out, stats) = run_ins(&h("0A 02 08 2A"), &rules).unwrap();
    assert_eq!(out, h("0A 08 08 2A 48 01 48 02 48 01"));
    assert_eq!(stats.inserted(), 3);
}

#[test]
fn inserted_records_are_inert() {
    // The inserted f5 record is output-only: the Delete targeting
    // f5 catches the source occurrence, never the insert.
    let tail = ins(Gap::TailOf, 5, 9);
    let rules = [
        Rule { path: &[], action: Action::Insert(&tail) },
        Rule { path: &[Segment::Field(f(5))], action: Action::Delete },
    ];
    let (out, stats) = run_ins(&h("28 05 08 01"), &rules).unwrap();
    assert_eq!(out, h("08 01 28 09"));
    assert_eq!((stats.deleted(), stats.inserted()), (1, 1));
}

#[test]
fn scattered_len_inserts_gather_behind_one_minimal_prefix() {
    let parts: [&[u8]; 2] = [b"he", b"llo"];
    let insert = InsertRule { gap: Gap::TailOf, field: f(2), value: Value::LenParts(&parts) };
    let rules = [Rule { path: &[], action: Action::Insert(&insert) }];
    let (out, stats) = run_ins(&h("08 01"), &rules).unwrap();
    assert_eq!(out, h("08 01 12 05 68 65 6C 6C 6F"));
    assert_eq!(stats.inserted(), 1);
}

#[test]
fn gap_anchors_ride_wildcards_at_every_committed_depth() {
    let head = ins(Gap::HeadOf, 9, 1);
    let route = [f(1)];
    let rules = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
        action: Action::Insert(&head),
    }];
    // f2 at depth zero and inside the crossed f1 both anchor.
    let (out, stats) = run_ins(&h("0A 04 12 02 18 07 12 02 18 07"), &rules).unwrap();
    assert_eq!(out, h("0A 06 12 04 48 01 18 07 12 04 48 01 18 07"));
    assert_eq!((stats.inserted(), stats.descended()), (2, 3));
}

#[test]
fn the_sink_face_replays_inserts_identically() {
    let head = ins(Gap::HeadOf, 2, 7);
    let root_tail = ins(Gap::TailOf, 6, 2);
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) },
        Rule { path: &[], action: Action::Insert(&root_tail) },
    ];
    let set = InsertRuleSet::over(&rules).unwrap();
    let doc = h("0A 02 08 01 10 05");
    let (buffered, buffered_stats) = rewrite(&doc, &set, D).unwrap();
    assert_eq!(buffered, h("0A 04 10 07 08 01 10 05 30 02"));
    let mut handed = Vec::new();
    let stats = rewrite_sink(&doc, &set, D, |bytes| handed.extend_from_slice(bytes)).unwrap();
    assert_eq!(handed, buffered);
    assert_eq!(stats, buffered_stats);
    assert_eq!(stats.inserted(), 2);
}
