//! Contract pins: each test states one clause of the machine's
//! contract (the three canonical jobs, fidelity tiers, slot
//! discipline, shadowing, the kind gate, budgets, transactions).

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

// ─── Normalize over the six-code language ───

#[test]
fn normalize_reauthors_a_groups_framing_and_walks_its_interior() {
    // Group f2 with both framing tags padded, a padded varint f3
    // inside: the group's own tags re-author minimally; the
    // interior record is its own rule's business.
    let input = h("93 00 98 00 01 94 00");
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Normalize }];
    let (out, stats) = run(&input, &rules).unwrap();
    assert_eq!(out, h("13 98 00 01 14"), "the interior stays verbatim");
    assert_eq!(stats.normalized(), 1);

    // A second rule reaches inside the normalized group: the walk
    // still matches there (commitment by syntax, as ever).
    let both = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(2)), Segment::Field(f(3))], action: Action::Normalize },
    ];
    let (out, stats) = run(&input, &both).unwrap();
    assert_eq!(out, h("13 18 01 14"));
    assert_eq!(stats.normalized(), 2);
}

#[test]
fn a_normalized_group_spends_the_container_budget() {
    // Deleting a group discards its interior, but normalizing one
    // walks it: the walk's container budget applies, so a nested
    // group under a one-deep limit refuses as the depth breach.
    let input = h("0B 13 14 0C");
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Normalize }];
    let set = RuleSet::over(&rules).expect("test rules admit");
    let fault = rewrite(&input, &set, DepthLimit::MIN).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::Depth));
}

#[cfg(feature = "scan-grouped")]
#[test]
fn a_fully_normalized_grouped_document_reingests_canonical_minimal() {
    use crate::scan::Standard;
    use crate::scan::grouped::Validator;

    #[track_caller]
    fn canonical(bytes: &[u8]) -> bool {
        let mut gate = Validator::new(Standard::CanonicalMinimal, D);
        if gate.feed(bytes).is_err() {
            return false;
        }
        gate.finish().is_ok()
    }

    let input = h("93 00 98 00 01 94 00");
    assert!(!canonical(&input), "the padded control must refuse");
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(2)), Segment::Field(f(3))], action: Action::Normalize },
    ];
    let (out, _) = run(&input, &rules).unwrap();
    assert!(canonical(&out), "every padded word fell under a target");
}

// ─── the sink face ───

#[test]
fn the_sink_rewrite_concatenation_is_the_buffered_rewrite() {
    // A normalized group, a replaced varint, and a clean group.
    let input = h("93 00 18 01 94 00  08 9601  13 20 07 14");
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
        Rule { path: &[Segment::Field(f(1))], action: Action::Replace(Value::Varint(7)) },
    ];
    let set = RuleSet::over(&rules).expect("test rules admit");
    let (expected, stats) = rewrite(&input, &set, D).unwrap();
    assert_eq!(expected, h("13 18 01 14 08 07 13 20 07 14"));

    let mut streamed = Vec::new();
    let sunk = rewrite_sink(&input, &set, D, |chunk| {
        assert!(!chunk.is_empty(), "sink slices are non-empty");
        streamed.extend_from_slice(chunk);
    })
    .unwrap();
    assert_eq!(streamed, expected);
    assert_eq!(sunk, stats);
}

#[test]
fn a_faulting_sink_job_hands_the_sink_nothing() {
    let mut calls = 0usize;
    let mut count = |_: &[u8]| calls += 1;

    // Broken group framing, mid-document.
    let set = RuleSet::over(&[]).unwrap();
    assert!(rewrite_sink(&h("08 01 0B"), &set, D, &mut count).is_err());

    // A group-targeting replacement is the author's kind error.
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Replace(Value::Varint(0)) }];
    let set2 = RuleSet::over(&rules).unwrap();
    assert!(rewrite_sink(&h("08 01 13 14"), &set2, D, &mut count).is_err());

    assert_eq!(calls, 0, "Err hands the sink nothing");
}

// ─── the scatter payload ───

#[test]
fn a_scatter_replacement_equals_its_whole_slice_twin_across_groups() {
    // The replaced LEN sits beside group framing (the group's own
    // interior stays unrouted); the scatter and whole-slice forms
    // must produce byte-identical jobs, and a group-targeting
    // scatter is the same kind error a whole-slice LEN replacement
    // is.
    let input = h("12 02 61 62  1B 12 01 61 1C");
    let whole =
        [Rule { path: &[Segment::Field(f(2))], action: Action::Replace(Value::Len(b"hey")) }];
    let parts: [&[u8]; 2] = [b"he", b"y"];
    let scattered =
        [Rule { path: &[Segment::Field(f(2))], action: Action::Replace(Value::LenParts(&parts)) }];
    let whole_set = RuleSet::over(&whole).expect("test rules admit");
    let parts_set = RuleSet::over(&scattered).expect("test rules admit");
    let (expected, whole_stats) = rewrite(&input, &whole_set, D).unwrap();
    let (gathered, parts_stats) = rewrite(&input, &parts_set, D).unwrap();
    assert_eq!(gathered, expected);
    assert_eq!(parts_stats, whole_stats);

    // A group target refuses the scatter by kind, as it does the
    // whole slice.
    let group_target =
        [Rule { path: &[Segment::Field(f(3))], action: Action::Replace(Value::LenParts(&parts)) }];
    let set = RuleSet::over(&group_target).unwrap();
    let fault = rewrite(&h("1B 08 01 1C"), &set, D).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::KindMismatch { .. }));
}

// ─── the three canonical jobs ───

#[test]
fn deleting_a_top_level_field_erases_every_occurrence() {
    let input = h("08 01 10 02 08 03");
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let (out, stats) = run(&input, &rules).unwrap();
    assert_eq!(out, h("10 02"));
    assert_eq!(stats, Stats { deleted: 2, replaced: 0, normalized: 0, descended: 0 });
}

#[test]
fn replacing_a_value_reemits_the_payload_canonically() {
    let input = h("08 9601");
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Replace(Value::Varint(7)) }];
    let (out, stats) = run(&input, &rules).unwrap();
    assert_eq!(out, h("08 07"));
    assert_eq!(stats.replaced, 1);
}

#[test]
fn a_recursive_redaction_descends_by_the_declared_alphabet() {
    // Tree { Tree child = 1; bytes data = 2 } — redact all data.
    let input = h("0A 07 0A 02 12 00 12 01 61 12 02 62 63");
    let route = [f(1)];
    let rules = [Rule {
        path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
        action: Action::Replace(Value::Len(b"X")),
    }];
    let (out, stats) = run(&input, &rules).unwrap();
    assert_eq!(out, h("0A 08 0A 03 12 01 58 12 01 58 12 01 58"));
    assert_eq!(stats, Stats { deleted: 0, replaced: 3, normalized: 0, descended: 2 });
}

// ─── fidelity tiers ───

#[test]
fn a_ruleless_job_is_a_bit_true_identity_even_over_padding() {
    // Padded tag, padded LEN prefix, padded varint value: all
    // verbatim.
    let input = h("88 00 01 0A 82 80 00 61 62 08 81 00");
    let (out, stats) = run(&input, &[]).unwrap();
    assert_eq!(out, input);
    assert_eq!(stats, Stats::default());
}

#[test]
fn a_same_length_dirty_interior_keeps_the_padded_prefix_verbatim() {
    // f1's prefix is padded (2 in two bytes); the interior edit
    // keeps the length, so the prefix bytes stay untouched.
    let input = h("0A 82 00 08 07");
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(1))],
        action: Action::Replace(Value::Varint(9)),
    }];
    let (out, _) = run(&input, &rules).unwrap();
    assert_eq!(out, h("0A 82 00 08 09"));
}

#[test]
fn a_changed_length_reemits_the_prefix_canonically_but_not_the_tag() {
    let input = h("0A 82 00 08 07");
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(1))],
        action: Action::Replace(Value::Varint(300)),
    }];
    let (out, _) = run(&input, &rules).unwrap();
    // Interior grows to three bytes: prefix canonical `03`, tag
    // verbatim.
    assert_eq!(out, h("0A 03 08 AC 02"));
}

#[test]
fn a_replaced_records_padded_tag_stays_verbatim() {
    // Padded tag (field 1 varint in two bytes), replaced value.
    let input = h("88 00 05");
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Replace(Value::Varint(1)) }];
    let (out, _) = run(&input, &rules).unwrap();
    assert_eq!(out, h("88 00 01"), "tag bytes are untouched by a payload action");
}

// ─── slot discipline ───

#[test]
fn a_clean_sibling_before_a_dirty_one_is_copied_whole() {
    // Both f1 LENs are descended (committed); only the second
    // changes. The clean slot's descendant count keeps the slot
    // cursor aligned.
    let input = h("0A 02 18 01 0A 02 10 01");
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2))],
        action: Action::Replace(Value::Varint(5)),
    }];
    let (out, stats) = run(&input, &rules).unwrap();
    assert_eq!(out, h("0A 02 18 01 0A 02 10 05"));
    assert_eq!(stats.descended, 2);
}

#[test]
fn nested_clean_subtrees_skip_their_descendant_slots() {
    // f1[f1[f3]] all clean, then a dirty sibling: the outer clean
    // slot must skip its inner slot.
    let input = h("0A 04 0A 02 18 01 0A 02 10 01");
    let rules = [Rule {
        path: &[
            Segment::AnyDepth { descend: &[FieldNumber::new(1).unwrap()] },
            Segment::Field(f(2)),
        ],
        action: Action::Replace(Value::Varint(9)),
    }];
    let (out, _) = run(&input, &rules).unwrap();
    assert_eq!(out, h("0A 04 0A 02 18 01 0A 02 10 09"));
}

// ─── conflicts and shadowing ───

#[test]
fn a_double_target_is_a_loud_conflict() {
    let route = [f(1)];
    let rules = [
        Rule { path: &[Segment::Field(f(7))], action: Action::Delete },
        Rule {
            path: &[Segment::AnyDepth { descend: &route }, Segment::Field(f(7))],
            action: Action::Replace(Value::Varint(0)),
        },
    ];
    let fault = run(&h("38 01"), &rules).unwrap_err();
    assert_eq!(fault.at, 0);
    assert_eq!(fault.kind, FaultKind::Conflict { first: 0, second: 1 });
}

#[test]
fn a_consumed_container_shadows_its_interior_rules() {
    // Rule 0 deletes the container; rule 1's path through it never
    // fires (the interior does not exist any more).
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Delete },
        Rule {
            path: &[Segment::Field(f(1)), Segment::Field(f(2))],
            action: Action::Replace(Value::Varint(9)),
        },
    ];
    let (out, stats) = run(&h("0A 02 10 01"), &rules).unwrap();
    assert_eq!(out, h(""));
    assert_eq!(stats, Stats { deleted: 1, replaced: 0, normalized: 0, descended: 0 });
}

// ─── the kind gate ───

#[test]
fn a_kind_mismatched_replacement_is_the_authors_fault() {
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Replace(Value::I32(5)) }];
    let fault = run(&h("08 01"), &rules).unwrap_err();
    assert_eq!(fault.kind, FaultKind::KindMismatch { rule: 0 });

    // A group can be deleted but not replaced.
    let rules = [Rule { path: &[Segment::Field(f(3))], action: Action::Replace(Value::Varint(1)) }];
    let fault = run(&h("1B 1C"), &rules).unwrap_err();
    assert_eq!(fault.kind, FaultKind::KindMismatch { rule: 0 });
}

#[test]
fn deletion_is_kind_free_and_a_deleted_group_vanishes_whole() {
    let rules = [Rule { path: &[Segment::Field(f(3))], action: Action::Delete }];
    let (out, stats) = run(&h("1B 08 01 13 14 1C 08 05"), &rules).unwrap();
    assert_eq!(out, h("08 05"));
    assert_eq!(stats.deleted, 1, "the group counts once");
}

#[test]
fn group_frames_ride_verbatim_around_interior_edits() {
    // Route through group f3, replace f1 inside.
    let rules = [Rule {
        path: &[Segment::Field(f(3)), Segment::Field(f(1))],
        action: Action::Replace(Value::Varint(9)),
    }];
    let (out, _) = run(&h("1B 08 01 1C"), &rules).unwrap();
    assert_eq!(out, h("1B 08 09 1C"));
}

// ─── budgets ───

#[test]
fn the_depth_budget_spans_groups_and_len_crossings() {
    let one = DepthLimit::MIN;
    // One LEN crossing fits...
    let rules =
        [Rule { path: &[Segment::Field(f(1)), Segment::Field(f(1))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();
    let (out, _) = rewrite(&h("0A 02 0A 00"), &set, one).unwrap();
    assert_eq!(out, h("0A 00"));

    // ...a second one does not.
    let deep_rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(1)), Segment::Field(f(1))],
        action: Action::Delete,
    }];
    let set = RuleSet::over(&deep_rules).unwrap();
    let fault = rewrite(&h("0A 04 0A 02 0A 00"), &set, one).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::Depth));
    assert_eq!(fault.at, 2);

    // A group spends from the same account: after entering group
    // f3, no budget remains for the committed LEN.
    let mixed = [Rule {
        path: &[Segment::Field(f(3)), Segment::Field(f(1)), Segment::Field(f(5))],
        action: Action::Delete,
    }];
    let set = RuleSet::over(&mixed).unwrap();
    let fault = rewrite(&h("1B 0A 00 1C"), &set, one).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::Depth));
}

// ─── the deleted-group depth account ───

#[test]
fn a_deleted_group_spends_the_depth_account_after_a_len_crossing() {
    // LEN f1 { group f2 {} }: the crossing spends the only
    // account, so the group's enter — even a vanishing one — must
    // refuse before suppression starts.
    let input = h("0A 02 13 14");
    let rules =
        [Rule { path: &[Segment::Field(f(1)), Segment::Field(f(2))], action: Action::Delete }];
    let set = RuleSet::over(&rules).expect("test rules admit");
    let fault = rewrite(&input, &set, DepthLimit::MIN).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::Depth));
    assert_eq!(fault.at, 2);

    // One more account admits the same job: the group vanishes and
    // its interior dies with it.
    let two = DepthLimit::new(2).unwrap();
    let (out, stats) = rewrite(&input, &set, two).unwrap();
    assert_eq!(out, h("0A 00"));
    assert_eq!((stats.deleted(), stats.descended()), (1, 1));
}

#[test]
fn a_deleted_group_inside_a_group_spends_the_same_account() {
    // The group-first order: group f3 { group f2 {} } under a
    // one-deep budget — the kept outer group spends it, so the
    // targeted delete inside must refuse. The account is one,
    // whatever happens to the body.
    let input = h("1B 13 14 1C");
    let rules =
        [Rule { path: &[Segment::Field(f(3)), Segment::Field(f(2))], action: Action::Delete }];
    let set = RuleSet::over(&rules).expect("test rules admit");
    let fault = rewrite(&input, &set, DepthLimit::MIN).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::Depth));
    assert_eq!(fault.at, 1);
}

#[test]
fn nested_groups_inside_a_deleted_tree_still_spend_accounts() {
    // Deleting group f2 suppresses its body, but the body's own
    // groups still nest the reader: under a one-deep budget the
    // suppressed enter refuses; a two-deep budget deletes the tree
    // whole.
    let input = h("13 13 14 14");
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Delete }];
    let set = RuleSet::over(&rules).expect("test rules admit");
    let fault = rewrite(&input, &set, DepthLimit::MIN).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::Depth));
    assert_eq!(fault.at, 1);

    let two = DepthLimit::new(2).unwrap();
    let (out, stats) = rewrite(&input, &set, two).unwrap();
    assert_eq!(out, h(""));
    assert_eq!((stats.deleted(), stats.descended()), (1, 0));
}

#[test]
fn a_deleted_len_never_walks_so_it_spends_no_account() {
    // The discriminating twin: Delete on a LEN swallows the
    // payload opaque — no descent, no reader nesting, no charge —
    // so the budget question never arises even at the tightest
    // bound.
    let input = h("0A 02 13 14");
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();
    let (out, stats) = rewrite(&input, &set, DepthLimit::MIN).unwrap();
    assert_eq!(out, h(""));
    assert_eq!((stats.deleted(), stats.descended()), (1, 0));
}

#[test]
fn a_deleted_groups_framing_still_faces_the_canonical_judgment() {
    use crate::Standard;

    // Suppression skips matching and emission, never wire law: a
    // padded end tag inside a deleted tree refuses under the
    // canonical standard exactly as a kept one would.
    let padded_end = h("13 18 01 94 00");
    let rules = [Rule { path: &[Segment::Field(f(2))], action: Action::Delete }];
    let set = RuleSet::over(&rules).unwrap();
    let fault =
        rewrite_standard(&padded_end, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
            .unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::NonMinimal));
    assert_eq!(fault.at, 3);
    let (out, _) =
        rewrite_standard(&padded_end, &set, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    assert_eq!(out, h(""));

    // And the canonical instance repeats the tolerant depth
    // verdict: both passes of both instances derive one plan.
    let input = h("0A 02 13 14");
    let cross =
        [Rule { path: &[Segment::Field(f(1)), Segment::Field(f(2))], action: Action::Delete }];
    let set = RuleSet::over(&cross).unwrap();
    let fault =
        rewrite_standard(&input, &set, Standard::CanonicalMinimal, DepthLimit::MIN).unwrap_err();
    assert_eq!(fault.kind, FaultKind::Wire(WireBreach::Depth));
    assert_eq!(fault.at, 2);
}

// ─── faults carry the promise chain ───

#[test]
fn wire_faults_inside_commitments_carry_the_trail() {
    let rules =
        [Rule { path: &[Segment::Field(f(1)), Segment::Field(f(2))], action: Action::Delete }];
    // The committed payload starts with a field-zero tag.
    let fault = run(&h("0A 02 00 00"), &rules).unwrap_err();
    assert_eq!(fault.at, 2);
    assert_eq!(&fault.trail[..], &[Crossing::new(f(1), 0)]);
    assert!(matches!(fault.kind, FaultKind::Wire(WireBreach::Tag)));
}

#[test]
fn uncommitted_len_payloads_are_opaque_even_if_unparseable() {
    // No rule routes into f1: its garbage payload rides verbatim.
    let input = h("0A 02 00 00");
    let (out, _) = run(&input, &[]).unwrap();
    assert_eq!(out, input);
}

// ─── transactionality ───

#[test]
fn a_faulting_job_leaves_the_reuse_buffer_untouched() {
    let mut out = h("DE AD");
    let set = RuleSet::over(&[]).unwrap();
    let err = rewrite_into(&h("00"), &set, D, &mut out).unwrap_err();
    assert!(matches!(err.kind, FaultKind::Wire(_)));
    assert_eq!(out, h("DE AD"), "nothing appended on Err");

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

    // And the success path appends without touching the prefix.
    let stats = rewrite_into(&h("08 01"), &set, D, &mut out).unwrap();
    assert_eq!(out, h("DE AD 08 01"));
    assert_eq!(stats, Stats::default());
}

// ─── insertion: the grouped anchor contract ───

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
fn group_gaps_land_inside_both_framing_tags() {
    let head = ins(Gap::HeadOf, 9, 1);
    let tail = ins(Gap::TailOf, 9, 2);
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&head) },
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&tail) },
    ];
    // group f2 { varint f3=1 }: HeadOf inside the open tag, TailOf
    // before the end tag.
    let (out, stats) = run_ins(&h("13 18 01 14"), &rules).unwrap();
    assert_eq!(out, h("13 48 01 18 01 48 02 14"));
    assert_eq!(stats.inserted(), 2);

    // An empty group: the interior exists, head-inserts precede
    // tail-inserts at the coincident gap.
    let (out, stats) = run_ins(&h("13 14"), &rules).unwrap();
    assert_eq!(out, h("13 48 01 48 02 14"));
    assert_eq!(stats.inserted(), 2);
}

#[test]
fn interior_gaps_compose_with_a_normalized_group() {
    // The dialect asymmetry's grouped half: group-Normalize keeps
    // its interior with the walk, so head/tail inserts land inside
    // the minimally re-authored framing.
    let head = ins(Gap::HeadOf, 9, 1);
    let tail = ins(Gap::TailOf, 9, 2);
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&head) },
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&tail) },
        Rule { path: &[Segment::Field(f(2))], action: Action::Normalize },
    ];
    // Padded framing tags re-author minimal; the inserts ride
    // inside them.
    let (out, stats) = run_ins(&h("93 00 18 01 94 00"), &rules).unwrap();
    assert_eq!(out, h("13 48 01 18 01 48 02 14"));
    assert_eq!((stats.normalized(), stats.inserted()), (1, 2));
}

#[test]
fn a_deleted_groups_interior_gaps_die_silently() {
    let head = ins(Gap::HeadOf, 9, 1);
    let tail = ins(Gap::TailOf, 9, 2);
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&head) },
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&tail) },
        Rule { path: &[Segment::Field(f(2))], action: Action::Delete },
    ];
    // The group's whole span vanishes under suppression; its
    // interior gaps die with it — the zero count is the exposure.
    let (out, stats) = run_ins(&h("08 05 13 18 01 14 20 06"), &rules).unwrap();
    assert_eq!(out, h("08 05 20 06"));
    assert_eq!((stats.deleted(), stats.inserted()), (1, 0));
}

#[test]
fn a_len_normalizes_interior_gaps_die_silently() {
    // The dialect asymmetry's suppressing half: a LEN-Normalize
    // rides its interior verbatim — no walk, so interior gaps die
    // with it (the composing half is the group-Normalize row
    // above).
    let head = ins(Gap::HeadOf, 9, 1);
    let rules = [
        Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) },
        Rule { path: &[Segment::Field(f(1))], action: Action::Normalize },
    ];
    // LEN f1 with a padded prefix: the prefix re-authors minimal,
    // the interior rides verbatim, and the insert never fires.
    let (out, stats) = run_ins(&h("0A 82 00 08 01"), &rules).unwrap();
    assert_eq!(out, h("0A 02 08 01"));
    assert_eq!((stats.normalized(), stats.inserted()), (1, 0));
}

#[test]
fn same_gap_inserts_all_emit_in_rule_order_at_a_group_gap() {
    // The grouped runtime half of the shared admission law:
    // same-gap inserts all emit, rule-index order, identical
    // rules included — at a group's tail gap.
    let first = ins(Gap::TailOf, 9, 1);
    let second = ins(Gap::TailOf, 9, 2);
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&first) },
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&second) },
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&first) },
    ];
    let (out, stats) = run_ins(&h("13 18 2A 14"), &rules).unwrap();
    assert_eq!(out, h("13 18 2A 48 01 48 02 48 01 14"));
    assert_eq!(stats.inserted(), 3);
}

#[test]
fn inserted_records_are_inert_in_the_grouped_walk() {
    // The inserted f5 record is output-only: the Delete targeting
    // f5 catches the source occurrence inside the group, never
    // the record the tail gap authored.
    let tail = ins(Gap::TailOf, 5, 9);
    let rules = [
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&tail) },
        Rule { path: &[Segment::Field(f(2)), Segment::Field(f(5))], action: Action::Delete },
    ];
    let (out, stats) = run_ins(&h("13 28 05 18 01 14"), &rules).unwrap();
    assert_eq!(out, h("13 18 01 28 09 14"));
    assert_eq!((stats.deleted(), stats.inserted()), (1, 1));
}

#[test]
fn group_tail_inserts_cascade_into_enclosing_len_prefixes() {
    // A tail insert inside a group inside a crossed LEN: the group
    // needs no length, the LEN's prefix re-settles.
    let tail = ins(Gap::TailOf, 9, 7);
    let rules = [Rule {
        path: &[Segment::Field(f(1)), Segment::Field(f(2))],
        action: Action::Insert(&tail),
    }];
    let (out, stats) = run_ins(&h("0A 04 13 18 01 14"), &rules).unwrap();
    assert_eq!(out, h("0A 06 13 18 01 48 07 14"));
    assert_eq!((stats.inserted(), stats.descended()), (1, 1));
}

#[test]
fn len_anchors_carry_the_shared_interior_gap_mechanics() {
    let head = ins(Gap::HeadOf, 2, 7);
    let rules = [Rule { path: &[Segment::Field(f(1))], action: Action::Insert(&head) }];
    let (out, stats) = run_ins(&h("0A 02 08 01"), &rules).unwrap();
    assert_eq!(out, h("0A 04 10 07 08 01"));
    assert_eq!((stats.inserted(), stats.descended()), (1, 1));

    // A scalar occurrence still faults the commitment.
    let fault = run_ins(&h("08 01"), &rules).unwrap_err();
    assert!(matches!(fault.kind, FaultKind::KindMismatch { rule: 0 }));
}

#[test]
fn root_gaps_and_the_sink_face_agree_with_the_buffered_twin() {
    let root_head = ins(Gap::HeadOf, 5, 1);
    let tail = ins(Gap::TailOf, 9, 4);
    let rules = [
        Rule { path: &[], action: Action::Insert(&root_head) },
        Rule { path: &[Segment::Field(f(2))], action: Action::Insert(&tail) },
    ];
    let set = InsertRuleSet::over(&rules).unwrap();
    let doc = h("13 18 01 14 08 05");
    let (buffered, buffered_stats) = rewrite(&doc, &set, D).unwrap();
    assert_eq!(buffered, h("28 01 13 18 01 48 04 14 08 05"));
    let mut handed = Vec::new();
    let stats = rewrite_sink(&doc, &set, D, |bytes| handed.extend_from_slice(bytes)).unwrap();
    assert_eq!(handed, buffered);
    assert_eq!(stats, buffered_stats);
    assert_eq!(stats.inserted(), 2);
}
