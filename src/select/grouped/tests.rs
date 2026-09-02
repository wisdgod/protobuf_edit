//! Contract pins for the grouped selector: exhaustive on the
//! dialect clauses (group post-order delivery, syntax crossing,
//! pairing, the shared budget), representative on shared read
//! semantics.

use alloc::vec::Vec;

use super::*;
use crate::path::Segment;
use crate::wire::FieldNumber;

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

// ─── the dialect's own clauses ───

#[test]
fn a_selected_group_delivers_its_interior_at_the_verified_close() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3))]];
    let program = Program::over(&paths).unwrap();
    // varint f1=5 · group f3 { varint f1=1 · f2=2 } · varint f1=6
    let doc = h("08 05 1B 08 01 10 02 1C 08 06");
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].field(), f(3));
    assert_eq!(hits[0].kind(), MatchKind::Group(&h("08 01 10 02")));
    assert_eq!((hits[0].span().start(), hits[0].span().end()), (2, 8));
}

#[test]
fn interior_matches_precede_the_groups_own_delivery() {
    // The group's extent exists only at its close: interior
    // selections land first (their own order), the group's single
    // delivery follows — the post-order split against the
    // LEN pre-order.
    let group: &[Segment<'_>] = &[Segment::Field(f(3))];
    let inner: &[Segment<'_>] = &[Segment::Field(f(3)), Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 2] = [group, inner];
    let program = Program::over(&paths).unwrap();
    // group f3 { varint f1=1 }
    let doc = h("1B 08 01 1C");
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!((hits[0].path().index(), hits[0].kind()), (1, MatchKind::Varint(1)));
    assert_eq!((hits[1].path().index(), hits[1].kind()), (0, MatchKind::Group(&h("08 01"))));
}

#[test]
fn nested_selected_groups_deliver_inner_before_outer() {
    let route = [f(3)];
    let path: &[Segment<'_>] = &[Segment::AnyDepth { descend: &route }, Segment::Field(f(3))];
    let paths: [&[Segment<'_>]; 1] = [path];
    let program = Program::over(&paths).unwrap();
    // group f3 { group f3 { } } — the wildcard's ε makes the outer
    // group a target, and its self-loop targets the inner one.
    let doc = h("1B 1B 1C 1C");
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].kind(), MatchKind::Group(&[]));
    assert_eq!((hits[0].span().start(), hits[0].span().end()), (1, 3));
    assert_eq!(hits[1].kind(), MatchKind::Group(&h("1B 1C")));
    assert_eq!((hits[1].span().start(), hits[1].span().end()), (0, 4));
}

#[test]
fn multi_path_group_targets_fan_out_at_the_close() {
    let route = [f(1)];
    let exact: &[Segment<'_>] = &[Segment::Field(f(3))];
    let wild: &[Segment<'_>] = &[Segment::AnyDepth { descend: &route }, Segment::Field(f(3))];
    let paths: [&[Segment<'_>]; 2] = [exact, wild];
    let program = Program::over(&paths).unwrap();
    // group f3 { varint f1=1 }
    let doc = h("1B 08 01 1C");
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!((hits[0].path().index(), hits[1].path().index()), (0, 1));
    assert!(hits.iter().all(|hit| hit.kind() == MatchKind::Group(&h("08 01"))));
}

#[test]
fn groups_cross_by_syntax_exactly_where_the_descend_set_says() {
    // The wildcard's set {f2} carries the pattern through group
    // f2; group f8 is outside the set, so its interior is walked
    // (pairing verified) but pattern-dead.
    let route = [f(2)];
    let path: &[Segment<'_>] = &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [path];
    let program = Program::over(&paths).unwrap();
    // group f2 { varint f1=1 } · group f8 { varint f1=2 } · f1=3
    let doc = h("13 08 01 14 43 08 02 44 08 03");
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    let starts: Vec<u32> = hits.iter().map(|hit| hit.span().start()).collect();
    assert_eq!(starts, [1, 8], "inside the routed group and at top — never inside f8");
}

#[test]
fn group_pairing_faults_map_to_grouping() {
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    // group f3 closed by f4's end tag.
    let doc = h("1B 24");
    let mut hits = Matches::over(&doc, &program, D).unwrap();
    let fault = hits.next().unwrap().unwrap_err();
    assert_eq!(fault.breach(), WireBreach::Grouping);
    assert_eq!(fault.breach().class(), crate::FaultClass::Grammar);
    assert_eq!(hits.next(), None, "the first refusal fuses");
}

#[test]
fn the_depth_budget_spans_groups_and_len_crossings() {
    let one = DepthLimit::MIN;
    // Groups spend budget even under an empty program (they are
    // walked by syntax): the second nested enter overdraws.
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    let fault = Matches::over(&h("1B 1B 1C 1C"), &program, one)
        .unwrap()
        .find_map(Result::err)
        .expect("the second group enter overdraws");
    assert_eq!((fault.at(), fault.breach()), (1, WireBreach::Depth));

    // A group then a committed LEN spend from one account.
    let path: &[Segment<'_>] = &[Segment::Field(f(3)), Segment::Field(f(1)), Segment::Field(f(5))];
    let paths: [&[Segment<'_>]; 1] = [path];
    let program = Program::over(&paths).unwrap();
    let fault = Matches::over(&h("1B 0A 00 1C"), &program, one)
        .unwrap()
        .find_map(Result::err)
        .expect("the LEN crossing after the group overdraws");
    assert_eq!((fault.at(), fault.breach()), (1, WireBreach::Depth));
}

// ─── shared semantics, representative ───

#[test]
fn a_len_both_target_and_route_stays_pre_order() {
    let route = [f(3)];
    let parent: &[Segment<'_>] = &[Segment::Field(f(3))];
    let inner: &[Segment<'_>] = &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];
    // LEN f3 { varint f1=1 }
    let doc = h("1A 02 08 01");
    let paths: [&[Segment<'_>]; 2] = [parent, inner];
    let program = Program::over(&paths).unwrap();
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!((hits[0].path().index(), hits[0].kind()), (0, MatchKind::Len(&h("08 01"))));
    assert_eq!((hits[1].path().index(), hits[1].kind()), (1, MatchKind::Varint(1)));
}

#[test]
fn wire_faults_inside_commitments_carry_the_trail_and_fuse() {
    let path: &[Segment<'_>] = &[Segment::Field(f(1)), Segment::Field(f(2))];
    let paths: [&[Segment<'_>]; 1] = [path];
    let program = Program::over(&paths).unwrap();
    let doc = h("0A 02 00 00");
    let mut hits = Matches::over(&doc, &program, D).unwrap();
    let fault = hits.next().unwrap().unwrap_err();
    assert_eq!(fault.at(), 2);
    assert_eq!(fault.trail(), &[Crossing::new(f(1), 0)]);
    assert_eq!(fault.breach(), WireBreach::Tag);
    assert_eq!(hits.next(), None, "fused for good");
}

#[test]
fn group_interiors_borrow_the_input() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    // group f2 { varint f1=1 }
    let doc = h("13 08 01 14");
    let kept = {
        let mut hits = Matches::over(&doc, &program, D).unwrap();
        let kept = hits.next().unwrap().unwrap();
        drop(hits);
        kept
    };
    let MatchKind::Group(interior) = kept.kind() else {
        panic!("f2 is a group");
    };
    assert_eq!(interior, h("08 01"));
    assert!(
        core::ptr::eq(interior.as_ptr(), doc[1..].as_ptr()),
        "the interior is the input's own bytes, not a copy"
    );
}

// ─── the canonical twin ───

#[test]
fn the_canonical_selection_equals_the_tolerant_one_on_minimal_wire() {
    // A group target, a routed interior scalar, and a top LEN —
    // over minimal wire the twins deliver the same rows in the
    // same order, group post-order included.
    let route = [f(2)];
    let paths: [&[Segment<'_>]; 3] = [
        &[Segment::Field(f(2))],
        &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
        &[Segment::Field(f(4))],
    ];
    let program = Program::over(&paths).unwrap();
    // varint f1 · group f2 { varint f1 } · LEN f4 "a"
    let doc = h("08 01 13 08 07 14 22 01 61");
    let tolerant: Vec<_> =
        Matches::over(&doc, &program, D).unwrap().map(|hit| hit.expect("lawful wire")).collect();
    let canonical: Vec<_> = CanonicalMatches::over(&doc, &program, D)
        .unwrap()
        .map(|hit| hit.expect("minimal wire"))
        .collect();
    assert_eq!(tolerant, canonical);
    assert!(tolerant.len() >= 3, "the walk really delivered");
}

#[test]
fn the_canonical_selection_refuses_a_padded_end_tag_as_width() {
    // group f1 with its end tag padded: the tolerant walk closes
    // the pair, the canonical twin refuses the width at the end
    // tag's head.
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    let doc = h("0B 8C 80 00");
    let survived = Matches::over(&doc, &program, D)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .expect("the tolerant walk accepts the padded end tag");
    assert!(survived.is_empty(), "nothing is targeted");

    let mut hits = CanonicalMatches::over(&doc, &program, D).unwrap();
    let fault = hits.next().unwrap().unwrap_err();
    assert_eq!(fault.at(), 1, "the end tag's head");
    assert_eq!(fault.breach(), WireBreach::NonMinimal);
    assert_eq!(hits.next(), None, "the first refusal fuses");
}
