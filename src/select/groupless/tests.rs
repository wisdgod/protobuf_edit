//! Contract pins for the groupless selector: exhaustive on the
//! read-fold clauses (fan-out, pre-order, opacity, the stalled
//! depth refusal), representative on shared wire judgment.

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

/// Runs one selection to completion, panicking on any fault.
#[track_caller]
fn run(input: &[u8], paths: &[&[Segment<'_>]]) -> Vec<(u32, u32, u32)> {
    let program = Program::over(paths).expect("test paths admit");
    Matches::over(input, &program, D)
        .expect("test input admits")
        .map(|hit| {
            let hit = hit.expect("test input is lawful");
            (hit.path().index(), hit.span().start(), hit.span().end())
        })
        .collect()
}

// ─── the dialect's own clauses ───

#[test]
fn group_codes_fault_as_the_inherited_capability_refusal() {
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    let doc = h("0B");
    let mut hits = Matches::over(&doc, &program, D).unwrap();
    let fault = hits.next().unwrap().unwrap_err();
    assert_eq!(fault.breach(), WireBreach::GroupCode);
    assert_eq!(fault.breach().class(), crate::FaultClass::Capability);
    assert_eq!(hits.next(), None, "the first refusal fuses");

    // Inside a commitment too, with the trail.
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1)), Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    let doc = h("0A 01 0C");
    let fault = Matches::over(&doc, &program, D)
        .unwrap()
        .find_map(Result::err)
        .expect("the committed interior faults");
    assert_eq!(fault.at(), 2);
    assert_eq!(fault.trail(), &[Crossing::new(f(1), 0)]);
    assert_eq!(fault.breach(), WireBreach::GroupCode);
}

// ─── read semantics ───

#[test]
fn multi_hit_fan_out_delivers_every_path_ascending() {
    // Two paths converge on one record — the write fold's Conflict
    // shape — and both deliver, ascending by path id, one record
    // pull feeding both.
    let route = [f(1)];
    let exact: &[Segment<'_>] = &[Segment::Field(f(7))];
    let wild: &[Segment<'_>] = &[Segment::AnyDepth { descend: &route }, Segment::Field(f(7))];
    // varint f7=1 · varint f2=2
    let doc = h("38 01 10 02");
    assert_eq!(run(&doc, &[exact, wild]), [(0, 0, 2), (1, 0, 2)]);
    // The same two paths in the other authoring order: ids follow
    // authoring, not spelling shape.
    assert_eq!(run(&doc, &[wild, exact]), [(0, 0, 2), (1, 0, 2)]);
}

#[test]
fn a_len_both_target_and_route_delivers_payload_then_interior() {
    // Path 0 selects f3 itself; path 1 routes through it. The LEN
    // match lands first (pre-order), its interior's afterwards.
    let route = [f(3)];
    let parent: &[Segment<'_>] = &[Segment::Field(f(3))];
    let inner: &[Segment<'_>] = &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];
    // LEN f3 { varint f1=1 } · varint f1=42
    let doc = h("1A 02 08 01 08 2A");
    let paths: [&[Segment<'_>]; 2] = [parent, inner];
    let program = Program::over(&paths).unwrap();
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 3);
    assert_eq!((hits[0].path().index(), hits[0].kind()), (0, MatchKind::Len(&h("08 01"))));
    assert_eq!((hits[1].path().index(), hits[1].span().start()), (1, 2));
    assert_eq!(hits[1].kind(), MatchKind::Varint(1));
    assert_eq!((hits[2].path().index(), hits[2].span().start()), (1, 4));
}

#[test]
fn an_empty_program_still_judges_the_top_layer() {
    let none: [&[Segment<'_>]; 0] = [];
    let program = Program::over(&none).unwrap();
    // Lawful wire: no matches, clean end.
    let doc = h("08 01 12 02 68 69");
    assert_eq!(Matches::over(&doc, &program, D).unwrap().count(), 0);
    // Unlawful wire still faults: selection is a read of the
    // document, not a grep over bytes.
    let doc = h("00");
    let mut hits = Matches::over(&doc, &program, D).unwrap();
    assert_eq!(hits.next().unwrap().unwrap_err().breach(), WireBreach::Tag);
}

#[test]
fn converging_wildcard_states_deliver_once_per_record() {
    // Stacked wildcards sharing member f1: two live states reach
    // one terminal — each matching record delivers exactly once.
    let outer = [f(1), f(2)];
    let inner = [f(1), f(3)];
    let path: &[Segment<'_>] = &[
        Segment::AnyDepth { descend: &outer },
        Segment::AnyDepth { descend: &inner },
        Segment::Field(f(4)),
    ];
    // f1{ f1{ f4=1 } · f4=2 } · f4 — every f4 record hits once.
    let doc = h("0A 06 0A 02 20 01 20 02 25 00 00 00 00");
    let paths: [&[Segment<'_>]; 1] = [path];
    let program = Program::over(&paths).unwrap();
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 3);
    assert!(hits.iter().all(|hit| hit.path().index() == 0));
    assert_eq!(hits[0].span().start(), 4);
    assert_eq!(hits[1].span().start(), 6);
    assert_eq!(hits[2].span().start(), 8);
}

#[test]
fn scalar_kinds_carry_the_records_own_observation() {
    let paths: [&[Segment<'_>]; 3] =
        [&[Segment::Field(f(1))], &[Segment::Field(f(2))], &[Segment::Field(f(3))]];
    // varint f1=150 · I32 f2 · I64 f3
    let doc = h("08 9601 15 01000000 19 0200000000000000");
    let program = Program::over(&paths).unwrap();
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 3);
    assert_eq!((hits[0].field(), hits[0].kind()), (f(1), MatchKind::Varint(150)));
    assert_eq!((hits[1].field(), hits[1].kind()), (f(2), MatchKind::I32(1)));
    assert_eq!((hits[2].field(), hits[2].kind()), (f(3), MatchKind::I64(2)));
    assert_eq!((hits[0].span().start(), hits[0].span().end()), (0, 3));
    assert_eq!((hits[1].span().start(), hits[1].span().end()), (3, 8));
    assert_eq!((hits[2].span().start(), hits[2].span().end()), (8, 17));
}

#[test]
fn uncommitted_len_payloads_stay_opaque_even_if_unparseable() {
    // A selected LEN that no path routes through delivers its
    // bytes and is never entered: garbage inside is the payload's
    // own business.
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1))]];
    let program = Program::over(&paths).unwrap();
    let doc = h("0A 01 FF");
    let hits: Vec<_> = Matches::over(&doc, &program, D).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind(), MatchKind::Len(&[0xFF]));

    // Unselected and unrouted: it passes silently.
    let doc = h("12 01 FF");
    assert_eq!(Matches::over(&doc, &program, D).unwrap().count(), 0);
}

#[test]
fn the_depth_budget_gates_len_recursion() {
    let one = DepthLimit::MIN;
    let deep: &[Segment<'_>] = &[Segment::Field(f(1)), Segment::Field(f(1)), Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [deep];
    let program = Program::over(&paths).unwrap();
    let fault = Matches::over(&h("0A 04 0A 02 0A 00"), &program, one)
        .unwrap()
        .find_map(Result::err)
        .expect("the second crossing overdraws the budget");
    assert_eq!(fault.at(), 2);
    assert_eq!(fault.breach(), WireBreach::Depth);
    assert_eq!(fault.breach().class(), crate::FaultClass::Policy);
}

#[test]
fn a_selected_len_at_the_depth_wall_delivers_then_refuses() {
    // The wildcard both selects f1 and routes through it: at the
    // budget wall the selection still delivers (pre-order), and
    // the crossing refusal follows, fusing the iterator.
    let route = [f(1)];
    let path: &[Segment<'_>] = &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];
    let paths: [&[Segment<'_>]; 1] = [path];
    let program = Program::over(&paths).unwrap();
    let doc = h("0A 04 0A 02 08 01");
    let mut hits = Matches::over(&doc, &program, DepthLimit::MIN).unwrap();
    let outer = hits.next().unwrap().unwrap();
    assert_eq!((outer.span().start(), outer.kind()), (0, MatchKind::Len(&h("0A 02 08 01"))));
    let inner = hits.next().unwrap().unwrap();
    assert_eq!((inner.span().start(), inner.kind()), (2, MatchKind::Len(&h("08 01"))));
    let fault = hits.next().unwrap().unwrap_err();
    assert_eq!((fault.at(), fault.breach()), (2, WireBreach::Depth));
    assert_eq!(fault.trail(), &[Crossing::new(f(1), 0)]);
    assert_eq!(hits.next(), None, "the refusal fuses the iterator");
}

#[test]
fn wire_faults_inside_commitments_carry_the_trail_and_fuse() {
    let path: &[Segment<'_>] = &[Segment::Field(f(1)), Segment::Field(f(2))];
    let paths: [&[Segment<'_>]; 1] = [path];
    let program = Program::over(&paths).unwrap();
    // The committed payload starts with a field-zero tag.
    let doc = h("0A 02 00 00");
    let mut hits = Matches::over(&doc, &program, D).unwrap();
    let fault = hits.next().unwrap().unwrap_err();
    assert_eq!(fault.at(), 2);
    assert_eq!(fault.trail(), &[Crossing::new(f(1), 0)]);
    assert_eq!(fault.breach(), WireBreach::Tag);
    assert_eq!(hits.next(), None);
    assert_eq!(hits.next(), None, "fused for good");
}

// ─── the canonical twin ───

#[test]
fn the_canonical_selection_equals_the_tolerant_one_on_minimal_wire() {
    // The oracle-shaped walk: a wildcard leg, an exact two-hop, a
    // top LEN target — over minimal wire the twins deliver the
    // same rows in the same order.
    let route = [f(3)];
    let paths: [&[Segment<'_>]; 3] = [
        &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))],
        &[Segment::Field(f(3)), Segment::Field(f(2))],
        &[Segment::Field(f(4))],
    ];
    let program = Program::over(&paths).unwrap();
    // varint f1 · LEN f3 { varint f1 · varint f2 } · LEN f4 "a"
    let doc = h("08 01 1A 04 08 07 10 2A 22 01 61");
    let tolerant: Vec<_> =
        Matches::over(&doc, &program, D).unwrap().map(|hit| hit.expect("lawful wire")).collect();
    let canonical: Vec<_> = CanonicalMatches::over(&doc, &program, D)
        .unwrap()
        .map(|hit| hit.expect("minimal wire"))
        .collect();
    assert_eq!(tolerant, canonical);
    assert!(tolerant.len() >= 4, "the walk really fanned out");
}

#[test]
fn the_canonical_selection_refuses_padding_inside_committed_layers() {
    // The padded word sits inside a committed LEN: the tolerant
    // walk delivers it, the canonical twin refuses at the value's
    // first byte with the crossing trail.
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(3)), Segment::Field(f(1))]];
    let program = Program::over(&paths).unwrap();
    // LEN f3 { varint f1 = 150 padded to three bytes }
    let doc = h("1A 04 08 96 81 00");
    let rows = Matches::over(&doc, &program, D)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .expect("the tolerant walk accepts padding");
    assert_eq!(rows.len(), 1);

    let mut hits = CanonicalMatches::over(&doc, &program, D).unwrap();
    let fault = hits.next().unwrap().unwrap_err();
    assert_eq!(fault.at(), 3, "the value construct's first byte");
    assert_eq!(fault.breach(), WireBreach::NonMinimal);
    assert_eq!(fault.breach().class(), crate::FaultClass::Policy);
    assert_eq!(fault.trail(), &[Crossing::new(f(3), 0)]);
    assert_eq!(hits.next(), None, "the first refusal fuses");
}

#[test]
fn matches_borrow_the_input_and_outlive_the_iterator() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    // varint f1=150 · LEN f2 "hi"
    let doc = h("08 9601 12 02 6869");
    let kept = {
        let mut hits = Matches::over(&doc, &program, D).unwrap();
        let kept = hits.next().unwrap().unwrap();
        // Dropping the iterator is the early stop; the match
        // borrows the input, not the machine.
        drop(hits);
        kept
    };
    let MatchKind::Len(payload) = kept.kind() else {
        panic!("f2 is a LEN record");
    };
    assert_eq!(payload, b"hi");
    assert!(
        core::ptr::eq(payload.as_ptr(), doc[5..].as_ptr()),
        "the payload is the input's own bytes, not a copy"
    );
}
