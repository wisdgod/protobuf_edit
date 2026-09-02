//! Contract pins: each test states one clause of the machine's
//! contract. The dialect-orthogonal semantics (speculation,
//! barriers, depth, supply) are pinned representatively — their
//! full matrices live with the `full` dialect; this dialect's own
//! clauses (the capability refusal, the groupless vocabulary) are
//! pinned exhaustively. Corpus alignment belongs to the shared
//! harness, a separate deliverable.

use alloc::vec::Vec;

use super::*;
use crate::inspect::NoAdvice;

#[track_caller]
fn fnum(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

#[track_caller]
fn nid(n: u32) -> NodeId {
    NodeId::new(n).expect("test node id in class")
}

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
fn parse(data: &[u8]) -> Tree<'_> {
    Tree::parse(Admitted::new(data).expect("test input admitted"), D, &mut NoAdvice)
}

#[track_caller]
fn parse_with<'a, A: Advisor>(data: &'a [u8], advice: &mut A) -> Tree<'a> {
    Tree::parse(Admitted::new(data).expect("test input admitted"), D, advice)
}

const D: DepthLimit = DepthLimit::REFERENCE;

struct ByField(&'static [(u32, Advice)]);
impl Advisor for ByField {
    fn advise(&mut self, _ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
        self.0.iter().find(|(n, _)| *n == field.as_inner()).map_or(Advice::Speculate, |(_, a)| *a)
    }
}

// ─── the capability refusal (this dialect's own law) ───

#[test]
fn a_group_open_is_refused_as_outside_the_language() {
    let data = h("0B"); // field 1, code 3
    let x = parse(&data);
    let fault = x.fault().expect("group code refused");
    assert_eq!(fault.kind, FaultKind::GroupCode { field: fnum(1), code: Low3::new(3).unwrap() });
    assert_eq!(fault.at(), 0);
}

#[test]
fn a_group_end_is_refused_the_same_way() {
    let data = h("0C"); // field 1, code 4
    let x = parse(&data);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::GroupCode { field: fnum(1), code: Low3::new(4).unwrap() })
    );
}

// ─── the canonical engine ───

#[test]
fn a_canonical_parse_equals_the_tolerant_one_on_minimal_wire() {
    // varint · I32 · LEN {varint} · I64: minimal widths — the
    // engine instances must produce identical geometry.
    let data = h("08 9601 15 01020304 12 02 0807 19 0102030405060708");
    let tolerant = parse(&data);
    let canonical =
        Tree::parse_standard(Admitted::new(&data).unwrap(), Standard::CanonicalMinimal, D, &mut {
            NoAdvice
        });
    assert!(tolerant.is_complete() && canonical.is_complete());
    assert_eq!(tolerant.node_count(), canonical.node_count());
    for id in tolerant.nodes() {
        assert_eq!(tolerant.span(id), canonical.span(id));
        assert_eq!(tolerant.field(id), canonical.field(id));
        assert_eq!(tolerant.kind(id), canonical.kind(id));
    }
}

#[test]
fn a_canonical_parse_refuses_padding_in_the_committed_zone() {
    // A padded value at top level: the committed zone's own law.
    let data = h("08 96 81 00");
    let x = Tree::parse_standard(
        Admitted::new(&data).unwrap(),
        Standard::CanonicalMinimal,
        D,
        &mut NoAdvice,
    );
    let fault = x.fault().expect("padding refused");
    assert_eq!((fault.at(), fault.kind()), (1, FaultKind::NonMinimalValue { field: fnum(1) }));
    assert_eq!(fault.kind().class(), FaultClass::Policy);
    // A padded tag: width ahead of field zero and classification.
    let data = h("80 00");
    let x = Tree::parse_standard(
        Admitted::new(&data).unwrap(),
        Standard::CanonicalMinimal,
        D,
        &mut NoAdvice,
    );
    assert_eq!(x.fault().map(|f| (f.at(), f.kind())), Some((0, FaultKind::NonMinimalTag)));
}

#[test]
fn speculation_absorbs_padding_and_commitment_faults_it() {
    // LEN f2 whose payload parses tolerantly but carries a padded
    // word: a canonical speculation concludes "bytes" (complete
    // tree, leaf payload); a canonical commitment faults it.
    let data = h("12 04 08 96 81 00");
    let speculated = Tree::parse_standard(
        Admitted::new(&data).unwrap(),
        Standard::CanonicalMinimal,
        D,
        &mut NoAdvice,
    );
    assert!(speculated.is_complete(), "speculation absorbs the width fault");
    let root = speculated.top().next().unwrap();
    assert_eq!(speculated.children(root).count(), 0, "the payload concluded as bytes");

    let committed = Tree::parse_standard(
        Admitted::new(&data).unwrap(),
        Standard::CanonicalMinimal,
        D,
        &mut ByField(&[(2, Advice::Commit)]),
    );
    let fault = committed.fault().expect("commitment owns the width fault");
    assert_eq!((fault.at(), fault.kind()), (3, FaultKind::NonMinimalValue { field: fnum(1) }));

    // The same speculation under Tolerant descends: the padded
    // word is lawful there — the engines really differ.
    let tolerant = parse(&data);
    let root = tolerant.top().next().unwrap();
    assert_eq!(tolerant.children(root).count(), 1, "tolerant speculation descends");
}

#[test]
fn a_group_inside_speculation_concludes_bytes_not_fault() {
    // A proto2 submessage (group) embedded in an Unknown LEN: the
    // pure-proto3 inspector presents the payload as bytes — mixed
    // traffic is not a document fault.
    let data = h("0A04 0B08010C");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.node_count(), 1);
    assert_eq!(x.children(nid(0)).count(), 0);
}

#[test]
fn a_group_inside_a_committed_message_is_a_real_fault() {
    let data = h("0A04 0B08010C");
    let mut advice = ByField(&[(1, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    let fault = x.fault().expect("committed capability refusal");
    assert_eq!(fault.kind, FaultKind::GroupCode { field: fnum(1), code: Low3::new(3).unwrap() });
    assert_eq!(fault.at(), 2);
}

#[test]
fn field_zero_precedes_the_group_code_judgment() {
    // field 0 with group code 3: identity judges first, and the
    // fault quotes the code it carried.
    let data = h("03");
    let x = parse(&data);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::FieldZero { code: Low3::new(3).unwrap() })
    );
}

// ─── topology (representative) ───

#[test]
fn preorder_contiguity_and_links() {
    // varint f1 · LEN f3 wrapping (varint f1) · I32 f2
    let data = h("089601 1A03089601 1501000000");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.node_count(), 4);
    assert_eq!(x.top().collect::<Vec<_>>(), [nid(0), nid(1), nid(3)]);
    assert_eq!(x.children(nid(1)).collect::<Vec<_>>(), [nid(2)]);
    assert_eq!(x.parent(nid(2)), Some(nid(1)));
    assert_eq!(x.ancestors(nid(2)).collect::<Vec<_>>(), [nid(1)]);
    assert_eq!(x.kind(nid(3)), RecordKind::I32);
}

#[test]
fn empty_input_is_the_empty_message() {
    let x = parse(&[]);
    assert_eq!(x.fault(), None);
    assert!(x.is_empty());
}

// ─── speculation and barriers (representative) ───

#[test]
fn len_payload_that_fails_becomes_a_blob_leaf() {
    let data = h("0A05 68656C6C6F"); // "hello"
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.payload_bytes(nid(0)), b"hello");
}

#[test]
fn a_conditional_promise_evaporates_with_its_speculating_ancestor() {
    // Unknown f1 { Message f2 { bad } varint }: the fault inside
    // the conditional promise unwinds the speculating ancestor.
    let data = h("0A05 1201FF 0801");
    let mut advice = ByField(&[(2, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    assert_eq!(x.fault(), None);
    assert_eq!(x.node_count(), 1);
}

#[test]
fn a_committed_chain_stops_at_the_inner_speculations_boundary() {
    let data = h("0A05 1201FF 0801");
    let mut advice = ByField(&[(1, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    assert_eq!(x.fault(), None);
    assert_eq!(x.children(nid(0)).count(), 2);
    assert_eq!(x.children(nid(1)).count(), 0); // demoted leaf
}

// ─── depth (representative; empty LEN still declares nesting) ───

#[test]
fn empty_len_still_declares_nesting_under_message_advice() {
    let data = h("0A02 1A00");
    let mut advice = ByField(&[(1, Advice::Commit), (3, Advice::Commit)]);
    let x = Tree::parse(Admitted::new(&data).unwrap(), DepthLimit::MIN, &mut advice);
    let fault = x.fault().expect("empty message still nests");
    assert_eq!(fault.kind, FaultKind::DepthExceeded { field: fnum(3), limit: DepthLimit::MIN });
}

#[test]
fn depth_limit_demotes_speculative_descent_to_blobs() {
    let data = h("1A05 1A03089601");
    let x = Tree::parse(Admitted::new(&data).unwrap(), DepthLimit::MIN, &mut NoAdvice);
    assert_eq!(x.fault(), None);
    assert_eq!(x.children(nid(1)).count(), 0);
}

// ─── widths, windows, seals (representative) ───

#[test]
fn nonminimal_widths_are_stored_facts() {
    let data = h("8800 968100");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.varint_word(nid(0)), Some(150));
    assert_eq!(
        x.source_spans(nid(0)),
        RecordSpans::Varint { tag: Span::new(0, 2), value: Span::new(2, 5) }
    );
    assert_eq!(x.span(nid(0)), Span::new(0, 5));
}

#[test]
fn len_overrun_quotes_declared_and_zone_left() {
    let data = h("0A05 0801");
    let x = parse(&data);
    let declared = PayloadLen::new(5).unwrap();
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::LenOverrun { field: fnum(1), declared, zone_left: 2 })
    );
}

#[test]
fn value_terminal_beyond_u64_is_refused() {
    let data = h("08 808080808080808080 02");
    let x = parse(&data);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::Read {
            stage: Stage::Value { field: fnum(1) },
            cause: ReadFault::OutOfClass
        })
    );
}

#[test]
fn the_cut_never_swallows_the_bad_records_tag() {
    // Message f3 { varint f1 with truncated value }: diagnostic at
    // the value start, clip at the record start.
    let data = h("1A01 08");
    let mut advice = ByField(&[(3, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    let fault = x.fault().expect("cut varint value");
    assert_eq!(
        fault.kind,
        FaultKind::Read { stage: Stage::Value { field: fnum(1) }, cause: ReadFault::Truncated }
    );
    assert_eq!(fault.at(), 3);
    assert_eq!(x.indexed_end(), 2);
    // The clipped LEN keeps its declared, sealed span.
    assert_eq!(x.span(nid(0)), Span::new(0, 3));
}

// ─── queries (representative) ───

#[test]
fn narrowest_descends_to_the_tightest_record() {
    let data = h("1A06 0801 12026162");
    let x = parse(&data);
    assert_eq!(x.narrowest(0), Some(nid(0)));
    assert_eq!(x.narrowest(2), Some(nid(1)));
    assert_eq!(x.narrowest(7), Some(nid(2)));
    assert_eq!(x.narrowest(8), None);
}

#[test]
fn fixed_payload_bits_read_little_endian() {
    let data = h("0D 01000000 09 0200000000000000");
    let x = parse(&data);
    assert_eq!(x.i32_bits(nid(0)), Some(1));
    assert_eq!(x.i64_bits(nid(1)), Some(2));
    assert_eq!(x.i32_bits(nid(1)), None); // kind-gated
}

#[test]
#[should_panic = "index out of bounds"]
fn node_ids_are_indices_and_forged_ids_panic() {
    let x = parse(&[]);
    let _ = x.field(nid(0));
}

#[test]
fn by_field_narrows_in_wire_order() {
    // f1 · f2 · f1
    let data = h("0801 1002 0803");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    let ones: Vec<NodeId> = x.top().by_field(fnum(1)).collect();
    assert_eq!(ones, [nid(0), nid(2)]);
    assert_eq!(x.top().by_field(fnum(3)).count(), 0);
}

// ─── geometry partition law ───

#[test]
fn source_spans_partition_every_node() {
    let data = h("089601 15AABBCCDD 19AABBCCDD11223344 12026869");
    let x = parse(&data);
    for id in x.nodes() {
        let span = x.span(id);
        match x.source_spans(id) {
            RecordSpans::Varint { tag, value }
            | RecordSpans::I32 { tag, value }
            | RecordSpans::I64 { tag, value } => {
                assert_eq!(tag.start(), span.start());
                assert_eq!(tag.end(), value.start());
                assert_eq!(value.end(), span.end());
            }
            RecordSpans::Len { tag, prefix, payload } => {
                assert_eq!(tag.start(), span.start());
                assert_eq!(tag.end(), prefix.start());
                assert_eq!(prefix.end(), payload.start());
                assert_eq!(payload.end(), span.end());
            }
        }
    }
}
