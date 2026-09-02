//! Contract pins: each test states one clause of the machine's
//! contract. Alignment against the reference corpus belongs to the
//! shared harness, a separate deliverable.

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

/// Advice by field number, path-blind (tests that need paths build
/// their own advisor).
struct ByField(&'static [(u32, Advice)]);
impl Advisor for ByField {
    fn advise(&mut self, _ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
        self.0.iter().find(|(n, _)| *n == field.as_inner()).map_or(Advice::Speculate, |(_, a)| *a)
    }
}

// ─── admission ───

#[test]
fn admission_is_the_constructors_judgment() {
    assert!(Admitted::new(&[]).is_some());
    let a = Admitted::new(b"xyz").unwrap();
    assert_eq!((a.len(), a.is_empty()), (3, false));
    // The refusing branch needs a >2 GiB allocation; the bound
    // itself is pinned by the constructor's comparison constant.
}

// ─── topology ───

#[test]
fn preorder_contiguity_and_links() {
    // varint f1 · LEN f3 wrapping (varint f1) · empty group f1
    let data = h("089601 1A03089601 0B0C");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert!(x.is_complete());
    assert_eq!(x.node_count(), 4);
    let roots: Vec<NodeId> = x.top().collect();
    assert_eq!(roots, [nid(0), nid(1), nid(3)]);
    assert_eq!(x.children(nid(1)).collect::<Vec<_>>(), [nid(2)]);
    assert_eq!(x.parent(nid(2)), Some(nid(1)));
    assert_eq!(x.parent(nid(0)), None);
    assert_eq!(x.kind(nid(3)), RecordKind::Group);
    assert_eq!(x.children(nid(3)).count(), 0);
    assert_eq!(x.indexed_end(), data.len() as u32);
}

#[test]
fn empty_input_is_the_empty_message() {
    let x = parse(&[]);
    assert_eq!(x.fault(), None);
    assert!(x.is_empty());
    assert_eq!(x.top().count(), 0);
}

#[test]
fn nodes_and_descendants_are_preorder_ranges() {
    // LEN f3 { varint · LEN f2 { varint } } · varint
    let data = h("1A06 0801 12020802 0803");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.nodes().collect::<Vec<_>>(), [nid(0), nid(1), nid(2), nid(3), nid(4)]);
    assert_eq!(x.descendants(nid(0)).collect::<Vec<_>>(), [nid(1), nid(2), nid(3)]);
    assert_eq!(x.descendants(nid(0)).len(), 3); // ExactSize
    assert_eq!(x.nodes().next_back(), Some(nid(4))); // DoubleEnded
}

#[test]
fn ancestors_walk_nearest_first() {
    let data = h("1A04 12020801");
    let x = parse(&data);
    assert_eq!(x.ancestors(nid(2)).collect::<Vec<_>>(), [nid(1), nid(0)]);
    assert_eq!(x.ancestors(nid(0)).count(), 0);
}

// ─── speculation and barriers ───

#[test]
fn len_payload_that_parses_becomes_children() {
    let data = h("1A03 089601");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.children(nid(0)).count(), 1);
}

#[test]
fn len_payload_that_fails_becomes_a_blob_leaf() {
    // "hello" — 0x68 is a tag whose value bytes overrun the extent.
    let data = h("0A05 68656C6C6F");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.node_count(), 1);
    assert_eq!(x.children(nid(0)).count(), 0);
    assert_eq!(x.payload_bytes(nid(0)), b"hello");
}

#[test]
fn speculation_failure_unwinds_only_the_innermost_speculation() {
    // outer LEN: varint f1 · inner LEN f2 whose payload is garbage
    let data = h("0A06 0801 1202FFFF");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.children(nid(0)).collect::<Vec<_>>(), [nid(1), nid(2)]);
    assert_eq!(x.children(nid(2)).count(), 0); // inner: blob
}

#[test]
fn open_group_inside_speculation_unwinds_to_blob() {
    // payload: SGROUP f1 then a truncated record — never terminated
    let data = h("0A02 0B08");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.node_count(), 1);
}

#[test]
fn a_conditional_promise_evaporates_with_its_speculating_ancestor() {
    // Unknown f1 { Message f2 { bad } varint }: the Message promise
    // sits under a speculating ancestor, so its internal fault
    // unwinds the ancestor — the whole f1 payload concludes "bytes"
    // and the document has no fault (the ancestor may itself be
    // bytes; stopping would forge a fault the reference reader
    // never reports).
    let data = h("0A05 1201FF 0801");
    let mut advice = ByField(&[(2, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    assert_eq!(x.fault(), None);
    assert_eq!(x.node_count(), 1);
    assert_eq!(x.children(nid(0)).count(), 0);
}

#[test]
fn a_committed_chain_stops_at_the_inner_speculations_boundary() {
    // Message f1 { Unknown f2 { bad } varint }: the inner
    // speculation absorbs its own fault (f2 demotes to bytes); the
    // committed f1 keeps parsing and completes.
    let data = h("0A05 1201FF 0801");
    let mut advice = ByField(&[(1, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    assert_eq!(x.fault(), None);
    assert_eq!(x.children(nid(0)).count(), 2);
    assert_eq!(x.children(nid(1)).count(), 0); // demoted leaf
}

#[test]
fn a_root_committed_message_fault_is_real() {
    // Message f1 { tag truncated }: committed from the root.
    let data = h("0A01 FF");
    let mut advice = ByField(&[(1, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    let fault = x.fault().expect("committed zone fault");
    assert_eq!(fault.kind, FaultKind::Read { stage: Stage::Tag, cause: ReadFault::Truncated });
    assert_eq!(fault.at(), 2);
}

#[test]
fn judgments_are_blind_to_commitment() {
    // The same bad bytes fault identically at root level and inside
    // a committed Message (advice moves where faults surface, never
    // how bytes are judged) — at shifts by the enclosure prefix.
    let bad = h("08 808080808080808080 02"); // value out of class
    let root = parse(&bad);
    let root_fault = root.fault().expect("root fault");

    let mut wrapped = h("0A0B");
    wrapped.extend_from_slice(&bad);
    let mut advice = ByField(&[(1, Advice::Commit)]);
    let inner = parse_with(&wrapped, &mut advice);
    let inner_fault = inner.fault().expect("committed fault");
    assert_eq!(root_fault.kind, inner_fault.kind);
    assert_eq!(inner_fault.at(), root_fault.at() + 2);
}

// ─── advice (partial schema supply) ───

#[test]
fn opaque_advice_suppresses_descent_into_a_parseable_payload() {
    let data = h("1A03 089601");
    let mut advice = ByField(&[(3, Advice::Opaque)]);
    let x = parse_with(&data, &mut advice);
    assert_eq!(x.fault(), None);
    assert_eq!(x.node_count(), 1);
}

#[test]
fn message_advice_commits_the_zone_so_its_fault_is_real() {
    // payload: a tag with its value cut by the sealed extent
    let data = h("1A01 08");
    let mut advice = ByField(&[(3, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    let fault = x.fault().expect("committed zone fault");
    assert_eq!(
        fault.kind,
        FaultKind::Read { stage: Stage::Value { field: fnum(1) }, cause: ReadFault::Truncated }
    );
    assert_eq!(fault.at(), 3);
    assert_eq!(x.node_count(), 1); // the LEN row survives, clipped
}

#[test]
fn advisors_receive_the_enclosing_field_path() {
    // f2 is opaque only directly under f3; the same f2 at root
    // still speculates.
    struct Under3;
    impl Advisor for Under3 {
        fn advise(&mut self, ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
            if field == FieldNumber::new(2).unwrap()
                && ancestry.fields().eq([FieldNumber::new(3).unwrap()])
            {
                Advice::Opaque
            } else {
                Advice::Speculate
            }
        }
    }
    // LEN f3 { LEN f2 { varint f1 } } · LEN f2 { varint f1 }
    let data = h("1A04 12020801 12020801");
    let x = parse_with(&data, &mut Under3);
    assert_eq!(x.fault(), None);
    assert_eq!(x.top().collect::<Vec<_>>(), [nid(0), nid(2)]);
    assert_eq!(x.children(nid(1)).count(), 0); // nested f2: opaque
    assert_eq!(x.children(nid(2)).count(), 1); // root f2: parsed
}

#[test]
fn empty_len_still_declares_nesting_under_message_advice() {
    // An empty Message payload is one nesting level: at the bound
    // it is refused (the reference reader counts entering an empty
    // submessage all the same).
    let data = h("0A02 1A00");
    let mut advice = ByField(&[(1, Advice::Commit), (3, Advice::Commit)]);
    let x = Tree::parse(Admitted::new(&data).unwrap(), DepthLimit::MIN, &mut advice);
    let fault = x.fault().expect("empty message still nests");
    assert_eq!(fault.kind, FaultKind::DepthExceeded { field: fnum(3), limit: DepthLimit::MIN });
    assert_eq!(fault.at(), 2);
}

#[test]
fn empty_len_under_unknown_advice_demotes_quietly_at_the_bound() {
    let data = h("0A02 1A00");
    let x = Tree::parse(Admitted::new(&data).unwrap(), DepthLimit::MIN, &mut NoAdvice);
    assert_eq!(x.fault(), None);
    assert_eq!(x.node_count(), 2);
    assert_eq!(x.children(nid(0)).count(), 1);
    assert_eq!(x.children(nid(1)).count(), 0); // demoted at the bound
}

// ─── width tolerance (in-class padding is an input fact) ───

#[test]
fn nonminimal_tag_and_value_widths_are_stored_facts() {
    // tag f1 in two bytes, 150 in three bytes
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
fn nonminimal_len_prefix_spans_are_exact() {
    let data = h("0A 8580808000 68656C6C6F");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(
        x.source_spans(nid(0)),
        RecordSpans::Len {
            tag: Span::new(0, 1),
            prefix: Span::new(1, 6),
            payload: Span::new(6, 11),
        }
    );
}

// ─── the canonical engine ───

#[test]
fn a_canonical_parse_walks_minimal_groups_and_refuses_padded_framing() {
    // Minimal group pair: both engine instances agree on geometry.
    let data = h("0B 10 9601 0C");
    let tolerant = parse(&data);
    let canonical = Tree::parse_standard(
        Admitted::new(&data).unwrap(),
        Standard::CanonicalMinimal,
        D,
        &mut NoAdvice,
    );
    assert!(tolerant.is_complete() && canonical.is_complete());
    assert_eq!(tolerant.node_count(), canonical.node_count());
    for id in tolerant.nodes() {
        assert_eq!(tolerant.span(id), canonical.span(id));
        assert_eq!(tolerant.kind(id), canonical.kind(id));
    }

    // The same pair with a padded end tag: tolerant stores the
    // width as a fact, canonical refuses it at the end tag's head.
    let padded_end = h("0B 10 9601 8C 80 00");
    assert!(parse(&padded_end).is_complete());
    let refused = Tree::parse_standard(
        Admitted::new(&padded_end).unwrap(),
        Standard::CanonicalMinimal,
        D,
        &mut NoAdvice,
    );
    let fault = refused.fault().expect("padded framing refused");
    assert_eq!((fault.at(), fault.kind()), (4, FaultKind::NonMinimalTag));
    assert_eq!(fault.kind().class(), FaultClass::Policy);
}

#[test]
fn canonical_speculation_absorbs_padding_and_commitment_faults_it() {
    // LEN f2 wrapping a padded varint: speculation concludes
    // "bytes", commitment owns the width fault.
    let data = h("12 04 08 96 81 00");
    let speculated = Tree::parse_standard(
        Admitted::new(&data).unwrap(),
        Standard::CanonicalMinimal,
        D,
        &mut NoAdvice,
    );
    assert!(speculated.is_complete(), "speculation absorbs the width fault");
    assert_eq!(speculated.children(nid(0)).count(), 0, "the payload concluded as bytes");

    let committed = Tree::parse_standard(
        Admitted::new(&data).unwrap(),
        Standard::CanonicalMinimal,
        D,
        &mut ByField(&[(2, Advice::Commit)]),
    );
    let fault = committed.fault().expect("commitment owns the width fault");
    assert_eq!((fault.at(), fault.kind()), (3, FaultKind::NonMinimalValue { field: fnum(1) }));
}

// ─── window caps (corpus-pinned windows) ───

#[test]
fn eleven_byte_value_is_refused() {
    let data = h("08 80808080808080808080 01");
    let x = parse(&data);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::Read { stage: Stage::Value { field: fnum(1) }, cause: ReadFault::TooWide })
    );
}

#[test]
fn six_byte_len_prefix_is_refused() {
    let data = h("12 838080808000 616263");
    let x = parse(&data);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::Read {
            stage: Stage::LenPrefix { field: fnum(2) },
            cause: ReadFault::TooWide
        })
    );
}

// ─── forgery refusal (out-of-class terminals never wrap) ───

#[test]
fn tag_terminal_beyond_u32_is_refused() {
    let data = h("F8FFFFFF10 01");
    let x = parse(&data);
    let fault = x.fault().expect("tag forgery");
    assert_eq!(
        (fault.kind, fault.at()),
        (FaultKind::Read { stage: Stage::Tag, cause: ReadFault::OutOfClass }, 0)
    );
}

#[test]
fn value_terminal_beyond_u64_is_refused() {
    let data = h("08 808080808080808080 02");
    let x = parse(&data);
    let fault = x.fault().expect("value forgery");
    assert_eq!(
        fault.kind,
        FaultKind::Read { stage: Stage::Value { field: fnum(1) }, cause: ReadFault::OutOfClass }
    );
    assert_eq!(fault.at(), 1); // the value's first byte
}

#[test]
fn len_beyond_its_class_is_refused() {
    let data = h("0A 8080808008 0801");
    let x = parse(&data);
    let fault = x.fault().expect("length class forgery");
    assert_eq!(
        fault.kind,
        FaultKind::Read {
            stage: Stage::LenPrefix { field: fnum(1) },
            cause: ReadFault::OutOfClass
        }
    );
    assert_eq!(fault.at(), 1); // the prefix's first byte
}

// ─── tag identity and vocabulary ───

#[test]
fn padded_zero_tag_is_field_zero() {
    let data = h("8000");
    let x = parse(&data);
    let fault = x.fault().expect("field zero");
    assert_eq!(fault.kind, FaultKind::FieldZero { code: Low3::new(0).unwrap() });
    assert_eq!(fault.at(), 0);
}

#[test]
fn field_zero_precedes_the_code_judgment() {
    // field 0 with unassigned code 6: identity judges first.
    let data = h("06");
    let x = parse(&data);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::FieldZero { code: Low3::new(6).unwrap() })
    );
}

#[test]
fn unassigned_codes_quote_field_and_code() {
    let data = h("0E"); // field 1, code 6
    let x = parse(&data);
    let fault = x.fault().expect("code 6 is unassigned");
    assert_eq!(fault.kind, FaultKind::Unassigned { field: fnum(1), code: Low3::new(6).unwrap() });
    assert_eq!(fault.at(), 0);
}

// ─── sealed extents ───

#[test]
fn len_overrun_quotes_declared_and_zone_left() {
    // f1 LEN declares 5; the root extent holds 2 more bytes.
    let data = h("0A05 0801");
    let x = parse(&data);
    let fault = x.fault().expect("declared exceeds the sealed space");
    let declared = PayloadLen::new(5).unwrap();
    assert_eq!(fault.kind, FaultKind::LenOverrun { field: fnum(1), declared, zone_left: 2 });
    assert_eq!(fault.at(), 1); // the prefix's first byte
}

// ─── groups ───

#[test]
fn group_tag_widths_are_independent_facts() {
    // two-byte SGROUP tag, one-byte EGROUP tag
    let data = h("8B00 089601 0C");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.span(nid(0)), Span::new(0, 6));
    assert_eq!(
        x.source_spans(nid(0)),
        RecordSpans::Group {
            tag: Span::new(0, 2),
            interior: Span::new(2, 5),
            end_tag: Span::new(5, 6),
        }
    );

    // the reverse asymmetry
    let data = h("0B 089601 8C00");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.span(nid(0)), Span::new(0, 6));
    assert_eq!(
        x.source_spans(nid(0)),
        RecordSpans::Group {
            tag: Span::new(0, 1),
            interior: Span::new(1, 4),
            end_tag: Span::new(4, 6),
        }
    );
}

#[test]
fn group_end_field_must_match_the_open_group() {
    let data = h("0B 14");
    let x = parse(&data);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::GroupEndMismatch { open: fnum(1), found: fnum(2) })
    );
}

#[test]
fn group_end_without_an_open_group_is_an_orphan() {
    let data = h("0C");
    let x = parse(&data);
    assert_eq!(x.fault().map(|f| f.kind), Some(FaultKind::GroupEndOrphan { found: fnum(1) }));
}

#[test]
fn a_group_never_spans_a_len_boundary() {
    // committed LEN payload ends while a group inside it is open
    let data = h("1A01 0B");
    let mut advice = ByField(&[(3, Advice::Commit)]);
    let x = parse_with(&data, &mut advice);
    let fault = x.fault().expect("unclosed at the seal");
    assert_eq!(fault.kind, FaultKind::GroupUnclosed { open: fnum(1) });
    assert_eq!(fault.at(), 3); // the sealed extent's end
}

#[test]
fn committed_fault_clips_open_ancestors_to_the_cut() {
    // varint · SGROUP f1 · varint child · input ends: unterminated
    let data = h("089601 0B 0801");
    let x = parse(&data);
    let fault = x.fault().expect("unterminated group");
    assert_eq!(fault.kind, FaultKind::GroupUnclosed { open: fnum(1) });
    assert_eq!(fault.at(), 6);
    assert_eq!(x.node_count(), 3);
    // The open group's body clips to the boundary; its parsed child
    // is retained; the end tag is not on the wire.
    assert_eq!(
        x.source_spans(nid(1)),
        RecordSpans::ClippedGroup { tag: Span::new(3, 4), interior: Span::new(4, 6) }
    );
    assert_eq!(x.children(nid(1)).collect::<Vec<_>>(), [nid(2)]);
}

#[test]
fn the_cut_never_swallows_the_bad_records_tag() {
    // group f1 { varint f1 with truncated value }: the fault's
    // diagnostic position is the value's first byte, but the clip
    // uses the failed record's start — the group's body must not
    // absorb the bad record's tag byte.
    let data = h("0B 08");
    let x = parse(&data);
    let fault = x.fault().expect("cut varint value");
    assert_eq!(
        fault.kind,
        FaultKind::Read { stage: Stage::Value { field: fnum(1) }, cause: ReadFault::Truncated }
    );
    assert_eq!(fault.at(), 2); // diagnostic: where the value starts
    assert_eq!(x.indexed_end(), 1); // transactional: the bad record's tag
    assert_eq!(
        x.source_spans(nid(0)),
        RecordSpans::ClippedGroup { tag: Span::new(0, 1), interior: Span::new(1, 1) }
    );
}

// ─── depth ───

#[test]
fn depth_limit_demotes_speculative_descent_to_blobs() {
    // Outer LEN opens at depth 1; the inner speculation sits at the
    // bound and demotes to an opaque leaf.
    let data = h("1A05 1A03089601");
    let x = Tree::parse(Admitted::new(&data).unwrap(), DepthLimit::MIN, &mut NoAdvice);
    assert_eq!(x.fault(), None);
    assert_eq!(x.children(nid(0)).collect::<Vec<_>>(), [nid(1)]);
    assert_eq!(x.children(nid(1)).count(), 0);
}

#[test]
fn depth_limit_faults_committed_descent() {
    // Nested groups: the inner open sits at the bound.
    let data = h("0B 0B0C 0C");
    let x = Tree::parse(Admitted::new(&data).unwrap(), DepthLimit::MIN, &mut NoAdvice);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::DepthExceeded { field: fnum(1), limit: DepthLimit::MIN })
    );

    // Nested Message claims: the inner claim is refused, committed.
    let data = h("0A05 1A03089601");
    let mut advice = ByField(&[(1, Advice::Commit), (3, Advice::Commit)]);
    let x = Tree::parse(Admitted::new(&data).unwrap(), DepthLimit::MIN, &mut advice);
    assert_eq!(
        x.fault().map(|f| f.kind),
        Some(FaultKind::DepthExceeded { field: fnum(3), limit: DepthLimit::MIN })
    );
}

// ─── queries ───

#[test]
fn narrowest_descends_to_the_tightest_record() {
    let data = h("1A06 0801 12026162");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.narrowest(0), Some(nid(0))); // outer tag byte
    assert_eq!(x.narrowest(2), Some(nid(1))); // child varint's tag
    assert_eq!(x.narrowest(7), Some(nid(2))); // inside "ab"
    assert_eq!(x.narrowest(8), None); // past the input
}

#[test]
fn narrowest_attributes_group_end_bytes_to_the_group_itself() {
    let data = h("0B 0801 0C");
    let x = parse(&data);
    assert_eq!(x.narrowest(3), Some(nid(0)));
}

#[test]
fn fixed_payload_bits_read_little_endian() {
    let data = h("0D 01000000 09 0200000000000000");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    assert_eq!(x.i32_bits(nid(0)), Some(1));
    assert_eq!(x.i64_bits(nid(1)), Some(2));
    assert_eq!(x.i32_bits(nid(1)), None); // kind-gated
}

#[test]
fn record_bytes_borrow_the_input_not_the_tree() {
    let data = h("089601");
    let x = parse(&data);
    let bytes = x.record_bytes(nid(0));
    drop(x);
    assert_eq!(bytes, data.as_slice());
}

#[test]
fn sibling_size_hint_brackets_the_walk() {
    // three roots, the middle one a container with two children
    let data = h("0801 1A04 0802 0803 0804");
    let x = parse(&data);
    assert_eq!(x.fault(), None);
    let it = x.top();
    let (lo, hi) = it.size_hint();
    let actual = it.count();
    assert_eq!(actual, 3);
    assert!(lo <= actual);
    assert!(hi.unwrap() >= actual);
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
    // Every kind incl. nesting; then a clipped group (truncated).
    for data in [
        h("089601 15AABBCCDD 19AABBCCDD11223344 1A026869 0B 089601 1A00 0C"),
        h("0B 089601"), // clipped group
    ] {
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
                RecordSpans::Group { tag, interior, end_tag } => {
                    assert_eq!(tag.start(), span.start());
                    assert_eq!(tag.end(), interior.start());
                    assert_eq!(interior.end(), end_tag.start());
                    assert_eq!(end_tag.end(), span.end());
                }
                RecordSpans::ClippedGroup { tag, interior } => {
                    assert_eq!(tag.start(), span.start());
                    assert_eq!(tag.end(), interior.start());
                    assert_eq!(interior.end(), span.end());
                }
            }
        }
    }
}
