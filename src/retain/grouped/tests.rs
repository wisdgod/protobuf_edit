//! The grouped retained inspector's module suite: the borrowed
//! differential twin (every query face agrees with `inspect` on
//! identical bytes, both standards) and the ownership-tenure pins.

// The buffered-twin differential's vocabulary rides its feature.
#[cfg(feature = "inspect-grouped")]
use alloc::vec::Vec;

use super::Retained;
use crate::retain::NoAdvice;
#[cfg(feature = "inspect-grouped")]
use crate::retain::{Advice, Advisor, Ancestry};
#[cfg(feature = "inspect-grouped")]
use crate::wire::FieldNumber;
use crate::{DepthLimit, Standard};

// ─── ownership tenure ───

#[test]
fn the_buffer_moves_in_and_out_without_a_copy() {
    // varint f1=150 · group f2 { varint f3=1 }
    let src = alloc::vec![0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let addr = src.as_ptr().addr();
    let kept = Retained::parse(src, DepthLimit::REFERENCE, &mut NoAdvice).unwrap();
    assert_eq!(kept.bytes().as_ptr().addr(), addr, "parse must move the buffer, not copy it");
    let back = kept.into_bytes();
    assert_eq!(back.as_ptr().addr(), addr, "release must move the buffer back, not copy it");
    assert_eq!(back, [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14]);
}

// The refusal fixture allocates past the coordinate class
// (> 2 GiB): 32-bit targets cannot host it, and under Miri it is
// byte bulk without provenance value. The refusal arithmetic
// itself is target-independent.
#[cfg(all(not(target_family = "wasm"), not(miri)))]
#[test]
fn an_oversize_buffer_is_refused_with_its_tenure_returned() {
    use crate::admission;

    let src = alloc::vec![0u8; admission::MAX + 1];
    let addr = src.as_ptr().addr();
    let len = src.len();
    let Err((back, _oversize)) = Retained::parse(src, DepthLimit::REFERENCE, &mut NoAdvice) else {
        panic!("an oversize buffer must refuse");
    };
    assert_eq!(back.as_ptr().addr(), addr, "the refusal must return the buffer, not a copy");
    assert_eq!(back.len(), len);
}

// ─── the borrowed differential twin ───

/// One advisor answering both machines' supply traits with the
/// same pure function, so a differential run consults identical
/// schema knowledge on both sides.
#[cfg(feature = "inspect-grouped")]
#[derive(Clone, Copy)]
struct Pin;

#[cfg(feature = "inspect-grouped")]
impl Pin {
    fn answer(field: FieldNumber) -> Advice {
        match field.as_inner() {
            2 => Advice::Commit,
            3 => Advice::Opaque,
            _ => Advice::Speculate,
        }
    }
}

#[cfg(feature = "inspect-grouped")]
impl Advisor for Pin {
    fn advise(&mut self, _ancestry: Ancestry<'_>, field: FieldNumber) -> Advice {
        Self::answer(field)
    }
}

#[cfg(feature = "inspect-grouped")]
impl crate::inspect::Advisor for Pin {
    fn advise(
        &mut self,
        _ancestry: crate::inspect::Ancestry<'_>,
        field: FieldNumber,
    ) -> crate::inspect::Advice {
        match Self::answer(field) {
            Advice::Speculate => crate::inspect::Advice::Speculate,
            Advice::Commit => crate::inspect::Advice::Commit,
            Advice::Opaque => crate::inspect::Advice::Opaque,
        }
    }
}

/// Asserts every query face of the owned product against the
/// borrowed tree over the same bytes: whole-product facts, every
/// row's answers, every structural walk, and `narrowest` at every
/// byte position (one past the end included).
#[cfg(feature = "inspect-grouped")]
fn agree<RA, TA>(bytes: &[u8], standard: Standard, depth: DepthLimit, ra: &mut RA, ta: &mut TA)
where
    RA: Advisor,
    TA: crate::inspect::Advisor,
{
    use alloc::format;

    use crate::inspect::Admitted;
    use crate::inspect::grouped::Tree;

    let tree = Tree::parse_standard(Admitted::new(bytes).unwrap(), standard, depth, ta);
    let kept = Retained::parse_standard(bytes.to_vec(), standard, depth, ra).unwrap();

    assert_eq!(kept.bytes(), tree.bytes());
    assert_eq!(kept.is_complete(), tree.is_complete());
    assert_eq!(kept.indexed_end(), tree.indexed_end());
    assert_eq!(kept.node_count(), tree.node_count());
    assert_eq!(kept.is_empty(), tree.is_empty());
    match (kept.fault(), tree.fault()) {
        (None, None) => {}
        (Some(kf), Some(tf)) => {
            assert_eq!(kf.at(), tf.at());
            assert_eq!(format!("{:?}", kf.kind()), format!("{:?}", tf.kind()));
        }
        (kf, tf) => panic!("fault presence disagrees: {kf:?} vs {tf:?}"),
    }

    let ids = |v: &Retained| -> Vec<u32> { v.nodes().map(|id| id.as_inner()).collect() };
    let tids: Vec<u32> = tree.nodes().map(|id| id.as_inner()).collect();
    assert_eq!(ids(&kept), tids, "preorder tables must align");

    for (kid, tid) in kept.nodes().zip(tree.nodes()) {
        assert_eq!(kept.field(kid), tree.field(tid));
        assert_eq!(kept.kind(kid), tree.kind(tid));
        assert_eq!(kept.span(kid), tree.span(tid));
        assert_eq!(
            format!("{:?}", kept.source_spans(kid)),
            format!("{:?}", tree.source_spans(tid))
        );
        assert_eq!(
            kept.parent(kid).map(crate::retain::NodeId::as_inner),
            tree.parent(tid).map(crate::inspect::NodeId::as_inner)
        );
        assert_eq!(kept.record_bytes(kid), tree.record_bytes(tid));
        assert_eq!(kept.payload_bytes(kid), tree.payload_bytes(tid));
        assert_eq!(kept.varint_word(kid), tree.varint_word(tid));
        assert_eq!(kept.i32_bits(kid), tree.i32_bits(tid));
        assert_eq!(kept.i64_bits(kid), tree.i64_bits(tid));
        let kept_children: Vec<u32> = kept.children(kid).map(|id| id.as_inner()).collect();
        let tree_children: Vec<u32> = tree.children(tid).map(|id| id.as_inner()).collect();
        assert_eq!(kept_children, tree_children);
        let kept_desc: Vec<u32> = kept.descendants(kid).map(|id| id.as_inner()).collect();
        let tree_desc: Vec<u32> = tree.descendants(tid).map(|id| id.as_inner()).collect();
        assert_eq!(kept_desc, tree_desc);
        let kept_anc: Vec<u32> = kept.ancestors(kid).map(|id| id.as_inner()).collect();
        let tree_anc: Vec<u32> = tree.ancestors(tid).map(|id| id.as_inner()).collect();
        assert_eq!(kept_anc, tree_anc);
    }

    for pos in 0..=crate::admission::admitted_u32(bytes.len()) + 1 {
        assert_eq!(
            kept.narrowest(pos).map(crate::retain::NodeId::as_inner),
            tree.narrowest(pos).map(crate::inspect::NodeId::as_inner),
            "narrowest({pos}) disagrees"
        );
    }
}

#[cfg(feature = "inspect-grouped")]
fn agree_all_standards(bytes: &[u8], depth: DepthLimit) {
    use crate::inspect::NoAdvice as TreeNoAdvice;

    for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
        agree(bytes, standard, depth, &mut NoAdvice, &mut TreeNoAdvice);
        agree(bytes, standard, depth, &mut Pin, &mut Pin);
    }
}

// ─── the canonical engine's own arcs ───

#[test]
fn the_canonical_engine_names_each_padded_construct() {
    use super::FaultKind;

    // The accept arc: minimal wire parses complete and faultless
    // under the canonical standard.
    let minimal = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14, 0x12, 0x02, 0x68, 0x69];
    let kept = Retained::parse_standard(
        minimal.to_vec(),
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
        &mut NoAdvice,
    )
    .unwrap();
    assert!(kept.is_complete() && kept.fault().is_none());

    // Each padded construct produces its named fault at the
    // construct's first byte — every `NonMinimal*` kind live.
    let arcs: &[(&[u8], u32)] = &[
        // Padded record tag.
        (&[0x88, 0x00, 0x2A], 0),
        // Padded varint value.
        (&[0x08, 0x96, 0x81, 0x00], 1),
        // Padded LEN length prefix.
        (&[0x12, 0x82, 0x00, 0x68, 0x69], 1),
        // Padded group end tag.
        (&[0x0B, 0x8C, 0x80, 0x00], 1),
    ];
    for &(bytes, at) in arcs {
        let kept = Retained::parse_standard(
            bytes.to_vec(),
            Standard::CanonicalMinimal,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();
        let fault = kept.fault().expect("the padded construct must refuse");
        assert_eq!(fault.at(), at, "wrong coordinate on {bytes:02X?}");
    }

    let value_fault = |bytes: &[u8]| {
        Retained::parse_standard(
            bytes.to_vec(),
            Standard::CanonicalMinimal,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap()
        .fault()
        .map(|fault| fault.kind())
    };
    assert!(matches!(
        value_fault(&[0x08, 0x96, 0x81, 0x00]),
        Some(FaultKind::NonMinimalValue { field }) if field.as_inner() == 1
    ));
    assert!(matches!(
        value_fault(&[0x12, 0x82, 0x00, 0x68, 0x69]),
        Some(FaultKind::NonMinimalLen { field }) if field.as_inner() == 2
    ));
    assert!(matches!(value_fault(&[0x88, 0x00, 0x2A]), Some(FaultKind::NonMinimalTag)));
}

#[cfg(feature = "scan-grouped")]
#[test]
fn canonical_refusals_land_where_the_stream_validator_judges_them() {
    // The module doc's cross-machine position claim, judged: over
    // padded and minimal documents, the retained parse's canonical
    // verdict and coordinate equal the stream scanner's canonical
    // validator's on the same bytes.
    fn scan_verdict(bytes: &[u8]) -> Option<u64> {
        use crate::scan::grouped::Validator;
        let mut v = Validator::new(Standard::CanonicalMinimal, DepthLimit::REFERENCE);
        match v.feed(bytes) {
            Err(fault) => Some(fault.at()),
            Ok(()) => v.finish().err().map(|fault| fault.at()),
        }
    }
    let corpus: &[&[u8]] = &[
        &[0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14],
        &[0x88, 0x00, 0x2A],
        &[0x08, 0x96, 0x81, 0x00],
        &[0x12, 0x82, 0x00, 0x68, 0x69],
        &[0x0B, 0x8C, 0x80, 0x00],
        // Padding inside a group interior: committed on both sides.
        &[0x13, 0x18, 0x81, 0x00, 0x14],
        // Padding inside a LEN payload: opaque on both sides (the
        // scanner swallows by count; retain's speculation absorbs
        // and concludes bytes), so both accept.
        &[0x12, 0x04, 0x08, 0x96, 0x81, 0x00],
    ];
    for bytes in corpus {
        let kept = Retained::parse_standard(
            bytes.to_vec(),
            Standard::CanonicalMinimal,
            DepthLimit::REFERENCE,
            &mut NoAdvice,
        )
        .unwrap();
        let retained_at = kept.fault().map(|fault| u64::from(fault.at()));
        assert_eq!(retained_at, scan_verdict(bytes), "coordinates diverge on {bytes:02X?}");
    }
}

#[cfg(feature = "inspect-grouped")]
#[test]
fn every_query_face_agrees_with_the_borrowed_tree() {
    let fixtures: &[&[u8]] = &[
        // Empty message.
        &[],
        // varint f1=150 · group f2 { varint f3=1 }.
        &[0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14],
        // Nested groups: group f1 { group f4 { i32 f5 } } · i64 f6.
        &[0x0B, 0x23, 0x2D, 1, 2, 3, 4, 0x24, 0x0C, 0x31, 1, 2, 3, 4, 5, 6, 7, 8],
        // A LEN inside a group, parseable payload (f2 commits under
        // Pin, speculates under NoAdvice).
        &[0x0B, 0x12, 0x02, 0x08, 0x01, 0x0C],
        // A group inside a LEN: pairing may not cross the seal —
        // NoAdvice speculation absorbs the unclosed interior; a
        // committed read faults it.
        &[0x12, 0x02, 0x0B, 0x0C],
        &[0x12, 0x01, 0x0B],
        // Padded group framing: end tag continuation-padded.
        &[0x0B, 0x8C, 0x80, 0x00],
        // An orphan end tag and a mismatched end tag.
        &[0x0C],
        &[0x0B, 0x1C],
        // A group left open by the input's end: clipped.
        &[0x0B, 0x08, 0x01],
        // Truncated at the root: legal prefix plus a fault.
        &[0x08, 0x96, 0x01, 0x08],
        // A declared length puncturing its seal.
        &[0x12, 0x05, 0x01],
    ];
    for bytes in fixtures {
        agree_all_standards(bytes, DepthLimit::REFERENCE);
        // A tight bound exercises demote-to-opaque, the committed
        // depth fault, and the group depth fault.
        agree_all_standards(bytes, DepthLimit::MIN);
    }
}
