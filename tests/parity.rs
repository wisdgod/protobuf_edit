//! Dialect parity: on group-free inputs the grouped and groupless
//! twins must agree byte-for-byte and verdict-for-verdict.
//!
//! The twins are separate concrete machines (scene isolation), so
//! nothing but this harness checks that a fix landing in one also
//! landed in the other. Inputs are exhaustive short strings (no
//! selection bias) plus representative constructed documents;
//! "group-free" is judged by the grouped inspector itself (no group
//! node in its tree and no group-specific fault), keeping the
//! filter inside the system under test.
//!
//! Faults are compared through their `Debug` text: the two fault
//! enums are distinct types by design, but on group-free inputs
//! every reachable arm carries the same name and payload on both
//! sides.

// The full consumer closure this suite drives; under any narrower
// feature set the target compiles empty, so per-cell `--all-targets`
// builds stay green. The transfer rows carry their own additional
// gates.
#![cfg(all(
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "session-grouped",
    feature = "session-groupless"
))]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

fn two_byte_universe() -> impl Iterator<Item = Vec<u8>> {
    (0u16..=u16::MAX).map(|w| w.to_le_bytes().to_vec())
}

fn three_byte_sample() -> impl Iterator<Item = Vec<u8>> {
    // Step 7 keeps the run fast while sweeping all byte roles.
    (0u32..(1 << 24)).step_by(7).map(|w| w.to_le_bytes()[..3].to_vec())
}

fn representatives() -> Vec<Vec<u8>> {
    #[track_caller]
    fn h(s: &str) -> Vec<u8> {
        let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        hex.chunks(2)
            .map(|p| {
                let hi = (p[0] as char).to_digit(16).unwrap();
                let lo = (p[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }
    alloc::vec![
        Vec::new(),
        h("089601"),
        h("089601 15AABBCCDD 19AABBCCDD11223344 12026869"),
        h("1A00"),
        h("1A03 089601"),
        h("12 05 12 03 12 01 00"),               // nested LENs
        h("08 FFFFFFFFFFFFFFFFFF01"),            // ten-byte varint
        h("08 8096 01".trim_start_matches(' ')), // padded varint value
        h("F8FFFFFF0F 00"),                      // max field number
        h("08"),                                 // cut value
        h("12 7F 00"),                           // LEN overrun
    ]
}

#[cfg(all(feature = "inspect-grouped", feature = "inspect-groupless"))]
mod inspect_parity {
    use protobuf_edit::DepthLimit;
    use protobuf_edit::inspect::NoAdvice;

    use super::*;

    /// `None`: the input is not group-free (skip it).
    #[track_caller]
    fn grouped_face(bytes: &[u8]) -> Option<String> {
        use protobuf_edit::inspect::grouped::{FaultKind, Tree};
        use protobuf_edit::wire::grouped::RecordKind;
        let admitted = protobuf_edit::inspect::Admitted::new(bytes).unwrap();
        let tree = Tree::parse(admitted, DepthLimit::REFERENCE, &mut NoAdvice);
        // Group-free filter: no group node, no group-arm fault.
        for id in tree.nodes() {
            if matches!(tree.kind(id), RecordKind::Group) {
                return None;
            }
        }
        if let Some(fault) = tree.fault() {
            // Only the group-specific arms disqualify: DepthExceeded
            // is reachable by LEN nesting alone and must agree.
            if matches!(
                fault.kind(),
                FaultKind::GroupUnclosed { .. }
                    | FaultKind::GroupEndOrphan { .. }
                    | FaultKind::GroupEndMismatch { .. }
            ) {
                return None;
            }
        }
        let mut out = String::new();
        for id in tree.nodes() {
            out.push_str(&format!(
                "{:?} {:?} {:?} {:?};",
                tree.field(id),
                tree.kind(id),
                tree.span(id),
                tree.source_spans(id)
            ));
        }
        out.push_str(&format!("fault={:?}", tree.fault()));
        Some(out)
    }

    #[track_caller]
    fn groupless_face(bytes: &[u8]) -> String {
        use protobuf_edit::inspect::groupless::Tree;
        let admitted = protobuf_edit::inspect::Admitted::new(bytes).unwrap();
        let tree = Tree::parse(admitted, DepthLimit::REFERENCE, &mut NoAdvice);
        let mut out = String::new();
        for id in tree.nodes() {
            out.push_str(&format!(
                "{:?} {:?} {:?} {:?};",
                tree.field(id),
                tree.kind(id),
                tree.span(id),
                tree.source_spans(id)
            ));
        }
        out.push_str(&format!("fault={:?}", tree.fault()));
        out
    }

    #[track_caller]
    fn agree(bytes: &[u8]) {
        if let Some(grouped) = grouped_face(bytes) {
            assert_eq!(grouped, groupless_face(bytes), "input {bytes:02X?}");
        }
    }

    #[test]
    fn exhaustive_two_bytes() {
        for input in two_byte_universe() {
            agree(&input);
        }
    }

    #[test]
    fn sampled_three_bytes() {
        for input in three_byte_sample() {
            agree(&input);
        }
    }

    #[test]
    fn representative_documents() {
        for input in representatives() {
            agree(&input);
        }
    }
}

#[cfg(all(feature = "session-grouped", feature = "session-groupless"))]
mod session_parity {
    use super::*;

    /// Group-free filter by the grouped session itself: open both,
    /// require identical verdict shape.
    #[track_caller]
    fn agree(bytes: &[u8]) {
        use protobuf_edit::session::grouped::Session as G;
        use protobuf_edit::session::groupless::Session as L;
        match (G::open_copy(bytes), L::open_copy(bytes)) {
            (Ok(g), Ok(l)) => {
                let gs = g.save().unwrap();
                let ls = l.save().unwrap();
                assert_eq!(gs.as_slice(), ls.as_slice(), "clean save {bytes:02X?}");
                assert_eq!(g.top().count(), l.top().count(), "top-layer row count {bytes:02X?}");
            }
            (Err(ge), Err(le)) => {
                // A group input is named by the groupless side (it
                // refuses the code); the grouped side may fail
                // deeper inside the group for unrelated reasons, so
                // its refusal text cannot judge group-ness.
                let ld = format!("{le:?}");
                if !ld.contains("Group") {
                    assert_eq!(format!("{ge:?}"), ld, "refusal {bytes:02X?}");
                }
            }
            (Ok(g), Err(le)) => {
                // Lawful only if the grouped document actually uses
                // groups (the groupless twin refuses the code).
                let uses_groups = format!("{le:?}").contains("Group");
                assert!(
                    uses_groups && g.top().count() > 0,
                    "split verdict without groups {bytes:02X?}: groupless said {le:?}"
                );
            }
            (Err(ge), Ok(_)) => {
                panic!("grouped refused what groupless accepted {bytes:02X?}: {ge:?}");
            }
        }
    }

    #[test]
    fn exhaustive_two_bytes() {
        for input in two_byte_universe() {
            agree(&input);
        }
    }

    #[test]
    fn representative_documents() {
        for input in representatives() {
            agree(&input);
        }
    }

    /// The same edit script must produce identical bytes.
    #[test]
    fn scripted_edits_agree() {
        use protobuf_edit::FieldNumber;
        use protobuf_edit::session::grouped::InsertAt as GAt;
        use protobuf_edit::session::groupless::InsertAt as LAt;
        let data: Vec<u8> = representatives()[2].clone();
        let f9 = FieldNumber::new(9).unwrap();

        let mut g = protobuf_edit::session::grouped::Session::open_copy(&data).unwrap();
        let mut l = protobuf_edit::session::groupless::Session::open_copy(&data).unwrap();

        let gt: Vec<_> = g.top().collect();
        let lt: Vec<_> = l.top().collect();
        g.set_varint(gt[0], 7).unwrap();
        l.set_varint(lt[0], 7).unwrap();
        g.insert_varint(GAt::After(gt[0]), f9, 1).unwrap();
        l.insert_varint(LAt::After(lt[0]), f9, 1).unwrap();
        g.delete(gt[1]).unwrap();
        l.delete(lt[1]).unwrap();

        assert_eq!(g.save().unwrap().as_slice(), l.save().unwrap().as_slice());
    }
}

#[cfg(all(feature = "patch-grouped", feature = "patch-groupless"))]
mod patch_parity {
    use protobuf_edit::DepthLimit;

    use super::*;

    /// Group-free filter by the grouped patch itself: open both,
    /// require identical verdict shape and identical clean saves.
    #[track_caller]
    fn agree(bytes: &[u8]) {
        use protobuf_edit::patch::grouped::Patch as G;
        use protobuf_edit::patch::groupless::Patch as L;
        match (G::open(bytes, DepthLimit::REFERENCE), L::open(bytes, DepthLimit::REFERENCE)) {
            (Ok(g), Ok(l)) => {
                assert_eq!(g.save().unwrap(), l.save().unwrap(), "clean save {bytes:02X?}");
                assert_eq!(g.top().count(), l.top().count(), "top-layer row count {bytes:02X?}");
            }
            (Err(ge), Err(le)) => {
                // A group input is named by the groupless side (it
                // refuses the code); the grouped side may fail
                // deeper inside the group for unrelated reasons, so
                // its refusal text cannot judge group-ness.
                let ld = format!("{le:?}");
                if !ld.contains("Group") {
                    assert_eq!(format!("{ge:?}"), ld, "refusal {bytes:02X?}");
                }
            }
            (Ok(g), Err(le)) => {
                let uses_groups = format!("{le:?}").contains("Group");
                assert!(
                    uses_groups && g.top().count() > 0,
                    "split verdict without groups {bytes:02X?}: groupless said {le:?}"
                );
            }
            (Err(ge), Ok(_)) => {
                panic!("grouped refused what groupless accepted {bytes:02X?}: {ge:?}");
            }
        }
    }

    #[test]
    fn exhaustive_two_bytes() {
        for input in two_byte_universe() {
            agree(&input);
        }
    }

    #[test]
    fn representative_documents() {
        for input in representatives() {
            agree(&input);
        }
    }

    /// The same edit script must produce identical bytes.
    #[test]
    fn scripted_edits_agree() {
        use protobuf_edit::FieldNumber;
        use protobuf_edit::patch::grouped::InsertAt as GAt;
        use protobuf_edit::patch::groupless::InsertAt as LAt;
        let data: Vec<u8> = representatives()[2].clone();
        let f9 = FieldNumber::new(9).unwrap();

        let mut g =
            protobuf_edit::patch::grouped::Patch::open(&data, DepthLimit::REFERENCE).unwrap();
        let mut l =
            protobuf_edit::patch::groupless::Patch::open(&data, DepthLimit::REFERENCE).unwrap();

        let gt: Vec<_> = g.top().collect();
        let lt: Vec<_> = l.top().collect();
        g.set_varint(gt[0], 7).unwrap();
        l.set_varint(lt[0], 7).unwrap();
        g.insert_varint(GAt::After(gt[0]), f9, 1).unwrap();
        l.insert_varint(LAt::After(lt[0]), f9, 1).unwrap();
        g.delete(gt[1]).unwrap();
        l.delete(lt[1]).unwrap();

        assert_eq!(g.save().unwrap(), l.save().unwrap());

        // The canonical faces are dialect-parity surface too: the
        // same script and the same closure normalize identically.
        assert_eq!(g.save_canonical().unwrap(), l.save_canonical().unwrap());
    }

    /// A padded group-free survivor no edit touches: both dialect
    /// twins normalize it to the same bytes through every canonical
    /// face.
    #[test]
    fn canonical_saves_agree_over_padded_survivors() {
        use protobuf_edit::patch::grouped::Patch as G;
        use protobuf_edit::patch::groupless::Patch as L;
        // padded tag · padded LEN prefix over an opaque payload.
        let padded = {
            let mut doc = Vec::new();
            doc.extend_from_slice(&[0x88, 0x00, 0x01]);
            doc.extend_from_slice(&[0x12, 0x82, 0x00, 0x68, 0x69]);
            doc
        };
        let g = G::open(&padded, DepthLimit::REFERENCE).unwrap();
        let l = L::open(&padded, DepthLimit::REFERENCE).unwrap();
        let expect = [0x08, 0x01, 0x12, 0x02, 0x68, 0x69];
        assert_eq!(g.save_canonical().unwrap(), expect);
        assert_eq!(l.save_canonical().unwrap(), expect);
        let mut g_into = Vec::new();
        g.save_canonical_into(&mut g_into).unwrap();
        let mut l_into = Vec::new();
        l.save_canonical_into(&mut l_into).unwrap();
        assert_eq!(g_into, l_into);
        let mut g_sink = Vec::new();
        g.save_canonical_sink(|s| g_sink.extend_from_slice(s)).unwrap();
        let mut l_sink = Vec::new();
        l.save_canonical_sink(|s| l_sink.extend_from_slice(s)).unwrap();
        assert_eq!(g_sink, l_sink);
    }
}

#[cfg(all(feature = "scan-grouped", feature = "scan-groupless"))]
mod scan_parity {
    use protobuf_edit::DepthLimit;

    use super::*;

    #[track_caller]
    fn agree(bytes: &[u8]) {
        use protobuf_edit::scan::grouped::Validator as G;
        use protobuf_edit::scan::groupless::Validator as L;
        use protobuf_edit::scan::Standard;

        let mut g = G::new(Standard::Tolerant, DepthLimit::REFERENCE);
        let gv = g.feed(bytes).and_then(|()| g.finish());
        let mut l = L::new(Standard::Tolerant);
        let lv = l.feed(bytes).and_then(|()| l.finish());
        match (gv, lv) {
            (Ok(()), Ok(())) => {}
            (Err(ge), Err(le)) => {
                let gd = format!("{ge:?}");
                if !gd.contains("Group") && !format!("{le:?}").contains("Group") {
                    assert_eq!(gd, format!("{le:?}"), "verdict {bytes:02X?}");
                }
            }
            (Ok(()), Err(le)) => {
                assert!(
                    format!("{le:?}").contains("Group"),
                    "split verdict without groups {bytes:02X?}: {le:?}"
                );
            }
            (Err(ge), Ok(())) => {
                panic!("grouped refused, groupless accepted {bytes:02X?}: {ge:?}");
            }
        }
    }

    #[test]
    fn exhaustive_two_bytes() {
        for input in two_byte_universe() {
            agree(&input);
        }
    }

    #[test]
    fn representative_documents() {
        for input in representatives() {
            agree(&input);
        }
    }
}

#[cfg(all(
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless"
))]
mod inplace_rewrite_refusal_parity {
    //! The in-place judge walk against the rewriter's measuring
    //! pass: two parallel implementations of one static-matcher
    //! walk, held to identical admission verdicts — wire faults,
    //! group verdicts, depth, canonical non-minimality — at
    //! identical byte coordinates, on shared fixtures. The rules
    //! route through every container (a wildcard over the
    //! fixtures' whole field range) and target a field no fixture
    //! carries, so both machines walk everything and act on
    //! nothing.

    use protobuf_edit::{DepthLimit, FieldNumber, Standard};

    use super::{representatives, two_byte_universe};

    // Fields 1..=31 cover every field a two-byte record head can
    // spell, so the wildcard commits every container the fixtures
    // hold; field 2048 needs a three-byte tag, so no fixture can
    // spell even its bare enter — the rules act on nothing.
    const ROUTE: [FieldNumber; 31] = {
        let mut route = [FieldNumber::new(1).unwrap(); 31];
        let mut index = 0;
        while index < 31 {
            #[allow(clippy::as_conversions, reason = "tiny loop indices widen losslessly")]
            {
                route[index] = FieldNumber::new(index as u32 + 1).unwrap();
            }
            index += 1;
        }
        route
    };

    /// (accepted, coordinate, breach-name) — the comparable frame
    /// of one machine's verdict.
    type Verdict = (bool, u32, String);

    fn inplace_groupless(bytes: &[u8], standard: Standard) -> Verdict {
        use protobuf_edit::inplace::groupless::apply_standard;
        use protobuf_edit::inplace::{Action, Rule, RuleSet};
        use protobuf_edit::path::Segment;
        let rules = [Rule {
            path: &[
                Segment::AnyDepth { descend: &ROUTE },
                Segment::Field(FieldNumber::new(2048).unwrap()),
            ],
            action: Action::SetVarint(0),
        }];
        let set = RuleSet::over(&rules).unwrap();
        let mut buf = bytes.to_vec();
        match apply_standard(&mut buf, &set, standard, DepthLimit::REFERENCE) {
            Ok(_) => (true, 0, String::new()),
            Err(fault) => {
                let kind = fault.kind();
                let protobuf_edit::inplace::groupless::FaultKind::Wire(breach) = kind else {
                    panic!("actionless walks fault on wire alone: {kind:?}");
                };
                (false, fault.at(), format!("{breach:?}"))
            }
        }
    }

    fn rewrite_groupless(bytes: &[u8], standard: Standard) -> Verdict {
        use protobuf_edit::rewrite::groupless::rewrite_standard;
        use protobuf_edit::path::Segment;
        use protobuf_edit::rewrite::{Action, Rule, RuleSet};
        let rules = [Rule {
            path: &[
                Segment::AnyDepth { descend: &ROUTE },
                Segment::Field(FieldNumber::new(2048).unwrap()),
            ],
            action: Action::Delete,
        }];
        let set = RuleSet::over(&rules).unwrap();
        match rewrite_standard(bytes, &set, standard, DepthLimit::REFERENCE) {
            Ok(_) => (true, 0, String::new()),
            Err(fault) => {
                let kind = fault.kind();
                let protobuf_edit::rewrite::groupless::FaultKind::Wire(breach) = kind else {
                    panic!("actionless walks fault on wire alone: {kind:?}");
                };
                (false, fault.at(), format!("{breach:?}"))
            }
        }
    }

    fn inplace_grouped(bytes: &[u8], standard: Standard) -> Verdict {
        use protobuf_edit::inplace::grouped::apply_standard;
        use protobuf_edit::inplace::{Action, Rule, RuleSet};
        use protobuf_edit::path::Segment;
        let rules = [Rule {
            path: &[
                Segment::AnyDepth { descend: &ROUTE },
                Segment::Field(FieldNumber::new(2048).unwrap()),
            ],
            action: Action::SetVarint(0),
        }];
        let set = RuleSet::over(&rules).unwrap();
        let mut buf = bytes.to_vec();
        match apply_standard(&mut buf, &set, standard, DepthLimit::REFERENCE) {
            Ok(_) => (true, 0, String::new()),
            Err(fault) => {
                let kind = fault.kind();
                let protobuf_edit::inplace::grouped::FaultKind::Wire(breach) = kind else {
                    panic!("actionless walks fault on wire alone: {kind:?}");
                };
                (false, fault.at(), format!("{breach:?}"))
            }
        }
    }

    fn rewrite_grouped(bytes: &[u8], standard: Standard) -> Verdict {
        use protobuf_edit::path::Segment;
        use protobuf_edit::rewrite::grouped::rewrite_standard;
        use protobuf_edit::rewrite::{Action, Rule, RuleSet};
        let rules = [Rule {
            path: &[
                Segment::AnyDepth { descend: &ROUTE },
                Segment::Field(FieldNumber::new(2048).unwrap()),
            ],
            action: Action::Delete,
        }];
        let set = RuleSet::over(&rules).unwrap();
        match rewrite_standard(bytes, &set, standard, DepthLimit::REFERENCE) {
            Ok(_) => (true, 0, String::new()),
            Err(fault) => {
                let kind = fault.kind();
                let protobuf_edit::rewrite::grouped::FaultKind::Wire(breach) = kind else {
                    panic!("actionless walks fault on wire alone: {kind:?}");
                };
                (false, fault.at(), format!("{breach:?}"))
            }
        }
    }

    fn agree(bytes: &[u8]) {
        for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
            assert_eq!(
                inplace_groupless(bytes, standard),
                rewrite_groupless(bytes, standard),
                "groupless {standard:?} verdict {bytes:02X?}"
            );
            assert_eq!(
                inplace_grouped(bytes, standard),
                rewrite_grouped(bytes, standard),
                "grouped {standard:?} verdict {bytes:02X?}"
            );
        }
    }

    #[test]
    fn exhaustive_two_bytes() {
        for input in two_byte_universe() {
            agree(&input);
        }
    }

    #[test]
    fn representative_documents() {
        for input in representatives() {
            agree(&input);
        }
    }

    #[test]
    fn depth_verdicts_agree_at_the_boundary() {
        // Nested LENs exactly at and one past a tight budget: both
        // machines route through, and the refusals name one
        // coordinate.
        let at_budget = [0x0A, 0x02, 0x08, 0x01];
        let past_budget = [0x0A, 0x04, 0x0A, 0x02, 0x08, 0x01];
        for standard in [Standard::Tolerant, Standard::CanonicalMinimal] {
            for (doc, refused) in [(&at_budget[..], false), (&past_budget[..], true)] {
                use protobuf_edit::path::Segment;
                let route = [FieldNumber::new(1).unwrap()];
                let path = [
                    Segment::AnyDepth { descend: &route },
                    Segment::Field(FieldNumber::new(2048).unwrap()),
                ];
                let in_rules = [protobuf_edit::inplace::Rule {
                    path: &path,
                    action: protobuf_edit::inplace::Action::SetVarint(0),
                }];
                let in_set = protobuf_edit::inplace::RuleSet::over(&in_rules).unwrap();
                let mut buf = doc.to_vec();
                let limit = DepthLimit::MIN;
                let inplace = protobuf_edit::inplace::groupless::apply_standard(
                    &mut buf, &in_set, standard, limit,
                );
                let re_rules = [protobuf_edit::rewrite::Rule {
                    path: &path,
                    action: protobuf_edit::rewrite::Action::Delete,
                }];
                let re_set = protobuf_edit::rewrite::RuleSet::over(&re_rules).unwrap();
                let rewrite = protobuf_edit::rewrite::groupless::rewrite_standard(
                    doc, &re_set, standard, limit,
                );
                assert_eq!(inplace.is_err(), refused, "{standard:?} {doc:02X?}");
                assert_eq!(rewrite.is_err(), refused, "{standard:?} {doc:02X?}");
                if let (Err(a), Err(b)) = (inplace, rewrite) {
                    assert_eq!(a.at(), b.at(), "{standard:?} {doc:02X?}");
                    assert_eq!(
                        format!("{:?}", a.kind()),
                        format!("{:?}", b.kind()),
                        "{standard:?} {doc:02X?}"
                    );
                }
            }
        }
    }
}

/// The transfer dialect matrix: a groupless designation widens into
/// a grouped host verbatim; a grouped designation narrows only after
/// the common-kind proof — a group refuses, a scalar crosses.
#[cfg(all(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "transfer-patch-grouped",
    feature = "transfer-patch-groupless"
))]
#[test]
fn the_dialect_matrix_widens_and_narrows_through_the_proofs() {
    use protobuf_edit::DepthLimit;
    use protobuf_edit::inspect::{Admitted, NoAdvice};

    #[track_caller]
    fn h(s: &str) -> Vec<u8> {
        let hex: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        hex.chunks(2)
            .map(|p| {
                let hi = (p[0] as char).to_digit(16).unwrap();
                let lo = (p[1] as char).to_digit(16).unwrap();
                (hi * 16 + lo) as u8
            })
            .collect()
    }

    // A groupless LEN record widens into this grouped host.
    let foreign = h("12 02 68 69");
    let input = Admitted::new(&foreign).unwrap();
    let tree =
        protobuf_edit::inspect::groupless::Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let widened = tree.record_ref(tree.top().next().unwrap()).unwrap().widen();

    let data = h("18 07");
    let mut p =
        protobuf_edit::patch::grouped::TransferPatch::open(&data, DepthLimit::REFERENCE).unwrap();
    p.copy_record_from(widened, protobuf_edit::patch::grouped::InsertAt::TailOf(None)).unwrap();
    assert_eq!(p.save().unwrap(), h("18 07 12 02 68 69"));

    // A grouped group refuses to narrow; a grouped scalar narrows
    // and imports into the groupless twin.
    let grouped_doc = h("0B 0C 10 05");
    let ginput = Admitted::new(&grouped_doc).unwrap();
    let gtree =
        protobuf_edit::inspect::grouped::Tree::parse(ginput, DepthLimit::REFERENCE, &mut NoAdvice);
    let ids: Vec<_> = gtree.top().collect();
    assert!(matches!(
        gtree.record_ref(ids[0]).unwrap().try_groupless(),
        Err(protobuf_edit::source::grouped::Fault::DialectMismatch { .. })
    ));
    let narrowed = gtree.record_ref(ids[1]).unwrap().try_groupless().unwrap();

    let base = h("08 01");
    let mut narrow_host =
        protobuf_edit::patch::groupless::TransferPatch::open(&base, DepthLimit::REFERENCE).unwrap();
    narrow_host
        .copy_record_from(narrowed, protobuf_edit::patch::groupless::InsertAt::TailOf(None))
        .unwrap();
    assert_eq!(narrow_host.save().unwrap(), h("08 01 10 05"));
}
