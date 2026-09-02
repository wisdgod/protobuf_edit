//! Contract pins for the groupless-output converter: total
//! re-framing, fidelity of everything else, the closure sentence,
//! and the identity on group-free input.

use alloc::vec::Vec;

use super::*;

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

const D: DepthLimit = DepthLimit::REFERENCE;

#[track_caller]
fn convert(input: &[u8]) -> (Vec<u8>, Stats) {
    Converter::new(Standard::Tolerant, D).convert(input).expect("test input converts")
}

#[test]
fn every_group_reframes_as_a_len_record() {
    // varint f1=150 · group f2 { varint f3=1 } · LEN f2 "hi"
    let (out, stats) = convert(&h("08 9601 13 1801 14 12 02 6869"));
    assert_eq!(out, h("08 9601 12 02 1801 12 02 6869"));
    assert_eq!(stats.converted(), 1);
}

#[test]
fn nested_groups_convert_bottom_up() {
    // group f1 { group f2 { varint f3=7 } }
    let (out, stats) = convert(&h("0B 13 1807 14 0C"));
    assert_eq!(out, h("0A 04 12 02 1807"));
    assert_eq!(stats.converted(), 2);

    // Sequenced siblings inside one group.
    // group f1 { group f2 {} · varint f3=1 · group f2 { i32 f4=5 } }
    let (out, stats) = convert(&h("0B 13 14 1801 13 25 05000000 14 0C"));
    assert_eq!(out, h("0A 0B 1200 1801 12 05 25 05000000"));
    assert_eq!(stats.converted(), 3);
}

#[test]
fn an_empty_group_becomes_an_empty_len_record() {
    let (out, stats) = convert(&h("0B 0C"));
    assert_eq!(out, h("0A 00"));
    assert_eq!(stats.converted(), 1);
}

#[test]
fn group_free_input_is_the_byte_identity() {
    let input = h("08 9601 12 03 616263 25 01020304 19 0102030405060708");
    let (out, stats) = convert(&input);
    assert_eq!(out, input);
    assert_eq!(stats.converted(), 0);
}

#[test]
fn len_payloads_stay_opaque_declarations() {
    // A LEN whose payload happens to spell a group pair: the
    // payload is the producer's domain, never walked, never
    // converted — it rides verbatim.
    let input = h("12 02 0B 0C");
    let (out, stats) = convert(&input);
    assert_eq!(out, input);
    assert_eq!(stats.converted(), 0);
}

#[test]
fn padded_words_ride_verbatim_and_padded_framing_vanishes() {
    // Padded open tag (0x13 as two bytes), padded end tag, and a
    // padded interior value: the framing is dropped and re-authored
    // minimal, the interior word rides verbatim — the closure
    // sentence's two halves.
    let (out, stats) = convert(&h("9300 18 8100 9400"));
    assert_eq!(out, h("12 03 18 8100"));
    assert_eq!(stats.converted(), 1);
}

#[test]
fn the_canonical_standard_refuses_padded_input_words() {
    let strict = Converter::new(Standard::CanonicalMinimal, D);
    // Padded group open tag: refused at the tag's first byte.
    let fault = strict.convert(&h("9300 14")).unwrap_err();
    assert_eq!(fault.at(), 0);
    let FaultKind::Wire(breach) = fault.kind() else { panic!("a wire breach") };
    assert_eq!(breach, WireBreach::NonMinimal);
    assert_eq!(breach.class(), FaultClass::Policy);

    // Clean input converts identically under both standards.
    let msg = h("13 1801 14");
    let (strict_out, _) = strict.convert(&msg).unwrap();
    let (tolerant_out, _) = convert(&msg);
    assert_eq!(strict_out, tolerant_out);
}

#[test]
fn pairing_breaches_fault_as_grouping() {
    // An orphan end tag after one clean record.
    let fault = Converter::new(Standard::Tolerant, D).convert(&h("08 01 14")).unwrap_err();
    assert_eq!(fault.at(), 2);
    let FaultKind::Wire(breach) = fault.kind() else { panic!("a wire breach") };
    assert_eq!(breach, WireBreach::Grouping);
    assert_eq!(breach.class(), FaultClass::Grammar);

    // A group left open at the input end.
    let fault = Converter::new(Standard::Tolerant, D).convert(&h("0B 08 01")).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Grouping)));
}

#[test]
fn group_nesting_spends_the_declared_depth_budget() {
    let tight = Converter::new(Standard::Tolerant, DepthLimit::MIN);
    // One level: inside the budget.
    assert!(tight.convert(&h("0B 0C")).is_ok());
    // Two levels: the inner open leaves it.
    let fault = tight.convert(&h("0B 0B 0C 0C")).unwrap_err();
    assert_eq!(fault.at(), 1);
    let FaultKind::Wire(breach) = fault.kind() else { panic!("a wire breach") };
    assert_eq!(breach, WireBreach::Depth);
    assert_eq!(breach.class(), FaultClass::Policy);
}

#[test]
fn converted_output_is_a_fixed_point() {
    // The output is groupless-lawful, and groupless-lawful bytes
    // are grouped-lawful (sub-language), so re-converting is the
    // group-free identity.
    let (once, _) = convert(&h("0B 13 1807 14 1801 0C 08 9601"));
    let (twice, stats) = convert(&once);
    assert_eq!(twice, once);
    assert_eq!(stats.converted(), 0);
}

#[cfg(feature = "traverse-groupless")]
#[test]
fn output_re_ingests_under_the_groupless_dialect() {
    use crate::cursor::groupless::Cursor as Groupless;

    // Nested groups, scalars of every kind, an opaque LEN.
    let (out, _) = convert(&h("0B 13 1807 14 25 01020304 0C 12 03 616263 19 0102030405060708"));
    let entries: Vec<_> = Groupless::over(&out)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .expect("converted output walks clean under the groupless language");
    // Top level: the converted f1 LEN and the two verbatim records.
    assert_eq!(entries.len(), 3);
}

#[test]
fn a_wide_body_earns_a_wider_prefix_than_the_end_tag_it_replaces() {
    // A 128-byte body: the end tag it loses was one byte, the
    // prefix it gains is two — the output grows, and the enclosing
    // group's own measurement absorbs it.
    let mut inner = h("0B 12 7D");
    inner.extend(core::iter::repeat_n(0x61, 0x7D));
    inner.extend(h("0C"));
    let mut outer = h("0B");
    outer.extend(&inner);
    outer.extend(h("0C"));
    let (out, stats) = convert(&outer);
    // The inner group's body is one 127-byte LEN record, so the
    // converted inner record is 1 (tag) + 1 (prefix 0x7F) + 127 =
    // 129 bytes — which is the outer body, crossing the one-byte
    // prefix boundary: the outer prefix spells 129 in two bytes.
    assert_eq!(stats.converted(), 2);
    assert_eq!(out.len(), 3 + 129);
    assert_eq!(&out[..4], &h("0A 8101 0A")[..]);
    assert_eq!(out[4], 0x7F);
}

#[test]
fn convert_into_appends_and_is_untouched_on_err() {
    let converter = Converter::new(Standard::Tolerant, D);
    let mut out = h("FF");
    let stats = converter.convert_into(&h("0B 0C"), &mut out).unwrap();
    assert_eq!(out, h("FF 0A 00"));
    assert_eq!(stats.converted(), 1);

    let before = out.clone();
    assert!(converter.convert_into(&h("14"), &mut out).is_err());
    assert_eq!(out, before);
}

#[test]
fn the_sink_face_hands_the_buffered_bytes_and_nothing_on_err() {
    let converter = Converter::new(Standard::Tolerant, D);
    let msg = h("08 9601 13 1801 14 12 02 6869");
    let (buffered, buffered_stats) = converter.convert(&msg).unwrap();

    let mut handed = Vec::new();
    let stats = converter.convert_sink(&msg, |bytes| handed.extend_from_slice(bytes)).unwrap();
    assert_eq!(handed, buffered);
    assert_eq!(stats, buffered_stats);

    // A late pairing fault: the sink saw nothing.
    let mut handed = Vec::new();
    assert!(
        converter.convert_sink(&h("08 01 14"), |bytes| handed.extend_from_slice(bytes)).is_err()
    );
    assert!(handed.is_empty());
}
