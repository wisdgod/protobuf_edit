//! Contract pins for the grouped-output converter: designated
//! re-framing, the crossing cascade, the commitment doctrine, and
//! the identity of an empty or inapplicable policy.

use alloc::vec::Vec;

use crate::path::{Program, Segment};
use crate::wire::FieldNumber;

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

#[track_caller]
fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

const D: DepthLimit = DepthLimit::REFERENCE;

#[track_caller]
fn convert(input: &[u8], paths: &[&[Segment<'_>]]) -> Result<(Vec<u8>, Stats), Fault> {
    let program = Program::over(paths).expect("test paths admit");
    Converter::new(Standard::Tolerant, D, program).convert(input)
}

#[test]
fn a_designated_len_reframes_as_a_group() {
    // varint f1=150 · LEN f2 [ varint f3=1 ] · LEN f4 "hi"
    let (out, stats) =
        convert(&h("08 9601 12 02 1801 22 02 6869"), &[&[Segment::Field(f(2))]]).unwrap();
    // f2 re-frames; f4 is undesignated and rides verbatim.
    assert_eq!(out, h("08 9601 13 1801 14 22 02 6869"));
    assert_eq!((stats.converted(), stats.descended()), (1, 0));
}

#[test]
fn nested_designations_convert_within_the_converted_interior() {
    // LEN f2 [ LEN f4 [ varint f1=1 ] ]
    let paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(2))], &[Segment::Field(f(2)), Segment::Field(f(4))]];
    let (out, stats) = convert(&h("12 04 22 02 0801"), &paths).unwrap();
    assert_eq!(out, h("13 23 0801 24 14"));
    assert_eq!((stats.converted(), stats.descended()), (2, 0));
}

#[test]
fn a_conversion_under_a_crossing_resettles_the_enclosing_prefix() {
    // LEN f1 [ LEN f16 [] ]: f16's LEN spelling is 3 bytes
    // (two-byte tag + prefix), its group spelling 4 (two two-byte
    // framing tags) — the crossed f1 prefix re-settles minimally.
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1)), Segment::Field(f(16))]];
    let (out, stats) = convert(&h("0A 03 8201 00"), &paths).unwrap();
    assert_eq!(out, h("0A 04 8301 8401"));
    assert_eq!((stats.converted(), stats.descended()), (1, 1));

    // The same shape where sizes coincide: the crossed prefix
    // rides verbatim (a dirty layer of unchanged length keeps its
    // framing bytes).
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1)), Segment::Field(f(2))]];
    let (out, stats) = convert(&h("0A 04 12 02 1807"), &paths).unwrap();
    assert_eq!(out, h("0A 04 13 1807 14"));
    assert_eq!((stats.converted(), stats.descended()), (1, 1));
}

#[test]
fn an_empty_policy_is_the_byte_identity() {
    let input = h("08 9601 12 02 1801 22 02 6869");
    let (out, stats) = convert(&input, &[]).unwrap();
    assert_eq!(out, input);
    assert_eq!((stats.converted(), stats.descended()), (0, 0));
}

#[test]
fn an_inapplicable_policy_is_silent_and_the_zero_count_signals_it() {
    // Field 9 never occurs: nothing converts, nothing faults.
    let input = h("08 9601 12 02 1801");
    let (out, stats) = convert(&input, &[&[Segment::Field(f(9))]]).unwrap();
    assert_eq!(out, input);
    assert_eq!(stats.converted(), 0);
}

#[test]
fn a_designated_scalar_is_the_callers_schema_error() {
    // Field 1 is a varint; the program commits it to carry
    // messages.
    let fault = convert(&h("08 9601"), &[&[Segment::Field(f(1))]]).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::KindMismatch { path: 0 }));

    // Inside a converted interior too — the second path designates
    // the scalar, and the trail quotes the conversion crossing.
    let paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(2))], &[Segment::Field(f(2)), Segment::Field(f(3))]];
    let fault = convert(&h("12 02 1801"), &paths).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::KindMismatch { path: 1 }));
    assert_eq!(fault.trail().len(), 1);
    assert_eq!(fault.trail()[0].field(), f(2));
    assert_eq!(fault.trail()[0].at(), 0);
}

#[test]
fn converging_designations_convert_once_and_quote_the_lowest_path() {
    // Two program paths — a direct spelling and a wildcard one —
    // converge on the same f2 occurrence inside f1. The
    // single-action fold's promise: one conversion per occurrence
    // (converging paths agree by construction), never a double
    // re-framing.
    let route = [f(1)];
    let converging: [&[Segment<'_>]; 2] = [
        &[Segment::Field(f(1)), Segment::Field(f(2))],
        &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
    ];
    // LEN f1 [ LEN f2 [ varint f3=1 ] ]
    let (out, stats) = convert(&h("0A 04 12 02 1801"), &converging).unwrap();
    assert_eq!(out, h("0A 04 13 1801 14"));
    assert_eq!(stats.converted(), 1, "converging paths convert the occurrence once");

    // The mismatch arm quotes the lowest converging path: ids 1
    // and 2 converge on the scalar f2 (id 0 designates elsewhere),
    // so the fault names 1.
    let converging_scalar: [&[Segment<'_>]; 3] = [
        &[Segment::Field(f(9))],
        &[Segment::Field(f(1)), Segment::Field(f(2))],
        &[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))],
    ];
    let fault = convert(&h("0A 02 1001"), &converging_scalar).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::KindMismatch { path: 1 }));
}

#[test]
fn wildcard_designations_convert_at_every_committed_depth() {
    // **(via f1)/f2: every f2 along the f1 route re-frames.
    let route = [f(1)];
    let paths: [&[Segment<'_>]; 1] =
        [&[Segment::AnyDepth { descend: &route }, Segment::Field(f(2))]];
    // LEN f1 [ LEN f2 [ varint f3=7 ] · varint f3=1 ] ·
    // LEN f2 [ varint f1=7 ]
    let (out, stats) = convert(&h("0A 06 12 02 1807 1801 12 02 0807"), &paths).unwrap();
    // Top-level f2 converts (zero crossings) and the nested one
    // converts under the crossed f1.
    assert_eq!(out, h("0A 06 13 1807 14 1801 13 0807 14"));
    assert_eq!((stats.converted(), stats.descended()), (2, 1));
}

#[test]
fn repeated_designated_occurrences_each_convert() {
    let (out, stats) = convert(&h("12 02 0801 12 02 1002"), &[&[Segment::Field(f(2))]]).unwrap();
    assert_eq!(out, h("13 0801 14 13 1002 14"));
    assert_eq!(stats.converted(), 2);
}

#[test]
fn converted_interiors_are_committed_and_fault_for_real() {
    // The designated payload is one lone continuation byte: no
    // lawful record head — a real fault with the crossing trail.
    let fault = convert(&h("12 01 FF"), &[&[Segment::Field(f(2))]]).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Varint)));
    assert_eq!(fault.trail().len(), 1);
    assert_eq!(fault.trail()[0].field(), f(2));
}

#[test]
fn conversions_spend_the_container_depth_budget() {
    // With a budget of one, the crossing spends it and the nested
    // designation has none left.
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1)), Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    let tight = Converter::new(Standard::Tolerant, DepthLimit::MIN, program);
    let fault = tight.convert(&h("0A 04 12 02 1807")).unwrap_err();
    assert_eq!(fault.at(), 2);
    let FaultKind::Wire(breach) = fault.kind() else { panic!("a wire breach") };
    assert_eq!(breach, WireBreach::Depth);
    assert_eq!(breach.class(), FaultClass::Policy);

    // A top-level designation under the same budget is lawful.
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    let tight = Converter::new(Standard::Tolerant, DepthLimit::MIN, program);
    assert!(tight.convert(&h("12 02 1807")).is_ok());
}

#[test]
fn group_codes_in_the_input_are_the_capability_refusal() {
    let fault = convert(&h("0B 0C"), &[]).unwrap_err();
    assert_eq!(fault.at(), 0);
    let FaultKind::Wire(breach) = fault.kind() else { panic!("a wire breach") };
    assert_eq!(breach, WireBreach::GroupCode);
    assert_eq!(breach.class(), FaultClass::Capability);
}

#[test]
fn the_canonical_standard_refuses_padded_input_words() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    // The designated record's prefix is padded (0x02 as two
    // bytes).
    let msg = h("12 8200 1807");
    let strict = Converter::new(Standard::CanonicalMinimal, D, program);
    let fault = strict.convert(&msg).unwrap_err();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::NonMinimal)));

    // Tolerant: the padded framing is dropped whole — the authored
    // group framing is minimal, so the padding vanishes with it.
    let tolerant = Converter::new(Standard::Tolerant, D, program);
    let (out, _) = tolerant.convert(&msg).unwrap();
    assert_eq!(out, h("13 1807 14"));

    // A padded word the conversion does not touch rides verbatim.
    let msg = h("08 8100 12 00");
    let (out, _) = tolerant.convert(&msg).unwrap();
    assert_eq!(out, h("08 8100 13 14"));
}

#[cfg(feature = "traverse-grouped")]
#[test]
fn output_re_ingests_under_the_grouped_dialect_with_lawful_pairing() {
    use crate::cursor::GroupDepth;
    use crate::cursor::grouped::{Cursor as Grouped, EntryKind as GroupedKind};

    let paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(2))], &[Segment::Field(f(2)), Segment::Field(f(4))]];
    let (out, _) = convert(&h("12 04 22 02 0801 08 07"), &paths).unwrap();
    let entries: Vec<_> = Grouped::over(&out, GroupDepth::REFERENCE)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .expect("converted output walks clean under the grouped language");
    let enters = entries.iter().filter(|e| matches!(e.kind(), GroupedKind::GroupEnter)).count();
    let exits = entries.iter().filter(|e| matches!(e.kind(), GroupedKind::GroupExit)).count();
    assert_eq!((enters, exits), (2, 2), "authored framing pairs");
}

#[cfg(feature = "convert-groupless")]
#[test]
fn conversion_round_trips_through_the_groupless_cell() {
    use crate::convert::groupless::Converter as ToGroupless;

    // Minimally framed input: LEN → group → LEN is the exact
    // identity (the groupless cell re-authors the framing this
    // cell dropped, and minimal framing is the fixed point).
    let input = h("08 9601 12 04 22 02 0801 12 02 1002");
    let paths: [&[Segment<'_>]; 2] =
        [&[Segment::Field(f(2))], &[Segment::Field(f(2)), Segment::Field(f(4))]];
    let (grouped, stats) = convert(&input, &paths).unwrap();
    let back = ToGroupless::new(Standard::Tolerant, D);
    let (round, back_stats) = back.convert(&grouped).unwrap();
    assert_eq!(round, input);
    // Every group the forward direction authored converts back.
    assert_eq!(back_stats.converted(), stats.converted());
}

#[test]
fn convert_into_appends_and_is_untouched_on_err() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    let converter = Converter::new(Standard::Tolerant, D, program);
    let mut out = h("FF");
    converter.convert_into(&h("12 00"), &mut out).unwrap();
    assert_eq!(out, h("FF 13 14"));

    let before = out.clone();
    // A designated scalar: the schema error leaves `out` whole.
    assert!(converter.convert_into(&h("10 01"), &mut out).is_err());
    assert_eq!(out, before);
}

#[test]
fn the_sink_face_hands_the_buffered_bytes_and_nothing_on_err() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();
    let converter = Converter::new(Standard::Tolerant, D, program);
    let msg = h("08 9601 12 02 1801 22 02 6869");
    let (buffered, buffered_stats) = converter.convert(&msg).unwrap();

    let mut handed = Vec::new();
    let stats = converter.convert_sink(&msg, |bytes| handed.extend_from_slice(bytes)).unwrap();
    assert_eq!(handed, buffered);
    assert_eq!(stats, buffered_stats);

    // A late schema fault: the sink saw nothing.
    let mut handed = Vec::new();
    assert!(
        converter
            .convert_sink(&h("22 00 12 01 61 08 01"), |bytes| handed.extend_from_slice(bytes))
            .is_err()
    );
    assert!(handed.is_empty());
}
