use alloc::vec::Vec;

use super::*;
use crate::replay_source::SliceSource;
use crate::wire::PayloadLen;

const D: DepthLimit = DepthLimit::REFERENCE;

/// The doc example through all three faces: the byte pins agree.
#[test]
fn the_three_faces_agree_on_one_conversion() {
    // varint f1=150 · group f2 { varint f3=1 }
    let msg = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let expected = [0x08, 0x96, 0x01, 0x12, 0x02, 0x18, 0x01];

    let (fresh, stats) = convert(&mut SliceSource::new(&msg), Standard::Tolerant, D).unwrap();
    assert_eq!(fresh, expected);
    assert_eq!(stats.converted(), 1);

    let mut appended = alloc::vec![0xEE];
    let into_stats =
        convert_into(&mut SliceSource::new(&msg), Standard::Tolerant, D, &mut appended).unwrap();
    assert_eq!(appended[0], 0xEE);
    assert_eq!(&appended[1..], expected);
    assert_eq!(into_stats, stats);

    let mut handed = Vec::new();
    let sink_stats = convert_sink(&mut SliceSource::new(&msg), Standard::Tolerant, D, |view| {
        handed.extend_from_slice(view)
    })
    .unwrap();
    assert_eq!(handed, expected);
    assert_eq!(sink_stats, stats);
}

/// The settle boundary at production granularity: the measuring
/// machine's group close drives the minted-prefix settle with
/// seeded logical totals (`copy_to` books length without bytes),
/// so the LEN-class cap is judged with no giant source in play.
#[test]
fn a_group_body_settles_at_the_len_class_top_and_refuses_one_past() {
    let seed = |body: u64| -> Result<(), JobFault<crate::replay_source::SliceFault>> {
        let bytes: [u8; 0] = [];
        let mut source = SliceSource::new(&bytes);
        let walk = source.begin().unwrap();
        let mut machine = Machine {
            pump: Pump::new(walk),
            script: Script::new(),
            stack: Vec::new(),
            limit: D,
            stats: Stats::default(),
        };
        // A group of field 1 opens at offset 0; its body's logical
        // total seeds through the script's own accounting.
        machine.group_open(0, FieldNumber::new(1).unwrap())?;
        machine.script.copy_to(body);
        machine.settle_group(body, body + 1)
    };

    let top = u64::from(PayloadLen::MAX.as_inner());
    assert!(seed(top).is_ok(), "the class top settles");

    let fault = seed(top + 1).unwrap_err();
    let JobFault::Document(fault) = fault else { panic!("a document fault was expected") };
    assert_eq!(fault.at(), 0, "Growth names the group's open tag");
    assert!(matches!(fault.kind(), FaultKind::Growth { len } if len == top + 1));
}

/// The minted-prefix widths pinned on real bytes: a one-byte body
/// meets the minimal prefix, and a body past the one-byte boundary
/// settles wider — authored minimally either way.
#[test]
fn a_minted_prefix_settles_met_and_widened_bodies_minimally() {
    // group f1 { varint f2=5 }: a one-byte body — the minimal
    // width is met.
    let small = [0x0B, 0x10, 0x05, 0x0C];
    let (out, _) = convert(&mut SliceSource::new(&small), Standard::Tolerant, D).unwrap();
    assert_eq!(out, [0x0A, 0x02, 0x10, 0x05]);

    // group f1 { LEN f2 [130 bytes] }: a 133-byte converted body
    // crosses the one-byte prefix boundary.
    let mut grouped = alloc::vec![0x0B, 0x12, 0x82, 0x01];
    grouped.extend_from_slice(&[0xA5; 130]);
    grouped.push(0x0C);
    let (out, stats) = convert(&mut SliceSource::new(&grouped), Standard::Tolerant, D).unwrap();
    assert_eq!(stats.converted(), 1);
    assert_eq!(out[..4], [0x0A, 0x85, 0x01, 0x12], "a two-byte prefix authored minimally");
    assert_eq!(out.len(), 3 + 133);
}
