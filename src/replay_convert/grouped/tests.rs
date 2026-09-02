use alloc::vec::Vec;

use super::*;
use crate::path::Segment;
use crate::replay_source::{SliceFault, SliceSource};
use crate::wire::PayloadLen;

const D: DepthLimit = DepthLimit::REFERENCE;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

/// The doc example through all three faces: the byte pins agree.
#[test]
fn the_three_faces_agree_on_one_conversion() {
    // varint f1=150 · LEN f2 [ varint f3=1 ]
    let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x18, 0x01];
    let expected = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(2))]];
    let program = Program::over(&paths).unwrap();

    let (fresh, stats) =
        convert(&mut SliceSource::new(&msg), program, Standard::Tolerant, D).unwrap();
    assert_eq!(fresh, expected);
    assert_eq!((stats.converted(), stats.descended()), (1, 0));

    let mut appended = alloc::vec![0xEE];
    let into_stats =
        convert_into(&mut SliceSource::new(&msg), program, Standard::Tolerant, D, &mut appended)
            .unwrap();
    assert_eq!(appended[0], 0xEE);
    assert_eq!(&appended[1..], expected);
    assert_eq!(into_stats, stats);

    let mut handed = Vec::new();
    let sink_stats =
        convert_sink(&mut SliceSource::new(&msg), program, Standard::Tolerant, D, |view| {
            handed.extend_from_slice(view)
        })
        .unwrap();
    assert_eq!(handed, expected);
    assert_eq!(sink_stats, stats);
}

/// The settle boundary at production granularity: the measuring
/// machine's layer close drives the crossed-prefix settle with
/// seeded logical totals (`copy_to` books length without bytes),
/// so the LEN-class cap, the fault coordinate, and the trail are
/// judged with no giant source in play.
#[test]
fn a_resized_interior_settles_at_the_len_class_top_and_refuses_one_past() {
    let seed = |interior: u64| -> Result<(), JobFault<SliceFault>> {
        let bytes: [u8; 0] = [];
        let mut source = SliceSource::new(&bytes);
        let walk = source.begin().unwrap();
        let none: [&[Segment<'_>]; 0] = [];
        let mut machine = Machine {
            pump: Pump::new(walk),
            matcher: Matcher::new(Program::over(&none).unwrap()),
            script: Script::new(),
            stack: Vec::new(),
            limit: D,
            stats: Stats::default(),
        };
        // An enclosing converted layer (the trail element) around
        // the crossed layer whose interior the seed resizes.
        machine.matcher.commit_descent();
        machine.stack.push(Frame {
            field: f(7),
            at: 0,
            interior: 2,
            declared: u64::MAX - 2,
            prev_zone: u64::MAX,
            kind: FrameKind::Convert,
        });
        machine.script.copy_to(3);
        let slot = machine.script.open_prefix(3, 4);
        machine.matcher.commit_descent();
        machine.stack.push(Frame {
            field: f(1),
            at: 2,
            interior: 4,
            declared: 100,
            prev_zone: u64::MAX,
            kind: FrameKind::Cross { slot, mark: machine.script.out_len() },
        });
        machine.script.copy_to(4 + interior);
        machine.close_frame()
    };

    let top = u64::from(PayloadLen::MAX.as_inner());
    assert!(seed(top).is_ok(), "the class top settles");

    let fault = seed(top + 1).unwrap_err();
    let JobFault::Document(fault) = fault else { panic!("a document fault was expected") };
    assert_eq!(fault.at(), 2, "Growth names the crossed record's head");
    assert!(matches!(fault.kind(), FaultKind::Growth { len } if len == top + 1));
    assert_eq!(fault.trail().len(), 1, "the enclosing converted layer is a commitment");
    assert_eq!(fault.trail()[0].field(), f(7));
    assert_eq!(fault.trail()[0].at(), 0);
}

/// A crossed prefix re-settles in place, wider, and narrower —
/// the three settle arms pinned on real bytes.
#[test]
fn a_crossed_prefix_settles_held_wider_and_narrower_interiors() {
    let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f(1)), Segment::Field(f(16))]];
    let program = Program::over(&paths).unwrap();

    // Held, padded: LEN f1 (prefix 4 spelled over two bytes)
    // [ LEN f2 [ varint f3=7 ] ] — f2 is neither designated nor
    // routed inside the crossing, so the interior length holds and
    // the padded prefix rides byte-verbatim.
    let held = alloc::vec![0x0A, 0x84, 0x00, 0x12, 0x02, 0x18, 0x07];
    // Wider: LEN f1 [ LEN f16 [62 varint records] ] — the
    // committed interior is walked, and the converted extent
    // crosses the one-byte prefix boundary (127 → 128).
    let mut wider = alloc::vec![0x0A, 0x7F, 0x82, 0x01, 0x7C];
    for _ in 0..62 {
        wider.extend_from_slice(&[0x08, 0x01]);
    }
    // Narrower: a padded crossed prefix (3 spelled over two bytes)
    // whose resized interior re-authors minimally.
    let narrower = alloc::vec![0x0A, 0x83, 0x00, 0x82, 0x01, 0x00];

    let (out, _) = convert(&mut SliceSource::new(&held), program, Standard::Tolerant, D).unwrap();
    assert_eq!(out, held, "an unchanged crossed prefix rides verbatim, padding included");
    let (out, _) = convert(&mut SliceSource::new(&wider), program, Standard::Tolerant, D).unwrap();
    assert_eq!(out[..5], [0x0A, 0x80, 0x01, 0x83, 0x01], "the prefix widened minimally");
    assert_eq!(
        out.len(),
        wider.len() + 2,
        "framing re-authored: -3 dropped, +4 authored, +1 prefix"
    );
    let (out, _) =
        convert(&mut SliceSource::new(&narrower), program, Standard::Tolerant, D).unwrap();
    assert_eq!(
        out,
        [0x0A, 0x04, 0x83, 0x01, 0x84, 0x01],
        "the padded prefix re-authored minimally"
    );
}
