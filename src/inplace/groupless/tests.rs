use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::inplace::{Action, Rule, RuleSet, Stats};
use crate::path::Segment;
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::{DepthLimit, FieldNumber, Standard};

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

const F1: FieldNumber = FieldNumber::new(1).unwrap();
const P1: &[Segment<'static>] = &[Segment::Field(F1)];

/// One tolerant job over a fresh set (the plain door).
fn t(buf: &mut [u8], rules: &[Rule<'_>]) -> Result<Stats, Fault> {
    apply(buf, &RuleSet::over(rules).unwrap(), DepthLimit::REFERENCE)
}

/// One canonical job over a fresh set.
fn c(buf: &mut [u8], rules: &[Rule<'_>]) -> Result<Stats, Fault> {
    apply_standard(
        buf,
        &RuleSet::over(rules).unwrap(),
        Standard::CanonicalMinimal,
        DepthLimit::REFERENCE,
    )
}

const fn set1(value: u64) -> Rule<'static> {
    Rule { path: P1, action: Action::SetVarint(value) }
}

// ─── width laws, per action × standard ───

#[test]
fn set_varint_pads_narrower_values_under_tolerant() {
    // The met slot is two bytes: a one-byte value lands padded, a
    // two-byte value lands minimal, a three-byte value refuses.
    let mut msg = [0x08, 0x96, 0x01];
    assert_eq!(t(&mut msg, &[set1(7)]).unwrap().replaced(), 1);
    assert_eq!(msg, [0x08, 0x87, 0x00]);

    let mut msg = [0x08, 0x96, 0x01];
    t(&mut msg, &[set1(300)]).unwrap();
    assert_eq!(msg, [0x08, 0xAC, 0x02]);

    let mut msg = [0x08, 0x96, 0x01];
    let fault = t(&mut msg, &[set1(16_384)]).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::ValueWidth { rule: 0, need: 3, have: 2 }));
    assert_eq!(msg, [0x08, 0x96, 0x01]);
}

#[test]
fn set_varint_requires_the_exact_width_under_canonical() {
    // Canonical admission makes every met slot minimal, so only
    // equal-width values fit — narrower refuses where tolerant
    // pads.
    let mut msg = [0x08, 0x96, 0x01];
    c(&mut msg, &[set1(200)]).unwrap();
    assert_eq!(msg, [0x08, 0xC8, 0x01]);

    let mut msg = [0x08, 0x96, 0x01];
    let fault = c(&mut msg, &[set1(7)]).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::ValueWidth { rule: 0, need: 1, have: 2 }));

    // Padded input refuses at admission, scan-parity: the value
    // site's first byte.
    let mut padded = [0x08, 0x96, 0x81, 0x00];
    let fault = c(&mut padded, &[set1(150)]).unwrap_err();
    assert_eq!(fault.at(), 1);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::NonMinimal)));
    assert_eq!(padded, [0x08, 0x96, 0x81, 0x00]);
}

#[test]
fn fixed_width_bits_always_fit() {
    // Width four equals four and eight equals eight — no width
    // judgment exists for the fixed kinds, under either standard.
    let one = [Segment::Field(f(1))];
    let two = [Segment::Field(f(2))];
    let msg = [0x0D, 0x01, 0x00, 0x00, 0x00, 0x11, 0x02, 0, 0, 0, 0, 0, 0, 0];
    let rules = [
        Rule { path: &one, action: Action::SetI32(0xAABB_CCDD) },
        Rule { path: &two, action: Action::SetI64(0x0102_0304_0506_0708) },
    ];
    for job in [t, c] {
        let mut buf = msg;
        assert_eq!(job(&mut buf, &rules).unwrap().replaced(), 2);
        assert_eq!(
            buf,
            [0x0D, 0xDD, 0xCC, 0xBB, 0xAA, 0x11, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }
}

#[test]
fn set_payload_requires_the_exact_extent() {
    let two = [Segment::Field(f(2))];
    // Equal length lands; the prefix and tag ride verbatim.
    let mut msg = [0x12, 0x02, 0x68, 0x69];
    let rules = [Rule { path: &two, action: Action::SetPayload(b"no") }];
    assert_eq!(t(&mut msg, &rules).unwrap().replaced(), 1);
    assert_eq!(msg, [0x12, 0x02, b'n', b'o']);

    // Longer and shorter refuse under both standards — bytes have
    // no padded spelling.
    for (bytes, need) in [(&b"xyz"[..], 3), (&b""[..], 0)] {
        let rules = [Rule { path: &two, action: Action::SetPayload(bytes) }];
        for job in [t, c] {
            let mut msg = [0x12, 0x02, 0x68, 0x69];
            let fault = job(&mut msg, &rules).unwrap_err();
            assert_eq!(fault.at(), 0);
            assert!(matches!(
                fault.kind(),
                FaultKind::PayloadLength { rule: 0, need: n, have: 2 } if n == need
            ));
            assert_eq!(msg, [0x12, 0x02, 0x68, 0x69]);
        }
    }

    // The empty extent hosts exactly the empty payload.
    let mut empty = [0x12, 0x00];
    let rules = [Rule { path: &two, action: Action::SetPayload(b"") }];
    assert_eq!(t(&mut empty, &rules).unwrap().replaced(), 1);
    assert_eq!(empty, [0x12, 0x00]);
}

#[test]
fn kind_gates_refuse_mismatched_actions() {
    let one = [Segment::Field(f(1))];
    let varint_doc = [0x08, 0x05];
    let i32_doc = [0x0D, 0x01, 0x02, 0x03, 0x04];
    let len_doc = [0x0A, 0x01, 0x41];
    let cases: [(&[u8], Action<'_>); 6] = [
        (&i32_doc, Action::SetVarint(1)),
        (&varint_doc, Action::SetI32(1)),
        (&i32_doc, Action::SetI64(1)),
        (&varint_doc, Action::SetPayload(b"x")),
        (&len_doc, Action::SetVarint(1)),
        (&len_doc, Action::SetI64(1)),
    ];
    for (doc, action) in cases {
        let mut buf = doc.to_vec();
        let fault = t(&mut buf, &[Rule { path: &one, action }]).unwrap_err();
        assert_eq!(fault.at(), 0, "{action:?}");
        assert!(matches!(fault.kind(), FaultKind::KindMismatch { rule: 0 }), "{action:?}");
        assert_eq!(buf, doc);
    }
}

#[test]
fn renumber_rewrites_the_tag_at_the_met_width() {
    let one = [Segment::Field(f(1))];
    // Same-width renumber: the tag byte moves, the value rides.
    let mut msg = [0x08, 0x96, 0x01];
    let rules = [Rule { path: &one, action: Action::Renumber(f(2)) }];
    assert_eq!(t(&mut msg, &rules).unwrap().renumbered(), 1);
    assert_eq!(msg, [0x10, 0x96, 0x01]);

    // A wider tag word refuses.
    let mut msg = [0x08, 0x96, 0x01];
    let rules = [Rule { path: &one, action: Action::Renumber(f(16)) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert!(matches!(fault.kind(), FaultKind::TagWidth { rule: 0, need: 2, have: 1 }));

    // A padded tag slot (tolerant input) pads the new word out to
    // the met width.
    let mut padded = [0x88, 0x00, 0x96, 0x01];
    let rules = [Rule { path: &one, action: Action::Renumber(f(2)) }];
    assert_eq!(t(&mut padded, &rules).unwrap().renumbered(), 1);
    assert_eq!(padded, [0x90, 0x00, 0x96, 0x01]);

    // The kind is preserved: a LEN record renumbers to a LEN tag.
    let two = [Segment::Field(f(2))];
    let mut len = [0x12, 0x02, 0x68, 0x69];
    let rules = [Rule { path: &two, action: Action::Renumber(f(3)) }];
    assert_eq!(t(&mut len, &rules).unwrap().renumbered(), 1);
    assert_eq!(len, [0x1A, 0x02, 0x68, 0x69]);

    // Canonical: the exact width alone fits.
    let mut msg = [0x08, 0x96, 0x01];
    let rules = [Rule { path: &one, action: Action::Renumber(f(15)) }];
    assert_eq!(c(&mut msg, &rules).unwrap().renumbered(), 1);
    assert_eq!(msg, [0x78, 0x96, 0x01]);
    let mut msg = [0x08, 0x96, 0x01];
    let rules = [Rule { path: &one, action: Action::Renumber(f(16)) }];
    assert!(matches!(
        c(&mut msg, &rules).unwrap_err().kind(),
        FaultKind::TagWidth { rule: 0, need: 2, have: 1 }
    ));
}

// ─── the tombstone boundary battery ───

/// Drives one tombstone over a target of extent `W` and pins the
/// exact filler bytes the solvability theorem derives, plus
/// re-ingestion under the declared standard and the untouched
/// neighborhood.
fn tombstone_case(standard: Standard, target: &[u8], target_field: u32, filler: &[u8]) {
    assert_eq!(target.len(), filler.len(), "the filler tiles the extent exactly");
    let neighbor = [0x28, 0x07]; // varint f5=7
    let mut doc = Vec::from(target);
    doc.extend_from_slice(&neighbor);
    let path = [Segment::Field(f(target_field))];
    let rules = [Rule { path: &path, action: Action::Tombstone { field: f(1) } }];
    let set = RuleSet::over(&rules).unwrap();
    let stats = apply_standard(&mut doc, &set, standard, DepthLimit::REFERENCE).unwrap();
    assert_eq!(stats.tombstoned(), 1, "W = {}", target.len());
    assert_eq!(&doc[..target.len()], filler, "W = {}", target.len());
    assert_eq!(&doc[target.len()..], &neighbor, "W = {}", target.len());
    // The output re-ingests under the declared standard, and every
    // filler record carries the declared field.
    let mut fillers = 0;
    let mut judge = |entry: crate::cursor::groupless::Entry<'_>| {
        if entry.field() == f(1) {
            fillers += 1;
            match entry.kind() {
                EntryKind::Varint(value) => assert_eq!(value, 0),
                EntryKind::Len(payload) => assert!(payload.iter().all(|&b| b == 0)),
                observed => panic!("unexpected filler kind {observed:?}"),
            }
        } else {
            assert_eq!(entry.field(), f(5));
        }
    };
    // Each standard's engine instance through the crate-side step
    // face (the public canonical twin is the traverse cell's own
    // face).
    let mut cursor = Cursor::over(&doc).unwrap();
    match standard {
        Standard::Tolerant => {
            while let Some(entry) = cursor.step::<false>() {
                judge(entry.unwrap());
            }
        }
        Standard::CanonicalMinimal => {
            while let Some(entry) = cursor.step::<true>() {
                judge(entry.unwrap());
            }
        }
    }
    assert!(fillers >= 1, "the tombstone authored at least one filler record");
}

/// A LEN target of field 2 (tag `0x12`) whose prefix spells
/// `payload_len` over `prefix` bytes (padded when wider than
/// minimal), payload filled with `0xAA`.
fn len_target(prefix_bytes: &[u8], payload_len: usize) -> Vec<u8> {
    let mut target = vec![0x12];
    target.extend_from_slice(prefix_bytes);
    target.extend(core::iter::repeat_n(0xAA, payload_len));
    target
}

#[test]
fn tombstone_boundaries_solve_under_tolerant() {
    // W = 2, 3: varint targets; the filler is the padded varint.
    tombstone_case(Standard::Tolerant, &[0x10, 0x00], 2, &[0x08, 0x00]);
    tombstone_case(Standard::Tolerant, &[0x10, 0x96, 0x01], 2, &[0x08, 0x80, 0x00]);
    // W = 11: the widest one-varint filler (value zero at ten).
    tombstone_case(
        Standard::Tolerant,
        &len_target(&[0x09], 9),
        2,
        &[0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
    );
    // W = 129, 130, 131: LEN fillers, prefix padded to the full
    // window (the tolerant shape has no gap set).
    let filler = |prefix: &[u8], zeros: usize| {
        let mut filler = vec![0x0A];
        filler.extend_from_slice(prefix);
        filler.extend(core::iter::repeat_n(0, zeros));
        filler
    };
    tombstone_case(
        Standard::Tolerant,
        &len_target(&[0x7F], 127),
        2,
        &filler(&[0xFB, 0x80, 0x80, 0x80, 0x00], 123),
    );
    // The 130-byte tolerant target pads its own prefix — lawful
    // reference wire.
    tombstone_case(
        Standard::Tolerant,
        &len_target(&[0xFF, 0x00], 127),
        2,
        &filler(&[0xFC, 0x80, 0x80, 0x80, 0x00], 124),
    );
    tombstone_case(
        Standard::Tolerant,
        &len_target(&[0x80, 0x01], 128),
        2,
        &filler(&[0xFD, 0x80, 0x80, 0x80, 0x00], 125),
    );
    // W = 16385, 16386: the two-byte-prefix class.
    tombstone_case(
        Standard::Tolerant,
        &len_target(&[0xFE, 0x7F], 16_382),
        2,
        &filler(&[0xFB, 0xFF, 0x80, 0x80, 0x00], 16_379),
    );
    tombstone_case(
        Standard::Tolerant,
        &len_target(&[0xFF, 0x7F], 16_383),
        2,
        &filler(&[0xFC, 0xFF, 0x80, 0x80, 0x00], 16_380),
    );
}

#[test]
fn tombstone_boundaries_solve_under_canonical() {
    let filler = |head: &[u8], zeros: usize| {
        let mut filler = Vec::from(head);
        filler.extend(core::iter::repeat_n(0, zeros));
        filler
    };
    // W = 2: the one-byte varint filler; W = 3: the smallest LEN
    // filler (a two-byte varint value would be non-minimal).
    tombstone_case(Standard::CanonicalMinimal, &[0x10, 0x00], 2, &[0x08, 0x00]);
    tombstone_case(Standard::CanonicalMinimal, &[0x10, 0x96, 0x01], 2, &[0x0A, 0x01, 0x00]);
    tombstone_case(
        Standard::CanonicalMinimal,
        &len_target(&[0x09], 9),
        2,
        &filler(&[0x0A, 0x09], 9),
    );
    // W = 129: the one-byte-prefix class top.
    tombstone_case(
        Standard::CanonicalMinimal,
        &len_target(&[0x7F], 127),
        2,
        &filler(&[0x0A, 0x7F], 127),
    );
    // W = 130 (interior 129 = 2^7 + 1, the first gap): the pair
    // split — one minimal varint filler peels the extent into a
    // solvable remainder. The canonical 130-byte target needs a
    // two-byte tag (extent 130 is off the one-byte-tag record
    // grammar), so the target is field 16.
    let mut target = vec![0x82, 0x01, 0x7F];
    target.extend(core::iter::repeat_n(0xAA, 127));
    tombstone_case(
        Standard::CanonicalMinimal,
        &target,
        16,
        &filler(&[0x08, 0x00, 0x0A, 0x7E], 126),
    );
    // W = 131: past the gap, minimal two-byte prefix.
    tombstone_case(
        Standard::CanonicalMinimal,
        &len_target(&[0x80, 0x01], 128),
        2,
        &filler(&[0x0A, 0x80, 0x01], 128),
    );
    // W = 16385, 16386: up to the two-byte-prefix class top (the
    // next gap sits one past it).
    tombstone_case(
        Standard::CanonicalMinimal,
        &len_target(&[0xFE, 0x7F], 16_382),
        2,
        &filler(&[0x0A, 0xFE, 0x7F], 16_382),
    );
    tombstone_case(
        Standard::CanonicalMinimal,
        &len_target(&[0xFF, 0x7F], 16_383),
        2,
        &filler(&[0x0A, 0xFF, 0x7F], 16_383),
    );
}

#[test]
fn filler_unfit_pins_the_two_byte_record_pair() {
    // A two-byte record cannot host a field-16 filler (three-byte
    // minimum) and exactly hosts a field-15 one.
    let one = [Segment::Field(f(1))];
    let mut msg = [0x08, 0x00];
    let rules = [Rule { path: &one, action: Action::Tombstone { field: f(16) } }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::FillerUnfit { rule: 0, need: 3, have: 2 }));
    assert_eq!(msg, [0x08, 0x00]);

    let rules = [Rule { path: &one, action: Action::Tombstone { field: f(15) } }];
    assert_eq!(t(&mut msg, &rules).unwrap().tombstoned(), 1);
    assert_eq!(msg, [0x78, 0x00]);
}

// ─── whole-record replacement ───

#[test]
fn replace_record_substitutes_kind_crossing_and_compound_records() {
    let one = [Segment::Field(f(1))];
    // Kind-crossing at equal extent: varint → LEN.
    let mut msg = [0x08, 0x96, 0x01];
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&[0x0A, 0x01, 0x41]) }];
    assert_eq!(t(&mut msg, &rules).unwrap().substituted(), 1);
    assert_eq!(msg, [0x0A, 0x01, 0x41]);

    // Compound (renumber + new value) in one record.
    let mut msg = [0x08, 0x96, 0x01];
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&[0x10, 0xC8, 0x03]) }];
    assert_eq!(c(&mut msg, &rules).unwrap().substituted(), 1);
    assert_eq!(msg, [0x10, 0xC8, 0x03]);

    // LEN → varint at equal extent, canonical-lawful.
    let two = [Segment::Field(f(2))];
    let mut msg = [0x12, 0x02, 0x68, 0x69];
    let rules = [Rule { path: &two, action: Action::ReplaceRecord(&[0x08, 0x80, 0x80, 0x01]) }];
    assert_eq!(c(&mut msg, &rules).unwrap().substituted(), 1);
    assert_eq!(msg, [0x08, 0x80, 0x80, 0x01]);
}

#[test]
fn replace_record_refusals_carry_both_coordinate_frames() {
    // The target sits at offset 2, so the fault's own coordinate
    // (source-relative) and the candidate-relative one differ.
    let one = [Segment::Field(f(1))];
    let doc = [0x28, 0x07, 0x08, 0x96, 0x01];

    // Length mismatch.
    let mut msg = doc;
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&[0x08, 0x00]) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::ReplacementLength { rule: 0, need: 2, have: 3 }));
    assert_eq!(msg, doc);

    // A candidate wire refusal quotes its own byte coordinate: the
    // LEN claims five bytes where the candidate holds one, refused
    // at the candidate's payload start.
    let mut msg = doc;
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&[0x0A, 0x05, 0x41]) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(
        fault.kind(),
        FaultKind::ReplacementWire { rule: 0, at: 2, breach: WireBreach::Truncated }
    ));

    // A group code inside the candidate is the capability refusal.
    let mut msg = doc;
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&[0x0B, 0x0C, 0x00]) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert!(matches!(
        fault.kind(),
        FaultKind::ReplacementWire { rule: 0, at: 0, breach: WireBreach::GroupCode }
    ));

    // Two records inside the extent are not one record.
    let two = [Segment::Field(f(2))];
    let mut msg = [0x12, 0x02, 0x68, 0x69];
    let rules = [Rule { path: &two, action: Action::ReplaceRecord(&[0x08, 0x00, 0x08, 0x00]) }];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::ReplacementShape { rule: 0 }));

    // The candidate is judged under the job's standard: a padded
    // word lands under Tolerant and refuses under CanonicalMinimal.
    let padded = [0x08, 0x80, 0x00];
    let rules = [Rule { path: &one, action: Action::ReplaceRecord(&padded) }];
    let mut msg = doc;
    assert_eq!(t(&mut msg, &rules).unwrap().substituted(), 1);
    assert_eq!(msg[2..], padded);
    let mut msg = doc;
    let fault = c(&mut msg, &rules).unwrap_err();
    assert!(matches!(
        fault.kind(),
        FaultKind::ReplacementWire { rule: 0, at: 1, breach: WireBreach::NonMinimal }
    ));
}

// ─── ownership, conflicts, liveness ───

#[test]
fn wholly_overwritten_interiors_fire_no_rules() {
    // SetPayload, Tombstone, and ReplaceRecord own the record: the
    // interior rule fires nowhere, silently — the zero count is
    // the signal.
    let container = [Segment::Field(f(2))];
    let interior = [Segment::Field(f(2)), Segment::Field(f(1))];
    let doc = [0x12, 0x02, 0x08, 0x01];

    // The expected `replaced` count is the container's own landing
    // (SetPayload counts there; the others count elsewhere) — the
    // interior rule adding one more is exactly the breach judged.
    let cases: [(Action<'_>, [u8; 4], u32); 3] = [
        (Action::SetPayload(b"XY"), [0x12, 0x02, b'X', b'Y'], 1),
        (Action::Tombstone { field: f(9) }, [0x48, 0x80, 0x80, 0x00], 0),
        (Action::ReplaceRecord(&[0x0A, 0x02, 0x41, 0x42]), [0x0A, 0x02, 0x41, 0x42], 0),
    ];
    for (action, expected, own) in cases {
        let mut msg = doc;
        let rules = [
            Rule { path: &container, action },
            Rule { path: &interior, action: Action::SetVarint(9) },
        ];
        let stats = t(&mut msg, &rules).unwrap();
        assert_eq!(msg, expected, "{action:?}");
        assert_eq!(stats.replaced(), own, "the interior rule fired under {action:?}");
    }
}

#[test]
fn renumbered_containers_keep_their_interiors_live() {
    // A renumber touches the tag alone, so the interior stays
    // subject to the walk — both rules land, at disjoint extents.
    let container = [Segment::Field(f(2))];
    let interior = [Segment::Field(f(2)), Segment::Field(f(1))];
    let mut msg = [0x12, 0x02, 0x08, 0x01];
    let rules = [
        Rule { path: &container, action: Action::Renumber(f(3)) },
        Rule { path: &interior, action: Action::SetVarint(9) },
    ];
    let stats = t(&mut msg, &rules).unwrap();
    assert_eq!(msg, [0x1A, 0x02, 0x08, 0x09]);
    assert_eq!((stats.renumbered(), stats.replaced()), (1, 1));
}

#[test]
fn two_rules_on_one_record_conflict() {
    // Distinct patterns, one record: the wildcard also matches
    // zero crossings, so both rules target the top-level f1.
    let route = [f(3)];
    let direct = [Segment::Field(f(1))];
    let wild = [Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];
    let mut msg = [0x08, 0x00];
    let rules = [
        Rule { path: &direct, action: Action::SetVarint(1) },
        Rule { path: &wild, action: Action::SetVarint(2) },
    ];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 0);
    assert!(matches!(fault.kind(), FaultKind::Conflict { first: 0, second: 1 }));
    assert_eq!(msg, [0x08, 0x00]);
}

// ─── transactionality and the untouched complement ───

#[test]
fn every_refusal_leaves_the_buffer_byte_identical() {
    // One representative per fault class; the snapshot equality is
    // the transaction promise (nothing was written), not a repair.
    let one: &[Segment<'_>] = &[Segment::Field(f(1))];
    let two: &[Segment<'_>] = &[Segment::Field(f(2))];
    let deep: &[Segment<'_>] = &[Segment::Field(f(2)), Segment::Field(f(2)), Segment::Field(f(1))];
    let route = [f(3)];
    let wild: &[Segment<'_>] = &[Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];

    let cases: [(&[u8], Rule<'_>, &str); 9] = [
        (&[0x08], Rule { path: one, action: Action::SetVarint(1) }, "wire"),
        (&[0x0B, 0x0C], Rule { path: one, action: Action::SetVarint(1) }, "group code"),
        (&[0x0D, 1, 2, 3, 4], Rule { path: one, action: Action::SetVarint(1) }, "kind"),
        (&[0x08, 0x05], Rule { path: one, action: Action::SetVarint(300) }, "value width"),
        (&[0x08, 0x05], Rule { path: one, action: Action::Renumber(f(16)) }, "tag width"),
        (
            &[0x12, 0x02, 0x68, 0x69],
            Rule { path: two, action: Action::SetPayload(b"xyz") },
            "payload length",
        ),
        (
            &[0x08, 0x05],
            Rule { path: one, action: Action::Tombstone { field: f(16) } },
            "filler unfit",
        ),
        (
            &[0x08, 0x05],
            Rule { path: one, action: Action::ReplaceRecord(&[0x08]) },
            "replacement length",
        ),
        (&[0x12, 0x02, 0x12, 0x00], Rule { path: deep, action: Action::SetVarint(1) }, "depth"),
    ];
    for (doc, rule, label) in cases {
        let mut buf = doc.to_vec();
        let set_rules = [rule];
        let set = RuleSet::over(&set_rules).unwrap();
        let limit = if label == "depth" { DepthLimit::MIN } else { DepthLimit::REFERENCE };
        assert!(apply(&mut buf, &set, limit).is_err(), "{label} refused");
        assert_eq!(buf, doc, "{label}: buffer changed on Err");
    }
    // The conflict case carries two rules.
    let mut buf = vec![0x08, 0x00];
    let rules = [
        Rule { path: one, action: Action::SetVarint(1) },
        Rule { path: wild, action: Action::SetVarint(2) },
    ];
    assert!(t(&mut buf, &rules).is_err());
    assert_eq!(buf, [0x08, 0x00]);
}

#[test]
fn depth_refuses_exactly_past_the_budget() {
    // One committed descent under DepthLimit::MIN is lawful; the
    // second refuses at the inner container's head.
    let shallow: &[Segment<'static>] = &[Segment::Field(f(2)), Segment::Field(f(1))];
    let mut ok = [0x12, 0x02, 0x08, 0x01];
    let rules = [Rule { path: shallow, action: Action::SetVarint(9) }];
    let set = RuleSet::over(&rules).unwrap();
    assert_eq!(apply(&mut ok, &set, DepthLimit::MIN).unwrap().replaced(), 1);

    let deep: &[Segment<'static>] =
        &[Segment::Field(f(2)), Segment::Field(f(2)), Segment::Field(f(1))];
    let mut refused = [0x12, 0x02, 0x12, 0x00];
    let rules = [Rule { path: deep, action: Action::SetVarint(9) }];
    let set = RuleSet::over(&rules).unwrap();
    let fault = apply(&mut refused, &set, DepthLimit::MIN).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Depth)));
}

#[test]
fn untouched_regions_survive_byte_for_byte() {
    // Two writes in a five-record document: every byte outside the
    // two planned extents rides verbatim — including padding.
    // f1=150 · f2 "hi" · f3 (padded varint) · f4 I32 · f5 "x"
    let doc = [
        0x08, 0x96, 0x01, // f1, untouched
        0x12, 0x02, 0x68, 0x69, // f2, payload replaced (spans 5..7)
        0x18, 0x85, 0x80, 0x00, // f3, value replaced (spans 8..11)
        0x25, 0x01, 0x02, 0x03, 0x04, // f4, untouched
        0x2A, 0x01, 0x78, // f5, untouched
    ];
    let two = [Segment::Field(f(2))];
    let three = [Segment::Field(f(3))];
    let rules = [
        Rule { path: &two, action: Action::SetPayload(b"HI") },
        Rule { path: &three, action: Action::SetVarint(1) },
    ];
    let mut buf = doc;
    let stats = t(&mut buf, &rules).unwrap();
    assert_eq!(stats.replaced(), 2);
    let touched = [5usize, 6, 8, 9, 10];
    for (index, (&was, &is)) in doc.iter().zip(buf.iter()).enumerate() {
        if touched.contains(&index) {
            continue;
        }
        assert_eq!(was, is, "byte {index} moved outside the planned spans");
    }
    assert_eq!(&buf[5..7], b"HI");
    assert_eq!(&buf[8..11], [0x81, 0x80, 0x00]); // 1 padded to the met 3
}

// ─── doors, receipts, coordinates ───

#[test]
fn the_plain_door_is_the_tolerant_instance() {
    let one = [Segment::Field(f(1))];
    let rules = [Rule { path: &one, action: Action::SetVarint(7) }];
    let set = RuleSet::over(&rules).unwrap();
    let mut plain = [0x08, 0x96, 0x01];
    let mut declared = [0x08, 0x96, 0x01];
    let a = apply(&mut plain, &set, DepthLimit::REFERENCE).unwrap();
    let b = apply_standard(&mut declared, &set, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
    assert_eq!(plain, declared);
    assert_eq!(a, b);
}

#[test]
fn zero_match_jobs_leave_the_buffer_untouched_with_zero_counts() {
    let nine = [Segment::Field(f(9))];
    let rules = [Rule { path: &nine, action: Action::SetVarint(1) }];
    let doc = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let mut buf = doc;
    let stats = t(&mut buf, &rules).unwrap();
    assert_eq!(buf, doc);
    assert_eq!(stats, Stats::default());
    assert_eq!(
        (stats.replaced(), stats.renumbered(), stats.tombstoned(), stats.substituted()),
        (0, 0, 0, 0)
    );
}

#[test]
fn wire_faults_carry_absolute_coordinates_through_committed_descents() {
    // A rule routing through field 3 commits its payloads; the
    // unlawful byte inside faults at its whole-buffer coordinate.
    let route = [f(3)];
    let path = [Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];
    let rules = [Rule { path: &path, action: Action::SetVarint(1) }];
    let mut msg = [0x1A, 0x01, 0xFF];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 2);
    assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::Varint)));
    assert_eq!(fault.kind().to_string(), WireBreach::Varint.to_string());
}

#[test]
fn group_codes_refuse_as_capability() {
    let one = [Segment::Field(f(1))];
    let rules = [Rule { path: &one, action: Action::SetVarint(1) }];
    let mut msg = [0x0B, 0x0C];
    let fault = t(&mut msg, &rules).unwrap_err();
    assert_eq!(fault.at(), 0);
    let FaultKind::Wire(breach) = fault.kind() else {
        panic!("group codes surface as wire breaches");
    };
    assert_eq!(breach, WireBreach::GroupCode);
    assert_eq!(breach.class(), crate::FaultClass::Capability);
}
