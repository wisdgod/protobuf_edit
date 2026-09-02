//! The groupless intake's module suite: the canonical-door pins,
//! the ownership-tenure pins, and the owned-adopt differential twin
//! on canonical inputs (identical command arcs ⇒ byte-identical
//! saves — acceptance judges the door, never the edits).

use alloc::vec::Vec;

use super::{BorrowIntake, CopyIntake, Descent, InsertAt, Intake, OpenFault, Refusal};
use crate::DepthLimit;
use crate::wire::FieldNumber;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

// ─── the canonical door ───

#[test]
fn the_door_refuses_each_padded_site_with_the_buffer_intact() {
    // A tag padded to two bytes.
    let src = alloc::vec![0x88, 0x00, 0x01];
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("a padded tag must refuse");
    };
    assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 })));
    assert_eq!(back, [0x88, 0x00, 0x01]);

    // A LEN prefix padded to two bytes.
    let src = alloc::vec![0x12, 0x81, 0x00, 0x61];
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("a padded length prefix must refuse");
    };
    assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalLen { at: 1, width: 2, .. })));
    assert_eq!(back, [0x12, 0x81, 0x00, 0x61]);

    // A varint value padded to three bytes.
    let src = alloc::vec![0x08, 0x96, 0x81, 0x00];
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("a padded varint value must refuse");
    };
    assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalValue { at: 1, width: 3, .. })));
    assert_eq!(back, [0x08, 0x96, 0x81, 0x00]);
}

#[test]
fn hidden_padding_refuses_at_descent_as_a_resident_verdict() {
    // LEN f3 whose interior carries a padded LEN prefix: opaque at
    // the door, judged at the descent commitment.
    let msg = alloc::vec![0x1A, 0x03, 0x12, 0x81, 0x00];
    let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
    let record = intake.top().next().unwrap();
    let Descent::Refused(refusal) = intake.descend(record).unwrap() else {
        panic!("the padded interior must refuse descent");
    };
    assert!(matches!(refusal, Refusal::NonMinimalLen { at: 3, width: 2, .. }));
    // The verdict is resident; the document itself still saves.
    assert_eq!(intake.save().unwrap(), [0x1A, 0x03, 0x12, 0x81, 0x00]);
}

// ─── ownership tenure ───

#[test]
fn the_buffer_moves_in_and_releases_without_a_copy() {
    let src = alloc::vec![0x08, 0x2A, 0x12, 0x02, 0x68, 0x69];
    let addr = src.as_ptr().addr();
    let mut intake = Intake::open(src, DepthLimit::REFERENCE).unwrap();
    assert_eq!(intake.source().as_ptr().addr(), addr, "open must move the buffer, not copy it");
    // Staged edits are a plan; release discards them and the bytes
    // come back exactly as they moved in.
    let first = intake.top().next().unwrap();
    intake.set_varint(first, 7).unwrap();
    let back = intake.into_source();
    assert_eq!(back.as_ptr().addr(), addr, "release must move the buffer back, not copy it");
    assert_eq!(back, [0x08, 0x2A, 0x12, 0x02, 0x68, 0x69]);
}

#[test]
fn a_refused_open_returns_the_buffer_intact() {
    // A group code: lawful wire outside this dialect.
    let src = alloc::vec![0x0B, 0x0C];
    let addr = src.as_ptr().addr();
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("a group code at the root must refuse");
    };
    assert!(matches!(fault, OpenFault::Refused(Refusal::GroupCode { at: 0, .. })));
    assert_eq!(back.as_ptr().addr(), addr, "the refusal must return the buffer, not a copy");
    assert_eq!(back, [0x0B, 0x0C]);

    // A wire-grammar fault refuses the same way.
    let src = alloc::vec![0x08];
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("a truncated record at the root must refuse");
    };
    assert!(matches!(fault, OpenFault::Wire(_)));
    assert_eq!(back, [0x08]);
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
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("an oversize buffer must refuse");
    };
    assert!(matches!(fault, OpenFault::TooLarge { len: l } if l == len));
    assert_eq!(back.as_ptr().addr(), addr, "the refusal must return the buffer, not a copy");
    assert_eq!(back.len(), len);
}

#[test]
fn a_mid_edit_intake_moves_across_frames_and_saves_after() {
    fn stage(msg: Vec<u8>) -> Intake<'static> {
        let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
        let tops: Vec<_> = intake.top().collect();
        intake.set_varint(tops[0], 7).unwrap();
        intake.delete(tops[1]).unwrap();
        intake
    }
    // varint f1=42 · varint f2=5 · LEN f3 "hi"
    let staged = stage(alloc::vec![0x08, 0x2A, 0x10, 0x05, 0x1A, 0x02, 0x68, 0x69]);
    // The plan and the source traveled together; the save happens
    // wherever the machine lands.
    assert_eq!(staged.save().unwrap(), [0x08, 0x07, 0x1A, 0x02, 0x68, 0x69]);
}

#[test]
fn the_sized_doors_refuse_class_overflow_without_allocating() {
    // The declared form's over-cap pin: the class judgment lands
    // at begin, before any reservation — no giant allocation
    // exists to build, so the pin runs on every target and under
    // Miri (the tenure-returning oversize-open twin above keeps
    // its cfg gate).
    use super::EditFault;
    use crate::admission::usize_of;
    use crate::wire::PayloadLen;

    let mut intake =
        Intake::open(alloc::vec![0x12, 0x02, 0x61, 0x62], DepthLimit::REFERENCE).unwrap();
    let record = intake.top().next().unwrap();
    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        intake.begin_set_payload_sized(record, over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert!(matches!(
        intake.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert_eq!(intake.save().unwrap(), [0x12, 0x02, 0x61, 0x62]);
}

// ─── the owned-adopt differential twin ───

/// Every save face of both machines over the same rows, compared:
/// the priced length, the fresh save, the append face, the sink
/// face, and the output-order span table.
#[cfg(feature = "adopt-groupless")]
fn saves_agree(adopt: &crate::adopt::groupless::Adopt<'_>, intake: &Intake<'_>) {
    let a = adopt.save().unwrap();
    let i = intake.save().unwrap();
    assert_eq!(a, i, "identical command arcs must save byte-identically");
    assert_eq!(adopt.save_len().unwrap(), intake.save_len().unwrap());
    assert_eq!(u64::try_from(a.len()).unwrap(), u64::from(intake.save_len().unwrap()));

    let mut appended = alloc::vec![0xEE_u8; 3];
    intake.save_into(&mut appended).unwrap();
    assert_eq!(appended[..3], [0xEE; 3]);
    assert_eq!(appended[3..], a[..]);

    let mut sunk = Vec::new();
    intake.save_sink(|bytes| sunk.extend_from_slice(bytes)).unwrap();
    assert_eq!(sunk, a);

    let a_spans: Vec<_> = adopt.save_spans().unwrap().iter().map(|(_, span)| span).collect();
    let i_spans: Vec<_> = intake.save_spans().unwrap().iter().map(|(_, span)| span).collect();
    assert_eq!(a_spans, i_spans, "the output-order span tables must agree");
}

/// The read faces of both machines over one handle pair (same
/// arena index on both sides — identical command arcs mint
/// identical rows).
#[cfg(feature = "adopt-groupless")]
fn faces_agree(
    adopt: &crate::adopt::groupless::Adopt<'_>,
    ah: crate::adopt::Handle,
    intake: &Intake<'_>,
    ih: super::Handle,
) {
    use alloc::format;

    assert_eq!(adopt.field(ah), intake.field(ih));
    assert_eq!(adopt.kind(ah), intake.kind(ih));
    assert_eq!(format!("{:?}", adopt.status(ah)), format!("{:?}", intake.status(ih)));
    assert_eq!(adopt.span(ah), intake.span(ih));
    assert_eq!(format!("{:?}", adopt.source_spans(ah)), format!("{:?}", intake.source_spans(ih)));
    assert_eq!(adopt.varint_word(ah), intake.varint_word(ih));
    assert_eq!(adopt.i32_bits(ah), intake.i32_bits(ih));
    assert_eq!(adopt.i64_bits(ah), intake.i64_bits(ih));
    assert_eq!(adopt.payload_bytes(ah), intake.payload_bytes(ih));
}

/// The full command set, applied pairwise to the tolerant adopt
/// and the canonical intake over identical minimal bytes: scalar
/// sets, payload replacement in all three supplies (borrowed,
/// copied, scatter), deletion, insertion at every anchor, descent
/// with nested edits (growth and shrink), and the staged payload
/// frames. Every save face and every read face must agree —
/// acceptance judges the door, and on bytes both doors admit the
/// machines are the same machine.
#[cfg(feature = "adopt-groupless")]
#[test]
fn identical_command_arcs_save_byte_identically() {
    use crate::adopt::groupless::{Adopt, InsertAt as AInsertAt};

    // varint f1 · i32 f2 · i64 f3 · LEN f4 "abc" · LEN f5 "hi" ·
    // LEN f6 { f9 varint 1 · f12 LEN "xy" } · varint f8 ·
    // LEN f10 "zz" (frame target) — minimal throughout, so both
    // doors admit it.
    let msg: &[u8] = &[
        0x08, 0x2A, // f1 varint 42
        0x15, 0x01, 0x02, 0x03, 0x04, // f2 i32
        0x19, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // f3 i64
        0x22, 0x03, b'a', b'b', b'c', // f4 LEN
        0x2A, 0x02, b'h', b'i', // f5 LEN
        0x32, 0x06, 0x48, 0x01, 0x62, 0x02, b'x', b'y', // f6 LEN { .. }
        0x40, 0x96, 0x01, // f8 varint 150
        0x52, 0x02, b'z', b'z', // f10 LEN
    ];

    let mut adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mut intake = Intake::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();

    let at: Vec<_> = adopt.top().collect();
    let it: Vec<_> = intake.top().collect();
    assert_eq!(at.len(), it.len());

    // Scalar replacements (the untouched f8 rides verbatim on
    // both).
    adopt.set_varint(at[0], 300).unwrap();
    intake.set_varint(it[0], 300).unwrap();
    adopt.set_i32(at[1], 0xDEAD_BEEF).unwrap();
    intake.set_i32(it[1], 0xDEAD_BEEF).unwrap();
    adopt.set_i64(at[2], 0x0102_0304_0506_0708).unwrap();
    intake.set_i64(it[2], 0x0102_0304_0506_0708).unwrap();

    // Payload replacement across all three supplies, re-sets
    // included (the last supply wins on both sides).
    adopt.set_payload(at[3], b"grown payload").unwrap();
    intake.set_payload(it[3], b"grown payload").unwrap();
    adopt.set_payload_copy(at[3], b"copied").unwrap();
    intake.set_payload_copy(it[3], b"copied").unwrap();
    static PARTS: [&[u8]; 3] = [b"sc", b"at", b"ter"];
    adopt.set_payload_parts(at[3], &PARTS).unwrap();
    intake.set_payload_parts(it[3], &PARTS).unwrap();

    // Deletion.
    adopt.delete(at[4]).unwrap();
    intake.delete(it[4]).unwrap();

    // Descent and nested edits: drop one interior record, grow the
    // other — the cascade re-authors the container prefix on both.
    let crate::adopt::groupless::Descent::Opened { first: Some(_) } = adopt.descend(at[5]).unwrap()
    else {
        unreachable!()
    };
    let Descent::Opened { first: Some(_) } = intake.descend(it[5]).unwrap() else { unreachable!() };
    let ak: Vec<_> = adopt.children(at[5]).collect();
    let ik: Vec<_> = intake.children(it[5]).collect();
    adopt.delete(ak[0]).unwrap();
    intake.delete(ik[0]).unwrap();
    adopt.set_payload(ak[1], b"longer than before").unwrap();
    intake.set_payload(ik[1], b"longer than before").unwrap();

    // Insertion at every anchor shape.
    adopt.insert_varint(AInsertAt::HeadOf(None), f(13), 7).unwrap();
    intake.insert_varint(InsertAt::HeadOf(None), f(13), 7).unwrap();
    adopt.insert_i32(AInsertAt::After(at[1]), f(13), 5).unwrap();
    intake.insert_i32(InsertAt::After(it[1]), f(13), 5).unwrap();
    adopt.insert_i64(AInsertAt::TailOf(None), f(13), 6).unwrap();
    intake.insert_i64(InsertAt::TailOf(None), f(13), 6).unwrap();
    adopt.insert_payload(AInsertAt::TailOf(Some(at[5])), f(14), b"in").unwrap();
    intake.insert_payload(InsertAt::TailOf(Some(it[5])), f(14), b"in").unwrap();
    adopt.insert_payload_copy(AInsertAt::HeadOf(Some(at[5])), f(14), b"tmp").unwrap();
    intake.insert_payload_copy(InsertAt::HeadOf(Some(it[5])), f(14), b"tmp").unwrap();
    static INS_PARTS: [&[u8]; 2] = [b"pa", b"rts"];
    adopt.insert_payload_parts(AInsertAt::TailOf(None), f(15), &INS_PARTS).unwrap();
    intake.insert_payload_parts(InsertAt::TailOf(None), f(15), &INS_PARTS).unwrap();

    // The staged payload frames: a set and an insert, chunked
    // identically on both sides.
    let mut af = adopt.begin_set_payload(at[6 + 1]).unwrap();
    af.write(b"fra").unwrap();
    af.write(b"med").unwrap();
    af.finish().unwrap();
    let mut ifr = intake.begin_set_payload(it[6 + 1]).unwrap();
    ifr.write(b"fra").unwrap();
    ifr.write(b"med").unwrap();
    ifr.finish().unwrap();
    let mut af = adopt.begin_insert_payload(AInsertAt::After(at[6]), f(15)).unwrap();
    af.write(b"gro").unwrap();
    af.write(b"wn!").unwrap();
    let afh = af.finish().unwrap();
    let mut ifr = intake.begin_insert_payload(InsertAt::After(it[6]), f(15)).unwrap();
    ifr.write(b"gro").unwrap();
    ifr.write(b"wn!").unwrap();
    let ifh = ifr.finish().unwrap();

    // The sized payload frames: the same chunks under a declared
    // total, on both sides (the canonical frame's append path runs
    // on the reservation proof alone).
    let mut af = adopt.begin_set_payload_sized(at[3], 5).unwrap();
    af.write(b"siz").unwrap();
    af.write(b"ed").unwrap();
    af.finish().unwrap();
    let mut ifr = intake.begin_set_payload_sized(it[3], 5).unwrap();
    ifr.write(b"siz").unwrap();
    ifr.write(b"ed").unwrap();
    ifr.finish().unwrap();
    let mut af = adopt.begin_insert_payload_sized(AInsertAt::TailOf(None), f(15), 4).unwrap();
    af.write(b"decl").unwrap();
    let afs = af.finish().unwrap();
    let mut ifr = intake.begin_insert_payload_sized(InsertAt::TailOf(None), f(15), 4).unwrap();
    ifr.write(b"decl").unwrap();
    let ifs = ifr.finish().unwrap();
    faces_agree(&adopt, afs, &intake, ifs);

    saves_agree(&adopt, &intake);
    for (ah, ih) in adopt.top().zip(intake.top()) {
        faces_agree(&adopt, ah, &intake, ih);
    }
    for (ah, ih) in adopt.children(at[5]).zip(intake.children(it[5])) {
        faces_agree(&adopt, ah, &intake, ih);
    }
    faces_agree(&adopt, afh, &intake, ifh);

    // The coordinate-resolving face agrees at every source byte.
    for pos in 0..=u32::try_from(msg.len()).unwrap() + 1 {
        assert_eq!(
            adopt.narrowest(pos).is_some(),
            intake.narrowest(pos).is_some(),
            "narrowest({pos}) presence disagrees"
        );
        if let (Some(ah), Some(ih)) = (adopt.narrowest(pos), intake.narrowest(pos)) {
            faces_agree(&adopt, ah, &intake, ih);
        }
    }

    // A shrink twin over a fresh pair: the container prefix
    // re-authors downward on both sides.
    let mut adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mut intake = Intake::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let at: Vec<_> = adopt.top().collect();
    let it: Vec<_> = intake.top().collect();
    let crate::adopt::groupless::Descent::Opened { .. } = adopt.descend(at[5]).unwrap() else {
        unreachable!()
    };
    let Descent::Opened { .. } = intake.descend(it[5]).unwrap() else { unreachable!() };
    let ak: Vec<_> = adopt.children(at[5]).collect();
    let ik: Vec<_> = intake.children(it[5]).collect();
    adopt.set_payload(ak[1], b"z").unwrap();
    intake.set_payload(ik[1], b"z").unwrap();
    saves_agree(&adopt, &intake);
}

/// The clean arc: no command lands, and both machines save the
/// minimal source verbatim through every face.
#[cfg(feature = "adopt-groupless")]
#[test]
fn a_clean_intake_saves_the_source_verbatim_like_a_clean_adopt() {
    use crate::adopt::groupless::Adopt;

    let msg: &[u8] = &[0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let intake = Intake::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    saves_agree(&adopt, &intake);
    assert_eq!(intake.save().unwrap(), msg);
}

/// Command refusals agree: the same ill-formed commands refuse
/// with the same fault on both machines, leaving both unchanged.
#[cfg(feature = "adopt-groupless")]
#[test]
fn command_refusals_agree_with_the_tolerant_adopt() {
    use alloc::format;

    use crate::adopt::groupless::{Adopt, InsertAt as AInsertAt};

    // varint f1 · LEN f2 "hi"
    let msg: &[u8] = &[0x08, 0x2A, 0x12, 0x02, 0x68, 0x69];
    let mut adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mut intake = Intake::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let at: Vec<_> = adopt.top().collect();
    let it: Vec<_> = intake.top().collect();

    // Kind mismatch, deleted target, unopened container — judged
    // identically.
    let ae = adopt.set_varint(at[1], 1).unwrap_err();
    let ie = intake.set_varint(it[1], 1).unwrap_err();
    assert_eq!(format!("{ae:?}"), format!("{ie:?}"));
    adopt.delete(at[0]).unwrap();
    intake.delete(it[0]).unwrap();
    let ae = adopt.set_varint(at[0], 1).unwrap_err();
    let ie = intake.set_varint(it[0], 1).unwrap_err();
    assert_eq!(format!("{ae:?}"), format!("{ie:?}"));
    let ae = adopt.insert_varint(AInsertAt::TailOf(Some(at[1])), f(3), 1).unwrap_err();
    let ie = intake.insert_varint(InsertAt::TailOf(Some(it[1])), f(3), 1).unwrap_err();
    assert_eq!(format!("{ae:?}"), format!("{ie:?}"));

    saves_agree(&adopt, &intake);
}

// ─── the payload-backing siblings ───

#[test]
fn the_thin_siblings_match_the_mixed_machine_on_their_arcs() {
    let data: &[u8] = &[0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69, 0x1A, 0x02, 0x08, 0x01];
    let payload = [0xA5u8; 40];

    // Borrowed-only: whole-slice and scatter arcs, and the shared
    // scalar core, land byte-identically.
    let mut mixed = Intake::open(data.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mut thin = BorrowIntake::open(data.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mt: Vec<_> = mixed.top().collect();
    let tt: Vec<_> = thin.top().collect();
    mixed.set_payload(mt[1], &payload).unwrap();
    thin.set_payload(tt[1], &payload).unwrap();
    static PARTS: [&[u8]; 2] = [b"sca", b"tter"];
    mixed.set_payload_parts(mt[2], &PARTS).unwrap();
    thin.set_payload_parts(tt[2], &PARTS).unwrap();
    mixed.insert_payload(InsertAt::TailOf(None), f(4), &payload).unwrap();
    thin.insert_payload(InsertAt::TailOf(None), f(4), &payload).unwrap();
    mixed.set_varint(mt[0], 300).unwrap();
    thin.set_varint(tt[0], 300).unwrap();
    assert_eq!(mixed.save().unwrap(), thin.save().unwrap());
    assert_eq!(mixed.save_len().unwrap(), thin.save_len().unwrap());

    // Copy-only: copy sets and inserts under their unsuffixed
    // names plus both frame families; the machine also releases
    // its tenure like the mixed one.
    let mut mixed = Intake::open(data.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mut thin = CopyIntake::open(data.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mt: Vec<_> = mixed.top().collect();
    let tt: Vec<_> = thin.top().collect();
    mixed.set_payload_copy(mt[1], b"copied").unwrap();
    thin.set_payload(tt[1], b"copied").unwrap();
    mixed.insert_payload_copy(InsertAt::After(mt[0]), f(4), b"tmp").unwrap();
    thin.insert_payload(InsertAt::After(tt[0]), f(4), b"tmp").unwrap();
    let mut mf = mixed.begin_set_payload_sized(mt[2], 5).unwrap();
    mf.write(b"si").unwrap();
    mf.write(b"zed").unwrap();
    mf.finish().unwrap();
    let mut tf = thin.begin_set_payload_sized(tt[2], 5).unwrap();
    tf.write(b"si").unwrap();
    tf.write(b"zed").unwrap();
    tf.finish().unwrap();
    assert_eq!(mixed.save().unwrap(), thin.save().unwrap());
    assert_eq!(thin.into_source(), data, "release returns the moved-in bytes");
}
