//! The grouped intake's module suite: the canonical-door pins
//! (group interiors are scanned, so their padding refuses at
//! open), the ownership-tenure pins, and the owned-adopt
//! differential twin on canonical inputs (identical command arcs ⇒
//! byte-identical saves, groups included).

use alloc::vec::Vec;

use super::{BorrowIntake, CopyIntake, Descent, InsertAt, Intake, OpenFault, Refusal};
use crate::DepthLimit;
use crate::wire::FieldNumber;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

// ─── the canonical door ───

#[test]
fn the_door_refuses_padding_wherever_the_scan_meets_it() {
    // A group's framing tag padded to two bytes: the scan is the
    // parse, so the padding refuses at the door.
    let src = alloc::vec![0x8B, 0x00, 0x18, 0x01, 0x0C];
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("a padded group tag must refuse");
    };
    assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 })));
    assert_eq!(back, [0x8B, 0x00, 0x18, 0x01, 0x0C]);

    // A padded tag inside a minimally framed group: interiors are
    // scanned eagerly, so this too refuses at the door.
    let src = alloc::vec![0x0B, 0x88, 0x00, 0x01, 0x0C];
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("a padded tag inside a group must refuse");
    };
    assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalTag { at: 1, width: 2 })));
    assert_eq!(back, [0x0B, 0x88, 0x00, 0x01, 0x0C]);
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
    // varint f1=150 · group f2 { varint f3=1 }
    let src = alloc::vec![0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let addr = src.as_ptr().addr();
    let mut intake = Intake::open(src, DepthLimit::REFERENCE).unwrap();
    assert_eq!(intake.source().as_ptr().addr(), addr, "open must move the buffer, not copy it");
    let tops: Vec<_> = intake.top().collect();
    intake.delete(tops[1]).unwrap(); // staged, never saved
    let back = intake.into_source();
    assert_eq!(back.as_ptr().addr(), addr, "release must move the buffer back, not copy it");
    assert_eq!(back, [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14]);
}

#[test]
fn a_refused_open_returns_the_buffer_intact() {
    // An orphan group end tag: a wire-grammar fault at the root.
    let src = alloc::vec![0x0C];
    let addr = src.as_ptr().addr();
    let Err((back, fault)) = Intake::open(src, DepthLimit::REFERENCE) else {
        panic!("an orphan end tag at the root must refuse");
    };
    assert!(matches!(fault, OpenFault::Wire(_)));
    assert_eq!(back.as_ptr().addr(), addr, "the refusal must return the buffer, not a copy");
    assert_eq!(back, [0x0C]);
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
        let inner = intake.children(tops[1]).next().unwrap();
        intake.set_varint(inner, 9).unwrap();
        intake
    }
    // varint f1=150 · group f2 { varint f3=1 }
    let staged = stage(alloc::vec![0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14]);
    assert_eq!(staged.save().unwrap(), [0x08, 0x96, 0x01, 0x13, 0x18, 0x09, 0x14]);
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

/// Every save face of both machines over the same rows, compared.
#[cfg(feature = "adopt-grouped")]
fn saves_agree(adopt: &crate::adopt::grouped::Adopt<'_>, intake: &Intake<'_>) {
    let a = adopt.save().unwrap();
    let i = intake.save().unwrap();
    assert_eq!(a, i, "identical command arcs must save byte-identically");
    assert_eq!(adopt.save_len().unwrap(), intake.save_len().unwrap());

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

/// The read faces of both machines over one handle pair.
#[cfg(feature = "adopt-grouped")]
fn faces_agree(
    adopt: &crate::adopt::grouped::Adopt<'_>,
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

/// The grouped command set, applied pairwise to the tolerant adopt
/// and the canonical intake over identical minimal bytes: edits
/// inside eagerly materialized groups, whole-group deletion, group
/// insertion with interior authoring, a LEN cascade flowing
/// through a group, and the shared scalar/payload/frame arcs.
/// Acceptance judges the door — on bytes both doors admit the
/// machines are the same machine.
#[cfg(feature = "adopt-grouped")]
#[test]
fn identical_command_arcs_save_byte_identically() {
    use crate::adopt::grouped::{Adopt, InsertAt as AInsertAt};

    // group f1 { f2 varint 150 · group f3 { f4 i32 } } · f5 varint ·
    // f6 LEN "abc" · group f7 { f2 varint 1 } · f8 varint ·
    // f10 LEN { group f11 { f2 varint 150 } } — minimal throughout,
    // so both doors admit it.
    let msg: &[u8] = &[
        0x0B, // group f1 start
        0x10, 0x96, 0x01, // f2 varint 150
        0x1B, 0x25, 0x01, 0x02, 0x03, 0x04, 0x1C, // group f3 { f4 i32 }
        0x0C, // group f1 end
        0x28, 0x05, // f5 varint 5
        0x32, 0x03, b'a', b'b', b'c', // f6 LEN
        0x3B, 0x10, 0x01, 0x3C, // group f7 { f2 varint 1 }
        0x40, 0x96, 0x01, // f8 varint 150
        0x52, 0x05, 0x5B, 0x10, 0x96, 0x01, 0x5C, // f10 LEN { group f11 { f2 } }
    ];

    let mut adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mut intake = Intake::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();

    let at: Vec<_> = adopt.top().collect();
    let it: Vec<_> = intake.top().collect();
    assert_eq!(at.len(), it.len());

    // Edits inside the eagerly materialized group f1: rewrite the
    // varint (shrinks — group framing cascades nothing), drop the
    // nested group whole.
    let ak: Vec<_> = adopt.children(at[0]).collect();
    let ik: Vec<_> = intake.children(it[0]).collect();
    adopt.set_varint(ak[0], 7).unwrap();
    intake.set_varint(ik[0], 7).unwrap();
    adopt.delete(ak[1]).unwrap();
    intake.delete(ik[1]).unwrap();

    // Root scalar growth and an opaque payload replacement.
    adopt.set_varint(at[1], 300).unwrap();
    intake.set_varint(it[1], 300).unwrap();
    adopt.set_payload(at[2], b"xyzzy").unwrap();
    intake.set_payload(it[2], b"xyzzy").unwrap();

    // Whole-group deletion, then a fresh group authored in its
    // place with an interior record.
    adopt.delete(at[3]).unwrap();
    intake.delete(it[3]).unwrap();
    let ag = adopt.insert_group(AInsertAt::After(at[3]), f(9)).unwrap();
    let ig = intake.insert_group(InsertAt::After(it[3]), f(9)).unwrap();
    adopt.insert_varint(AInsertAt::TailOf(Some(ag)), f(2), 7).unwrap();
    intake.insert_varint(InsertAt::TailOf(Some(ig)), f(2), 7).unwrap();

    // A cascade through a group into its LEN ancestor: descend the
    // LEN, edit inside the group it wraps — the prefix re-authors.
    let crate::adopt::grouped::Descent::Opened { first: Some(a_f11) } =
        adopt.descend(at[5]).unwrap()
    else {
        unreachable!()
    };
    let Descent::Opened { first: Some(i_f11) } = intake.descend(it[5]).unwrap() else {
        unreachable!()
    };
    let a_inner = adopt.children(a_f11).next().unwrap();
    let i_inner = intake.children(i_f11).next().unwrap();
    adopt.set_varint(a_inner, 7).unwrap();
    intake.set_varint(i_inner, 7).unwrap();

    // A staged frame on the LEN under everything above.
    let mut af = adopt.begin_set_payload(at[2]).unwrap();
    af.write(b"re").unwrap();
    af.write(b"framed").unwrap();
    af.finish().unwrap();
    let mut ifr = intake.begin_set_payload(it[2]).unwrap();
    ifr.write(b"re").unwrap();
    ifr.write(b"framed").unwrap();
    ifr.finish().unwrap();

    // The sized payload frames: the same chunks under a declared
    // total, on both sides (the canonical frame's append path runs
    // on the reservation proof alone).
    let mut af = adopt.begin_set_payload_sized(at[2], 5).unwrap();
    af.write(b"siz").unwrap();
    af.write(b"ed").unwrap();
    af.finish().unwrap();
    let mut ifr = intake.begin_set_payload_sized(it[2], 5).unwrap();
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
    for (ah, ih) in adopt.children(at[0]).zip(intake.children(it[0])) {
        faces_agree(&adopt, ah, &intake, ih);
    }
    for (ah, ih) in adopt.children(a_f11).zip(intake.children(i_f11)) {
        faces_agree(&adopt, ah, &intake, ih);
    }

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
}

/// The clean arc: no command lands, and both machines save the
/// minimal source verbatim — group framing included.
#[cfg(feature = "adopt-grouped")]
#[test]
fn a_clean_intake_saves_the_source_verbatim_like_a_clean_adopt() {
    use crate::adopt::grouped::Adopt;

    let msg: &[u8] = &[0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let intake = Intake::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    saves_agree(&adopt, &intake);
    assert_eq!(intake.save().unwrap(), msg);
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
