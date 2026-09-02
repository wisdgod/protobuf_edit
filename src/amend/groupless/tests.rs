//! The groupless amend's module suite: the canonical-door pins,
//! the borrowed-tenure pins, and the borrowed-patch differential
//! twin on canonical inputs (identical command arcs ⇒
//! byte-identical saves — acceptance judges the door, never the
//! edits).

use alloc::vec::Vec;

use super::{Amend, BorrowAmend, CopyAmend, Descent, InsertAt, OpenFault, Refusal};
use crate::DepthLimit;
use crate::wire::FieldNumber;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

// ─── the canonical door ───

#[test]
fn the_door_refuses_each_padded_site_with_the_buffer_untouched() {
    // A tag padded to two bytes.
    let src = [0x88, 0x00, 0x01];
    let Some(OpenFault::Refused(refusal)) = Amend::open(&src, DepthLimit::REFERENCE).err() else {
        panic!("a padded tag must refuse");
    };
    assert!(matches!(refusal, Refusal::NonMinimalTag { at: 0, width: 2 }));
    assert_eq!(src, [0x88, 0x00, 0x01], "the caller's buffer is unchanged");

    // A LEN prefix padded to two bytes.
    let src = [0x12, 0x81, 0x00, 0x61];
    let Some(OpenFault::Refused(refusal)) = Amend::open(&src, DepthLimit::REFERENCE).err() else {
        panic!("a padded length prefix must refuse");
    };
    assert!(matches!(refusal, Refusal::NonMinimalLen { at: 1, width: 2, .. }));

    // A varint value padded to three bytes.
    let src = [0x08, 0x96, 0x81, 0x00];
    let Some(OpenFault::Refused(refusal)) = Amend::open(&src, DepthLimit::REFERENCE).err() else {
        panic!("a padded varint value must refuse");
    };
    assert!(matches!(refusal, Refusal::NonMinimalValue { at: 1, width: 3, .. }));
}

#[test]
fn hidden_padding_refuses_at_descent_as_a_resident_verdict() {
    // LEN f3 whose interior carries a padded LEN prefix: opaque at
    // the door, judged at the descent commitment.
    let msg = [0x1A, 0x03, 0x12, 0x81, 0x00];
    let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
    let record = amend.top().next().unwrap();
    let Descent::Refused(refusal) = amend.descend(record).unwrap() else {
        panic!("the padded interior must refuse descent");
    };
    assert!(matches!(refusal, Refusal::NonMinimalLen { at: 3, width: 2, .. }));
    // The verdict is resident; the document itself still saves.
    assert_eq!(amend.save().unwrap(), msg);
}

// ─── borrowed tenure ───

#[test]
fn the_open_borrows_and_source_outlives_the_machine() {
    let msg = alloc::vec![0x08, 0x2A, 0x12, 0x02, 0x68, 0x69];
    let addr = msg.as_ptr().addr();
    let recovered = {
        let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
        assert_eq!(amend.source().as_ptr().addr(), addr, "open must borrow, not copy");
        // Staged edits are a plan; dropping the amend discards them
        // and the caller's bytes were never touched.
        let first = amend.top().next().unwrap();
        amend.set_varint(first, 7).unwrap();
        // The accessor hands back the borrow itself, not a
        // machine-lived view: it outlives the amend.
        amend.source()
    };
    assert_eq!(recovered.as_ptr().addr(), addr);
    assert_eq!(msg, [0x08, 0x2A, 0x12, 0x02, 0x68, 0x69]);
}

#[test]
fn a_refused_open_is_a_plain_fault_and_never_touches_the_buffer() {
    // A group code: lawful wire outside this dialect.
    let src = [0x0B, 0x0C];
    assert!(matches!(
        Amend::open(&src, DepthLimit::REFERENCE).err(),
        Some(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
    ));
    assert_eq!(src, [0x0B, 0x0C], "the caller's buffer is unchanged");

    // A wire-grammar fault refuses the same way.
    assert!(matches!(Amend::open(&[0x08], DepthLimit::REFERENCE).err(), Some(OpenFault::Wire(_))));
}

// The refusal fixture allocates past the coordinate class
// (> 2 GiB): 32-bit targets cannot host it, and under Miri it is
// byte bulk without provenance value. The refusal arithmetic
// itself is target-independent.
#[cfg(all(not(target_family = "wasm"), not(miri)))]
#[test]
fn an_oversize_buffer_is_refused_before_any_work() {
    use crate::admission;

    let src = alloc::vec![0u8; admission::MAX + 1];
    let len = src.len();
    assert!(matches!(
        Amend::open(&src, DepthLimit::REFERENCE).err(),
        Some(OpenFault::TooLarge { len: l }) if l == len
    ));
}

#[test]
fn the_sized_doors_refuse_class_overflow_without_allocating() {
    // The declared form's over-cap pin: the class judgment lands
    // at begin, before any reservation — no giant allocation
    // exists to build, so the pin runs on every target and under
    // Miri (the oversize-open twin above keeps its cfg gate).
    use super::EditFault;
    use crate::admission::usize_of;
    use crate::wire::PayloadLen;

    let msg = [0x12, 0x02, 0x61, 0x62];
    let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
    let record = amend.top().next().unwrap();
    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        amend.begin_set_payload_sized(record, over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert!(matches!(
        amend.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert_eq!(amend.save().unwrap(), msg);
}

// ─── the borrowed-patch differential twin ───

/// Every save face of both machines over the same rows, compared:
/// the priced length, the fresh save, the append face, the sink
/// face, and the output-order span table.
#[cfg(feature = "patch-groupless")]
fn saves_agree(patch: &crate::patch::groupless::Patch<'_, '_>, amend: &Amend<'_, '_>) {
    let p = patch.save().unwrap();
    let a = amend.save().unwrap();
    assert_eq!(p, a, "identical command arcs must save byte-identically");
    assert_eq!(patch.save_len().unwrap(), amend.save_len().unwrap());
    assert_eq!(u64::try_from(a.len()).unwrap(), u64::from(amend.save_len().unwrap()));

    let mut appended = alloc::vec![0xEE_u8; 3];
    amend.save_into(&mut appended).unwrap();
    assert_eq!(appended[..3], [0xEE; 3]);
    assert_eq!(appended[3..], a[..]);

    let mut sunk = Vec::new();
    amend.save_sink(|bytes| sunk.extend_from_slice(bytes)).unwrap();
    assert_eq!(sunk, a);

    let p_spans: Vec<_> = patch.save_spans().unwrap().iter().map(|(_, span)| span).collect();
    let a_spans: Vec<_> = amend.save_spans().unwrap().iter().map(|(_, span)| span).collect();
    assert_eq!(p_spans, a_spans, "the output-order span tables must agree");
}

/// The read faces of both machines over one handle pair (same
/// arena index on both sides — identical command arcs mint
/// identical rows).
#[cfg(feature = "patch-groupless")]
fn faces_agree(
    patch: &crate::patch::groupless::Patch<'_, '_>,
    ph: crate::patch::Handle,
    amend: &Amend<'_, '_>,
    ah: super::Handle,
) {
    use alloc::format;

    assert_eq!(patch.field(ph), amend.field(ah));
    assert_eq!(patch.kind(ph), amend.kind(ah));
    assert_eq!(format!("{:?}", patch.status(ph)), format!("{:?}", amend.status(ah)));
    assert_eq!(patch.span(ph), amend.span(ah));
    assert_eq!(format!("{:?}", patch.source_spans(ph)), format!("{:?}", amend.source_spans(ah)));
    assert_eq!(patch.varint_word(ph), amend.varint_word(ah));
    assert_eq!(patch.i32_bits(ph), amend.i32_bits(ah));
    assert_eq!(patch.i64_bits(ph), amend.i64_bits(ah));
    assert_eq!(patch.payload_bytes(ph), amend.payload_bytes(ah));
}

/// The full command set, applied pairwise to the tolerant patch
/// and the canonical amend over identical minimal bytes: scalar
/// sets, payload replacement in all three supplies (borrowed,
/// copied, scatter), deletion, insertion at every anchor, descent
/// with nested edits (growth and shrink), and the staged payload
/// frames. Every save face and every read face must agree —
/// acceptance judges the door, and on bytes both doors admit the
/// machines are the same machine.
#[cfg(feature = "patch-groupless")]
#[test]
fn identical_command_arcs_save_byte_identically() {
    use crate::patch::groupless::{InsertAt as PInsertAt, Patch};

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

    let mut patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let mut amend = Amend::open(msg, DepthLimit::REFERENCE).unwrap();

    let pt: Vec<_> = patch.top().collect();
    let at: Vec<_> = amend.top().collect();
    assert_eq!(pt.len(), at.len());

    // Scalar replacements (the untouched f8 rides verbatim on
    // both).
    patch.set_varint(pt[0], 300).unwrap();
    amend.set_varint(at[0], 300).unwrap();
    patch.set_i32(pt[1], 0xDEAD_BEEF).unwrap();
    amend.set_i32(at[1], 0xDEAD_BEEF).unwrap();
    patch.set_i64(pt[2], 0x0102_0304_0506_0708).unwrap();
    amend.set_i64(at[2], 0x0102_0304_0506_0708).unwrap();

    // Payload replacement across all three supplies, re-sets
    // included (the last supply wins on both sides).
    patch.set_payload(pt[3], b"grown payload").unwrap();
    amend.set_payload(at[3], b"grown payload").unwrap();
    patch.set_payload_copy(pt[3], b"copied").unwrap();
    amend.set_payload_copy(at[3], b"copied").unwrap();
    static PARTS: [&[u8]; 3] = [b"sc", b"at", b"ter"];
    patch.set_payload_parts(pt[3], &PARTS).unwrap();
    amend.set_payload_parts(at[3], &PARTS).unwrap();

    // Deletion.
    patch.delete(pt[4]).unwrap();
    amend.delete(at[4]).unwrap();

    // Descent and nested edits: drop one interior record, grow the
    // other — the cascade re-authors the container prefix on both.
    let crate::patch::groupless::Descent::Opened { first: Some(_) } = patch.descend(pt[5]).unwrap()
    else {
        unreachable!()
    };
    let Descent::Opened { first: Some(_) } = amend.descend(at[5]).unwrap() else { unreachable!() };
    let pk: Vec<_> = patch.children(pt[5]).collect();
    let ak: Vec<_> = amend.children(at[5]).collect();
    patch.delete(pk[0]).unwrap();
    amend.delete(ak[0]).unwrap();
    patch.set_payload(pk[1], b"longer than before").unwrap();
    amend.set_payload(ak[1], b"longer than before").unwrap();

    // Insertion at every anchor shape.
    patch.insert_varint(PInsertAt::HeadOf(None), f(13), 7).unwrap();
    amend.insert_varint(InsertAt::HeadOf(None), f(13), 7).unwrap();
    patch.insert_i32(PInsertAt::After(pt[1]), f(13), 5).unwrap();
    amend.insert_i32(InsertAt::After(at[1]), f(13), 5).unwrap();
    patch.insert_i64(PInsertAt::TailOf(None), f(13), 6).unwrap();
    amend.insert_i64(InsertAt::TailOf(None), f(13), 6).unwrap();
    patch.insert_payload(PInsertAt::TailOf(Some(pt[5])), f(14), b"in").unwrap();
    amend.insert_payload(InsertAt::TailOf(Some(at[5])), f(14), b"in").unwrap();
    patch.insert_payload_copy(PInsertAt::HeadOf(Some(pt[5])), f(14), b"tmp").unwrap();
    amend.insert_payload_copy(InsertAt::HeadOf(Some(at[5])), f(14), b"tmp").unwrap();
    static INS_PARTS: [&[u8]; 2] = [b"pa", b"rts"];
    patch.insert_payload_parts(PInsertAt::TailOf(None), f(15), &INS_PARTS).unwrap();
    amend.insert_payload_parts(InsertAt::TailOf(None), f(15), &INS_PARTS).unwrap();

    // The staged payload frames: a set and an insert, chunked
    // identically on both sides.
    let mut pf = patch.begin_set_payload(pt[6 + 1]).unwrap();
    pf.write(b"fra").unwrap();
    pf.write(b"med").unwrap();
    pf.finish().unwrap();
    let mut af = amend.begin_set_payload(at[6 + 1]).unwrap();
    af.write(b"fra").unwrap();
    af.write(b"med").unwrap();
    af.finish().unwrap();
    let mut pf = patch.begin_insert_payload(PInsertAt::After(pt[6]), f(15)).unwrap();
    pf.write(b"gro").unwrap();
    pf.write(b"wn!").unwrap();
    let pfh = pf.finish().unwrap();
    let mut af = amend.begin_insert_payload(InsertAt::After(at[6]), f(15)).unwrap();
    af.write(b"gro").unwrap();
    af.write(b"wn!").unwrap();
    let afh = af.finish().unwrap();

    // The sized payload frames: the same chunks under a declared
    // total, on both sides (the canonical frame's append path runs
    // on the reservation proof alone).
    let mut pf = patch.begin_set_payload_sized(pt[3], 5).unwrap();
    pf.write(b"siz").unwrap();
    pf.write(b"ed").unwrap();
    pf.finish().unwrap();
    let mut af = amend.begin_set_payload_sized(at[3], 5).unwrap();
    af.write(b"siz").unwrap();
    af.write(b"ed").unwrap();
    af.finish().unwrap();
    let mut pf = patch.begin_insert_payload_sized(PInsertAt::TailOf(None), f(15), 4).unwrap();
    pf.write(b"decl").unwrap();
    let pfs = pf.finish().unwrap();
    let mut af = amend.begin_insert_payload_sized(InsertAt::TailOf(None), f(15), 4).unwrap();
    af.write(b"decl").unwrap();
    let afs = af.finish().unwrap();
    faces_agree(&patch, pfs, &amend, afs);

    saves_agree(&patch, &amend);
    for (ph, ah) in patch.top().zip(amend.top()) {
        faces_agree(&patch, ph, &amend, ah);
    }
    for (ph, ah) in patch.children(pt[5]).zip(amend.children(at[5])) {
        faces_agree(&patch, ph, &amend, ah);
    }
    faces_agree(&patch, pfh, &amend, afh);

    // The coordinate-resolving face agrees at every source byte.
    for pos in 0..=u32::try_from(msg.len()).unwrap() + 1 {
        assert_eq!(
            patch.narrowest(pos).is_some(),
            amend.narrowest(pos).is_some(),
            "narrowest({pos}) presence disagrees"
        );
        if let (Some(ph), Some(ah)) = (patch.narrowest(pos), amend.narrowest(pos)) {
            faces_agree(&patch, ph, &amend, ah);
        }
    }

    // A shrink twin over a fresh pair: the container prefix
    // re-authors downward on both sides.
    let mut patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let mut amend = Amend::open(msg, DepthLimit::REFERENCE).unwrap();
    let pt: Vec<_> = patch.top().collect();
    let at: Vec<_> = amend.top().collect();
    let crate::patch::groupless::Descent::Opened { .. } = patch.descend(pt[5]).unwrap() else {
        unreachable!()
    };
    let Descent::Opened { .. } = amend.descend(at[5]).unwrap() else { unreachable!() };
    let pk: Vec<_> = patch.children(pt[5]).collect();
    let ak: Vec<_> = amend.children(at[5]).collect();
    patch.set_payload(pk[1], b"z").unwrap();
    amend.set_payload(ak[1], b"z").unwrap();
    saves_agree(&patch, &amend);
}

/// The clean arc: no command lands, and both machines save the
/// minimal source verbatim through every face.
#[cfg(feature = "patch-groupless")]
#[test]
fn a_clean_amend_saves_the_source_verbatim_like_a_clean_patch() {
    use crate::patch::groupless::Patch;

    let msg: &[u8] = &[0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
    let patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let amend = Amend::open(msg, DepthLimit::REFERENCE).unwrap();
    saves_agree(&patch, &amend);
    assert_eq!(amend.save().unwrap(), msg);
}

/// Command refusals agree: the same ill-formed commands refuse
/// with the same fault on both machines, leaving both unchanged.
#[cfg(feature = "patch-groupless")]
#[test]
fn command_refusals_agree_with_the_tolerant_patch() {
    use alloc::format;

    use crate::patch::groupless::{InsertAt as PInsertAt, Patch};

    // varint f1 · LEN f2 "hi"
    let msg: &[u8] = &[0x08, 0x2A, 0x12, 0x02, 0x68, 0x69];
    let mut patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let mut amend = Amend::open(msg, DepthLimit::REFERENCE).unwrap();
    let pt: Vec<_> = patch.top().collect();
    let at: Vec<_> = amend.top().collect();

    // Kind mismatch, deleted target, unopened container — judged
    // identically.
    let pe = patch.set_varint(pt[1], 1).unwrap_err();
    let ae = amend.set_varint(at[1], 1).unwrap_err();
    assert_eq!(format!("{pe:?}"), format!("{ae:?}"));
    patch.delete(pt[0]).unwrap();
    amend.delete(at[0]).unwrap();
    let pe = patch.set_varint(pt[0], 1).unwrap_err();
    let ae = amend.set_varint(at[0], 1).unwrap_err();
    assert_eq!(format!("{pe:?}"), format!("{ae:?}"));
    let pe = patch.insert_varint(PInsertAt::TailOf(Some(pt[1])), f(3), 1).unwrap_err();
    let ae = amend.insert_varint(InsertAt::TailOf(Some(at[1])), f(3), 1).unwrap_err();
    assert_eq!(format!("{pe:?}"), format!("{ae:?}"));

    saves_agree(&patch, &amend);
}

// ─── the payload-backing siblings ───

#[test]
fn the_thin_siblings_match_the_mixed_machine_on_their_arcs() {
    let data: &[u8] = &[0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69, 0x1A, 0x02, 0x08, 0x01];
    let payload = [0xA5u8; 40];

    // Borrowed-only: whole-slice and scatter arcs, and the shared
    // scalar core, land byte-identically.
    let mut mixed = Amend::open(data, DepthLimit::REFERENCE).unwrap();
    let mut thin = BorrowAmend::open(data, DepthLimit::REFERENCE).unwrap();
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
    // names plus both frame families; the source borrow stays the
    // caller's like the mixed one.
    let mut mixed = Amend::open(data, DepthLimit::REFERENCE).unwrap();
    let mut thin = CopyAmend::open(data, DepthLimit::REFERENCE).unwrap();
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
    assert_eq!(thin.source(), data, "the borrow is the caller's own slice");
}
