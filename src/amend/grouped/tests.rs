//! The grouped amend's module suite: the canonical-door pins
//! (group interiors are scanned, so their padding refuses at
//! open), the borrowed-tenure pins, and the borrowed-patch
//! differential twin on canonical inputs (identical command arcs ⇒
//! byte-identical saves, groups included).

use alloc::vec::Vec;

use super::{Amend, BorrowAmend, CopyAmend, Descent, InsertAt, OpenFault, Refusal};
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
    let src = [0x8B, 0x00, 0x18, 0x01, 0x0C];
    let Some(OpenFault::Refused(refusal)) = Amend::open(&src, DepthLimit::REFERENCE).err() else {
        panic!("a padded group tag must refuse");
    };
    assert!(matches!(refusal, Refusal::NonMinimalTag { at: 0, width: 2 }));
    assert_eq!(src, [0x8B, 0x00, 0x18, 0x01, 0x0C], "the caller's buffer is unchanged");

    // A padded tag inside a minimally framed group: interiors are
    // scanned eagerly, so this too refuses at the door.
    let src = [0x0B, 0x88, 0x00, 0x01, 0x0C];
    let Some(OpenFault::Refused(refusal)) = Amend::open(&src, DepthLimit::REFERENCE).err() else {
        panic!("a padded tag inside a group must refuse");
    };
    assert!(matches!(refusal, Refusal::NonMinimalTag { at: 1, width: 2 }));
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
    // varint f1=150 · group f2 { varint f3=1 }
    let msg = alloc::vec![0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let addr = msg.as_ptr().addr();
    let recovered = {
        let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
        assert_eq!(amend.source().as_ptr().addr(), addr, "open must borrow, not copy");
        let tops: Vec<_> = amend.top().collect();
        amend.delete(tops[1]).unwrap(); // staged, never saved
        // The accessor hands back the borrow itself, not a
        // machine-lived view: it outlives the amend.
        amend.source()
    };
    assert_eq!(recovered.as_ptr().addr(), addr);
    assert_eq!(msg, [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14]);
}

#[test]
fn a_refused_open_is_a_plain_fault_and_never_touches_the_buffer() {
    // An orphan group end tag: a wire-grammar fault at the root.
    let src = [0x0C];
    assert!(matches!(Amend::open(&src, DepthLimit::REFERENCE).err(), Some(OpenFault::Wire(_))));
    assert_eq!(src, [0x0C], "the caller's buffer is unchanged");
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

/// Every save face of both machines over the same rows, compared.
#[cfg(feature = "patch-grouped")]
fn saves_agree(patch: &crate::patch::grouped::Patch<'_, '_>, amend: &Amend<'_, '_>) {
    let p = patch.save().unwrap();
    let a = amend.save().unwrap();
    assert_eq!(p, a, "identical command arcs must save byte-identically");
    assert_eq!(patch.save_len().unwrap(), amend.save_len().unwrap());

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

/// The read faces of both machines over one handle pair.
#[cfg(feature = "patch-grouped")]
fn faces_agree(
    patch: &crate::patch::grouped::Patch<'_, '_>,
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

/// The grouped command set, applied pairwise to the tolerant patch
/// and the canonical amend over identical minimal bytes: edits
/// inside eagerly materialized groups, whole-group deletion, group
/// insertion with interior authoring, a LEN cascade flowing
/// through a group, and the shared scalar/payload/frame arcs.
/// Acceptance judges the door — on bytes both doors admit the
/// machines are the same machine.
#[cfg(feature = "patch-grouped")]
#[test]
fn identical_command_arcs_save_byte_identically() {
    use crate::patch::grouped::{InsertAt as PInsertAt, Patch};

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

    let mut patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let mut amend = Amend::open(msg, DepthLimit::REFERENCE).unwrap();

    let pt: Vec<_> = patch.top().collect();
    let at: Vec<_> = amend.top().collect();
    assert_eq!(pt.len(), at.len());

    // Edits inside the eagerly materialized group f1: rewrite the
    // varint (shrinks — group framing cascades nothing), drop the
    // nested group whole.
    let pk: Vec<_> = patch.children(pt[0]).collect();
    let ak: Vec<_> = amend.children(at[0]).collect();
    patch.set_varint(pk[0], 7).unwrap();
    amend.set_varint(ak[0], 7).unwrap();
    patch.delete(pk[1]).unwrap();
    amend.delete(ak[1]).unwrap();

    // Root scalar growth and an opaque payload replacement.
    patch.set_varint(pt[1], 300).unwrap();
    amend.set_varint(at[1], 300).unwrap();
    patch.set_payload(pt[2], b"xyzzy").unwrap();
    amend.set_payload(at[2], b"xyzzy").unwrap();

    // Whole-group deletion, then a fresh group authored in its
    // place with an interior record.
    patch.delete(pt[3]).unwrap();
    amend.delete(at[3]).unwrap();
    let pg = patch.insert_group(PInsertAt::After(pt[3]), f(9)).unwrap();
    let ag = amend.insert_group(InsertAt::After(at[3]), f(9)).unwrap();
    patch.insert_varint(PInsertAt::TailOf(Some(pg)), f(2), 7).unwrap();
    amend.insert_varint(InsertAt::TailOf(Some(ag)), f(2), 7).unwrap();

    // A cascade through a group into its LEN ancestor: descend the
    // LEN, edit inside the group it wraps — the prefix re-authors.
    let crate::patch::grouped::Descent::Opened { first: Some(p_f11) } =
        patch.descend(pt[5]).unwrap()
    else {
        unreachable!()
    };
    let Descent::Opened { first: Some(a_f11) } = amend.descend(at[5]).unwrap() else {
        unreachable!()
    };
    let p_inner = patch.children(p_f11).next().unwrap();
    let a_inner = amend.children(a_f11).next().unwrap();
    patch.set_varint(p_inner, 7).unwrap();
    amend.set_varint(a_inner, 7).unwrap();

    // A staged frame on the LEN under everything above.
    let mut pf = patch.begin_set_payload(pt[2]).unwrap();
    pf.write(b"re").unwrap();
    pf.write(b"framed").unwrap();
    pf.finish().unwrap();
    let mut af = amend.begin_set_payload(at[2]).unwrap();
    af.write(b"re").unwrap();
    af.write(b"framed").unwrap();
    af.finish().unwrap();

    // The sized payload frames: the same chunks under a declared
    // total, on both sides (the canonical frame's append path runs
    // on the reservation proof alone).
    let mut pf = patch.begin_set_payload_sized(pt[2], 5).unwrap();
    pf.write(b"siz").unwrap();
    pf.write(b"ed").unwrap();
    pf.finish().unwrap();
    let mut af = amend.begin_set_payload_sized(at[2], 5).unwrap();
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
    for (ph, ah) in patch.children(pt[0]).zip(amend.children(at[0])) {
        faces_agree(&patch, ph, &amend, ah);
    }
    for (ph, ah) in patch.children(p_f11).zip(amend.children(a_f11)) {
        faces_agree(&patch, ph, &amend, ah);
    }

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
}

/// The clean arc: no command lands, and both machines save the
/// minimal source verbatim — group framing included.
#[cfg(feature = "patch-grouped")]
#[test]
fn a_clean_amend_saves_the_source_verbatim_like_a_clean_patch() {
    use crate::patch::grouped::Patch;

    let msg: &[u8] = &[0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let amend = Amend::open(msg, DepthLimit::REFERENCE).unwrap();
    saves_agree(&patch, &amend);
    assert_eq!(amend.save().unwrap(), msg);
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
