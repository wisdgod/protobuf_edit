//! The grouped adopt's module suite: the borrowed-patch
//! differential twin (identical command arcs ⇒ byte-identical
//! saves, groups included) and the ownership-tenure pins.

use alloc::vec::Vec;

// Named by the borrowed-patch differential alone.
#[cfg(feature = "patch-grouped")]
use super::Descent;
use super::{Adopt, BorrowAdopt, CopyAdopt, InsertAt, OpenFault};
use crate::DepthLimit;
use crate::wire::FieldNumber;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

// ─── ownership tenure ───

#[test]
fn the_buffer_moves_in_and_releases_without_a_copy() {
    // varint f1=150 · group f2 { varint f3=1 }
    let src = alloc::vec![0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
    let addr = src.as_ptr().addr();
    let mut adopt = Adopt::open(src, DepthLimit::REFERENCE).unwrap();
    assert_eq!(adopt.source().as_ptr().addr(), addr, "open must move the buffer, not copy it");
    let tops: Vec<_> = adopt.top().collect();
    adopt.delete(tops[1]).unwrap(); // staged, never saved
    let back = adopt.into_source();
    assert_eq!(back.as_ptr().addr(), addr, "release must move the buffer back, not copy it");
    assert_eq!(back, [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14]);
}

#[test]
fn a_refused_open_returns_the_buffer_intact() {
    // An orphan group end tag: a wire-grammar fault at the root.
    let src = alloc::vec![0x0C];
    let addr = src.as_ptr().addr();
    let Err((back, fault)) = Adopt::open(src, DepthLimit::REFERENCE) else {
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
    let Err((back, fault)) = Adopt::open(src, DepthLimit::REFERENCE) else {
        panic!("an oversize buffer must refuse");
    };
    assert!(matches!(fault, OpenFault::TooLarge { len: l } if l == len));
    assert_eq!(back.as_ptr().addr(), addr, "the refusal must return the buffer, not a copy");
    assert_eq!(back.len(), len);
}

#[test]
fn a_mid_edit_adopt_moves_across_frames_and_saves_after() {
    fn stage(msg: Vec<u8>) -> Adopt<'static> {
        let mut adopt = Adopt::open(msg, DepthLimit::REFERENCE).unwrap();
        let tops: Vec<_> = adopt.top().collect();
        let inner = adopt.children(tops[1]).next().unwrap();
        adopt.set_varint(inner, 9).unwrap();
        adopt
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
    use crate::admission::usize_of;
    use crate::wire::PayloadLen;

    use super::EditFault;

    let mut adopt =
        Adopt::open(alloc::vec![0x12, 0x02, 0x61, 0x62], DepthLimit::REFERENCE).unwrap();
    let record = adopt.top().next().unwrap();
    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        adopt.begin_set_payload_sized(record, over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert!(matches!(
        adopt.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert_eq!(adopt.save().unwrap(), [0x12, 0x02, 0x61, 0x62]);
}

// ─── the borrowed-patch differential twin ───

/// Every save face of both machines over the same rows, compared.
#[cfg(feature = "patch-grouped")]
fn saves_agree(patch: &crate::patch::grouped::Patch<'_, '_>, adopt: &Adopt<'_>) {
    let p = patch.save().unwrap();
    let a = adopt.save().unwrap();
    assert_eq!(p, a, "identical command arcs must save byte-identically");
    assert_eq!(patch.save_len().unwrap(), adopt.save_len().unwrap());

    let mut appended = alloc::vec![0xEE_u8; 3];
    adopt.save_into(&mut appended).unwrap();
    assert_eq!(appended[..3], [0xEE; 3]);
    assert_eq!(appended[3..], p[..]);

    let mut sunk = Vec::new();
    adopt.save_sink(|bytes| sunk.extend_from_slice(bytes)).unwrap();
    assert_eq!(sunk, p);

    let p_spans: Vec<_> = patch.save_spans().unwrap().iter().map(|(_, span)| span).collect();
    let a_spans: Vec<_> = adopt.save_spans().unwrap().iter().map(|(_, span)| span).collect();
    assert_eq!(p_spans, a_spans, "the output-order span tables must agree");
}

/// The read faces of both machines over one handle pair.
#[cfg(feature = "patch-grouped")]
fn faces_agree(
    patch: &crate::patch::grouped::Patch<'_, '_>,
    ph: crate::patch::Handle,
    adopt: &Adopt<'_>,
    ah: super::Handle,
) {
    use alloc::format;

    assert_eq!(patch.field(ph), adopt.field(ah));
    assert_eq!(patch.kind(ph), adopt.kind(ah));
    assert_eq!(format!("{:?}", patch.status(ph)), format!("{:?}", adopt.status(ah)));
    assert_eq!(patch.span(ph), adopt.span(ah));
    assert_eq!(format!("{:?}", patch.source_spans(ph)), format!("{:?}", adopt.source_spans(ah)));
    assert_eq!(patch.varint_word(ph), adopt.varint_word(ah));
    assert_eq!(patch.i32_bits(ph), adopt.i32_bits(ah));
    assert_eq!(patch.i64_bits(ph), adopt.i64_bits(ah));
    assert_eq!(patch.payload_bytes(ph), adopt.payload_bytes(ah));
}

/// The grouped command set, applied pairwise over identical bytes:
/// edits inside eagerly materialized groups, whole-group deletion,
/// group insertion with interior authoring, a LEN cascade flowing
/// through a group, and the shared scalar/payload/frame arcs.
#[cfg(feature = "patch-grouped")]
#[test]
fn identical_command_arcs_save_byte_identically() {
    use crate::patch::grouped::{InsertAt as PInsertAt, Patch};

    // group f1 { f2 varint 150 · group f3 { f4 i32 } } · f5 varint ·
    // f6 LEN "abc" · group f7 { f2 varint 1 } · f8 varint padded ·
    // f10 LEN { group f11 { f2 varint 150 } }
    let msg: &[u8] = &[
        0x0B, // group f1 start
        0x10, 0x96, 0x01, // f2 varint 150
        0x1B, 0x25, 0x01, 0x02, 0x03, 0x04, 0x1C, // group f3 { f4 i32 }
        0x0C, // group f1 end
        0x28, 0x05, // f5 varint 5
        0x32, 0x03, b'a', b'b', b'c', // f6 LEN
        0x3B, 0x10, 0x01, 0x3C, // group f7 { f2 varint 1 }
        0x40, 0x96, 0x81, 0x00, // f8 varint padded
        0x52, 0x05, 0x5B, 0x10, 0x96, 0x01, 0x5C, // f10 LEN { group f11 { f2 } }
    ];

    let mut patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let mut adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();

    let pt: Vec<_> = patch.top().collect();
    let at: Vec<_> = adopt.top().collect();
    assert_eq!(pt.len(), at.len());

    // Edits inside the eagerly materialized group f1: rewrite the
    // varint (shrinks — group framing cascades nothing), drop the
    // nested group whole.
    let pk: Vec<_> = patch.children(pt[0]).collect();
    let ak: Vec<_> = adopt.children(at[0]).collect();
    patch.set_varint(pk[0], 7).unwrap();
    adopt.set_varint(ak[0], 7).unwrap();
    patch.delete(pk[1]).unwrap();
    adopt.delete(ak[1]).unwrap();

    // Root scalar growth and an opaque payload replacement.
    patch.set_varint(pt[1], 300).unwrap();
    adopt.set_varint(at[1], 300).unwrap();
    patch.set_payload(pt[2], b"xyzzy").unwrap();
    adopt.set_payload(at[2], b"xyzzy").unwrap();

    // Whole-group deletion, then a fresh group authored in its
    // place with an interior record.
    patch.delete(pt[3]).unwrap();
    adopt.delete(at[3]).unwrap();
    let pg = patch.insert_group(PInsertAt::After(pt[3]), f(9)).unwrap();
    let ag = adopt.insert_group(InsertAt::After(at[3]), f(9)).unwrap();
    patch.insert_varint(PInsertAt::TailOf(Some(pg)), f(2), 7).unwrap();
    adopt.insert_varint(InsertAt::TailOf(Some(ag)), f(2), 7).unwrap();

    // A cascade through a group into its LEN ancestor: descend the
    // LEN, edit inside the group it wraps — the prefix re-authors.
    let Descent::Opened { first: Some(a_f11) } = adopt.descend(at[5]).unwrap() else {
        unreachable!()
    };
    let crate::patch::grouped::Descent::Opened { first: Some(p_f11) } =
        patch.descend(pt[5]).unwrap()
    else {
        unreachable!()
    };
    let p_inner = patch.children(p_f11).next().unwrap();
    let a_inner = adopt.children(a_f11).next().unwrap();
    patch.set_varint(p_inner, 7).unwrap();
    adopt.set_varint(a_inner, 7).unwrap();

    // A staged frame on the LEN under everything above.
    let mut pf = patch.begin_set_payload(pt[2]).unwrap();
    pf.write(b"re").unwrap();
    pf.write(b"framed").unwrap();
    pf.finish().unwrap();
    let mut af = adopt.begin_set_payload(at[2]).unwrap();
    af.write(b"re").unwrap();
    af.write(b"framed").unwrap();
    af.finish().unwrap();

    // The sized payload frames: the same chunks under a declared
    // total, on both sides.
    let mut pf = patch.begin_set_payload_sized(pt[2], 5).unwrap();
    pf.write(b"siz").unwrap();
    pf.write(b"ed").unwrap();
    pf.finish().unwrap();
    let mut af = adopt.begin_set_payload_sized(at[2], 5).unwrap();
    af.write(b"siz").unwrap();
    af.write(b"ed").unwrap();
    af.finish().unwrap();
    let mut pf = patch.begin_insert_payload_sized(PInsertAt::TailOf(None), f(15), 4).unwrap();
    pf.write(b"decl").unwrap();
    let pfs = pf.finish().unwrap();
    let mut af = adopt.begin_insert_payload_sized(InsertAt::TailOf(None), f(15), 4).unwrap();
    af.write(b"decl").unwrap();
    let afs = af.finish().unwrap();
    faces_agree(&patch, pfs, &adopt, afs);

    saves_agree(&patch, &adopt);
    for (ph, ah) in patch.top().zip(adopt.top()) {
        faces_agree(&patch, ph, &adopt, ah);
    }
    for (ph, ah) in patch.children(pt[0]).zip(adopt.children(at[0])) {
        faces_agree(&patch, ph, &adopt, ah);
    }
    for (ph, ah) in patch.children(p_f11).zip(adopt.children(a_f11)) {
        faces_agree(&patch, ph, &adopt, ah);
    }

    for pos in 0..=u32::try_from(msg.len()).unwrap() + 1 {
        assert_eq!(
            patch.narrowest(pos).is_some(),
            adopt.narrowest(pos).is_some(),
            "narrowest({pos}) presence disagrees"
        );
        if let (Some(ph), Some(ah)) = (patch.narrowest(pos), adopt.narrowest(pos)) {
            faces_agree(&patch, ph, &adopt, ah);
        }
    }
}

/// The clean arc: no command lands, and both machines save the
/// source verbatim — group framing and padding included.
#[cfg(feature = "patch-grouped")]
#[test]
fn a_clean_adopt_saves_the_source_verbatim_like_a_clean_patch() {
    use crate::patch::grouped::Patch;

    let msg: &[u8] = &[0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x01, 0x14];
    let patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    saves_agree(&patch, &adopt);
    assert_eq!(adopt.save().unwrap(), msg);
}

// ─── the payload-backing siblings ───

#[test]
fn the_thin_siblings_match_the_mixed_machine_on_their_arcs() {
    let data: &[u8] = &[0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69, 0x1A, 0x02, 0x08, 0x01];
    let payload = [0xA5u8; 40];

    // Borrowed-only: whole-slice and scatter arcs, and the shared
    // scalar core, land byte-identically.
    let mut mixed = Adopt::open(data.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mut thin = BorrowAdopt::open(data.to_vec(), DepthLimit::REFERENCE).unwrap();
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
    let mut mixed = Adopt::open(data.to_vec(), DepthLimit::REFERENCE).unwrap();
    let mut thin = CopyAdopt::open(data.to_vec(), DepthLimit::REFERENCE).unwrap();
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
