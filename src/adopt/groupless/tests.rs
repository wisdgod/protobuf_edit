//! The groupless adopt's module suite: the borrowed-patch
//! differential twin (identical command arcs ⇒ byte-identical
//! saves) and the ownership-tenure pins.

use alloc::vec::Vec;

// Named by the borrowed-patch differential alone.
#[cfg(feature = "patch-groupless")]
use super::Descent;
use super::{Adopt, BorrowAdopt, CopyAdopt, InsertAt, OpenFault, Refusal};
use crate::DepthLimit;
use crate::wire::FieldNumber;

fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).unwrap()
}

// ─── ownership tenure ───

#[test]
fn the_buffer_moves_in_and_releases_without_a_copy() {
    let src = alloc::vec![0x08, 0x2A, 0x12, 0x02, 0x68, 0x69];
    let addr = src.as_ptr().addr();
    let mut adopt = Adopt::open(src, DepthLimit::REFERENCE).unwrap();
    assert_eq!(adopt.source().as_ptr().addr(), addr, "open must move the buffer, not copy it");
    // Staged edits are a plan; release discards them and the bytes
    // come back exactly as they moved in.
    let first = adopt.top().next().unwrap();
    adopt.set_varint(first, 7).unwrap();
    let back = adopt.into_source();
    assert_eq!(back.as_ptr().addr(), addr, "release must move the buffer back, not copy it");
    assert_eq!(back, [0x08, 0x2A, 0x12, 0x02, 0x68, 0x69]);
}

#[test]
fn a_refused_open_returns_the_buffer_intact() {
    // A group code: lawful wire outside this dialect.
    let src = alloc::vec![0x0B, 0x0C];
    let addr = src.as_ptr().addr();
    let Err((back, fault)) = Adopt::open(src, DepthLimit::REFERENCE) else {
        panic!("a group code at the root must refuse");
    };
    assert!(matches!(fault, OpenFault::Refused(Refusal::GroupCode { at: 0, .. })));
    assert_eq!(back.as_ptr().addr(), addr, "the refusal must return the buffer, not a copy");
    assert_eq!(back, [0x0B, 0x0C]);

    // A wire-grammar fault refuses the same way.
    let src = alloc::vec![0x08];
    let Err((back, fault)) = Adopt::open(src, DepthLimit::REFERENCE) else {
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
        adopt.set_varint(tops[0], 7).unwrap();
        adopt.delete(tops[1]).unwrap();
        adopt
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

/// Every save face of both machines over the same rows, compared:
/// the priced length, the fresh save, the append face, the sink
/// face, and the output-order span table.
#[cfg(feature = "patch-groupless")]
fn saves_agree(patch: &crate::patch::groupless::Patch<'_, '_>, adopt: &Adopt<'_>) {
    let p = patch.save().unwrap();
    let a = adopt.save().unwrap();
    assert_eq!(p, a, "identical command arcs must save byte-identically");
    assert_eq!(patch.save_len().unwrap(), adopt.save_len().unwrap());
    assert_eq!(u64::try_from(p.len()).unwrap(), u64::from(adopt.save_len().unwrap()));

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

/// The read faces of both machines over one handle pair (same
/// arena index on both sides — identical command arcs mint
/// identical rows).
#[cfg(feature = "patch-groupless")]
fn faces_agree(
    patch: &crate::patch::groupless::Patch<'_, '_>,
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

/// The full command set, applied pairwise to the borrowed patch
/// and the owned adopt over identical bytes: scalar sets, payload
/// replacement in all three supplies (borrowed, copied, scatter),
/// deletion, insertion at every anchor, descent with nested edits
/// (growth and shrink), and the staged payload frames. Every save
/// face and every read face must agree.
#[cfg(feature = "patch-groupless")]
#[test]
fn identical_command_arcs_save_byte_identically() {
    use crate::patch::groupless::{InsertAt as PInsertAt, Patch};

    // varint f1 · i32 f2 · i64 f3 · LEN f4 "abc" · LEN f5 "hi" ·
    // LEN f6 { f9 varint 1 · f12 LEN "xy" } · varint f8 padded ·
    // LEN f10 "zz" (frame target)
    let msg: &[u8] = &[
        0x08, 0x2A, // f1 varint 42
        0x15, 0x01, 0x02, 0x03, 0x04, // f2 i32
        0x19, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // f3 i64
        0x22, 0x03, b'a', b'b', b'c', // f4 LEN
        0x2A, 0x02, b'h', b'i', // f5 LEN
        0x32, 0x06, 0x48, 0x01, 0x62, 0x02, b'x', b'y', // f6 LEN { .. }
        0x40, 0x96, 0x81, 0x00, // f8 varint 150 padded
        0x52, 0x02, b'z', b'z', // f10 LEN
    ];

    let mut patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let mut adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();

    let pt: Vec<_> = patch.top().collect();
    let at: Vec<_> = adopt.top().collect();
    assert_eq!(pt.len(), at.len());

    // Scalar replacements (the padded f8 stays untouched: both
    // machines must ride its padding verbatim).
    patch.set_varint(pt[0], 300).unwrap();
    adopt.set_varint(at[0], 300).unwrap();
    patch.set_i32(pt[1], 0xDEAD_BEEF).unwrap();
    adopt.set_i32(at[1], 0xDEAD_BEEF).unwrap();
    patch.set_i64(pt[2], 0x0102_0304_0506_0708).unwrap();
    adopt.set_i64(at[2], 0x0102_0304_0506_0708).unwrap();

    // Payload replacement across all three supplies, re-sets
    // included (the last supply wins on both sides).
    patch.set_payload(pt[3], b"grown payload").unwrap();
    adopt.set_payload(at[3], b"grown payload").unwrap();
    patch.set_payload_copy(pt[3], b"copied").unwrap();
    adopt.set_payload_copy(at[3], b"copied").unwrap();
    static PARTS: [&[u8]; 3] = [b"sc", b"at", b"ter"];
    patch.set_payload_parts(pt[3], &PARTS).unwrap();
    adopt.set_payload_parts(at[3], &PARTS).unwrap();

    // Deletion.
    patch.delete(pt[4]).unwrap();
    adopt.delete(at[4]).unwrap();

    // Descent and nested edits: drop one interior record, grow the
    // other — the cascade re-authors the container prefix on both.
    let Descent::Opened { first: Some(_) } = adopt.descend(at[5]).unwrap() else { unreachable!() };
    let crate::patch::groupless::Descent::Opened { first: Some(_) } = patch.descend(pt[5]).unwrap()
    else {
        unreachable!()
    };
    let pk: Vec<_> = patch.children(pt[5]).collect();
    let ak: Vec<_> = adopt.children(at[5]).collect();
    patch.delete(pk[0]).unwrap();
    adopt.delete(ak[0]).unwrap();
    patch.set_payload(pk[1], b"longer than before").unwrap();
    adopt.set_payload(ak[1], b"longer than before").unwrap();

    // Insertion at every anchor shape.
    patch.insert_varint(PInsertAt::HeadOf(None), f(13), 7).unwrap();
    adopt.insert_varint(InsertAt::HeadOf(None), f(13), 7).unwrap();
    patch.insert_i32(PInsertAt::After(pt[1]), f(13), 5).unwrap();
    adopt.insert_i32(InsertAt::After(at[1]), f(13), 5).unwrap();
    patch.insert_i64(PInsertAt::TailOf(None), f(13), 6).unwrap();
    adopt.insert_i64(InsertAt::TailOf(None), f(13), 6).unwrap();
    patch.insert_payload(PInsertAt::TailOf(Some(pt[5])), f(14), b"in").unwrap();
    adopt.insert_payload(InsertAt::TailOf(Some(at[5])), f(14), b"in").unwrap();
    patch.insert_payload_copy(PInsertAt::HeadOf(Some(pt[5])), f(14), b"tmp").unwrap();
    adopt.insert_payload_copy(InsertAt::HeadOf(Some(at[5])), f(14), b"tmp").unwrap();
    static INS_PARTS: [&[u8]; 2] = [b"pa", b"rts"];
    patch.insert_payload_parts(PInsertAt::TailOf(None), f(15), &INS_PARTS).unwrap();
    adopt.insert_payload_parts(InsertAt::TailOf(None), f(15), &INS_PARTS).unwrap();

    // The staged payload frames: a set and an insert, chunked
    // identically on both sides.
    let mut pf = patch.begin_set_payload(pt[6 + 1]).unwrap();
    pf.write(b"fra").unwrap();
    pf.write(b"med").unwrap();
    pf.finish().unwrap();
    let mut af = adopt.begin_set_payload(at[6 + 1]).unwrap();
    af.write(b"fra").unwrap();
    af.write(b"med").unwrap();
    af.finish().unwrap();
    let mut pf = patch.begin_insert_payload(PInsertAt::After(pt[6]), f(15)).unwrap();
    pf.write(b"gro").unwrap();
    pf.write(b"wn!").unwrap();
    let pfh = pf.finish().unwrap();
    let mut af = adopt.begin_insert_payload(InsertAt::After(at[6]), f(15)).unwrap();
    af.write(b"gro").unwrap();
    af.write(b"wn!").unwrap();
    let afh = af.finish().unwrap();

    // The sized payload frames: the same chunks under a declared
    // total, on both sides.
    let mut pf = patch.begin_set_payload_sized(pt[3], 5).unwrap();
    pf.write(b"siz").unwrap();
    pf.write(b"ed").unwrap();
    pf.finish().unwrap();
    let mut af = adopt.begin_set_payload_sized(at[3], 5).unwrap();
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
    for (ph, ah) in patch.children(pt[5]).zip(adopt.children(at[5])) {
        faces_agree(&patch, ph, &adopt, ah);
    }
    faces_agree(&patch, pfh, &adopt, afh);

    // The coordinate-resolving face agrees at every source byte.
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

    // A shrink twin over a fresh pair: the container prefix
    // re-authors downward on both sides.
    let mut patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let mut adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let pt: Vec<_> = patch.top().collect();
    let at: Vec<_> = adopt.top().collect();
    let crate::patch::groupless::Descent::Opened { .. } = patch.descend(pt[5]).unwrap() else {
        unreachable!()
    };
    let Descent::Opened { .. } = adopt.descend(at[5]).unwrap() else { unreachable!() };
    let pk: Vec<_> = patch.children(pt[5]).collect();
    let ak: Vec<_> = adopt.children(at[5]).collect();
    patch.set_payload(pk[1], b"z").unwrap();
    adopt.set_payload(ak[1], b"z").unwrap();
    saves_agree(&patch, &adopt);
}

/// The clean arc: no command lands, and both machines save the
/// source verbatim — padding included — through every face.
#[cfg(feature = "patch-groupless")]
#[test]
fn a_clean_adopt_saves_the_source_verbatim_like_a_clean_patch() {
    use crate::patch::groupless::Patch;

    let msg: &[u8] = &[0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
    let patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    saves_agree(&patch, &adopt);
    assert_eq!(adopt.save().unwrap(), msg);
}

/// Command refusals agree: the same ill-formed commands refuse
/// with the same fault on both machines, leaving both unchanged.
#[cfg(feature = "patch-groupless")]
#[test]
fn command_refusals_agree_with_the_borrowed_patch() {
    use alloc::format;

    use crate::patch::groupless::{InsertAt as PInsertAt, Patch};

    // varint f1 · LEN f2 "hi"
    let msg: &[u8] = &[0x08, 0x2A, 0x12, 0x02, 0x68, 0x69];
    let mut patch = Patch::open(msg, DepthLimit::REFERENCE).unwrap();
    let mut adopt = Adopt::open(msg.to_vec(), DepthLimit::REFERENCE).unwrap();
    let pt: Vec<_> = patch.top().collect();
    let at: Vec<_> = adopt.top().collect();

    // Kind mismatch, deleted target, unopened container — judged
    // identically.
    let pe = patch.set_varint(pt[1], 1).unwrap_err();
    let ae = adopt.set_varint(at[1], 1).unwrap_err();
    assert_eq!(format!("{pe:?}"), format!("{ae:?}"));
    patch.delete(pt[0]).unwrap();
    adopt.delete(at[0]).unwrap();
    let pe = patch.set_varint(pt[0], 1).unwrap_err();
    let ae = adopt.set_varint(at[0], 1).unwrap_err();
    assert_eq!(format!("{pe:?}"), format!("{ae:?}"));
    let pe = patch.insert_varint(PInsertAt::TailOf(Some(pt[1])), f(3), 1).unwrap_err();
    let ae = adopt.insert_varint(InsertAt::TailOf(Some(at[1])), f(3), 1).unwrap_err();
    assert_eq!(format!("{pe:?}"), format!("{ae:?}"));

    saves_agree(&patch, &adopt);
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
