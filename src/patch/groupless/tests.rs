//! Contract pins: each test states one clause of the machine's
//! contract. The cross-machine equivalence oracle lives in the
//! shared harness (`tests/patch_oracle.rs`).

use alloc::vec::Vec;

use super::*;

#[track_caller]
pub(super) fn fnum(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

#[track_caller]
pub(super) fn h(s: &str) -> Vec<u8> {
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
pub(super) fn open(data: &[u8]) -> Patch<'_, 'static> {
    Patch::open(data, DepthLimit::REFERENCE).expect("test document opens")
}

pub(super) fn tops(p: &Patch<'_, '_>) -> Vec<Handle> {
    p.top().collect()
}

#[track_caller]
pub(super) fn saved(p: &Patch<'_, '_>) -> Vec<u8> {
    p.save().expect("test save succeeds")
}

// ─── the sink save ───

#[test]
fn a_clean_sink_save_is_one_source_window() {
    let data = h("08 96 81 00 12 02 68 69");
    let p = open(&data);
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    p.save_sink(|c| chunks.push(c.to_vec())).unwrap();
    assert_eq!(chunks.len(), 1, "a clean save is one window");
    assert_eq!(chunks[0], data);
}

#[test]
fn the_sink_save_matches_the_vec_save_across_edit_shapes() {
    // f1 varint · f2 LEN {f1 varint} · f2 varint · f3 LEN "a"
    let data = h("08 01 12 02 08 07 10 2A 1A 01 61");
    let mut p = open(&data);
    let t = tops(&p);
    p.set_varint(t[0], 300).unwrap();
    let Descent::Opened { first: Some(inner) } = p.descend(t[1]).unwrap() else { unreachable!() };
    p.set_varint(inner, 5).unwrap();
    p.delete(t[2]).unwrap();
    p.set_payload(t[3], b"zz").unwrap();
    p.insert_varint(InsertAt::TailOf(None), fnum(4), 1).unwrap();

    let expected = saved(&p);
    let mut streamed = Vec::new();
    let mut slices = 0usize;
    p.save_sink(|c| {
        assert!(!c.is_empty(), "sink slices are non-empty");
        slices += 1;
        streamed.extend_from_slice(c);
    })
    .unwrap();
    assert_eq!(streamed, expected);
    assert!(slices > 2, "runs and authored words hand out separately");
}

// ─── the scatter payload and the staged frame ───

#[test]
fn scatter_payloads_equal_their_whole_slice_twins() {
    // f2 LEN "ab" replaced; a fresh LEN inserted at the tail —
    // once whole, once as pieces (an empty piece included): the
    // saves are byte-identical through both output faces.
    let data = h("12 02 61 62 08 01");
    let mut whole = open(&data);
    let t = tops(&whole);
    whole.set_payload(t[0], b"hello").unwrap();
    whole.insert_payload(InsertAt::TailOf(None), fnum(3), b"xy").unwrap();
    let expected = saved(&whole);

    let mut scattered = open(&data);
    let t = tops(&scattered);
    let set_parts: [&[u8]; 3] = [b"hel", b"", b"lo"];
    scattered.set_payload_parts(t[0], &set_parts).unwrap();
    let insert_parts: [&[u8]; 2] = [b"x", b"y"];
    scattered.insert_payload_parts(InsertAt::TailOf(None), fnum(3), &insert_parts).unwrap();
    assert_eq!(saved(&scattered), expected);

    let mut streamed = Vec::new();
    scattered.save_sink(|chunk| streamed.extend_from_slice(chunk)).unwrap();
    assert_eq!(streamed, expected);

    // No contiguous view exists before the gather.
    assert_eq!(scattered.payload_bytes(t[0]), None);
    // A whole-slice re-set over the scatter slot restores it.
    scattered.set_payload(t[0], b"back").unwrap();
    assert_eq!(scattered.payload_bytes(t[0]), Some(&b"back"[..]));
}

#[test]
fn the_staged_frame_installs_at_finish_and_only_then() {
    let data = h("12 02 61 62 08 01");
    // The set frame: chunks stage, nothing observable until
    // finish; the abandoned twin leaves the patch unchanged.
    let mut p = open(&data);
    let t = tops(&p);
    {
        let mut frame = p.begin_set_payload(t[0]).unwrap();
        frame.write(b"dis").unwrap();
        frame.write(b"carded").unwrap();
        // Dropped unfinished: no record changed.
    }
    assert_eq!(saved(&p), data, "an abandoned frame changes nothing");
    let mut frame = p.begin_set_payload(t[0]).unwrap();
    frame.write(b"wor").unwrap();
    frame.write(b"").unwrap();
    frame.write(b"ld").unwrap();
    let handle = frame.finish().unwrap();
    assert_eq!(handle, t[0]);
    assert_eq!(p.payload_bytes(t[0]), Some(&b"world"[..]), "staged bytes are contiguous");

    // The insert frame against its whole-slice twin.
    let mut whole = open(&data);
    whole.insert_payload_copy(InsertAt::After(t[0]), fnum(3), b"xyz").unwrap();
    let expected = saved(&whole);
    let mut framed = open(&data);
    let t = tops(&framed);
    let mut frame = framed.begin_insert_payload(InsertAt::After(t[0]), fnum(3)).unwrap();
    frame.write(b"xy").unwrap();
    frame.write(b"z").unwrap();
    let minted = frame.finish().unwrap();
    assert_eq!(saved(&framed), expected);
    assert_eq!(framed.payload_bytes(minted), Some(&b"xyz"[..]));
}

#[test]
fn abandoned_and_refused_frames_reclaim_the_staging_column() {
    // The staging column's cursor is finite `u32` offset space and
    // the save fingerprint cannot see it, so the cursor is its own
    // judge: every non-publishing frame exit must return the
    // column to its pre-frame state — byte length and slot count.
    let data = h("12 02 61 62 08 01");
    let mut p = open(&data);
    let t = tops(&p);
    let cursor = p.payloads.stage_mark();
    let slots = p.payloads.slots.len();

    // An abandoned undeclared frame.
    {
        let mut frame = p.begin_set_payload(t[0]).unwrap();
        frame.write(b"junk").unwrap();
    }
    assert_eq!(p.payloads.stage_mark(), cursor, "abandoned frame reclaims its bytes");
    assert_eq!(p.payloads.slots.len(), slots);

    // An abandoned sized frame, reservation and all.
    {
        let mut frame = p.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), 8).unwrap();
        frame.write(b"abc").unwrap();
    }
    assert_eq!(p.payloads.stage_mark(), cursor, "abandoned sized frame reclaims its bytes");
    assert_eq!(p.payloads.slots.len(), slots);

    // A refused finish is a non-publishing exit too.
    let mut frame = p.begin_set_payload_sized(t[0], 3).unwrap();
    frame.write(b"ab").unwrap();
    assert!(matches!(
        frame.finish().err(),
        Some(FrameFault::UnderDeclared { declared: 3, staged: 2 })
    ));
    assert_eq!(p.payloads.stage_mark(), cursor, "refused finish reclaims the staged bytes");
    assert_eq!(p.payloads.slots.len(), slots);
    assert_eq!(saved(&p), data);

    // A publishing finish keeps exactly the staged extent; a later
    // re-set leaves the published extent behind inert (the
    // commit-only trade) — only staging is ever reclaimed.
    let mut frame = p.begin_set_payload(t[0]).unwrap();
    frame.write(b"wxyz").unwrap();
    frame.finish().unwrap();
    assert_eq!(p.payloads.stage_mark(), cursor + 4, "published bytes are retained exactly");
    assert_eq!(p.payloads.slots.len(), slots + 1);
    p.set_payload(t[0], b"hi").unwrap();
    assert_eq!(p.payloads.stage_mark(), cursor + 4, "re-sets never truncate published extents");
}

// The fixture stages a real 2 GiB column: 32-bit targets cannot
// host it, and under Miri it is byte-bulk without provenance value.
// The refusal arithmetic itself is target-independent.
#[cfg(all(not(target_family = "wasm"), not(miri)))]
// The giant class-top fixture follows the streaming twin's law: a
// 32-bit wasm heap cannot host it, and under Miri it is byte-bulk
// without provenance value. The judgment itself is
// target-independent.
#[cfg(all(not(target_family = "wasm"), not(miri)))]
#[test]
fn the_staged_frame_refuses_class_overflow_per_chunk() {
    let data = h("12 02 61 62");
    let mut p = open(&data);
    let t = tops(&p);
    let mut frame = p.begin_set_payload(t[0]).unwrap();
    let big = alloc::vec![0u8; usize::try_from(PayloadLen::MAX.as_inner()).unwrap()];
    frame.write(&big).unwrap();
    let fault = frame.write(&[0]).unwrap_err();
    assert!(matches!(fault, EditFault::PayloadTooLarge { .. }));
    // The refused chunk is not staged; the frame stays usable.
    frame.finish().unwrap();
    assert_eq!(p.payload_bytes(t[0]).unwrap().len(), big.len());
}

#[test]
fn the_sized_doors_refuse_class_overflow_without_allocating() {
    // The declared form's over-cap pin: the class judgment lands
    // at begin, before any reservation — no giant allocation
    // exists to build, so the pin runs on every target and under
    // Miri (the undeclared door's allocation-backed twin stays
    // cfg-gated above).
    let data = h("12 02 61 62 08 01");
    let mut p = open(&data);
    let t = tops(&p);
    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        p.begin_set_payload_sized(t[0], over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert!(matches!(
        p.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    // Exactly the class top is admitted at the judgment (the door
    // reserves it, which this fixture-free pin must not pay), so
    // the boundary is judged one past instead: MAX + 1 refused,
    // and the machine is unchanged either way.
    assert_eq!(saved(&p), data);
}

#[test]
fn the_sized_frame_holds_its_declaration() {
    let data = h("12 02 61 62 08 01");
    let mut p = open(&data);
    let t = tops(&p);

    // A write past the declaration refuses, is not staged, and
    // the frame stays usable at its word.
    let mut frame = p.begin_set_payload_sized(t[0], 3).unwrap();
    frame.write(b"ab").unwrap();
    assert!(matches!(
        frame.write(b"cd").err(),
        Some(FrameFault::OverDeclared { declared: 3, total: 4 })
    ));
    frame.write(b"c").unwrap();
    assert_eq!(frame.finish().unwrap(), t[0]);
    assert_eq!(p.payload_bytes(t[0]), Some(&b"abc"[..]));

    // A finish short of the declaration refuses and installs
    // nothing — the machine is observably unchanged.
    let mut fresh = open(&data);
    let t = tops(&fresh);
    let mut frame = fresh.begin_set_payload_sized(t[0], 5).unwrap();
    frame.write(b"ab").unwrap();
    assert!(matches!(
        frame.finish().err(),
        Some(FrameFault::UnderDeclared { declared: 5, staged: 2 })
    ));
    assert_eq!(saved(&fresh), data, "an under-declared finish changes nothing");

    // The insert door judges the same declaration.
    let mut frame = fresh.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), 2).unwrap();
    frame.write(b"x").unwrap();
    assert!(matches!(
        frame.finish().err(),
        Some(FrameFault::UnderDeclared { declared: 2, staged: 1 })
    ));
    assert_eq!(saved(&fresh), data, "an under-declared insert splices nothing");
}

#[test]
fn sized_and_undeclared_frames_save_identically() {
    // Identical content through both doors — set and insert, the
    // same chunk seams — must land byte-identically.
    let data = h("12 02 61 62 08 01");
    let mut undeclared = open(&data);
    let t = tops(&undeclared);
    let mut frame = undeclared.begin_set_payload(t[0]).unwrap();
    frame.write(b"wor").unwrap();
    frame.write(b"ld").unwrap();
    frame.finish().unwrap();
    let mut frame = undeclared.begin_insert_payload(InsertAt::After(t[1]), fnum(3)).unwrap();
    frame.write(b"x").unwrap();
    frame.write(b"yz").unwrap();
    frame.finish().unwrap();
    let expected = saved(&undeclared);

    let mut sized = open(&data);
    let t = tops(&sized);
    let mut frame = sized.begin_set_payload_sized(t[0], 5).unwrap();
    frame.write(b"wor").unwrap();
    frame.write(b"ld").unwrap();
    frame.finish().unwrap();
    let mut frame = sized.begin_insert_payload_sized(InsertAt::After(t[1]), fnum(3), 3).unwrap();
    frame.write(b"x").unwrap();
    frame.write(b"yz").unwrap();
    frame.finish().unwrap();
    assert_eq!(saved(&sized), expected);

    // An empty declaration is lawful: zero chunks satisfy it.
    let mut empty = open(&data);
    let t = tops(&empty);
    let frame = empty.begin_set_payload_sized(t[0], 0).unwrap();
    frame.finish().unwrap();
    assert_eq!(empty.payload_bytes(t[0]), Some(&[][..]));
}

// ─── the price arithmetic ───

#[test]
fn the_price_tracks_the_emission_at_every_stage() {
    // f1 varint · f2 LEN {f1 varint · f2 LEN "hi"} · f3 varint ·
    // f4 LEN "abc" — the pricing arithmetic and the fused save are
    // independent machines; equality at every stage is the
    // differential.
    let data = h("08 01 12 06 08 07 12 02 68 69 18 2A 22 03 61 62 63");
    let mut p = open(&data);
    let t = tops(&p);
    #[track_caller]
    fn check(p: &Patch<'_, '_>) {
        assert_eq!(u32::try_from(saved(p).len()).unwrap(), p.save_len().unwrap());
    }
    check(&p); // clean: the source length, no walk

    // Two edits under one root: one splice root, priced once.
    let Descent::Opened { first: Some(inner) } = p.descend(t[1]).unwrap() else { unreachable!() };
    p.set_varint(inner, 300).unwrap(); // grows
    check(&p);
    p.set_varint(inner, 1).unwrap(); // re-set shrinks; same root
    check(&p);

    // A replaced payload in both directions.
    p.set_payload(t[3], b"zzzzzz").unwrap();
    check(&p);
    p.set_payload(t[3], b"z").unwrap();
    check(&p);

    // A deleted intact root: minus its extent, no size walk.
    p.delete(t[0]).unwrap();
    check(&p);

    // An authored root: no source extent, plus its size — and
    // deleting it afterwards cancels both.
    let fresh = p.insert_varint(InsertAt::TailOf(None), fnum(9), 300).unwrap();
    check(&p);
    p.delete(fresh).unwrap();
    check(&p);

    // Dirty-then-deleted: the interior edit priced this root once;
    // deletion now prices it as pure removal.
    p.delete(t[1]).unwrap();
    check(&p);
}

// ─── the output span table ───

#[test]
fn a_clean_patch_spans_the_source_itself() {
    let data = h("08 01 12 02 08 07");
    let mut p = open(&data);
    let t = tops(&p);
    // A descend is a read: the patch stays clean, the interior
    // rows join the table.
    let Descent::Opened { first: Some(inner) } = p.descend(t[1]).unwrap() else { unreachable!() };
    let spans = p.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(table, [(t[0], Span::new(0, 2)), (t[1], Span::new(2, 6)), (inner, Span::new(4, 6))]);
}

#[test]
fn save_spans_tables_the_live_rows_in_output_order() {
    // f1 varint (padded) · f2 LEN {f1 varint} · f3 varint
    let data = h("08 96 81 00 12 02 08 07 18 2A");
    let mut p = open(&data);
    let t = tops(&p);
    let Descent::Opened { first: Some(inner) } = p.descend(t[1]).unwrap() else { unreachable!() };
    p.set_varint(inner, 300).unwrap(); // grows: the prefix re-prices
    p.delete(t[2]).unwrap();
    let inserted = p.insert_varint(InsertAt::TailOf(None), fnum(4), 1).unwrap();

    let out = saved(&p);
    assert_eq!(out, h("08 96 81 00 12 03 08 AC 02 20 01"));

    let spans = p.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(
        table,
        [
            (t[0], Span::new(0, 4)),
            (t[1], Span::new(4, 9)),
            (inner, Span::new(6, 9)),
            (inserted, Span::new(9, 11)),
        ]
    );
    // Deleted rows leave the table; the tail end is the priced
    // save; the spans cut the real bytes.
    assert!(table.iter().all(|(handle, _)| *handle != t[2]));
    assert_eq!(table.last().unwrap().1.end(), p.save_len().unwrap());
    assert_eq!(&out[table[2].1.as_range()], h("08 AC 02").as_slice());
    assert_eq!(&out[table[3].1.as_range()], h("20 01").as_slice());
}

// ─── open: the root layer ───

#[test]
fn opens_the_flat_root_layer() {
    // varint f1 · I32 f2 · LEN f3 (unopened)
    let data = h("089601 1501000000 1A03089601");
    let p = open(&data);
    let t = tops(&p);
    assert_eq!(t.len(), 3);
    assert_eq!(p.kind(t[0]), RecordKind::Varint);
    assert_eq!(p.kind(t[1]), RecordKind::I32);
    assert_eq!(p.kind(t[2]), RecordKind::Len);
    // LENs stay lazy.
    assert_eq!(p.children(t[2]).count(), 0);
    // Zero copy: the machine answers with the borrowed bytes.
    assert!(core::ptr::eq(p.source(), data.as_slice()));
}

#[test]
fn tolerant_admission_stores_padded_widths_as_input_facts() {
    // tag padded to 2 · value padded to 3 · LEN with prefix padded
    // to 2
    let data = h("8800 968100 12 8200 6869");
    let p = open(&data);
    let t = tops(&p);
    assert_eq!(t.len(), 2);
    assert_eq!(p.varint_word(t[0]).unwrap(), 150);
    // Spans rebuild from stored widths, not from re-encoded values.
    let RecordSpans::Varint { tag, value } = p.source_spans(t[0]).unwrap() else { unreachable!() };
    assert_eq!((tag.start(), tag.end()), (0, 2));
    assert_eq!((value.start(), value.end()), (2, 5));
    let RecordSpans::Len { prefix, payload, .. } = p.source_spans(t[1]).unwrap() else {
        unreachable!()
    };
    assert_eq!((prefix.start(), prefix.end()), (6, 8));
    assert_eq!((payload.start(), payload.end()), (8, 10));
}

#[test]
fn wire_faults_stop_the_open() {
    assert!(matches!(
        Patch::open(&h("08"), DepthLimit::REFERENCE).err(),
        Some(OpenFault::Wire(Fault { at: 1, kind: FaultKind::Value { field, fault: ReadFault::Truncated } }))
            if field.as_inner() == 1
    ));
    assert!(matches!(
        Patch::open(&h("00"), DepthLimit::REFERENCE).err(),
        Some(OpenFault::Wire(Fault { at: 0, kind: FaultKind::FieldZero }))
    ));
    assert!(matches!(
        Patch::open(&h("1204 0801"), DepthLimit::REFERENCE).err(),
        Some(OpenFault::Wire(Fault { at: 2, kind: FaultKind::PayloadCut { field, need: 4, have: 2 } }))
            if field.as_inner() == 2
    ));
}

#[test]
fn group_codes_are_a_capability_refusal_not_a_grammar_fault() {
    // A well-formed group open tag: lawful wire outside this
    // dialect's language.
    assert!(matches!(
        Patch::open(&h("0B 0C"), DepthLimit::REFERENCE).err(),
        Some(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
    ));
    // Inside a payload the same judgment is a resident verdict and
    // the payload stays readable as bytes.
    let data = h("1202 0B0C");
    let mut p = open(&data);
    let record = p.top().next().unwrap();
    assert!(matches!(
        p.descend(record).unwrap(),
        Descent::Refused(Refusal::GroupCode { at: 2, .. })
    ));
    assert!(matches!(
        p.descend(record).unwrap(),
        Descent::Refused(Refusal::GroupCode { at: 2, .. })
    ));
    assert_eq!(p.payload_bytes(record).unwrap(), h("0B0C"));
    assert_eq!(saved(&p), data);
}

#[test]
fn the_depth_bound_is_a_resident_descend_refusal() {
    // A LEN inside a descended LEN against a bound of one: the
    // outer descent spends the one level, the inner refuses —
    // residently.
    let doc = h("1204 12020801");
    let mut p = Patch::open(&doc, DepthLimit::MIN).unwrap();
    let outer = p.top().next().unwrap();
    let Descent::Opened { first: Some(inner) } = p.descend(outer).unwrap() else { unreachable!() };
    assert!(matches!(
        p.descend(inner).unwrap(),
        Descent::Refused(Refusal::DepthExceeded { at: 2, .. })
    ));
    assert!(matches!(
        p.descend(inner).unwrap(),
        Descent::Refused(Refusal::DepthExceeded { at: 2, .. })
    ));
}

// ─── the fidelity theorem ───

#[test]
fn descents_are_reads_and_spend_no_fidelity() {
    // padded varint · LEN{varint} · I32. Descend the LEN and edit
    // nothing: the save is still the input, bit for bit — the
    // walkless clean arm rests on the dirty witness, and reads
    // never raise it.
    let data = h("8800 968100 12 8200 0801 0D 01000000");
    let mut p = open(&data);
    let t = tops(&p);
    assert!(matches!(p.descend(t[1]).unwrap(), Descent::Opened { .. }));
    assert_eq!(saved(&p), data);
    // An edit elsewhere leaves the opened, untouched container on
    // its verbatim arm: framing and interior ride bit-exactly.
    p.set_i32(t[2], 0xAA).unwrap();
    assert_eq!(saved(&p), h("8800 968100 12 8200 0801 0D AA000000"));
}

#[test]
fn an_unedited_patch_saves_the_input_bit_exactly() {
    // Padding in every framing role this dialect has.
    let data = h("8800 968100 12 8200 6869 0D 01000000");
    let p = open(&data);
    assert_eq!(saved(&p), data);
    // Saving is repeatable.
    assert_eq!(saved(&p), data);
}

#[test]
fn untouched_records_ride_verbatim_around_an_edit() {
    // padded varint · I32 · padded LEN — only the I32 is touched.
    let data = h("8800 968100 0D 01000000 12 8200 6869");
    let mut p = open(&data);
    let t = tops(&p);
    p.set_i32(t[1], 0xAA).unwrap();
    assert_eq!(saved(&p), h("8800 968100 0D AA000000 12 8200 6869"));
}

#[test]
fn a_replaced_scalar_keeps_its_padded_source_tag() {
    let data = h("8800 968100");
    let mut p = open(&data);
    let t = tops(&p);
    p.set_varint(t[0], 7).unwrap();
    // Padded tag verbatim; the value re-emits minimally.
    assert_eq!(saved(&p), h("8800 07"));
}

#[test]
fn a_len_prefix_rides_verbatim_while_its_length_is_unchanged() {
    // Interior edit that keeps the body length: the padded prefix
    // is untouched bytes.
    let data = h("12 8200 0801");
    let mut p = open(&data);
    let wrapper = p.top().next().unwrap();
    let Descent::Opened { first: Some(inner) } = p.descend(wrapper).unwrap() else {
        unreachable!()
    };
    p.set_varint(inner, 2).unwrap();
    assert_eq!(saved(&p), h("12 8200 0802"));
}

#[test]
fn a_len_prefix_reauthors_minimally_when_its_length_moves() {
    let data = h("12 8200 0801");
    let mut p = open(&data);
    let wrapper = p.top().next().unwrap();
    let Descent::Opened { first: Some(inner) } = p.descend(wrapper).unwrap() else {
        unreachable!()
    };
    // 300 widens the value: body 2 → 3, prefix re-authored at
    // minimal width.
    p.set_varint(inner, 300).unwrap();
    assert_eq!(saved(&p), h("12 03 08AC02"));
}

#[test]
fn a_replaced_payload_keeps_the_prefix_iff_the_length_holds() {
    let data = h("12 8200 6869");
    let mut same = open(&data);
    let record = same.top().next().unwrap();
    same.set_payload(record, b"no").unwrap();
    assert_eq!(saved(&same), h("12 8200 6E6F"));

    let mut moved = open(&data);
    let record = moved.top().next().unwrap();
    moved.set_payload(record, b"y").unwrap();
    assert_eq!(saved(&moved), h("12 01 79"));
}

#[test]
fn prefix_reauthoring_cascades_through_nested_spines() {
    // outer LEN { inner LEN { varint } } — the inner edit widens
    // both bodies, so both prefixes re-author; the tags ride.
    let data = h("12 8400 12020801");
    let mut p = open(&data);
    let outer = p.top().next().unwrap();
    let Descent::Opened { first: Some(inner) } = p.descend(outer).unwrap() else { unreachable!() };
    let Descent::Opened { first: Some(leaf) } = p.descend(inner).unwrap() else { unreachable!() };
    p.set_varint(leaf, 300).unwrap();
    assert_eq!(saved(&p), h("12 05 1203 08AC02"));
}

// ─── the edit algebra ───

#[test]
fn reads_answer_the_pending_value_and_survive_deletion() {
    let data = h("089601 0D01000000 09FF00000000000000 12026869");
    let mut p = open(&data);
    let t = tops(&p);
    assert_eq!(p.varint_word(t[0]).unwrap(), 150);
    assert_eq!(p.i32_bits(t[1]).unwrap(), 1);
    assert_eq!(p.i64_bits(t[2]).unwrap(), 0xFF);
    assert_eq!(p.payload_bytes(t[3]).unwrap(), b"hi");

    p.set_varint(t[0], 7).unwrap();
    p.set_i32(t[1], 2).unwrap();
    p.set_i64(t[2], 3).unwrap();
    p.set_payload(t[3], b"no").unwrap();
    assert_eq!(p.varint_word(t[0]).unwrap(), 7);
    assert_eq!(p.i32_bits(t[1]).unwrap(), 2);
    assert_eq!(p.i64_bits(t[2]).unwrap(), 3);
    assert_eq!(p.payload_bytes(t[3]).unwrap(), b"no");

    // Deletion prunes the save, not the reads.
    p.delete(t[0]).unwrap();
    assert_eq!(p.status(t[0]), EditStatus::Deleted);
    assert_eq!(p.varint_word(t[0]).unwrap(), 7);
}

#[test]
fn statuses_track_the_algebra() {
    let data = h("089601 12026869");
    let mut p = open(&data);
    let t = tops(&p);
    assert_eq!(p.status(t[0]), EditStatus::Intact);
    p.set_varint(t[0], 7).unwrap();
    assert_eq!(p.status(t[0]), EditStatus::Replaced);
    // Re-sets stay Replaced (overwrite in place).
    p.set_varint(t[0], 8).unwrap();
    assert_eq!(p.status(t[0]), EditStatus::Replaced);
    let new = p.insert_varint(InsertAt::TailOf(None), fnum(4), 1).unwrap();
    assert_eq!(p.status(new), EditStatus::Inserted);
    // Setting an inserted record's value keeps it Inserted.
    p.set_varint(new, 2).unwrap();
    assert_eq!(p.status(new), EditStatus::Inserted);
    p.delete(new).unwrap();
    assert_eq!(p.status(new), EditStatus::Deleted);
}

#[test]
fn kind_and_deletion_gates_refuse_structurally() {
    let data = h("089601 12026869");
    let mut p = open(&data);
    let t = tops(&p);
    assert_eq!(
        p.set_varint(t[1], 1).err(),
        Some(EditFault::KindMismatch { have: RecordKind::Len })
    );
    assert_eq!(
        p.set_payload(t[0], b"x").err(),
        Some(EditFault::KindMismatch { have: RecordKind::Varint })
    );
    // Value reads are kind-gated queries, not fault channels.
    assert_eq!(p.varint_word(t[1]), None);
    assert_eq!(p.payload_bytes(t[0]), None);
    p.delete(t[0]).unwrap();
    assert_eq!(p.set_varint(t[0], 1).err(), Some(EditFault::DeletedTarget));
    assert_eq!(p.delete(t[0]).err(), Some(EditFault::DeletedTarget));
}

#[test]
fn a_deleted_record_vanishes_whole_with_its_subtree() {
    // LEN f2 { varint f1 } · varint f1
    let data = h("12020801 0807");
    let mut p = open(&data);
    let t = tops(&p);
    assert!(matches!(p.descend(t[0]).unwrap(), Descent::Opened { .. }));
    // Insertions inside the doomed subtree vanish with it.
    p.insert_varint(InsertAt::TailOf(Some(t[0])), fnum(5), 9).unwrap();
    p.delete(t[0]).unwrap();
    assert_eq!(saved(&p), h("0807"));
}

// ─── descent ───

#[test]
fn descend_is_an_explicit_commitment_with_resident_verdicts() {
    // LEN whose payload is a lawful message · LEN whose payload is
    // cut short (a wire fault under commitment).
    let data = h("12020801 1A0108");
    let mut p = open(&data);
    let t = tops(&p);
    let Descent::Opened { first: Some(inner) } = p.descend(t[0]).unwrap() else { unreachable!() };
    assert_eq!(p.varint_word(inner).unwrap(), 1);
    // The interior row hangs off the container's chain.
    assert_eq!(p.ancestors(inner).collect::<Vec<_>>(), [t[0]]);
    assert_eq!(p.ancestors(t[0]).count(), 0);
    // Re-descending projects the stored layer, not a re-parse.
    let Descent::Opened { first: Some(again) } = p.descend(t[0]).unwrap() else { unreachable!() };
    assert_eq!(again, inner);

    assert!(matches!(
        p.descend(t[1]).unwrap(),
        Descent::Faulted(Fault { at: 7, kind: FaultKind::Value { field, fault: ReadFault::Truncated } })
            if field.as_inner() == 1
    ));
    assert!(matches!(
        p.descend(t[1]).unwrap(),
        Descent::Faulted(Fault { at: 7, kind: FaultKind::Value { field, fault: ReadFault::Truncated } })
            if field.as_inner() == 1
    ));
    // The faulted payload stays readable as bytes…
    assert_eq!(p.payload_bytes(t[1]).unwrap(), h("08"));
    // …and the whole record still rides verbatim at save.
    assert_eq!(saved(&p), data);
}

#[test]
fn descend_refuses_scalars_authored_and_deleted_targets() {
    let data = h("089601 12026869 1A020801");
    let mut p = open(&data);
    let t = tops(&p);
    assert_eq!(p.descend(t[0]).err(), Some(EditFault::KindMismatch { have: RecordKind::Varint }));
    p.set_payload_copy(t[1], &h("0801")).unwrap();
    assert_eq!(p.descend(t[1]).err(), Some(EditFault::AuthoredPayload));
    let new = p.insert_payload_copy(InsertAt::TailOf(None), fnum(4), &h("0801")).unwrap();
    assert_eq!(p.descend(new).err(), Some(EditFault::AuthoredPayload));
    p.delete(t[2]).unwrap();
    assert_eq!(p.descend(t[2]).err(), Some(EditFault::DeletedTarget));
}

#[test]
fn replacing_a_faulted_payload_is_the_repair_path() {
    let data = h("1A0108");
    let mut p = open(&data);
    let record = p.top().next().unwrap();
    assert!(matches!(p.descend(record).unwrap(), Descent::Faulted(_)));
    // The repair clears the parked verdict…
    p.set_payload_copy(record, &h("0801")).unwrap();
    assert_eq!(saved(&p), h("1A020801"));
    // …and the record is authored now: no source interior.
    assert_eq!(p.descend(record).err(), Some(EditFault::AuthoredPayload));
}

#[test]
fn an_opened_interior_refuses_wholesale_replacement() {
    let data = h("12020801");
    let mut p = open(&data);
    let record = p.top().next().unwrap();
    assert!(matches!(p.descend(record).unwrap(), Descent::Opened { .. }));
    assert_eq!(p.set_payload(record, b"xy").err(), Some(EditFault::OpenedTarget));
}

// ─── insertion ───

#[test]
fn anchors_name_gaps_at_head_tail_and_after() {
    let data = h("0801 0802");
    let mut p = open(&data);
    let t = tops(&p);
    p.insert_varint(InsertAt::HeadOf(None), fnum(3), 3).unwrap();
    p.insert_varint(InsertAt::After(t[0]), fnum(4), 4).unwrap();
    p.insert_varint(InsertAt::TailOf(None), fnum(5), 5).unwrap();
    assert_eq!(saved(&p), h("1803 0801 2004 0802 2805"));
}

#[test]
fn insertion_reaches_descended_lens_only() {
    let data = h("12020801");
    let mut p = open(&data);
    let record = p.top().next().unwrap();
    // A LEN needs the descent commitment first.
    assert_eq!(
        p.insert_varint(InsertAt::TailOf(Some(record)), fnum(1), 2).err(),
        Some(EditFault::TargetUnopened)
    );
    assert!(matches!(p.descend(record).unwrap(), Descent::Opened { .. }));
    p.insert_varint(InsertAt::TailOf(Some(record)), fnum(1), 2).unwrap();
    assert_eq!(saved(&p), h("1204 0801 0802"));
}

#[test]
fn insertion_gates_refuse_scalars_deleted_and_authored_containers() {
    let data = h("089601 12026869 1A020801");
    let mut p = open(&data);
    let t = tops(&p);
    assert_eq!(
        p.insert_varint(InsertAt::TailOf(Some(t[0])), fnum(1), 1).err(),
        Some(EditFault::KindMismatch { have: RecordKind::Varint })
    );
    p.set_payload_copy(t[1], &h("0801")).unwrap();
    assert_eq!(
        p.insert_varint(InsertAt::TailOf(Some(t[1])), fnum(1), 1).err(),
        Some(EditFault::AuthoredPayload)
    );
    p.delete(t[2]).unwrap();
    assert_eq!(
        p.insert_varint(InsertAt::TailOf(Some(t[2])), fnum(1), 1).err(),
        Some(EditFault::DeletedTarget)
    );
}

#[test]
fn an_anchor_after_a_deleted_sibling_names_the_surviving_gap() {
    let data = h("0801 0802");
    let mut p = open(&data);
    let t = tops(&p);
    p.delete(t[0]).unwrap();
    p.insert_varint(InsertAt::After(t[0]), fnum(3), 3).unwrap();
    assert_eq!(saved(&p), h("1803 0802"));
}

#[test]
fn inserted_records_emit_every_kind_minimally() {
    let mut p = open(&[]);
    p.insert_varint(InsertAt::TailOf(None), fnum(1), 150).unwrap();
    p.insert_i32(InsertAt::TailOf(None), fnum(2), 1).unwrap();
    p.insert_i64(InsertAt::TailOf(None), fnum(3), 2).unwrap();
    p.insert_payload(InsertAt::TailOf(None), fnum(4), b"hi").unwrap();
    assert_eq!(saved(&p), h("089601 1501000000 190200000000000000 22026869"));
}

// ─── the borrowed payload channel ───

#[test]
fn twin_payload_faces_save_equal_bytes() {
    let data = h("089601 12026869 1A020801");
    let payload = [0xA5u8; 200];
    let mut borrowed = open(&data);
    let mut copied = open(&data);
    let bt = tops(&borrowed);
    let ct = tops(&copied);
    borrowed.set_payload(bt[1], &payload).unwrap();
    copied.set_payload_copy(ct[1], &payload).unwrap();
    let bh = borrowed.insert_payload(InsertAt::TailOf(None), fnum(4), &payload).unwrap();
    let ch = copied.insert_payload_copy(InsertAt::TailOf(None), fnum(4), &payload).unwrap();
    // Re-sets exercise the in-place slot overwrite on both faces.
    borrowed.set_payload(bh, b"tw").unwrap();
    copied.set_payload_copy(ch, b"tw").unwrap();
    borrowed.set_payload(bt[1], &payload).unwrap();
    copied.set_payload_copy(ct[1], &payload).unwrap();
    assert_eq!(saved(&borrowed), saved(&copied));
    assert_eq!(borrowed.payload_bytes(bt[1]).unwrap(), copied.payload_bytes(ct[1]).unwrap());
}

#[test]
fn a_borrowed_payload_never_enters_the_copied_column() {
    let data = h("12026869");
    let payload = [0x5Au8; 4096];
    let mut p = open(&data);
    let t = tops(&p);
    p.set_payload(t[0], &payload).unwrap();
    p.insert_payload(InsertAt::TailOf(None), fnum(3), &payload).unwrap();
    assert!(p.payloads.copied.is_empty(), "borrowed payloads stage nothing");
    // The read face answers straight from the caller's memory.
    assert!(core::ptr::eq(p.payload_bytes(t[0]).unwrap().as_ptr(), payload.as_ptr()));
    let out = saved(&p);
    assert_eq!(out.len(), (1 + 2 + 4096) * 2);
}

// ─── the coordinate face ───

#[test]
fn narrowest_resolves_source_positions_to_the_materialized_depth() {
    // varint f1=150 (0..3) · LEN f2 len=2 (3..7): tag 3, prefix 4,
    // payload 5..7 wrapping varint f1=1.
    let data = h("089601 12 02 0801");
    let mut p = open(&data);
    let t = tops(&p);
    // Scalar bytes: tag and value both name the record.
    assert_eq!(p.narrowest(0), Some(t[0]));
    assert_eq!(p.narrowest(2), Some(t[0]));
    // The whole LEN span answers as the LEN while unopened.
    assert_eq!(p.narrowest(4), Some(t[1]));
    assert_eq!(p.narrowest(6), Some(t[1]));
    // Past the document: no owner.
    assert_eq!(p.narrowest(7), None);
    // After a descend, payload positions name the interior record;
    // the LEN's own framing stays the LEN's.
    let Descent::Opened { first: Some(inner) } = p.descend(t[1]).unwrap() else { unreachable!() };
    assert_eq!(p.narrowest(5), Some(inner));
    assert_eq!(p.narrowest(6), Some(inner));
    assert_eq!(p.narrowest(4), Some(t[1]));
}

#[test]
fn narrowest_skips_authored_rows_and_keeps_deleted_ones() {
    let data = h("089601 100A");
    let mut p = open(&data);
    let t = tops(&p);
    p.insert_varint(InsertAt::After(t[0]), fnum(3), 7).unwrap();
    p.delete(t[1]).unwrap();
    assert_eq!(p.narrowest(1), Some(t[0]));
    assert_eq!(p.narrowest(3), Some(t[1]), "a deleted record still owns its source bytes");
}

// ─── save ───

#[test]
fn save_into_appends_and_leaves_the_prefix_alone() {
    let data = h("089601");
    let p = open(&data);
    let mut out = h("FF");
    p.save_into(&mut out).unwrap();
    assert_eq!(out, h("FF 089601"));
}

#[test]
fn the_machine_is_plain_data_and_the_product_is_send() {
    const fn machine_is_send<T: Send + Sync>() {}
    const fn product_is_send<T: Send + 'static>() {}
    machine_is_send::<Patch<'_, '_>>();
    product_is_send::<Vec<u8>>();
}

// ─── the payload-backing siblings ───

#[test]
fn the_thin_siblings_match_the_mixed_machine_on_their_arcs() {
    let data = h("089601 12026869 1A020801");
    let payload = [0xA5u8; 40];

    // Borrowed-only: whole-slice and scatter arcs, and the shared
    // scalar/delete core, land byte-identically.
    let mut mixed = open(&data);
    let mut thin = BorrowPatch::open(&data, DepthLimit::REFERENCE).unwrap();
    let mt = tops(&mixed);
    let tt: Vec<_> = thin.top().collect();
    mixed.set_payload(mt[1], &payload).unwrap();
    thin.set_payload(tt[1], &payload).unwrap();
    static PARTS: [&[u8]; 2] = [b"sca", b"tter"];
    mixed.set_payload_parts(mt[2], &PARTS).unwrap();
    thin.set_payload_parts(tt[2], &PARTS).unwrap();
    mixed.insert_payload(InsertAt::TailOf(None), fnum(4), &payload).unwrap();
    thin.insert_payload(InsertAt::TailOf(None), fnum(4), &payload).unwrap();
    mixed.insert_payload_parts(InsertAt::HeadOf(None), fnum(5), &PARTS).unwrap();
    thin.insert_payload_parts(InsertAt::HeadOf(None), fnum(5), &PARTS).unwrap();
    mixed.set_varint(mt[0], 300).unwrap();
    thin.set_varint(tt[0], 300).unwrap();
    assert_eq!(saved(&mixed), thin.save().unwrap());
    assert_eq!(mixed.save_len().unwrap(), thin.save_len().unwrap());
    let ms: Vec<_> = mixed.save_spans().unwrap().iter().map(|(_, s)| s).collect();
    let ts: Vec<_> = thin.save_spans().unwrap().iter().map(|(_, s)| s).collect();
    assert_eq!(ms, ts, "the output-order span tables must agree");

    // Copy-only: the copy sets and inserts under their unsuffixed
    // names, and both frame families, land byte-identically
    // against the mixed machine's staging twins.
    let mut mixed = open(&data);
    let mut thin = CopyPatch::open(&data, DepthLimit::REFERENCE).unwrap();
    let mt = tops(&mixed);
    let tt: Vec<_> = thin.top().collect();
    mixed.set_payload_copy(mt[1], b"copied").unwrap();
    thin.set_payload(tt[1], b"copied").unwrap();
    mixed.insert_payload_copy(InsertAt::After(mt[0]), fnum(4), b"tmp").unwrap();
    thin.insert_payload(InsertAt::After(tt[0]), fnum(4), b"tmp").unwrap();
    let mut mf = mixed.begin_set_payload(mt[2]).unwrap();
    mf.write(b"fra").unwrap();
    mf.write(b"med").unwrap();
    mf.finish().unwrap();
    let mut tf = thin.begin_set_payload(tt[2]).unwrap();
    tf.write(b"fra").unwrap();
    tf.write(b"med").unwrap();
    tf.finish().unwrap();
    let mut mf = mixed.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(6), 4).unwrap();
    mf.write(b"decl").unwrap();
    mf.finish().unwrap();
    let mut tf = thin.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(6), 4).unwrap();
    tf.write(b"decl").unwrap();
    tf.finish().unwrap();
    assert_eq!(saved(&mixed), thin.save().unwrap());
    assert_eq!(mixed.save_len().unwrap(), thin.save_len().unwrap());

    // The sized door's zero-allocation class refusal holds on the
    // copy-only sibling too.
    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        thin.begin_set_payload_sized(tt[2], over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
}

// ─── source transfer: the local faces ───

// ─── source transfer: the external face ───
