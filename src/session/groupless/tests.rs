//! Contract pins: this dialect's own clauses exhaustively (the
//! capability refusal, the flat layer), the dialect-orthogonal
//! semantics representatively (their full matrices live with the
//! full dialect).

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
pub(super) fn open(data: &[u8]) -> Session {
    Session::open_copy(data).expect("test document opens")
}

pub(super) fn tops(s: &Session) -> Vec<Handle> {
    s.top().collect()
}

// ─── the portable save and the output span table ───

#[test]
fn save_into_matches_the_carrier_save_across_edit_shapes() {
    // f1 varint · f2 LEN {f1 varint} · f3 varint
    let data = h("08 01 12 02 08 07 18 2A");
    let mut s = open(&data);
    let t = tops(&s);
    s.set_varint(t[0], 300).unwrap();
    let Descent::Opened { first: Some(inner) } = s.descend(t[1]).unwrap() else { unreachable!() };
    s.set_varint(inner, 5).unwrap();
    s.delete(t[2]).unwrap();
    s.insert_payload(InsertAt::TailOf(None), fnum(4), &[0xAB]).unwrap();

    let carrier = s.save().unwrap();
    let mut out = h("BE EF");
    s.save_into(&mut out).unwrap();
    assert_eq!(out[..2], h("BE EF")[..]);
    assert_eq!(out[2..], *carrier.as_slice());

    // The clean path too: a fresh session appends the document.
    let clean = open(&data);
    let mut out = Vec::new();
    clean.save_into(&mut out).unwrap();
    assert_eq!(out, data);
}

#[test]
fn the_sink_save_matches_the_carrier_save_across_edit_shapes() {
    // f1 varint · f2 LEN {f1 varint} · f3 varint — a replaced
    // scalar, an interior edit under a re-priced spine, a shroud,
    // and an authored insertion, so runs and authored words
    // interleave.
    let data = h("08 01 12 02 08 07 18 2A");
    let mut s = open(&data);
    let t = tops(&s);
    s.set_varint(t[0], 300).unwrap();
    let Descent::Opened { first: Some(inner) } = s.descend(t[1]).unwrap() else { unreachable!() };
    s.set_varint(inner, 5).unwrap();
    s.delete(t[2]).unwrap();
    s.insert_payload(InsertAt::TailOf(None), fnum(4), &[0xAB]).unwrap();

    let expected = s.save().unwrap();
    let mut streamed = Vec::new();
    let mut slices = 0usize;
    s.save_sink(|slice| {
        assert!(!slice.is_empty(), "sink slices are non-empty");
        slices += 1;
        streamed.extend_from_slice(slice);
    })
    .unwrap();
    assert_eq!(streamed, expected.as_slice());
    assert!(slices > 2, "runs and authored words hand out separately");
}

#[test]
fn a_clean_sink_save_is_one_document_window() {
    let data = h("08 96 01 12 02 68 69");
    let s = open(&data);
    let mut windows: Vec<Vec<u8>> = Vec::new();
    s.save_sink(|slice| windows.push(slice.to_vec())).unwrap();
    assert_eq!(windows.len(), 1, "a clean save is one window");
    assert_eq!(windows[0], data);
}

// ─── the staged payload frame ───

#[test]
fn the_payload_frame_equals_its_whole_slice_twin_and_reverts_in_one_step() {
    let data = h("08 01 12 02 61 62");
    let mut whole = open(&data);
    let t = tops(&whole);
    whole.set_payload(t[1], b"world").unwrap();
    whole.insert_payload(InsertAt::TailOf(None), fnum(3), b"xy").unwrap();
    let expected = whole.save().unwrap();

    let mut framed = open(&data);
    let t = tops(&framed);
    let mut frame = framed.begin_set_payload(t[1]).unwrap();
    frame.write(b"wor").unwrap();
    frame.write(b"").unwrap();
    frame.write(b"ld").unwrap();
    assert_eq!(frame.finish().unwrap(), t[1]);
    let mut frame = framed.begin_insert_payload(InsertAt::TailOf(None), fnum(3)).unwrap();
    frame.write(b"x").unwrap();
    frame.write(b"y").unwrap();
    let minted = frame.finish().unwrap();
    assert_eq!(framed.save().unwrap().as_slice(), expected.as_slice());
    assert_eq!(framed.payload_bytes(minted), Ok(&b"xy"[..]));

    // Exactly one transition per frame: two reverts restore the
    // opened document.
    assert_eq!(framed.pending(), 2);
    framed.revert();
    framed.revert();
    assert_eq!(framed.save().unwrap().as_slice(), &data[..]);
}

#[test]
fn an_abandoned_payload_frame_leaves_the_session_unchanged() {
    let data = h("12 02 61 62");
    let mut s = open(&data);
    let t = tops(&s);
    {
        let mut frame = s.begin_set_payload(t[0]).unwrap();
        frame.write(b"discarded").unwrap();
        // Dropped unfinished: no transition appended.
    }
    assert_eq!(s.pending(), 0, "no log state before a finish");
    assert_eq!(s.save().unwrap().as_slice(), &data[..]);
    {
        let mut frame = s.begin_insert_payload(InsertAt::TailOf(None), fnum(3)).unwrap();
        frame.write(b"junk").unwrap();
    }
    assert_eq!(s.pending(), 0);
    assert_eq!(s.save().unwrap().as_slice(), &data[..]);
}

#[test]
fn abandoned_and_refused_frames_reclaim_the_stores_byte_cursor() {
    // The store's byte cursor is finite `At32` offset space and the
    // save/log fingerprint cannot see it, so the cursor is its own
    // judge: every non-publishing frame exit must return the store
    // to its pre-frame state — byte length and span count both.
    let data = h("12 02 61 62");
    let mut s = open(&data);
    let t = tops(&s);
    let cursor = s.store.stage_mark();
    let spans = s.store.spans.len();

    // An abandoned undeclared frame.
    {
        let mut frame = s.begin_set_payload(t[0]).unwrap();
        frame.write(b"junk").unwrap();
    }
    assert_eq!(s.store.stage_mark(), cursor, "abandoned frame reclaims its bytes");
    assert_eq!(s.store.spans.len(), spans);

    // An abandoned sized frame: its staged bytes and offset space
    // reclaim; capacity the reservation gained may stay behind.
    {
        let mut frame = s.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), 8).unwrap();
        frame.write(b"abc").unwrap();
    }
    assert_eq!(s.store.stage_mark(), cursor, "abandoned sized frame reclaims its bytes");
    assert_eq!(s.store.spans.len(), spans);

    // A refused finish is a non-publishing exit too.
    let mut frame = s.begin_set_payload_sized(t[0], 3).unwrap();
    frame.write(b"ab").unwrap();
    assert!(matches!(
        frame.finish().err(),
        Some(FrameFault::UnderDeclared { declared: 3, staged: 2 })
    ));
    assert_eq!(s.store.stage_mark(), cursor, "refused finish reclaims the staged bytes");
    assert_eq!(s.store.spans.len(), spans);

    // A publishing finish keeps exactly the staged extent, and undo
    // retains it: published values are append-only — only staging
    // is ever reclaimed.
    let mut frame = s.begin_set_payload(t[0]).unwrap();
    frame.write(b"wxyz").unwrap();
    frame.finish().unwrap();
    assert_eq!(s.store.stage_mark(), cursor + 4, "published bytes are retained exactly");
    assert_eq!(s.store.spans.len(), spans + 1);
    s.revert();
    assert_eq!(s.store.stage_mark(), cursor + 4, "undo never truncates published values");
    assert_eq!(s.save().unwrap().as_slice(), &data[..]);
}

// The fixture stages a real 2 GiB column: 32-bit targets cannot
// host it, and under Miri it is byte-bulk without provenance value.
// The refusal arithmetic itself is target-independent.
#[cfg(all(not(target_family = "wasm"), not(miri)))]
#[test]
fn the_payload_frame_refuses_class_overflow_per_chunk() {
    let data = h("12 02 61 62");
    let mut s = open(&data);
    let t = tops(&s);
    let mut frame = s.begin_set_payload(t[0]).unwrap();
    let big = alloc::vec![0u8; usize::try_from(PayloadLen::MAX.as_inner()).unwrap()];
    frame.write(&big).unwrap();
    let fault = frame.write(&[0]).unwrap_err();
    assert!(matches!(fault, EditFault::PayloadTooLarge { .. }));
    // The refused chunk is not staged; the frame stays usable.
    frame.finish().unwrap();
    assert_eq!(s.payload_bytes(t[0]).unwrap().len(), big.len());
}

#[test]
fn the_sized_doors_refuse_class_overflow_without_allocating() {
    // The declared form's over-cap pin: the class judgment lands
    // at begin, before the fallible reservation — no giant
    // allocation exists to build, so the pin runs on every target
    // and under Miri (the allocation-backed per-chunk twin above
    // keeps its cfg gate).
    let data = h("12 02 61 62");
    let mut s = open(&data);
    let t = tops(&s);
    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        s.begin_set_payload_sized(t[0], over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert!(matches!(
        s.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert_eq!(s.pending(), 0);
    assert_eq!(s.save().unwrap().as_slice(), &data[..]);
}

#[test]
fn the_sized_frame_holds_its_declaration() {
    let data = h("12 02 61 62");
    let mut s = open(&data);
    let t = tops(&s);

    // A write past the declaration refuses, is not staged, and
    // the frame stays usable at its word.
    let mut frame = s.begin_set_payload_sized(t[0], 3).unwrap();
    frame.write(b"ab").unwrap();
    assert!(matches!(
        frame.write(b"cd").err(),
        Some(FrameFault::OverDeclared { declared: 3, total: 4 })
    ));
    frame.write(b"c").unwrap();
    assert_eq!(frame.finish().unwrap(), t[0]);
    assert_eq!(s.payload_bytes(t[0]), Ok(&b"abc"[..]));
    assert_eq!(s.pending(), 1, "a sized finish logs exactly one transition");

    // A finish short of the declaration refuses and installs
    // nothing — no row, no log entry, byte-identical save.
    let mut fresh = open(&data);
    let t = tops(&fresh);
    let mut frame = fresh.begin_set_payload_sized(t[0], 5).unwrap();
    frame.write(b"ab").unwrap();
    assert!(matches!(
        frame.finish().err(),
        Some(FrameFault::UnderDeclared { declared: 5, staged: 2 })
    ));
    assert_eq!(fresh.pending(), 0, "an under-declared finish logs nothing");
    assert_eq!(fresh.save().unwrap().as_slice(), &data[..]);

    // The insert door judges the same declaration.
    let mut frame = fresh.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), 2).unwrap();
    frame.write(b"x").unwrap();
    assert!(matches!(
        frame.finish().err(),
        Some(FrameFault::UnderDeclared { declared: 2, staged: 1 })
    ));
    assert_eq!(fresh.pending(), 0);
    assert_eq!(fresh.save().unwrap().as_slice(), &data[..]);
}

#[test]
fn sized_and_undeclared_frames_save_identically() {
    // Identical content through both doors — set and insert, the
    // same chunk seams — must land byte-identically, and the sized
    // finishes revert in the same single steps.
    let data = h("08 01 12 02 61 62");
    let mut undeclared = open(&data);
    let t = tops(&undeclared);
    let mut frame = undeclared.begin_set_payload(t[1]).unwrap();
    frame.write(b"wor").unwrap();
    frame.write(b"ld").unwrap();
    frame.finish().unwrap();
    let mut frame = undeclared.begin_insert_payload(InsertAt::TailOf(None), fnum(3)).unwrap();
    frame.write(b"x").unwrap();
    frame.write(b"y").unwrap();
    frame.finish().unwrap();
    let expected = undeclared.save().unwrap();

    let mut sized = open(&data);
    let t = tops(&sized);
    let mut frame = sized.begin_set_payload_sized(t[1], 5).unwrap();
    frame.write(b"wor").unwrap();
    frame.write(b"ld").unwrap();
    frame.finish().unwrap();
    let mut frame = sized.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), 2).unwrap();
    frame.write(b"x").unwrap();
    frame.write(b"y").unwrap();
    frame.finish().unwrap();
    assert_eq!(sized.save().unwrap().as_slice(), expected.as_slice());

    assert_eq!(sized.pending(), 2);
    sized.revert();
    sized.revert();
    assert_eq!(sized.save().unwrap().as_slice(), &data[..]);
}

#[test]
fn save_spans_tables_the_emitted_rows_in_output_order() {
    // f1 varint · f2 LEN {f1 varint} · f3 varint
    let data = h("08 01 12 02 08 07 18 2A");
    let mut s = open(&data);
    let t = tops(&s);
    let Descent::Opened { first: Some(inner) } = s.descend(t[1]).unwrap() else { unreachable!() };
    s.set_varint(inner, 300).unwrap(); // grows: the prefix re-prices
    s.delete(t[2]).unwrap();
    let inserted = s.insert_varint(InsertAt::TailOf(None), fnum(4), 1).unwrap();

    let out = s.save().unwrap();
    assert_eq!(out.as_slice(), h("08 01 12 03 08 AC 02 20 01").as_slice());

    let spans = s.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(
        table,
        [
            (t[0], Span::new(0, 2)),
            (t[1], Span::new(2, 7)),
            (inner, Span::new(4, 7)),
            (inserted, Span::new(7, 9)),
        ]
    );
    // Shrouded rows leave the table; a revert restores the entry.
    assert!(table.iter().all(|(handle, _)| *handle != t[2]));
    let far = table.iter().map(|(_, span)| span.end()).max().unwrap();
    assert_eq!(far, s.save_len().unwrap());
    assert_eq!(&out.as_slice()[table[2].1.as_range()], h("08 AC 02").as_slice());
}

#[test]
fn ghosts_and_authored_interiors_stay_off_the_span_table() {
    let data = h("08 01");
    let mut s = open(&data);
    // A reverted insertion is a ghost: no bytes, no entry.
    s.insert_varint(InsertAt::TailOf(None), fnum(2), 7).unwrap();
    s.revert().unwrap();
    // An authored payload emits wholesale: one entry, even after a
    // descend scanned rows out of it.
    let body = s.insert_payload(InsertAt::TailOf(None), fnum(3), &h("08 05")).unwrap();
    assert!(matches!(s.descend(body).unwrap(), Descent::Opened { first: Some(_) }));

    let spans = s.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(table.len(), 2);
    assert_eq!(table[0].1, Span::new(0, 2));
    assert_eq!((table[1].0, table[1].1), (body, Span::new(2, 6)));
}

#[test]
fn a_span_carries_a_record_across_the_save_reopen_gap() {
    // The cross-save identity recipe, end to end: span before the
    // save, narrowest after the reopen.
    let data = h("08 01 12 02 08 07");
    let mut s = open(&data);
    let t = tops(&s);
    let Descent::Opened { first: Some(inner) } = s.descend(t[1]).unwrap() else { unreachable!() };
    s.set_varint(inner, 300).unwrap();

    let spans = s.save_spans().unwrap();
    let (_, span) = spans.iter().find(|(handle, _)| *handle == inner).unwrap();
    let saved = s.save().unwrap();

    // LEN interiors materialize on descend: the byte coordinate
    // first names the covering container, then the exact record.
    let mut next = Session::open(saved).unwrap();
    let container = next.narrowest(span.start()).unwrap();
    assert_eq!(next.field(container), Ok(fnum(2)));
    assert!(matches!(next.descend(container).unwrap(), Descent::Opened { .. }));
    let recovered = next.narrowest(span.start()).unwrap();
    assert_eq!(next.field(recovered), Ok(fnum(1)));
    assert_eq!(next.varint_word(recovered), Ok(300));
}

// ─── the capability refusal (this dialect's own law) ───

#[test]
fn a_group_open_at_root_is_refused_as_outside_the_language() {
    let fault = Session::open_copy(&h("0B")).err().expect("group code refused");
    assert!(
        matches!(
            fault,
            OpenFault::Refused(Refusal::GroupCode { at: 0, low3, .. })
                if low3 == Low3::new(3).unwrap()
        ),
        "expected the capability refusal, got {fault:?}"
    );
}

#[test]
fn a_group_end_is_refused_the_same_way() {
    let fault = Session::open_copy(&h("0C")).err().expect("group end refused");
    assert!(matches!(fault, OpenFault::Refused(Refusal::GroupCode { at: 0, .. })), "got {fault:?}");
}

#[test]
fn a_group_inside_a_len_is_a_resident_refusal_not_a_session_stop() {
    // Mixed proto2 traffic in a LEN payload: descend refuses, the
    // session lives on, the payload reads as bytes.
    let data = h("0A04 0B08010C");
    let mut s = open(&data);
    let len = tops(&s)[0];
    match s.descend(len).unwrap() {
        Descent::Refused(Refusal::GroupCode { at: 2, field, .. }) => {
            assert_eq!(*field, fnum(1));
        }
        other => panic!("expected the resident refusal, got {other:?}"),
    }
    assert_eq!(s.payload_bytes(len).unwrap(), &h("0B08010C")[..]);
}

// ─── the flat layer ───

#[test]
fn opens_a_flat_layer_and_stays_lazy() {
    let data = h("089601 0A03089601 0D01000000");
    let s = open(&data);
    let t = tops(&s);
    assert_eq!(t.len(), 3);
    assert_eq!(s.kind(t[0]).unwrap(), RecordKind::Varint);
    assert_eq!(s.kind(t[1]).unwrap(), RecordKind::Len);
    assert_eq!(s.kind(t[2]).unwrap(), RecordKind::I32);
    assert_eq!(s.children(t[1]).unwrap().count(), 0); // lazy
}

#[test]
fn nonminimal_widths_are_refused_not_faulted() {
    let fault = Session::open_copy(&h("8800 01")).err().expect("padding refused");
    assert!(
        matches!(fault, OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 })),
        "got {fault:?}"
    );
}

#[test]
fn wire_violations_fault() {
    let fault = Session::open_copy(&h("08")).err().expect("cut value");
    assert!(
        matches!(fault, OpenFault::Wire(Fault { at: 1, kind: FaultKind::Value { .. } })),
        "got {fault:?}"
    );
}

// ─── representative shared semantics ───

#[test]
fn descend_edit_revert_round_trip() {
    let data = h("0A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.expect("one child"),
        other => panic!("{other:?}"),
    };
    assert_eq!(s.varint_word(kid).unwrap(), 150);
    s.set_varint(kid, 7).unwrap();
    assert_eq!(s.varint_word(kid).unwrap(), 7);
    s.revert();
    assert_eq!(s.varint_word(kid).unwrap(), 150);
    assert_eq!(s.status(kid).unwrap(), EditStatus::Intact);
}

#[test]
fn rebacking_over_an_edited_interior_is_refused() {
    let data = h("0A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.unwrap(),
        other => panic!("{other:?}"),
    };
    s.set_varint(kid, 7).unwrap();
    assert!(matches!(s.set_payload(len, b"zz"), Err(EditFault::EditedInterior)));
    s.revert_all();
    s.set_payload(len, b"zz").unwrap();
    assert!(matches!(s.varint_word(kid), Err(EditFault::DeadHandle)));
}

#[test]
fn authored_payloads_descend_but_refuse_edits() {
    let data = h("0A0161");
    let mut s = open(&data);
    let len = tops(&s)[0];
    s.set_payload(len, &h("089601")).unwrap();
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.expect("authored interior parses"),
        other => panic!("{other:?}"),
    };
    assert_eq!(s.varint_word(kid).unwrap(), 150);
    assert!(matches!(s.set_varint(kid, 1), Err(EditFault::InsideAuthoredBody)));
}

#[test]
fn inserts_splice_and_ghosts_stay() {
    let data = h("089601");
    let mut s = open(&data);
    let t = tops(&s);
    let ins = s.insert_payload(InsertAt::After(t[0]), fnum(2), b"ab").unwrap();
    assert_eq!(s.top().count(), 2);
    s.revert();
    assert_eq!(s.status(ins).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(s.top().count(), 2); // topology is monotone
}

// ─── save ───

#[test]
fn clean_and_ghosted_sessions_save_pointer_clean() {
    let data = h("089601 0A0161");
    let mut s = open(&data);
    assert!(DocBytes::ptr_eq(s.doc(), &s.save().unwrap()));
    let _ = s.insert_varint(InsertAt::TailOf(None), fnum(3), 1).unwrap();
    s.revert();
    assert!(DocBytes::ptr_eq(s.doc(), &s.save().unwrap()));
}

#[test]
fn len_prefixes_recompute_and_clean_spans_copy_bit_true() {
    // LEN f1 { varint f1 · varint f1 } · I32 f2 — delete one
    // child; the fixed record must be byte-identical.
    let data = h("0A04 0801 0802 1501000000");
    let mut s = open(&data);
    let t = tops(&s);
    assert!(matches!(s.descend(t[0]).unwrap(), Descent::Opened { .. }));
    let kids: Vec<_> = s.children(t[0]).unwrap().collect();
    s.delete(kids[0]).unwrap();
    let saved = s.save().unwrap();
    assert_eq!(saved.as_slice(), &h("0A02 0802 1501000000")[..]);
}

#[test]
fn nested_authored_payloads_emit_recursively() {
    // Replace a payload with bytes that themselves parse; edits are
    // wholesale, and save emits the authored bytes verbatim.
    let data = h("0A0161");
    let mut s = open(&data);
    let len = tops(&s)[0];
    s.set_payload(len, &h("089601")).unwrap();
    let saved = s.save().unwrap();
    assert_eq!(saved.as_slice(), &h("0A03 089601")[..]);
}

#[test]
fn saved_documents_reopen_zero_copy() {
    let data = h("089601");
    let mut s = open(&data);
    s.set_varint(tops(&s)[0], 1).unwrap();
    let saved = s.save().unwrap();
    let s2 = Session::open(saved).unwrap();
    assert_eq!(s2.varint_word(tops(&s2)[0]).unwrap(), 1);
}

// ─── handles and spans ───

#[test]
#[should_panic = "index out of bounds"]
pub(super) fn forged_handles_panic() {
    let data = h("089601");
    let s = open(&data);
    let _ = s.kind(Handle(RowId::new(99).unwrap()));
}

#[test]
fn spans_index_the_hex_view() {
    let data = h("089601 0A0161");
    let s = open(&data);
    let t = tops(&s);
    assert_eq!(s.span(t[0]).unwrap(), Some(Span::new(0, 3)));
    assert_eq!(s.span(t[1]).unwrap(), Some(Span::new(3, 6)));
    assert_eq!(s.narrowest(4), Some(t[1]));
}

// ─── consumer-facing axes: geometry, by-number ───

#[test]
fn source_spans_partition_each_backed_record() {
    let data = h("089601 15AABBCCDD 19AABBCCDD11223344 12026869");
    let s = open(&data);
    for handle in s.top() {
        let span = s.span(handle).unwrap().unwrap();
        match s.source_spans(handle).unwrap().unwrap() {
            RecordSpans::Varint { tag, value }
            | RecordSpans::I32 { tag, value }
            | RecordSpans::I64 { tag, value } => {
                assert_eq!(tag.start(), span.start());
                assert_eq!(tag.end(), value.start());
                assert_eq!(value.end(), span.end());
            }
            RecordSpans::Len { tag, prefix, payload } => {
                assert_eq!(tag.start(), span.start());
                assert_eq!(tag.end(), prefix.start());
                assert_eq!(prefix.end(), payload.start());
                assert_eq!(payload.end(), span.end());
            }
        }
    }
}

#[test]
fn by_field_narrows_in_wire_order() {
    let data = h("0801 1002 0803");
    let s = open(&data);
    let t = tops(&s);
    let ones: Vec<Handle> = s.top().by_field(fnum(1)).collect();
    assert_eq!(ones, [t[0], t[2]]);
}

// ─── the edit algebra law: revert restores the observable state ───

#[test]
fn any_edit_sequence_reverts_to_the_pristine_observable_state() {
    let data = h("089601 12026869");
    let mut s = open(&data);
    let t = tops(&s);

    s.set_varint(t[0], 7).unwrap();
    s.set_payload(t[1], b"world").unwrap();
    let inserted = s.insert_varint(InsertAt::After(t[0]), fnum(9), 1).unwrap();
    s.delete(t[0]).unwrap();
    s.undelete(t[0]).unwrap();
    s.set_varint(inserted, 2).unwrap();
    s.set_varint(t[0], 8).unwrap();
    s.clear_edit(t[0]).unwrap();

    while s.revert().is_some() {}

    let saved = s.save().unwrap();
    assert!(DocBytes::ptr_eq(&saved, &s.save().unwrap()));
    assert_eq!(saved.as_slice(), data.as_slice());
    assert_eq!(s.pending(), 0);
    for &handle in &t {
        assert_eq!(s.status(handle).unwrap(), EditStatus::Intact);
    }
}

// ─── narrowest: bisection against the full-walk definition ───

/// A tiny deterministic generator for the equivalence loop.
pub(super) struct XorShift(u32);

impl XorShift {
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

/// Every reachable handle, by descending the materialized tree.
pub(super) fn reachable(s: &Session) -> Vec<Handle> {
    let mut out: Vec<Handle> = Vec::new();
    let mut stack: Vec<Handle> = s.top().collect();
    while let Some(handle) = stack.pop() {
        out.push(handle);
        stack.extend(s.children(handle).unwrap());
    }
    out
}

/// The definitional answer: the minimum-width source span covering
/// `pos`, found by walking every reachable record.
pub(super) fn narrowest_by_walk(s: &Session, pos: u32) -> Option<Handle> {
    let mut best: Option<(u32, Handle)> = None;
    for handle in reachable(s) {
        if let Some(span) = s.span(handle).unwrap()
            && span.start() <= pos
            && pos < span.end()
        {
            let width = span.end() - span.start();
            if best.is_none_or(|(w, _)| width < w) {
                best = Some((width, handle));
            }
        }
    }
    best.map(|(_, handle)| handle)
}

#[test]
fn narrowest_matches_a_full_walk_under_random_commands() {
    // varint · LEN{varint · LEN{varint}} · I32 · LEN{group code} —
    // every kind, one nesting axis, and a payload whose descend
    // faults resident (group codes are refused in this dialect).
    let data = h("089601 1A08 089601 1A03089601 15AABBCCDD 1A01 0B");
    let sweep = u32::try_from(data.len()).unwrap() + 2;
    let mut s = open(&data);
    let mut rng = XorShift(0x9E37_79B9);
    let mut opened: Vec<Handle> = Vec::new();
    let mut new_layers = 0_u32;
    let mut resident_faults = 0_u32;
    let mut payload_sets = 0_u32;
    let mut opened_flips = 0_u32;
    for _ in 0..200 {
        let pool = reachable(&s);
        let pick = pool[rng.next() as usize % pool.len()];
        let lens: Vec<Handle> = pool
            .iter()
            .copied()
            .filter(|&handle| matches!(s.kind(handle), Ok(RecordKind::Len)))
            .collect();
        let len_pick = if lens.is_empty() { pick } else { lens[rng.next() as usize % lens.len()] };
        match rng.next() % 12 {
            0 | 1 => {
                let _ = s.set_varint(pick, u64::from(rng.next()));
            }
            2 => {
                let _ = s.delete(pick);
            }
            3 => {
                let _ = s.undelete(pick);
            }
            4 | 5 => match s.descend(len_pick) {
                Ok(Descent::Opened { .. }) if !opened.contains(&len_pick) => {
                    new_layers += 1;
                    opened.push(len_pick);
                }
                Ok(Descent::Faulted(_) | Descent::Refused(_)) => resident_faults += 1,
                _ => {}
            },
            6 | 7 => {
                let payload = match rng.next() % 4 {
                    0 => h("089601"),
                    1 => Vec::new(),
                    2 => h("1A03089601"),
                    // A group code: the descend of this authored
                    // payload refuses resident.
                    _ => h("0B"),
                };
                if s.set_payload(len_pick, &payload).is_ok() {
                    payload_sets += 1;
                    if let Some(at) = opened.iter().position(|&handle| handle == len_pick) {
                        opened_flips += 1;
                        let _ = opened.swap_remove(at);
                    }
                }
            }
            8 => {
                let _ = s.insert_varint(InsertAt::After(pick), fnum(9), 7);
            }
            9 => {
                let _ = s.insert_payload(InsertAt::TailOf(None), fnum(3), &h("0801"));
            }
            10 => {
                let _ = s.clear_edit(pick);
            }
            _ => {
                let _ = s.revert();
            }
        }
        for pos in 0..sweep {
            assert_eq!(s.narrowest(pos), narrowest_by_walk(&s, pos), "pos {pos}");
        }
    }
    // Coverage census: the loop must keep reaching the states the
    // bisection depends on — fresh interior runs, resident faults
    // (`source: None`), and flips that orphan an opened interior —
    // or the equivalence claim above goes hollow.
    assert!(new_layers >= 4, "descend opened only {new_layers} new layers");
    assert!(resident_faults >= 2, "descend faulted resident only {resident_faults} times");
    assert!(payload_sets >= 8, "set_payload succeeded only {payload_sets} times");
    assert!(opened_flips >= 2, "only {opened_flips} flips orphaned an opened interior");
}

// ─── the interior gate: counter reads against the definition ───

/// The gate's definition, independent of the counters: walk the
/// whole log and climb each entry's ancestor chain; the target is
/// refused exactly when a chain passes through it.
pub(super) fn gated_by_log_walk(s: &Session, target: Handle) -> bool {
    s.log.iter().any(|t| {
        let mut cur = s.rows[t.row().index()].parent;
        while let Some(parent) = cur {
            if parent == target.0 {
                return true;
            }
            cur = s.rows[parent.index()].parent;
        }
        false
    })
}

#[test]
fn the_interior_gate_matches_the_log_climb_on_every_row() {
    let data = h("089601 1A08 089601 1A03089601 15AABBCCDD");
    let mut s = open(&data);
    let mut rng = XorShift(0xB529_7A4D);
    for _ in 0..300 {
        let pool = reachable(&s);
        let pick = pool[rng.next() as usize % pool.len()];
        match rng.next() % 8 {
            0 | 1 => {
                let _ = s.set_varint(pick, u64::from(rng.next()));
            }
            2 => {
                let _ = s.descend(pick);
            }
            3 => {
                let _ = s.set_payload(pick, &h("089601"));
            }
            4 => {
                let _ = s.delete(pick);
            }
            5 => {
                let _ = s.undelete(pick);
            }
            6 => {
                let _ = s.insert_varint(InsertAt::After(pick), fnum(9), 7);
            }
            _ => {
                let _ = s.revert();
            }
        }
        for index in 0..s.rows.len() {
            let id = RowId::new(u32::try_from(index).unwrap()).unwrap();
            let refused = matches!(s.interior_gate(id), Err(EditFault::EditedInterior));
            assert_eq!(refused, gated_by_log_walk(&s, Handle(id)), "row {index}");
        }
    }
}

// ─── layer tails: TailOf at every publication depth ───

#[test]
fn tail_inserts_land_last_at_every_depth() {
    let data = h("1A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    // Into a descend-published interior layer.
    assert!(matches!(s.descend(len).unwrap(), Descent::Opened { .. }));
    let in_len = s.insert_varint(InsertAt::TailOf(Some(len)), fnum(2), 2).unwrap();
    assert_eq!(s.children(len).unwrap().last(), Some(in_len));
    // A reverted tail insert leaves a ghost at the tail; the next
    // tail insert lands after it.
    let ghost = s.insert_varint(InsertAt::TailOf(None), fnum(2), 3).unwrap();
    s.revert();
    assert_eq!(s.status(ghost).unwrap(), EditStatus::InsertedDeleted);
    let after_ghost = s.insert_varint(InsertAt::TailOf(None), fnum(2), 4).unwrap();
    assert_eq!(tops(&s).last().copied(), Some(after_ghost));
    let saved = s.save().unwrap();
    assert_eq!(saved.as_slice(), &h("1A05 089601 1002 1004")[..]);
}

// ─── the borrowed-payload sibling, in lockstep with the copy-only
// session: the same command script must leave both machines with
// byte-identical saves and log depths at every step ───

/// The copy-only session and its borrowed-payload sibling over the
/// same document, driven command by command.
pub(super) struct Twins<'p> {
    copy: Session,
    borrow: BorrowSession<'p>,
}

impl<'p> Twins<'p> {
    #[track_caller]
    fn open(data: &[u8]) -> Self {
        Self {
            copy: Session::open_copy(data).expect("twin document opens"),
            borrow: BorrowSession::open_copy(data).expect("twin document opens"),
        }
    }

    /// Applies one command to each twin and pins the observable
    /// agreement: byte-identical saves, equal prices, equal log
    /// depths.
    #[track_caller]
    fn lockstep(
        &mut self,
        copy_cmd: impl FnOnce(&mut Session),
        borrow_cmd: impl FnOnce(&mut BorrowSession<'p>),
    ) {
        copy_cmd(&mut self.copy);
        borrow_cmd(&mut self.borrow);
        let a = self.copy.save().expect("copy twin saves");
        let b = self.borrow.save().expect("borrow twin saves");
        assert_eq!(a[..], b[..], "the twins' saves diverged");
        assert_eq!(self.copy.save_len().unwrap(), self.borrow.save_len().unwrap());
        assert_eq!(self.copy.pending(), self.borrow.pending(), "log depths diverged");
    }
}

#[test]
fn borrowed_installs_and_reverts_track_the_copy_only_session() {
    // LEN f2 "a" · varint f1=150
    let doc = h("12 01 61 08 96 01");
    let alpha = h("08 01");
    let beta = h("08 07 08 08");
    let mut t = Twins::open(&doc);
    // Install alpha, then beta over it: two slots, two log steps.
    t.lockstep(
        |s| s.set_payload(tops(s)[0], &alpha).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &alpha).unwrap();
        },
    );
    t.lockstep(
        |s| s.set_payload(tops(s)[0], &beta).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &beta).unwrap();
        },
    );
    // Revert beta: the restored coordinate names alpha's own slot.
    t.lockstep(
        |s| {
            s.revert();
        },
        |s| {
            s.revert();
        },
    );
    let r = t.borrow.top().next().unwrap();
    assert_eq!(t.borrow.payload_bytes(r).unwrap(), alpha);
    // Revert alpha: the source payload speaks again.
    t.lockstep(
        |s| {
            s.revert();
        },
        |s| {
            s.revert();
        },
    );
    assert_eq!(t.borrow.payload_bytes(r).unwrap(), *b"a");
    assert_eq!(t.borrow.save().unwrap()[..], doc[..]);
}

#[test]
fn delete_and_undelete_ride_a_borrowed_replacement_in_lockstep() {
    let doc = h("12 01 61 08 96 01");
    let alpha = h("08 2A");
    let mut t = Twins::open(&doc);
    t.lockstep(
        |s| s.set_payload(tops(s)[0], &alpha).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &alpha).unwrap();
        },
    );
    // The shroud parks the replacement; undeletion restores the
    // same slot coordinate.
    t.lockstep(
        |s| s.delete(tops(s)[0]).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.delete(r).unwrap();
        },
    );
    t.lockstep(
        |s| s.undelete(tops(s)[0]).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.undelete(r).unwrap();
        },
    );
    let r = t.borrow.top().next().unwrap();
    assert_eq!(t.borrow.status(r).unwrap(), EditStatus::Replaced);
    assert_eq!(t.borrow.payload_bytes(r).unwrap(), alpha);
}

#[test]
fn clear_and_reapply_flip_the_backing_in_lockstep() {
    let doc = h("12 01 61");
    let alpha = h("08 01");
    let beta = h("08 07");
    let mut t = Twins::open(&doc);
    t.lockstep(
        |s| s.set_payload(tops(s)[0], &alpha).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &alpha).unwrap();
        },
    );
    // Clearing restores the scanned state; the slot stays behind
    // for the log to restore.
    t.lockstep(
        |s| s.clear_edit(tops(s)[0]).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.clear_edit(r).unwrap();
        },
    );
    assert_eq!(t.borrow.save().unwrap()[..], doc[..]);
    t.lockstep(
        |s| s.set_payload(tops(s)[0], &beta).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &beta).unwrap();
        },
    );
    let r = t.borrow.top().next().unwrap();
    assert_eq!(t.borrow.payload_bytes(r).unwrap(), beta);
    // Unwinding the whole script lands back on the source bytes.
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.borrow.save().unwrap()[..], doc[..]);
}

#[test]
fn a_borrowed_insertions_birth_reverts_to_a_ghost_in_lockstep() {
    let doc = h("08 96 01");
    let body = h("08 01");
    let mut t = Twins::open(&doc);
    t.lockstep(
        |s| {
            s.insert_payload(InsertAt::TailOf(None), fnum(2), &body).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), fnum(2), &body).unwrap();
        },
    );
    t.lockstep(
        |s| {
            s.revert();
        },
        |s| {
            s.revert();
        },
    );
    // The birth reverts to a ghost: in the topology, off the save.
    let ghost = t.borrow.top().last().unwrap();
    assert_eq!(t.borrow.status(ghost).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(t.borrow.save().unwrap()[..], doc[..]);
}

#[test]
fn descents_agree_before_and_after_each_backing_flip() {
    // LEN f2 wrapping varint f1=1.
    let doc = h("12 02 08 01");
    // A nested authored payload: LEN f2 wrapping varint f1=7.
    let nested = h("12 02 08 07");
    let mut t = Twins::open(&doc);
    // Descend the source-backed interior and edit inside it.
    t.lockstep(
        |s| {
            let r = tops(s)[0];
            let Descent::Opened { first: Some(inner) } = s.descend(r).unwrap() else {
                panic!("source interior opens")
            };
            s.set_varint(inner, 5).unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            let Descent::Opened { first: Some(inner) } = s.descend(r).unwrap() else {
                panic!("source interior opens")
            };
            s.set_varint(inner, 5).unwrap();
        },
    );
    // Unwind the interior edit, then flip the backing to a
    // borrowed payload whose interior nests one more LEN.
    t.lockstep(
        |s| {
            s.revert();
            s.set_payload(tops(s)[0], &nested).unwrap();
        },
        |s| {
            s.revert();
            let r = s.top().next().unwrap();
            s.set_payload(r, &nested).unwrap();
        },
    );
    // Both descend the authored zone; the borrowed twin reads the
    // slot through the ancestor witness at depth one and two.
    let (copy_inner, borrow_inner) = {
        let rc = tops(&t.copy)[0];
        let Descent::Opened { first: Some(ci) } = t.copy.descend(rc).unwrap() else {
            panic!("authored interior opens")
        };
        let rb = t.borrow.top().next().unwrap();
        let Descent::Opened { first: Some(bi) } = t.borrow.descend(rb).unwrap() else {
            panic!("authored interior opens")
        };
        (ci, bi)
    };
    assert_eq!(
        t.copy.payload_bytes(copy_inner).unwrap(),
        t.borrow.payload_bytes(borrow_inner).unwrap(),
    );
    let (copy_leaf, borrow_leaf) = {
        let Descent::Opened { first: Some(cl) } = t.copy.descend(copy_inner).unwrap() else {
            panic!("nested authored interior opens")
        };
        let Descent::Opened { first: Some(bl) } = t.borrow.descend(borrow_inner).unwrap() else {
            panic!("nested authored interior opens")
        };
        (cl, bl)
    };
    assert_eq!(t.copy.varint_word(copy_leaf).unwrap(), 7);
    assert_eq!(t.borrow.varint_word(borrow_leaf).unwrap(), 7);
    // Authored rows are browse-only in both machines.
    assert!(matches!(t.borrow.set_varint(borrow_leaf, 9), Err(EditFault::InsideAuthoredBody)));
    // Flip back to the source: the authored tree orphans whole,
    // and the re-descended interior is source-backed again.
    t.lockstep(
        |s| s.clear_edit(tops(s)[0]).unwrap(),
        |s| {
            let r = s.top().next().unwrap();
            s.clear_edit(r).unwrap();
        },
    );
    assert!(matches!(t.borrow.payload_bytes(borrow_inner), Err(EditFault::DeadHandle)));
    t.lockstep(
        |s| {
            let r = tops(s)[0];
            assert!(matches!(s.descend(r).unwrap(), Descent::Opened { .. }));
        },
        |s| {
            let r = s.top().next().unwrap();
            assert!(matches!(s.descend(r).unwrap(), Descent::Opened { .. }));
        },
    );
    assert_eq!(t.borrow.save().unwrap()[..], doc[..]);
}

// ─── source transfer: local faces, imports, the move law ───

// ─── the priced typestate: settled bodies, census, tiers ───

#[cfg(feature = "priced-session-groupless")]
mod priced {
    use super::*;

    #[track_caller]
    fn priced(data: &[u8]) -> PricedSession {
        Session::open_copy(data)
            .expect("test document opens")
            .into_priced()
            .map_err(|(_, fault)| fault)
            .expect("clean admits")
    }

    /// One LEN f1 record wrapping `len` zero bytes, raw.
    fn len_doc(len: usize) -> Vec<u8> {
        let mut data = alloc::vec![0x0A];
        crate::varint::push64(&mut data, u64::try_from(len).expect("test lengths are small"));
        data.extend(core::iter::repeat_n(0u8, len));
        data
    }

    /// Wraps `leaf` in `depth` LEN f1 layers and descends a fresh
    /// priced session to the leaf record; returns both.
    fn deep(leaf: &[u8], depth: usize) -> (PricedSession, Handle) {
        let mut data = leaf.to_vec();
        for _ in 0..depth {
            let mut wrapped = alloc::vec![0x0A];
            crate::varint::push64(&mut wrapped, u64::try_from(data.len()).expect("small"));
            wrapped.extend_from_slice(&data);
            data = wrapped;
        }
        let mut p = priced(&data);
        let mut cur = p.top().next().unwrap();
        for _ in 0..depth {
            let Descent::Opened { first: Some(inner) } = p.descend(cur).unwrap() else {
                unreachable!()
            };
            cur = inner;
        }
        (p, cur)
    }

    #[test]
    fn priced_wrong_kind_command_touches_no_ledger() {
        // Judge-then-reserve: the wrapped gates run before any
        // ledger obligation exists, so a deep wrong-kind command
        // performs zero ledger allocations and leaves the map
        // empty — no capacity is retained for a refusal.
        let (mut p, leaf) = deep(&[0x08, 0x01], 8);
        let total = p.save_len().expect("clean total");
        assert!(matches!(p.set_i32(leaf, 7), Err(EditFault::KindMismatch { .. })));
        assert!(matches!(p.set_payload(leaf, b"x"), Err(EditFault::KindMismatch { .. })));
        assert!(p.bodies.is_empty(), "a refused command leaves the map empty");
        assert_eq!(p.bodies.capacity(), 0, "a refused command allocates no ledger");
        assert_eq!(p.save_len(), Ok(total));
    }

    #[test]
    fn priced_zero_delta_commands_touch_no_ledger() {
        // Fixed-width and equal-width replacements move no body,
        // prefix, census member, or total, so the plan commits them
        // with no ledger reservation and no climb: the map stays
        // empty on the static case and gains no capacity on the
        // dynamic one.
        let (mut p, leaf) = deep(&[0x0D, 0, 0, 0, 0], 8);
        let total = p.save_len().expect("clean total");
        p.set_i32(leaf, 7).expect("fixed-width set succeeds");
        assert!(p.bodies.is_empty(), "a fixed-width set leaves the map empty");
        assert_eq!(p.bodies.capacity(), 0, "a fixed-width set allocates no ledger");
        assert_eq!(p.save_len(), Ok(total));

        let (mut p, leaf) = deep(&[0x08, 0x05], 8);
        p.set_varint(leaf, 300).expect("the widening set dirties the chain");
        let priced_total = p.save_len().expect("dirty total");
        let held = p.bodies.capacity();
        assert!(!p.bodies.is_empty(), "the widening set built the chain entries");
        p.set_varint(leaf, 400).expect("equal-width re-set succeeds");
        assert_eq!(p.bodies.capacity(), held, "an equal-width re-set grows no ledger");
        assert_eq!(p.save_len(), Ok(priced_total), "equal widths keep the price");
    }

    #[test]
    fn priced_abandoned_frame_touches_no_ledger() {
        // Frame doors stop reserving at open: the ledger reserve
        // belongs to the publishing finish, so a deep frame that
        // stages bytes and is dropped performs zero ledger
        // allocations and leaves the map empty.
        let (mut p, leaf) = deep(&[0x0A, 0x00], 8);
        let total = p.save_len().expect("clean total");
        {
            let mut frame = p.begin_set_payload(leaf).unwrap();
            frame.write(b"abc").unwrap();
            // Dropped unfinished: the staged bytes are reclaimed.
        }
        assert!(p.bodies.is_empty(), "an abandoned frame leaves the map empty");
        assert_eq!(p.bodies.capacity(), 0, "an abandoned frame allocates no ledger");
        {
            let mut frame = p.begin_set_payload_sized(leaf, 3).unwrap();
            frame.write(b"ab").unwrap();
        }
        assert!(p.bodies.is_empty(), "an abandoned sized frame leaves the map empty");
        assert_eq!(p.bodies.capacity(), 0, "an abandoned sized frame allocates no ledger");
        assert_eq!(p.save_len(), Ok(total));
    }

    #[test]
    fn priced_width_cascade_crosses_both_boundaries_at_the_child() {
        // head 1 + prefix 1 + 127 bytes.
        let mut p = priced(&len_doc(127));
        let t0 = p.top().next().unwrap();
        assert_eq!(p.save_len(), Ok(129));
        for (body, expect) in [(128, 131), (16383, 16386), (16384, 16388), (127, 129)] {
            p.set_payload(t0, &alloc::vec![0u8; body]).unwrap();
            assert_eq!(p.save_len(), Ok(expect), "body {body}");
            assert_eq!(p.save().unwrap().len(), expect, "body {body}");
        }
        p.revert_all();
        assert_eq!(p.save_len(), Ok(129));
    }

    #[test]
    fn priced_width_cascade_crosses_both_boundaries_at_the_ancestor() {
        // LEN f1 { LEN f2 { 125 zeros } }: the outer body sits at 127,
        // one byte under its prefix boundary.
        let mut data = alloc::vec![0x0A, 0x7F, 0x12, 0x7D];
        data.extend(core::iter::repeat_n(0u8, 125));
        let mut p = priced(&data);
        let outer = p.top().next().unwrap();
        let Descent::Opened { first: Some(inner) } = p.descend(outer).unwrap() else {
            unreachable!()
        };
        assert_eq!(p.save_len(), Ok(129));
        // Growing the inner payload by one crosses the outer prefix.
        p.set_payload(inner, &alloc::vec![0u8; 126]).unwrap();
        assert_eq!(p.save_len(), Ok(131));
        assert_eq!(p.save().unwrap().len(), 131);
        p.revert();
        assert_eq!(p.save_len(), Ok(129));

        // The 16383/16384 boundary, same shape: outer body 16383.
        let mut data = alloc::vec![0x0A, 0xFF, 0x7F, 0x12, 0xFC, 0x7F];
        data.extend(core::iter::repeat_n(0u8, 16380));
        let mut p = priced(&data);
        let outer = p.top().next().unwrap();
        let Descent::Opened { first: Some(inner) } = p.descend(outer).unwrap() else {
            unreachable!()
        };
        assert_eq!(p.save_len(), Ok(16386));
        p.set_payload(inner, &alloc::vec![0u8; 16381]).unwrap();
        assert_eq!(p.save_len(), Ok(16388), "outer prefix widens with its body");
        assert_eq!(p.save().unwrap().len(), 16388);
        p.revert();
        assert_eq!(p.save_len(), Ok(16386));
    }

    #[test]
    fn priced_entries_seed_at_first_dirt_and_settle_back_to_the_seed() {
        // LEN f2 { varint f1 = 150 }: the container's seed is its
        // source payload length.
        let data = h("12 03 08 96 01");
        let mut p = priced(&data);
        let container = p.top().next().unwrap();
        let Descent::Opened { first: Some(inner) } = p.descend(container).unwrap() else {
            unreachable!()
        };
        assert!(p.bodies.is_empty(), "descend seeds nothing");

        p.set_varint(inner, 7).unwrap();
        assert_eq!(p.bodies.get(&container.0), Some(&2), "the climb settled the shrunk body");
        assert_eq!(p.save_len(), Ok(4));

        // Dirt falls: the entry stays behind, holding the seed again.
        p.revert();
        assert_eq!(p.bodies.get(&container.0), Some(&3), "the entry settled back to its seed");
        assert_eq!(p.save_len(), Ok(5));
        assert_eq!(p.total, 5);
    }

    #[test]
    fn priced_census_crosses_the_length_class_in_both_directions() {
        // A real machine at a synthetic boundary: the ledger is seeded
        // just under the length class, and one settled climb walks the
        // crossing arithmetic both ways. The class cap is far past any
        // affordable fixture, so the boundary values are synthetic;
        // the climb, census, and tier code under judgment are real.
        let data = h("0A 02 08 01");
        let mut p = priced(&data);
        let container = p.top().next().unwrap();
        let Descent::Opened { first: Some(inner) } = p.descend(container).unwrap() else {
            unreachable!()
        };
        let cap = u64::from(PayloadLen::MAX.as_inner());
        p.bodies.insert(container.0, cap - 1);
        p.total = 100;
        assert_eq!(p.save_len(), Ok(100), "the fast tier answers the settled total");

        // Grow across the class: the census rises and save_len
        // delegates to the wrapped sizing walk.
        p.settle_climb(inner.0, 2);
        assert_eq!(p.bodies.get(&container.0), Some(&(cap + 1)));
        assert_eq!(p.over_caps, 1, "the crossing entered the census");
        assert_eq!(p.total, 102, "the prefix width holds across this boundary");
        assert_eq!(p.save_len(), p.machine.save_len(), "a raised census delegates");

        // Shrink back: the census clears and the fast tier returns.
        p.settle_climb(inner.0, -2);
        assert_eq!(p.bodies.get(&container.0), Some(&(cap - 1)));
        assert_eq!(p.over_caps, 0);
        assert_eq!(p.save_len(), Ok(100));
    }

    #[test]
    fn priced_shrouded_over_cap_spines_cost_the_fast_path_only() {
        // A shrouded container with an over-cap body keeps the census
        // raised (never a false negative), but the save prunes the
        // shroud, so the delegated answer is still Ok — the false
        // positive costs the O(1) tier, not correctness.
        let data = h("0A 02 08 01 08 2A");
        let mut p = priced(&data);
        let container = p.top().next().unwrap();
        let Descent::Opened { first: Some(inner) } = p.descend(container).unwrap() else {
            unreachable!()
        };
        let cap = u64::from(PayloadLen::MAX.as_inner());
        p.machine.delete(container).unwrap();
        p.bodies.insert(container.0, cap + 1);
        p.over_caps = 1;
        p.total = 2;

        // A climb from under the shroud updates the body and freezes:
        // the census holds, the total never moves.
        p.settle_climb(inner.0, 3);
        assert_eq!(p.bodies.get(&container.0), Some(&(cap + 4)));
        assert_eq!(p.over_caps, 1);
        assert_eq!(p.total, 2, "the shroud freezes the climb");
        assert_eq!(p.save_len(), Ok(2), "delegation answers Ok past the pruned shroud");
        assert_eq!(p.machine.save_len(), Ok(2));
    }

    #[test]
    fn priced_save_len_reports_the_doc_cap_tier_exactly() {
        let data = h("08 01");
        let mut p = priced(&data);
        p.total = u64::from(DocBytes::CAP);
        assert_eq!(p.save_len(), Ok(DocBytes::CAP), "the cap itself is in class");
        p.total = u64::from(DocBytes::CAP) + 1;
        assert_eq!(
            p.save_len(),
            Err(SaveFault::DocOverCap { total: u64::from(DocBytes::CAP) + 1 }),
            "the over-cap tier reports the exact settled total"
        );
    }

    // ─── the priced frames ───

    #[test]
    fn priced_frames_publish_and_settle_like_their_whole_slice_twins() {
        // LEN f2 "ab" · varint f1: a set frame, an insert frame, and
        // their sized twins, each settling one logged transition.
        let data = h("12 02 61 62 08 01");
        let mut p = priced(&data);
        let target = p.top().next().unwrap();

        let mut frame = p.begin_set_payload(target).unwrap();
        frame.write(b"wor").unwrap();
        frame.write(b"ld").unwrap();
        assert_eq!(frame.finish().unwrap(), target);
        assert_eq!(p.save_len(), Ok(9));
        assert_eq!(p.save().unwrap().len(), 9);

        let mut frame = p.begin_insert_payload(InsertAt::TailOf(None), fnum(3)).unwrap();
        frame.write(b"xy").unwrap();
        let minted = frame.finish().unwrap();
        assert_eq!(p.payload_bytes(minted), Ok(&b"xy"[..]));
        assert_eq!(p.save_len(), Ok(13));

        let mut frame = p.begin_set_payload_sized(target, 5).unwrap();
        frame.write(b"scale").unwrap();
        frame.finish().unwrap();
        assert_eq!(p.save_len(), Ok(13));

        let mut frame = p.begin_insert_payload_sized(InsertAt::After(minted), fnum(4), 3).unwrap();
        frame.write(b"end").unwrap();
        frame.finish().unwrap();
        assert_eq!(p.save_len(), Ok(18));
        assert_eq!(p.save().unwrap().len(), 18);

        // One logged transition per frame: four settles walk back.
        assert_eq!(p.pending(), 4);
        p.revert_all();
        assert_eq!(p.save_len(), Ok(6));
        assert_eq!(p.save().unwrap()[..], data[..]);
    }

    // ─── the lockstep differential: priced against the plain walk ───

    /// The priced wrapper and a plain session over the same document,
    /// driven command by command. Identical byte input and identical
    /// command order mint identical arenas, so one handle names the
    /// same record in both machines.
    struct PricedTwins {
        priced: PricedSession,
        base: Session,
    }

    impl PricedTwins {
        #[track_caller]
        fn open(data: &[u8]) -> Self {
            Self { priced: priced(data), base: open(data) }
        }

        /// The three-way price judgment: the settled answer, the plain
        /// sizing walk, and the emitted document agree byte-for-byte.
        #[track_caller]
        fn judge(&self) {
            let settled = self.priced.save_len();
            assert_eq!(settled, self.base.save_len(), "the settled price left the walk");
            let len = settled.expect("lockstep arcs stay in class");
            let saved = self.base.save().expect("in-class twins save");
            assert_eq!(saved.len(), len, "the walk left the emission");
            assert_eq!(
                self.priced.save().expect("in-class twins save").as_slice(),
                saved.as_slice(),
                "the twins' saves diverged"
            );
        }

        /// Applies one command to both twins and judges the three-way
        /// agreement.
        #[track_caller]
        fn lockstep(
            &mut self,
            priced_cmd: impl FnOnce(&mut PricedSession),
            base_cmd: impl FnOnce(&mut Session),
        ) {
            priced_cmd(&mut self.priced);
            base_cmd(&mut self.base);
            self.judge();
        }
    }

    #[test]
    fn priced_lockstep_covers_the_scripted_arc_family() {
        // varint f1 · LEN f2 { varint f1 · LEN f2 { varint f1 } } ·
        // I32 f4 · I64 f5 · LEN f3 "ab": every kind, two nesting
        // levels.
        let data =
            h("08 01 12 09 08 07 12 05 08 96 01 08 09 25 AABBCCDD 29 AABBCCDD11223344 1A 02 61 62");
        let mut t = PricedTwins::open(&data);
        let tops: Vec<Handle> = t.priced.top().collect();

        // Same-row re-sets, growing and shrinking the leaf.
        for word in [0u64, 1, u64::from(u32::MAX), u64::MAX, 5] {
            t.lockstep(
                |p| p.set_varint(tops[0], word).unwrap(),
                |b| {
                    b.set_varint(tops[0], word).unwrap();
                },
            );
        }
        // Fixed-width zero-delta sets.
        t.lockstep(|p| p.set_i32(tops[2], 0xAB).unwrap(), |b| b.set_i32(tops[2], 0xAB).unwrap());
        t.lockstep(|p| p.set_i64(tops[3], 0xCD).unwrap(), |b| b.set_i64(tops[3], 0xCD).unwrap());
        // Payload grow, shrink, and equal-src-len replacement.
        for body in [&b"grown far past"[..], &b""[..], &b"ab"[..]] {
            t.lockstep(
                |p| p.set_payload(tops[4], body).unwrap(),
                |b| {
                    b.set_payload(tops[4], body).unwrap();
                },
            );
        }
        // Source descents, then edits at both depths.
        let (inner, leaf) = {
            let Descent::Opened { first: Some(inner) } = t.priced.descend(tops[1]).unwrap() else {
                unreachable!()
            };
            assert!(matches!(t.base.descend(tops[1]).unwrap(), Descent::Opened { .. }));
            let deep = t.priced.children(tops[1]).unwrap().nth(1).unwrap();
            let Descent::Opened { first: Some(leaf) } = t.priced.descend(deep).unwrap() else {
                unreachable!()
            };
            assert!(matches!(t.base.descend(deep).unwrap(), Descent::Opened { .. }));
            t.judge();
            (inner, leaf)
        };
        t.lockstep(|p| p.set_varint(inner, 300).unwrap(), |b| b.set_varint(inner, 300).unwrap());
        t.lockstep(|p| p.set_varint(leaf, 1).unwrap(), |b| b.set_varint(leaf, 1).unwrap());
        // Births: scalar and payload, at the root and under the spine.
        t.lockstep(
            |p| {
                p.insert_varint(InsertAt::TailOf(None), fnum(9), 7).unwrap();
            },
            |b| {
                b.insert_varint(InsertAt::TailOf(None), fnum(9), 7).unwrap();
            },
        );
        let born = t.priced.top().last().unwrap();
        t.lockstep(
            |p| {
                p.insert_payload(InsertAt::After(tops[0]), fnum(8), &h("08 05")).unwrap();
            },
            |b| {
                b.insert_payload(InsertAt::After(tops[0]), fnum(8), &h("08 05")).unwrap();
            },
        );
        // Deletes: intact, replaced, inserted (a ghost is born), and
        // the dirty container (its settled body waits under the
        // shroud).
        for target in [tops[2], tops[0], born, tops[1]] {
            t.lockstep(|p| p.delete(target).unwrap(), |b| b.delete(target).unwrap());
        }
        // An edit under the shrouded container.
        t.lockstep(|p| p.set_varint(inner, 4).unwrap(), |b| b.set_varint(inner, 4).unwrap());
        for target in [tops[2], tops[0], tops[1]] {
            t.lockstep(|p| p.undelete(target).unwrap(), |b| b.undelete(target).unwrap());
        }
        // A revert after the arc, then edits into the deep leaf.
        t.lockstep(
            |p| {
                p.revert();
            },
            |b| {
                b.revert();
            },
        );
        t.lockstep(|p| p.set_varint(leaf, 9).unwrap(), |b| b.set_varint(leaf, 9).unwrap());
        t.lockstep(
            |p| {
                p.revert();
            },
            |b| {
                b.revert();
            },
        );
        // The deep interior is now history-free: flip the spine's
        // backing wholesale, orphaning the descended interior.
        t.lockstep(|p| p.revert_all(), |b| b.revert_all());
        t.lockstep(
            |p| p.set_payload(tops[1], &h("08 01")).unwrap(),
            |b| {
                b.set_payload(tops[1], &h("08 01")).unwrap();
            },
        );
        // The authored descent (browse-only interior).
        {
            assert!(matches!(t.priced.descend(tops[1]).unwrap(), Descent::Opened { .. }));
            assert!(matches!(t.base.descend(tops[1]).unwrap(), Descent::Opened { .. }));
            t.judge();
        }
        // Clear the flip; everything unwinds to the source.
        t.lockstep(|p| p.clear_edit(tops[1]).unwrap(), |b| b.clear_edit(tops[1]).unwrap());
        t.lockstep(|p| p.revert_all(), |b| b.revert_all());
        assert_eq!(t.priced.save_len().map(usize_of), Ok(data.len()));
    }

    #[test]
    fn priced_lockstep_frames_publish_and_abandon_in_step() {
        let data = h("08 01 12 02 61 62");
        let mut t = PricedTwins::open(&data);
        let target = t.priced.top().nth(1).unwrap();

        t.lockstep(
            |p| {
                let mut frame = p.begin_set_payload(target).unwrap();
                frame.write(b"wor").unwrap();
                frame.write(b"ld").unwrap();
                frame.finish().unwrap();
            },
            |b| {
                let mut frame = b.begin_set_payload(target).unwrap();
                frame.write(b"world").unwrap();
                frame.finish().unwrap();
            },
        );
        t.lockstep(
            |p| {
                let mut frame =
                    p.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), 2).unwrap();
                frame.write(b"xy").unwrap();
                frame.finish().unwrap();
            },
            |b| {
                let mut frame =
                    b.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), 2).unwrap();
                frame.write(b"xy").unwrap();
                frame.finish().unwrap();
            },
        );
        // Abandonments publish nothing on either side.
        t.lockstep(
            |p| {
                let mut frame = p.begin_set_payload_sized(target, 8).unwrap();
                frame.write(b"junk").unwrap();
            },
            |b| {
                let mut frame = b.begin_set_payload_sized(target, 8).unwrap();
                frame.write(b"junk").unwrap();
            },
        );
        t.lockstep(|p| p.revert_all(), |b| b.revert_all());
        assert_eq!(t.priced.save_len().map(usize_of), Ok(data.len()));
    }

    #[test]
    fn priced_lockstep_survives_the_xorshift_soak() {
        // Every kind, one nesting axis, and a payload whose descend
        // faults resident — the narrowest soak's corpus, judged
        // three ways after every step.
        let data = h("089601 1A08 089601 1A03089601 15AABBCCDD 1A01 0B");
        let mut t = PricedTwins::open(&data);
        let mut rng = XorShift(0x2545_F491);
        for step in 0..300 {
            let pool = reachable(&t.base);
            let pick = pool[rng.next() as usize % pool.len()];
            let lens: Vec<Handle> = pool
                .iter()
                .copied()
                .filter(|&handle| matches!(t.base.kind(handle), Ok(RecordKind::Len)))
                .collect();
            let len_pick =
                if lens.is_empty() { pick } else { lens[rng.next() as usize % lens.len()] };
            match rng.next() % 14 {
                0 | 1 => {
                    let word = u64::from(rng.next());
                    assert_eq!(
                        t.priced.set_varint(pick, word),
                        t.base.set_varint(pick, word),
                        "verdicts diverged at step {step}"
                    );
                }
                2 => assert_eq!(t.priced.delete(pick), t.base.delete(pick)),
                3 => assert_eq!(t.priced.undelete(pick), t.base.undelete(pick)),
                4 | 5 => {
                    let a = t.priced.descend(len_pick).is_ok();
                    let b = t.base.descend(len_pick).is_ok();
                    assert_eq!(a, b, "descend verdicts diverged at step {step}");
                }
                6 | 7 => {
                    let payload = match rng.next() % 4 {
                        0 => h("089601"),
                        1 => Vec::new(),
                        2 => h("1A03089601"),
                        _ => h("0B"),
                    };
                    assert_eq!(
                        t.priced.set_payload(len_pick, &payload),
                        t.base.set_payload(len_pick, &payload),
                    );
                }
                8 => {
                    assert_eq!(
                        t.priced.insert_varint(InsertAt::After(pick), fnum(9), 7),
                        t.base.insert_varint(InsertAt::After(pick), fnum(9), 7),
                    );
                }
                9 => {
                    assert_eq!(
                        t.priced.insert_payload(InsertAt::TailOf(None), fnum(3), &h("0801")),
                        t.base.insert_payload(InsertAt::TailOf(None), fnum(3), &h("0801")),
                    );
                }
                10 => assert_eq!(t.priced.clear_edit(pick), t.base.clear_edit(pick)),
                11 => {
                    let priced_published =
                        t.priced.begin_set_payload(len_pick).is_ok_and(|mut frame| {
                            frame.write(b"fr").unwrap();
                            frame.finish().is_ok()
                        });
                    let base_published =
                        t.base.begin_set_payload(len_pick).is_ok_and(|mut frame| {
                            frame.write(b"fr").unwrap();
                            frame.finish().is_ok()
                        });
                    assert_eq!(priced_published, base_published, "frames diverged at {step}");
                }
                _ => assert_eq!(t.priced.revert(), t.base.revert()),
            }
            t.judge();
        }
        // The whole history unwinds to the source length.
        t.lockstep(|p| p.revert_all(), |b| b.revert_all());
        assert_eq!(t.priced.save_len().map(usize_of), Ok(data.len()));
    }

    // ─── admission arcs ───

    #[test]
    fn priced_admission_prices_the_dirty_region() {
        // Dirt at two depths beside clean siblings, a shroud, and a
        // ghost: the admission walk must price exactly what the
        // sizing walk prices.
        let data = h("08 01 12 07 08 07 12 03 08 96 01 15 AABBCCDD 1A 02 61 62");
        let mut base = open(&data);
        let tops = tops(&base);
        let Descent::Opened { first: Some(inner) } = base.descend(tops[1]).unwrap() else {
            unreachable!()
        };
        base.set_varint(inner, 300).unwrap();
        base.delete(tops[2]).unwrap();
        base.insert_varint(InsertAt::TailOf(None), fnum(9), 1).unwrap();
        base.revert().unwrap();
        let expect = base.save_len().unwrap();

        let p = base.into_priced().map_err(|(_, fault)| fault).expect("dirty machine admits");
        assert_eq!(p.save_len(), Ok(expect));
        assert_eq!(p.save().unwrap().len(), expect);
        assert!(p.bodies.contains_key(&tops[1].0), "the dirty spine carries its entry");
    }

    #[test]
    fn priced_admission_enters_shrouded_layers_so_the_lift_prices_right() {
        // Edit a child, shroud its container, admit, lift: the walk
        // entered the shrouded layer, so the restored spine re-enters
        // at its edited body — not its source seed.
        let data = h("12 03 08 96 01 08 01");
        let mut base = open(&data);
        let tops = tops(&base);
        let Descent::Opened { first: Some(inner) } = base.descend(tops[0]).unwrap() else {
            unreachable!()
        };
        base.set_varint(inner, 7).unwrap();
        base.delete(tops[0]).unwrap();

        let mut p = base.into_priced().map_err(|(_, fault)| fault).expect("shrouded dirt admits");
        assert_eq!(p.bodies.get(&tops[0].0), Some(&2), "the shrouded layer was entered");
        assert_eq!(p.save_len(), Ok(2));

        let mut twin = open(&data);
        let Descent::Opened { first: Some(twin_inner) } = twin.descend(tops[0]).unwrap() else {
            unreachable!()
        };
        twin.set_varint(twin_inner, 7).unwrap();
        twin.delete(tops[0]).unwrap();
        twin.undelete(tops[0]).unwrap();
        p.undelete(tops[0]).unwrap();
        assert_eq!(p.save_len(), twin.save_len(), "the lifted spine re-enters settled");
        assert_eq!(p.save_len(), Ok(6));
        assert_eq!(p.save().unwrap().as_slice(), twin.save().unwrap().as_slice());
    }

    #[test]
    fn priced_admission_of_a_clean_machine_is_the_source_length() {
        // Ghosts and settled history are not dirt: the O(1) door.
        let data = h("08 96 01 12 02 68 69");
        let mut base = open(&data);
        base.insert_varint(InsertAt::TailOf(None), fnum(9), 1).unwrap();
        base.revert().unwrap();
        let p = base.into_priced().map_err(|(_, fault)| fault).expect("clean admits");
        assert!(p.bodies.is_empty());
        assert_eq!(p.total, 7);
        assert_eq!(p.save_len(), Ok(7));
    }

    // The fixture stages a real 2 GiB payload: no smaller input can
    // cross the length class end to end, and 32-bit targets and Miri
    // cannot host the allocation.
    #[cfg(all(not(target_family = "wasm"), not(miri)))]
    #[test]
    fn priced_over_cap_crossing_matches_the_walk_end_to_end() {
        let _giant = crate::session::giant_fixture::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let data = h("0A 02 08 01");
        let mut p = priced(&data);
        let container = p.top().next().unwrap();
        assert!(matches!(p.descend(container).unwrap(), Descent::Opened { .. }));

        // Grow past the class: the settled fault is the walk's fault,
        // payload included.
        let big = alloc::vec![0u8; usize_of(PayloadLen::MAX.as_inner())];
        p.insert_payload(InsertAt::TailOf(Some(container)), fnum(2), &big).unwrap();
        drop(big);
        assert_eq!(p.over_caps, 1, "the climb counted the crossing");
        let fault = p.save_len().unwrap_err();
        assert_eq!(Err(fault), p.machine.save_len(), "the delegated fault is the walk's");
        assert_eq!(p.machine.save().map(|_| ()).unwrap_err(), fault, "the save agrees");

        // An over-cap machine admits: the door is not a save.
        let session = p.into_session();
        let readmitted =
            session.into_priced().map_err(|(_, fault)| fault).expect("over-cap machines admit");
        let mut p = readmitted;
        assert_eq!(p.over_caps, 1, "admission recounted the crossing");
        assert_eq!(p.save_len().unwrap_err(), fault);

        // Shrink back across the class: the settled answer returns to
        // the fast tier and the walk agrees.
        p.revert().unwrap();
        assert_eq!(p.over_caps, 0, "the crossing left the census");
        assert_eq!(p.save_len(), Ok(4));
        assert_eq!(p.machine.save_len(), Ok(4));
        assert_eq!(p.save().unwrap().len(), 4);
    }

    #[test]
    fn priced_frames_leave_the_price_untouched_on_every_non_publishing_exit() {
        let data = h("12 02 61 62");
        let mut p = priced(&data);
        let target = p.top().next().unwrap();
        let cursor = p.machine.store.stage_mark();

        // An abandoned undeclared frame.
        {
            let mut frame = p.begin_set_payload(target).unwrap();
            frame.write(b"junk").unwrap();
        }
        assert_eq!(p.pending(), 0);
        assert_eq!(p.total, 4, "an abandoned frame settles nothing");
        assert!(p.bodies.is_empty());
        assert_eq!(p.machine.store.stage_mark(), cursor, "the staged bytes reclaim");

        // An abandoned sized insert frame.
        {
            let mut frame =
                p.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(3), 8).unwrap();
            frame.write(b"abc").unwrap();
        }
        assert_eq!(p.total, 4);
        assert!(p.bodies.is_empty());
        assert_eq!(p.machine.store.stage_mark(), cursor);

        // A refused finish is a non-publishing exit too.
        let mut frame = p.begin_set_payload_sized(target, 3).unwrap();
        frame.write(b"ab").unwrap();
        assert!(matches!(
            frame.finish().err(),
            Some(FrameFault::UnderDeclared { declared: 3, staged: 2 })
        ));
        assert_eq!(p.total, 4);
        assert_eq!(p.machine.store.stage_mark(), cursor);

        // A refused write leaves the frame usable and settles nothing
        // until the finish publishes.
        let mut frame = p.begin_set_payload_sized(target, 3).unwrap();
        frame.write(b"ab").unwrap();
        assert!(matches!(
            frame.write(b"cd").err(),
            Some(FrameFault::OverDeclared { declared: 3, total: 4 })
        ));
        frame.write(b"c").unwrap();
        frame.finish().unwrap();
        assert_eq!(p.save_len(), Ok(5));
        assert_eq!(p.save().unwrap().len(), 5);
        assert_eq!(p.pending(), 1, "exactly the publishing finish logged");
    }
}

#[test]
fn the_borrowed_sink_save_hands_the_installed_slice_through() {
    let doc = h("12 01 61");
    let alpha = h("08 2A");
    let mut s = BorrowSession::open_copy(&doc).unwrap();
    let r = s.top().next().unwrap();
    s.set_payload(r, &alpha).unwrap();
    let mut streamed = Vec::new();
    let mut handed = false;
    s.save_sink(|slice| {
        // Pointer identity: one window is the installed owner's own
        // slice, at its exact length — handed through, never copied.
        if slice.as_ptr() == alpha.as_ptr() {
            assert_eq!(slice.len(), alpha.len(), "the installed slice hands through whole");
            handed = true;
        }
        streamed.extend_from_slice(slice);
    })
    .unwrap();
    assert!(handed, "no callback window was the installed slice itself");
    assert_eq!(streamed[..], s.save().unwrap()[..]);
}

// ─── the mixed-backing sibling: lockstep twins in both drives, the
// interleaved history on one log, and the provenance flips ───

/// The mixed session driven borrow-only beside the borrowed-only
/// sibling: byte-identical saves, equal prices, equal span tables,
/// and equal log depths at every step.
pub(super) struct MixBorrowDrive<'p> {
    mix: MixSession<'p>,
    borrow: BorrowSession<'p>,
}

impl<'p> MixBorrowDrive<'p> {
    #[track_caller]
    fn open(data: &[u8]) -> Self {
        Self {
            mix: MixSession::open_copy(data).expect("twin document opens"),
            borrow: BorrowSession::open_copy(data).expect("twin document opens"),
        }
    }

    #[track_caller]
    fn lockstep(
        &mut self,
        mix_cmd: impl FnOnce(&mut MixSession<'p>),
        borrow_cmd: impl FnOnce(&mut BorrowSession<'p>),
    ) {
        mix_cmd(&mut self.mix);
        borrow_cmd(&mut self.borrow);
        let a = self.mix.save().expect("mix twin saves");
        let b = self.borrow.save().expect("borrow twin saves");
        assert_eq!(a[..], b[..], "the twins' saves diverged");
        assert_eq!(self.mix.save_len().unwrap(), self.borrow.save_len().unwrap());
        let spans_a: Vec<_> =
            self.mix.save_spans().unwrap().iter().map(|(_, s)| (s.start(), s.end())).collect();
        let spans_b: Vec<_> =
            self.borrow.save_spans().unwrap().iter().map(|(_, s)| (s.start(), s.end())).collect();
        assert_eq!(spans_a, spans_b, "the twins' span tables diverged");
        assert_eq!(self.mix.pending(), self.borrow.pending(), "log depths diverged");
    }
}

/// The mixed session driven copy-only beside the copy-only base
/// machine: the `_copy` faces and frame doors against the base's
/// unsuffixed faces and frames, compared the same way.
pub(super) struct MixCopyDrive {
    mix: MixSession<'static>,
    copy: Session,
}

impl MixCopyDrive {
    #[track_caller]
    fn open(data: &[u8]) -> Self {
        Self {
            mix: MixSession::open_copy(data).expect("twin document opens"),
            copy: Session::open_copy(data).expect("twin document opens"),
        }
    }

    #[track_caller]
    fn lockstep(
        &mut self,
        mix_cmd: impl FnOnce(&mut MixSession<'static>),
        copy_cmd: impl FnOnce(&mut Session),
    ) {
        mix_cmd(&mut self.mix);
        copy_cmd(&mut self.copy);
        let a = self.mix.save().expect("mix twin saves");
        let b = self.copy.save().expect("copy twin saves");
        assert_eq!(a[..], b[..], "the twins' saves diverged");
        assert_eq!(self.mix.save_len().unwrap(), self.copy.save_len().unwrap());
        let spans_a: Vec<_> =
            self.mix.save_spans().unwrap().iter().map(|(_, s)| (s.start(), s.end())).collect();
        let spans_b: Vec<_> =
            self.copy.save_spans().unwrap().iter().map(|(_, s)| (s.start(), s.end())).collect();
        assert_eq!(spans_a, spans_b, "the twins' span tables diverged");
        assert_eq!(self.mix.pending(), self.copy.pending(), "log depths diverged");
    }
}

#[test]
fn mix_borrow_drive_tracks_the_borrowed_sibling() {
    // LEN f2 "a" · varint f1=150.
    let doc = h("12 01 61 08 96 01");
    let alpha = h("08 01");
    let beta = h("08 07 08 08");
    let body = h("08 2A");
    let mut t = MixBorrowDrive::open(&doc);
    // Two installs, a shroud/restore pair, a clear, a birth, and
    // the full unwind — all through the unsuffixed borrowed faces.
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &alpha).unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &alpha).unwrap();
        },
    );
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &beta).unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &beta).unwrap();
        },
    );
    t.lockstep(
        |s| {
            s.revert();
        },
        |s| {
            s.revert();
        },
    );
    let r = t.mix.top().next().unwrap();
    assert_eq!(t.mix.payload_bytes(r).unwrap(), alpha, "the restored coordinate names alpha");
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            s.delete(r).unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            s.delete(r).unwrap();
        },
    );
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            s.undelete(r).unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            s.undelete(r).unwrap();
        },
    );
    assert_eq!(t.mix.status(r).unwrap(), EditStatus::Replaced);
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            s.clear_edit(r).unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            s.clear_edit(r).unwrap();
        },
    );
    t.lockstep(
        |s| {
            s.insert_payload(InsertAt::TailOf(None), fnum(3), &body).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), fnum(3), &body).unwrap();
        },
    );
    // Identical fault behavior over the shared refusals.
    t.lockstep(
        |s| {
            let scalar = s.top().nth(1).unwrap();
            assert!(matches!(
                s.set_payload(scalar, &alpha),
                Err(EditFault::KindMismatch { have: RecordKind::Varint })
            ));
        },
        |s| {
            let scalar = s.top().nth(1).unwrap();
            assert!(matches!(
                s.set_payload(scalar, &alpha),
                Err(EditFault::KindMismatch { have: RecordKind::Varint })
            ));
        },
    );
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap()[..], doc[..]);
}

#[test]
fn mix_copy_drive_tracks_the_copy_only_session() {
    let doc = h("12 01 61 08 96 01");
    let alpha = h("08 01");
    let beta = h("08 07 08 08");
    let body = h("08 2A");
    let mut t = MixCopyDrive::open(&doc);
    // The same arc as the borrow drive, through the copying twins.
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload_copy(r, &alpha).unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &alpha).unwrap();
        },
    );
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload_copy(r, &beta).unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            s.set_payload(r, &beta).unwrap();
        },
    );
    t.lockstep(
        |s| {
            s.revert();
        },
        |s| {
            s.revert();
        },
    );
    t.lockstep(
        |s| {
            s.insert_payload_copy(InsertAt::TailOf(None), fnum(3), &body).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), fnum(3), &body).unwrap();
        },
    );
    // The undeclared frames stage chunk for chunk.
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            let mut frame = s.begin_set_payload(r).unwrap();
            frame.write(b"a").unwrap();
            frame.write(b"bc").unwrap();
            frame.finish().unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
            let mut frame = s.begin_set_payload(r).unwrap();
            frame.write(b"a").unwrap();
            frame.write(b"bc").unwrap();
            frame.finish().unwrap();
        },
    );
    // The sized doors hold the same declaration law.
    t.lockstep(
        |s| {
            let mut frame =
                s.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(4), 2).unwrap();
            assert!(matches!(
                frame.write(b"abc"),
                Err(FrameFault::OverDeclared { declared: 2, total: 3 })
            ));
            frame.write(b"ok").unwrap();
            frame.finish().unwrap();
        },
        |s| {
            let mut frame =
                s.begin_insert_payload_sized(InsertAt::TailOf(None), fnum(4), 2).unwrap();
            assert!(matches!(
                frame.write(b"abc"),
                Err(FrameFault::OverDeclared { declared: 2, total: 3 })
            ));
            frame.write(b"ok").unwrap();
            frame.finish().unwrap();
        },
    );
    // An abandoned frame changes nothing on either side.
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            let mut frame = s.begin_set_payload(r).unwrap();
            frame.write(b"zz").unwrap();
            drop(frame);
        },
        |s| {
            let r = s.top().next().unwrap();
            let mut frame = s.begin_set_payload(r).unwrap();
            frame.write(b"zz").unwrap();
            drop(frame);
        },
    );
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap()[..], doc[..]);
}

#[test]
fn mix_interleaved_history_walks_both_backings_exactly() {
    // LEN f2 "a": one row, one log, five backings deep.
    let doc = h("12 01 61");
    let alpha = h("08 01");
    let charlie = h("08 05");
    let mut s = MixSession::open_copy(&doc).unwrap();
    let r = s.top().next().unwrap();
    // borrow A -> copy B -> borrow C on one handle arena.
    s.set_payload(r, &alpha).unwrap();
    {
        let transient = h("08 07");
        s.set_payload_copy(r, &transient).unwrap();
        // The owner dies here; the copied slot keeps the bytes.
    }
    s.set_payload(r, &charlie).unwrap();
    assert_eq!(s.pending(), 3, "three installs, one log");
    assert_eq!(s.payload_bytes(r).unwrap(), charlie);
    assert_eq!(s.save().unwrap()[..], h("12 02 08 05")[..]);
    // revert to B: the copied slot still names the dead owner's
    // exact bytes.
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), h("08 07"));
    assert_eq!(s.save().unwrap()[..], h("12 02 08 07")[..]);
    // revert to A: the borrowed slot answers again.
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), alpha);
    assert_eq!(s.save().unwrap()[..], h("12 02 08 01")[..]);
    // Delete/undelete park and restore the mixed coordinate.
    s.delete(r).unwrap();
    s.undelete(r).unwrap();
    assert_eq!(s.payload_bytes(r).unwrap(), alpha);
    // Every save face answers the same bytes mid-history.
    let saved = s.save().unwrap();
    let mut into = h("BEEF");
    s.save_into(&mut into).unwrap();
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    s.save_sink(|chunk| streamed.extend_from_slice(chunk)).unwrap();
    assert_eq!(streamed[..], saved[..], "the sink concatenation is the save");
    // revert to the source; the whole history unwinds.
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], doc[..]);
    assert_eq!(s.pending(), 0);
}

#[test]
fn mix_descents_reach_the_right_provenance_over_each_flip() {
    // LEN f2 wrapping varint f1=1.
    let doc = h("12 02 08 01");
    // A nested borrowed payload: LEN f2 wrapping varint f1=7.
    let nested = h("12 02 08 07");
    let mut s = MixSession::open_copy(&doc).unwrap();
    let r = s.top().next().unwrap();
    // Source-backed interior first.
    let Descent::Opened { first: Some(source_inner) } = s.descend(r).unwrap() else {
        panic!("source interior opens")
    };
    assert_eq!(s.varint_word(source_inner).unwrap(), 1);
    // Flip to a borrowed install: the old tree orphans whole, and
    // the re-descended interior climbs to the borrowed slot.
    s.set_payload(r, &nested).unwrap();
    assert!(matches!(s.varint_word(source_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(borrow_inner) } = s.descend(r).unwrap() else {
        panic!("borrowed interior opens")
    };
    assert_eq!(s.payload_bytes(borrow_inner).unwrap(), h("08 07"));
    let Descent::Opened { first: Some(borrow_leaf) } = s.descend(borrow_inner).unwrap() else {
        panic!("nested borrowed interior opens")
    };
    assert_eq!(s.varint_word(borrow_leaf).unwrap(), 7, "depth two reads the borrowed slot");
    assert!(matches!(s.set_varint(borrow_leaf, 9), Err(EditFault::InsideAuthoredBody)));
    // Flip to a copied install: the borrowed tree orphans whole,
    // and the re-descended interior climbs to the copied extent.
    {
        let transient = h("12 02 08 63");
        s.set_payload_copy(r, &transient).unwrap();
    }
    assert!(matches!(s.payload_bytes(borrow_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(copy_inner) } = s.descend(r).unwrap() else {
        panic!("copied interior opens")
    };
    assert_eq!(s.payload_bytes(copy_inner).unwrap(), h("08 63"));
    let Descent::Opened { first: Some(copy_leaf) } = s.descend(copy_inner).unwrap() else {
        panic!("nested copied interior opens")
    };
    assert_eq!(s.varint_word(copy_leaf).unwrap(), 99, "depth two reads the copied extent");
    // revert to the borrowed install: the copied tree orphans, and
    // a fresh descent climbs back to the borrowed slot.
    s.revert();
    assert!(matches!(s.payload_bytes(copy_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(again) } = s.descend(r).unwrap() else {
        panic!("borrowed interior reopens")
    };
    assert_eq!(s.payload_bytes(again).unwrap(), h("08 07"));
    // revert to the source: scanned bytes speak again.
    s.revert();
    let Descent::Opened { first: Some(back) } = s.descend(r).unwrap() else {
        panic!("source interior reopens")
    };
    assert_eq!(s.varint_word(back).unwrap(), 1);
    assert_eq!(s.save().unwrap()[..], doc[..]);
}

#[test]
fn mix_soak_mixes_backings_across_containers_with_descents() {
    // Two LEN containers and a scalar: the soak drives installs of
    // both backings, descents, and reverts over one log, with an
    // exact payload oracle checked after every operation.
    let doc = h("12 01 61 1A 01 62 08 2A");
    let pool = [h("08 01"), h("08 07"), h("12 00"), h("08 96 01"), h("")];
    let mut s = MixSession::open_copy(&doc).unwrap();
    let t: Vec<_> = s.top().collect();
    let targets = [t[0], t[1]];
    // The oracle: each target's expected payload, and the install
    // history the log must unwind through.
    let mut current: [Vec<u8>; 2] = [h("61"), h("62")];
    let mut history: Vec<(usize, Vec<u8>)> = Vec::new();
    for step in 0..96_u32 {
        let which = usize_of(step % 2);
        let target = targets[which];
        match step % 8 {
            0 | 3 => {
                // A borrowed install from the long-lived pool.
                let payload = &pool[usize_of(step) % pool.len()];
                s.set_payload(target, payload).unwrap();
                history.push((which, core::mem::replace(&mut current[which], payload.clone())));
            }
            1 | 5 => {
                // A copied install whose owner dies immediately.
                let transient = alloc::vec![0x08, u8::try_from(step % 0x60).unwrap()];
                s.set_payload_copy(target, &transient).unwrap();
                history.push((which, core::mem::replace(&mut current[which], transient)));
            }
            2 | 6 => {
                // A descent between installs: payload-only edits on
                // the sibling never orphan this target's tree.
                let _ = s.descend(target);
            }
            _ => {
                // A revert, when history remains.
                if let Some((which, prior)) = history.pop() {
                    s.revert();
                    current[which] = prior;
                }
            }
        }
        assert_eq!(s.pending(), history.len(), "step {step}: log depth");
        for (index, expected) in current.iter().enumerate() {
            assert_eq!(
                s.payload_bytes(targets[index]).unwrap(),
                *expected,
                "step {step}: target {index}"
            );
        }
    }
    // The full unwind ends at the source product.
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], doc[..]);
}
