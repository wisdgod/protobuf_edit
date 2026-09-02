//! Contract pins: each test states one clause of the machine's
//! contract. Alignment against the reference corpus belongs to the
//! shared harness.

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

// ─── the portable save and the output span table, over groups ───

#[test]
fn save_into_and_save_spans_cover_groups() {
    // group f2 { varint f3 } · varint f1
    let data = h("13 18 01 14 08 2A");
    let mut s = open(&data);
    let t = tops(&s);
    let inner = s.children(t[0]).unwrap().next().unwrap();
    s.set_varint(inner, 300).unwrap();
    let fresh = s.insert_group(InsertAt::TailOf(None), fnum(5)).unwrap();
    let kid = s.insert_varint(InsertAt::TailOf(Some(fresh)), fnum(1), 7).unwrap();

    let carrier = s.save().unwrap();
    assert_eq!(carrier.as_slice(), h("13 18 AC 02 14 08 2A 2B 08 07 2C").as_slice());
    let mut out = Vec::new();
    s.save_into(&mut out).unwrap();
    assert_eq!(out, *carrier.as_slice());

    let spans = s.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(
        table,
        [
            (t[0], Span::new(0, 5)),
            (inner, Span::new(1, 4)),
            (t[1], Span::new(5, 7)),
            (fresh, Span::new(7, 11)),
            (kid, Span::new(8, 10)),
        ]
    );
    // The size-consistency pin: the farthest span end is the
    // priced save (the last entry is the trailing group's kid).
    let far = table.iter().map(|(_, span)| span.end()).max().unwrap();
    assert_eq!(far, s.save_len().unwrap());
    assert_eq!(&out[table[3].1.as_range()], h("2B 08 07 2C").as_slice());
}

#[test]
fn the_sink_save_matches_the_carrier_save_over_groups() {
    // group f2 { varint f3 } · varint f1 — an interior edit under
    // re-emitted group framing plus an authored group, so verbatim
    // runs, framing tags, and authored words all hand out.
    let data = h("13 18 01 14 08 2A");
    let mut s = open(&data);
    let t = tops(&s);
    let inner = s.children(t[0]).unwrap().next().unwrap();
    s.set_varint(inner, 300).unwrap();
    let fresh = s.insert_group(InsertAt::TailOf(None), fnum(5)).unwrap();
    s.insert_varint(InsertAt::TailOf(Some(fresh)), fnum(1), 7).unwrap();

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

    // The clean path: one document window.
    let clean = open(&data);
    let mut windows: Vec<Vec<u8>> = Vec::new();
    clean.save_sink(|slice| windows.push(slice.to_vec())).unwrap();
    assert_eq!(windows.len(), 1, "a clean save is one window");
    assert_eq!(windows[0], data);
}

#[test]
fn a_machine_holding_only_an_inserted_group_walks_every_read_face() {
    // The inserted group's value coordinate is the unbacked group
    // sentinel: no store column holds an entry for it. Every read
    // face stays green with zero payload installs — the value
    // readers refuse on kind before any store access, and the save
    // faces author framing words alone.
    let mut s = open(&[]);
    let g = s.insert_group(InsertAt::TailOf(None), fnum(5)).unwrap();

    assert_eq!(s.pending(), 1);
    assert_eq!(tops(&s), [g]);
    assert_eq!(s.kind(g).unwrap(), RecordKind::Group);
    assert_eq!(s.field(g).unwrap(), fnum(5));
    assert_eq!(s.status(g).unwrap(), EditStatus::Inserted);
    assert!(s.dirty(g).unwrap());
    assert_eq!(s.parent(g).unwrap(), None);
    assert_eq!(s.children(g).unwrap().count(), 0);
    assert_eq!(s.children(g).unwrap().by_field(fnum(5)).count(), 0);
    assert_eq!(s.ancestors(g).unwrap().count(), 0);
    assert_eq!(s.span(g).unwrap(), None, "authored rows own no hex");
    assert_eq!(s.narrowest(0), None);

    // The kind gates hold every value reader off the group row.
    assert!(matches!(s.varint_word(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(s.i32_bits(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(s.i64_bits(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(s.payload_bytes(g), Err(EditFault::KindMismatch { .. })));

    // Group descent projects the already-open (empty) layer.
    assert!(matches!(s.descend(g).unwrap(), Descent::Opened { first: None }));

    assert_eq!(s.save_len().unwrap(), 2);
    let carrier = s.save().unwrap();
    assert_eq!(carrier.as_slice(), [0x2B, 0x2C]);
    let mut out = Vec::new();
    s.save_into(&mut out).unwrap();
    assert_eq!(out, [0x2B, 0x2C]);
    let mut streamed = Vec::new();
    s.save_sink(|slice| streamed.extend_from_slice(slice)).unwrap();
    assert_eq!(streamed, [0x2B, 0x2C]);
    let spans = s.save_spans().unwrap();
    assert_eq!(spans.iter().collect::<Vec<_>>(), [(g, Span::new(0, 2))]);
}

// ─── the staged payload frame, over groups ───

#[test]
fn the_payload_frame_covers_group_interiors() {
    // group f2 { LEN f3 "ab" }: replace the interior LEN through a
    // frame and insert a fresh LEN into the group through another;
    // the whole-slice twin must match, and each frame is one undo
    // step.
    let data = h("13 1A 02 61 62 14");
    let mut whole = open(&data);
    let group = tops(&whole)[0];
    let inner = whole.children(group).unwrap().next().unwrap();
    whole.set_payload(inner, b"hello").unwrap();
    whole.insert_payload(InsertAt::TailOf(Some(group)), fnum(4), b"xy").unwrap();
    let expected = whole.save().unwrap();

    let mut framed = open(&data);
    let group = tops(&framed)[0];
    let inner = framed.children(group).unwrap().next().unwrap();
    let mut frame = framed.begin_set_payload(inner).unwrap();
    frame.write(b"hel").unwrap();
    frame.write(b"lo").unwrap();
    frame.finish().unwrap();
    let mut frame = framed.begin_insert_payload(InsertAt::TailOf(Some(group)), fnum(4)).unwrap();
    frame.write(b"xy").unwrap();
    frame.finish().unwrap();
    assert_eq!(framed.save().unwrap().as_slice(), expected.as_slice());

    assert_eq!(framed.pending(), 2);
    framed.revert();
    framed.revert();
    assert_eq!(framed.save().unwrap().as_slice(), &data[..]);

    // An abandoned frame leaves no trace.
    {
        let mut frame = framed.begin_set_payload(inner).unwrap();
        frame.write(b"junk").unwrap();
    }
    assert_eq!(framed.pending(), 0, "no log state before a finish");
    assert_eq!(framed.save().unwrap().as_slice(), &data[..]);
}

#[test]
fn abandoned_and_refused_frames_reclaim_the_stores_byte_cursor() {
    // The store's byte cursor is finite `At32` offset space and the
    // save/log fingerprint cannot see it, so the cursor is its own
    // judge: every non-publishing frame exit must return the store
    // to its pre-frame state — byte length and span count both.
    let data = h("13 1A 02 61 62 14");
    let mut s = open(&data);
    let group = tops(&s)[0];
    let inner = s.children(group).unwrap().next().unwrap();
    let cursor = s.store.stage_mark();
    let spans = s.store.spans.len();

    // An abandoned undeclared frame.
    {
        let mut frame = s.begin_set_payload(inner).unwrap();
        frame.write(b"junk").unwrap();
    }
    assert_eq!(s.store.stage_mark(), cursor, "abandoned frame reclaims its bytes");
    assert_eq!(s.store.spans.len(), spans);

    // An abandoned sized frame: its staged bytes and offset space
    // reclaim; capacity the reservation gained may stay behind.
    {
        let mut frame =
            s.begin_insert_payload_sized(InsertAt::TailOf(Some(group)), fnum(4), 8).unwrap();
        frame.write(b"abc").unwrap();
    }
    assert_eq!(s.store.stage_mark(), cursor, "abandoned sized frame reclaims its bytes");
    assert_eq!(s.store.spans.len(), spans);

    // A refused finish is a non-publishing exit too.
    let mut frame = s.begin_set_payload_sized(inner, 3).unwrap();
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
    let mut frame = s.begin_set_payload(inner).unwrap();
    frame.write(b"wxyz").unwrap();
    frame.finish().unwrap();
    assert_eq!(s.store.stage_mark(), cursor + 4, "published bytes are retained exactly");
    assert_eq!(s.store.spans.len(), spans + 1);
    s.revert();
    assert_eq!(s.store.stage_mark(), cursor + 4, "undo never truncates published values");
    assert_eq!(s.save().unwrap().as_slice(), &data[..]);
}

#[test]
fn the_sized_doors_hold_their_declaration_and_match_the_undeclared_twin() {
    // group f2 { LEN f3 "ab" }: the sized doors judge the class at
    // begin with nothing allocated, refuse over/under-declaration
    // by name, and land byte-identically to the undeclared twin on
    // the same chunks.
    let data = h("13 1A 02 61 62 14");
    let mut s = open(&data);
    let group = tops(&s)[0];
    let inner = s.children(group).unwrap().next().unwrap();

    // Zero-allocation class refusal at begin, on both doors.
    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        s.begin_set_payload_sized(inner, over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert!(matches!(
        s.begin_insert_payload_sized(InsertAt::TailOf(Some(group)), fnum(4), over).err(),
        Some(EditFault::PayloadTooLarge { len }) if len == over
    ));

    // Over- and under-declaration refuse by name; the machine is
    // unchanged after either.
    let mut frame = s.begin_set_payload_sized(inner, 3).unwrap();
    frame.write(b"ab").unwrap();
    assert!(matches!(
        frame.write(b"cd").err(),
        Some(FrameFault::OverDeclared { declared: 3, total: 4 })
    ));
    assert!(matches!(
        frame.finish().err(),
        Some(FrameFault::UnderDeclared { declared: 3, staged: 2 })
    ));
    assert_eq!(s.pending(), 0);
    assert_eq!(s.save().unwrap().as_slice(), &data[..]);

    // The byte-differential against the undeclared twin.
    let mut undeclared = open(&data);
    let group = tops(&undeclared)[0];
    let inner = undeclared.children(group).unwrap().next().unwrap();
    let mut frame = undeclared.begin_set_payload(inner).unwrap();
    frame.write(b"hel").unwrap();
    frame.write(b"lo").unwrap();
    frame.finish().unwrap();
    let mut frame =
        undeclared.begin_insert_payload(InsertAt::TailOf(Some(group)), fnum(4)).unwrap();
    frame.write(b"xy").unwrap();
    frame.finish().unwrap();
    let expected = undeclared.save().unwrap();

    let group = tops(&s)[0];
    let inner = s.children(group).unwrap().next().unwrap();
    let mut frame = s.begin_set_payload_sized(inner, 5).unwrap();
    frame.write(b"hel").unwrap();
    frame.write(b"lo").unwrap();
    frame.finish().unwrap();
    let mut frame =
        s.begin_insert_payload_sized(InsertAt::TailOf(Some(group)), fnum(4), 2).unwrap();
    frame.write(b"xy").unwrap();
    frame.finish().unwrap();
    assert_eq!(s.save().unwrap().as_slice(), expected.as_slice());

    assert_eq!(s.pending(), 2);
    s.revert();
    s.revert();
    assert_eq!(s.save().unwrap().as_slice(), &data[..]);
}

#[test]
fn a_span_recovers_a_group_member_across_the_save_reopen_gap() {
    let data = h("13 18 01 14 08 2A");
    let mut s = open(&data);
    let t = tops(&s);
    let inner = s.children(t[0]).unwrap().next().unwrap();
    s.set_varint(inner, 300).unwrap();

    let spans = s.save_spans().unwrap();
    let (_, span) = spans.iter().find(|(handle, _)| *handle == inner).unwrap();
    let saved = s.save().unwrap();

    let next = Session::open(saved).unwrap();
    let recovered = next.narrowest(span.start()).unwrap();
    assert_eq!(next.field(recovered), Ok(fnum(3)));
    assert_eq!(next.varint_word(recovered), Ok(300));
}

// ─── open: the root layer ───

#[test]
fn opens_scalars_lens_and_groups_in_one_layer() {
    // varint f1 · LEN f3 (unopened) · group f1 { varint f1 }
    let data = h("089601 1A03089601 0B 089601 0C");
    let s = open(&data);
    let t = tops(&s);
    assert_eq!(t.len(), 3);
    assert_eq!(s.kind(t[0]).unwrap(), RecordKind::Varint);
    assert_eq!(s.kind(t[1]).unwrap(), RecordKind::Len);
    assert_eq!(s.kind(t[2]).unwrap(), RecordKind::Group);
    // Groups materialize with their layer (the scan is the parse).
    let group_kids: Vec<_> = s.children(t[2]).unwrap().collect();
    assert_eq!(group_kids.len(), 1);
    assert_eq!(s.varint_word(group_kids[0]).unwrap(), 150);
    // LEN stays lazy.
    assert_eq!(s.children(t[1]).unwrap().count(), 0);
}

#[test]
fn empty_document_opens_empty() {
    let s = open(&[]);
    assert_eq!(s.top().count(), 0);
    assert!(DocBytes::ptr_eq(s.doc(), &s.save().unwrap()));
}

#[test]
fn nonminimal_widths_are_refused_not_faulted() {
    // two-byte tag for field 1 — reference-acceptable padding.
    let data = h("8800 01");
    let fault = Session::open_copy(&data).err().expect("padding refused");
    assert!(
        matches!(fault, OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 })),
        "expected the capability refusal, got {fault:?}"
    );
}

#[test]
fn wire_violations_fault() {
    let data = h("08"); // tag then nothing: value truncated
    let fault = Session::open_copy(&data).err().expect("cut value faults");
    assert!(
        matches!(fault, OpenFault::Wire(Fault { at: 1, kind: FaultKind::Value { .. } })),
        "expected a wire fault, got {fault:?}"
    );
    let data = h("0B 089601"); // group never closed
    let fault = Session::open_copy(&data).err().expect("open group faults");
    assert!(
        matches!(
            fault,
            OpenFault::Wire(Fault { at: 0, kind: FaultKind::GroupUnclosed { open } })
                if open.as_inner() == 1
        ),
        "expected GroupUnclosed, got {fault:?}"
    );
}

#[test]
fn group_end_mismatch_and_orphan_fault() {
    let fault = Session::open_copy(&h("0B 14")).err().expect("mismatch faults");
    assert!(
        matches!(fault, OpenFault::Wire(Fault { at: 1, kind: FaultKind::GroupEndMismatch { .. } })),
        "expected mismatch, got {fault:?}"
    );
    let fault = Session::open_copy(&h("0C")).err().expect("orphan faults");
    assert!(
        matches!(fault, OpenFault::Wire(Fault { at: 0, kind: FaultKind::GroupEndOrphan { .. } })),
        "expected orphan, got {fault:?}"
    );
}

#[test]
fn a_thousand_nested_groups_open_and_chain_ancestors() {
    // Nesting depth is bounded by the row arena, not a call stack:
    // the scan keeps its open-group chain in the rows themselves.
    let mut data = alloc::vec![0x0B; 1000];
    data.extend(core::iter::repeat_n(0x0C, 1000));
    let s = open(&data);
    let t = tops(&s);
    assert_eq!(t.len(), 1);
    // Deepest chain materialized: walk ancestors from the innermost.
    let mut cur = t[0];
    let mut depth = 1;
    while let Some(kid) = s.children(cur).unwrap().next() {
        cur = kid;
        depth += 1;
    }
    assert_eq!(depth, 1000);
    assert_eq!(s.ancestors(cur).unwrap().count(), 999);
}

// ─── descend ───

#[test]
fn descend_parses_once_and_projects_after() {
    let data = h("1A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    let first = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.expect("one child"),
        other => panic!("expected Opened, got {other:?}"),
    };
    assert_eq!(s.varint_word(first).unwrap(), 150);
    // Second call projects the same stored outcome.
    match s.descend(len).unwrap() {
        Descent::Opened { first: Some(again) } => assert_eq!(again, first),
        other => panic!("expected the stored outcome, got {other:?}"),
    }
}

#[test]
fn descend_faults_are_resident_and_do_not_stop_the_session() {
    let data = h("0A01 FF"); // payload: a truncated tag
    let mut s = open(&data);
    let len = tops(&s)[0];
    match s.descend(len).unwrap() {
        Descent::Faulted(Fault { at: 2, kind: FaultKind::Tag { .. } }) => {}
        other => panic!("expected a resident fault, got {other:?}"),
    }
    // The payload is still readable as bytes.
    assert_eq!(s.payload_bytes(len).unwrap(), &[0xFF]);
}

#[test]
fn descend_refuses_nonminimal_interiors() {
    let data = h("0A02 8800"); // interior: padded tag
    let mut s = open(&data);
    let len = tops(&s)[0];
    match s.descend(len).unwrap() {
        Descent::Refused(Refusal::NonMinimalTag { at: 2, width: 2 }) => {}
        other => panic!("expected the interior refusal, got {other:?}"),
    }
}

#[test]
fn scalars_do_not_descend() {
    let data = h("089601");
    let mut s = open(&data);
    let v = tops(&s)[0];
    assert!(matches!(s.descend(v), Err(EditFault::KindMismatch { have: RecordKind::Varint })));
}

// ─── the edit algebra (the full transition table) ───

#[test]
fn set_then_read_round_trips_each_shape() {
    let data = h("089601 0D01000000 09FFFFFFFFFFFFFFFF 0A0161");
    let mut s = open(&data);
    let t = tops(&s);
    s.set_varint(t[0], 7).unwrap();
    assert_eq!(s.varint_word(t[0]).unwrap(), 7);
    s.set_i32(t[1], 0xAB).unwrap();
    assert_eq!(s.i32_bits(t[1]).unwrap(), 0xAB);
    s.set_i64(t[2], 0xCD).unwrap();
    assert_eq!(s.i64_bits(t[2]).unwrap(), 0xCD);
    s.set_payload(t[3], b"xyz").unwrap();
    assert_eq!(s.payload_bytes(t[3]).unwrap(), b"xyz");
}

#[test]
fn the_transition_table_is_exhaustive() {
    let data = h("089601");
    let mut s = open(&data);
    let v = tops(&s)[0];
    // Intact —set→ Replaced —set→ Replaced.
    s.set_varint(v, 1).unwrap();
    s.set_varint(v, 2).unwrap();
    assert_eq!(s.status(v).unwrap(), EditStatus::Replaced);
    // Replaced —delete→ Deleted(Some) : shrouded, set refused.
    s.delete(v).unwrap();
    assert_eq!(s.status(v).unwrap(), EditStatus::Deleted);
    assert!(matches!(s.set_varint(v, 3), Err(EditFault::DeletedTarget)));
    assert!(matches!(s.delete(v), Err(EditFault::DeletedTarget)));
    // Deleted(Some v) —undelete→ Replaced(v) : the shroud held it.
    s.undelete(v).unwrap();
    assert_eq!(s.status(v).unwrap(), EditStatus::Replaced);
    assert_eq!(s.varint_word(v).unwrap(), 2);
    assert!(matches!(s.undelete(v), Err(EditFault::NotDeleted)));
    // Replaced —clear→ Intact.
    s.clear_edit(v).unwrap();
    assert_eq!(s.status(v).unwrap(), EditStatus::Intact);
    assert_eq!(s.varint_word(v).unwrap(), 150);
    // Intact —delete→ Deleted(None) —undelete→ Intact.
    s.delete(v).unwrap();
    s.undelete(v).unwrap();
    assert_eq!(s.status(v).unwrap(), EditStatus::Intact);
}

#[test]
fn inserted_rows_have_no_virgin_state() {
    let data = h("089601");
    let mut s = open(&data);
    let ins = s.insert_varint(InsertAt::TailOf(None), fnum(2), 9).unwrap();
    assert_eq!(s.status(ins).unwrap(), EditStatus::Inserted);
    assert!(matches!(s.clear_edit(ins), Err(EditFault::NotClearable)));
    // Inserted —delete→ ghost —undelete→ Inserted.
    s.delete(ins).unwrap();
    assert_eq!(s.status(ins).unwrap(), EditStatus::InsertedDeleted);
    s.undelete(ins).unwrap();
    assert_eq!(s.status(ins).unwrap(), EditStatus::Inserted);
}

#[test]
fn kind_gates_hold_on_every_setter() {
    let data = h("089601");
    let mut s = open(&data);
    let v = tops(&s)[0];
    assert!(matches!(s.set_i32(v, 0), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(s.set_payload(v, b""), Err(EditFault::KindMismatch { .. })));
}

// ─── inserts and topology ───

#[test]
fn inserts_splice_at_every_anchor() {
    let data = h("089601 0802");
    let mut s = open(&data);
    let t = tops(&s);
    let head = s.insert_varint(InsertAt::HeadOf(None), fnum(9), 1).unwrap();
    let tail = s.insert_varint(InsertAt::TailOf(None), fnum(9), 2).unwrap();
    let mid = s.insert_varint(InsertAt::After(t[0]), fnum(9), 3).unwrap();
    let now = tops(&s);
    assert_eq!(now, [head, t[0], mid, t[1], tail]);
}

#[test]
fn insert_into_a_len_requires_descend_first() {
    let data = h("1A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    assert!(matches!(
        s.insert_varint(InsertAt::HeadOf(Some(len)), fnum(1), 1),
        Err(EditFault::TargetUnopened)
    ));
    assert!(matches!(s.descend(len).unwrap(), Descent::Opened { .. }));
    let kid = s.insert_varint(InsertAt::HeadOf(Some(len)), fnum(1), 1).unwrap();
    assert_eq!(s.children(len).unwrap().next(), Some(kid));
}

#[test]
fn inserted_groups_grow_purely_by_insertion() {
    let data = h("089601");
    let mut s = open(&data);
    let g = s.insert_group(InsertAt::TailOf(None), fnum(4)).unwrap();
    let inner = s.insert_varint(InsertAt::HeadOf(Some(g)), fnum(1), 5).unwrap();
    assert_eq!(s.children(g).unwrap().collect::<Vec<_>>(), [inner]);
}

// ─── authored bodies and rebacking ───

#[test]
fn authored_payloads_descend_but_refuse_edits() {
    let data = h("0A0161");
    let mut s = open(&data);
    let len = tops(&s)[0];
    s.set_payload(len, &h("089601")).unwrap();
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.expect("authored interior parses"),
        other => panic!("expected Opened, got {other:?}"),
    };
    assert_eq!(s.varint_word(kid).unwrap(), 150);
    // Browsing is legal; editing inside authored bytes is not.
    assert!(matches!(s.set_varint(kid, 1), Err(EditFault::InsideAuthoredBody)));
    assert!(matches!(s.delete(kid), Err(EditFault::InsideAuthoredBody)));
    assert!(matches!(
        s.insert_varint(InsertAt::After(kid), fnum(1), 1),
        Err(EditFault::InsideAuthoredBody)
    ));
}

#[test]
fn rebacking_over_an_edited_interior_is_refused() {
    // Source LEN with a parsed interior; edit the interior, then
    // try to replace the whole payload: precise undo would lose the
    // interior edit — refused until cleared.
    let data = h("1A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.unwrap(),
        other => panic!("{other:?}"),
    };
    s.set_varint(kid, 7).unwrap();
    assert!(matches!(s.set_payload(len, b"zz"), Err(EditFault::EditedInterior)));
    // Clearing the edit is not enough: its undo history still
    // points into the interior.
    s.clear_edit(kid).unwrap();
    assert!(matches!(s.set_payload(len, b"zz"), Err(EditFault::EditedInterior)));
    // Unwinding the history frees the rebacking.
    s.revert_all();
    s.set_payload(len, b"zz").unwrap();
}

#[test]
fn rebacking_orphans_the_old_view() {
    let data = h("1A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.unwrap(),
        other => panic!("{other:?}"),
    };
    s.set_payload(len, &h("0801")).unwrap();
    // The old child is dead — a domain answer, not a panic.
    assert!(matches!(s.varint_word(kid), Err(EditFault::DeadHandle)));
    // The new interior descends fresh.
    let new_kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(s.varint_word(new_kid).unwrap(), 1);
    assert_ne!(new_kid, kid);
}

#[test]
fn shrouds_do_not_invalidate_views() {
    // Deletion moves no bytes: the parsed interior survives.
    let data = h("1A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.unwrap(),
        other => panic!("{other:?}"),
    };
    s.delete(len).unwrap();
    assert_eq!(s.varint_word(kid).unwrap(), 150); // view survives
    s.undelete(len).unwrap();
    assert_eq!(s.children(len).unwrap().next(), Some(kid));
}

// ─── revert ───

#[test]
fn revert_walks_the_log_backwards() {
    let data = h("089601");
    let mut s = open(&data);
    let v = tops(&s)[0];
    s.set_varint(v, 1).unwrap();
    s.set_varint(v, 2).unwrap();
    s.delete(v).unwrap();
    assert_eq!(s.pending(), 3);
    s.revert();
    assert_eq!(s.status(v).unwrap(), EditStatus::Replaced);
    assert_eq!(s.varint_word(v).unwrap(), 2);
    s.revert();
    assert_eq!(s.varint_word(v).unwrap(), 1);
    s.revert();
    assert_eq!(s.status(v).unwrap(), EditStatus::Intact);
    assert_eq!(s.revert(), None);
}

#[test]
fn reverting_an_insert_leaves_a_ghost() {
    let data = h("089601");
    let mut s = open(&data);
    let ins = s.insert_varint(InsertAt::TailOf(None), fnum(2), 9).unwrap();
    assert_eq!(s.top().count(), 2);
    s.revert();
    // The forged past: birth undone = shrouded, topology monotone.
    assert_eq!(s.status(ins).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(s.top().count(), 2); // still in the chain, UI filters
}

// ─── save ───

#[test]
fn a_clean_session_saves_as_the_same_allocation() {
    let data = h("089601 1A03089601 0B0C");
    let s = open(&data);
    let saved = s.save().unwrap();
    assert!(DocBytes::ptr_eq(s.doc(), &saved));
}

#[test]
fn ghosts_do_not_break_the_clean_fast_path() {
    let data = h("089601");
    let mut s = open(&data);
    let _ = s.insert_varint(InsertAt::TailOf(None), fnum(2), 9).unwrap();
    s.revert();
    let saved = s.save().unwrap();
    assert!(DocBytes::ptr_eq(s.doc(), &saved)); // T2's whole point
}

#[test]
fn untouched_subtrees_are_copied_bit_true() {
    // Edit one root; the group root must be byte-identical.
    let data = h("089601 0B 12026162 0C");
    let mut s = open(&data);
    let t = tops(&s);
    s.set_varint(t[0], 1).unwrap();
    let saved = s.save().unwrap();
    assert_eq!(&saved.as_slice()[2..], &data[3..]); // group span verbatim
    assert_eq!(&saved.as_slice()[..2], &h("0801")[..]); // new scalar
}

#[test]
fn deletes_prune_and_len_prefixes_recompute() {
    // LEN f3 { varint f1 · varint f1 } — delete one child.
    let data = h("1A04 0801 0802");
    let mut s = open(&data);
    let len = tops(&s)[0];
    assert!(matches!(s.descend(len).unwrap(), Descent::Opened { .. }));
    let kids: Vec<_> = s.children(len).unwrap().collect();
    s.delete(kids[0]).unwrap();
    let saved = s.save().unwrap();
    assert_eq!(saved.as_slice(), &h("1A02 0802")[..]);
}

#[test]
fn replaced_values_and_inserts_emit_canonically() {
    let data = h("089601");
    let mut s = open(&data);
    let v = tops(&s)[0];
    s.set_varint(v, 1).unwrap();
    let g = s.insert_group(InsertAt::TailOf(None), fnum(2)).unwrap();
    let _ = s.insert_varint(InsertAt::HeadOf(Some(g)), fnum(1), 5).unwrap();
    let saved = s.save().unwrap();
    assert_eq!(saved.as_slice(), &h("0801 13 0805 14")[..]);
}

#[test]
fn edit_revert_all_save_is_pointer_clean() {
    let data = h("1A04 0801 0802 0D01000000");
    let mut s = open(&data);
    let t = tops(&s);
    let kids: Vec<_> = match s.descend(t[0]).unwrap() {
        Descent::Opened { .. } => s.children(t[0]).unwrap().collect(),
        other => panic!("{other:?}"),
    };
    s.set_varint(kids[1], 99).unwrap();
    s.set_i32(t[1], 7).unwrap();
    s.delete(kids[0]).unwrap();
    s.revert_all();
    let saved = s.save().unwrap();
    assert!(DocBytes::ptr_eq(s.doc(), &saved));
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

// ─── handles ───

#[test]
#[should_panic = "index out of bounds"]
pub(super) fn forged_handles_panic() {
    let data = h("089601");
    let s = open(&data);
    let forged = Handle(RowId::new(99).unwrap());
    let _ = s.kind(forged);
}

// ─── spans and navigation ───

#[test]
fn spans_index_the_hex_view() {
    let data = h("089601 1A03089601");
    let s = open(&data);
    let t = tops(&s);
    assert_eq!(s.span(t[0]).unwrap(), Some(Span::new(0, 3)));
    assert_eq!(s.span(t[1]).unwrap(), Some(Span::new(3, 8)));
    assert_eq!(s.narrowest(4), Some(t[1]));
    assert_eq!(s.narrowest(0), Some(t[0]));
}

#[test]
fn narrowest_descends_into_materialized_children() {
    let data = h("1A03 089601");
    let mut s = open(&data);
    let len = tops(&s)[0];
    assert_eq!(s.narrowest(3), Some(len)); // unopened: the LEN itself
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(s.narrowest(3), Some(kid)); // materialized: the child
}

#[test]
fn authored_rows_have_no_hex_span() {
    let data = h("0A0161");
    let mut s = open(&data);
    let len = tops(&s)[0];
    let ins = s.insert_varint(InsertAt::TailOf(None), fnum(2), 1).unwrap();
    assert_eq!(s.span(ins).unwrap(), None);
    s.set_payload(len, &h("0801")).unwrap();
    let kid = match s.descend(len).unwrap() {
        Descent::Opened { first } => first.unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(s.span(kid).unwrap(), None); // authored backing
}

// ─── consumer-facing axes: geometry, by-number ───

#[test]
fn source_spans_partition_each_backed_record() {
    // One record per kind: varint, I32, I64, LEN, group.
    let data = h("089601 15AABBCCDD 19AABBCCDD11223344 1A026869 0B 089601 0C");
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
            RecordSpans::Group { tag, interior, end_tag } => {
                assert_eq!(tag.start(), span.start());
                assert_eq!(tag.end(), interior.start());
                assert_eq!(interior.end(), end_tag.start());
                assert_eq!(end_tag.end(), span.end());
            }
        }
    }
}

#[test]
fn authored_rows_have_no_source_geometry() {
    let data = h("089601");
    let mut s = open(&data);
    let t0 = tops(&s)[0];
    let new = s.insert_varint(InsertAt::After(t0), fnum(2), 7).unwrap();
    assert_eq!(s.source_spans(new).unwrap(), None);
}

#[test]
fn by_field_narrows_in_wire_order() {
    // f1 · f2 · f1
    let data = h("0801 1002 0803");
    let s = open(&data);
    let t = tops(&s);
    let ones: Vec<Handle> = s.top().by_field(fnum(1)).collect();
    assert_eq!(ones, [t[0], t[2]]);
    assert_eq!(s.top().by_field(fnum(3)).count(), 0);
}

// ─── the edit algebra law: revert restores the observable state ───

#[test]
fn any_edit_sequence_reverts_to_the_pristine_observable_state() {
    // varint · LEN "hi" · group { varint } — every kind on the top
    // layer, then a scripted mix of every command class.
    let data = h("089601 1A026869 0B 089601 0C");
    let mut s = open(&data);
    let t = tops(&s);

    s.set_varint(t[0], 7).unwrap();
    s.set_payload(t[1], b"world").unwrap();
    let inserted = s.insert_varint(InsertAt::After(t[0]), fnum(9), 1).unwrap();
    s.delete(t[0]).unwrap();
    s.undelete(t[0]).unwrap();
    s.set_varint(inserted, 2).unwrap();
    s.delete(t[2]).unwrap();
    s.set_varint(t[0], 8).unwrap();
    s.clear_edit(t[0]).unwrap();

    while s.revert().is_some() {}

    // The strong form: pointer-clean save (root_dirty must have
    // walked back to zero — the reconciliation oracle guards every
    // step in debug), plus per-handle status restoration.
    let saved = s.save().unwrap();
    assert!(DocBytes::ptr_eq(&saved, &s.save().unwrap()));
    assert_eq!(saved.as_slice(), data.as_slice());
    assert_eq!(s.pending(), 0);
    for &handle in &t {
        assert_eq!(s.status(handle).unwrap(), EditStatus::Intact);
    }
}

#[test]
fn failed_commands_leave_no_observable_trace() {
    let data = h("089601");
    let mut s = open(&data);
    let t0 = tops(&s)[0];
    let before_pending = s.pending();
    let before_bytes = s.save().unwrap();

    // Kind gate refusal.
    assert!(s.set_i32(t0, 1).is_err());
    // Anchor refusal: a forged-generation handle is a panic, but a
    // dead anchor is a domain error — delete then insert after it
    // stays lawful, so use the payload-kind gate on insert instead.
    assert!(s.set_payload(t0, b"x").is_err());

    assert_eq!(s.pending(), before_pending, "no log growth on Err");
    let after = s.save().unwrap();
    assert!(DocBytes::ptr_eq(&after, &before_bytes), "no dirt on Err");
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
fn narrowest_attributes_group_end_tags_to_the_group_row() {
    // outer group 0..7 { varint 1..4 · inner group 4..6 }
    let data = h("0B 089601 0B0C 0C");
    let s = open(&data);
    let t = tops(&s);
    let kids: Vec<Handle> = s.children(t[0]).unwrap().collect();
    let (varint, inner) = (kids[0], kids[1]);
    assert_eq!(s.narrowest(3), Some(varint));
    assert_eq!(s.narrowest(4), Some(inner)); // inner open tag
    assert_eq!(s.narrowest(5), Some(inner)); // inner end tag
    assert_eq!(s.narrowest(6), Some(t[0])); // outer end tag
    assert_eq!(s.narrowest(7), None); // past the content
}

#[test]
fn narrowest_matches_a_full_walk_under_random_commands() {
    // varint · LEN{varint · LEN{varint}} · group{varint · group{}}
    // · I32 · LEN{group cut short} — every kind, two nesting axes,
    // and a payload whose descend faults resident.
    let data = h("089601 1A08 089601 1A03089601 0B 089601 0B0C 0C 15AABBCCDD 1A02 0BFF");
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
                    // A group cut short: the descend of this
                    // authored payload faults resident.
                    _ => h("0BFF"),
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
                let _ = s.insert_group(InsertAt::TailOf(None), fnum(1));
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
    let data = h("089601 1A08 089601 1A03089601 0B 089601 0B0C 0C");
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
    // group{varint} · LEN{varint}
    let data = h("0B 089601 0C 1A03 089601");
    let mut s = open(&data);
    let t = tops(&s);
    let (group, len) = (t[0], t[1]);
    // Into a scan-published group layer.
    let in_group = s.insert_varint(InsertAt::TailOf(Some(group)), fnum(2), 1).unwrap();
    assert_eq!(s.children(group).unwrap().last(), Some(in_group));
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
    assert_eq!(saved.as_slice(), &h("0B 089601 1001 0C 1A05 089601 1002 1004")[..]);
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
    // An authored payload whose interior nests a group: the
    // borrowed twin's slot witness climbs through the group layer.
    let nested = h("0B 08 07 0C");
    let mut t = Twins::open(&doc);
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
    // Both descend the authored zone: the interior's group layer
    // materialized at the authored scan, and the leaf's value read
    // climbs group, then container, to the slot.
    let (copy_group, borrow_group) = {
        let rc = tops(&t.copy)[0];
        let Descent::Opened { first: Some(cg) } = t.copy.descend(rc).unwrap() else {
            panic!("authored interior opens")
        };
        let rb = t.borrow.top().next().unwrap();
        let Descent::Opened { first: Some(bg) } = t.borrow.descend(rb).unwrap() else {
            panic!("authored interior opens")
        };
        (cg, bg)
    };
    let copy_leaf = t.copy.children(copy_group).unwrap().next().unwrap();
    let borrow_leaf = t.borrow.children(borrow_group).unwrap().next().unwrap();
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
    assert!(matches!(t.borrow.varint_word(borrow_leaf), Err(EditFault::DeadHandle)));
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

// ─── source transfer: closures, the move law, sealed imports ───

// ─── the priced typestate: settled bodies, census, tiers ───

#[cfg(feature = "priced-session-grouped")]
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
    fn priced_width_cascade_crosses_the_boundary_at_the_ancestor() {
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
        p.set_payload(inner, &alloc::vec![0u8; 126]).unwrap();
        assert_eq!(p.save_len(), Ok(131), "the outer prefix widens with its body");
        assert_eq!(p.save().unwrap().len(), 131);
        p.revert();
        assert_eq!(p.save_len(), Ok(129));
    }

    #[test]
    fn priced_group_levels_pass_the_delta_through_fixed_framing() {
        // group f1 { LEN f2 { 125 zeros } }: the group body crosses
        // 127 → 128, but group framing is fixed-width, so the total
        // moves by exactly the interior delta.
        let mut data = alloc::vec![0x0B, 0x12, 0x7D];
        data.extend(core::iter::repeat_n(0u8, 125));
        data.push(0x0C);
        let mut p = priced(&data);
        let group = p.top().next().unwrap();
        let inner = p.children(group).unwrap().next().unwrap();
        assert_eq!(p.save_len(), Ok(129));
        p.set_payload(inner, &alloc::vec![0u8; 126]).unwrap();
        assert_eq!(p.save_len(), Ok(130), "no prefix rides a group boundary");
        assert_eq!(p.save().unwrap().len(), 130);

        // The same growth under a LEN ancestor pays the prefix too:
        // the group's interior cascade still reaches the LEN above.
        let mut data = alloc::vec![0x0A, 0x7F, 0x0B, 0x12, 0x7B];
        data.extend(core::iter::repeat_n(0u8, 123));
        data.push(0x0C);
        let mut p = priced(&data);
        let outer = p.top().next().unwrap();
        let Descent::Opened { first: Some(group) } = p.descend(outer).unwrap() else {
            unreachable!()
        };
        let inner = p.children(group).unwrap().next().unwrap();
        assert_eq!(p.save_len(), Ok(129));
        p.set_payload(inner, &alloc::vec![0u8; 124]).unwrap();
        assert_eq!(p.save_len(), Ok(131), "the LEN above the group re-prices");
        assert_eq!(p.save().unwrap().len(), 131);
    }

    #[test]
    fn priced_entries_seed_scanned_groups_at_their_interior_span() {
        // group f2 { varint f3 = 1 }: span 4, both framing tags one
        // byte, so the seed is 2.
        let data = h("13 18 01 14");
        let mut p = priced(&data);
        let group = p.top().next().unwrap();
        let inner = p.children(group).unwrap().next().unwrap();
        p.set_varint(inner, 300).unwrap();
        assert_eq!(p.bodies.get(&group.0), Some(&3), "the widened word settled");
        assert_eq!(p.save_len(), Ok(5));
        p.revert();
        assert_eq!(p.bodies.get(&group.0), Some(&2), "the entry settled back to its seed");
        assert_eq!(p.save_len(), Ok(4));
    }

    #[test]
    fn priced_authored_groups_seed_empty_and_settle_their_births() {
        let mut p = priced(&h("08 2A"));
        let group = p.insert_group(InsertAt::TailOf(None), fnum(5)).unwrap();
        assert_eq!(p.save_len(), Ok(4), "an authored group prices its two framing tags");
        p.insert_varint(InsertAt::TailOf(Some(group)), fnum(1), 7).unwrap();
        assert_eq!(p.bodies.get(&group.0), Some(&2));
        assert_eq!(p.save_len(), Ok(6));
        assert_eq!(p.save().unwrap().len(), 6);
        // The births settle back off: the ghost group prices nothing.
        p.revert();
        p.revert();
        assert_eq!(p.bodies.get(&group.0), Some(&0), "the ghost's entry rests at its seed");
        assert_eq!(p.save_len(), Ok(2));
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
    fn priced_lockstep_covers_the_group_arc_family() {
        // varint f1 · group f2 { varint f1 · group f2 { varint f1 } } ·
        // LEN f3 { varint f1 }: nested groups beside a LEN spine.
        let data = h("08 01 13 08 07 13 08 09 14 14 1A 02 08 05");
        let mut t = PricedTwins::open(&data);
        let tops: Vec<Handle> = t.priced.top().collect();
        let outer_kids: Vec<Handle> = t.priced.children(tops[1]).unwrap().collect();
        let inner_group = outer_kids[1];
        let deep = t.priced.children(inner_group).unwrap().next().unwrap();

        // Edits at both group depths: the deltas pass the fixed
        // framing unchanged.
        t.lockstep(|p| p.set_varint(deep, 300).unwrap(), |b| b.set_varint(deep, 300).unwrap());
        t.lockstep(
            |p| p.set_varint(outer_kids[0], 5).unwrap(),
            |b| b.set_varint(outer_kids[0], 5).unwrap(),
        );
        // Shroud the dirty inner group; edit under the shroud; lift.
        t.lockstep(|p| p.delete(inner_group).unwrap(), |b| b.delete(inner_group).unwrap());
        t.lockstep(|p| p.set_varint(deep, 4).unwrap(), |b| b.set_varint(deep, 4).unwrap());
        t.lockstep(|p| p.undelete(inner_group).unwrap(), |b| b.undelete(inner_group).unwrap());
        // Group births at the root and inside the LEN spine.
        t.lockstep(
            |p| {
                p.insert_group(InsertAt::TailOf(None), fnum(5)).unwrap();
            },
            |b| {
                b.insert_group(InsertAt::TailOf(None), fnum(5)).unwrap();
            },
        );
        let born = t.priced.top().last().unwrap();
        t.lockstep(
            |p| {
                p.insert_varint(InsertAt::TailOf(Some(born)), fnum(1), 9).unwrap();
            },
            |b| {
                b.insert_varint(InsertAt::TailOf(Some(born)), fnum(1), 9).unwrap();
            },
        );
        let ghost_kid = t.priced.children(born).unwrap().next().unwrap();
        // The ghost-group arc: shroud the authored group, edit its
        // still-live child under the ghost, then lift the ghost.
        t.lockstep(|p| p.delete(born).unwrap(), |b| b.delete(born).unwrap());
        t.lockstep(
            |p| p.set_varint(ghost_kid, 300).unwrap(),
            |b| b.set_varint(ghost_kid, 300).unwrap(),
        );
        t.lockstep(|p| p.undelete(born).unwrap(), |b| b.undelete(born).unwrap());
        // Reverts walk every arc back to the source.
        t.lockstep(|p| p.revert_all(), |b| b.revert_all());
        assert_eq!(t.priced.save_len().map(usize_of), Ok(data.len()));
    }

    #[test]
    fn priced_lockstep_survives_the_xorshift_soak() {
        // Scanned groups, a LEN spine, and a payload whose descend
        // faults resident, judged three ways after every step.
        let data = h("089601 13 0801 14 1A03089601 15AABBCCDD 1A01 0B");
        let mut t = PricedTwins::open(&data);
        let mut rng = XorShift(0x6C07_8965);
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
            let containers: Vec<Handle> = pool
                .iter()
                .copied()
                .filter(|&handle| {
                    matches!(t.base.kind(handle), Ok(RecordKind::Group | RecordKind::Len))
                })
                .collect();
            let container_pick = if containers.is_empty() {
                None
            } else {
                Some(containers[rng.next() as usize % containers.len()])
            };
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
                4 => {
                    let a = t.priced.descend(len_pick).is_ok();
                    let b = t.base.descend(len_pick).is_ok();
                    assert_eq!(a, b, "descend verdicts diverged at step {step}");
                }
                5 => {
                    assert_eq!(
                        t.priced.insert_group(InsertAt::TailOf(container_pick), fnum(7)).is_ok(),
                        t.base.insert_group(InsertAt::TailOf(container_pick), fnum(7)).is_ok(),
                    );
                }
                6 | 7 => {
                    let payload = match rng.next() % 4 {
                        0 => h("089601"),
                        1 => Vec::new(),
                        2 => h("13 0801 14"),
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
                        t.priced.insert_varint(InsertAt::TailOf(container_pick), fnum(6), 1),
                        t.base.insert_varint(InsertAt::TailOf(container_pick), fnum(6), 1),
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
    fn priced_admission_prices_groups_and_shrouded_group_layers() {
        // Dirt inside a scanned group, an authored group with a live
        // child, and a shrouded group whose layer carries dirt: the
        // admission walk enters all three.
        let data = h("13 08 07 14 08 01");
        let mut base = open(&data);
        let tops = tops(&base);
        let inner = base.children(tops[0]).unwrap().next().unwrap();
        base.set_varint(inner, 300).unwrap();
        let born = base.insert_group(InsertAt::TailOf(None), fnum(5)).unwrap();
        base.insert_varint(InsertAt::TailOf(Some(born)), fnum(1), 9).unwrap();
        base.delete(tops[0]).unwrap();
        let expect = base.save_len().unwrap();

        let mut p = base.into_priced().map_err(|(_, fault)| fault).expect("group dirt admits");
        assert_eq!(p.save_len(), Ok(expect));
        assert_eq!(p.bodies.get(&tops[0].0), Some(&3), "the shrouded group layer was entered");
        assert_eq!(p.bodies.get(&born.0), Some(&2), "the authored group accumulated its child");

        // Lifting the shroud re-enters the group at its edited body.
        p.undelete(tops[0]).unwrap();
        assert_eq!(p.save_len(), Ok(expect + 5));
        assert_eq!(p.save().unwrap().len(), expect + 5);
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

    #[test]
    fn priced_frames_leave_the_price_untouched_on_every_non_publishing_exit() {
        // The frame stages inside an authored group's layer, so the
        // settle at the publishing finish climbs a group level too.
        let mut p = priced(&h("08 01"));
        let group = p.insert_group(InsertAt::TailOf(None), fnum(5)).unwrap();
        assert_eq!(p.save_len(), Ok(4));
        let cursor = p.machine.store.stage_mark();
        let settled = p.total;

        // An abandoned undeclared frame.
        {
            let mut frame = p.begin_insert_payload(InsertAt::TailOf(Some(group)), fnum(3)).unwrap();
            frame.write(b"junk").unwrap();
        }
        assert_eq!(p.pending(), 1, "only the group birth is logged");
        assert_eq!(p.total, settled, "an abandoned frame settles nothing");
        assert_eq!(p.machine.store.stage_mark(), cursor, "the staged bytes reclaim");

        // A refused sized finish is a non-publishing exit too.
        let mut frame =
            p.begin_insert_payload_sized(InsertAt::TailOf(Some(group)), fnum(3), 4).unwrap();
        frame.write(b"ab").unwrap();
        assert!(matches!(
            frame.finish().err(),
            Some(FrameFault::UnderDeclared { declared: 4, staged: 2 })
        ));
        assert_eq!(p.total, settled);
        assert_eq!(p.machine.store.stage_mark(), cursor);

        // The publishing finish settles through the group level.
        let mut frame = p.begin_insert_payload(InsertAt::TailOf(Some(group)), fnum(3)).unwrap();
        frame.write(b"hi").unwrap();
        let minted = frame.finish().unwrap();
        assert_eq!(p.payload_bytes(minted), Ok(&b"hi"[..]));
        assert_eq!(p.bodies.get(&group.0), Some(&4), "the group body settled the publish");
        assert_eq!(p.save_len(), Ok(8));
        assert_eq!(p.save().unwrap().len(), 8);
    }

    #[test]
    fn priced_group_entries_stay_off_the_length_class_census() {
        // Groups carry no length prefix, so an over-cap group body is
        // synthetic-legal for the ledger and never enters the census;
        // the fast tier keeps answering. The boundary value is
        // synthetic (no affordable fixture reaches it); the census
        // filter and tier selection under judgment are real.
        let data = h("13 18 01 14");
        let mut p = priced(&data);
        let group = p.top().next().unwrap();
        let inner = p.children(group).unwrap().next().unwrap();
        let cap = u64::from(PayloadLen::MAX.as_inner());
        p.bodies.insert(group.0, cap - 1);
        p.total = 50;
        p.settle_climb(inner.0, 2);
        assert_eq!(p.bodies.get(&group.0), Some(&(cap + 1)));
        assert_eq!(p.over_caps, 0, "group bodies carry no class");
        assert_eq!(p.total, 52, "fixed framing passes the delta through");
        assert_eq!(p.save_len(), Ok(52), "the fast tier still answers");
    }

    #[test]
    fn priced_census_crosses_the_length_class_in_both_directions() {
        // A real machine at a synthetic boundary: the LEN ledger entry
        // is seeded just under the length class inside a group, and
        // one settled climb walks the crossing arithmetic both ways —
        // the LEN level must enter and leave the census while the
        // group level passes the delta with no class judgment. The
        // class cap is far past any affordable fixture, so the
        // boundary values are synthetic; the climb, census, and tier
        // code under judgment are real.
        // group f3 { LEN f1 { varint f1 } }.
        let data = h("1B 0A 02 08 01 1C");
        let mut p = priced(&data);
        let group = p.top().next().unwrap();
        let container = p.children(group).unwrap().next().unwrap();
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
        assert_eq!(p.over_caps, 1, "the LEN crossing entered the census");
        assert_eq!(p.bodies.get(&group.0), Some(&6), "the group body carried the delta");
        assert_eq!(p.total, 102, "prefix and group framing hold across this boundary");
        assert_eq!(p.save_len(), p.machine.save_len(), "a raised census delegates");

        // Shrink back: the census clears and the fast tier returns.
        p.settle_climb(inner.0, -2);
        assert_eq!(p.bodies.get(&container.0), Some(&(cap - 1)));
        assert_eq!(p.over_caps, 0, "the lowering left the census");
        assert_eq!(p.total, 100);
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

    // The fixture stages a real 2 GiB payload: no smaller input can
    // cross the length class end to end, and 32-bit targets and Miri
    // cannot host the allocation.
    #[cfg(all(not(target_family = "wasm"), not(miri)))]
    #[test]
    fn priced_over_cap_crossing_matches_the_walk_end_to_end() {
        let _giant = crate::session::giant_fixture::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // group f2 { LEN f1 {} }: the crossing climbs a LEN level
        // under a group level, so the census counts exactly once and
        // the group passes the delta.
        let data = h("13 0A 00 14");
        let mut p = priced(&data);
        let group = p.top().next().unwrap();
        let container = p.children(group).unwrap().next().unwrap();
        assert!(matches!(p.descend(container).unwrap(), Descent::Opened { .. }));

        // Grow past the class: the settled fault is the walk's fault,
        // payload included.
        let big = alloc::vec![0u8; usize_of(PayloadLen::MAX.as_inner())];
        p.insert_payload(InsertAt::TailOf(Some(container)), fnum(3), &big).unwrap();
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
}

// ─── the mixed-backing sibling: lockstep twins in both drives, the
// interleaved history on one log, and the provenance flips — the
// arcs run inside and beside groups ───

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
fn mix_borrow_drive_tracks_the_borrowed_sibling_around_groups() {
    // group f1 { LEN f2 "a" } · LEN f2 "b": the arcs land inside
    // and beside the group.
    let doc = h("0B 12 01 61 0C 12 01 62");
    let alpha = h("08 01");
    let beta = h("08 07 08 08");
    let body = h("08 2A");
    let mut t = MixBorrowDrive::open(&doc);
    // Install inside the group, then over the sibling beside it.
    t.lockstep(
        |s| {
            let group = s.top().next().unwrap();
            let inner = s.children(group).unwrap().next().unwrap();
            s.set_payload(inner, &alpha).unwrap();
        },
        |s| {
            let group = s.top().next().unwrap();
            let inner = s.children(group).unwrap().next().unwrap();
            s.set_payload(inner, &alpha).unwrap();
        },
    );
    t.lockstep(
        |s| {
            let outer = s.top().nth(1).unwrap();
            s.set_payload(outer, &beta).unwrap();
        },
        |s| {
            let outer = s.top().nth(1).unwrap();
            s.set_payload(outer, &beta).unwrap();
        },
    );
    // Shroud the whole group around the interior install.
    t.lockstep(
        |s| {
            let group = s.top().next().unwrap();
            s.delete(group).unwrap();
        },
        |s| {
            let group = s.top().next().unwrap();
            s.delete(group).unwrap();
        },
    );
    t.lockstep(
        |s| {
            let group = s.top().next().unwrap();
            s.undelete(group).unwrap();
        },
        |s| {
            let group = s.top().next().unwrap();
            s.undelete(group).unwrap();
        },
    );
    // A birth beside the group, its revert, and the full unwind.
    t.lockstep(
        |s| {
            s.insert_payload(InsertAt::TailOf(None), fnum(3), &body).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), fnum(3), &body).unwrap();
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
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap()[..], doc[..]);
}

#[test]
fn mix_copy_drive_tracks_the_copy_only_session_around_groups() {
    let doc = h("0B 12 01 61 0C 12 01 62");
    let alpha = h("08 01");
    let mut t = MixCopyDrive::open(&doc);
    // Copied installs inside the group and beside it.
    t.lockstep(
        |s| {
            let group = s.top().next().unwrap();
            let inner = s.children(group).unwrap().next().unwrap();
            s.set_payload_copy(inner, &alpha).unwrap();
        },
        |s| {
            let group = s.top().next().unwrap();
            let inner = s.children(group).unwrap().next().unwrap();
            s.set_payload(inner, &alpha).unwrap();
        },
    );
    t.lockstep(
        |s| {
            s.insert_payload_copy(InsertAt::TailOf(None), fnum(3), &alpha).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), fnum(3), &alpha).unwrap();
        },
    );
    // A frame staged onto the record beside the group.
    t.lockstep(
        |s| {
            let outer = s.top().nth(1).unwrap();
            let mut frame = s.begin_set_payload_sized(outer, 2).unwrap();
            frame.write(b"ok").unwrap();
            frame.finish().unwrap();
        },
        |s| {
            let outer = s.top().nth(1).unwrap();
            let mut frame = s.begin_set_payload_sized(outer, 2).unwrap();
            frame.write(b"ok").unwrap();
            frame.finish().unwrap();
        },
    );
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap()[..], doc[..]);
}

#[test]
fn mix_interleaved_history_walks_both_backings_inside_a_group() {
    // group f1 { LEN f2 "a" }: the interleaved arc runs on a row
    // inside the group's layer.
    let doc = h("0B 12 01 61 0C");
    let alpha = h("08 01");
    let charlie = h("08 05");
    let mut s = MixSession::open_copy(&doc).unwrap();
    let group = s.top().next().unwrap();
    let r = s.children(group).unwrap().next().unwrap();
    s.set_payload(r, &alpha).unwrap();
    {
        let transient = h("08 07");
        s.set_payload_copy(r, &transient).unwrap();
    }
    s.set_payload(r, &charlie).unwrap();
    assert_eq!(s.pending(), 3, "three installs, one log");
    assert_eq!(s.save().unwrap()[..], h("0B 12 02 08 05 0C")[..]);
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), h("08 07"));
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), alpha);
    s.revert();
    assert_eq!(s.save().unwrap()[..], doc[..]);
    assert_eq!(s.pending(), 0);
}

#[test]
fn mix_descents_reach_the_right_provenance_over_each_flip() {
    // LEN f2 wrapping varint f1=1, beside a group.
    let doc = h("12 02 08 01 0B 0C");
    // A nested payload whose interior holds a group closure.
    let nested = h("12 04 0B 08 07 0C");
    let mut s = MixSession::open_copy(&doc).unwrap();
    let r = s.top().next().unwrap();
    let Descent::Opened { first: Some(source_inner) } = s.descend(r).unwrap() else {
        panic!("source interior opens")
    };
    assert_eq!(s.varint_word(source_inner).unwrap(), 1);
    // Borrowed flip: the authored interior nests a LEN wrapping a
    // group; the group's own layer materializes at the scan.
    s.set_payload(r, &nested).unwrap();
    assert!(matches!(s.varint_word(source_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(borrow_inner) } = s.descend(r).unwrap() else {
        panic!("borrowed interior opens")
    };
    let Descent::Opened { first: Some(inner_group) } = s.descend(borrow_inner).unwrap() else {
        panic!("nested borrowed interior opens")
    };
    let leaf = s.children(inner_group).unwrap().next().unwrap();
    assert_eq!(s.varint_word(leaf).unwrap(), 7, "depth two reads the borrowed slot");
    assert!(matches!(s.set_varint(leaf, 9), Err(EditFault::InsideAuthoredBody)));
    // Copied flip: the copied extent is its own zone the same way.
    {
        let transient = h("12 02 08 63");
        s.set_payload_copy(r, &transient).unwrap();
    }
    assert!(matches!(s.payload_bytes(borrow_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(copy_inner) } = s.descend(r).unwrap() else {
        panic!("copied interior opens")
    };
    let Descent::Opened { first: Some(copy_leaf) } = s.descend(copy_inner).unwrap() else {
        panic!("nested copied interior opens")
    };
    assert_eq!(s.varint_word(copy_leaf).unwrap(), 99, "depth two reads the copied extent");
    // Unwind: borrowed provenance, then the scanned source.
    s.revert();
    let Descent::Opened { first: Some(again) } = s.descend(r).unwrap() else {
        panic!("borrowed interior reopens")
    };
    assert_eq!(s.payload_bytes(again).unwrap(), h("0B 08 07 0C"));
    s.revert();
    let Descent::Opened { first: Some(back) } = s.descend(r).unwrap() else {
        panic!("source interior reopens")
    };
    assert_eq!(s.varint_word(back).unwrap(), 1);
    assert_eq!(s.save().unwrap()[..], doc[..]);
}

#[test]
fn mix_soak_mixes_backings_across_containers_with_descents() {
    // A group holding a LEN, a top LEN, and a scalar: the soak
    // drives both backings inside and beside the group, with an
    // exact payload oracle checked after every operation.
    let doc = h("0B 12 01 61 0C 1A 01 62 08 2A");
    let pool = [h("08 01"), h("08 07"), h("12 00"), h("08 96 01"), h("")];
    let mut s = MixSession::open_copy(&doc).unwrap();
    let t: Vec<_> = s.top().collect();
    let in_group = s.children(t[0]).unwrap().next().unwrap();
    let targets = [in_group, t[1]];
    let mut current: [Vec<u8>; 2] = [h("61"), h("62")];
    let mut history: Vec<(usize, Vec<u8>)> = Vec::new();
    for step in 0..96_u32 {
        let which = usize_of(step % 2);
        let target = targets[which];
        match step % 8 {
            0 | 3 => {
                let payload = &pool[usize_of(step) % pool.len()];
                s.set_payload(target, payload).unwrap();
                history.push((which, core::mem::replace(&mut current[which], payload.clone())));
            }
            1 | 5 => {
                let transient = alloc::vec![0x08, u8::try_from(step % 0x60).unwrap()];
                s.set_payload_copy(target, &transient).unwrap();
                history.push((which, core::mem::replace(&mut current[which], transient)));
            }
            2 | 6 => {
                let _ = s.descend(target);
            }
            _ => {
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
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], doc[..]);
}
