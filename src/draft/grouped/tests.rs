//! Contract pins for the grouped draft: tolerant admission with
//! group framing widths, the fidelity save, exact revision, and
//! the tenure doors.

use alloc::vec::Vec;

use super::*;

#[track_caller]
fn h(s: &str) -> Vec<u8> {
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
fn f(n: u32) -> FieldNumber {
    FieldNumber::new(n).expect("test field in range")
}

/// Every output face of one draft, cross-checked: `save`,
/// `save_into`, `save_sink` concatenation, and `save_len` all
/// answer the same bytes.
#[track_caller]
fn all_saves(draft: &Draft) -> Vec<u8> {
    let saved = draft.save().expect("save succeeds");
    assert_eq!(
        draft.save_len().expect("save_len succeeds") as usize,
        saved.len(),
        "save_len prices the save"
    );
    let mut into = h("DEAD");
    draft.save_into(&mut into).expect("save_into succeeds");
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    draft.save_sink(|chunk| streamed.extend_from_slice(chunk)).expect("save_sink succeeds");
    assert_eq!(streamed, saved, "the sink concatenation is the save");
    saved
}

// ─── tolerant admission and group framing widths ───

#[test]
fn padded_group_framing_admits_and_rides_saves_verbatim() {
    // Group f2 with both framing tags padded to two bytes, its
    // interior a padded varint; a padded scalar rides beside it.
    let msg = h("93 00  18 96 81 00  94 00  88 00 01");
    let draft = Draft::open(msg.clone()).unwrap();
    let tops: Vec<_> = draft.top().collect();
    assert_eq!(tops.len(), 2);
    let inner = draft.children(tops[0]).unwrap().next().unwrap();
    assert_eq!(draft.varint_word(inner).unwrap(), 150);
    assert_eq!(all_saves(&draft), msg, "an untouched draft saves its padded source");
}

#[test]
fn interior_edits_keep_the_padded_group_tags_verbatim() {
    let msg = h("93 00 18 01 94 00");
    let mut draft = Draft::open(msg).unwrap();
    let group = draft.top().next().unwrap();
    let inner = draft.children(group).unwrap().next().unwrap();

    draft.set_varint(inner, 300).unwrap();
    assert_eq!(
        all_saves(&draft),
        h("93 00 18 AC 02 94 00"),
        "a scanned group's framing tags ride verbatim whatever happens inside"
    );
}

#[test]
fn an_inserted_group_emits_minimally_beside_padded_wire() {
    let msg = h("88 00 01");
    let mut draft = Draft::open(msg).unwrap();
    let group = draft.insert_group(InsertAt::TailOf(None), f(2)).unwrap();
    draft.insert_varint(InsertAt::TailOf(Some(group)), f(3), 3).unwrap();
    assert_eq!(all_saves(&draft), h("88 00 01 13 18 03 14"));
}

#[test]
fn a_replaced_scalar_inside_a_padded_group_keeps_its_own_padded_tag() {
    // The group's framing and the record's tag are input facts;
    // only the replaced value re-authors.
    let msg = h("93 00  98 00 96 81 00  94 00");
    let mut draft = Draft::open(msg).unwrap();
    let group = draft.top().next().unwrap();
    let inner = draft.children(group).unwrap().next().unwrap();
    draft.set_varint(inner, 7).unwrap();
    assert_eq!(all_saves(&draft), h("93 00 98 00 07 94 00"));
}

#[test]
fn len_prefix_fidelity_composes_under_groups() {
    // Group f2 { LEN f1 (padded prefix) "hi" }.
    let msg = h("93 00  0A 82 00 68 69  94 00");
    let mut draft = Draft::open(msg).unwrap();
    let group = draft.top().next().unwrap();
    let inner = draft.children(group).unwrap().next().unwrap();

    draft.set_payload(inner, b"no").unwrap();
    assert_eq!(all_saves(&draft), h("93 00 0A 82 00 6E 6F 94 00"), "same length keeps the prefix");

    draft.set_payload(inner, b"xyz").unwrap();
    assert_eq!(all_saves(&draft), h("93 00 0A 03 78 79 7A 94 00"), "moved length re-authors");
}

// ─── the revert oracle ───

#[test]
fn revert_all_after_any_command_prefix_restores_the_padded_source() {
    // Padded group wrapping a padded varint · LEN (padded prefix)
    // · minimal varint.
    let msg = h("93 00 18 96 81 00 94 00  12 82 00 68 69  08 2A");
    let mut draft = Draft::open(msg.clone()).unwrap();
    let tops: Vec<_> = draft.top().collect();
    let in_group = draft.children(tops[0]).unwrap().next().unwrap();

    draft.set_varint(in_group, 1).unwrap();
    draft.delete(tops[2]).unwrap();
    let group = draft.insert_group(InsertAt::After(tops[0]), f(5)).unwrap();
    draft.insert_i64(InsertAt::HeadOf(Some(group)), f(1), 0xAB).unwrap();
    draft.set_payload(tops[1], b"world").unwrap();
    assert_eq!(draft.pending(), 5);

    draft.revert_all();
    assert_eq!(draft.pending(), 0);
    assert_eq!(all_saves(&draft), msg, "revert_all restores the padded source");
}

#[test]
fn each_revert_step_restores_the_previous_save() {
    // The per-step half of the revert oracle, over group framing:
    // every command family lands once, and each revert restores
    // the previous checkpoint's bytes exactly.
    let msg = h("93 00 18 96 81 00 94 00  08 2A");
    let mut draft = Draft::open(msg).unwrap();
    let tops: Vec<_> = draft.top().collect();
    let in_group = draft.children(tops[0]).unwrap().next().unwrap();

    let mut checkpoints = Vec::new();
    checkpoints.push(all_saves(&draft));
    draft.set_varint(in_group, 7).unwrap();
    checkpoints.push(all_saves(&draft));
    draft.delete(tops[1]).unwrap();
    checkpoints.push(all_saves(&draft));
    let group = draft.insert_group(InsertAt::TailOf(None), f(5)).unwrap();
    checkpoints.push(all_saves(&draft));
    draft.insert_varint(InsertAt::HeadOf(Some(group)), f(1), 300).unwrap();
    checkpoints.push(all_saves(&draft));

    while draft.pending() > 0 {
        checkpoints.pop();
        draft.revert();
        assert_eq!(&all_saves(&draft), checkpoints.last().unwrap());
    }
}

#[test]
fn clear_edit_restores_the_padded_spelling() {
    // The whole-history clear on one record, under group framing:
    // the padded interior varint's spelling returns byte-exactly.
    let msg = h("93 00 18 96 81 00 94 00");
    let mut draft = Draft::open(msg.clone()).unwrap();
    let group = draft.top().next().unwrap();
    let inner = draft.children(group).unwrap().next().unwrap();
    draft.set_varint(inner, 7).unwrap();
    draft.clear_edit(inner).unwrap();
    assert_eq!(all_saves(&draft), msg);
}

// ─── the tenure doors ───

#[test]
fn a_refused_open_returns_the_buffer_intact() {
    let unclosed = h("0B 08 01");
    let Err((back, fault)) = Draft::open(unclosed) else {
        panic!("an unclosed group is a grammar fault")
    };
    assert!(matches!(fault, OpenFault::Wire(Fault { kind: FaultKind::GroupUnclosed { .. }, .. })));
    assert_eq!(back, h("0B 08 01"));
}

#[test]
fn into_source_releases_the_buffer_with_edits_discarded() {
    let msg = h("93 00 18 01 94 00");
    let mut draft = Draft::open(msg.clone()).unwrap();
    let group = draft.top().next().unwrap();
    let inner = draft.children(group).unwrap().next().unwrap();
    draft.set_varint(inner, 7).unwrap();
    assert_eq!(draft.source(), &msg[..]);
    assert_eq!(draft.into_source(), msg);
}

// ─── width-true geometry ───

#[test]
fn group_source_spans_report_the_stored_framing_widths() {
    let msg = h("93 00 18 01 94 00");
    let draft = Draft::open(msg).unwrap();
    let group = draft.top().next().unwrap();

    let Some(RecordSpans::Group { tag, interior, end_tag }) = draft.source_spans(group).unwrap()
    else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (0, 2), "the padded open tag's stored width");
    assert_eq!((interior.start(), interior.end()), (2, 4));
    assert_eq!((end_tag.start(), end_tag.end()), (4, 6), "the padded end tag's stored width");

    // The reverse index: interior bytes answer the inner record,
    // trailing end-tag bytes climb to the group.
    let inner = draft.children(group).unwrap().next().unwrap();
    assert_eq!(draft.narrowest(2), Some(inner));
    assert_eq!(draft.narrowest(4), Some(group), "the padded end tag belongs to the group");
    assert_eq!(draft.narrowest(5), Some(group));
    assert_eq!(draft.narrowest(6), None);
}

#[test]
fn save_spans_enclose_padded_groups_exactly() {
    let msg = h("93 00 18 01 94 00  08 2A");
    let mut draft = Draft::open(msg).unwrap();
    let tops: Vec<_> = draft.top().collect();
    let inner = draft.children(tops[0]).unwrap().next().unwrap();
    draft.set_varint(inner, 300).unwrap(); // one byte grows to two

    let saved = draft.save().unwrap();
    assert_eq!(saved, h("93 00 18 AC 02 94 00 08 2A"));
    let spans = draft.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(table.len(), 3);
    assert_eq!((table[0].1.start(), table[0].1.end()), (0, 7), "the group encloses its interior");
    assert_eq!((table[1].1.start(), table[1].1.end()), (2, 5));
    assert_eq!((table[2].1.start(), table[2].1.end()), (7, 9));
}

#[test]
fn a_machine_holding_only_an_inserted_group_walks_every_read_face() {
    // The unbacked group sentinel under tolerant admission: no
    // store column holds an entry for the inserted group's value
    // coordinate, so every read face must answer without touching
    // the payload side — the kind gates refuse the value readers,
    // the tolerant save dispatch authors framing words alone, and
    // descent projects the already-open empty layer.
    let mut d = Draft::open(Vec::new()).unwrap();
    let g = d.insert_group(InsertAt::TailOf(None), f(5)).unwrap();

    assert_eq!(d.pending(), 1);
    assert_eq!(d.top().collect::<Vec<_>>(), [g]);
    assert_eq!(d.kind(g).unwrap(), RecordKind::Group);
    assert_eq!(d.field(g).unwrap(), f(5));
    assert_eq!(d.status(g).unwrap(), EditStatus::Inserted);
    assert!(d.dirty(g).unwrap());
    assert_eq!(d.parent(g).unwrap(), None);
    assert_eq!(d.children(g).unwrap().count(), 0);
    assert_eq!(d.ancestors(g).unwrap().count(), 0);
    assert_eq!(d.span(g).unwrap(), None, "authored rows own no hex");
    assert_eq!(d.source_spans(g).unwrap(), None, "authored rows own no source geometry");
    assert_eq!(d.narrowest(0), None);

    // The kind gates hold every value reader off the group row.
    assert!(matches!(d.varint_word(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(d.i32_bits(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(d.i64_bits(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(d.payload_bytes(g), Err(EditFault::KindMismatch { .. })));

    // Group descent projects the already-open (empty) layer.
    assert!(matches!(d.descend(g).unwrap(), Descent::Opened { first: None }));

    assert_eq!(all_saves(&d), [0x2B, 0x2C]);
    let spans = d.save_spans().unwrap();
    assert_eq!(spans.iter().collect::<Vec<_>>(), [(g, Span::new(0, 2))]);

    // Revert unwinds the splice to a ghost: the saves are the
    // source again and no face dereferences the sentinel.
    assert_eq!(d.revert(), Some(g));
    assert_eq!(d.status(g).unwrap(), EditStatus::InsertedDeleted);
    assert!(all_saves(&d).is_empty());
    assert_eq!(d.save_spans().unwrap().iter().count(), 0);
}

#[test]
fn a_borrowed_machine_holding_only_an_inserted_group_walks_every_read_face() {
    // The tolerant borrowed twin: the payload store is the borrowed
    // slot table with zero slots, so a value read that ever reached
    // it would be an out-of-bounds slot access — the kind gates,
    // the borrowed descent arm, and the tolerant save dispatch must
    // never ask the payload side.
    let mut d = BorrowDraft::open_copy(&[]).unwrap();
    let g = d.insert_group(InsertAt::TailOf(None), f(5)).unwrap();

    assert_eq!(d.pending(), 1);
    assert_eq!(d.top().collect::<Vec<_>>(), [g]);
    assert_eq!(d.kind(g).unwrap(), RecordKind::Group);
    assert_eq!(d.field(g).unwrap(), f(5));
    assert_eq!(d.status(g).unwrap(), EditStatus::Inserted);
    assert!(d.dirty(g).unwrap());
    assert_eq!(d.parent(g).unwrap(), None);
    assert_eq!(d.children(g).unwrap().count(), 0);
    assert_eq!(d.ancestors(g).unwrap().count(), 0);
    assert_eq!(d.span(g).unwrap(), None, "authored rows own no hex");
    assert_eq!(d.source_spans(g).unwrap(), None, "authored rows own no source geometry");
    assert_eq!(d.narrowest(0), None);

    // The kind gates hold every value reader off the group row.
    assert!(matches!(d.varint_word(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(d.i32_bits(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(d.i64_bits(g), Err(EditFault::KindMismatch { .. })));
    assert!(matches!(d.payload_bytes(g), Err(EditFault::KindMismatch { .. })));

    // Group descent projects the already-open (empty) layer.
    assert!(matches!(d.descend(g).unwrap(), Descent::Opened { first: None }));

    assert_eq!(d.save_len().unwrap(), 2);
    assert_eq!(d.save().unwrap(), [0x2B, 0x2C]);
    let mut streamed = Vec::new();
    d.save_sink(|slice| streamed.extend_from_slice(slice)).unwrap();
    assert_eq!(streamed, [0x2B, 0x2C]);
    let spans = d.save_spans().unwrap();
    assert_eq!(spans.iter().collect::<Vec<_>>(), [(g, Span::new(0, 2))]);

    // Revert unwinds the splice to a ghost: the saves are the
    // source again and no face dereferences the sentinel.
    assert_eq!(d.revert(), Some(g));
    assert_eq!(d.status(g).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(d.save_len().unwrap(), 0);
    assert!(d.save().unwrap().is_empty());
    assert_eq!(d.save_spans().unwrap().iter().count(), 0);
}

// ─── the staged payload doors ───

#[test]
fn both_payload_door_families_stage_under_padded_framing() {
    let msg = h("12 82 00 68 69");
    let mut draft = Draft::open(msg.clone()).unwrap();
    let record = draft.top().next().unwrap();

    let mut frame = draft.begin_set_payload(record).unwrap();
    frame.write(b"ab").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&draft), h("12 82 00 61 62"));

    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        draft.begin_set_payload_sized(record, over).map(|_| ()),
        Err(EditFault::PayloadTooLarge { len }) if len == over
    ));

    let mut frame = draft.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), 2).unwrap();
    frame.write(b"ok").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&draft), h("12 82 00 61 62 1A 02 6F 6B"));

    draft.revert_all();
    assert_eq!(all_saves(&draft), msg);
}

#[test]
fn the_sized_frame_holds_its_declaration() {
    // The declaration enforcement rows, on this dialect's own
    // emitted machine: over-declaration refuses per write,
    // under-declaration refuses the finish, and either failure
    // installs nothing.
    let msg = h("93 00 12 02 68 69 94 00");
    let mut draft = Draft::open(msg).unwrap();
    let group = draft.top().next().unwrap();
    let inner = draft.children(group).unwrap().next().unwrap();

    let mut frame = draft.begin_set_payload_sized(inner, 2).unwrap();
    assert!(matches!(frame.write(b"abc"), Err(FrameFault::OverDeclared { declared: 2, total: 3 })));
    frame.write(b"a").unwrap();
    assert!(matches!(frame.finish(), Err(FrameFault::UnderDeclared { declared: 2, staged: 1 })));
    assert_eq!(draft.pending(), 0, "a failed frame installs nothing");

    let mut frame =
        draft.begin_insert_payload_sized(InsertAt::TailOf(Some(group)), f(3), 2).unwrap();
    frame.write(b"ok").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&draft), h("93 00 12 02 68 69 1A 02 6F 6B 94 00"));
}

// ─── re-ingestion of authored payload interiors ───

#[test]
fn descend_into_a_padded_authored_payload_is_tolerant_and_browse_only() {
    let msg = h("12 00");
    let mut draft = Draft::open(msg).unwrap();
    let record = draft.top().next().unwrap();
    // The authored payload's interior is itself padded wire —
    // group framing included: tolerant admission commits it.
    draft.set_payload(record, &h("93 00 18 96 81 00 94 00")).unwrap();
    let Descent::Opened { first: Some(group) } = draft.descend(record).unwrap() else {
        unreachable!()
    };
    let inner = draft.children(group).unwrap().next().unwrap();
    assert_eq!(draft.varint_word(inner).unwrap(), 150);
    assert!(matches!(draft.set_varint(inner, 1), Err(EditFault::InsideAuthoredBody)));
    assert_eq!(draft.span(inner).unwrap(), None, "authored rows own no hex");
}

#[test]
fn a_deep_closure_designates_with_its_exact_depth() {
    // 65,536 nested groups — past the sixteen-bit edge on a host
    // with no depth bound — built arithmetically: 128 KiB of
    // one-byte group tags.
    let mut bytes = alloc::vec![0x0B; 65_536];
    bytes.extend_from_slice(&alloc::vec![0x0C; 65_536]);
    let draft = Draft::open(bytes.clone()).unwrap();
    let top = draft.top().next().unwrap();
    let record = draft.record_ref(top).unwrap();
    assert_eq!(record.group_depth(), 65_536);
    assert_eq!(record.as_bytes(), bytes);
}

// ─── the borrowed-payload sibling, in lockstep with the copy-only
// draft: the same command script must leave both machines with
// byte-identical saves — the fidelity reading included — and equal
// log depths at every step ───

/// The copy-only draft and its borrowed-payload sibling over the
/// same padded document, driven command by command.
struct Twins<'p> {
    copy: Draft,
    borrow: BorrowDraft<'p>,
}

impl<'p> Twins<'p> {
    #[track_caller]
    fn open(data: &[u8]) -> Self {
        Self {
            copy: Draft::open_copy(data).expect("twin document opens"),
            borrow: BorrowDraft::open_copy(data).expect("twin document opens"),
        }
    }

    /// Applies one command to each twin and pins the observable
    /// agreement: byte-identical saves, equal prices, equal log
    /// depths.
    #[track_caller]
    fn lockstep(
        &mut self,
        copy_cmd: impl FnOnce(&mut Draft),
        borrow_cmd: impl FnOnce(&mut BorrowDraft<'p>),
    ) {
        copy_cmd(&mut self.copy);
        borrow_cmd(&mut self.borrow);
        let a = self.copy.save().expect("copy twin saves");
        let b = self.borrow.save().expect("borrow twin saves");
        assert_eq!(a, b, "the twins' saves diverged");
        assert_eq!(self.copy.save_len().unwrap(), self.borrow.save_len().unwrap());
        assert_eq!(self.copy.pending(), self.borrow.pending(), "log depths diverged");
    }
}

#[test]
fn borrowed_installs_keep_the_fidelity_reading_in_lockstep() {
    // A padded group wrapping a padded varint · LEN f2 "a" with a
    // padded prefix: the framing facts the fidelity save must
    // reproduce around a borrowed install.
    let doc = h("93 00 18 96 81 00 94 00 12 81 00 61");
    let same_len = h("7A");
    let longer = h("08 07");
    let mut t = Twins::open(&doc);
    // A same-length replacement keeps the padded prefix verbatim.
    t.lockstep(
        |s| {
            let r = s.top().nth(1).unwrap();
            s.set_payload(r, &same_len).unwrap();
        },
        |s| {
            let r = s.top().nth(1).unwrap();
            s.set_payload(r, &same_len).unwrap();
        },
    );
    assert_eq!(t.borrow.save().unwrap(), h("93 00 18 96 81 00 94 00 12 81 00 7A"));
    // A longer replacement re-authors the prefix minimally; the
    // padded group framing still rides verbatim.
    t.lockstep(
        |s| {
            let r = s.top().nth(1).unwrap();
            s.set_payload(r, &longer).unwrap();
        },
        |s| {
            let r = s.top().nth(1).unwrap();
            s.set_payload(r, &longer).unwrap();
        },
    );
    assert_eq!(t.borrow.save().unwrap(), h("93 00 18 96 81 00 94 00 12 02 08 07"));
    // Undo restores the earlier install, then the padded source,
    // byte-exactly.
    t.lockstep(
        |s| {
            s.revert();
        },
        |s| {
            s.revert();
        },
    );
    assert_eq!(t.borrow.save().unwrap(), h("93 00 18 96 81 00 94 00 12 81 00 7A"));
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.borrow.save().unwrap(), doc);
}

#[test]
fn delete_undelete_clear_and_births_ride_borrowed_installs_in_lockstep() {
    let doc = h("12 81 00 61 08 96 01");
    let alpha = h("08 2A");
    let body = h("08 01");
    let mut t = Twins::open(&doc);
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
    let r = t.borrow.top().next().unwrap();
    assert_eq!(t.borrow.status(r).unwrap(), EditStatus::Replaced);
    assert_eq!(t.borrow.payload_bytes(r).unwrap(), alpha);
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
            s.insert_payload(InsertAt::TailOf(None), f(3), &body).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &body).unwrap();
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
    let ghost = t.borrow.top().last().unwrap();
    assert_eq!(t.borrow.status(ghost).unwrap(), EditStatus::InsertedDeleted);
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.borrow.save().unwrap(), doc);
}

#[test]
fn descents_agree_before_and_after_each_backing_flip() {
    // LEN f2 with a padded prefix wrapping varint f1=1.
    let doc = h("12 82 00 08 01");
    // An authored payload whose padded interior nests a group: the
    // borrowed twin's slot witness climbs through the group layer
    // at the widths the authored scan met.
    let nested = h("0B 08 96 81 00 0C");
    let mut t = Twins::open(&doc);
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
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
            let r = s.top().next().unwrap();
            s.set_payload(r, &nested).unwrap();
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
        let rc = t.copy.top().next().unwrap();
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
    assert_eq!(t.copy.varint_word(copy_leaf).unwrap(), 150);
    assert_eq!(t.borrow.varint_word(borrow_leaf).unwrap(), 150);
    assert!(matches!(t.borrow.set_varint(borrow_leaf, 9), Err(EditFault::InsideAuthoredBody)));
    // Flip back to the source: the authored tree orphans whole,
    // and the re-descended interior is source-backed again.
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
    assert!(matches!(t.borrow.varint_word(borrow_leaf), Err(EditFault::DeadHandle)));
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            assert!(matches!(s.descend(r).unwrap(), Descent::Opened { .. }));
        },
        |s| {
            let r = s.top().next().unwrap();
            assert!(matches!(s.descend(r).unwrap(), Descent::Opened { .. }));
        },
    );
    assert_eq!(t.borrow.save().unwrap(), doc);
}

#[test]
fn the_borrowed_draft_releases_its_source_and_hands_slices_through() {
    let doc = h("12 81 00 61");
    let alpha = h("08 2A");
    let mut s = BorrowDraft::open(doc.clone()).unwrap();
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
    assert_eq!(streamed, s.save().unwrap());
    // The move door's inverse gives the padded buffer back whole.
    assert_eq!(s.into_source(), doc);
}

// ─── the mixed-backing sibling: lockstep twins in both drives and
// the interleaved history on one log — the arcs run inside and
// beside groups, padded framing included ───

/// The mixed draft driven borrow-only beside the borrowed-only
/// sibling: byte-identical fidelity saves, equal prices, and equal
/// log depths at every step.
struct MixBorrowDrive<'p> {
    mix: MixDraft<'p>,
    borrow: BorrowDraft<'p>,
}

impl<'p> MixBorrowDrive<'p> {
    #[track_caller]
    fn open(data: &[u8]) -> Self {
        Self {
            mix: MixDraft::open_copy(data).expect("twin document opens"),
            borrow: BorrowDraft::open_copy(data).expect("twin document opens"),
        }
    }

    #[track_caller]
    fn lockstep(
        &mut self,
        mix_cmd: impl FnOnce(&mut MixDraft<'p>),
        borrow_cmd: impl FnOnce(&mut BorrowDraft<'p>),
    ) {
        mix_cmd(&mut self.mix);
        borrow_cmd(&mut self.borrow);
        let a = self.mix.save().expect("mix twin saves");
        let b = self.borrow.save().expect("borrow twin saves");
        assert_eq!(a, b, "the twins' saves diverged");
        assert_eq!(self.mix.save_len().unwrap(), self.borrow.save_len().unwrap());
        assert_eq!(self.mix.pending(), self.borrow.pending(), "log depths diverged");
    }
}

/// The mixed draft driven copy-only beside the copy-only base
/// machine, compared the same way.
struct MixCopyDrive {
    mix: MixDraft<'static>,
    copy: Draft,
}

impl MixCopyDrive {
    #[track_caller]
    fn open(data: &[u8]) -> Self {
        Self {
            mix: MixDraft::open_copy(data).expect("twin document opens"),
            copy: Draft::open_copy(data).expect("twin document opens"),
        }
    }

    #[track_caller]
    fn lockstep(
        &mut self,
        mix_cmd: impl FnOnce(&mut MixDraft<'static>),
        copy_cmd: impl FnOnce(&mut Draft),
    ) {
        mix_cmd(&mut self.mix);
        copy_cmd(&mut self.copy);
        let a = self.mix.save().expect("mix twin saves");
        let b = self.copy.save().expect("copy twin saves");
        assert_eq!(a, b, "the twins' saves diverged");
        assert_eq!(self.mix.save_len().unwrap(), self.copy.save_len().unwrap());
        assert_eq!(self.mix.pending(), self.copy.pending(), "log depths diverged");
    }
}

#[test]
fn mix_borrow_drive_keeps_the_fidelity_reading_around_groups() {
    // group f1 { LEN f2 "a", padded prefix } · varint f1=150
    // (value padded): the arcs land inside and beside the group.
    let doc = h("0B 12 81 00 61 0C 08 96 81 00");
    let alpha = h("08 01");
    let mut t = MixBorrowDrive::open(&doc);
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
    t.lockstep(
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &alpha).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &alpha).unwrap();
        },
    );
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap(), doc, "the padded source rides back verbatim");
}

#[test]
fn mix_copy_drive_tracks_the_copy_only_draft_around_groups() {
    let doc = h("0B 12 81 00 61 0C 08 96 81 00");
    let alpha = h("08 01");
    let mut t = MixCopyDrive::open(&doc);
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
            let group = s.top().next().unwrap();
            let inner = s.children(group).unwrap().next().unwrap();
            let mut frame = s.begin_set_payload_sized(inner, 2).unwrap();
            frame.write(b"ok").unwrap();
            frame.finish().unwrap();
        },
        |s| {
            let group = s.top().next().unwrap();
            let inner = s.children(group).unwrap().next().unwrap();
            let mut frame = s.begin_set_payload_sized(inner, 2).unwrap();
            frame.write(b"ok").unwrap();
            frame.finish().unwrap();
        },
    );
    t.lockstep(
        |s| {
            s.insert_payload_copy(InsertAt::TailOf(None), f(3), &alpha).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &alpha).unwrap();
        },
    );
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap(), doc);
}

#[test]
fn mix_interleaved_history_and_flips_run_inside_a_group() {
    // group f1 { LEN f2 "a", padded prefix }: the arc runs on a row
    // inside the group's layer and restores the padding at the end.
    let doc = h("0B 12 81 00 61 0C");
    let alpha = h("08 01");
    let charlie = h("08 05");
    let mut s = MixDraft::open_copy(&doc).unwrap();
    let group = s.top().next().unwrap();
    let r = s.children(group).unwrap().next().unwrap();
    s.set_payload(r, &alpha).unwrap();
    {
        let transient = h("08 07");
        s.set_payload_copy(r, &transient).unwrap();
    }
    s.set_payload(r, &charlie).unwrap();
    assert_eq!(s.pending(), 3, "three installs, one log");
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), h("08 07"), "the copied install restores");
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), alpha, "the borrowed install restores");
    // Flip to a borrowed interior holding a group closure and
    // descend through it; then flip to a copied one.
    let nested = h("0B 08 07 0C");
    s.set_payload(r, &nested).unwrap();
    let Descent::Opened { first: Some(inner_group) } = s.descend(r).unwrap() else {
        panic!("borrowed interior opens")
    };
    let leaf = s.children(inner_group).unwrap().next().unwrap();
    assert_eq!(s.varint_word(leaf).unwrap(), 7, "the borrowed slot's group interior reads");
    {
        let transient = h("08 63");
        s.set_payload_copy(r, &transient).unwrap();
    }
    assert!(matches!(s.varint_word(leaf), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(copied) } = s.descend(r).unwrap() else {
        panic!("copied interior opens")
    };
    assert_eq!(s.varint_word(copied).unwrap(), 99, "the copied extent scans slot-local");
    s.revert_all();
    assert_eq!(s.save().unwrap(), doc, "the padded source rides back verbatim");
}

#[test]
fn mix_descents_reach_the_right_provenance_over_each_flip() {
    // LEN f2 wrapping varint f1=1, beside a group.
    let doc = h("12 02 08 01 0B 0C");
    // A nested payload whose interior holds a group closure.
    let nested = h("12 04 0B 08 07 0C");
    let mut s = MixDraft::open_copy(&doc).unwrap();
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
    assert_eq!(s.save().unwrap(), doc);
}
