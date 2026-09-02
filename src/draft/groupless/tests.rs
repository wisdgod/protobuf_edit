//! Contract pins for the groupless draft: tolerant admission,
//! width-true geometry, the fidelity save, exact revision, and the
//! tenure doors.

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
    let mut into = h("BEEF");
    draft.save_into(&mut into).expect("save_into succeeds");
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    draft.save_sink(|chunk| streamed.extend_from_slice(chunk)).expect("save_sink succeeds");
    assert_eq!(streamed, saved, "the sink concatenation is the save");
    saved
}

// ─── tolerant admission and the fidelity save ───

#[test]
fn padded_framing_admits_and_rides_saves_verbatim() {
    // Padded tag [88 00] · padded value [96 81 00] · LEN f2 with a
    // padded two-byte prefix.
    let msg = h("88 00 96 81 00  12 82 00 68 69");
    let draft = Draft::open(msg.clone()).unwrap();
    let tops: Vec<_> = draft.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(draft.varint_word(tops[0]).unwrap(), 150);
    assert_eq!(draft.payload_bytes(tops[1]).unwrap(), *b"hi");
    assert_eq!(all_saves(&draft), msg, "an untouched draft saves its padded source");
}

#[test]
fn a_replaced_scalar_keeps_its_padded_tag_and_reauthors_its_value() {
    // Padded tag, padded value: the tag is an input fact, the
    // value is the command's to re-author minimally.
    let msg = h("88 00 96 81 00");
    let mut draft = Draft::open(msg).unwrap();
    let record = draft.top().next().unwrap();
    draft.set_varint(record, 7).unwrap();
    assert_eq!(all_saves(&draft), h("88 00 07"));
}

#[test]
fn a_same_length_payload_keeps_its_padded_prefix() {
    let msg = h("12 82 00 68 69");
    let mut draft = Draft::open(msg).unwrap();
    let record = draft.top().next().unwrap();

    draft.set_payload(record, b"no").unwrap();
    assert_eq!(all_saves(&draft), h("12 82 00 6E 6F"), "same length: the padded prefix rides");

    draft.set_payload(record, b"xyz").unwrap();
    assert_eq!(all_saves(&draft), h("12 03 78 79 7A"), "moved length: minimal re-author");
}

#[test]
fn interior_edits_keep_the_padded_len_framing_while_the_length_holds() {
    // LEN f2 (padded prefix) wrapping varint f1=1.
    let msg = h("12 82 00 08 01");
    let mut draft = Draft::open(msg).unwrap();
    let container = draft.top().next().unwrap();
    let Descent::Opened { first: Some(inner) } = draft.descend(container).unwrap() else {
        unreachable!()
    };

    draft.set_varint(inner, 7).unwrap();
    assert_eq!(all_saves(&draft), h("12 82 00 08 07"), "unchanged body length keeps the prefix");

    draft.set_varint(inner, 300).unwrap();
    assert_eq!(all_saves(&draft), h("12 03 08 AC 02"), "a grown body re-authors the prefix");
}

#[test]
fn deletion_and_insertion_compose_with_padding() {
    // Padded varint · minimal varint f2=42.
    let msg = h("88 00 96 81 00 10 2A");
    let mut draft = Draft::open(msg).unwrap();
    let tops: Vec<_> = draft.top().collect();
    draft.delete(tops[1]).unwrap();
    draft.insert_varint(InsertAt::TailOf(None), f(3), 1).unwrap();
    assert_eq!(all_saves(&draft), h("88 00 96 81 00 18 01"));

    draft.undelete(tops[1]).unwrap();
    assert_eq!(all_saves(&draft), h("88 00 96 81 00 10 2A 18 01"));
}

#[test]
fn clear_edit_restores_the_padded_spelling() {
    let msg = h("88 00 96 81 00");
    let mut draft = Draft::open(msg.clone()).unwrap();
    let record = draft.top().next().unwrap();
    draft.set_varint(record, 7).unwrap();
    draft.clear_edit(record).unwrap();
    assert_eq!(all_saves(&draft), msg);
}

// ─── the revert oracle ───

#[test]
fn revert_all_after_any_command_prefix_restores_the_padded_source() {
    // Padded tag varint · LEN (padded prefix) wrapping a padded
    // varint · minimal varint.
    let msg = h("88 00 96 81 00  12 84 00 08 96 81 00  10 2A");
    let mut draft = Draft::open(msg.clone()).unwrap();
    let tops: Vec<_> = draft.top().collect();

    // A compound arc across every command family.
    draft.set_varint(tops[0], 7).unwrap();
    let Descent::Opened { first: Some(inner) } = draft.descend(tops[1]).unwrap() else {
        unreachable!()
    };
    draft.set_varint(inner, 1).unwrap();
    draft.delete(tops[2]).unwrap();
    let fresh = draft.insert_payload(InsertAt::TailOf(None), f(4), b"zz").unwrap();
    let mut frame = draft.begin_set_payload(fresh).unwrap();
    frame.write(b"ab").unwrap();
    frame.finish().unwrap();
    assert_eq!(draft.pending(), 5);

    // Every prefix of the revert unwinds exactly; the full unwind
    // is byte fidelity, padding included.
    draft.revert_all();
    assert_eq!(draft.pending(), 0);
    assert_eq!(all_saves(&draft), msg, "revert_all restores the padded source");
}

#[test]
fn each_revert_step_restores_the_previous_save() {
    let msg = h("88 00 96 81 00 10 2A");
    let mut draft = Draft::open(msg).unwrap();
    let tops: Vec<_> = draft.top().collect();

    let mut checkpoints = Vec::new();
    checkpoints.push(all_saves(&draft));
    draft.set_varint(tops[0], 7).unwrap();
    checkpoints.push(all_saves(&draft));
    draft.delete(tops[1]).unwrap();
    checkpoints.push(all_saves(&draft));
    draft.insert_varint(InsertAt::HeadOf(None), f(5), 300).unwrap();
    checkpoints.push(all_saves(&draft));

    while draft.pending() > 0 {
        checkpoints.pop();
        draft.revert();
        assert_eq!(&all_saves(&draft), checkpoints.last().unwrap());
    }
}

// ─── the tenure doors ───

#[test]
fn a_refused_open_returns_the_buffer_intact() {
    // A group code: lawful wire outside this dialect's language.
    let group = h("0B 0C");
    let Err((back, fault)) = Draft::open(group) else {
        panic!("group codes refuse under the groupless dialect")
    };
    assert!(matches!(fault, OpenFault::Refused(Refusal::GroupCode { at: 0, .. })));
    assert_eq!(back, h("0B 0C"));

    // A grammar fault returns it too.
    let zero = h("00");
    let Err((back, fault)) = Draft::open(zero) else { panic!("field zero is a grammar fault") };
    assert!(matches!(fault, OpenFault::Wire(Fault { at: 0, kind: FaultKind::FieldZero })));
    assert_eq!(back, h("00"));
}

#[test]
fn into_source_releases_the_buffer_with_edits_discarded() {
    let msg = h("88 00 96 81 00");
    let mut draft = Draft::open(msg.clone()).unwrap();
    let record = draft.top().next().unwrap();
    draft.set_varint(record, 7).unwrap();
    assert_eq!(draft.source(), &msg[..]);
    assert_eq!(draft.into_source(), msg);
}

#[test]
fn saves_reopen_through_the_move_door() {
    let msg = h("88 00 96 81 00 10 2A");
    let mut draft = Draft::open(msg).unwrap();
    let tops: Vec<_> = draft.top().collect();
    draft.set_varint(tops[1], 7).unwrap();

    let mut next = Draft::open(draft.save().unwrap()).unwrap();
    let tops: Vec<_> = next.top().collect();
    assert_eq!(next.varint_word(tops[0]).unwrap(), 150, "the padded record re-reads");
    next.set_varint(tops[1], 8).unwrap();
    assert_eq!(next.save().unwrap(), h("88 00 96 81 00 10 08"));
}

// ─── width-true geometry ───

#[test]
fn source_spans_and_narrowest_answer_at_the_scanned_widths() {
    // Padded tag varint at 0..5 · LEN (padded prefix) at 5..10.
    let msg = h("88 00 96 81 00  12 82 00 68 69");
    let draft = Draft::open(msg).unwrap();
    let tops: Vec<_> = draft.top().collect();

    let Some(RecordSpans::Varint { tag, value }) = draft.source_spans(tops[0]).unwrap() else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (0, 2), "the padded tag's stored width");
    assert_eq!((value.start(), value.end()), (2, 5), "the padded value's scanned extent");

    let Some(RecordSpans::Len { tag, prefix, payload }) = draft.source_spans(tops[1]).unwrap()
    else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (5, 6));
    assert_eq!((prefix.start(), prefix.end()), (6, 8), "the padded prefix's stored width");
    assert_eq!((payload.start(), payload.end()), (8, 10));

    // The reverse index covers every padded byte.
    for pos in 0..5 {
        assert_eq!(draft.narrowest(pos), Some(tops[0]), "byte {pos}");
    }
    for pos in 5..10 {
        assert_eq!(draft.narrowest(pos), Some(tops[1]), "byte {pos}");
    }
    assert_eq!(draft.narrowest(10), None);
}

#[test]
fn save_spans_price_the_fidelity_save() {
    let msg = h("88 00 96 81 00  12 82 00 68 69  10 2A");
    let mut draft = Draft::open(msg).unwrap();
    let tops: Vec<_> = draft.top().collect();
    draft.set_varint(tops[2], 300).unwrap();

    let saved = draft.save().unwrap();
    let spans = draft.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(table.len(), 3);
    // The untouched padded records keep their extents; the edited
    // one re-prices.
    assert_eq!((table[0].1.start(), table[0].1.end()), (0, 5));
    assert_eq!((table[1].1.start(), table[1].1.end()), (5, 10));
    assert_eq!((table[2].1.start(), table[2].1.end()), (10, 13));
    assert_eq!(table[2].1.end() as usize, saved.len(), "the last span ends the save");
}

// ─── the staged payload doors ───

#[test]
fn the_undeclared_frame_stages_and_installs_once() {
    let msg = h("12 82 00 68 69");
    let mut draft = Draft::open(msg.clone()).unwrap();
    let record = draft.top().next().unwrap();

    let mut frame = draft.begin_set_payload(record).unwrap();
    frame.write(b"a").unwrap();
    frame.write(b"b").unwrap();
    frame.finish().unwrap();
    assert_eq!(draft.pending(), 1, "one logged transition per frame");
    assert_eq!(all_saves(&draft), h("12 82 00 61 62"), "two staged bytes keep the padded prefix");

    draft.revert();
    assert_eq!(all_saves(&draft), msg);
}

#[test]
fn the_sized_doors_judge_oversize_declarations_before_reserving() {
    let msg = h("12 82 00 68 69");
    let mut draft = Draft::open(msg).unwrap();
    let record = draft.top().next().unwrap();

    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        draft.begin_set_payload_sized(record, over).map(|_| ()),
        Err(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert!(matches!(
        draft.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), over).map(|_| ()),
        Err(EditFault::PayloadTooLarge { len }) if len == over
    ));
    assert_eq!(draft.pending(), 0, "refused declarations change nothing");
}

#[test]
fn the_sized_frame_holds_its_declaration() {
    let msg = h("12 82 00 68 69");
    let mut draft = Draft::open(msg).unwrap();
    let record = draft.top().next().unwrap();

    let mut frame = draft.begin_set_payload_sized(record, 2).unwrap();
    assert!(matches!(frame.write(b"abc"), Err(FrameFault::OverDeclared { declared: 2, total: 3 })));
    frame.write(b"a").unwrap();
    assert!(matches!(frame.finish(), Err(FrameFault::UnderDeclared { declared: 2, staged: 1 })));
    assert_eq!(draft.pending(), 0, "a failed frame installs nothing");

    let mut frame = draft.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), 2).unwrap();
    frame.write(b"ok").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&draft), h("12 82 00 68 69 1A 02 6F 6B"));
}

// ─── re-ingestion of authored payload interiors ───

#[test]
fn descend_into_a_padded_authored_payload_is_tolerant_and_browse_only() {
    let msg = h("12 00");
    let mut draft = Draft::open(msg).unwrap();
    let record = draft.top().next().unwrap();
    // The authored payload's interior is itself padded wire:
    // tolerant admission commits it.
    draft.set_payload(record, &h("88 00 96 81 00")).unwrap();
    let Descent::Opened { first: Some(inner) } = draft.descend(record).unwrap() else {
        unreachable!()
    };
    assert_eq!(draft.varint_word(inner).unwrap(), 150);
    assert!(matches!(draft.set_varint(inner, 1), Err(EditFault::InsideAuthoredBody)));
    assert_eq!(draft.span(inner).unwrap(), None, "authored rows own no hex");
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
    // varint f1=150 (value padded) · LEN f2 "a" with a padded
    // prefix: the framing facts the fidelity save must reproduce.
    let doc = h("08 96 81 00 12 81 00 61");
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
    assert_eq!(t.borrow.save().unwrap(), h("08 96 81 00 12 81 00 7A"));
    // A longer replacement re-authors the prefix minimally; the
    // padded varint still rides verbatim.
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
    assert_eq!(t.borrow.save().unwrap(), h("08 96 81 00 12 02 08 07"));
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
    assert_eq!(t.borrow.save().unwrap(), h("08 96 81 00 12 81 00 7A"));
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
    // Shroud and restore around the borrowed replacement.
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
    // Clearing restores the scanned state — the padded spelling
    // included.
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
    // An insertion's birth reverts to a ghost.
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
    // Everything unwound: the padded source rides back verbatim.
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.borrow.save().unwrap(), doc);
}

#[test]
fn descents_agree_before_and_after_each_backing_flip() {
    // LEN f2 with a padded prefix wrapping varint f1=1.
    let doc = h("12 82 00 08 01");
    // A nested authored payload, itself padded wire: LEN f2 with a
    // padded prefix wrapping a padded varint.
    let nested = h("12 84 00 08 96 81 00");
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
    // Both descend the authored zone; the borrowed twin reads the
    // slot through the ancestor witness at depth one and two, at
    // the padded widths the authored scan met.
    let (copy_inner, borrow_inner) = {
        let rc = t.copy.top().next().unwrap();
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
    assert!(matches!(t.borrow.payload_bytes(borrow_inner), Err(EditFault::DeadHandle)));
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
// the interleaved history on one log, padded framing included ───

/// The mixed draft driven borrow-only beside the borrowed-only
/// sibling: byte-identical fidelity saves, equal prices, equal span
/// tables, and equal log depths at every step.
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
        let spans_a: Vec<_> =
            self.mix.save_spans().unwrap().iter().map(|(_, s)| (s.start(), s.end())).collect();
        let spans_b: Vec<_> =
            self.borrow.save_spans().unwrap().iter().map(|(_, s)| (s.start(), s.end())).collect();
        assert_eq!(spans_a, spans_b, "the twins' span tables diverged");
        assert_eq!(self.mix.pending(), self.borrow.pending(), "log depths diverged");
    }
}

/// The mixed draft driven copy-only beside the copy-only base
/// machine: the `_copy` faces and frame doors against the base's
/// unsuffixed faces and frames, compared the same way.
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
fn mix_borrow_drive_keeps_the_fidelity_reading_in_lockstep() {
    // varint f1=150 (value padded) · LEN f2 "a" with a padded
    // prefix: the framing facts the fidelity save must reproduce.
    let doc = h("08 96 81 00 12 81 00 61");
    let same_len = h("7A");
    let longer = h("08 07");
    let mut t = MixBorrowDrive::open(&doc);
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
    assert_eq!(t.mix.save().unwrap(), h("08 96 81 00 12 81 00 7A"), "same length keeps the prefix");
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
    t.lockstep(
        |s| {
            let r = s.top().nth(1).unwrap();
            s.delete(r).unwrap();
        },
        |s| {
            let r = s.top().nth(1).unwrap();
            s.delete(r).unwrap();
        },
    );
    t.lockstep(
        |s| {
            let r = s.top().nth(1).unwrap();
            s.undelete(r).unwrap();
        },
        |s| {
            let r = s.top().nth(1).unwrap();
            s.undelete(r).unwrap();
        },
    );
    t.lockstep(
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &same_len).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &same_len).unwrap();
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
    assert_eq!(t.mix.save().unwrap(), doc, "the padded source rides back verbatim");
}

#[test]
fn mix_copy_drive_tracks_the_copy_only_draft() {
    let doc = h("08 96 81 00 12 81 00 61");
    let alpha = h("08 01");
    let mut t = MixCopyDrive::open(&doc);
    t.lockstep(
        |s| {
            let r = s.top().nth(1).unwrap();
            s.set_payload_copy(r, &alpha).unwrap();
        },
        |s| {
            let r = s.top().nth(1).unwrap();
            s.set_payload(r, &alpha).unwrap();
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
    // The undeclared frame and a sized door, chunk for chunk.
    t.lockstep(
        |s| {
            let r = s.top().nth(1).unwrap();
            let mut frame = s.begin_set_payload(r).unwrap();
            frame.write(b"a").unwrap();
            frame.write(b"b").unwrap();
            frame.finish().unwrap();
        },
        |s| {
            let r = s.top().nth(1).unwrap();
            let mut frame = s.begin_set_payload(r).unwrap();
            frame.write(b"a").unwrap();
            frame.write(b"b").unwrap();
            frame.finish().unwrap();
        },
    );
    t.lockstep(
        |s| {
            let mut frame = s.begin_insert_payload_sized(InsertAt::TailOf(None), f(4), 2).unwrap();
            frame.write(b"ok").unwrap();
            frame.finish().unwrap();
        },
        |s| {
            let mut frame = s.begin_insert_payload_sized(InsertAt::TailOf(None), f(4), 2).unwrap();
            frame.write(b"ok").unwrap();
            frame.finish().unwrap();
        },
    );
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap(), doc);
}

#[test]
fn mix_interleaved_history_and_flips_ride_the_padded_source() {
    // LEN f2 with a padded prefix: the interleaved arc must restore
    // the padded spelling at the end.
    let doc = h("12 81 00 61");
    let alpha = h("08 01");
    let charlie = h("08 05");
    // A nested authored payload, itself padded wire.
    let nested = h("12 84 00 08 96 81 00");
    let mut s = MixDraft::open_copy(&doc).unwrap();
    let r = s.top().next().unwrap();
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
    // Flip to a padded borrowed interior and descend through it.
    s.set_payload(r, &nested).unwrap();
    let Descent::Opened { first: Some(inner) } = s.descend(r).unwrap() else {
        panic!("borrowed interior opens")
    };
    assert_eq!(s.payload_bytes(inner).unwrap(), h("08 96 81 00"), "tolerant slot-local scan");
    // Flip to a copied interior: the old tree orphans whole.
    {
        let transient = h("12 81 00 63");
        s.set_payload_copy(r, &transient).unwrap();
    }
    assert!(matches!(s.payload_bytes(inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(copied) } = s.descend(r).unwrap() else {
        panic!("copied interior opens")
    };
    assert_eq!(s.payload_bytes(copied).unwrap(), h("63"), "padded copied scan is slot-local");
    // Every save face answers the same bytes mid-history.
    let saved = s.save().unwrap();
    let mut into = h("BEEF");
    s.save_into(&mut into).unwrap();
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    s.save_sink(|chunk| streamed.extend_from_slice(chunk)).unwrap();
    assert_eq!(streamed, saved, "the sink concatenation is the save");
    s.revert_all();
    assert_eq!(s.save().unwrap(), doc, "the padded source rides back verbatim");
}

#[test]
fn mix_descents_reach_the_right_provenance_over_each_flip() {
    // LEN f2 wrapping varint f1=1.
    let doc = h("12 02 08 01");
    // A nested borrowed payload: LEN f2 wrapping varint f1=7.
    let nested = h("12 02 08 07");
    let mut s = MixDraft::open_copy(&doc).unwrap();
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
    assert_eq!(s.save().unwrap(), doc);
}
