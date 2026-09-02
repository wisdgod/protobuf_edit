//! Contract pins for the grouped markup: tolerant admission with
//! group framing widths, the fidelity save, exact revision, and
//! the borrow door.

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

/// Every output face of one markup, cross-checked: `save`,
/// `save_into`, `save_sink` concatenation, and `save_len` all
/// answer the same bytes.
#[track_caller]
fn all_saves(markup: &Markup<'_>) -> Vec<u8> {
    let saved = markup.save().expect("save succeeds");
    assert_eq!(
        markup.save_len().expect("save_len succeeds") as usize,
        saved.len(),
        "save_len prices the save"
    );
    let mut into = h("DEAD");
    markup.save_into(&mut into).expect("save_into succeeds");
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    markup.save_sink(|chunk| streamed.extend_from_slice(chunk)).expect("save_sink succeeds");
    assert_eq!(streamed, saved, "the sink concatenation is the save");
    saved
}

// ─── tolerant admission and group framing widths ───

#[test]
fn padded_group_framing_admits_and_rides_saves_verbatim() {
    // Group f2 with both framing tags padded to two bytes, its
    // interior a padded varint; a padded scalar rides beside it.
    let msg = h("93 00  18 96 81 00  94 00  88 00 01");
    let markup = Markup::open(&msg).unwrap();
    let tops: Vec<_> = markup.top().collect();
    assert_eq!(tops.len(), 2);
    let inner = markup.children(tops[0]).unwrap().next().unwrap();
    assert_eq!(markup.varint_word(inner).unwrap(), 150);
    assert_eq!(all_saves(&markup), msg, "an untouched markup saves its padded source");
}

#[test]
fn interior_edits_keep_the_padded_group_tags_verbatim() {
    let msg = h("93 00 18 01 94 00");
    let mut markup = Markup::open(&msg).unwrap();
    let group = markup.top().next().unwrap();
    let inner = markup.children(group).unwrap().next().unwrap();

    markup.set_varint(inner, 300).unwrap();
    assert_eq!(
        all_saves(&markup),
        h("93 00 18 AC 02 94 00"),
        "a scanned group's framing tags ride verbatim whatever happens inside"
    );
}

#[test]
fn an_inserted_group_emits_minimally_beside_padded_wire() {
    let msg = h("88 00 01");
    let mut markup = Markup::open(&msg).unwrap();
    let group = markup.insert_group(InsertAt::TailOf(None), f(2)).unwrap();
    markup.insert_varint(InsertAt::TailOf(Some(group)), f(3), 3).unwrap();
    assert_eq!(all_saves(&markup), h("88 00 01 13 18 03 14"));
}

#[test]
fn len_prefix_fidelity_composes_under_groups() {
    // Group f2 { LEN f1 (padded prefix) "hi" }.
    let msg = h("93 00  0A 82 00 68 69  94 00");
    let mut markup = Markup::open(&msg).unwrap();
    let group = markup.top().next().unwrap();
    let inner = markup.children(group).unwrap().next().unwrap();

    markup.set_payload(inner, b"no").unwrap();
    assert_eq!(all_saves(&markup), h("93 00 0A 82 00 6E 6F 94 00"), "same length keeps the prefix");

    markup.set_payload(inner, b"xyz").unwrap();
    assert_eq!(all_saves(&markup), h("93 00 0A 03 78 79 7A 94 00"), "moved length re-authors");
}

// ─── the revert oracle ───

#[test]
fn revert_all_after_any_command_prefix_restores_the_padded_source() {
    // Padded group wrapping a padded varint · LEN (padded prefix)
    // · minimal varint.
    let msg = h("93 00 18 96 81 00 94 00  12 82 00 68 69  08 2A");
    let mut markup = Markup::open(&msg).unwrap();
    let tops: Vec<_> = markup.top().collect();
    let in_group = markup.children(tops[0]).unwrap().next().unwrap();

    markup.set_varint(in_group, 1).unwrap();
    markup.delete(tops[2]).unwrap();
    let group = markup.insert_group(InsertAt::After(tops[0]), f(5)).unwrap();
    markup.insert_i64(InsertAt::HeadOf(Some(group)), f(1), 0xAB).unwrap();
    markup.set_payload(tops[1], b"world").unwrap();
    assert_eq!(markup.pending(), 5);

    markup.revert_all();
    assert_eq!(markup.pending(), 0);
    assert_eq!(all_saves(&markup), msg, "revert_all restores the padded source");
}

// ─── the borrow door ───

#[test]
fn a_refused_open_is_a_plain_fault_and_never_touches_the_buffer() {
    let unclosed = h("0B 08 01");
    assert!(matches!(
        Markup::open(&unclosed).err(),
        Some(OpenFault::Wire(Fault { kind: FaultKind::GroupUnclosed { .. }, .. }))
    ));
    assert_eq!(unclosed, h("0B 08 01"), "the caller's buffer is unchanged");
}

#[test]
fn source_answers_the_borrow_at_its_full_lifetime() {
    let msg = h("93 00 18 01 94 00");
    let recovered = {
        let mut markup = Markup::open(&msg).unwrap();
        let group = markup.top().next().unwrap();
        let inner = markup.children(group).unwrap().next().unwrap();
        markup.set_varint(inner, 7).unwrap();
        // The accessor hands back the borrow itself, not a
        // machine-lived view: it outlives the markup.
        markup.source()
    };
    assert_eq!(recovered, &msg[..]);
}

// ─── width-true geometry ───

#[test]
fn group_source_spans_report_the_stored_framing_widths() {
    let msg = h("93 00 18 01 94 00");
    let markup = Markup::open(&msg).unwrap();
    let group = markup.top().next().unwrap();

    let Some(RecordSpans::Group { tag, interior, end_tag }) = markup.source_spans(group).unwrap()
    else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (0, 2), "the padded open tag's stored width");
    assert_eq!((interior.start(), interior.end()), (2, 4));
    assert_eq!((end_tag.start(), end_tag.end()), (4, 6), "the padded end tag's stored width");

    // The reverse index: interior bytes answer the inner record,
    // trailing end-tag bytes climb to the group.
    let inner = markup.children(group).unwrap().next().unwrap();
    assert_eq!(markup.narrowest(2), Some(inner));
    assert_eq!(markup.narrowest(4), Some(group), "the padded end tag belongs to the group");
    assert_eq!(markup.narrowest(5), Some(group));
    assert_eq!(markup.narrowest(6), None);
}

#[test]
fn save_spans_enclose_padded_groups_exactly() {
    let msg = h("93 00 18 01 94 00  08 2A");
    let mut markup = Markup::open(&msg).unwrap();
    let tops: Vec<_> = markup.top().collect();
    let inner = markup.children(tops[0]).unwrap().next().unwrap();
    markup.set_varint(inner, 300).unwrap(); // one byte grows to two

    let saved = markup.save().unwrap();
    assert_eq!(saved, h("93 00 18 AC 02 94 00 08 2A"));
    let spans = markup.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(table.len(), 3);
    assert_eq!((table[0].1.start(), table[0].1.end()), (0, 7), "the group encloses its interior");
    assert_eq!((table[1].1.start(), table[1].1.end()), (2, 5));
    assert_eq!((table[2].1.start(), table[2].1.end()), (7, 9));
}

// ─── the staged payload doors ───

#[test]
fn both_payload_door_families_stage_under_padded_framing() {
    let msg = h("12 82 00 68 69");
    let mut markup = Markup::open(&msg).unwrap();
    let record = markup.top().next().unwrap();

    let mut frame = markup.begin_set_payload(record).unwrap();
    frame.write(b"ab").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&markup), h("12 82 00 61 62"));

    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        markup.begin_set_payload_sized(record, over).map(|_| ()),
        Err(EditFault::PayloadTooLarge { len }) if len == over
    ));

    let mut frame = markup.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), 2).unwrap();
    frame.write(b"ok").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&markup), h("12 82 00 61 62 1A 02 6F 6B"));

    markup.revert_all();
    assert_eq!(all_saves(&markup), msg);
}

// ─── the borrowed-payload sibling, in lockstep with the copy-only
// markup: the same command script must leave both machines with
// byte-identical saves and log depths at every step ───

/// The copy-only markup and its borrowed-payload sibling over the
/// same document, driven command by command.
struct Twins<'d, 'p> {
    copy: Markup<'d>,
    borrow: BorrowMarkup<'d, 'p>,
}

impl<'d, 'p> Twins<'d, 'p> {
    #[track_caller]
    fn open(data: &'d [u8]) -> Self {
        Self {
            copy: Markup::open(data).expect("twin document opens"),
            borrow: BorrowMarkup::open(data).expect("twin document opens"),
        }
    }

    /// Applies one command to each twin and pins the observable
    /// agreement: byte-identical saves, equal prices, equal log
    /// depths.
    #[track_caller]
    fn lockstep(
        &mut self,
        copy_cmd: impl FnOnce(&mut Markup<'d>),
        borrow_cmd: impl FnOnce(&mut BorrowMarkup<'d, 'p>),
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
fn borrowed_installs_and_reverts_track_the_copy_only_markup() {
    // varint f1=150 (value padded) · LEN f2 "a" with a padded
    // prefix: the framing facts the fidelity save must reproduce.
    let doc = h("08 96 81 00 12 81 00 61");
    let same_len = h("7A");
    let longer = h("08 07");
    let mut t = Twins::open(&doc);
    // A same-length replacement keeps the prefix verbatim.
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
    // A longer replacement re-authors the prefix minimally.
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
    // Undo restores the earlier install, then the source,
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
    // Everything unwound: the source rides back verbatim.
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.borrow.save().unwrap(), doc);
}

#[test]
fn borrowed_descents_agree_before_and_after_each_backing_flip() {
    // LEN f2 with a padded prefix wrapping varint f1=1.
    let doc = h("12 82 00 08 01");
    // A nested authored payload: LEN f2 with a padded prefix
    // wrapping a padded varint.
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
    // slot through the ancestor witness at depth one and two.
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
fn the_borrowed_sink_save_hands_the_installed_slice_through() {
    let doc = h("12 81 00 61");
    let alpha = h("08 2A");
    let mut s = BorrowMarkup::open(&doc).unwrap();
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
}

// ─── the mixed-backing sibling: lockstep twins in both drives and
// the interleaved history on one log — the arcs run inside and
// beside groups, padded framing included ───

/// The mixed markup driven borrow-only beside the borrowed-only
/// sibling: byte-identical fidelity saves, equal prices, and equal
/// log depths at every step.
struct MixBorrowDrive<'d, 'p> {
    mix: MixMarkup<'d, 'p>,
    borrow: BorrowMarkup<'d, 'p>,
}

impl<'d, 'p> MixBorrowDrive<'d, 'p> {
    #[track_caller]
    fn open(data: &'d [u8]) -> Self {
        Self {
            mix: MixMarkup::open(data).expect("twin document opens"),
            borrow: BorrowMarkup::open(data).expect("twin document opens"),
        }
    }

    #[track_caller]
    fn lockstep(
        &mut self,
        mix_cmd: impl FnOnce(&mut MixMarkup<'d, 'p>),
        borrow_cmd: impl FnOnce(&mut BorrowMarkup<'d, 'p>),
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

/// The mixed markup driven copy-only beside the copy-only base
/// machine, compared the same way.
struct MixCopyDrive<'d> {
    mix: MixMarkup<'d, 'static>,
    copy: Markup<'d>,
}

impl<'d> MixCopyDrive<'d> {
    #[track_caller]
    fn open(data: &'d [u8]) -> Self {
        Self {
            mix: MixMarkup::open(data).expect("twin document opens"),
            copy: Markup::open(data).expect("twin document opens"),
        }
    }

    #[track_caller]
    fn lockstep(
        &mut self,
        mix_cmd: impl FnOnce(&mut MixMarkup<'d, 'static>),
        copy_cmd: impl FnOnce(&mut Markup<'d>),
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
    // (value padded).
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
fn mix_copy_drive_tracks_the_copy_only_markup_around_groups() {
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
    // group f1 { LEN f2 "a", padded prefix }.
    let doc = h("0B 12 81 00 61 0C");
    let alpha = h("08 01");
    let charlie = h("08 05");
    let mut s = MixMarkup::open(&doc).unwrap();
    let group = s.top().next().unwrap();
    let r = s.children(group).unwrap().next().unwrap();
    s.set_payload(r, &alpha).unwrap();
    {
        let transient = h("08 07");
        s.set_payload_copy(r, &transient).unwrap();
    }
    s.set_payload(r, &charlie).unwrap();
    assert_eq!(s.pending(), 3, "three installs, one log");
    // The canonical faces walk the same mixed slots inside the
    // group closure.
    assert_eq!(s.save_canonical().unwrap(), h("0B 12 02 08 05 0C"));
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), h("08 07"), "the copied install restores");
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), alpha, "the borrowed install restores");
    // Borrowed interior holding a group closure, then a copied
    // flip over it.
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
    let mut s = MixMarkup::open(&doc).unwrap();
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
