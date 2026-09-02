//! Contract pins for the groupless markup: tolerant admission,
//! width-true geometry, the fidelity save, exact revision, and the
//! borrow door.

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
    let mut into = h("BEEF");
    markup.save_into(&mut into).expect("save_into succeeds");
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    markup.save_sink(|chunk| streamed.extend_from_slice(chunk)).expect("save_sink succeeds");
    assert_eq!(streamed, saved, "the sink concatenation is the save");
    saved
}

// ─── tolerant admission and the fidelity save ───

#[test]
fn padded_framing_admits_and_rides_saves_verbatim() {
    // Padded tag [88 00] · padded value [96 81 00] · LEN f2 with a
    // padded two-byte prefix.
    let msg = h("88 00 96 81 00  12 82 00 68 69");
    let markup = Markup::open(&msg).unwrap();
    let tops: Vec<_> = markup.top().collect();
    assert_eq!(tops.len(), 2);
    assert_eq!(markup.varint_word(tops[0]).unwrap(), 150);
    assert_eq!(markup.payload_bytes(tops[1]).unwrap(), *b"hi");
    assert_eq!(all_saves(&markup), msg, "an untouched markup saves its padded source");
}

#[test]
fn a_replaced_scalar_keeps_its_padded_tag_and_reauthors_its_value() {
    // Padded tag, padded value: the tag is an input fact, the
    // value is the command's to re-author minimally.
    let msg = h("88 00 96 81 00");
    let mut markup = Markup::open(&msg).unwrap();
    let record = markup.top().next().unwrap();
    markup.set_varint(record, 7).unwrap();
    assert_eq!(all_saves(&markup), h("88 00 07"));
}

#[test]
fn interior_edits_keep_the_padded_len_framing_while_the_length_holds() {
    // LEN f2 (padded prefix) wrapping varint f1=1.
    let msg = h("12 82 00 08 01");
    let mut markup = Markup::open(&msg).unwrap();
    let container = markup.top().next().unwrap();
    let Descent::Opened { first: Some(inner) } = markup.descend(container).unwrap() else {
        unreachable!()
    };

    markup.set_varint(inner, 7).unwrap();
    assert_eq!(all_saves(&markup), h("12 82 00 08 07"), "unchanged body length keeps the prefix");

    markup.set_varint(inner, 300).unwrap();
    assert_eq!(all_saves(&markup), h("12 03 08 AC 02"), "a grown body re-authors the prefix");
}

// ─── the revert oracle ───

#[test]
fn revert_all_after_any_command_prefix_restores_the_padded_source() {
    // Padded tag varint · LEN (padded prefix) wrapping a padded
    // varint · minimal varint.
    let msg = h("88 00 96 81 00  12 84 00 08 96 81 00  10 2A");
    let mut markup = Markup::open(&msg).unwrap();
    let tops: Vec<_> = markup.top().collect();

    // A compound arc across every command family.
    markup.set_varint(tops[0], 7).unwrap();
    let Descent::Opened { first: Some(inner) } = markup.descend(tops[1]).unwrap() else {
        unreachable!()
    };
    markup.set_varint(inner, 1).unwrap();
    markup.delete(tops[2]).unwrap();
    let fresh = markup.insert_payload(InsertAt::TailOf(None), f(4), b"zz").unwrap();
    let mut frame = markup.begin_set_payload(fresh).unwrap();
    frame.write(b"ab").unwrap();
    frame.finish().unwrap();
    assert_eq!(markup.pending(), 5);

    markup.revert_all();
    assert_eq!(markup.pending(), 0);
    assert_eq!(all_saves(&markup), msg, "revert_all restores the padded source");
}

#[test]
fn each_revert_step_restores_the_previous_save() {
    let msg = h("88 00 96 81 00 10 2A");
    let mut markup = Markup::open(&msg).unwrap();
    let tops: Vec<_> = markup.top().collect();

    let mut checkpoints = Vec::new();
    checkpoints.push(all_saves(&markup));
    markup.set_varint(tops[0], 7).unwrap();
    checkpoints.push(all_saves(&markup));
    markup.delete(tops[1]).unwrap();
    checkpoints.push(all_saves(&markup));
    markup.insert_varint(InsertAt::HeadOf(None), f(5), 300).unwrap();
    checkpoints.push(all_saves(&markup));

    while markup.pending() > 0 {
        checkpoints.pop();
        markup.revert();
        assert_eq!(&all_saves(&markup), checkpoints.last().unwrap());
    }
}

// ─── the borrow door ───

#[test]
fn a_refused_open_is_a_plain_fault_and_never_touches_the_buffer() {
    // A group code: lawful wire outside this dialect's language.
    let group = h("0B 0C");
    assert!(matches!(
        Markup::open(&group).err(),
        Some(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
    ));
    assert_eq!(group, h("0B 0C"), "the caller's buffer is unchanged");

    let zero = h("00");
    assert!(matches!(
        Markup::open(&zero).err(),
        Some(OpenFault::Wire(Fault { at: 0, kind: FaultKind::FieldZero }))
    ));
}

#[test]
fn source_answers_the_borrow_at_its_full_lifetime() {
    let msg = h("88 00 96 81 00");
    let recovered = {
        let mut markup = Markup::open(&msg).unwrap();
        let record = markup.top().next().unwrap();
        markup.set_varint(record, 7).unwrap();
        // The accessor hands back the borrow itself, not a
        // machine-lived view: it outlives the markup.
        markup.source()
    };
    assert_eq!(recovered, &msg[..]);
}

#[test]
fn saves_reopen_through_the_borrow_door() {
    let msg = h("88 00 96 81 00 10 2A");
    let mut markup = Markup::open(&msg).unwrap();
    let tops: Vec<_> = markup.top().collect();
    markup.set_varint(tops[1], 7).unwrap();

    let saved = markup.save().unwrap();
    let mut next = Markup::open(&saved).unwrap();
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
    let markup = Markup::open(&msg).unwrap();
    let tops: Vec<_> = markup.top().collect();

    let Some(RecordSpans::Varint { tag, value }) = markup.source_spans(tops[0]).unwrap() else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (0, 2), "the padded tag's stored width");
    assert_eq!((value.start(), value.end()), (2, 5), "the padded value's scanned extent");

    let Some(RecordSpans::Len { tag, prefix, payload }) = markup.source_spans(tops[1]).unwrap()
    else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (5, 6));
    assert_eq!((prefix.start(), prefix.end()), (6, 8), "the padded prefix's stored width");
    assert_eq!((payload.start(), payload.end()), (8, 10));

    // The reverse index covers every padded byte.
    for pos in 0..5 {
        assert_eq!(markup.narrowest(pos), Some(tops[0]), "byte {pos}");
    }
    for pos in 5..10 {
        assert_eq!(markup.narrowest(pos), Some(tops[1]), "byte {pos}");
    }
    assert_eq!(markup.narrowest(10), None);
}

// ─── the staged payload doors ───

#[test]
fn the_undeclared_frame_stages_and_installs_once() {
    let msg = h("12 82 00 68 69");
    let mut markup = Markup::open(&msg).unwrap();
    let record = markup.top().next().unwrap();

    let mut frame = markup.begin_set_payload(record).unwrap();
    frame.write(b"a").unwrap();
    frame.write(b"b").unwrap();
    frame.finish().unwrap();
    assert_eq!(markup.pending(), 1, "one logged transition per frame");
    assert_eq!(all_saves(&markup), h("12 82 00 61 62"), "two staged bytes keep the padded prefix");

    markup.revert();
    assert_eq!(all_saves(&markup), msg);
}

#[test]
fn the_sized_frame_holds_its_declaration() {
    let msg = h("12 82 00 68 69");
    let mut markup = Markup::open(&msg).unwrap();
    let record = markup.top().next().unwrap();

    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        markup.begin_set_payload_sized(record, over).map(|_| ()),
        Err(EditFault::PayloadTooLarge { len }) if len == over
    ));

    let mut frame = markup.begin_set_payload_sized(record, 2).unwrap();
    assert!(matches!(frame.write(b"abc"), Err(FrameFault::OverDeclared { declared: 2, total: 3 })));
    frame.write(b"a").unwrap();
    assert!(matches!(frame.finish(), Err(FrameFault::UnderDeclared { declared: 2, staged: 1 })));
    assert_eq!(markup.pending(), 0, "a failed frame installs nothing");

    let mut frame = markup.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), 2).unwrap();
    frame.write(b"ok").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&markup), h("12 82 00 68 69 1A 02 6F 6B"));
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
// the interleaved history on one log, padded framing included ───

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
fn mix_borrow_drive_keeps_the_fidelity_reading_in_lockstep() {
    // varint f1=150 (value padded) · LEN f2 "a" with a padded
    // prefix.
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
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap(), doc, "the padded source rides back verbatim");
}

#[test]
fn mix_copy_drive_tracks_the_copy_only_markup() {
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
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap(), doc);
}

#[test]
fn mix_interleaved_history_and_flips_ride_the_padded_source() {
    let doc = h("12 81 00 61");
    let alpha = h("08 01");
    let charlie = h("08 05");
    let nested = h("12 84 00 08 96 81 00");
    let mut s = MixMarkup::open(&doc).unwrap();
    let r = s.top().next().unwrap();
    s.set_payload(r, &alpha).unwrap();
    {
        let transient = h("08 07");
        s.set_payload_copy(r, &transient).unwrap();
    }
    s.set_payload(r, &charlie).unwrap();
    assert_eq!(s.pending(), 3, "three installs, one log");
    // The canonical faces walk the same mixed slots: minimal
    // framing over the live install's bytes.
    assert_eq!(s.save_canonical().unwrap(), h("12 02 08 05"));
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), h("08 07"), "the copied install restores");
    s.revert();
    assert_eq!(s.payload_bytes(r).unwrap(), alpha, "the borrowed install restores");
    s.set_payload(r, &nested).unwrap();
    let Descent::Opened { first: Some(inner) } = s.descend(r).unwrap() else {
        panic!("borrowed interior opens")
    };
    assert_eq!(s.payload_bytes(inner).unwrap(), h("08 96 81 00"), "tolerant slot-local scan");
    {
        let transient = h("12 81 00 63");
        s.set_payload_copy(r, &transient).unwrap();
    }
    assert!(matches!(s.payload_bytes(inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(copied) } = s.descend(r).unwrap() else {
        panic!("copied interior opens")
    };
    assert_eq!(s.payload_bytes(copied).unwrap(), h("63"), "padded copied scan is slot-local");
    s.revert_all();
    assert_eq!(s.save().unwrap(), doc, "the padded source rides back verbatim");
}

#[test]
fn mix_descents_reach_the_right_provenance_over_each_flip() {
    // LEN f2 wrapping varint f1=1.
    let doc = h("12 02 08 01");
    // A nested borrowed payload: LEN f2 wrapping varint f1=7.
    let nested = h("12 02 08 07");
    let mut s = MixMarkup::open(&doc).unwrap();
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
