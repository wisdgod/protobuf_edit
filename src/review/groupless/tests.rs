//! Contract pins for the groupless review: the canonical door,
//! derived geometry, exact revision over minimal wire, the borrow
//! door, and the borrowed-markup differential twin on canonical
//! inputs (identical command arcs ⇒ byte-identical saves at every
//! revision checkpoint — acceptance judges the door, never the
//! edits or the log).

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

/// Every output face of one review, cross-checked: `save`,
/// `save_into`, `save_sink` concatenation, and `save_len` all
/// answer the same bytes.
#[track_caller]
fn all_saves(review: &Review<'_>) -> Vec<u8> {
    let saved = review.save().expect("save succeeds");
    assert_eq!(
        review.save_len().expect("save_len succeeds") as usize,
        saved.len(),
        "save_len prices the save"
    );
    let mut into = h("BEEF");
    review.save_into(&mut into).expect("save_into succeeds");
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    review.save_sink(|chunk| streamed.extend_from_slice(chunk)).expect("save_sink succeeds");
    assert_eq!(streamed, saved, "the sink concatenation is the save");
    saved
}

// ─── the canonical door ───

#[test]
fn the_door_refuses_each_padded_site_with_the_buffer_untouched() {
    // A tag padded to two bytes.
    let src = h("88 00 01");
    assert!(matches!(
        Review::open(&src).err(),
        Some(OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 }))
    ));
    assert_eq!(src, h("88 00 01"), "the caller's buffer is unchanged");

    // A LEN prefix padded to two bytes.
    assert!(matches!(
        Review::open(&h("12 81 00 61")).err(),
        Some(OpenFault::Refused(Refusal::NonMinimalLen { at: 1, width: 2, .. }))
    ));

    // A varint value padded to three bytes.
    assert!(matches!(
        Review::open(&h("08 96 81 00")).err(),
        Some(OpenFault::Refused(Refusal::NonMinimalValue { at: 1, width: 3, .. }))
    ));

    // A group code: lawful wire outside this dialect.
    assert!(matches!(
        Review::open(&h("0B 0C")).err(),
        Some(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
    ));

    // A wire-grammar fault refuses apart from the policy refusals.
    assert!(matches!(
        Review::open(&h("00")).err(),
        Some(OpenFault::Wire(Fault { at: 0, kind: FaultKind::FieldZero }))
    ));
}

#[test]
fn hidden_padding_refuses_at_descent_as_a_resident_verdict() {
    // LEN f3 whose interior carries a padded LEN prefix: opaque at
    // the door, judged at the descent commitment.
    let msg = h("1A 03 12 81 00");
    let mut review = Review::open(&msg).unwrap();
    let record = review.top().next().unwrap();
    let Descent::Refused(refusal) = review.descend(record).unwrap() else {
        panic!("the padded interior must refuse descent");
    };
    assert!(matches!(refusal, Refusal::NonMinimalLen { at: 3, width: 2, .. }));
    // The verdict is resident; the document itself still saves.
    assert_eq!(all_saves(&review), msg);
}

// ─── the revert oracle ───

#[test]
fn revert_all_after_any_command_prefix_restores_the_source() {
    // varint · LEN wrapping a varint · varint — minimal throughout.
    let msg = h("08 96 01  12 03 08 96 01  10 2A");
    let mut review = Review::open(&msg).unwrap();
    let tops: Vec<_> = review.top().collect();

    // A compound arc across every command family.
    review.set_varint(tops[0], 7).unwrap();
    let Descent::Opened { first: Some(inner) } = review.descend(tops[1]).unwrap() else {
        unreachable!()
    };
    review.set_varint(inner, 1).unwrap();
    review.delete(tops[2]).unwrap();
    let fresh = review.insert_payload(InsertAt::TailOf(None), f(4), b"zz").unwrap();
    let mut frame = review.begin_set_payload(fresh).unwrap();
    frame.write(b"ab").unwrap();
    frame.finish().unwrap();
    assert_eq!(review.pending(), 5);

    review.revert_all();
    assert_eq!(review.pending(), 0);
    assert_eq!(all_saves(&review), msg, "revert_all restores the source");
}

#[test]
fn each_revert_step_restores_the_previous_save() {
    let msg = h("08 96 01 10 2A");
    let mut review = Review::open(&msg).unwrap();
    let tops: Vec<_> = review.top().collect();

    let mut checkpoints = Vec::new();
    checkpoints.push(all_saves(&review));
    review.set_varint(tops[0], 7).unwrap();
    checkpoints.push(all_saves(&review));
    review.delete(tops[1]).unwrap();
    checkpoints.push(all_saves(&review));
    review.insert_varint(InsertAt::HeadOf(None), f(5), 300).unwrap();
    checkpoints.push(all_saves(&review));

    while review.pending() > 0 {
        checkpoints.pop();
        review.revert();
        assert_eq!(&all_saves(&review), checkpoints.last().unwrap());
    }
}

// ─── the borrow door ───

#[test]
fn source_answers_the_borrow_at_its_full_lifetime() {
    let msg = h("08 96 01");
    let recovered = {
        let mut review = Review::open(&msg).unwrap();
        let record = review.top().next().unwrap();
        review.set_varint(record, 7).unwrap();
        // The accessor hands back the borrow itself, not a
        // machine-lived view: it outlives the review.
        review.source()
    };
    assert_eq!(recovered, &msg[..]);
    assert_eq!(msg, h("08 96 01"), "staged edits never touch the caller's buffer");
}

#[test]
fn saves_reopen_through_the_canonical_door() {
    // Admission proves the source minimal and authored words emit
    // minimal, so outputs chain through the same door.
    let msg = h("08 96 01 10 2A");
    let mut review = Review::open(&msg).unwrap();
    let tops: Vec<_> = review.top().collect();
    review.set_varint(tops[1], 7).unwrap();

    let saved = review.save().unwrap();
    let mut next = Review::open(&saved).unwrap();
    let tops: Vec<_> = next.top().collect();
    assert_eq!(next.varint_word(tops[0]).unwrap(), 150);
    next.set_varint(tops[1], 8).unwrap();
    assert_eq!(next.save().unwrap(), h("08 96 01 10 08"));
}

// ─── derived geometry ───

#[test]
fn source_spans_and_narrowest_answer_at_the_derived_widths() {
    // varint at 0..3 · LEN at 3..7 — every width is the value's
    // own encoding (admission proved it).
    let msg = h("08 96 01  12 02 68 69");
    let review = Review::open(&msg).unwrap();
    let tops: Vec<_> = review.top().collect();

    let Some(RecordSpans::Varint { tag, value }) = review.source_spans(tops[0]).unwrap() else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (0, 1));
    assert_eq!((value.start(), value.end()), (1, 3));

    let Some(RecordSpans::Len { tag, prefix, payload }) = review.source_spans(tops[1]).unwrap()
    else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (3, 4));
    assert_eq!((prefix.start(), prefix.end()), (4, 5));
    assert_eq!((payload.start(), payload.end()), (5, 7));

    // The reverse index covers every byte.
    for pos in 0..3 {
        assert_eq!(review.narrowest(pos), Some(tops[0]), "byte {pos}");
    }
    for pos in 3..7 {
        assert_eq!(review.narrowest(pos), Some(tops[1]), "byte {pos}");
    }
    assert_eq!(review.narrowest(7), None);
}

// ─── the staged payload doors ───

#[test]
fn the_undeclared_frame_stages_and_installs_once() {
    let msg = h("12 02 68 69");
    let mut review = Review::open(&msg).unwrap();
    let record = review.top().next().unwrap();

    let mut frame = review.begin_set_payload(record).unwrap();
    frame.write(b"a").unwrap();
    frame.write(b"b").unwrap();
    frame.finish().unwrap();
    assert_eq!(review.pending(), 1, "one logged transition per frame");
    assert_eq!(all_saves(&review), h("12 02 61 62"));

    review.revert();
    assert_eq!(all_saves(&review), msg);
}

#[test]
fn the_sized_frame_holds_its_declaration() {
    let msg = h("12 02 68 69");
    let mut review = Review::open(&msg).unwrap();
    let record = review.top().next().unwrap();

    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        review.begin_set_payload_sized(record, over).map(|_| ()),
        Err(EditFault::PayloadTooLarge { len }) if len == over
    ));

    let mut frame = review.begin_set_payload_sized(record, 2).unwrap();
    assert!(matches!(frame.write(b"abc"), Err(FrameFault::OverDeclared { declared: 2, total: 3 })));
    frame.write(b"a").unwrap();
    assert!(matches!(frame.finish(), Err(FrameFault::UnderDeclared { declared: 2, staged: 1 })));
    assert_eq!(review.pending(), 0, "a failed frame installs nothing");

    let mut frame = review.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), 2).unwrap();
    frame.write(b"ok").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&review), h("12 02 68 69 1A 02 6F 6B"));
}

// ─── the borrowed-markup differential twin ───

/// The full command set with interleaved revision, applied
/// pairwise to the tolerant markup and the canonical review over
/// identical minimal bytes: at every checkpoint — after each
/// command, each revert, and the final revert_all — the saves must
/// agree byte-identically. Acceptance judges the door, and on
/// bytes both doors admit the machines are the same machine, the
/// revision log included.
#[cfg(feature = "markup-groupless")]
#[test]
fn identical_command_arcs_save_byte_identically_at_every_checkpoint() {
    use crate::markup::groupless::{InsertAt as MInsertAt, Markup};

    // varint f1 · LEN f2 "abc" · LEN f3 { f9 varint 1 } · varint f8
    // — minimal throughout, so both doors admit it.
    let msg = h("08 2A  12 03 61 62 63  1A 02 48 01  40 96 01");
    let mut markup = Markup::open(&msg).unwrap();
    let mut review = Review::open(&msg).unwrap();

    macro_rules! agree {
        () => {{
            assert_eq!(markup.save().unwrap(), all_saves(&review));
            assert_eq!(markup.pending(), review.pending());
        }};
    }

    let mt: Vec<_> = markup.top().collect();
    let rt: Vec<_> = review.top().collect();
    assert_eq!(mt.len(), rt.len());
    agree!();

    markup.set_varint(mt[0], 300).unwrap();
    review.set_varint(rt[0], 300).unwrap();
    agree!();

    markup.set_payload(mt[1], b"grown payload").unwrap();
    review.set_payload(rt[1], b"grown payload").unwrap();
    agree!();

    let crate::markup::groupless::Descent::Opened { first: Some(m_in) } =
        markup.descend(mt[2]).unwrap()
    else {
        unreachable!()
    };
    let Descent::Opened { first: Some(r_in) } = review.descend(rt[2]).unwrap() else {
        unreachable!()
    };
    markup.set_varint(m_in, 7).unwrap();
    review.set_varint(r_in, 7).unwrap();
    agree!();

    markup.delete(mt[3]).unwrap();
    review.delete(rt[3]).unwrap();
    agree!();

    markup.insert_varint(MInsertAt::HeadOf(None), f(13), 5).unwrap();
    review.insert_varint(InsertAt::HeadOf(None), f(13), 5).unwrap();
    agree!();

    markup.insert_payload(MInsertAt::TailOf(Some(mt[2])), f(14), b"in").unwrap();
    review.insert_payload(InsertAt::TailOf(Some(rt[2])), f(14), b"in").unwrap();
    agree!();

    // A staged frame, then step the logs back in lockstep.
    let mut mf = markup.begin_set_payload(mt[1]).unwrap();
    mf.write(b"fra").unwrap();
    mf.write(b"med").unwrap();
    mf.finish().unwrap();
    let mut rf = review.begin_set_payload(rt[1]).unwrap();
    rf.write(b"fra").unwrap();
    rf.write(b"med").unwrap();
    rf.finish().unwrap();
    agree!();

    for _ in 0..3 {
        assert_eq!(markup.revert().is_some(), review.revert().is_some());
        agree!();
    }

    markup.revert_all();
    review.revert_all();
    agree!();
    assert_eq!(all_saves(&review), msg, "the emptied log restores the source");
}

// ─── the borrowed-payload sibling, in lockstep with the copy-only
// review: the same command script must leave both machines with
// byte-identical saves and log depths at every step ───

/// The copy-only review and its borrowed-payload sibling over the
/// same document, driven command by command.
struct Twins<'d, 'p> {
    copy: Review<'d>,
    borrow: BorrowReview<'d, 'p>,
}

impl<'d, 'p> Twins<'d, 'p> {
    #[track_caller]
    fn open(data: &'d [u8]) -> Self {
        Self {
            copy: Review::open(data).expect("twin document opens"),
            borrow: BorrowReview::open(data).expect("twin document opens"),
        }
    }

    /// Applies one command to each twin and pins the observable
    /// agreement: byte-identical saves, equal prices, equal log
    /// depths.
    #[track_caller]
    fn lockstep(
        &mut self,
        copy_cmd: impl FnOnce(&mut Review<'d>),
        borrow_cmd: impl FnOnce(&mut BorrowReview<'d, 'p>),
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
fn borrowed_installs_and_reverts_track_the_copy_only_review() {
    // varint f1=150 · LEN f2 "a".
    let doc = h("08 96 01 12 01 61");
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
    assert_eq!(t.borrow.save().unwrap(), h("08 96 01 12 01 7A"));
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
    assert_eq!(t.borrow.save().unwrap(), h("08 96 01 12 02 08 07"));
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
    assert_eq!(t.borrow.save().unwrap(), h("08 96 01 12 01 7A"));
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.borrow.save().unwrap(), doc);
}

#[test]
fn delete_undelete_clear_and_births_ride_borrowed_installs_in_lockstep() {
    let doc = h("12 01 61 08 96 01");
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
    // Clearing restores the scanned state.
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
    // LEN f2 wrapping varint f1=1.
    let doc = h("12 02 08 01");
    // A nested authored payload: LEN f2 wrapping varint f1=150.
    let nested = h("12 03 08 96 01");
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
    let doc = h("12 01 61");
    let alpha = h("08 2A");
    let mut s = BorrowReview::open(&doc).unwrap();
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
// the interleaved history on one log, under canonical admission ───

/// The mixed review driven borrow-only beside the borrowed-only
/// sibling: byte-identical saves, equal prices, and equal log
/// depths at every step.
struct MixBorrowDrive<'d, 'p> {
    mix: MixReview<'d, 'p>,
    borrow: BorrowReview<'d, 'p>,
}

impl<'d, 'p> MixBorrowDrive<'d, 'p> {
    #[track_caller]
    fn open(data: &'d [u8]) -> Self {
        Self {
            mix: MixReview::open(data).expect("twin document opens"),
            borrow: BorrowReview::open(data).expect("twin document opens"),
        }
    }

    #[track_caller]
    fn lockstep(
        &mut self,
        mix_cmd: impl FnOnce(&mut MixReview<'d, 'p>),
        borrow_cmd: impl FnOnce(&mut BorrowReview<'d, 'p>),
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

/// The mixed review driven copy-only beside the copy-only base
/// machine, compared the same way.
struct MixCopyDrive<'d> {
    mix: MixReview<'d, 'static>,
    copy: Review<'d>,
}

impl<'d> MixCopyDrive<'d> {
    #[track_caller]
    fn open(data: &'d [u8]) -> Self {
        Self {
            mix: MixReview::open(data).expect("twin document opens"),
            copy: Review::open(data).expect("twin document opens"),
        }
    }

    #[track_caller]
    fn lockstep(
        &mut self,
        mix_cmd: impl FnOnce(&mut MixReview<'d, 'static>),
        copy_cmd: impl FnOnce(&mut Review<'d>),
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
fn mix_borrow_drive_tracks_the_borrowed_sibling() {
    // LEN f2 "a" · varint f1=150, all minimal.
    let doc = h("12 01 61 08 96 01");
    let alpha = h("08 01");
    let beta = h("08 07 08 08");
    let mut t = MixBorrowDrive::open(&doc);
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
    t.lockstep(
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &alpha).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &alpha).unwrap();
        },
    );
    t.lockstep(|s| s.revert_all(), |s| s.revert_all());
    assert_eq!(t.mix.save().unwrap(), doc);
}

#[test]
fn mix_copy_drive_tracks_the_copy_only_review() {
    let doc = h("12 01 61 08 96 01");
    let alpha = h("08 01");
    let mut t = MixCopyDrive::open(&doc);
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
            s.insert_payload_copy(InsertAt::TailOf(None), f(3), &alpha).unwrap();
        },
        |s| {
            s.insert_payload(InsertAt::TailOf(None), f(3), &alpha).unwrap();
        },
    );
    t.lockstep(
        |s| {
            let r = s.top().next().unwrap();
            let mut frame = s.begin_set_payload(r).unwrap();
            frame.write(b"a").unwrap();
            frame.write(b"b").unwrap();
            frame.finish().unwrap();
        },
        |s| {
            let r = s.top().next().unwrap();
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
fn mix_interleaved_history_and_flips_on_one_log() {
    let doc = h("12 02 08 01");
    let alpha = h("08 01");
    let charlie = h("08 05");
    let nested = h("12 02 08 07");
    let mut s = MixReview::open(&doc).unwrap();
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
    // Borrowed nested interior, then a copied flip over it: each
    // descent climbs to its own install's bytes.
    s.set_payload(r, &nested).unwrap();
    let Descent::Opened { first: Some(inner) } = s.descend(r).unwrap() else {
        panic!("borrowed interior opens")
    };
    let Descent::Opened { first: Some(leaf) } = s.descend(inner).unwrap() else {
        panic!("nested borrowed interior opens")
    };
    assert_eq!(s.varint_word(leaf).unwrap(), 7, "depth two reads the borrowed slot");
    {
        let transient = h("12 02 08 63");
        s.set_payload_copy(r, &transient).unwrap();
    }
    assert!(matches!(s.varint_word(leaf), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(copied) } = s.descend(r).unwrap() else {
        panic!("copied interior opens")
    };
    let Descent::Opened { first: Some(copy_leaf) } = s.descend(copied).unwrap() else {
        panic!("nested copied interior opens")
    };
    assert_eq!(s.varint_word(copy_leaf).unwrap(), 99, "depth two reads the copied extent");
    s.revert_all();
    assert_eq!(s.save().unwrap(), doc);
}

#[test]
fn mix_descents_reach_the_right_provenance_over_each_flip() {
    // LEN f2 wrapping varint f1=1.
    let doc = h("12 02 08 01");
    // A nested borrowed payload: LEN f2 wrapping varint f1=7.
    let nested = h("12 02 08 07");
    let mut s = MixReview::open(&doc).unwrap();
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
