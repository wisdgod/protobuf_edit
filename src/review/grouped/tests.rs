//! Contract pins for the grouped review: the canonical door over
//! group framing (interiors scan eagerly, so their padding refuses
//! at open), exact revision over minimal wire, the borrow door,
//! and the borrowed-markup differential twin on canonical inputs.

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
    let mut into = h("DEAD");
    review.save_into(&mut into).expect("save_into succeeds");
    assert_eq!(into[2..], saved[..], "save_into appends the save");
    let mut streamed = Vec::new();
    review.save_sink(|chunk| streamed.extend_from_slice(chunk)).expect("save_sink succeeds");
    assert_eq!(streamed, saved, "the sink concatenation is the save");
    saved
}

// ─── the canonical door ───

#[test]
fn the_door_refuses_padding_wherever_the_scan_meets_it() {
    // A group's framing tag padded to two bytes: the scan is the
    // parse, so the padding refuses at the door.
    let src = h("8B 00 18 01 0C");
    assert!(matches!(
        Review::open(&src).err(),
        Some(OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 }))
    ));
    assert_eq!(src, h("8B 00 18 01 0C"), "the caller's buffer is unchanged");

    // A padded tag inside a minimally framed group: interiors are
    // scanned eagerly, so this too refuses at the door.
    assert!(matches!(
        Review::open(&h("0B 88 00 01 0C")).err(),
        Some(OpenFault::Refused(Refusal::NonMinimalTag { at: 1, width: 2 }))
    ));

    // A wire-grammar fault refuses apart from the policy refusals.
    let unclosed = h("0B 08 01");
    assert!(matches!(
        Review::open(&unclosed).err(),
        Some(OpenFault::Wire(Fault { kind: FaultKind::GroupUnclosed { .. }, .. }))
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

// ─── group edits and revision ───

#[test]
fn interior_group_edits_save_and_revert_exactly() {
    // group f2 { varint f3=1 } · varint f1=42.
    let msg = h("13 18 01 14 08 2A");
    let mut review = Review::open(&msg).unwrap();
    let tops: Vec<_> = review.top().collect();
    let inner = review.children(tops[0]).unwrap().next().unwrap();

    review.set_varint(inner, 300).unwrap();
    assert_eq!(all_saves(&review), h("13 18 AC 02 14 08 2A"));

    let group = review.insert_group(InsertAt::After(tops[0]), f(5)).unwrap();
    review.insert_i64(InsertAt::HeadOf(Some(group)), f(1), 0xAB).unwrap();
    review.delete(tops[1]).unwrap();
    assert_eq!(review.pending(), 4);

    review.revert_all();
    assert_eq!(review.pending(), 0);
    assert_eq!(all_saves(&review), msg, "revert_all restores the source");
}

#[test]
fn a_borrowed_machine_holding_only_an_inserted_group_walks_every_read_face() {
    // The unbacked group sentinel over the borrowed slot table: the
    // store holds zero slots, so a value read that ever reached the
    // table would be an out-of-bounds slot access — the kind gates
    // must hold every reader off the group row, and the borrowed
    // descent and save arms must never ask the payload side.
    let mut s = BorrowReview::open(&[]).unwrap();
    let g = s.insert_group(InsertAt::TailOf(None), f(5)).unwrap();

    assert_eq!(s.pending(), 1);
    assert_eq!(s.top().collect::<Vec<_>>(), [g]);
    assert_eq!(s.kind(g).unwrap(), RecordKind::Group);
    assert_eq!(s.field(g).unwrap(), f(5));
    assert_eq!(s.status(g).unwrap(), EditStatus::Inserted);
    assert!(s.dirty(g).unwrap());
    assert_eq!(s.parent(g).unwrap(), None);
    assert_eq!(s.children(g).unwrap().count(), 0);
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
    assert_eq!(s.save().unwrap(), [0x2B, 0x2C]);
    let mut streamed = Vec::new();
    s.save_sink(|slice| streamed.extend_from_slice(slice)).unwrap();
    assert_eq!(streamed, [0x2B, 0x2C]);
    let spans = s.save_spans().unwrap();
    assert_eq!(spans.iter().collect::<Vec<_>>(), [(g, Span::new(0, 2))]);

    // Revert unwinds the splice to a ghost: the saves are the
    // source again and no face dereferences the sentinel.
    assert_eq!(s.revert(), Some(g));
    assert_eq!(s.status(g).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(s.save_len().unwrap(), 0);
    assert!(s.save().unwrap().is_empty());
    assert_eq!(s.save_spans().unwrap().iter().count(), 0);
}

// ─── the borrow door ───

#[test]
fn source_answers_the_borrow_at_its_full_lifetime() {
    let msg = h("13 18 01 14");
    let recovered = {
        let mut review = Review::open(&msg).unwrap();
        let group = review.top().next().unwrap();
        let inner = review.children(group).unwrap().next().unwrap();
        review.set_varint(inner, 7).unwrap();
        // The accessor hands back the borrow itself, not a
        // machine-lived view: it outlives the review.
        review.source()
    };
    assert_eq!(recovered, &msg[..]);
}

#[test]
fn saves_reopen_through_the_canonical_door() {
    let msg = h("13 18 01 14 08 2A");
    let mut review = Review::open(&msg).unwrap();
    let tops: Vec<_> = review.top().collect();
    review.set_varint(tops[1], 7).unwrap();

    let saved = review.save().unwrap();
    let mut next = Review::open(&saved).unwrap();
    let tops: Vec<_> = next.top().collect();
    next.set_varint(tops[1], 8).unwrap();
    assert_eq!(next.save().unwrap(), h("13 18 01 14 08 08"));
}

// ─── derived geometry ───

#[test]
fn group_source_spans_report_the_derived_framing_widths() {
    let msg = h("13 18 01 14");
    let review = Review::open(&msg).unwrap();
    let group = review.top().next().unwrap();

    let Some(RecordSpans::Group { tag, interior, end_tag }) = review.source_spans(group).unwrap()
    else {
        unreachable!()
    };
    assert_eq!((tag.start(), tag.end()), (0, 1));
    assert_eq!((interior.start(), interior.end()), (1, 3));
    assert_eq!((end_tag.start(), end_tag.end()), (3, 4));

    // The reverse index: interior bytes answer the inner record,
    // the end-tag byte climbs to the group.
    let inner = review.children(group).unwrap().next().unwrap();
    assert_eq!(review.narrowest(1), Some(inner));
    assert_eq!(review.narrowest(3), Some(group), "the end tag belongs to the group");
    assert_eq!(review.narrowest(4), None);
}

#[test]
fn save_spans_enclose_groups_exactly() {
    let msg = h("13 18 01 14 08 2A");
    let mut review = Review::open(&msg).unwrap();
    let tops: Vec<_> = review.top().collect();
    let inner = review.children(tops[0]).unwrap().next().unwrap();
    review.set_varint(inner, 300).unwrap(); // one byte grows to two

    let saved = review.save().unwrap();
    assert_eq!(saved, h("13 18 AC 02 14 08 2A"));
    let spans = review.save_spans().unwrap();
    let table: Vec<_> = spans.iter().collect();
    assert_eq!(table.len(), 3);
    assert_eq!((table[0].1.start(), table[0].1.end()), (0, 5), "the group encloses its interior");
    assert_eq!((table[1].1.start(), table[1].1.end()), (1, 4));
    assert_eq!((table[2].1.start(), table[2].1.end()), (5, 7));
}

// ─── the staged payload doors ───

#[test]
fn both_payload_door_families_stage_and_revert() {
    let msg = h("12 02 68 69");
    let mut review = Review::open(&msg).unwrap();
    let record = review.top().next().unwrap();

    let mut frame = review.begin_set_payload(record).unwrap();
    frame.write(b"ab").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&review), h("12 02 61 62"));

    let over = usize_of(PayloadLen::MAX.as_inner()) + 1;
    assert!(matches!(
        review.begin_set_payload_sized(record, over).map(|_| ()),
        Err(EditFault::PayloadTooLarge { len }) if len == over
    ));

    let mut frame = review.begin_insert_payload_sized(InsertAt::TailOf(None), f(3), 2).unwrap();
    frame.write(b"ok").unwrap();
    frame.finish().unwrap();
    assert_eq!(all_saves(&review), h("12 02 61 62 1A 02 6F 6B"));

    review.revert_all();
    assert_eq!(all_saves(&review), msg);
}

// ─── the borrowed-markup differential twin ───

/// The grouped command set with interleaved revision, applied
/// pairwise to the tolerant markup and the canonical review over
/// identical minimal bytes: at every checkpoint — after each
/// command, each revert, and the final revert_all — the saves must
/// agree byte-identically, group framing included.
#[cfg(feature = "markup-grouped")]
#[test]
fn identical_command_arcs_save_byte_identically_at_every_checkpoint() {
    use crate::markup::grouped::{InsertAt as MInsertAt, Markup};

    // group f1 { f2 varint 150 } · varint f5 · LEN f6 "abc" ·
    // group f7 { f2 varint 1 } — minimal throughout.
    let msg = h("0B 10 96 01 0C  28 05  32 03 61 62 63  3B 10 01 3C");
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

    // Inside the eagerly materialized group.
    let m_in = markup.children(mt[0]).unwrap().next().unwrap();
    let r_in = review.children(rt[0]).unwrap().next().unwrap();
    markup.set_varint(m_in, 7).unwrap();
    review.set_varint(r_in, 7).unwrap();
    agree!();

    markup.set_varint(mt[1], 300).unwrap();
    review.set_varint(rt[1], 300).unwrap();
    agree!();

    markup.set_payload(mt[2], b"xyzzy").unwrap();
    review.set_payload(rt[2], b"xyzzy").unwrap();
    agree!();

    // Whole-group deletion, then a fresh group with an interior.
    markup.delete(mt[3]).unwrap();
    review.delete(rt[3]).unwrap();
    agree!();
    let mg = markup.insert_group(MInsertAt::After(mt[3]), f(9)).unwrap();
    let rg = review.insert_group(InsertAt::After(rt[3]), f(9)).unwrap();
    markup.insert_varint(MInsertAt::TailOf(Some(mg)), f(2), 7).unwrap();
    review.insert_varint(InsertAt::TailOf(Some(rg)), f(2), 7).unwrap();
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
// the interleaved history on one log — the arcs run inside and
// beside groups, under canonical admission ───

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
fn mix_borrow_drive_tracks_the_borrowed_sibling_around_groups() {
    // group f1 { LEN f2 "a" } · varint f1=42, all minimal.
    let doc = h("0B 12 01 61 0C 08 2A");
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
    assert_eq!(t.mix.save().unwrap(), doc);
}

#[test]
fn mix_copy_drive_tracks_the_copy_only_review_around_groups() {
    let doc = h("0B 12 01 61 0C 08 2A");
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
    // group f1 { LEN f2 "a" }.
    let doc = h("0B 12 01 61 0C");
    let alpha = h("08 01");
    let charlie = h("08 05");
    let mut s = MixReview::open(&doc).unwrap();
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
    assert_eq!(s.save().unwrap(), doc);
}

#[test]
fn mix_descents_reach_the_right_provenance_over_each_flip() {
    // LEN f2 wrapping varint f1=1, beside a group.
    let doc = h("12 02 08 01 0B 0C");
    // A nested payload whose interior holds a group closure.
    let nested = h("12 04 0B 08 07 0C");
    let mut s = MixReview::open(&doc).unwrap();
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
