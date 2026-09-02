//! The transfer siblings' behavioral rows.

use super::*;
#[allow(unused_imports)]
use super::super::tests::*;

fn open(data: &[u8]) -> TransferSession {
    TransferSession::open_copy(data).expect("test document opens")
}

fn tops(s: &TransferSession) -> Vec<Handle> {
    s.top().collect()
}

#[test]
fn copy_record_names_the_source_reading_and_reverts_in_one_step() {
    // varint f1=5 · varint f2=6; a pending replacement does not ride.
    let data = h("08 05 10 06");
    let mut s = open(&data);
    let t = tops(&s);
    s.set_varint(t[0], 300).unwrap();
    let copy = s.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(s.pending(), 2);
    // The copy is output-authored: Inserted status, no source
    // identity, no reverse lookup, no onward designation.
    assert_eq!(s.status(copy).unwrap(), EditStatus::Inserted);
    assert_eq!(s.span(copy).unwrap(), None);
    assert_eq!(s.source_spans(copy).unwrap(), None);
    assert!(s.record_ref(copy).is_err());
    // The replacement emits at the source, the source reading at the
    // copy.
    assert_eq!(s.save().unwrap()[..], h("08 AC 02 10 06 08 05")[..]);
    assert_eq!(s.revert(), Some(copy));
    assert_eq!(s.status(copy).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(s.revert(), Some(t[0]));
    assert_eq!(s.save().unwrap()[..], data[..]);
}
#[test]
fn move_record_is_one_step_and_one_revert_restores_both_sides() {
    let data = h("08 05 10 06");
    let mut s = open(&data);
    let t = tops(&s);
    let dest = s.move_record(t[0], InsertAt::After(t[1])).unwrap();
    assert_eq!(s.pending(), 1);
    assert_eq!(s.status(t[0]).unwrap(), EditStatus::Moved);
    assert_eq!(s.status(dest).unwrap(), EditStatus::Inserted);
    assert_eq!(s.save().unwrap()[..], h("10 06 08 05")[..]);
    // A moved record is suppressed, not shrouded.
    assert!(matches!(s.delete(t[0]), Err(EditFault::DeletedTarget)));
    assert!(matches!(s.undelete(t[0]), Err(EditFault::NotDeleted)));
    assert_eq!(s.revert(), Some(t[0]));
    assert_eq!(s.status(t[0]).unwrap(), EditStatus::Intact);
    assert_eq!(s.status(dest).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(s.save().unwrap()[..], data[..]);
    assert_eq!(s.pending(), 0);
}
#[test]
fn moves_refuse_edited_sources_and_gaps_inside_their_own_subtree() {
    // LEN f2 { varint f1=7 } · varint f3=9.
    let data = h("12 02 08 07 18 09");
    let mut s = open(&data);
    let t = tops(&s);
    // An interior edit blocks the move but not the copy.
    let Descent::Opened { first: Some(inner) } = s.descend(t[0]).unwrap() else { unreachable!() };
    s.set_varint(inner, 8).unwrap();
    assert!(matches!(s.move_record(t[0], InsertAt::After(t[1])), Err(EditFault::SourceModified)));
    s.copy_record(t[0], InsertAt::After(t[1])).unwrap();
    s.revert();
    s.revert();
    // A gap owned by the moved subtree has no emitted owner.
    assert!(matches!(
        s.move_record(t[0], InsertAt::TailOf(Some(t[0]))),
        Err(EditFault::MoveIntoSource)
    ));
    // A gap right after the source resolves into the parent's chain.
    let dest = s.move_record(t[0], InsertAt::After(t[0])).unwrap();
    assert_eq!(s.save().unwrap()[..], data[..]);
    s.revert();
    assert_eq!(s.status(dest).unwrap(), EditStatus::InsertedDeleted);
    // Suppressed, authored, and copied rows refuse designation.
    let dest = s.move_record(t[0], InsertAt::After(t[1])).unwrap();
    assert!(matches!(s.copy_record(t[0], InsertAt::TailOf(None)), Err(EditFault::SourceNotBacked)));
    assert!(matches!(s.copy_record(dest, InsertAt::TailOf(None)), Err(EditFault::SourceNotBacked)));
}
#[test]
fn copy_payload_tracks_the_designation_in_both_target_forms() {
    // LEN f1 "hi" · LEN f2 "no" · varint f3=1.
    let data = h("0A 02 68 69 12 02 6E 6F 18 01");
    let mut s = open(&data);
    let t = tops(&s);
    // Replacement: the target keeps its own framing, the designated
    // interior rides byte-exact.
    assert_eq!(s.copy_payload(t[0], PayloadTarget::Replace(t[1])).unwrap(), t[1]);
    assert_eq!(s.payload_bytes(t[1]).unwrap(), b"hi");
    assert_eq!(s.save().unwrap()[..], h("0A 02 68 69 12 02 68 69 18 01")[..]);
    // Scalars refuse the designation kind gate.
    assert!(matches!(
        s.copy_payload(t[2], PayloadTarget::Replace(t[1])),
        Err(EditFault::KindMismatch { .. })
    ));
    // Insertion: minimal authored framing over the same interior.
    let fresh = s
        .copy_payload(t[0], PayloadTarget::Insert { at: InsertAt::TailOf(None), field: fnum(4) })
        .unwrap();
    assert_eq!(s.payload_bytes(fresh).unwrap(), b"hi");
    assert_eq!(s.status(fresh).unwrap(), EditStatus::Inserted);
    assert_eq!(s.save().unwrap()[..], h("0A 02 68 69 12 02 68 69 18 01 22 02 68 69")[..]);
    // A value command supersedes the designation; clear restores the
    // scanned reading.
    s.set_payload(t[1], b"xyz").unwrap();
    assert_eq!(s.payload_bytes(t[1]).unwrap(), b"xyz");
    s.clear_edit(t[1]).unwrap();
    assert_eq!(s.payload_bytes(t[1]).unwrap(), b"no");
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], data[..]);
}
#[test]
fn designated_interiors_descend_into_first_class_rows() {
    // LEN f1 { varint f1=7 } · LEN f2 "no".
    let data = h("0A 02 08 07 12 02 6E 6F");
    let mut s = open(&data);
    let t = tops(&s);
    s.copy_payload(t[0], PayloadTarget::Replace(t[1])).unwrap();
    let Descent::Opened { first: Some(inner) } = s.descend(t[1]).unwrap() else { unreachable!() };
    assert_eq!(s.varint_word(inner).unwrap(), 7);
    // The designated interior's rows are output-authored and
    // editable; the edited interior walks at save.
    assert_eq!(s.status(inner).unwrap(), EditStatus::Inserted);
    assert_eq!(s.span(inner).unwrap(), None);
    s.set_varint(inner, 9).unwrap();
    assert_eq!(s.save().unwrap()[..], h("0A 02 08 07 12 02 08 09")[..]);
    // Inserting beside the designated rows is first-class too.
    s.insert_varint(InsertAt::TailOf(Some(t[1])), fnum(2), 1).unwrap();
    assert_eq!(s.save().unwrap()[..], h("0A 02 08 07 12 04 08 09 10 01")[..]);
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], data[..]);
}
#[test]
fn move_payload_relocates_the_interior_and_suppresses_the_record() {
    // LEN f1 "hi" · varint f3=9.
    let data = h("0A 02 68 69 18 09");
    let mut s = open(&data);
    let t = tops(&s);
    let dest = s.move_payload(t[0], InsertAt::After(t[1]), fnum(2)).unwrap();
    assert_eq!(s.pending(), 1);
    assert_eq!(s.status(t[0]).unwrap(), EditStatus::Moved);
    assert_eq!(s.payload_bytes(dest).unwrap(), b"hi");
    assert_eq!(s.save().unwrap()[..], h("18 09 12 02 68 69")[..]);
    assert_eq!(s.revert(), Some(t[0]));
    assert_eq!(s.save().unwrap()[..], data[..]);
}
#[test]
fn imports_land_whole_and_revert_in_one_step() {
    // Machine A designates; machine B imports the exact bytes.
    let source_doc = h("0A 02 08 07 10 07");
    let a = open(&source_doc);
    let at = tops(&a);
    let data = h("08 01");
    let mut b = open(&data);
    let len = b
        .copy_record_from(
            a.record_ref(at[0]).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    let word = b
        .copy_record_from(
            a.record_ref(at[1]).unwrap().try_canonical().unwrap(),
            InsertAt::HeadOf(None),
        )
        .unwrap();
    assert_eq!(b.pending(), 2);
    // Imported rows are output-authored and answer their reads.
    assert_eq!(b.status(len).unwrap(), EditStatus::Inserted);
    assert_eq!(b.source_spans(len).unwrap(), None);
    assert_eq!(b.payload_bytes(len).unwrap(), h("08 07"));
    assert_eq!(b.varint_word(word).unwrap(), 7);
    assert!(b.record_ref(len).is_err());
    assert_eq!(b.save().unwrap()[..], h("10 07 08 01 0A 02 08 07")[..]);
    // An imported LEN interior parses into first-class rows after an
    // explicit descent: value edits and insertions land inside the
    // import, and the save re-derives its prefix around them.
    let Descent::Opened { first: Some(inner) } = b.descend(len).unwrap() else { unreachable!() };
    b.set_varint(inner, 1).unwrap();
    assert_eq!(b.save().unwrap()[..], h("10 07 08 01 0A 02 08 01")[..]);
    b.insert_varint(InsertAt::TailOf(Some(len)), fnum(1), 2).unwrap();
    assert_eq!(b.save().unwrap()[..], h("10 07 08 01 0A 04 08 01 08 02")[..]);
    b.revert();
    b.revert();
    // A value command re-authors the import as an ordinary insertion.
    b.set_payload(len, b"xy").unwrap();
    assert_eq!(b.save().unwrap()[..], h("10 07 08 01 0A 02 78 79")[..]);
    b.revert_all();
    assert_eq!(b.save().unwrap()[..], data[..]);
    // The source machine is untouched throughout.
    assert_eq!(a.save().unwrap()[..], source_doc[..]);
}
#[test]
fn copied_interiors_parse_lazily_into_editable_alias_rows() {
    // LEN f2 { varint f1=7 · varint f2=8 }.
    let data = h("12 04 08 07 10 08");
    let mut s = open(&data);
    let t = tops(&s);
    let copy = s.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    let Descent::Opened { first: Some(first) } = s.descend(copy).unwrap() else { unreachable!() };
    assert_eq!(s.varint_word(first).unwrap(), 7);
    // First-class: value edits and insertions land inside the copy,
    // and the source keeps its reading.
    s.set_varint(first, 1).unwrap();
    s.insert_varint(InsertAt::TailOf(Some(copy)), fnum(3), 2).unwrap();
    assert_eq!(s.save().unwrap()[..], h("12 04 08 07 10 08 12 06 08 01 10 08 18 02")[..]);
    // The alias rows answer no reverse lookup: every source position
    // still names the original occurrence.
    for pos in 0..u32::try_from(data.len()).unwrap() {
        assert!(
            s.narrowest(pos)
                .is_some_and(|hit| hit == t[0] || s.ancestors(hit).unwrap().any(|up| up == t[0]))
        );
    }
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], data[..]);
}
#[test]
fn revert_arcs_interleave_moves_with_ordinary_commands() {
    let data = h("08 05 10 06 1A 02 68 69");
    let mut s = open(&data);
    let t = tops(&s);
    let mut prints: Vec<Vec<u8>> = alloc::vec![s.save().unwrap().as_slice().to_vec()];
    s.set_varint(t[1], 1).unwrap();
    prints.push(s.save().unwrap().as_slice().to_vec());
    let dest = s.move_record(t[0], InsertAt::After(t[2])).unwrap();
    prints.push(s.save().unwrap().as_slice().to_vec());
    s.set_varint(dest, 9).unwrap();
    prints.push(s.save().unwrap().as_slice().to_vec());
    s.delete(t[1]).unwrap();
    prints.push(s.save().unwrap().as_slice().to_vec());
    let moved_payload = s.move_payload(t[2], InsertAt::HeadOf(None), fnum(4)).unwrap();
    prints.push(s.save().unwrap().as_slice().to_vec());
    s.set_payload(moved_payload, b"z").unwrap();
    // Unwind the whole arc, checking every fingerprint on the way
    // down (LIFO: later commands on the destination unwind before
    // the move itself).
    while let Some(print) = prints.pop() {
        assert!(s.revert().is_some());
        assert_eq!(s.save().unwrap()[..], print[..]);
    }
    assert_eq!(s.pending(), 0);
}
#[test]
fn descents_reach_the_live_staged_extent_over_each_install() {
    // LEN f2 wrapping varint f1=1.
    let doc = h("12 02 08 01");
    // A nested payload: LEN f2 wrapping varint f1=7.
    let nested = h("12 02 08 07");
    let mut s = TransferSession::open_copy(&doc).unwrap();
    let r = s.top().next().unwrap();
    // Source-backed interior first.
    let Descent::Opened { first: Some(source_inner) } = s.descend(r).unwrap() else {
        panic!("source interior opens")
    };
    assert_eq!(s.varint_word(source_inner).unwrap(), 1);
    // An install stages its own copy of the bytes: the old tree
    // orphans whole, and the re-descended interior reads the staged
    // extent.
    s.set_payload(r, &nested).unwrap();
    assert!(matches!(s.varint_word(source_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(first_inner) } = s.descend(r).unwrap() else {
        panic!("staged interior opens")
    };
    assert_eq!(s.payload_bytes(first_inner).unwrap(), h("08 07"));
    let Descent::Opened { first: Some(first_leaf) } = s.descend(first_inner).unwrap() else {
        panic!("nested staged interior opens")
    };
    assert_eq!(s.varint_word(first_leaf).unwrap(), 7, "depth two reads the staged extent");
    assert!(matches!(s.set_varint(first_leaf, 9), Err(EditFault::InsideAuthoredBody)));
    // A second install replaces the reading; the store copied, so
    // the caller's buffer may die at the block's end.
    {
        let transient = h("12 02 08 63");
        s.set_payload(r, &transient).unwrap();
    }
    assert!(matches!(s.payload_bytes(first_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(second_inner) } = s.descend(r).unwrap() else {
        panic!("second staged interior opens")
    };
    assert_eq!(s.payload_bytes(second_inner).unwrap(), h("08 63"));
    let Descent::Opened { first: Some(second_leaf) } = s.descend(second_inner).unwrap() else {
        panic!("nested second staged interior opens")
    };
    assert_eq!(s.varint_word(second_leaf).unwrap(), 99, "depth two reads the second extent");
    // revert to the first install: its staged extent answers again.
    s.revert();
    assert!(matches!(s.payload_bytes(second_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(again) } = s.descend(r).unwrap() else {
        panic!("first staged interior reopens")
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
fn imported_records_stage_the_designation_and_answer_the_walk() {
    // A cross-machine import stages its own copy of the designated
    // bytes; the interior parses into first-class rows and the exact
    // designation bytes emit whole at save.
    let outside = open(&h("22 02 08 07"));
    let source = outside.top().next().unwrap();
    let doc = h("08 2A");
    let mut s = TransferSession::open_copy(&doc).unwrap();
    let imported = s
        .copy_record_from(
            outside.record_ref(source).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    assert_eq!(s.status(imported).unwrap(), EditStatus::Inserted);
    assert_eq!(s.payload_bytes(imported).unwrap(), h("08 07"));
    let Descent::Opened { first: Some(inner) } = s.descend(imported).unwrap() else {
        panic!("imported interior opens")
    };
    assert_eq!(s.varint_word(inner).unwrap(), 7, "the interior reads through the staged extent");
    // The exact designation bytes emit whole at save; a first-class
    // interior edit re-derives the framing around the changed row and
    // reverts to the wholesale reading.
    assert_eq!(s.save().unwrap()[..], h("08 2A 22 02 08 07")[..]);
    s.set_varint(inner, 9).unwrap();
    assert_eq!(s.save().unwrap()[..], h("08 2A 22 02 08 09")[..]);
    s.revert();
    assert_eq!(s.save().unwrap()[..], h("08 2A 22 02 08 07")[..]);
    // One command, one step: the revert ghosts the import.
    s.revert();
    assert_eq!(s.status(imported).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(s.save().unwrap()[..], doc[..]);
}

// ─── the borrowed twin over slot-local zones ───

#[test]
fn the_borrow_twin_walks_the_import_arc_over_its_slot_zone() {
    // The producer outlives the borrower; the import is retained,
    // and its interior parses at slot-relative offsets.
    let source_doc = h("0A 04 08 07 10 09");
    let outside = open(&source_doc);
    let src = outside.top().next().unwrap();

    let data = h("08 01");
    let mut b = TransferBorrowSession::open_copy(&data).unwrap();
    let import = b
        .copy_record_from(
            outside.record_ref(src).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    assert_eq!(b.pending(), 1);
    assert_eq!(b.status(import).unwrap(), EditStatus::Inserted);
    assert_eq!(b.payload_bytes(import).unwrap(), h("08 07 10 09"));
    assert_eq!(b.save().unwrap()[..], h("08 01 0A 04 08 07 10 09")[..]);

    // The retained closure parses into first-class rows: reads,
    // value edits, insertions, and the shroud pair all land inside,
    // and every step's save re-derives the framing byte-exact.
    let Descent::Opened { first: Some(first) } = b.descend(import).unwrap() else {
        panic!("imported interior opens")
    };
    assert_eq!(b.varint_word(first).unwrap(), 7);
    b.set_varint(first, 5).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0A 04 08 05 10 09")[..]);
    b.insert_varint(InsertAt::TailOf(Some(import)), fnum(3), 1).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0A 06 08 05 10 09 18 01")[..]);
    let interior: Vec<Handle> = b.children(import).unwrap().collect();
    b.delete(interior[1]).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0A 04 08 05 18 01")[..]);
    b.undelete(interior[1]).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0A 06 08 05 10 09 18 01")[..]);
    b.revert_all();
    assert_eq!(b.save().unwrap()[..], data[..]);
}

#[test]
fn the_borrow_twins_move_is_one_command_one_pending_one_revert() {
    let data = h("08 05 10 06");
    let mut b = TransferBorrowSession::open_copy(&data).unwrap();
    let t: Vec<Handle> = b.top().collect();
    let dest = b.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(b.pending(), 1);
    assert_eq!(b.status(t[0]).unwrap(), EditStatus::Moved);
    assert_eq!(b.varint_word(dest).unwrap(), 5);
    assert_eq!(b.save().unwrap()[..], h("10 06 08 05")[..]);
    assert_eq!(b.revert(), Some(t[0]));
    assert_eq!(b.pending(), 0);
    assert_eq!(b.save().unwrap()[..], data[..]);
}

#[test]
fn the_borrow_twin_redescends_through_each_retained_install() {
    // LEN f2 wrapping varint f1=1.
    let doc = h("12 02 08 01");
    // Two long-lived payloads: every install is retained, each in
    // its own slot, so both must outlive the machine.
    let first_install = h("12 02 08 07");
    let second_install = h("12 02 08 63");
    let mut b = TransferBorrowSession::open_copy(&doc).unwrap();
    let r = b.top().next().unwrap();
    // Source-backed interior first.
    let Descent::Opened { first: Some(source_inner) } = b.descend(r).unwrap() else {
        panic!("source interior opens")
    };
    assert_eq!(b.varint_word(source_inner).unwrap(), 1);
    // An install retains the caller's slice: the old tree orphans
    // whole, and the re-descended interior parses at slot-relative
    // offsets inside the retained slice.
    b.set_payload(r, &first_install).unwrap();
    assert!(matches!(b.varint_word(source_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(first_inner) } = b.descend(r).unwrap() else {
        panic!("retained interior opens")
    };
    assert_eq!(b.payload_bytes(first_inner).unwrap(), h("08 07"));
    let Descent::Opened { first: Some(first_leaf) } = b.descend(first_inner).unwrap() else {
        panic!("nested retained interior opens")
    };
    assert_eq!(b.varint_word(first_leaf).unwrap(), 7, "depth two reads the retained slot");
    assert!(matches!(b.set_varint(first_leaf, 9), Err(EditFault::InsideAuthoredBody)));
    // A second retained install replaces the reading; each slot
    // keeps its own zone.
    b.set_payload(r, &second_install).unwrap();
    assert!(matches!(b.payload_bytes(first_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(second_inner) } = b.descend(r).unwrap() else {
        panic!("second retained interior opens")
    };
    let Descent::Opened { first: Some(second_leaf) } = b.descend(second_inner).unwrap() else {
        panic!("nested second retained interior opens")
    };
    assert_eq!(b.varint_word(second_leaf).unwrap(), 99, "depth two reads the second slot");
    // revert to the first install: its slot answers again.
    b.revert();
    let Descent::Opened { first: Some(again) } = b.descend(r).unwrap() else {
        panic!("first retained interior reopens")
    };
    assert_eq!(b.payload_bytes(again).unwrap(), h("08 07"));
    // revert to the source: scanned bytes speak again.
    b.revert();
    let Descent::Opened { first: Some(back) } = b.descend(r).unwrap() else {
        panic!("source interior reopens")
    };
    assert_eq!(b.varint_word(back).unwrap(), 1);
    assert_eq!(b.save().unwrap()[..], doc[..]);
}

#[test]
fn the_borrow_twins_import_retains_the_designation_in_its_own_slot() {
    // The producer outlives the borrower; the import is retained as
    // a borrowed slot whose interior parses at slot-relative
    // offsets, and the exact designation bytes emit whole at save.
    let outside = open(&h("22 02 08 07"));
    let source = outside.top().next().unwrap();
    let doc = h("08 2A");
    let mut b = TransferBorrowSession::open_copy(&doc).unwrap();
    let imported = b
        .copy_record_from(
            outside.record_ref(source).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    assert_eq!(b.status(imported).unwrap(), EditStatus::Inserted);
    assert_eq!(b.payload_bytes(imported).unwrap(), h("08 07"));
    let Descent::Opened { first: Some(inner) } = b.descend(imported).unwrap() else {
        panic!("imported interior opens")
    };
    assert_eq!(b.varint_word(inner).unwrap(), 7, "the interior reads through the retained slot");
    assert_eq!(b.save().unwrap()[..], h("08 2A 22 02 08 07")[..]);
    // One command, one step: the revert ghosts the import.
    b.revert();
    assert_eq!(b.status(imported).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(b.save().unwrap()[..], doc[..]);
}

// ─── the priced wrapper, in lockstep with the plain twin ───

#[cfg(feature = "priced-transfer-session-groupless")]
mod priced {
    use super::*;

    use crate::session::groupless::PricedTransferSession;

    #[track_caller]
    fn priced(data: &[u8]) -> PricedTransferSession {
        TransferSession::open_copy(data)
            .expect("test document opens")
            .into_priced()
            .map_err(|(_, fault)| fault)
            .expect("clean admits")
    }

    struct PricedTwins {
        priced: PricedTransferSession,
        base: TransferSession,
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
            priced_cmd: impl FnOnce(&mut PricedTransferSession),
            base_cmd: impl FnOnce(&mut TransferSession),
        ) {
            priced_cmd(&mut self.priced);
            base_cmd(&mut self.base);
            self.judge();
        }
    }

    #[test]
    fn priced_lockstep_covers_the_transfer_arc_family() {
        // varint f1 · LEN f2 { varint f1 } · LEN f3 "ab": scalars and
        // containers for every transfer face, moves interleaved with
        // ordinary commands and unwound through the coupling.
        let data = h("08 01 12 02 08 07 1A 02 61 62");
        let mut t = PricedTwins::open(&data);
        let tops: Vec<Handle> = t.priced.top().collect();

        // Local copies: a scalar and a container.
        t.lockstep(
            |p| {
                p.copy_record(tops[0], InsertAt::TailOf(None)).unwrap();
            },
            |b| {
                b.copy_record(tops[0], InsertAt::TailOf(None)).unwrap();
            },
        );
        t.lockstep(
            |p| {
                p.copy_record(tops[1], InsertAt::HeadOf(None)).unwrap();
            },
            |b| {
                b.copy_record(tops[1], InsertAt::HeadOf(None)).unwrap();
            },
        );
        // A move, an ordinary edit above it, then payload transfers.
        t.lockstep(
            |p| {
                p.move_record(tops[0], InsertAt::After(tops[2])).unwrap();
            },
            |b| {
                b.move_record(tops[0], InsertAt::After(tops[2])).unwrap();
            },
        );
        t.lockstep(
            |p| {
                p.set_varint(tops[0], 5).unwrap_err();
            },
            |b| {
                b.set_varint(tops[0], 5).unwrap_err();
            },
        );
        t.lockstep(
            |p| {
                p.copy_payload(tops[2], PayloadTarget::Replace(tops[1])).unwrap();
            },
            |b| {
                b.copy_payload(tops[2], PayloadTarget::Replace(tops[1])).unwrap();
            },
        );
        t.lockstep(
            |p| {
                p.copy_payload(
                    tops[1],
                    PayloadTarget::Insert { at: InsertAt::TailOf(None), field: fnum(4) },
                )
                .unwrap();
            },
            |b| {
                b.copy_payload(
                    tops[1],
                    PayloadTarget::Insert { at: InsertAt::TailOf(None), field: fnum(4) },
                )
                .unwrap();
            },
        );
        t.lockstep(
            |p| {
                p.move_payload(tops[2], InsertAt::HeadOf(None), fnum(5)).unwrap();
            },
            |b| {
                b.move_payload(tops[2], InsertAt::HeadOf(None), fnum(5)).unwrap();
            },
        );
        // A cross-machine import through the canonical proof.
        let outside = open(&h("22 03 78 79 7A"));
        let source = outside.top().next().unwrap();
        t.lockstep(
            |p| {
                p.copy_record_from(
                    outside.record_ref(source).unwrap().try_canonical().unwrap(),
                    InsertAt::TailOf(None),
                )
                .unwrap();
            },
            |b| {
                b.copy_record_from(
                    outside.record_ref(source).unwrap().try_canonical().unwrap(),
                    InsertAt::TailOf(None),
                )
                .unwrap();
            },
        );
        // Unwind the whole arc: every revert settles one delta, the
        // move coupling included.
        while t.priced.pending() > 0 {
            t.lockstep(
                |p| {
                    p.revert().unwrap();
                },
                |b| {
                    b.revert().unwrap();
                },
            );
        }
        assert_eq!(t.priced.save().unwrap()[..], data[..]);
    }

    #[test]
    fn priced_lockstep_covers_a_first_class_import_arc() {
        // Import a LEN, descend it, and edit inside: the settled
        // price follows the re-derived framing through the zone rows.
        let outside = open(&h("22 02 08 07"));
        let source = outside.top().next().unwrap();
        let data = h("08 01");
        let mut t = PricedTwins::open(&data);
        t.lockstep(
            |p| {
                let record = outside.record_ref(source).unwrap().try_canonical().unwrap();
                p.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
            },
            |b| {
                let record = outside.record_ref(source).unwrap().try_canonical().unwrap();
                b.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
            },
        );
        let import_p = t.priced.top().nth(1).unwrap();
        let import_b = t.base.top().nth(1).unwrap();
        let mut inner_p = None;
        let mut inner_b = None;
        t.lockstep(
            |p| {
                let Descent::Opened { first } = p.descend(import_p).unwrap() else {
                    panic!("imported interior opens")
                };
                inner_p = first;
            },
            |b| {
                let Descent::Opened { first } = b.descend(import_b).unwrap() else {
                    panic!("imported interior opens")
                };
                inner_b = first;
            },
        );
        let (inner_p, inner_b) = (inner_p.unwrap(), inner_b.unwrap());
        t.lockstep(
            |p| {
                p.set_varint(inner_p, 300).unwrap();
            },
            |b| {
                b.set_varint(inner_b, 300).unwrap();
            },
        );
        t.lockstep(
            |p| {
                p.insert_varint(InsertAt::TailOf(Some(import_p)), fnum(2), 1).unwrap();
            },
            |b| {
                b.insert_varint(InsertAt::TailOf(Some(import_b)), fnum(2), 1).unwrap();
            },
        );
        while t.priced.pending() > 0 {
            t.lockstep(
                |p| {
                    p.revert().unwrap();
                },
                |b| {
                    b.revert().unwrap();
                },
            );
        }
        assert_eq!(t.priced.save().unwrap()[..], data[..]);
    }
}
