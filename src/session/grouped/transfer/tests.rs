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
fn group_closures_copy_move_and_revert_whole() {
    // group f1 { varint f2=5 · group f3 { varint f2=1 } } · varint f4.
    let data = h("0B 10 05 1B 10 01 1C 0C 20 09");
    let mut s = open(&data);
    let t = tops(&s);
    let copy = s.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(s.pending(), 1);
    assert_eq!(s.status(copy).unwrap(), EditStatus::Inserted);
    assert_eq!(s.span(copy).unwrap(), None);
    assert_eq!(
        s.save().unwrap()[..],
        h("0B 10 05 1B 10 01 1C 0C 20 09 0B 10 05 1B 10 01 1C 0C")[..]
    );
    // The clone's members are first-class: nested edits walk between
    // the cloned framing tags, and the source keeps its reading.
    let Descent::Opened { first: Some(first) } = s.descend(copy).unwrap() else { unreachable!() };
    s.set_varint(first, 7).unwrap();
    assert_eq!(
        s.save().unwrap()[..],
        h("0B 10 05 1B 10 01 1C 0C 20 09 0B 10 07 1B 10 01 1C 0C")[..]
    );
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], data[..]);
    // One move, one revert, both sides restored.
    let dest = s.move_record(t[0], InsertAt::After(t[1])).unwrap();
    assert_eq!(s.pending(), 1);
    assert_eq!(s.status(t[0]).unwrap(), EditStatus::Moved);
    assert_eq!(s.save().unwrap()[..], h("20 09 0B 10 05 1B 10 01 1C 0C")[..]);
    assert_eq!(s.revert(), Some(t[0]));
    assert_eq!(s.status(dest).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(s.save().unwrap()[..], data[..]);
}
#[test]
fn a_closure_copy_takes_the_source_reading_alone() {
    // group f1 { varint f2=5 }: an authored member inside the source
    // group is pending output, not source bytes — the copy omits it,
    // a shrouded member rides (shrouding is an edit too).
    let data = h("0B 10 05 10 06 0C");
    let mut s = open(&data);
    let t = tops(&s);
    let members: Vec<Handle> = s.children(t[0]).unwrap().collect();
    s.insert_varint(InsertAt::TailOf(Some(t[0])), fnum(2), 9).unwrap();
    s.delete(members[1]).unwrap();
    let copy = s.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(
        s.save().unwrap()[..],
        // Source: f2=5 stays, f2=6 shrouded, f2=9 authored; the copy
        // re-emits the exact source closure.
        h("0B 10 05 10 09 0C 0B 10 05 10 06 0C")[..]
    );
    // The copy's members answer the source reading.
    let clones: Vec<Handle> = s.children(copy).unwrap().collect();
    assert_eq!(clones.len(), 2);
    assert_eq!(s.varint_word(clones[1]).unwrap(), 6);
    assert_eq!(s.status(clones[1]).unwrap(), EditStatus::Inserted);
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], data[..]);
}
#[test]
fn moves_refuse_edited_closures_and_their_own_interior_gaps() {
    let data = h("0B 10 05 0C 20 09");
    let mut s = open(&data);
    let t = tops(&s);
    let member = s.children(t[0]).unwrap().next().unwrap();
    s.set_varint(member, 6).unwrap();
    assert!(matches!(s.move_record(t[0], InsertAt::After(t[1])), Err(EditFault::SourceModified)));
    s.revert();
    assert!(matches!(
        s.move_record(t[0], InsertAt::TailOf(Some(t[0]))),
        Err(EditFault::MoveIntoSource)
    ));
    let dest = s.move_record(t[0], InsertAt::After(t[0])).unwrap();
    assert_eq!(s.save().unwrap()[..], data[..]);
    assert_eq!(s.status(dest).unwrap(), EditStatus::Inserted);
}
#[test]
fn payload_designations_ride_groups_only_through_len_records() {
    // LEN f1 "hi" · group f2 { LEN f1 "no" }.
    let data = h("0A 02 68 69 13 0A 02 6E 6F 14");
    let mut s = open(&data);
    let t = tops(&s);
    // A group has no payload to designate.
    assert!(matches!(
        s.copy_payload(t[1], PayloadTarget::Replace(t[0])),
        Err(EditFault::KindMismatch { .. })
    ));
    // A LEN inside a group designates fine, and the designation lands
    // inside a group too.
    let inner = s.children(t[1]).unwrap().next().unwrap();
    s.copy_payload(t[0], PayloadTarget::Replace(inner)).unwrap();
    assert_eq!(s.payload_bytes(inner).unwrap(), b"hi");
    assert_eq!(s.save().unwrap()[..], h("0A 02 68 69 13 0A 02 68 69 14")[..]);
    let fresh = s
        .copy_payload(
            inner,
            PayloadTarget::Insert { at: InsertAt::TailOf(Some(t[1])), field: fnum(3) },
        )
        .unwrap();
    assert_eq!(s.payload_bytes(fresh).unwrap(), b"no");
    assert_eq!(s.save().unwrap()[..], h("0A 02 68 69 13 0A 02 68 69 1A 02 6E 6F 14")[..]);
    s.revert_all();
    assert_eq!(s.save().unwrap()[..], data[..]);
}
#[test]
fn imported_group_closures_open_first_class() {
    // Machine A designates a group; machine B imports the closure.
    let source_doc = h("0B 10 05 1B 10 01 1C 0C");
    let a = open(&source_doc);
    let sa = a.top().next().unwrap();
    let data = h("08 01");
    let mut b = open(&data);
    let import = b
        .copy_record_from(
            a.record_ref(sa).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    assert_eq!(b.pending(), 1);
    assert_eq!(b.status(import).unwrap(), EditStatus::Inserted);
    assert_eq!(b.save().unwrap()[..], h("08 01 0B 10 05 1B 10 01 1C 0C")[..]);
    // Group structure is structural: the closure parses between the
    // tags into first-class rows, edits and insertions land inside,
    // and the save re-derives both tags around the walked interior.
    let Descent::Opened { first: Some(inner) } = b.descend(import).unwrap() else {
        panic!("imported group interior opens")
    };
    assert_eq!(b.varint_word(inner).unwrap(), 5);
    b.set_varint(inner, 9).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0B 10 09 1B 10 01 1C 0C")[..]);
    b.insert_varint(InsertAt::TailOf(Some(import)), fnum(2), 1).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0B 10 09 1B 10 01 1C 10 01 0C")[..]);
    b.revert_all();
    assert_eq!(b.save().unwrap()[..], data[..]);
}
#[test]
fn designation_depth_ignores_authored_and_copied_structure() {
    // group f1 { varint f2=5 } · group f3 {} — each closure depth 1.
    let data = h("0B 10 05 0C 1B 1C");
    let mut s = open(&data);
    let t = tops(&s);
    assert_eq!(s.record_ref(t[0]).unwrap().group_depth(), 1);
    // An authored group and a copied closure land inside the
    // designated group; the designation still names the source
    // reading.
    s.insert_group(InsertAt::TailOf(Some(t[0])), fnum(9)).unwrap();
    s.copy_record(t[1], InsertAt::TailOf(Some(t[0]))).unwrap();
    assert_eq!(s.record_ref(t[0]).unwrap().group_depth(), 1);
    assert_eq!(s.save().unwrap()[..], h("0B 10 05 4B 4C 1B 1C 0C 1B 1C")[..]);
}
#[test]
fn imported_len_interiors_edit_after_descent() {
    let source_doc = h("0A 02 08 07");
    let a = open(&source_doc);
    let sa = a.top().next().unwrap();
    let mut b = open(&h("08 01"));
    let import = b
        .copy_record_from(
            a.record_ref(sa).unwrap().try_canonical().unwrap(),
            InsertAt::TailOf(None),
        )
        .unwrap();
    assert_eq!(b.payload_bytes(import).unwrap(), h("08 07"));
    let Descent::Opened { first: Some(inner) } = b.descend(import).unwrap() else { unreachable!() };
    assert_eq!(b.varint_word(inner).unwrap(), 7);
    // First-class: the edit lands and the save re-derives the import's
    // framing around the walked interior.
    b.set_varint(inner, 1).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0A 02 08 01")[..]);
    b.revert();
    assert_eq!(b.save().unwrap()[..], h("08 01 0A 02 08 07")[..]);
}
#[test]
fn descents_reach_the_live_staged_extent_over_each_install() {
    // LEN f2 wrapping varint f1=1, beside a group.
    let doc = h("12 02 08 01 0B 0C");
    // A nested payload whose interior holds a group closure.
    let nested = h("12 04 0B 08 07 0C");
    let mut s = TransferSession::open_copy(&doc).unwrap();
    let r = s.top().next().unwrap();
    let Descent::Opened { first: Some(source_inner) } = s.descend(r).unwrap() else {
        panic!("source interior opens")
    };
    assert_eq!(s.varint_word(source_inner).unwrap(), 1);
    // An install stages its own copy of the bytes — a LEN wrapping
    // a group, whose own layer materializes at the scan of the
    // staged extent.
    s.set_payload(r, &nested).unwrap();
    assert!(matches!(s.varint_word(source_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(first_inner) } = s.descend(r).unwrap() else {
        panic!("staged interior opens")
    };
    let Descent::Opened { first: Some(inner_group) } = s.descend(first_inner).unwrap() else {
        panic!("nested staged interior opens")
    };
    let leaf = s.children(inner_group).unwrap().next().unwrap();
    assert_eq!(s.varint_word(leaf).unwrap(), 7, "depth two reads the staged extent");
    assert!(matches!(s.set_varint(leaf, 9), Err(EditFault::InsideAuthoredBody)));
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
    let Descent::Opened { first: Some(second_leaf) } = s.descend(second_inner).unwrap() else {
        panic!("nested second staged interior opens")
    };
    assert_eq!(s.varint_word(second_leaf).unwrap(), 99, "depth two reads the second extent");
    // Unwind: the first staged extent, then the scanned source.
    s.revert();
    let Descent::Opened { first: Some(again) } = s.descend(r).unwrap() else {
        panic!("first staged interior reopens")
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
fn imported_records_stage_the_designation_and_answer_the_walk() {
    // A cross-machine import stages its own copy of the designated
    // bytes; the interior parses into first-class rows and the exact
    // designation bytes emit whole at save.
    let outside = open(&h("22 02 08 07"));
    let source = outside.top().next().unwrap();
    let doc = h("08 2A 0B 0C");
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
    assert_eq!(s.save().unwrap()[..], h("08 2A 0B 0C 22 02 08 07")[..]);
    // A first-class interior edit re-derives the framing around the
    // changed row and reverts to the wholesale reading.
    s.set_varint(inner, 9).unwrap();
    assert_eq!(s.save().unwrap()[..], h("08 2A 0B 0C 22 02 08 09")[..]);
    s.revert();
    assert_eq!(s.save().unwrap()[..], h("08 2A 0B 0C 22 02 08 07")[..]);
    s.revert();
    assert_eq!(s.status(imported).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(s.save().unwrap()[..], doc[..]);
}

// ─── the borrowed twin over slot-local zones ───

#[test]
fn the_borrow_twin_walks_the_import_arc_over_its_slot_zone() {
    // The producer outlives the borrower; the imported closure is
    // retained, and its interior parses at slot-relative offsets
    // between the group tags.
    let source_doc = h("0B 10 05 1B 10 01 1C 0C");
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
    assert_eq!(b.save().unwrap()[..], h("08 01 0B 10 05 1B 10 01 1C 0C")[..]);

    // The retained closure parses into first-class rows: reads,
    // value edits, insertions, and the shroud pair all land inside,
    // and every step's save re-derives both tags byte-exact.
    let Descent::Opened { first: Some(first) } = b.descend(import).unwrap() else {
        panic!("imported group interior opens")
    };
    assert_eq!(b.varint_word(first).unwrap(), 5);
    b.set_varint(first, 9).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0B 10 09 1B 10 01 1C 0C")[..]);
    b.insert_varint(InsertAt::TailOf(Some(import)), fnum(2), 1).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0B 10 09 1B 10 01 1C 10 01 0C")[..]);
    let interior: Vec<Handle> = b.children(import).unwrap().collect();
    b.delete(interior[1]).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0B 10 09 10 01 0C")[..]);
    b.undelete(interior[1]).unwrap();
    assert_eq!(b.save().unwrap()[..], h("08 01 0B 10 09 1B 10 01 1C 10 01 0C")[..]);
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
    // LEN f2 wrapping varint f1=1, beside a group.
    let doc = h("12 02 08 01 0B 0C");
    // Two long-lived payloads: every install is retained, each in
    // its own slot, so both must outlive the machine. The first
    // nests a group closure inside its LEN.
    let first_install = h("12 04 0B 08 07 0C");
    let second_install = h("12 02 08 63");
    let mut b = TransferBorrowSession::open_copy(&doc).unwrap();
    let r = b.top().next().unwrap();
    let Descent::Opened { first: Some(source_inner) } = b.descend(r).unwrap() else {
        panic!("source interior opens")
    };
    assert_eq!(b.varint_word(source_inner).unwrap(), 1);
    // An install retains the caller's slice: the old tree orphans
    // whole, and the re-descended interior — the group layer
    // included — parses at slot-relative offsets inside it.
    b.set_payload(r, &first_install).unwrap();
    assert!(matches!(b.varint_word(source_inner), Err(EditFault::DeadHandle)));
    let Descent::Opened { first: Some(first_inner) } = b.descend(r).unwrap() else {
        panic!("retained interior opens")
    };
    let Descent::Opened { first: Some(inner_group) } = b.descend(first_inner).unwrap() else {
        panic!("nested retained interior opens")
    };
    let leaf = b.children(inner_group).unwrap().next().unwrap();
    assert_eq!(b.varint_word(leaf).unwrap(), 7, "depth two reads the retained slot");
    assert!(matches!(b.set_varint(leaf, 9), Err(EditFault::InsideAuthoredBody)));
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
    // Unwind: the first retained slot, then the scanned source.
    b.revert();
    let Descent::Opened { first: Some(again) } = b.descend(r).unwrap() else {
        panic!("first retained interior reopens")
    };
    assert_eq!(b.payload_bytes(again).unwrap(), h("0B 08 07 0C"));
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
    let doc = h("08 2A 0B 0C");
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
    assert_eq!(b.save().unwrap()[..], h("08 2A 0B 0C 22 02 08 07")[..]);
    // One command, one step: the revert ghosts the import.
    b.revert();
    assert_eq!(b.status(imported).unwrap(), EditStatus::InsertedDeleted);
    assert_eq!(b.save().unwrap()[..], doc[..]);
}

// ─── the priced wrapper, in lockstep with the plain twin ───

#[cfg(feature = "priced-transfer-session-grouped")]
mod priced {
    use super::*;

    use crate::session::grouped::PricedTransferSession;

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
    fn priced_lockstep_covers_the_transfer_arc_family_over_groups() {
        // group f1 { varint f2=5 } · LEN f3 "ab" · varint f4: a
        // closure move through group levels, payload transfers, an
        // import, and the unwind through the coupling.
        let data = h("0B 10 05 0C 1A 02 61 62 20 09");
        let mut t = PricedTwins::open(&data);
        let tops: Vec<Handle> = t.priced.top().collect();

        t.lockstep(
            |p| {
                p.copy_record(tops[0], InsertAt::TailOf(None)).unwrap();
            },
            |b| {
                b.copy_record(tops[0], InsertAt::TailOf(None)).unwrap();
            },
        );
        // Move the group inside its sibling group copy's parent chain
        // stays lawful; move it after the scalar.
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
                p.copy_payload(
                    tops[1],
                    PayloadTarget::Insert { at: InsertAt::HeadOf(None), field: fnum(5) },
                )
                .unwrap();
            },
            |b| {
                b.copy_payload(
                    tops[1],
                    PayloadTarget::Insert { at: InsertAt::HeadOf(None), field: fnum(5) },
                )
                .unwrap();
            },
        );
        t.lockstep(
            |p| {
                p.move_payload(tops[1], InsertAt::TailOf(None), fnum(6)).unwrap();
            },
            |b| {
                b.move_payload(tops[1], InsertAt::TailOf(None), fnum(6)).unwrap();
            },
        );
        // An imported group closure prices its exact byte count.
        let outside = open(&h("3B 08 01 3C"));
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
        // Import a group, descend it, and edit inside: the settled
        // price follows the re-derived interior through the zone rows
        // while both met tags stay verbatim.
        let outside = open(&h("0B 10 05 0C"));
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
