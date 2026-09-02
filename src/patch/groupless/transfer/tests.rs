//! The transfer sibling' behavioral rows.

use super::*;
#[allow(unused_imports)]
use super::super::tests::*;

fn open(data: &[u8]) -> TransferPatch<'_, 'static> {
    TransferPatch::open(data, DepthLimit::REFERENCE).expect("test document opens")
}

fn tops(p: &TransferPatch<'_, '_>) -> Vec<Handle> {
    p.top().collect()
}

#[track_caller]
fn saved(p: &TransferPatch<'_, '_>) -> Vec<u8> {
    p.save().expect("test save succeeds")
}

#[test]
fn a_copied_record_contributes_its_exact_source_bytes() {
    // Padded corpus: padded tag, padded value, padded LEN prefix,
    // nested padded LEN inside an opaque interior.
    for record in ["88 00 01", "08 96 81 00", "12 82 00 68 69", "12 04 12 82 00 61"] {
        let mut data = h("18 07 ");
        let body = h(record);
        data.extend_from_slice(&body);
        let mut p = open(&data);
        let t = tops(&p);
        let copy = p.copy_record(t[1], InsertAt::HeadOf(None)).unwrap();

        // The identity answers speak the authored side.
        assert_eq!(p.status(copy), EditStatus::Inserted);
        assert_eq!(p.span(copy), None);
        assert_eq!(p.source_spans(copy), None);
        assert!(matches!(
            p.record_ref(copy),
            Err(crate::source::groupless::Fault::NotSourceBacked)
        ));

        // The save carries the copy byte-exactly, located by its
        // save span.
        let spans = p.save_spans().unwrap();
        let (_, span) = spans.iter().find(|(handle, _)| *handle == copy).unwrap();
        let out = saved(&p);
        assert_eq!(&out[span.as_range()], body.as_slice(), "record fidelity for {record}");
        assert_eq!(out.len(), data.len() + body.len());
    }
}
#[test]
fn a_copy_names_the_source_reading_never_the_pending_edit() {
    let data = h("08 05 10 06");
    let mut p = open(&data);
    let t = tops(&p);
    p.set_varint(t[0], 99).unwrap();
    p.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(saved(&p), h("08 63 10 06 08 05"), "the copy carries the original value");
}
#[test]
fn move_equals_copy_plus_delete_on_a_fresh_twin() {
    let data = h("08 96 81 00 12 02 68 69 18 07");
    let anchors = |p: &TransferPatch<'_, '_>| tops(p);
    for source in 0..3usize {
        for target in 0..3usize {
            if source == target {
                continue;
            }
            let mut moved = open(&data);
            let t = anchors(&moved);
            moved.move_record(t[source], InsertAt::After(t[target])).unwrap();

            let mut twin = open(&data);
            let t = anchors(&twin);
            twin.copy_record(t[source], InsertAt::After(t[target])).unwrap();
            twin.delete(t[source]).unwrap();

            assert_eq!(
                moved.save().unwrap(),
                twin.save().unwrap(),
                "move({source}) after {target} diverged from copy+delete"
            );
        }
    }
}
#[test]
fn a_moved_source_reads_deleted_and_refuses_further_commands() {
    let data = h("08 05 10 06");
    let mut p = open(&data);
    let t = tops(&p);
    let dest = p.move_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(p.status(t[0]), EditStatus::Deleted);
    assert_eq!(p.status(dest), EditStatus::Inserted);
    assert!(matches!(p.set_varint(t[0], 1), Err(EditFault::DeletedTarget)));
    assert!(matches!(p.move_record(t[0], InsertAt::TailOf(None)), Err(EditFault::SourceModified)));
}
#[test]
fn moves_refuse_modified_sources_and_their_own_subtrees() {
    // LEN f2 { varint f1 } · varint f3.
    let data = h("12 02 08 01 18 07");
    let mut p = open(&data);
    let t = tops(&p);

    // An edited source refuses the move but not the copy.
    p.set_varint(t[1], 9).unwrap();
    assert!(matches!(p.move_record(t[1], InsertAt::HeadOf(None)), Err(EditFault::SourceModified)));
    assert!(p.copy_record(t[1], InsertAt::HeadOf(None)).is_ok());

    // An interior edit dirties the subtree: the container refuses.
    let Descent::Opened { first: Some(inner) } = p.descend(t[0]).unwrap() else { unreachable!() };
    p.set_varint(inner, 2).unwrap();
    assert!(matches!(p.move_record(t[0], InsertAt::TailOf(None)), Err(EditFault::SourceModified)));

    // A gap owned by the source's own subtree refuses; the gap
    // right after the source is lawful.
    let fresh = h("12 02 08 01 18 07");
    let mut p = open(&fresh);
    let t = tops(&p);
    let Descent::Opened { first: Some(inner) } = p.descend(t[0]).unwrap() else { unreachable!() };
    assert!(matches!(
        p.move_record(t[0], InsertAt::TailOf(Some(t[0]))),
        Err(EditFault::MoveIntoSource)
    ));
    assert!(matches!(p.move_record(t[0], InsertAt::After(inner)), Err(EditFault::MoveIntoSource)));
    let relocated = p.move_record(t[0], InsertAt::After(t[0])).unwrap();
    assert_eq!(p.save().unwrap(), fresh, "a move right after its source is output-equivalent");
    assert_eq!(p.status(relocated), EditStatus::Inserted);
}
#[test]
fn copied_interiors_start_opaque_and_descend_on_the_retained_bytes() {
    // LEN f2 { varint f1=1 }, descended and edited in the source.
    let data = h("12 02 08 01");
    let mut p = open(&data);
    let t = tops(&p);
    let Descent::Opened { first: Some(inner) } = p.descend(t[0]).unwrap() else { unreachable!() };
    p.set_varint(inner, 9).unwrap();

    // The copy starts opaque and carries the source reading.
    let copy = p.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    assert_eq!(p.children(copy).count(), 0, "the copy's interior starts opaque");

    // Descending the copy parses the retained source-backed bytes;
    // its rows are output-authored and editable.
    let Descent::Opened { first: Some(copy_inner) } = p.descend(copy).unwrap() else {
        unreachable!()
    };
    assert_eq!(p.status(copy_inner), EditStatus::Inserted);
    assert_eq!(p.span(copy_inner), None);
    assert_eq!(p.varint_word(copy_inner), Some(1), "the retained interior is the source reading");
    p.set_varint(copy_inner, 5).unwrap();
    assert_eq!(saved(&p), h("12 02 08 09 12 02 08 05"));
}
#[test]
fn narrowest_never_names_a_copy() {
    let data = h("08 05");
    let mut p = open(&data);
    let t = tops(&p);
    let copy = p.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    let named = p.narrowest(0).unwrap();
    assert_eq!(named, t[0], "reverse lookup names the original occurrence");
    assert_ne!(named, copy);
}
#[test]
fn copy_payload_replaces_and_inserts_with_exact_interiors() {
    // LEN f1 with a nested padded LEN inside · LEN f2 "no".
    let data = h("0A 04 12 82 00 61 12 02 6E 6F");
    let mut p = open(&data);
    let t = tops(&p);

    // Replace: the target keeps its own tag; same-length interiors
    // keep the prefix verbatim rule out of play here (lengths move).
    p.copy_payload(t[0], PayloadTarget::Replace(t[1])).unwrap();
    assert_eq!(p.status(t[1]), EditStatus::Replaced);
    assert_eq!(p.payload_bytes(t[1]).unwrap(), h("12 82 00 61").as_slice());

    // Insert: a fresh minimal record under the supplied field.
    let fresh = p
        .copy_payload(t[0], PayloadTarget::Insert { at: InsertAt::TailOf(None), field: fnum(3) })
        .unwrap();
    assert_eq!(p.status(fresh), EditStatus::Inserted);
    assert_eq!(
        saved(&p),
        h("0A 04 12 82 00 61 12 04 12 82 00 61 1A 04 12 82 00 61"),
        "payload fidelity: interiors byte-exact behind destination framing"
    );
}
#[test]
fn copy_payload_matches_the_two_machine_composition() {
    let data = h("0A 03 61 62 63 12 01 7A");
    // The local coordinate face.
    let mut local = open(&data);
    let t = tops(&local);
    local.copy_payload(t[0], PayloadTarget::Replace(t[1])).unwrap();

    // The existing payload_bytes + set_payload composition.
    let mut composed = open(&data);
    let t2 = tops(&composed);
    let interior = composed.payload_bytes(t2[0]).unwrap().to_vec();
    composed.set_payload_copy(t2[1], &interior).unwrap();

    assert_eq!(local.save().unwrap(), composed.save().unwrap());
}
#[test]
fn move_payload_relocates_the_interior_and_suppresses_the_record() {
    let data = h("08 05 12 02 68 69");
    let mut p = open(&data);
    let t = tops(&p);
    let dest = p.move_payload(t[1], InsertAt::HeadOf(None), fnum(4)).unwrap();
    assert_eq!(p.status(t[1]), EditStatus::Deleted);
    assert_eq!(p.payload_bytes(dest).unwrap(), b"hi");
    assert_eq!(saved(&p), h("22 02 68 69 08 05"));

    // The differential: copy-to-gap plus delete on a fresh twin.
    let mut twin = open(&data);
    let t = tops(&twin);
    twin.copy_payload(t[1], PayloadTarget::Insert { at: InsertAt::HeadOf(None), field: fnum(4) })
        .unwrap();
    twin.delete(t[1]).unwrap();
    assert_eq!(twin.save().unwrap(), saved(&p));
}
#[test]
fn transfer_sources_must_be_original_occurrences() {
    let data = h("08 05 12 01 61");
    let mut p = open(&data);
    let t = tops(&p);
    let authored = p.insert_payload(InsertAt::TailOf(None), fnum(3), &[0x01]).unwrap();
    assert!(matches!(
        p.copy_record(authored, InsertAt::TailOf(None)),
        Err(EditFault::SourceNotBacked)
    ));
    assert!(matches!(
        p.copy_payload(authored, PayloadTarget::Replace(t[1])),
        Err(EditFault::SourceNotBacked)
    ));
    assert!(matches!(
        p.move_payload(t[0], InsertAt::TailOf(None), fnum(3)),
        Err(EditFault::KindMismatch { .. })
    ));

    let copy = p.copy_record(t[1], InsertAt::TailOf(None)).unwrap();
    assert!(matches!(p.copy_record(copy, InsertAt::TailOf(None)), Err(EditFault::SourceNotBacked)));
}
#[cfg(feature = "inspect-groupless")]
#[test]
fn an_imported_record_rides_byte_exact_and_answers_reads() {
    use crate::inspect::groupless::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    // A padded foreign record, designated from an inspect tree.
    let foreign = h("10 96 81 00");
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let record = tree.record_ref(tree.top().next().unwrap()).unwrap();

    let data = h("08 05");
    let mut p = open(&data);
    let imported = p.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    assert_eq!(p.status(imported), EditStatus::Inserted);
    assert_eq!(p.span(imported), None);
    assert_eq!(p.varint_word(imported), Some(150), "reads decode the imported value");
    assert_eq!(saved(&p), h("08 05 10 96 81 00"), "the padded spelling rides byte-exact");

    // The copying twin severs the designation's lifetime.
    let mut copied = open(&data);
    let imported = copied.copy_record_from_copy(record, InsertAt::HeadOf(None)).unwrap();
    drop(tree);
    assert_eq!(copied.status(imported), EditStatus::Inserted);
    assert_eq!(copied.save().unwrap(), h("10 96 81 00 08 05"));
}
#[cfg(feature = "inspect-groupless")]
#[test]
fn the_canonical_save_normalizes_imported_framing() {
    use crate::inspect::groupless::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    // Padded varint import and padded-prefix LEN import: the
    // fidelity save keeps them; the canonical save re-emits the
    // framing minimally while the LEN interior rides opaque.
    let foreign = h("10 96 81 00 1A 82 00 88 00");
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let ids: Vec<_> = tree.top().collect();

    let data = h("08 05");
    let mut p = open(&data);
    p.copy_record_from(tree.record_ref(ids[0]).unwrap(), InsertAt::TailOf(None)).unwrap();
    p.copy_record_from(tree.record_ref(ids[1]).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(saved(&p), h("08 05 10 96 81 00 1A 82 00 88 00"));
    assert_eq!(p.save_canonical().unwrap(), h("08 05 10 96 01 1A 02 88 00"));
}
#[cfg(feature = "inspect-groupless")]
#[test]
fn an_imported_record_takes_ordinary_commands_as_an_insertion() {
    use crate::inspect::groupless::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    let foreign = h("10 96 81 00");
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let record = tree.record_ref(tree.top().next().unwrap()).unwrap();

    let data = h("08 05");
    let mut p = open(&data);
    let imported = p.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    p.set_varint(imported, 7).unwrap();
    assert_eq!(p.status(imported), EditStatus::Inserted);
    assert_eq!(saved(&p), h("08 05 10 07"), "a re-set import re-authors minimally");
    assert!(matches!(p.descend(imported), Err(EditFault::KindMismatch { .. })));
}
#[cfg(feature = "inspect-groupless")]
#[test]
fn imported_len_interiors_edit_after_descent() {
    use crate::inspect::groupless::Tree;
    use crate::inspect::{Admitted, NoAdvice};

    // A padded-prefix LEN import: the slot rides byte-exact while
    // clean; a first-class interior edit walks the slot rows, keeps
    // the met tag, and re-derives the prefix only when the body
    // length moves.
    let foreign = h("1A 82 00 08 01");
    let input = Admitted::new(&foreign).unwrap();
    let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    let record = tree.record_ref(tree.top().next().unwrap()).unwrap();

    let data = h("08 05");
    let mut p = open(&data);
    let imported = p.copy_record_from(record, InsertAt::TailOf(None)).unwrap();
    assert_eq!(saved(&p), h("08 05 1A 82 00 08 01"), "clean imports ride byte-exact");
    let Descent::Opened { first: Some(inner) } = p.descend(imported).unwrap() else {
        panic!("imported interior opens")
    };
    assert_eq!(p.varint_word(inner), Some(1), "the interior reads through the slot");
    // Same body length: the padded met prefix rides verbatim.
    p.set_varint(inner, 7).unwrap();
    assert_eq!(saved(&p), h("08 05 1A 82 00 08 07"));
    // A growing body re-derives the prefix minimally.
    p.insert_varint(InsertAt::TailOf(Some(imported)), fnum(2), 2).unwrap();
    assert_eq!(saved(&p), h("08 05 1A 04 08 07 10 02"));
}
