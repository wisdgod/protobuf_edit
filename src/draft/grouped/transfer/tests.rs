//! The transfer siblings' behavioral rows.

use alloc::vec::Vec;

use super::{Descent, Handle, InsertAt, PayloadTarget, TransferBorrowDraft, TransferDraft};
use crate::wire::FieldNumber;

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
fn all_saves(draft: &TransferDraft) -> Vec<u8> {
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

#[test]
fn transfers_preserve_padded_source_framing_byte_exact() {
    // group f1 (padded open tag) { varint f2 (padded value) } ·
    // LEN f3 (padded prefix) "hi" · varint f4.
    let data = h("8B 00 10 81 00 0C 1A 82 00 68 69 20 09");
    let mut d = TransferDraft::open_copy(&data).unwrap();
    let t: Vec<Handle> = d.top().collect();
    // The copied closure keeps every met width.
    d.copy_record(t[0], InsertAt::TailOf(None)).unwrap();
    d.copy_record(t[1], InsertAt::TailOf(None)).unwrap();
    assert_eq!(
        all_saves(&d)[..],
        h("8B 00 10 81 00 0C 1A 82 00 68 69 20 09 8B 00 10 81 00 0C 1A 82 00 68 69")[..]
    );
    d.revert_all();
    // The moved closure keeps them too, at the new position alone.
    d.move_record(t[0], InsertAt::After(t[2])).unwrap();
    assert_eq!(all_saves(&d)[..], h("1A 82 00 68 69 20 09 8B 00 10 81 00 0C")[..]);
    d.revert();
    // A designated payload rides byte-exact behind the target's own
    // framing: the replaced target keeps its padded prefix while the
    // designated length matches its source length.
    d.copy_payload(t[1], PayloadTarget::Replace(t[1])).unwrap();
    assert_eq!(all_saves(&d)[..], data[..]);
    d.revert();
    assert_eq!(all_saves(&d)[..], data[..]);
}

#[test]
fn a_move_equals_copy_plus_delete_on_a_fresh_twin() {
    let data = h("8B 00 10 81 00 0C 1A 82 00 68 69 20 09");
    let mut moved = TransferDraft::open_copy(&data).unwrap();
    let mt: Vec<Handle> = moved.top().collect();
    moved.move_record(mt[0], InsertAt::After(mt[2])).unwrap();

    let mut twin = TransferDraft::open_copy(&data).unwrap();
    let tt: Vec<Handle> = twin.top().collect();
    twin.copy_record(tt[0], InsertAt::After(tt[2])).unwrap();
    twin.delete(tt[0]).unwrap();

    assert_eq!(all_saves(&moved), all_saves(&twin));
    // The composition differs where the law says: two pending steps
    // against one.
    assert_eq!(moved.pending(), 1);
    assert_eq!(twin.pending(), 2);
}

#[test]
fn an_edited_designated_interior_walks_under_authored_framing() {
    // LEN f1 { varint f1=7 } · varint f4: move the payload to a fresh
    // record, descend it, edit inside — the authored head and prefix
    // re-derive while the interior walks.
    let data = h("0A 02 08 07 20 09");
    let mut d = TransferDraft::open_copy(&data).unwrap();
    let t: Vec<Handle> = d.top().collect();
    let dest = d.move_payload(t[0], InsertAt::TailOf(None), f(2)).unwrap();
    assert_eq!(all_saves(&d)[..], h("20 09 12 02 08 07")[..]);
    let Descent::Opened { first: Some(inner) } = d.descend(dest).unwrap() else { unreachable!() };
    d.set_varint(inner, 300).unwrap();
    assert_eq!(all_saves(&d)[..], h("20 09 12 03 08 AC 02")[..]);
    d.insert_varint(InsertAt::TailOf(Some(dest)), f(2), 1).unwrap();
    assert_eq!(all_saves(&d)[..], h("20 09 12 05 08 AC 02 10 01")[..]);
    d.revert_all();
    assert_eq!(all_saves(&d)[..], data[..]);
}

#[test]
fn tolerant_imports_keep_met_framing_and_land_first_class() {
    // The outside document carries padded framing everywhere; the
    // tolerant host imports the exact bytes, and the imported group
    // closure descends into first-class interior rows.
    let outside_doc = h("8B 00 10 81 00 0C 1A 82 00 68 69");
    let outside = TransferDraft::open_copy(&outside_doc).unwrap();
    let ot: Vec<Handle> = outside.top().collect();
    let mut d = TransferDraft::open_copy(&h("08 01")).unwrap();
    let group =
        d.copy_record_from(outside.record_ref(ot[0]).unwrap(), InsertAt::TailOf(None)).unwrap();
    d.copy_record_from(outside.record_ref(ot[1]).unwrap(), InsertAt::TailOf(None)).unwrap();
    // Fidelity: the met framing rides byte-exact.
    assert_eq!(all_saves(&d)[..], h("08 01 8B 00 10 81 00 0C 1A 82 00 68 69")[..]);
    // The imported closure is first-class: descent parses the zone
    // into editable rows, and the edit rides between the met tags.
    let Descent::Opened { first: Some(kid) } = d.descend(group).unwrap() else { unreachable!() };
    d.set_varint(kid, 9).unwrap();
    assert_eq!(all_saves(&d)[..], h("08 01 8B 00 10 09 0C 1A 82 00 68 69")[..]);
    // The canonical face normalizes the materialized closure whole
    // and re-derives the LEN framing over its opaque payload.
    assert_eq!(d.save_canonical().unwrap()[..], h("08 01 0B 10 09 0C 1A 02 68 69")[..]);
    d.revert_all();
    assert_eq!(all_saves(&d)[..], h("08 01")[..]);
}

#[test]
fn a_padded_group_import_keeps_its_met_framing() {
    // Group f1 with a two-byte open tag and a three-byte end tag —
    // the two met widths differ, so the interior extent and the
    // close window both come from the zone's own words.
    let outside_doc = h("8B 00 10 05 8C 80 00");
    let outside = TransferDraft::open_copy(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = h("08 2A");
    let mut d = TransferDraft::open_copy(&data).unwrap();
    let imported =
        d.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(all_saves(&d)[..], h("08 2A 8B 00 10 05 8C 80 00")[..]);

    let Descent::Opened { first: Some(kid) } = d.descend(imported).unwrap() else { unreachable!() };
    d.set_varint(kid, 9).unwrap();
    // The met tags ride verbatim around the walked interior.
    assert_eq!(all_saves(&d)[..], h("08 2A 8B 00 10 09 8C 80 00")[..]);
    // The canonical save normalizes the materialized closure whole.
    assert_eq!(d.save_canonical().unwrap()[..], h("08 2A 0B 10 09 0C")[..]);
    d.revert_all();
    assert_eq!(all_saves(&d)[..], data[..]);
}

#[test]
fn the_borrow_twin_walks_the_import_arc_over_its_slot_zone() {
    // Group f1 with a two-byte open tag and a three-byte end tag
    // nesting a canonical group f3, retained as a borrowed slot:
    // the interior parses at slot-relative offsets between the met
    // tags, every step's save re-derives both met widths byte-exact,
    // and the canonical save normalizes the closure whole.
    let outside_doc = h("8B 00 10 05 1B 10 01 1C 8C 80 00");
    let outside = TransferBorrowDraft::open_copy(&outside_doc).unwrap();
    let source = outside.top().next().unwrap();

    let data = h("08 2A");
    let mut d = TransferBorrowDraft::open_copy(&data).unwrap();
    let import =
        d.copy_record_from(outside.record_ref(source).unwrap(), InsertAt::TailOf(None)).unwrap();
    assert_eq!(d.save().unwrap()[..], h("08 2A 8B 00 10 05 1B 10 01 1C 8C 80 00")[..]);

    let Descent::Opened { first: Some(kid) } = d.descend(import).unwrap() else { unreachable!() };
    assert_eq!(d.varint_word(kid).unwrap(), 5);
    d.set_varint(kid, 9).unwrap();
    assert_eq!(d.save().unwrap()[..], h("08 2A 8B 00 10 09 1B 10 01 1C 8C 80 00")[..]);
    d.insert_varint(InsertAt::TailOf(Some(import)), f(2), 1).unwrap();
    assert_eq!(d.save().unwrap()[..], h("08 2A 8B 00 10 09 1B 10 01 1C 10 01 8C 80 00")[..]);
    let interior: Vec<Handle> = d.children(import).unwrap().collect();
    d.delete(interior[1]).unwrap();
    assert_eq!(d.save().unwrap()[..], h("08 2A 8B 00 10 09 10 01 8C 80 00")[..]);
    d.undelete(interior[1]).unwrap();
    assert_eq!(d.save().unwrap()[..], h("08 2A 8B 00 10 09 1B 10 01 1C 10 01 8C 80 00")[..]);
    assert_eq!(d.save_canonical().unwrap()[..], h("08 2A 0B 10 09 1B 10 01 1C 10 01 0C")[..]);
    d.revert_all();
    assert_eq!(d.save().unwrap()[..], data[..]);
}
