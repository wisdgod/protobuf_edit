//! Contract pins for the shared layer: carrier lifecycle, edit
//! algebra theorems, store admission.

use super::*;

// ─── carrier ───

#[test]
fn load_copies_once_and_shares_by_count() {
    let doc = DocBytes::load(b"hello").expect("admitted");
    assert_eq!(doc.as_slice(), b"hello");
    assert_eq!(doc.len(), 5);
    let twin = doc.clone();
    assert!(DocBytes::ptr_eq(&doc, &twin));
    assert_eq!(twin.as_slice(), b"hello");
    drop(doc);
    // The clone keeps the allocation alive.
    assert_eq!(twin.as_slice(), b"hello");
}

#[test]
fn the_empty_document_loads() {
    let doc = DocBytes::load(&[]).expect("empty is admitted");
    assert!(doc.is_empty());
    assert_eq!(doc.as_slice(), b"");
}

#[test]
fn admission_refuses_beyond_cap_by_type_of_the_bound() {
    // The refusing branch needs a >2 GiB allocation; the bound
    // itself is pinned against the layout budget.
    assert_eq!(DocBytes::CAP, (1u32 << 31) - 32);
}

#[test]
fn raw_doc_round_trips_through_doc_bytes() {
    let mut raw = RawDoc::alloc(8).expect("output");
    raw.put_slice(b"ab");
    raw.put_varint(150);
    raw.put_bits32(1);
    let doc = raw.finish();
    assert_eq!(doc.as_slice(), &[b'a', b'b', 0x96, 0x01, 1, 0, 0, 0]);
}

#[test]
fn abandoned_raw_doc_frees_without_publishing() {
    let raw = RawDoc::alloc(16).expect("output");
    drop(raw); // Miri would flag a leak or double free here.
}

// ─── edit algebra ───

#[test]
fn effective_speaks_for_the_value_side() {
    let v = ValueAt::new(3).unwrap();
    assert_eq!(Edit::Intact.effective(), None);
    assert_eq!(Edit::Deleted(None).effective(), None);
    assert_eq!(Edit::Replaced(v).effective(), Some(v));
    assert_eq!(Edit::Deleted(Some(v)).effective(), Some(v));
    assert_eq!(Edit::Inserted(v).effective(), Some(v));
    assert_eq!(Edit::InsertedDeleted(v).effective(), Some(v));
}

#[test]
fn ghosts_are_not_dirty() {
    let v = ValueAt::new(0).unwrap();
    assert!(!Edit::Intact.own_dirty());
    assert!(!Edit::InsertedDeleted(v).own_dirty());
    assert!(Edit::Replaced(v).own_dirty());
    assert!(Edit::Deleted(None).own_dirty());
    assert!(Edit::Deleted(Some(v)).own_dirty());
    assert!(Edit::Inserted(v).own_dirty());
}

// ─── the transfer algebra ───

#[cfg(any(feature = "transfer-session-grouped", feature = "transfer-session-groupless"))]
#[test]
fn the_transfer_speaker_names_the_value_side_backing() {
    use super::transfer::{Edit, Speaker};
    let v = ValueAt::new(3).unwrap();
    let row = RowId::new(2).unwrap();
    // Shrouds keep their pre-shroud speaker: deletion never flips a
    // backing, so undeletion never re-parses one.
    assert_eq!(Edit::Intact.speaker(), Speaker::Scanned);
    assert_eq!(Edit::Deleted(None).speaker(), Speaker::Scanned);
    assert_eq!(Edit::Moved { destination: row }.speaker(), Speaker::Scanned);
    assert_eq!(Edit::SourceRecord.speaker(), Speaker::Scanned);
    assert_eq!(Edit::SourceRecordDeleted.speaker(), Speaker::Scanned);
    assert_eq!(Edit::Replaced(v).speaker(), Speaker::Store(v));
    assert_eq!(Edit::Deleted(Some(v)).speaker(), Speaker::Store(v));
    assert_eq!(Edit::Inserted(v).speaker(), Speaker::Store(v));
    assert_eq!(Edit::InsertedDeleted(v).speaker(), Speaker::Store(v));
    // Import roots speak from their own zone geometry: the closure is
    // first-class rows over the import zone, and the store span is only
    // the zone witness riding the state.
    assert_eq!(Edit::Imported(v).speaker(), Speaker::Scanned);
    assert_eq!(Edit::ImportedDeleted(v).speaker(), Speaker::Scanned);
    assert_eq!(Edit::SourcePayload(row).speaker(), Speaker::SourceRow(row));
    assert_eq!(Edit::SourcePayloadDeleted(row).speaker(), Speaker::SourceRow(row));
    assert_eq!(Edit::SourceInserted(row).speaker(), Speaker::SourceRow(row));
    assert_eq!(Edit::SourceInsertedDeleted(row).speaker(), Speaker::SourceRow(row));
    // Re-designation and re-replacement flip too: the speaker carries
    // the coordinate, not just the family.
    let w = ValueAt::new(4).unwrap();
    assert_ne!(Edit::Replaced(v).speaker(), Edit::Replaced(w).speaker());
}

#[cfg(any(feature = "transfer-session-grouped", feature = "transfer-session-groupless"))]
#[test]
fn transfer_ghosts_are_not_dirty() {
    use super::transfer::Edit;
    let v = ValueAt::new(0).unwrap();
    let row = RowId::new(2).unwrap();
    assert!(!Edit::Intact.own_dirty());
    assert!(!Edit::InsertedDeleted(v).own_dirty());
    assert!(Edit::Replaced(v).own_dirty());
    assert!(Edit::Deleted(None).own_dirty());
    assert!(Edit::Deleted(Some(v)).own_dirty());
    assert!(Edit::Inserted(v).own_dirty());
    // A live transfer is dirt (it emits at a new position); its ghost
    // is not — undoing a copy restores the untouched reading. A
    // shrouded designated payload stays dirt: a scanned record
    // stopped emitting its own reading.
    assert!(Edit::Moved { destination: row }.own_dirty());
    assert!(Edit::SourceRecord.own_dirty());
    assert!(!Edit::SourceRecordDeleted.own_dirty());
    assert!(Edit::SourcePayload(row).own_dirty());
    assert!(Edit::SourcePayloadDeleted(row).own_dirty());
    assert!(Edit::SourceInserted(row).own_dirty());
    assert!(!Edit::SourceInsertedDeleted(row).own_dirty());
    assert!(Edit::Imported(v).own_dirty());
    assert!(!Edit::ImportedDeleted(v).own_dirty());
}

// ─── store ───

#[test]
fn store_columns_issue_dense_coordinates() {
    let mut store = Store::new();
    let a = store.push_varint(1).unwrap();
    let b = store.push_varint(2).unwrap();
    assert_eq!(a.as_inner(), 0);
    assert_eq!(b.as_inner(), 1);
    assert_eq!(store.varints[b.as_inner() as usize], 2);
}

#[test]
fn byte_payloads_register_spans() {
    let mut store = Store::new();
    let v = store.push_bytes(b"abc").unwrap();
    assert_eq!(store.span_bytes(v), b"abc");
    let w = store.push_bytes(b"xy").unwrap();
    assert_eq!(store.span_bytes(w), b"xy");
    assert_eq!(store.span_bytes(v), b"abc"); // never truncated
}

#[test]
fn the_first_payload_mints_the_origin_coordinate() {
    let mut store = Store::new();
    let at = store.push_bytes(b"abc").unwrap();
    assert_eq!(at, ValueAt::new(0).unwrap(), "no seed entry precedes the first install");
    assert_eq!(store.span_bytes(at), b"abc");
}

// ─── the priced ledger's arithmetic theorem ───

#[cfg(any(feature = "priced-session-grouped", feature = "priced-session-groupless"))]
#[test]
fn the_price_ceiling_bounds_every_release_operation() {
    // The derived maxima, exercised pure: the signed widening and
    // both wrapping additions produce exact results at the ceiling.
    assert_eq!(PRICE_CEILING, 38_654_705_664);
    let widened = i64::try_from(PRICE_CEILING).expect("the ceiling widens losslessly");
    assert_eq!(widened.checked_neg(), Some(-widened), "the extreme delta negates in range");
    assert_eq!(0u64.wrapping_add_signed(widened), PRICE_CEILING, "the upward add is exact");
    assert_eq!(PRICE_CEILING.wrapping_add_signed(-widened), 0, "the downward add is exact");
}

#[cfg(any(feature = "priced-session-grouped", feature = "priced-session-groupless"))]
#[test]
fn the_row_framing_ceiling_matches_the_encoders() {
    // The fifteen-byte framing component is the encoders' own
    // maxima: a head word is at most five bytes, a scalar value or
    // LEN prefix at most ten more; group framing is two head words,
    // inside the same bound.
    use crate::varint::{encoded_len32, encoded_len64};
    assert_eq!(encoded_len32(u32::MAX), 5);
    assert_eq!(encoded_len64(u64::MAX), 10);
    assert_eq!(u64::from(encoded_len32(u32::MAX) + encoded_len64(u64::MAX)), ROW_FRAMING_CEILING);
    assert!(u64::from(encoded_len32(u32::MAX) * 2) <= ROW_FRAMING_CEILING);
}
