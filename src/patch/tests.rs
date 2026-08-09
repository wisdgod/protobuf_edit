use super::{BorrowedPatch, Patch, Span, Txn, ValueSpans};
use crate::wire::Tag;
use crate::{Buf, Document, FieldNumber, TreeError, WireType};

fn fnn(value: u32) -> FieldNumber {
    FieldNumber::new(value).unwrap()
}

fn buf_from_slice(bytes: &[u8]) -> Buf {
    let mut out = Buf::new();
    out.extend_from_slice(bytes).unwrap();
    out
}

#[test]
fn does_not_parse_child_message_from_non_message_bytes() {
    let mut root = Document::new();
    let _ = root.push_varint(fnn(1), 42).unwrap();
    let _ = root.push_length_delimited(fnn(2), buf_from_slice(b"abc")).unwrap();
    let bytes = root.to_buf().unwrap();

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root_msg = tree.root();
    let outer = Tag::from_parts(fnn(2), WireType::Len);

    let mut outer_fields = tree.fields_by_number(root_msg, outer.field_number()).unwrap();
    let outer_field = outer_fields.next().unwrap();
    assert!(outer_fields.next().is_none());
    assert_eq!(tree.field_child_message(outer_field).unwrap(), None);

    let err = tree.parse_child_message(outer_field).unwrap_err();
    assert!(matches!(err, TreeError::Malformed { .. }));
}

#[test]
fn parses_nested_messages_on_demand() {
    let mut child_a = Document::new();
    let _ = child_a.push_varint(fnn(2), 1).unwrap();
    let mut child_b = Document::new();
    let _ = child_b.push_varint(fnn(2), 3).unwrap();

    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(10), child_a.to_buf().unwrap()).unwrap();
    let _ = root.push_length_delimited(fnn(10), child_b.to_buf().unwrap()).unwrap();
    let bytes = root.to_buf().unwrap();

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root_msg = tree.root();

    let outer = Tag::from_parts(fnn(10), WireType::Len);
    let inner = Tag::from_parts(fnn(2), WireType::Varint);

    let outer_fields: alloc::vec::Vec<_> =
        tree.fields_by_number(root_msg, outer.field_number()).unwrap().collect();
    assert_eq!(outer_fields.len(), 2);

    let mut got = alloc::vec::Vec::new();
    for field_id in outer_fields {
        let child_msg = tree.parse_child_message(field_id).unwrap();
        let mut inner_fields = tree.fields_by_number(child_msg, inner.field_number()).unwrap();
        let inner_field = inner_fields.next().unwrap();
        assert!(inner_fields.next().is_none());
        got.push(tree.varint(inner_field).unwrap());
    }
    got.sort_unstable();
    assert_eq!(got.as_slice(), &[1, 3]);
}

#[test]
fn edits_child_payload_and_saves_lazily() {
    let mut child_a = Document::new();
    let _ = child_a.push_varint(fnn(2), 1).unwrap();
    let mut child_b = Document::new();
    let _ = child_b.push_varint(fnn(2), 3).unwrap();

    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(10), child_a.to_buf().unwrap()).unwrap();
    let _ = root.push_length_delimited(fnn(10), child_b.to_buf().unwrap()).unwrap();
    let bytes = root.to_buf().unwrap();

    let outer = Tag::from_parts(fnn(10), WireType::Len);
    let inner = Tag::from_parts(fnn(2), WireType::Varint);

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root_msg = tree.root();
    let outer_fields: alloc::vec::Vec<_> =
        tree.fields_by_number(root_msg, outer.field_number()).unwrap().collect();

    for outer_field_id in outer_fields {
        let child_msg = tree.parse_child_message(outer_field_id).unwrap();
        let inner_field_id =
            tree.fields_by_number(child_msg, inner.field_number()).unwrap().next().unwrap();
        let before = tree.varint(inner_field_id).unwrap();
        tree.set_varint(inner_field_id, before + 100).unwrap();
    }

    let out = tree.save().unwrap();
    assert_eq!(out.len(), bytes.len());
    let decoded = Document::from_bytes(out.as_slice()).unwrap();

    let mut got = alloc::vec::Vec::new();
    for outer_ref in decoded.repeated_refs(outer) {
        let child = outer_ref.as_message().unwrap();
        got.push(child.first_ref(inner).unwrap().as_uint64().unwrap());
    }
    got.sort_unstable();
    assert_eq!(got.as_slice(), &[101, 103]);
}

#[test]
fn transaction_rolls_back_on_drop() {
    let mut child_a = Document::new();
    let _ = child_a.push_varint(fnn(2), 1).unwrap();
    let mut child_b = Document::new();
    let _ = child_b.push_varint(fnn(2), 3).unwrap();

    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(10), child_a.to_buf().unwrap()).unwrap();
    let _ = root.push_length_delimited(fnn(10), child_b.to_buf().unwrap()).unwrap();
    let bytes = root.to_buf().unwrap();

    let outer = Tag::from_parts(fnn(10), WireType::Len);
    let inner = Tag::from_parts(fnn(2), WireType::Varint);

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    {
        let mut txn = Txn::begin(&mut tree);
        let root_msg = txn.tree().root();
        let outer_field_id =
            txn.tree().fields_by_number(root_msg, outer.field_number()).unwrap().next().unwrap();
        let child_msg = txn.tree().parse_child_message(outer_field_id).unwrap();
        let inner_field_id =
            txn.tree().fields_by_number(child_msg, inner.field_number()).unwrap().next().unwrap();
        let before = txn.tree().varint(inner_field_id).unwrap();
        txn.tree().set_varint(inner_field_id, before + 100).unwrap();
    }

    let out = tree.save().unwrap();
    let decoded = Document::from_bytes(out.as_slice()).unwrap();

    let mut got = alloc::vec::Vec::new();
    for outer_ref in decoded.repeated_refs(outer) {
        let child = outer_ref.as_message().unwrap();
        got.push(child.first_ref(inner).unwrap().as_uint64().unwrap());
    }
    got.sort_unstable();
    assert_eq!(got.as_slice(), &[1, 3]);
}

#[test]
fn transaction_commits_on_commit() {
    let mut child_a = Document::new();
    let _ = child_a.push_varint(fnn(2), 1).unwrap();
    let mut child_b = Document::new();
    let _ = child_b.push_varint(fnn(2), 3).unwrap();

    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(10), child_a.to_buf().unwrap()).unwrap();
    let _ = root.push_length_delimited(fnn(10), child_b.to_buf().unwrap()).unwrap();
    let bytes = root.to_buf().unwrap();

    let outer = Tag::from_parts(fnn(10), WireType::Len);
    let inner = Tag::from_parts(fnn(2), WireType::Varint);

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    {
        let mut txn = Txn::begin(&mut tree);
        let root_msg = txn.tree().root();
        let outer_field_id =
            txn.tree().fields_by_number(root_msg, outer.field_number()).unwrap().next().unwrap();
        let child_msg = txn.tree().parse_child_message(outer_field_id).unwrap();
        let inner_field_id =
            txn.tree().fields_by_number(child_msg, inner.field_number()).unwrap().next().unwrap();
        let before = txn.tree().varint(inner_field_id).unwrap();
        txn.tree().set_varint(inner_field_id, before + 100).unwrap();
        txn.commit();
    }

    let out = tree.save().unwrap();
    let decoded = Document::from_bytes(out.as_slice()).unwrap();

    let mut got = alloc::vec::Vec::new();
    for outer_ref in decoded.repeated_refs(outer) {
        let child = outer_ref.as_message().unwrap();
        got.push(child.first_ref(inner).unwrap().as_uint64().unwrap());
    }
    got.sort_unstable();
    assert_eq!(got.as_slice(), &[3, 101]);
}

#[test]
fn insert_and_delete_fields_affect_save_output() {
    let mut doc = Document::new();
    let _ = doc.push_varint(fnn(1), 7).unwrap();
    let _ = doc.push_varint(fnn(2), 8).unwrap();
    let bytes = doc.to_buf().unwrap();

    let mut patch = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root = patch.root();

    let tag1 = Tag::from_parts(fnn(1), WireType::Varint);
    let tag3 = Tag::from_parts(fnn(3), WireType::Varint);

    let field1 = patch.fields_by_number(root, tag1.field_number()).unwrap().next().unwrap();
    patch.delete_field(field1).unwrap();
    let _inserted = patch.insert_varint(root, tag3, 999).unwrap();

    let out = patch.save().unwrap();
    let roundtrip = Document::from_bytes(out.as_slice()).unwrap();

    assert!(roundtrip.first_ref(tag1).is_none());
    assert_eq!(roundtrip.first_ref(tag3).unwrap().as_uint64(), Some(999));
}

#[test]
fn save_and_reparse_refreshes_spans_for_inserted_fields() {
    let bytes = Document::new().to_buf().unwrap();
    let mut patch = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root = patch.root();

    let tag1 = Tag::from_parts(fnn(1), WireType::Varint);
    let inserted = patch.insert_varint(root, tag1, 1).unwrap();
    assert_eq!(patch.field_spans(inserted).unwrap(), None);

    let reparsed = patch.save_and_reparse().unwrap();
    let ids: alloc::vec::Vec<_> =
        reparsed.fields_by_number(reparsed.root(), tag1.field_number()).unwrap().collect();
    assert_eq!(ids.len(), 1);
    assert!(reparsed.field_spans(ids[0]).unwrap().is_some());
}

#[test]
fn deleting_child_field_makes_parent_len_field_dirty() {
    let mut child = Document::new();
    let _ = child.push_varint(fnn(2), 1).unwrap();

    let mut root = Document::new();
    let outer_tag = Tag::from_parts(fnn(10), WireType::Len);
    let _ = root.push_length_delimited(fnn(10), child.to_buf().unwrap()).unwrap();
    let src = root.to_buf().unwrap();

    let mut patch = Patch::from_bytes(src.as_slice()).unwrap();
    let root_msg = patch.root();
    let outer_field_id =
        patch.fields_by_number(root_msg, outer_tag.field_number()).unwrap().next().unwrap();
    let child_msg = patch.parse_child_message(outer_field_id).unwrap();

    let inner_tag = Tag::from_parts(fnn(2), WireType::Varint);
    let inner_field_id =
        patch.fields_by_number(child_msg, inner_tag.field_number()).unwrap().next().unwrap();
    patch.delete_field(inner_field_id).unwrap();

    let out = patch.save().unwrap();
    let decoded = Document::from_bytes(out.as_slice()).unwrap();
    let decoded_child = decoded.first_ref(outer_tag).unwrap().as_message().unwrap();
    assert!(decoded_child.first_ref(inner_tag).is_none());
}

#[test]
fn maps_child_message_spans_back_to_root() {
    let mut child = Document::new();
    let _ = child.push_varint(fnn(2), 150).unwrap();
    let child_bytes = child.to_buf().unwrap();

    let mut root = Document::new();
    let outer_tag = Tag::from_parts(fnn(10), WireType::Len);
    let _ = root.push_length_delimited(fnn(10), child_bytes.clone()).unwrap();
    let root_bytes = root.to_buf().unwrap();

    let mut patch = Patch::from_bytes(root_bytes.as_slice()).unwrap();
    let root_msg = patch.root();
    let outer_field_id =
        patch.fields_by_number(root_msg, outer_tag.field_number()).unwrap().next().unwrap();
    let outer_spans = patch.field_spans(outer_field_id).unwrap().unwrap();
    let outer_payload_span = match outer_spans.value {
        ValueSpans::Len { payload, .. } => payload,
        other => panic!("expected len field spans, got {other:?}"),
    };

    let child_msg = patch.parse_child_message(outer_field_id).unwrap();
    assert_eq!(patch.message_root_span(child_msg).unwrap(), Some(outer_payload_span));

    let inner_tag = Tag::from_parts(fnn(2), WireType::Varint);
    let inner_field_id =
        patch.fields_by_number(child_msg, inner_tag.field_number()).unwrap().next().unwrap();
    let inner_local = patch.field_spans(inner_field_id).unwrap().unwrap();

    let expected_field_span = Span::new(
        outer_payload_span.start() + inner_local.field.start(),
        outer_payload_span.start() + inner_local.field.end(),
    )
    .unwrap();

    assert_eq!(patch.field_root_spans(inner_field_id).unwrap().unwrap().field, expected_field_span);

    let root_field_bytes = &root_bytes.as_slice()
        [expected_field_span.start() as usize..expected_field_span.end() as usize];
    let child_field_bytes = &child_bytes.as_slice()
        [inner_local.field.start() as usize..inner_local.field.end() as usize];
    assert_eq!(root_field_bytes, child_field_bytes);
}

#[test]
fn owned_child_message_has_no_root_span_mapping() {
    let mut child = Document::new();
    let _ = child.push_varint(fnn(2), 150).unwrap();

    let mut root = Document::new();
    let outer_tag = Tag::from_parts(fnn(10), WireType::Len);
    let _ = root.push_length_delimited(fnn(10), child.to_buf().unwrap()).unwrap();
    let root_bytes = root.to_buf().unwrap();

    let mut patch = Patch::from_bytes(root_bytes.as_slice()).unwrap();
    let root_msg = patch.root();
    let outer_field_id =
        patch.fields_by_number(root_msg, outer_tag.field_number()).unwrap().next().unwrap();

    let mut edited_child = Document::new();
    let _ = edited_child.push_varint(fnn(2), 999).unwrap();
    patch.set_bytes(outer_field_id, edited_child.to_buf().unwrap()).unwrap();

    let child_msg = patch.parse_child_message(outer_field_id).unwrap();
    assert_eq!(patch.message_root_span(child_msg).unwrap(), None);

    let inner_tag = Tag::from_parts(fnn(2), WireType::Varint);
    let inner_field_id =
        patch.fields_by_number(child_msg, inner_tag.field_number()).unwrap().next().unwrap();
    let _inner_local = patch.field_spans(inner_field_id).unwrap().unwrap();

    assert_eq!(patch.field_root_spans(inner_field_id).unwrap(), None);
}

#[test]
fn borrowed_patch_shares_root_bytes() {
    let mut doc = Document::new();
    let _ = doc.push_varint(fnn(1), 7).unwrap();
    let bytes = doc.to_buf().unwrap();

    let patch = BorrowedPatch::from_bytes(bytes.as_slice()).unwrap();
    assert_eq!(patch.root_bytes(), bytes.as_slice());
    assert_eq!(patch.root_bytes().as_ptr(), bytes.as_slice().as_ptr());

    let out = patch.save().unwrap();
    assert_eq!(out.as_slice(), bytes.as_slice());

    let owned = patch.into_owned();
    assert_eq!(owned.root_bytes(), bytes.as_slice());
}

#[test]
fn transaction_rolls_back_insertions_and_deletions() {
    let mut doc = Document::new();
    let _ = doc.push_varint(fnn(1), 7).unwrap();
    let bytes = doc.to_buf().unwrap();

    let mut patch = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root = patch.root();

    let tag1 = Tag::from_parts(fnn(1), WireType::Varint);
    let tag2 = Tag::from_parts(fnn(2), WireType::Varint);

    {
        let mut txn = Txn::begin(&mut patch);
        let field1 =
            txn.tree().fields_by_number(root, tag1.field_number()).unwrap().next().unwrap();
        txn.tree().delete_field(field1).unwrap();
        let _ = txn.tree().insert_varint(root, tag2, 999).unwrap();
    }

    let out = patch.save().unwrap();
    let roundtrip = Document::from_bytes(out.as_slice()).unwrap();

    assert_eq!(roundtrip.first_ref(tag1).unwrap().as_uint64(), Some(7));
    assert!(roundtrip.first_ref(tag2).is_none());
}

#[test]
fn fields_by_number_chains_wire_types_and_skips_deleted() {
    // Same field number with two wire types: varint then fixed32.
    let mut doc = Document::new();
    let _ = doc.push_varint(fnn(1), 7).unwrap();
    let _ = doc.push_fixed32(fnn(1), 42).unwrap();
    let _ = doc.push_varint(fnn(2), 9).unwrap();
    let bytes = doc.to_buf().unwrap();

    let mut patch = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root = patch.root();

    // The number is the identity: both occurrences share one chain.
    let chain: alloc::vec::Vec<_> = patch.fields_by_number(root, fnn(1)).unwrap().collect();
    assert_eq!(chain.len(), 2);
    assert_eq!(patch.field_tag(chain[0]).unwrap().wire_type(), WireType::Varint);
    assert_eq!(patch.field_tag(chain[1]).unwrap().wire_type(), WireType::I32);

    // Deleted fields disappear from iteration without reparse.
    patch.delete_field(chain[0]).unwrap();
    let live: alloc::vec::Vec<_> = patch.fields_by_number(root, fnn(1)).unwrap().collect();
    assert_eq!(live, &chain[1..]);

    let (lo, hi) = patch.fields_by_number(root, fnn(1)).unwrap().size_hint();
    assert_eq!(lo, 0, "deleted fields make the length an upper bound only");
    assert_eq!(hi, Some(2));
}

#[test]
fn rollback_restores_pre_transaction_edit_values() {
    let mut doc = Document::new();
    let _ = doc.push_varint(fnn(1), 7).unwrap();
    let bytes = doc.to_buf().unwrap();

    let mut patch = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root = patch.root();
    let tag1 = Tag::from_parts(fnn(1), WireType::Varint);
    let field = patch.fields_by_number(root, tag1.field_number()).unwrap().next().unwrap();

    // Pre-transaction edit occupies a pool slot.
    patch.set_varint(field, 10).unwrap();
    assert_eq!(patch.varint(field).unwrap(), 10);

    // In-transaction edits must not clobber the pre-transaction slot value.
    patch.txn_begin();
    patch.set_varint(field, 20).unwrap();
    patch.set_varint(field, 30).unwrap();
    assert_eq!(patch.varint(field).unwrap(), 30);
    patch.txn_rollback();

    assert_eq!(patch.varint(field).unwrap(), 10, "rollback must restore the pre-txn edit value");

    // Rolling back an edit on a previously unedited field clears it fully.
    patch.txn_begin();
    patch.clear_field_edit(field).unwrap();
    patch.set_varint(field, 40).unwrap();
    patch.txn_rollback();
    assert_eq!(patch.varint(field).unwrap(), 10);
}

/// Differential oracle for the reverse save: random edit sequences on a
/// three-level tree must serialize byte-identically through the reverse
/// one-pass writer and the forward two-pass writer.
#[test]
fn reverse_save_matches_forward_save_under_random_edits() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn build() -> Buf {
        let mut leaf = Document::new();
        let _ = leaf.push_varint(fnn(1), 300).unwrap();
        let _ = leaf.push_fixed32(fnn(2), 0xAABB).unwrap();
        let mut mid = Document::new();
        let _ = mid.push_varint(fnn(1), 7).unwrap();
        let _ = mid.push_length_delimited(fnn(3), leaf.to_buf().unwrap()).unwrap();
        let _ = mid.push_fixed64(fnn(4), 0x11_2233_4455).unwrap();
        let _ = mid.push_length_delimited(fnn(5), buf_from_slice(b"payload")).unwrap();
        let mut root = Document::new();
        let _ = root.push_varint(fnn(1), 1).unwrap();
        let _ = root.push_length_delimited(fnn(2), mid.to_buf().unwrap()).unwrap();
        let _ = root.push_varint(fnn(6), u64::MAX).unwrap();
        let _ = root.push_length_delimited(fnn(2), mid.to_buf().unwrap()).unwrap();
        let _ = root.push_fixed32(fnn(7), 42).unwrap();
        root.to_buf().unwrap()
    }

    let bytes = build();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);

    for round in 0..8u32 {
        let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();

        for step in 0..40u32 {
            let field_count = tree.fields.len() as u32;
            let pick = super::FieldId::new(rng.next() as u32 % field_count).unwrap();
            let wire = tree.field_tag(pick).unwrap().wire_type();

            match rng.next() % 10 {
                0..=3 => {
                    // Overwrite the payload by wire type; random byte
                    // lengths cover both the reused (equal-length) and
                    // re-encoded length-prefix paths.
                    let _ = match wire {
                        WireType::Varint => tree.set_varint(pick, rng.next()),
                        WireType::I32 => tree.set_i32_bits(pick, rng.next() as u32),
                        WireType::I64 => tree.set_i64_bits(pick, rng.next()),
                        _ => {
                            let len = (rng.next() % 24) as usize;
                            let payload = alloc::vec![0xC3u8; len];
                            tree.set_bytes(pick, buf_from_slice(&payload))
                        }
                    };
                }
                4 | 5 => {
                    // Lazy descent; fails harmlessly on non-message payloads.
                    let _ = tree.parse_child_message(pick);
                }
                6 => {
                    let _ = tree.delete_field(pick);
                }
                7 => {
                    let _ = tree.clear_field_edit(pick);
                }
                _ => {
                    let msg_count = tree.messages.len() as u32;
                    let msg = super::MessageId::new(rng.next() as u32 % msg_count).unwrap();
                    let number = fnn(1 + (rng.next() as u32 % 12));
                    let _ = match rng.next() % 3 {
                        0 => tree
                            .insert_varint(msg, Tag::from_parts(number, WireType::Varint), rng.next())
                            .map(|_| ()),
                        1 => tree
                            .insert_i32_bits(msg, Tag::from_parts(number, WireType::I32), 9)
                            .map(|_| ()),
                        _ => tree
                            .insert_bytes(msg, Tag::from_parts(number, WireType::Len), buf_from_slice(b"ins"))
                            .map(|_| ()),
                    };
                }
            }

            let forward = tree.save_forward().unwrap();
            let reverse = tree.save().unwrap();
            assert_eq!(
                forward.as_slice(),
                reverse.as_slice(),
                "divergence at round {round} step {step}",
            );
        }
    }
}

#[test]
fn message_fields_iterate_backwards() {
    let mut doc = Document::new();
    let _ = doc.push_varint(fnn(1), 1).unwrap();
    let _ = doc.push_varint(fnn(2), 2).unwrap();
    let bytes = doc.to_buf().unwrap();

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root = tree.root();
    let tag = Tag::from_parts(fnn(3), WireType::Varint);
    let inserted = tree.insert_varint(root, tag, 3).unwrap();

    let forward: alloc::vec::Vec<_> = tree.message_fields(root).unwrap().collect();
    let mut backward: alloc::vec::Vec<_> = tree.message_fields(root).unwrap().rev().collect();
    backward.reverse();
    assert_eq!(forward, backward);
    assert_eq!(*forward.last().unwrap(), inserted, "inserted fields follow parsed ones");
}

#[test]
fn dirty_propagates_to_ancestors_only() {
    // root { f10: mid { f10: leaf { f2: varint } }, f11: sibling { f2 } }
    let mut leaf = Document::new();
    let _ = leaf.push_varint(fnn(2), 7).unwrap();
    let mut mid = Document::new();
    let _ = mid.push_length_delimited(fnn(10), leaf.to_buf().unwrap()).unwrap();
    let mut sibling = Document::new();
    let _ = sibling.push_varint(fnn(2), 8).unwrap();
    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(10), mid.to_buf().unwrap()).unwrap();
    let _ = root.push_length_delimited(fnn(11), sibling.to_buf().unwrap()).unwrap();
    let bytes = root.to_buf().unwrap();

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root_msg = tree.root();
    let mid_field = tree.fields_by_number(root_msg, fnn(10)).unwrap().next().unwrap();
    let mid_msg = tree.parse_child_message(mid_field).unwrap();
    let leaf_field = tree.fields_by_number(mid_msg, fnn(10)).unwrap().next().unwrap();
    let leaf_msg = tree.parse_child_message(leaf_field).unwrap();
    let sib_field = tree.fields_by_number(root_msg, fnn(11)).unwrap().next().unwrap();
    let sib_msg = tree.parse_child_message(sib_field).unwrap();

    // Lazy child parsing is not an edit: everything stays clean.
    for msg in [root_msg, mid_msg, leaf_msg, sib_msg] {
        assert!(!tree.message(msg).unwrap().subtree_dirty);
    }

    let value_field = tree.fields_by_number(leaf_msg, fnn(2)).unwrap().next().unwrap();
    tree.set_varint(value_field, 99).unwrap();

    assert!(tree.message(leaf_msg).unwrap().subtree_dirty);
    assert!(tree.message(mid_msg).unwrap().subtree_dirty);
    assert!(tree.message(root_msg).unwrap().subtree_dirty);
    assert!(!tree.message(sib_msg).unwrap().subtree_dirty, "siblings stay clean");
}

#[test]
fn rollback_restores_exact_dirty_set() {
    let mut child_a = Document::new();
    let _ = child_a.push_varint(fnn(2), 1).unwrap();
    let mut child_b = Document::new();
    let _ = child_b.push_varint(fnn(2), 3).unwrap();
    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(10), child_a.to_buf().unwrap()).unwrap();
    let _ = root.push_length_delimited(fnn(11), child_b.to_buf().unwrap()).unwrap();
    let bytes = root.to_buf().unwrap();

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root_msg = tree.root();
    let fa = tree.fields_by_number(root_msg, fnn(10)).unwrap().next().unwrap();
    let fb = tree.fields_by_number(root_msg, fnn(11)).unwrap().next().unwrap();
    let msg_a = tree.parse_child_message(fa).unwrap();
    let msg_b = tree.parse_child_message(fb).unwrap();

    // Pre-transaction edit dirties subtree A and the root.
    let field_a = tree.fields_by_number(msg_a, fnn(2)).unwrap().next().unwrap();
    tree.set_varint(field_a, 100).unwrap();

    // The in-transaction edit propagates through B and stops at the
    // already-dirty root, so rollback must clear exactly B.
    tree.txn_begin();
    let field_b = tree.fields_by_number(msg_b, fnn(2)).unwrap().next().unwrap();
    tree.set_varint(field_b, 200).unwrap();
    assert!(tree.message(msg_b).unwrap().subtree_dirty);
    tree.txn_rollback();

    assert!(!tree.message(msg_b).unwrap().subtree_dirty, "txn flip must roll back");
    assert!(tree.message(msg_a).unwrap().subtree_dirty, "pre-txn dirty survives");
    assert!(tree.message(root_msg).unwrap().subtree_dirty, "pre-txn dirty survives");
}

#[test]
fn dirty_from_every_edit_entry_point() {
    let mut doc = Document::new();
    let _ = doc.push_varint(fnn(1), 5).unwrap();
    let _ = doc.push_length_delimited(fnn(2), buf_from_slice(b"abc")).unwrap();
    let bytes = doc.to_buf().unwrap();
    let fresh = || Patch::from_bytes(bytes.as_slice()).unwrap();

    let mut t = fresh();
    let f = t.fields_by_number(t.root(), fnn(1)).unwrap().next().unwrap();
    t.set_varint(f, 6).unwrap();
    assert!(t.message(t.root()).unwrap().subtree_dirty, "set_varint");

    let mut t = fresh();
    let f = t.fields_by_number(t.root(), fnn(2)).unwrap().next().unwrap();
    t.set_bytes(f, buf_from_slice(b"xy")).unwrap();
    assert!(t.message(t.root()).unwrap().subtree_dirty, "set_bytes");

    let mut t = fresh();
    let f = t.fields_by_number(t.root(), fnn(1)).unwrap().next().unwrap();
    t.delete_field(f).unwrap();
    assert!(t.message(t.root()).unwrap().subtree_dirty, "delete_field");

    let mut t = fresh();
    let tag = Tag::from_parts(fnn(3), WireType::Varint);
    let _ = t.insert_varint(t.root(), tag, 1).unwrap();
    assert!(t.message(t.root()).unwrap().subtree_dirty, "insert");

    // clear_field_edit keeps the bit set (conservative direction: the
    // bit records that an edit happened, not that state differs).
    let mut t = fresh();
    let f = t.fields_by_number(t.root(), fnn(1)).unwrap().next().unwrap();
    t.set_varint(f, 6).unwrap();
    t.clear_field_edit(f).unwrap();
    assert!(t.message(t.root()).unwrap().subtree_dirty, "clear keeps the bit");

    // The clone carries the bits; a fresh reparse starts clean.
    let cloned = t.clone();
    assert!(cloned.message(cloned.root()).unwrap().subtree_dirty);
    let reparsed = t.save_and_reparse().unwrap();
    assert!(!reparsed.message(reparsed.root()).unwrap().subtree_dirty);
}
