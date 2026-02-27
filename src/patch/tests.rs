use crate::{
    BorrowedPatch, Buf, FieldNumber, Document, Patch, Span, TreeError, Txn, ValueSpans, WireType,
};

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
    let outer = Document::make_tag(fnn(2), WireType::Len);

    let mut outer_fields = tree.fields_by_tag(root_msg, outer).unwrap();
    let outer_field = outer_fields.next().unwrap();
    assert!(outer_fields.next().is_none());
    assert_eq!(tree.field_child_message(outer_field).unwrap(), None);

    let err = tree.parse_child_message(outer_field).unwrap_err();
    assert_eq!(err, TreeError::DecodeError);
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

    let outer = Document::make_tag(fnn(10), WireType::Len);
    let inner = Document::make_tag(fnn(2), WireType::Varint);

    let outer_fields: alloc::vec::Vec<_> = tree.fields_by_tag(root_msg, outer).unwrap().collect();
    assert_eq!(outer_fields.len(), 2);

    let mut got = alloc::vec::Vec::new();
    for field_id in outer_fields {
        let child_msg = tree.parse_child_message(field_id).unwrap();
        let mut inner_fields = tree.fields_by_tag(child_msg, inner).unwrap();
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

    let outer = Document::make_tag(fnn(10), WireType::Len);
    let inner = Document::make_tag(fnn(2), WireType::Varint);

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    let root_msg = tree.root();
    let outer_fields: alloc::vec::Vec<_> = tree.fields_by_tag(root_msg, outer).unwrap().collect();

    for outer_field_id in outer_fields {
        let child_msg = tree.parse_child_message(outer_field_id).unwrap();
        let inner_field_id = tree.fields_by_tag(child_msg, inner).unwrap().next().unwrap();
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

    let outer = Document::make_tag(fnn(10), WireType::Len);
    let inner = Document::make_tag(fnn(2), WireType::Varint);

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    {
        let mut txn = Txn::begin(&mut tree);
        let root_msg = txn.tree().root();
        let outer_field_id = txn.tree().fields_by_tag(root_msg, outer).unwrap().next().unwrap();
        let child_msg = txn.tree().parse_child_message(outer_field_id).unwrap();
        let inner_field_id = txn.tree().fields_by_tag(child_msg, inner).unwrap().next().unwrap();
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

    let outer = Document::make_tag(fnn(10), WireType::Len);
    let inner = Document::make_tag(fnn(2), WireType::Varint);

    let mut tree = Patch::from_bytes(bytes.as_slice()).unwrap();
    {
        let mut txn = Txn::begin(&mut tree);
        let root_msg = txn.tree().root();
        let outer_field_id = txn.tree().fields_by_tag(root_msg, outer).unwrap().next().unwrap();
        let child_msg = txn.tree().parse_child_message(outer_field_id).unwrap();
        let inner_field_id = txn.tree().fields_by_tag(child_msg, inner).unwrap().next().unwrap();
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

    let tag1 = Document::make_tag(fnn(1), WireType::Varint);
    let tag3 = Document::make_tag(fnn(3), WireType::Varint);

    let field1 = patch.fields_by_tag(root, tag1).unwrap().next().unwrap();
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

    let tag1 = Document::make_tag(fnn(1), WireType::Varint);
    let inserted = patch.insert_varint(root, tag1, 1).unwrap();
    assert_eq!(patch.field_spans(inserted).unwrap(), None);

    let reparsed = patch.save_and_reparse().unwrap();
    let ids: alloc::vec::Vec<_> = reparsed.fields_by_tag(reparsed.root(), tag1).unwrap().collect();
    assert_eq!(ids.len(), 1);
    assert!(reparsed.field_spans(ids[0]).unwrap().is_some());
}

#[test]
fn deleting_child_field_makes_parent_len_field_dirty() {
    let mut child = Document::new();
    let _ = child.push_varint(fnn(2), 1).unwrap();

    let mut root = Document::new();
    let outer_tag = Document::make_tag(fnn(10), WireType::Len);
    let _ = root.push_length_delimited(fnn(10), child.to_buf().unwrap()).unwrap();
    let src = root.to_buf().unwrap();

    let mut patch = Patch::from_bytes(src.as_slice()).unwrap();
    let root_msg = patch.root();
    let outer_field_id = patch.fields_by_tag(root_msg, outer_tag).unwrap().next().unwrap();
    let child_msg = patch.parse_child_message(outer_field_id).unwrap();

    let inner_tag = Document::make_tag(fnn(2), WireType::Varint);
    let inner_field_id = patch.fields_by_tag(child_msg, inner_tag).unwrap().next().unwrap();
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
    let outer_tag = Document::make_tag(fnn(10), WireType::Len);
    let _ = root.push_length_delimited(fnn(10), child_bytes.clone()).unwrap();
    let root_bytes = root.to_buf().unwrap();

    let mut patch = Patch::from_bytes(root_bytes.as_slice()).unwrap();
    let root_msg = patch.root();
    let outer_field_id = patch.fields_by_tag(root_msg, outer_tag).unwrap().next().unwrap();
    let outer_spans = patch.field_spans(outer_field_id).unwrap().unwrap();
    let outer_payload_span = match outer_spans.value {
        ValueSpans::Len { payload, .. } => payload,
        other => panic!("expected len field spans, got {other:?}"),
    };

    let child_msg = patch.parse_child_message(outer_field_id).unwrap();
    assert_eq!(patch.message_root_span(child_msg).unwrap(), Some(outer_payload_span));

    let inner_tag = Document::make_tag(fnn(2), WireType::Varint);
    let inner_field_id = patch.fields_by_tag(child_msg, inner_tag).unwrap().next().unwrap();
    let inner_local = patch.field_spans(inner_field_id).unwrap().unwrap();

    let expected_field_span = Span::new(
        outer_payload_span.start() + inner_local.field.start(),
        outer_payload_span.start() + inner_local.field.end(),
    )
    .unwrap();

    assert_eq!(
        patch.message_span_to_root(child_msg, inner_local.field).unwrap(),
        Some(expected_field_span)
    );
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
    let outer_tag = Document::make_tag(fnn(10), WireType::Len);
    let _ = root.push_length_delimited(fnn(10), child.to_buf().unwrap()).unwrap();
    let root_bytes = root.to_buf().unwrap();

    let mut patch = Patch::from_bytes(root_bytes.as_slice()).unwrap();
    let root_msg = patch.root();
    let outer_field_id = patch.fields_by_tag(root_msg, outer_tag).unwrap().next().unwrap();

    let mut edited_child = Document::new();
    let _ = edited_child.push_varint(fnn(2), 999).unwrap();
    patch.set_bytes(outer_field_id, edited_child.to_buf().unwrap()).unwrap();

    let child_msg = patch.parse_child_message(outer_field_id).unwrap();
    assert_eq!(patch.message_root_span(child_msg).unwrap(), None);

    let inner_tag = Document::make_tag(fnn(2), WireType::Varint);
    let inner_field_id = patch.fields_by_tag(child_msg, inner_tag).unwrap().next().unwrap();
    let inner_local = patch.field_spans(inner_field_id).unwrap().unwrap();

    assert_eq!(patch.message_span_to_root(child_msg, inner_local.field).unwrap(), None);
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

    let tag1 = Document::make_tag(fnn(1), WireType::Varint);
    let tag2 = Document::make_tag(fnn(2), WireType::Varint);

    {
        let mut txn = Txn::begin(&mut patch);
        let field1 = txn.tree().fields_by_tag(root, tag1).unwrap().next().unwrap();
        txn.tree().delete_field(field1).unwrap();
        let _ = txn.tree().insert_varint(root, tag2, 999).unwrap();
    }

    let out = patch.save().unwrap();
    let roundtrip = Document::from_bytes(out.as_slice()).unwrap();

    assert_eq!(roundtrip.first_ref(tag1).unwrap().as_uint64(), Some(7));
    assert!(roundtrip.first_ref(tag2).is_none());
}
