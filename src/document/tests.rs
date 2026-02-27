use super::*;
use crate::data_structures::Buf;
use crate::{varint, wire};
use crate::wire::WireType;

fn fnn(n: u32) -> wire::FieldNumber {
    wire::FieldNumber::new(n).unwrap()
}

fn buf_from_slice(data: &[u8]) -> Buf {
    let mut buf = Buf::new();
    buf.extend_from_slice(data).expect("tiny test fixture should fit");
    buf
}

#[test]
fn raw_varint32_unchecked_roundtrip_and_decode_validation() {
    let raw = [0xAC, 0x02];
    let packed = unsafe { RawVarint32::from_slice_unchecked(&raw) };
    let (bytes, len) = packed.to_array();
    assert_eq!(len, 2);
    assert_eq!(&bytes[..len], &raw);

    let raw_max = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
    let packed_max = unsafe { RawVarint32::from_slice_unchecked(&raw_max) };
    let (bytes_max, len_max) = packed_max.to_array();
    assert_eq!(len_max, 5);
    assert_eq!(&bytes_max[..len_max], &raw_max);

    let bad_last = [0xFF, 0xFF, 0xFF, 0xFF, 0xF0];
    assert!(matches!(RawVarint32::from_data(&bad_last), Err(TreeError::DecodeError)));
}

#[test]
fn raw_varint64_unchecked_roundtrip_and_decode_validation() {
    let raw = [0x80, 0x01];
    let packed = unsafe { RawVarint64::from_slice_unchecked(&raw) };
    let (bytes, len) = packed.to_array();
    assert_eq!(len, 2);
    assert_eq!(&bytes[..len], &raw);

    let raw_max = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
    let packed_max = unsafe { RawVarint64::from_slice_unchecked(&raw_max) };
    let (bytes_max, len_max) = packed_max.to_array();
    assert_eq!(len_max, 10);
    assert_eq!(&bytes_max[..len_max], &raw_max);

    let bad_last = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
    assert!(matches!(RawVarint64::from_data(&bad_last), Err(TreeError::DecodeError)));
}

#[test]
fn removed_is_bool_and_skipped_by_encoder() {
    let mut tree = Document::new();
    let _ = tree.push_varint(fnn(1), 7).unwrap();
    let removed_ix = tree.push_fixed32(fnn(2), 42).unwrap();
    tree.mark_removed(removed_ix);

    let encoded = tree.to_buf().unwrap();
    let roundtrip = Document::from_bytes(&encoded).unwrap();

    assert_eq!(roundtrip.fields.len(), 1);
    assert_eq!(roundtrip.fields[0].tag, Document::make_tag(fnn(1), WireType::Varint));
    assert_eq!(roundtrip.varints.len(), 1);
}

#[test]
fn roundtrip_all_scalar_wire_types() {
    let mut tree = Document::new();
    let _ = tree.push_varint(fnn(1), 150).unwrap();
    let _ = tree.push_fixed64(fnn(2), 0x0102_0304_0506_0708).unwrap();
    let _ = tree.push_length_delimited(fnn(3), buf_from_slice(b"abc")).unwrap();
    let _ = tree.push_fixed32(fnn(4), 0x1122_3344).unwrap();

    let encoded = tree.to_buf().unwrap();
    let roundtrip = Document::from_bytes(&encoded).unwrap();

    assert_eq!(roundtrip.fields.len(), 4);
    assert_eq!(roundtrip.varints[0].value, 150);
    assert_eq!(roundtrip.fixed64s[0].value, 0x0102_0304_0506_0708);
    assert_eq!(roundtrip.lendels[0].buf.as_slice(), b"abc");
    assert_eq!(roundtrip.fixed32s[0].value, 0x1122_3344);
}

#[test]
fn encoded_len_matches_to_buf_and_skips_removed() {
    let mut tree = Document::new();
    let _ = tree.push_varint(fnn(1), 150).unwrap();
    let removed_ix = tree.push_fixed32(fnn(2), 0x1122_3344).unwrap();
    let _ = tree.push_length_delimited(fnn(3), buf_from_slice(b"abc")).unwrap();
    tree.mark_removed(removed_ix);

    let exact = tree.encoded_len().unwrap();
    let encoded = tree.to_buf().unwrap();
    assert_eq!(exact, encoded.len());

    let mut out = buf_from_slice(b"xx");
    tree.encode_into(&mut out).unwrap();
    assert_eq!(out.len(), 2 + exact);
    assert_eq!(&out.as_slice()[2..], encoded.as_slice());
}

#[cfg(feature = "group")]
#[test]
fn group_roundtrip_keeps_body_bytes() {
    let mut group_body = Buf::new();
    wire::encode_tag(&mut group_body, fnn(2), WireType::Varint).unwrap();
    let _ = varint::encode64(&mut group_body, 999).unwrap();

    let mut tree = Document::new();
    let _ = tree.push_group(fnn(10), group_body.clone()).unwrap();

    let encoded = tree.to_buf().unwrap();
    let roundtrip = Document::from_bytes(&encoded).unwrap();

    assert_eq!(roundtrip.groups.len(), 1);
    assert_eq!(roundtrip.groups[0].buf.as_slice(), group_body.as_slice());
    assert_eq!(roundtrip.to_buf().unwrap(), encoded);
}

#[cfg(feature = "group")]
#[test]
fn encoded_len_matches_to_buf_with_group() {
    let mut group_body = Buf::new();
    wire::encode_tag(&mut group_body, fnn(2), WireType::Varint).unwrap();
    let _ = varint::encode64(&mut group_body, 999).unwrap();

    let mut tree = Document::new();
    let _ = tree.push_group(fnn(10), group_body).unwrap();
    let _ = tree.push_varint(fnn(1), 7).unwrap();

    assert_eq!(tree.encoded_len().unwrap(), tree.to_buf().unwrap().len());
}

#[cfg(feature = "group")]
#[test]
fn decode_nested_group_succeeds() {
    let mut msg = Buf::new();
    wire::encode_tag(&mut msg, fnn(1), WireType::SGroup).unwrap();
    wire::encode_tag(&mut msg, fnn(2), WireType::SGroup).unwrap();
    wire::encode_tag(&mut msg, fnn(2), WireType::EGroup).unwrap();
    wire::encode_tag(&mut msg, fnn(1), WireType::EGroup).unwrap();

    let tree = Document::from_bytes(&msg).unwrap();
    assert_eq!(tree.groups.len(), 1);
    assert_eq!(tree.to_buf().unwrap(), msg);
}

#[test]
fn decode_error_on_unexpected_end_group() {
    let mut bad = Buf::new();
    // Raw tag: (field_number << 3) | wire_type, where EndGroup wire type is 4.
    let _ = varint::encode32(&mut bad, (9 << 3) | 4).unwrap();
    assert!(matches!(Document::from_bytes(&bad), Err(TreeError::DecodeError)));
}

#[test]
fn decode_error_on_truncated_length_delimited() {
    let mut bad = Buf::new();
    wire::encode_tag(&mut bad, fnn(1), WireType::Len).unwrap();
    let _ = varint::encode32(&mut bad, 3).unwrap();
    let _ = bad.push(0xAA);

    assert!(matches!(Document::from_bytes(&bad), Err(TreeError::DecodeError)));
}

#[test]
fn query_key_is_tag() {
    let mut tree = Document::new();
    let _ = tree.push_varint(fnn(7), 1).unwrap();

    let tag = Document::make_tag(fnn(7), WireType::Varint);
    assert!(tree.bucket(tag).is_some());
    assert!(tree.bucket_by_parts(7, WireType::Varint).is_some());
    assert!(tree.bucket_by_parts(7, WireType::I32).is_none());
}

#[test]
fn push_does_not_pollute_typed_pool_when_fields_capacity_exceeded() {
    let mut tree = Document::new();
    let tag = Document::make_tag(fnn(1), WireType::Varint);
    for _ in 0..MAX_FIELDS {
        tree.fields.push(Field {
            tag,
            removed: false,
            index: Ix::MIN,
            prev: None,
            next: None,
            raw: RawVarint32::from_u32(tag.get()),
        });
    }

    let ret = tree.push_varint(fnn(1), 123);
    assert!(matches!(ret, Err(TreeError::CapacityExceeded)));
    assert_eq!(tree.varints.len(), 0);
}

#[test]
fn push_rejects_invalid_tag_before_pool_write() {
    let mut tree = Document::new();
    let ret = tree.push_varint_u32(0, 7);
    assert!(matches!(ret, Err(TreeError::InvalidTag)));
    assert!(tree.fields.is_empty());
    assert!(tree.varints.is_empty());
}

#[test]
fn decode_len_guard_matches_protobuf_limit() {
    const MAX: usize = const { i32::MAX as usize };
    assert!(super::helpers::ensure_decode_len(MAX).is_ok());
    assert!(matches!(super::helpers::ensure_decode_len(MAX + 1), Err(TreeError::DecodeError)));
}

#[test]
fn field_ref_and_field_mut_int32() {
    let mut tree = Document::new();
    let ix = tree.push_varint(fnn(3), 7).unwrap();

    {
        let mut f = tree.field_mut(ix).unwrap();
        f.int32(|v| *v += 5).unwrap();
    }

    let r = tree.field_ref(ix).unwrap();
    assert_eq!(r.as_int32(), Some(12));
}

#[test]
fn field_mut_message_edits_nested_tree() {
    let mut nested = Document::new();
    let _ = nested.push_varint(fnn(1), 10).unwrap();

    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(5), nested.to_buf().unwrap()).unwrap();

    let msg_tag = Document::make_tag(fnn(5), WireType::Len);
    root.first_mut(msg_tag)
        .unwrap()
        .message_with_capacities(Capacities::default(), |inner| {
            let _ = inner.push_varint(fnn(2), 99).unwrap();
            let v1_tag = Document::make_tag(fnn(1), WireType::Varint);
            inner.first_mut(v1_tag).unwrap().int32(|v| *v += 1).unwrap();
            Ok(())
        })
        .unwrap();

    let nested_after =
        root.first_ref(msg_tag).unwrap().as_message_with_capacities(Capacities::default()).unwrap();
    let f1_tag = Document::make_tag(fnn(1), WireType::Varint);
    let f2_tag = Document::make_tag(fnn(2), WireType::Varint);
    assert_eq!(nested_after.first_ref(f1_tag).unwrap().as_uint64(), Some(11));
    assert_eq!(nested_after.first_ref(f2_tag).unwrap().as_uint64(), Some(99));
}

#[test]
fn first_ref_skips_removed_nodes() {
    let mut tree = Document::new();
    let first = tree.push_varint(fnn(9), 1).unwrap();
    let _ = tree.push_varint(fnn(9), 2).unwrap();
    tree.mark_removed(first);

    let tag = Document::make_tag(fnn(9), WireType::Varint);
    let first_live = tree.first_ref(tag).unwrap();
    assert_eq!(first_live.as_uint64(), Some(2));
}

#[test]
fn field_mut_varint_method_family() {
    let mut tree = Document::new();
    let ix = tree.push_varint(fnn(1), 1).unwrap();

    let mut f = tree.field_mut(ix).unwrap();
    f.uint32(|v| *v = 10).unwrap();
    f.int64(|v| *v += 5).unwrap();
    f.sint64(|v| *v = -7).unwrap();
    f.bool(|v| *v = true).unwrap();

    let r = tree.field_ref(ix).unwrap();
    assert_eq!(r.as_bool(), Some(true));
}

#[test]
fn field_mut_fixed_method_family() {
    let mut tree = Document::new();
    let f32_ix = tree.push_fixed32(fnn(2), 1).unwrap();
    let f64_ix = tree.push_fixed64(fnn(3), 2).unwrap();

    {
        let mut f = tree.field_mut(f32_ix).unwrap();
        f.fixed32(|v| *v = 8).unwrap();
        f.sfixed32(|v| *v = -2).unwrap();
        f.float(|v| *v = 1.5).unwrap();
    }
    {
        let mut f = tree.field_mut(f64_ix).unwrap();
        f.fixed64(|v| *v = 9).unwrap();
        f.sfixed64(|v| *v = -3).unwrap();
        f.double(|v| *v = 2.5).unwrap();
    }

    let r32 = tree.field_ref(f32_ix).unwrap();
    let r64 = tree.field_ref(f64_ix).unwrap();
    assert_eq!(r32.as_float(), Some(1.5));
    assert_eq!(r64.as_double(), Some(2.5));
}

#[test]
fn field_mut_bytes_works() {
    let mut tree = Document::new();
    let bytes_ix = tree.push_length_delimited(fnn(4), buf_from_slice(b"ab")).unwrap();

    tree.field_mut(bytes_ix)
        .unwrap()
        .bytes(|b| b.extend_from_slice(b"c").expect("test append should fit"))
        .unwrap();

    assert_eq!(tree.field_ref(bytes_ix).unwrap().as_bytes(), Some(&b"abc"[..]));
}

#[cfg(feature = "group")]
#[test]
fn field_mut_group_bytes_works() {
    let mut tree = Document::new();
    let group_ix = tree.push_group(fnn(5), buf_from_slice(b"xy")).unwrap();
    tree.field_mut(group_ix)
        .unwrap()
        .group_bytes(|b| b.extend_from_slice(b"z").expect("test append should fit"))
        .unwrap();
    assert_eq!(tree.field_ref(group_ix).unwrap().as_group_bytes(), Some(&b"xyz"[..]));
}

#[test]
fn with_capacities_reserves_vectors() {
    let caps = Capacities {
        fields: 16,
        varints: 8,
        fixed32s: 4,
        fixed64s: 4,
        lendels: 2,
        #[cfg(feature = "group")]
        groups: 2,
        query: 8,
    };
    let tree = Document::with_capacities(caps);

    assert!(tree.fields.capacity() >= 16);
    assert!(tree.varints.capacity() >= 8);
    assert!(tree.fixed32s.capacity() >= 4);
    assert!(tree.fixed64s.capacity() >= 4);
    assert!(tree.lendels.capacity() >= 2);
    #[cfg(feature = "group")]
    assert!(tree.groups.capacity() >= 2);
}

#[test]
fn repeated_refs_and_visit_mut_work() {
    let mut tree = Document::new();
    let _ = tree.push_varint(fnn(11), 1).unwrap();
    let removed = tree.push_varint(fnn(11), 2).unwrap();
    let _ = tree.push_varint(fnn(11), 3).unwrap();
    tree.mark_removed(removed);

    let tag = Document::make_tag(fnn(11), WireType::Varint);
    let mut values = alloc::vec::Vec::new();
    for r in tree.repeated_refs(tag) {
        values.push(r.as_uint64().unwrap());
    }
    assert_eq!(values.as_slice(), &[1, 3]);

    tree.repeated_visit_mut(tag, |mut field| {
        field.int64(|v| *v += 10).unwrap();
        Ok(())
    })
    .unwrap();

    let mut values = alloc::vec::Vec::new();
    for r in tree.repeated_refs(tag) {
        values.push(r.as_uint64().unwrap());
    }
    assert_eq!(values.as_slice(), &[11, 13]);
    assert_eq!(tree.field_ref(removed).unwrap().as_uint64(), Some(12));
}

#[test]
fn packed_read_write_works() {
    let mut tree = Document::new();
    let packed_u32_ix = tree.push_length_delimited(fnn(12), Buf::new()).unwrap();
    let packed_s32_ix = tree.push_length_delimited(fnn(13), Buf::new()).unwrap();

    {
        let mut f = tree.field_mut(packed_u32_ix).unwrap();
        f.push_packed_uint32(1).unwrap();
        f.push_packed_uint32(150).unwrap();
    }
    {
        let mut f = tree.field_mut(packed_s32_ix).unwrap();
        f.push_packed_sint32(1).unwrap();
        f.push_packed_sint32(-3).unwrap();
    }

    let mut out = alloc::vec::Vec::new();
    out.extend(
        tree.field_ref(packed_u32_ix)
            .unwrap()
            .packed_uint32()
            .unwrap()
            .collect::<Result<alloc::vec::Vec<_>, _>>()
            .unwrap(),
    );
    assert_eq!(out.as_slice(), &[1, 150]);

    let mut sint = alloc::vec::Vec::new();
    sint.extend(
        tree.field_ref(packed_s32_ix)
            .unwrap()
            .packed_sint32()
            .unwrap()
            .collect::<Result<alloc::vec::Vec<_>, _>>()
            .unwrap(),
    );
    assert_eq!(sint.as_slice(), &[1, -3]);
}

#[test]
fn packed_fixed_iters_support_double_ended_and_exact_size() {
    let mut tree = Document::new();
    let packed_f32_ix = tree.push_length_delimited(fnn(20), Buf::new()).unwrap();
    let packed_f64_ix = tree.push_length_delimited(fnn(21), Buf::new()).unwrap();

    {
        let mut f = tree.field_mut(packed_f32_ix).unwrap();
        f.push_packed_fixed32(0x1122_3344).unwrap();
        f.push_packed_fixed32(0x5566_7788).unwrap();
    }
    {
        let mut f = tree.field_mut(packed_f64_ix).unwrap();
        f.push_packed_fixed64(0x0102_0304_0506_0708).unwrap();
        f.push_packed_fixed64(0x1112_1314_1516_1718).unwrap();
    }

    let mut it32 = tree.field_ref(packed_f32_ix).unwrap().packed_fixed32().unwrap();
    assert_eq!(it32.len(), 2);
    assert_eq!(it32.next(), Some(0x1122_3344));
    assert_eq!(it32.len(), 1);
    assert_eq!(it32.next_back(), Some(0x5566_7788));
    assert_eq!(it32.len(), 0);
    assert_eq!(it32.next(), None);
    assert_eq!(it32.next_back(), None);

    let mut it64 = tree.field_ref(packed_f64_ix).unwrap().packed_fixed64().unwrap();
    assert_eq!(it64.len(), 2);
    assert_eq!(it64.next_back(), Some(0x1112_1314_1516_1718));
    assert_eq!(it64.len(), 1);
    assert_eq!(it64.next(), Some(0x0102_0304_0506_0708));
    assert_eq!(it64.len(), 0);
    assert_eq!(it64.next(), None);
    assert_eq!(it64.next_back(), None);
}

#[test]
fn edit_planned_mut_updates_only_selected_tag() {
    let mut tree = Document::new();
    let _ = tree.push_varint(fnn(30), 1).unwrap();
    let _ = tree.push_varint(fnn(30), 2).unwrap();
    let _ = tree.push_varint(fnn(31), 9).unwrap();

    let src = tree.to_buf().unwrap();
    let tag30 = Document::make_tag(fnn(30), WireType::Varint);
    let tag31 = Document::make_tag(fnn(31), WireType::Varint);

    let plan = [(
        tag30,
        Capacities {
            fields: 4,
            varints: 4,
            fixed32s: 0,
            fixed64s: 0,
            lendels: 0,
            #[cfg(feature = "group")]
            groups: 0,
            query: 1,
        },
    )];

    let out = Document::edit_planned_mut(src.as_slice(), &plan, |mut field| {
        field.int64(|v| *v += 10).unwrap();
        Ok(())
    })
    .unwrap();

    let decoded = Document::from_bytes(out.as_slice()).unwrap();
    let values30 = decoded
        .repeated_refs(tag30)
        .map(|f| f.as_uint64().unwrap())
        .collect::<alloc::vec::Vec<_>>();
    let values31 = decoded
        .repeated_refs(tag31)
        .map(|f| f.as_uint64().unwrap())
        .collect::<alloc::vec::Vec<_>>();
    assert_eq!(values30.as_slice(), &[11, 12]);
    assert_eq!(values31.as_slice(), &[9]);
}

#[test]
fn visit_planned_refs_borrows_payload_for_read_only() {
    let mut tree = Document::new();
    let _ = tree.push_length_delimited(fnn(7), buf_from_slice(b"xyz")).unwrap();
    let src = tree.to_buf().unwrap();
    let src_slice = src.as_slice();

    let tag = Document::make_tag(fnn(7), WireType::Len);
    let (decoded_tag, tag_len) = wire::decode_tag(src_slice).unwrap();
    assert_eq!(decoded_tag, tag);
    let (len, len_len) = varint::decode32(&src_slice[tag_len as usize..]).unwrap();
    assert_eq!(len, 3);
    let body_start = tag_len as usize + len_len as usize;
    let expected_ptr = src_slice[body_start..].as_ptr();

    let mut seen_ptr: *const u8 = ::core::ptr::null();
    Document::visit_planned_refs(src_slice, &[(tag, Capacities::default())], |field| {
        let bytes = field.as_bytes().unwrap();
        seen_ptr = bytes.as_ptr();
        assert_eq!(bytes, b"xyz");
    })
    .unwrap();

    assert!(!seen_ptr.is_null());
    assert_eq!(seen_ptr, expected_ptr);
}

#[test]
fn from_bytes_with_capacities_decodes_owned_tree() {
    let mut tree = Document::new();
    let _ = tree.push_varint(fnn(3), 123).unwrap();
    let _ = tree.push_length_delimited(fnn(4), buf_from_slice(b"ab")).unwrap();
    let src = tree.to_buf().unwrap();

    let capacities = Capacities {
        fields: 8,
        varints: 4,
        fixed32s: 0,
        fixed64s: 0,
        lendels: 4,
        #[cfg(feature = "group")]
        groups: 0,
        query: 4,
    };
    let decoded = Document::from_bytes_with_capacities(src.as_slice(), capacities).unwrap();

    let tag3 = Document::make_tag(fnn(3), WireType::Varint);
    let tag4 = Document::make_tag(fnn(4), WireType::Len);
    assert_eq!(decoded.first_ref(tag3).unwrap().as_uint64(), Some(123));
    assert_eq!(decoded.first_ref(tag4).unwrap().as_bytes(), Some(&b"ab"[..]));
}

#[test]
fn borrowed_lazy_tree_wrapper_is_lifetime_bound_and_supports_field_ref_mut() {
    let mut src_tree = Document::new();
    let _ = src_tree.push_length_delimited(fnn(7), buf_from_slice(b"xyz")).unwrap();
    let src = src_tree.to_buf().unwrap();
    let src_slice = src.as_slice();
    let tag7 = Document::make_tag(fnn(7), WireType::Len);

    let (decoded_tag, tag_len) = wire::decode_tag(src_slice).unwrap();
    assert_eq!(decoded_tag, tag7);
    let (_, len_len) = varint::decode32(&src_slice[tag_len as usize..]).unwrap();
    let body_start = tag_len as usize + len_len as usize;
    let expected_ptr = src_slice[body_start..].as_ptr();

    let mut borrowed =
        BorrowedDocument::from_bytes_with_capacities(src_slice, Capacities::default()).unwrap();

    let first = borrowed.first_ref(tag7).unwrap();
    let body = first.as_bytes().unwrap();
    assert_eq!(body, b"xyz");
    assert_eq!(body.as_ptr(), expected_ptr);

    borrowed
        .first_mut(tag7)
        .unwrap()
        .bytes(|b| b.extend_from_slice(b"!").expect("append should fit"))
        .unwrap();
    let out = borrowed.to_buf().unwrap();
    let roundtrip = Document::from_bytes(out.as_slice()).unwrap();
    assert_eq!(roundtrip.first_ref(tag7).unwrap().as_bytes(), Some(&b"xyz!"[..]));
}

#[test]
fn field_ref_borrowed_message_with_capacities_works() {
    let mut inner = Document::new();
    let _ = inner.push_varint(fnn(2), 10).unwrap();

    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(1), inner.to_buf().unwrap()).unwrap();

    let outer = Document::make_tag(fnn(1), WireType::Len);
    let inner_tag = Document::make_tag(fnn(2), WireType::Varint);

    let nested =
        root.first_ref(outer).unwrap().as_message_with_capacities(Capacities::default()).unwrap();
    assert_eq!(nested.first_ref(inner_tag).unwrap().as_uint64(), Some(10));
}

#[test]
fn planned_path_descends_in_order_for_nested_edit() {
    let mut child_a = Document::new();
    let _ = child_a.push_varint(fnn(2), 1).unwrap();
    let mut child_b = Document::new();
    let _ = child_b.push_varint(fnn(2), 3).unwrap();

    let mut root = Document::new();
    let _ = root.push_length_delimited(fnn(10), child_a.to_buf().unwrap()).unwrap();
    let _ = root.push_length_delimited(fnn(10), child_b.to_buf().unwrap()).unwrap();

    let src = root.to_buf().unwrap();
    let outer = Document::make_tag(fnn(10), WireType::Len);
    let inner = Document::make_tag(fnn(2), WireType::Varint);
    let plan = [
        (
            outer,
            Capacities {
                fields: 4,
                varints: 0,
                fixed32s: 0,
                fixed64s: 0,
                lendels: 4,
                #[cfg(feature = "group")]
                groups: 0,
                query: 2,
            },
        ),
        (
            inner,
            Capacities {
                fields: 4,
                varints: 4,
                fixed32s: 0,
                fixed64s: 0,
                lendels: 0,
                #[cfg(feature = "group")]
                groups: 0,
                query: 2,
            },
        ),
    ];

    let out = Document::edit_planned_mut(src.as_slice(), &plan, |mut field| {
        field.int64(|v| *v += 100).unwrap();
        Ok(())
    })
    .unwrap();

    let decoded = Document::from_bytes(out.as_slice()).unwrap();
    let mut got = alloc::vec::Vec::new();
    for outer_ref in decoded.repeated_refs(outer) {
        let child = outer_ref.as_message().unwrap();
        got.push(child.first_ref(inner).unwrap().as_uint64().unwrap());
    }
    assert_eq!(got.as_slice(), &[101, 103]);
}
