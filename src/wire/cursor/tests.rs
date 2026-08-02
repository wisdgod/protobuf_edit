use alloc::vec::Vec;

use super::{CursorError, CursorErrorKind, FieldCursor, RawField, WireValue};
use crate::wire::WireType;

fn collect(data: &[u8]) -> Vec<RawField<'_>> {
    FieldCursor::new(data).map(|r| r.expect("fixture must parse")).collect()
}

fn first_err(data: &[u8]) -> CursorError {
    FieldCursor::new(data).find_map(Result::err).expect("fixture must contain a malformed field")
}

#[test]
fn empty_input_yields_nothing() {
    assert!(FieldCursor::new(&[]).next().is_none());
}

#[test]
fn walks_every_wire_type_with_exact_raw_spans() {
    // field 1 varint 150 | field 2 len "abc" | field 3 fixed32 | field 4 fixed64
    let data: &[u8] = &[
        0x08, 0x96, 0x01, // 0..3
        0x12, 0x03, b'a', b'b', b'c', // 3..8
        0x1D, 0x01, 0x02, 0x03, 0x04, // 8..13
        0x21, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // 13..22
    ];
    let fields = collect(data);
    assert_eq!(fields.len(), 4);

    assert_eq!(fields[0].tag.field_number().as_inner(), 1);
    assert_eq!(fields[0].tag.wire_type(), WireType::Varint);
    assert_eq!(fields[0].value, WireValue::Varint(150));
    assert_eq!(fields[0].raw, &data[0..3]);
    assert_eq!(fields[0].offset, 0);

    assert_eq!(fields[1].value, WireValue::Len(b"abc"));
    assert_eq!(fields[1].raw, &data[3..8]);
    assert_eq!(fields[1].offset, 3);

    assert_eq!(fields[2].value, WireValue::I32([0x01, 0x02, 0x03, 0x04]));
    assert_eq!(fields[2].raw, &data[8..13]);
    assert_eq!(fields[2].offset, 8);

    assert_eq!(fields[3].value, WireValue::I64([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]));
    assert_eq!(fields[3].raw, &data[13..22]);
    assert_eq!(fields[3].offset, 13);
}

#[test]
fn field_number_zero_is_invalid_tag() {
    let err = first_err(&[0x00, 0x01]);
    assert_eq!(err, CursorError { offset: 0, kind: CursorErrorKind::InvalidTag });
}

#[test]
fn invalid_wire_types_are_rejected() {
    // Wire types 6 and 7 are never valid.
    for wt in [6u8, 7u8] {
        let err = first_err(&[(1 << 3) | wt]);
        assert_eq!(err, CursorError { offset: 0, kind: CursorErrorKind::InvalidTag });
    }
    // Wire types 3/4 (groups) are invalid without the group feature.
    #[cfg(not(feature = "group"))]
    for wt in [3u8, 4u8] {
        let err = first_err(&[(1 << 3) | wt]);
        assert_eq!(err, CursorError { offset: 0, kind: CursorErrorKind::InvalidTag });
    }
}

#[test]
fn multi_byte_field_numbers() {
    // field 16 varint 1: tag raw = 16<<3 = 128 -> [0x80, 0x01]
    let data: &[u8] = &[0x80, 0x01, 0x01];
    let fields = collect(data);
    assert_eq!(fields[0].tag.field_number().as_inner(), 16);
    assert_eq!(fields[0].value, WireValue::Varint(1));
    assert_eq!(fields[0].raw, data);

    // Max field number (2^29 - 1), wire type I32: raw tag = 0xFFFF_FFFD.
    let data: &[u8] = &[0xFD, 0xFF, 0xFF, 0xFF, 0x0F, 0x01, 0x02, 0x03, 0x04];
    let fields = collect(data);
    assert_eq!(fields[0].tag.field_number().as_inner(), (1 << 29) - 1);
    assert_eq!(fields[0].tag.wire_type(), WireType::I32);
    assert_eq!(fields[0].raw, data);
}

#[test]
fn len_boundary_lengths_127_128_16383_16384() {
    fn len_field(len: usize, prefix: &[u8]) -> Vec<u8> {
        let mut data = alloc::vec![0x0A];
        data.extend_from_slice(prefix);
        data.resize(1 + prefix.len() + len, 0xAB);
        data
    }

    for (len, prefix) in [
        (127usize, &[0x7F][..]),
        (128, &[0x80, 0x01][..]),
        (16383, &[0xFF, 0x7F][..]),
        (16384, &[0x80, 0x80, 0x01][..]),
    ] {
        let data = len_field(len, prefix);
        let fields = collect(&data);
        assert_eq!(fields.len(), 1, "len {len}");
        let WireValue::Len(payload) = fields[0].value else {
            panic!("expected len value for len {len}");
        };
        assert_eq!(payload.len(), len);
        assert_eq!(fields[0].raw, &data[..]);

        // One byte short of the declared length must fail as truncation.
        let short = &data[..data.len() - 1];
        let err = first_err(short);
        assert_eq!(err.kind, CursorErrorKind::Truncated);
        assert_eq!(err.offset, 1 + prefix.len());
    }
}

#[test]
fn ten_byte_u64_varint_roundtrips() {
    let mut data = alloc::vec![0x08];
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
    let fields = collect(&data);
    assert_eq!(fields[0].value, WireValue::Varint(u64::MAX));
    assert_eq!(fields[0].raw, &data[..]);
}

#[test]
fn overlong_varints_are_invalid() {
    // 10th byte overflows u64 (only bit 0 may be set).
    let mut data = alloc::vec![0x08];
    data.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]);
    assert_eq!(first_err(&data), CursorError { offset: 1, kind: CursorErrorKind::InvalidVarint });

    // No terminator within 10 bytes.
    let mut data = alloc::vec![0x08];
    data.extend_from_slice(&[0xFF; 11]);
    assert_eq!(first_err(&data), CursorError { offset: 1, kind: CursorErrorKind::InvalidVarint });

    // Tag varint with the 5th byte overflowing u32.
    let data: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0x10, 0x00];
    assert_eq!(first_err(data), CursorError { offset: 0, kind: CursorErrorKind::InvalidVarint });
}

#[test]
fn truncation_is_distinguished_from_invalid_varints() {
    // Varint value cut off mid-way: continuation bit set, input ends.
    assert_eq!(
        first_err(&[0x08, 0x96]),
        CursorError { offset: 1, kind: CursorErrorKind::Truncated }
    );
    // Length prefix cut off mid-way.
    assert_eq!(
        first_err(&[0x12, 0x80]),
        CursorError { offset: 1, kind: CursorErrorKind::Truncated }
    );
    // Tag cut off mid-way.
    assert_eq!(first_err(&[0x80]), CursorError { offset: 0, kind: CursorErrorKind::Truncated });
}

#[test]
fn truncated_fixed32_and_fixed64() {
    let err = first_err(&[0x0D, 0x01, 0x02, 0x03]);
    assert_eq!(err, CursorError { offset: 1, kind: CursorErrorKind::Truncated });

    let err = first_err(&[0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    assert_eq!(err, CursorError { offset: 1, kind: CursorErrorKind::Truncated });
}

#[test]
fn non_canonical_tag_and_length_are_preserved_in_raw() {
    // Tag 8 (field 1 varint) in a non-canonical 2-byte encoding, value 1 in a
    // non-canonical 2-byte encoding.
    let data: &[u8] = &[0x88, 0x00, 0x81, 0x00];
    let fields = collect(data);
    assert_eq!(fields[0].tag.field_number().as_inner(), 1);
    assert_eq!(fields[0].value, WireValue::Varint(1));
    assert_eq!(fields[0].raw, data, "non-canonical bytes must survive in the raw span");

    // Non-canonical length prefix: 3 encoded as [0x83, 0x00].
    let data: &[u8] = &[0x12, 0x83, 0x00, b'a', b'b', b'c'];
    let fields = collect(data);
    assert_eq!(fields[0].value, WireValue::Len(b"abc"));
    assert_eq!(fields[0].raw, data);
}

#[test]
fn empty_len_payload() {
    let data: &[u8] = &[0x12, 0x00];
    let fields = collect(data);
    assert_eq!(fields[0].value, WireValue::Len(&[]));
    assert_eq!(fields[0].raw, data);
}

#[test]
fn error_poisons_the_cursor() {
    // Valid field followed by a field-number-0 tag.
    let data: &[u8] = &[0x08, 0x96, 0x01, 0x00];
    let mut cursor = FieldCursor::new(data);

    let first = cursor.next().unwrap().unwrap();
    assert_eq!(first.value, WireValue::Varint(150));

    let err = cursor.next().unwrap().unwrap_err();
    assert_eq!(err, CursorError { offset: 3, kind: CursorErrorKind::InvalidTag });

    assert!(cursor.next().is_none(), "cursor must not yield past the malformed unit");
}

#[test]
fn caller_driven_nested_descent() {
    // field 3 len { field 1 varint 150 } | field 4 varint 7
    let data: &[u8] = &[0x1A, 0x03, 0x08, 0x96, 0x01, 0x20, 0x07];
    let fields = collect(data);
    assert_eq!(fields.len(), 2);

    let WireValue::Len(payload) = fields[0].value else {
        panic!("expected len value");
    };
    let inner = collect(payload);
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].value, WireValue::Varint(150));
    assert_eq!(inner[0].offset, 0, "inner offsets are payload-relative");

    assert_eq!(fields[1].value, WireValue::Varint(7));
    assert_eq!(fields[1].offset, 5);
}

#[test]
fn cursor_offset_and_remaining_track_progress() {
    let data: &[u8] = &[0x08, 0x01, 0x10, 0x02];
    let mut cursor = FieldCursor::new(data);
    assert_eq!(cursor.offset(), 0);
    assert_eq!(cursor.remaining(), data);

    cursor.next().unwrap().unwrap();
    assert_eq!(cursor.offset(), 2);
    assert_eq!(cursor.remaining(), &data[2..]);

    cursor.next().unwrap().unwrap();
    assert_eq!(cursor.offset(), 4);
    assert!(cursor.remaining().is_empty());
    assert!(cursor.next().is_none());
}

#[cfg(feature = "group")]
mod group {
    use super::*;

    #[test]
    fn group_body_and_raw_span() {
        // field 1 SGroup { field 2 varint 5 } EGroup
        let data: &[u8] = &[0x0B, 0x10, 0x05, 0x0C];
        let fields = collect(data);
        assert_eq!(fields.len(), 1);
        let WireValue::Group(body) = fields[0].value else {
            panic!("expected group value");
        };
        assert_eq!(body, &data[1..3]);
        assert_eq!(fields[0].raw, data);
    }

    #[test]
    fn stray_end_group_is_malformed() {
        let err = first_err(&[0x0C]);
        assert_eq!(err, CursorError { offset: 0, kind: CursorErrorKind::MalformedGroup });
    }

    #[test]
    fn unterminated_group_is_malformed() {
        let err = first_err(&[0x0B, 0x10, 0x05]);
        assert_eq!(err, CursorError { offset: 1, kind: CursorErrorKind::MalformedGroup });
    }
}
