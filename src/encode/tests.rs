use super::{encode, encode_into, encoded_len, EncodeError, Field, Value, MAX_ENCODE_DEPTH};
use crate::buf::Buf;
use crate::field_number;
use crate::wire::{FieldCursor, WireValue};

#[test]
fn golden_varint_field() {
    // Canonical protobuf example: field 1, varint 150.
    let fields = [Field::new(field_number!(1), Value::Varint(150))];
    assert_eq!(encoded_len(&fields).unwrap(), 3);
    assert_eq!(encode(&fields).unwrap().as_slice(), &[0x08, 0x96, 0x01]);
}

#[test]
fn golden_all_value_kinds() {
    let fields = [
        Field::new(field_number!(1), Value::Varint(1)),
        Field::new(field_number!(2), Value::Fixed32(0x1122_3344)),
        Field::new(field_number!(3), Value::Fixed64(0x1122_3344_5566_7788)),
        Field::new(field_number!(4), Value::Bytes(b"abc")),
    ];
    let expected: &[u8] = &[
        0x08, 0x01, // field 1 varint 1
        0x15, 0x44, 0x33, 0x22, 0x11, // field 2 fixed32 LE
        0x19, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // field 3 fixed64 LE
        0x22, 0x03, b'a', b'b', b'c', // field 4 bytes "abc"
    ];
    assert_eq!(encoded_len(&fields).unwrap() as usize, expected.len());
    assert_eq!(encode(&fields).unwrap().as_slice(), expected);
}

#[test]
fn golden_nested_message() {
    // field 3 message { field 1 varint 150 }
    let inner = [Field::new(field_number!(1), Value::Varint(150))];
    let fields = [Field::new(field_number!(3), Value::Message(&inner))];
    assert_eq!(encode(&fields).unwrap().as_slice(), &[0x1A, 0x03, 0x08, 0x96, 0x01]);
}

#[test]
fn golden_empty_message_and_empty_bytes() {
    let fields = [
        Field::new(field_number!(1), Value::Message(&[])),
        Field::new(field_number!(2), Value::Bytes(&[])),
    ];
    assert_eq!(encode(&fields).unwrap().as_slice(), &[0x0A, 0x00, 0x12, 0x00]);
}

#[test]
fn golden_multi_byte_tag_and_length_prefix() {
    // field 16 varint 1: tag raw = 128 -> two tag bytes.
    let fields = [Field::new(field_number!(16), Value::Varint(1))];
    assert_eq!(encode(&fields).unwrap().as_slice(), &[0x80, 0x01, 0x01]);

    // 128-byte payload needs a two-byte length prefix.
    let payload = [0xABu8; 128];
    let fields = [Field::new(field_number!(1), Value::Bytes(&payload))];
    let out = encode(&fields).unwrap();
    assert_eq!(out.len() as usize, 1 + 2 + 128);
    assert_eq!(&out.as_slice()[..3], &[0x0A, 0x80, 0x01]);
    assert!(out.as_slice()[3..].iter().all(|&b| b == 0xAB));
}

#[test]
fn nested_length_prefixes_are_exact() {
    // Two levels: field 1 { field 2 { field 3 varint 1 } field 4 bytes "xy" }
    let leaf = [Field::new(field_number!(3), Value::Varint(1))];
    let mid = [
        Field::new(field_number!(2), Value::Message(&leaf)),
        Field::new(field_number!(4), Value::Bytes(b"xy")),
    ];
    let root = [Field::new(field_number!(1), Value::Message(&mid))];

    let expected: &[u8] = &[
        0x0A, 0x08, // field 1, len 8
        0x12, 0x02, 0x18, 0x01, // field 2, len 2 { field 3 varint 1 }
        0x22, 0x02, b'x', b'y', // field 4, len 2
    ];
    assert_eq!(encode(&root).unwrap().as_slice(), expected);
}

#[test]
fn encode_into_appends_after_existing_bytes() {
    let mut out = Buf::new();
    out.extend_from_slice(&[0xFF, 0xFE]).unwrap();

    let fields = [Field::new(field_number!(1), Value::Varint(150))];
    encode_into(&fields, &mut out).unwrap();
    assert_eq!(out.as_slice(), &[0xFF, 0xFE, 0x08, 0x96, 0x01]);
}

#[test]
fn encode_allocates_exactly_once() {
    let payload = [0x55u8; 300];
    let inner = [Field::new(field_number!(2), Value::Bytes(&payload))];
    let fields = [
        Field::new(field_number!(1), Value::Message(&inner)),
        Field::new(field_number!(3), Value::Varint(u64::MAX)),
    ];

    let len = encoded_len(&fields).unwrap();
    let out = encode(&fields).unwrap();
    assert_eq!(out.len(), len);
    // Exactly the reserved capacity: no growth happened during the write.
    assert_eq!(out.capacity(), len);
}

#[test]
fn depth_limit_is_enforced() {
    fn nest_and_measure(levels: usize, inner: &[Field<'_>]) -> Result<u32, EncodeError> {
        if levels == 0 {
            return encoded_len(inner);
        }
        let level = [Field::new(field_number!(1), Value::Message(inner))];
        nest_and_measure(levels - 1, &level)
    }

    let leaf = [Field::new(field_number!(2), Value::Varint(1))];
    assert!(nest_and_measure(MAX_ENCODE_DEPTH, &leaf).is_ok());
    assert_eq!(nest_and_measure(MAX_ENCODE_DEPTH + 1, &leaf), Err(EncodeError::DepthLimitExceeded));
}

#[test]
fn length_overflow_is_checked() {
    assert_eq!(super::add_len(i32::MAX as u32, 1), Err(EncodeError::LengthOverflow));
    assert_eq!(super::add_len(u32::MAX, 1), Err(EncodeError::LengthOverflow));
    assert_eq!(super::add_len(0, i32::MAX as u32), Ok(i32::MAX as u32));
    assert_eq!(super::payload_len(i32::MAX as usize + 1), Err(EncodeError::LengthOverflow));
}

/// Secondary check only: golden byte tests above are the primary oracle, so
/// encoder and cursor never validate solely against each other.
#[test]
fn cursor_reads_back_encoder_output() {
    let inner = [Field::new(field_number!(1), Value::Varint(150))];
    let fields = [
        Field::new(field_number!(3), Value::Message(&inner)),
        Field::new(field_number!(4), Value::Fixed32(7)),
    ];
    let out = encode(&fields).unwrap();

    let mut cursor = FieldCursor::new(out.as_slice());
    let first = cursor.next().unwrap().unwrap();
    let WireValue::Len(payload) = first.value else {
        panic!("expected len value");
    };
    let inner_field = FieldCursor::new(payload).next().unwrap().unwrap();
    assert_eq!(inner_field.value, WireValue::Varint(150));

    let second = cursor.next().unwrap().unwrap();
    assert_eq!(second.value, WireValue::I32(7u32.to_le_bytes()));
    assert!(cursor.next().is_none());
}
