use super::*;

#[test]
fn roundtrip_single_byte() {
    for v in 0..128u64 {
        let mut buf = Buf::new();
        let n = encode(&mut buf, v).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf.len(), 1);
        let (decoded, consumed) = decode64(&buf).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, 1);
    }
}

#[test]
fn roundtrip_multi_byte() {
    let values = [128u64, 255, 300, 16383, 16384, 1_000_000, u32::MAX as u64, u64::MAX];
    for &v in &values {
        let mut buf = Buf::new();
        let n = encode(&mut buf, v).unwrap();
        assert_eq!(n, encoded_len(v));
        assert_eq!(buf.len(), encoded_len(v));
        let (decoded, consumed) = decode64(&buf).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, buf.len());
    }
}

#[test]
fn decode_truncated() {
    assert!(decode::<u64>(&[0x80]).is_none());
    assert!(decode::<u64>(&[]).is_none());
}

#[test]
fn encoded_len_values() {
    assert_eq!(encoded_len(0u64), 1);
    assert_eq!(encoded_len(127u64), 1);
    assert_eq!(encoded_len(128u64), 2);
    assert_eq!(encoded_len(16383u64), 2);
    assert_eq!(encoded_len(16384u64), 3);
    assert_eq!(encoded_len(u64::MAX), 10);
}

#[test]
fn zigzag_roundtrip_32() {
    let values = [0i32, 1, -1, 2, -2, i32::MIN, i32::MAX, 42, -42];
    for &v in &values {
        assert_eq!(zigzag_decode(zigzag_encode(v)), v);
    }
}

#[test]
fn zigzag_roundtrip_64() {
    let values = [0i64, 1, -1, 2, -2, i64::MIN, i64::MAX, 42, -42];
    for &v in &values {
        assert_eq!(zigzag_decode(zigzag_encode(v)), v);
    }
}

#[test]
fn zigzag_known_values() {
    // From protobuf spec: https://protobuf.dev/programming-guides/encoding/#signed-ints
    assert_eq!(zigzag_encode(0i32), 0u32);
    assert_eq!(zigzag_encode(-1i32), 1u32);
    assert_eq!(zigzag_encode(1i32), 2u32);
    assert_eq!(zigzag_encode(-2i32), 3u32);
    assert_eq!(zigzag_encode(2147483647i32), 4294967294u32);
    assert_eq!(zigzag_encode(-2147483648i32), 4294967295u32);

    assert_eq!(zigzag_encode(0i64), 0u64);
    assert_eq!(zigzag_encode(-1i64), 1u64);
    assert_eq!(zigzag_encode(1i64), 2u64);
    assert_eq!(zigzag_encode(-2i64), 3u64);
}

// -----------------------------------------------------------------------
// 32-bit varint tests
// -----------------------------------------------------------------------

#[test]
fn roundtrip32_single_byte() {
    for v in 0..128u32 {
        let mut buf = Buf::new();
        let n = encode(&mut buf, v).unwrap();
        assert_eq!(n, 1);
        assert_eq!(buf.len(), 1);
        let (decoded, consumed) = decode32(&buf).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, 1);
    }
}

#[test]
fn roundtrip32_multi_byte() {
    let values = [128u32, 255, 300, 16383, 16384, 1_000_000, u32::MAX];
    for &v in &values {
        let mut buf = Buf::new();
        let n = encode(&mut buf, v).unwrap();
        assert_eq!(n, encoded_len(v));
        assert_eq!(buf.len(), encoded_len(v));
        let (decoded, consumed) = decode32(&buf).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(consumed, buf.len());
    }
}

#[test]
fn decode32_truncated() {
    assert!(decode::<u32>(&[0x80]).is_none());
    assert!(decode::<u32>(&[]).is_none());
}

#[test]
fn encoded_len32_values() {
    assert_eq!(encoded_len(0u32), 1);
    assert_eq!(encoded_len(127u32), 1);
    assert_eq!(encoded_len(128u32), 2);
    assert_eq!(encoded_len(16383u32), 2);
    assert_eq!(encoded_len(16384u32), 3);
    assert_eq!(encoded_len(u32::MAX), 5);
}

#[test]
fn decode32_rejects_overlong() {
    // 5-byte encoding with byte > 0x0F in 5th position
    let buf = [0x80, 0x80, 0x80, 0x80, 0x10]; // would be 2^32, overflow
    assert!(decode::<u32>(&buf).is_none());
}

#[test]
fn encode32_decode64_compat() {
    // A value encoded as 32-bit should be decodable as 64-bit
    for &v in &[0u32, 1, 127, 128, 16384, u32::MAX] {
        let mut buf = Buf::new();
        let _ = encode(&mut buf, v).unwrap();
        let (decoded, consumed) = decode::<u64>(&buf).unwrap();
        assert_eq!(decoded, v as u64);
        assert_eq!(consumed, buf.len());
    }
}
