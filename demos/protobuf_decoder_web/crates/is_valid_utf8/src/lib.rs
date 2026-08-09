// Copyright Mozilla Foundation. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg_attr(feature = "nightly", allow(internal_features))]
#![cfg_attr(feature = "nightly", feature(portable_simd))]
#![cfg_attr(feature = "nightly", feature(core_intrinsics))]
#![no_std]

mod ascii;

#[cfg(all(
    feature = "nightly",
    any(
        target_feature = "sse2",
        all(target_endian = "little", target_arch = "aarch64"),
        all(target_endian = "little", target_feature = "neon"),
        all(target_arch = "wasm32", target_feature = "simd128")
    )
))]
#[allow(unused)]
#[rustfmt::skip]
mod simd_funcs;

pub use ascii::is_valid_ascii;
use ascii::validate_ascii;

cfg_if::cfg_if! {
    if #[cfg(feature = "nightly")] {
        use ::core::intrinsics::likely;
    } else {
        #[inline(always)]
        fn likely(b: bool) -> bool { b }
    }
}

#[repr(align(64))]
struct Utf8Data {
    table: [u8; 384],
}

// BEGIN GENERATED CODE. PLEASE DO NOT EDIT.
// Instead, please regenerate using generate-encoding-data.py

static UTF8_DATA: Utf8Data = Utf8Data {
    table: [
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 84, 148, 148, 148,
        148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 148, 164, 164, 164, 164, 164,
        164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164, 164,
        164, 164, 164, 164, 164, 164, 164, 164, 164, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252, 252,
        252, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
        8, 8, 8, 8, 8, 8, 8, 16, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 32, 8, 8, 64, 8, 8, 8, 128, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    ],
};

// END GENERATED CODE

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Utf8Error {
    valid_up_to: usize,
    error_len: Option<u8>,
}

impl Utf8Error {
    #[inline]
    pub const fn valid_up_to(&self) -> usize {
        self.valid_up_to
    }

    #[inline]
    pub const fn error_len(&self) -> Option<u8> {
        self.error_len
    }
}

impl core::fmt::Display for Utf8Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(error_len) = self.error_len {
            write!(
                f,
                "invalid utf-8 sequence of {} bytes from index {}",
                error_len, self.valid_up_to
            )
        } else {
            write!(f, "incomplete utf-8 byte sequence from index {}", self.valid_up_to)
        }
    }
}

pub fn utf8_valid_up_to(src: &[u8]) -> usize {
    let mut read = 0;
    'outer: loop {
        let mut byte = {
            let src_remaining = &src[read..];
            match validate_ascii(src_remaining) {
                None => {
                    return src.len();
                }
                Some((non_ascii, consumed)) => {
                    read += consumed;
                    non_ascii
                }
            }
        };
        if likely(read + 4 <= src.len()) {
            'inner: loop {
                if likely(in_inclusive_range8(byte, 0xC2, 0xDF)) {
                    let second = unsafe { *(src.get_unchecked(read + 1)) };
                    if !in_inclusive_range8(second, 0x80, 0xBF) {
                        break 'outer;
                    }
                    read += 2;

                    if likely(read + 4 <= src.len()) {
                        byte = unsafe { *(src.get_unchecked(read)) };
                        if byte < 0x80 {
                            read += 1;
                            continue 'outer;
                        }
                        continue 'inner;
                    }
                    break 'inner;
                }
                if likely(byte < 0xF0) {
                    'three: loop {
                        let second = unsafe { *(src.get_unchecked(read + 1)) };
                        let third = unsafe { *(src.get_unchecked(read + 2)) };
                        if ((UTF8_DATA.table[usize::from(second)]
                            & unsafe { *(UTF8_DATA.table.get_unchecked(byte as usize + 0x80)) })
                            | (third >> 6))
                            != 2
                        {
                            break 'outer;
                        }
                        read += 3;

                        if likely(read + 4 <= src.len()) {
                            byte = unsafe { *(src.get_unchecked(read)) };
                            if in_inclusive_range8(byte, 0xE0, 0xEF) {
                                continue 'three;
                            }
                            if likely(byte < 0x80) {
                                read += 1;
                                continue 'outer;
                            }
                            continue 'inner;
                        }
                        break 'inner;
                    }
                }
                let second = unsafe { *(src.get_unchecked(read + 1)) };
                let third = unsafe { *(src.get_unchecked(read + 2)) };
                let fourth = unsafe { *(src.get_unchecked(read + 3)) };
                if (u16::from(
                    UTF8_DATA.table[usize::from(second)]
                        & unsafe { *(UTF8_DATA.table.get_unchecked(byte as usize + 0x80)) },
                ) | u16::from(third >> 6)
                    | (u16::from(fourth & 0xC0) << 2))
                    != 0x202
                {
                    break 'outer;
                }
                read += 4;

                if likely(read + 4 <= src.len()) {
                    byte = unsafe { *(src.get_unchecked(read)) };
                    if byte < 0x80 {
                        read += 1;
                        continue 'outer;
                    }
                    continue 'inner;
                }
                break 'inner;
            }
        }
        'tail: loop {
            if read >= src.len() {
                break 'outer;
            }
            byte = src[read];
            if byte < 0x80 {
                read += 1;
                continue 'tail;
            }
            if in_inclusive_range8(byte, 0xC2, 0xDF) {
                let new_read = read + 2;
                if new_read > src.len() {
                    break 'outer;
                }
                let second = src[read + 1];
                if !in_inclusive_range8(second, 0x80, 0xBF) {
                    break 'outer;
                }
                read += 2;
                continue 'tail;
            }
            if byte < 0xF0 {
                let new_read = read + 3;
                if new_read > src.len() {
                    break 'outer;
                }
                let second = src[read + 1];
                let third = src[read + 2];
                if ((UTF8_DATA.table[usize::from(second)]
                    & unsafe { *(UTF8_DATA.table.get_unchecked(byte as usize + 0x80)) })
                    | (third >> 6))
                    != 2
                {
                    break 'outer;
                }
                read += 3;
                break 'outer;
            }
            break 'outer;
        }
    }
    unsafe { core::hint::assert_unchecked(read <= src.len()) }
    read
}

#[inline(always)]
fn in_inclusive_range8(i: u8, start: u8, end: u8) -> bool {
    i.wrapping_sub(start) <= (end - start)
}

#[inline(always)]
pub fn is_valid_utf8(v: &[u8]) -> bool {
    utf8_valid_up_to(v) == v.len()
}

/// Validates `v` as UTF-8, returning the string view on success.
///
/// The `&str` return makes the validator the single entry point for
/// byte-to-string conversion: callers never follow up with
/// `core::str::from_utf8_unchecked` (the cast lives here, right next
/// to the proof).
#[inline]
pub fn validate_utf8(v: &[u8]) -> Result<&str, Utf8Error> {
    let index = utf8_valid_up_to(v);
    if index == v.len() {
        // SAFETY: `utf8_valid_up_to` accepted every byte of `v`.
        Ok(unsafe { core::str::from_utf8_unchecked(v) })
    } else {
        let error_len = match v.get(index) {
            None => None,
            Some(&byte) => {
                let width = utf8_char_width(byte);
                if width == 0 {
                    Some(1)
                } else if index + width > v.len() {
                    None
                } else {
                    Some(width as u8)
                }
            }
        };
        Err(Utf8Error { valid_up_to: index, error_len })
    }
}

#[inline]
const fn utf8_char_width(first_byte: u8) -> usize {
    match first_byte {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_utf8() {
        assert!(is_valid_utf8(b""));
        assert!(is_valid_utf8(b"hello"));
        assert!(is_valid_utf8("日本語".as_bytes()));
        assert!(is_valid_utf8("🦀".as_bytes()));
        assert!(is_valid_utf8("\u{0080}".as_bytes()));
        assert!(is_valid_utf8("\u{07FF}".as_bytes()));
        assert!(is_valid_utf8("\u{0800}".as_bytes()));
        assert!(is_valid_utf8("\u{FFFF}".as_bytes()));
        assert!(is_valid_utf8("\u{10000}".as_bytes()));
        assert!(is_valid_utf8("\u{10FFFF}".as_bytes()));
    }

    #[test]
    fn test_invalid_utf8() {
        assert!(!is_valid_utf8(b"\x80"));
        assert!(!is_valid_utf8(b"\xC0\x80"));
        assert!(!is_valid_utf8(b"\xC1\xBF"));
        assert!(!is_valid_utf8(b"\xED\xA0\x80"));
        assert!(!is_valid_utf8(b"\xF4\x90\x80\x80"));
        assert!(!is_valid_utf8(b"\xFF"));
        assert!(!is_valid_utf8(b"\xC2"));
        assert!(!is_valid_utf8(b"\xE0\xA0"));
        assert!(!is_valid_utf8(b"\xF0\x90\x80"));
    }

    #[test]
    fn test_valid_up_to() {
        assert_eq!(utf8_valid_up_to(b"hello\x80world"), 5);
        assert_eq!(utf8_valid_up_to(b"\x80"), 0);
        assert_eq!(utf8_valid_up_to(b"abc"), 3);
    }

    #[test]
    fn test_validate_utf8_error() {
        let err = validate_utf8(b"hello\x80").unwrap_err();
        assert_eq!(err.valid_up_to(), 5);
        assert_eq!(err.error_len(), Some(1));

        let err = validate_utf8(b"hello\xC2").unwrap_err();
        assert_eq!(err.valid_up_to(), 5);
        assert_eq!(err.error_len(), None);
    }

    #[test]
    fn test_validate_utf8_returns_str() {
        assert_eq!(validate_utf8(b"hello").unwrap(), "hello");
        assert_eq!(validate_utf8("日本語 🦀".as_bytes()).unwrap(), "日本語 🦀");
        assert_eq!(validate_utf8(b"").unwrap(), "");
    }

    #[test]
    fn test_ascii() {
        assert!(is_valid_ascii(b"hello world"));
        assert!(!is_valid_ascii(b"hello\x80"));
        assert!(is_valid_ascii(b""));
    }
}
