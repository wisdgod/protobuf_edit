use core::intrinsics::{assume, likely, unlikely};

use super::Buffer;

pub const trait Varint: Copy {
    const MAX_LEN: u32;
    fn encoded_len(self) -> u32;
    /// Decodes a varint from the start of `data`, returning the value and
    /// the consumed byte count.
    ///
    /// On success the count is in `1..=data.len()`: implementations must
    /// never report more consumed bytes than the input holds. Callers rely
    /// on this to re-slice past the varint without bounds checks.
    fn decode(data: &[u8]) -> Option<(Self, u32)>;
    fn encode(buf: &mut Buffer, value: Self) -> u32;
    /// Writes the LEB128 bytes of `value` forward at `ptr`, returning the count.
    ///
    /// # Safety
    /// `ptr` must be valid for writes of `encoded_len(value)` bytes.
    unsafe fn encode_to_ptr(ptr: *mut u8, value: Self) -> u32;
}

macro_rules! impl_varint {
    ($ty:ty) => {
        const impl Varint for $ty {
            const MAX_LEN: u32 = unsafe {
                <$ty>::MAX.bit_width().unchecked_mul(9).unchecked_shr(6).unchecked_add(1)
            };
            #[inline]
            fn encoded_len(self) -> u32 {
                unsafe {
                    let bits = self.bit_width();
                    let len = bits.unchecked_mul(9).unchecked_shr(6).unchecked_add(1);
                    assume(len >= 1 && len <= Self::MAX_LEN);
                    len
                }
            }
            #[inline]
            fn decode(data: &[u8]) -> Option<($ty, u32)> {
                const OVERLONG_MAX: u8 =
                    unsafe { 1u8.unchecked_shl(<$ty>::MAX.bit_width() % 7).unchecked_sub(1) };

                // Bounds-checked fallback: `data` is shorter than `MAX_LEN`
                // and its last byte carries a continuation bit. The varint
                // may still terminate mid-slice (trailing bytes belong to
                // later fields), so each step checks bounds; running out of
                // bytes here is genuine truncation. The terminator index
                // stays below `MAX_LEN - 1` (len < MAX_LEN), so the fast
                // path's overlong check is unreachable and omitted.
                #[cold]
                #[inline(never)]
                const fn slow(data: &[u8]) -> Option<($ty, u32)> {
                    let mut value: $ty = 0;
                    let mut i = 0u32;
                    while (i as usize) < data.len() {
                        let byte = data[i as usize];
                        value |= ((byte & 0x7F) as $ty) << (i * 7);
                        if byte < 0x80 {
                            return Some((value, i + 1));
                        }
                        i += 1;
                    }
                    None
                }

                if unlikely(data.is_empty()) {
                    return None;
                }
                let ptr = data.as_ptr();

                // Manual unroll of byte 0: single-byte varint is the likely case.
                let first = unsafe { ptr.read() };
                if likely(first < 0x80) {
                    return Some((first as $ty, 1));
                }

                // Fast path precondition: the slice holds a maximum-length
                // encoding, or its last byte lacks a continuation bit so the
                // loop exits at or before it. Either way every `ptr.add(i)`
                // read below is in bounds, and the loop bound is a
                // compile-time constant — unrollable, no per-byte bounds
                // check (a runtime `min(len, MAX_LEN)` bound defeats both).
                if likely(data.len() >= Self::MAX_LEN as usize || data[data.len() - 1] < 0x80) {
                    let mut value = (first & 0x7F) as $ty;
                    let mut i = 1;
                    while i < Self::MAX_LEN {
                        // SAFETY: in bounds by the precondition above.
                        let byte = unsafe { ptr.add(i as usize).read() };
                        value |= ((byte & 0x7F) as $ty) << (i * 7);

                        if likely(byte < 0x80) {
                            if i == const { Self::MAX_LEN - 1 } && byte > OVERLONG_MAX {
                                return None;
                            }
                            return Some((value, i + 1));
                        }
                        i += 1;
                    }
                    // MAX_LEN continuation bytes: no terminator within the width.
                    return None;
                }

                slow(data)
            }
            #[inline]
            fn encode(buf: &mut Buffer, value: $ty) -> u32 {
                // SAFETY: `Buffer` is 10 bytes, `encoded_len <= MAX_LEN <= 10`.
                unsafe { Self::encode_to_ptr(buf.as_mut_ptr().cast::<u8>(), value) }
            }

            #[inline]
            unsafe fn encode_to_ptr(ptr: *mut u8, mut value: $ty) -> u32 {
                let len = Self::encoded_len(value);
                unsafe {
                    let limit = (len - 1) as usize;
                    let mut i = 0;
                    while i < limit {
                        *ptr.add(i) = (value & 0x7F) as u8 | 0x80;
                        value >>= 7;
                        i += 1;
                    }
                    assume(value < 0x80);
                    *ptr.add(i) = value as u8;
                }
                len
            }
        }
    };
}

impl_varint!(u32);
impl_varint!(u64);

impl Varint for bool {
    const MAX_LEN: u32 = 1;
    #[inline]
    fn encoded_len(self) -> u32 {
        1
    }
    #[inline]
    fn decode(data: &[u8]) -> Option<(Self, u32)> {
        let first = *data.first()?;
        if first <= 1 { Some((first != 0, 1)) } else { None }
    }
    #[inline]
    fn encode(buf: &mut Buffer, value: Self) -> u32 {
        let ptr = buf.as_mut_ptr().cast::<u8>();
        unsafe { ptr.write(u8::from(value)) };
        1
    }
    #[inline]
    unsafe fn encode_to_ptr(ptr: *mut u8, value: Self) -> u32 {
        unsafe { ptr.write(u8::from(value)) };
        1
    }
}
