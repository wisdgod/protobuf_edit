use core::intrinsics::{assume, likely, unlikely};

use super::Buffer;

pub const trait Varint: Copy {
    const MAX_LEN: u32;
    fn encoded_len(self) -> u32;
    fn decode(data: &[u8]) -> Option<(Self, u32)>;
    fn encode(buf: &mut Buffer, value: Self) -> u32;
}

macro_rules! impl_varint {
    ($ty:ty) => {
        impl const Varint for $ty {
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

                if unlikely(data.is_empty()) {
                    return None;
                }
                let ptr = data.as_ptr();

                // Manual unroll of byte 0: single-byte varint is the likely case.
                let first = unsafe { ptr.read() };
                if likely(first < 0x80) {
                    return Some((first as $ty, 1));
                }

                // Multi-byte: cold. Byte 0 already consumed (continuation bit set).
                let data_len = data.len();
                let data_len = if data_len <= u32::MAX as usize {
                    data_len as u32
                } else {
                    return None;
                };
                let limit = if data_len < Self::MAX_LEN { data_len } else { Self::MAX_LEN };
                let mut value = (first & 0x7F) as $ty;

                let mut i = 1;
                while i < limit {
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

                None
            }
            #[inline]
            fn encode(buf: &mut Buffer, mut value: $ty) -> u32 {
                let len = Self::encoded_len(value);
                unsafe {
                    let ptr = buf.as_mut_ptr() as *mut u8;
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
        let ptr = buf.as_mut_ptr() as *mut u8;
        unsafe { ptr.write(value as u8) };
        1
    }
}
