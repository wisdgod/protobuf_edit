// Copyright Mozilla Foundation. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(all(
    feature = "nightly",
    any(
        target_feature = "sse2",
        all(target_endian = "little", target_arch = "aarch64"),
        all(target_endian = "little", target_feature = "neon"),
        all(target_arch = "wasm32", target_feature = "simd128")
    )
))]
#[allow(unused_imports)]
use super::simd_funcs::*;

#[allow(dead_code)]
pub const ASCII_MASK: usize = 0x8080_8080_8080_8080u64 as usize;

cfg_if::cfg_if! {
    if #[cfg(all(feature = "nightly", target_endian = "little", target_arch = "aarch64"))] {
        pub const ALU_STRIDE_SIZE: usize = 16;
        pub const ALU_ALIGNMENT: usize = 8;
        pub const ALU_ALIGNMENT_MASK: usize = 7;
    } else if #[cfg(all(feature = "nightly", target_endian = "little", target_feature = "neon"))] {
        pub const ALU_STRIDE_SIZE: usize = 8;
        pub const ALU_ALIGNMENT: usize = 4;
        pub const ALU_ALIGNMENT_MASK: usize = 3;
    } else if #[cfg(all(
        feature = "nightly",
        any(target_feature = "sse2", all(target_arch = "wasm32", target_feature = "simd128"))
    ))] {
        pub const SIMD_STRIDE_SIZE: usize = 16;
        pub const SIMD_ALIGNMENT: usize = 16;
        pub const SIMD_ALIGNMENT_MASK: usize = 15;
    } else if #[cfg(all(target_endian = "little", target_pointer_width = "64"))] {
        pub const ALU_STRIDE_SIZE: usize = 16;
        pub const ALU_ALIGNMENT: usize = 8;
        pub const ALU_ALIGNMENT_MASK: usize = 7;
    } else if #[cfg(all(target_endian = "little", target_pointer_width = "32"))] {
        pub const ALU_STRIDE_SIZE: usize = 8;
        pub const ALU_ALIGNMENT: usize = 4;
        pub const ALU_ALIGNMENT_MASK: usize = 3;
    } else if #[cfg(all(target_endian = "big", target_pointer_width = "64"))] {
        pub const ALU_STRIDE_SIZE: usize = 16;
        pub const ALU_ALIGNMENT: usize = 8;
        pub const ALU_ALIGNMENT_MASK: usize = 7;
    } else if #[cfg(all(target_endian = "big", target_pointer_width = "32"))] {
        pub const ALU_STRIDE_SIZE: usize = 8;
        pub const ALU_ALIGNMENT: usize = 4;
        pub const ALU_ALIGNMENT_MASK: usize = 3;
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_endian = "little")] {
        #[allow(dead_code)]
        #[inline(always)]
        fn count_zeros(word: usize) -> u32 { word.trailing_zeros() }
    } else {
        #[allow(dead_code)]
        #[inline(always)]
        fn count_zeros(word: usize) -> u32 { word.leading_zeros() }
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(
        feature = "nightly",
        any(target_feature = "sse2", all(target_arch = "wasm32", target_feature = "simd128"))
    ))] {
        #[inline(always)]
        pub fn validate_ascii(slice: &[u8]) -> Option<(u8, usize)> {
            let src = slice.as_ptr();
            let len = slice.len();
            let mut offset = 0usize;
            if SIMD_STRIDE_SIZE <= len {
                let simd = unsafe { load16_unaligned(src) };
                let mask = mask_ascii(simd);
                if mask != 0 {
                    offset = mask.trailing_zeros() as usize;
                    let non_ascii = unsafe { *src.add(offset) };
                    return Some((non_ascii, offset));
                }
                offset = SIMD_STRIDE_SIZE;

                let until_alignment = unsafe {
                    (SIMD_ALIGNMENT - ((src.add(offset) as usize) & SIMD_ALIGNMENT_MASK))
                        & SIMD_ALIGNMENT_MASK
                };
                if until_alignment + (SIMD_STRIDE_SIZE * 3) <= len {
                    if until_alignment != 0 {
                        let simd = unsafe { load16_unaligned(src.add(offset)) };
                        let mask = mask_ascii(simd);
                        if mask != 0 {
                            offset += mask.trailing_zeros() as usize;
                            let non_ascii = unsafe { *src.add(offset) };
                            return Some((non_ascii, offset));
                        }
                        offset += until_alignment;
                    }
                    let len_minus_stride_times_two = len - (SIMD_STRIDE_SIZE * 2);
                    loop {
                        let first = unsafe { load16_aligned(src.add(offset)) };
                        let second =
                            unsafe { load16_aligned(src.add(offset + SIMD_STRIDE_SIZE)) };
                        if !simd_is_ascii(first | second) {
                            let mask_first = mask_ascii(first);
                            if mask_first != 0 {
                                offset += mask_first.trailing_zeros() as usize;
                            } else {
                                let mask_second = mask_ascii(second);
                                offset +=
                                    SIMD_STRIDE_SIZE + mask_second.trailing_zeros() as usize;
                            }
                            let non_ascii = unsafe { *src.add(offset) };
                            return Some((non_ascii, offset));
                        }
                        offset += SIMD_STRIDE_SIZE * 2;
                        if offset > len_minus_stride_times_two {
                            break;
                        }
                    }
                    if offset + SIMD_STRIDE_SIZE <= len {
                        let simd = unsafe { load16_aligned(src.add(offset)) };
                        let mask = mask_ascii(simd);
                        if mask != 0 {
                            offset += mask.trailing_zeros() as usize;
                            let non_ascii = unsafe { *src.add(offset) };
                            return Some((non_ascii, offset));
                        }
                        offset += SIMD_STRIDE_SIZE;
                    }
                } else {
                    if offset + SIMD_STRIDE_SIZE <= len {
                        let simd = unsafe { load16_unaligned(src.add(offset)) };
                        let mask = mask_ascii(simd);
                        if mask != 0 {
                            offset += mask.trailing_zeros() as usize;
                            let non_ascii = unsafe { *src.add(offset) };
                            return Some((non_ascii, offset));
                        }
                        offset += SIMD_STRIDE_SIZE;
                        if offset + SIMD_STRIDE_SIZE <= len {
                            let simd = unsafe { load16_unaligned(src.add(offset)) };
                            let mask = mask_ascii(simd);
                            if mask != 0 {
                                offset += mask.trailing_zeros() as usize;
                                let non_ascii = unsafe { *src.add(offset) };
                                return Some((non_ascii, offset));
                            }
                            offset += SIMD_STRIDE_SIZE;
                        }
                    }
                }
            }
            while offset < len {
                let code_unit = unsafe { *(src.add(offset)) };
                if code_unit > 127 {
                    return Some((code_unit, offset));
                }
                offset += 1;
            }
            None
        }
    } else {
        #[inline(always)]
        fn find_non_ascii(word: usize, second_word: usize) -> Option<usize> {
            let word_masked = word & ASCII_MASK;
            let second_masked = second_word & ASCII_MASK;
            if (word_masked | second_masked) == 0 {
                return None;
            }
            if word_masked != 0 {
                let zeros = count_zeros(word_masked);
                let num_ascii = (zeros >> 3) as usize;
                return Some(num_ascii);
            }
            let zeros = count_zeros(second_masked);
            let num_ascii = (zeros >> 3) as usize;
            Some(ALU_ALIGNMENT + num_ascii)
        }

        #[inline(always)]
        unsafe fn validate_ascii_stride(src: *const usize) -> Option<usize> {
            let word = *src;
            let second_word = *(src.add(1));
            find_non_ascii(word, second_word)
        }

        #[allow(clippy::cast_ptr_alignment)]
        #[inline(always)]
        pub fn validate_ascii(slice: &[u8]) -> Option<(u8, usize)> {
            let src = slice.as_ptr();
            let len = slice.len();
            let mut offset = 0usize;
            let mut until_alignment =
                (ALU_ALIGNMENT - ((src as usize) & ALU_ALIGNMENT_MASK)) & ALU_ALIGNMENT_MASK;
            if until_alignment + ALU_STRIDE_SIZE <= len {
                while until_alignment != 0 {
                    let code_unit = slice[offset];
                    if code_unit > 127 {
                        return Some((code_unit, offset));
                    }
                    offset += 1;
                    until_alignment -= 1;
                }
                let len_minus_stride = len - ALU_STRIDE_SIZE;
                loop {
                    let ptr = unsafe { src.add(offset) as *const usize };
                    if let Some(num_ascii) = unsafe { validate_ascii_stride(ptr) } {
                        offset += num_ascii;
                        return Some((unsafe { *(src.add(offset)) }, offset));
                    }
                    offset += ALU_STRIDE_SIZE;
                    if offset > len_minus_stride {
                        break;
                    }
                }
            }
            while offset < len {
                let code_unit = slice[offset];
                if code_unit > 127 {
                    return Some((code_unit, offset));
                }
                offset += 1;
            }
            None
        }
    }
}

#[inline(always)]
pub fn is_valid_ascii(v: &[u8]) -> bool {
    validate_ascii(v).is_none()
}
