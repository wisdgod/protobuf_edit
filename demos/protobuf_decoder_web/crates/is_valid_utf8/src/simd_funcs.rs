// Copyright Mozilla Foundation. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use core::simd::u8x16;

#[inline(always)]
pub unsafe fn load16_unaligned(ptr: *const u8) -> u8x16 {
    let mut simd = ::core::mem::MaybeUninit::<u8x16>::uninit();
    unsafe {
        ::core::ptr::copy_nonoverlapping(ptr, simd.as_mut_ptr() as *mut u8, 16);
        simd.assume_init()
    }
}

#[inline(always)]
pub unsafe fn load16_aligned(ptr: *const u8) -> u8x16 {
    unsafe { *(ptr as *const u8x16) }
}

cfg_if::cfg_if! {
    if #[cfg(all(target_feature = "sse2", target_arch = "x86_64"))] {
        use core::arch::x86_64::_mm_movemask_epi8;
    } else if #[cfg(all(target_feature = "sse2", target_arch = "x86"))] {
        use core::arch::x86::_mm_movemask_epi8;
    }
}

#[cfg(target_feature = "sse2")]
#[inline(always)]
pub fn mask_ascii(s: u8x16) -> i32 {
    unsafe { _mm_movemask_epi8(s.into()) }
}

#[cfg(all(target_arch = "wasm32", target_feature = "simd128"))]
#[inline(always)]
pub fn mask_ascii(s: u8x16) -> u16 {
    // Same semantics as SSE2 `_mm_movemask_epi8`: one bit per lane,
    // set when the lane's high bit (non-ASCII) is set.
    core::arch::wasm32::u8x16_bitmask(s.into())
}

cfg_if::cfg_if! {
    if #[cfg(target_feature = "sse2")] {
        #[inline(always)]
        pub fn simd_is_ascii(s: u8x16) -> bool {
            unsafe { _mm_movemask_epi8(s.into()) == 0 }
        }
    } else if #[cfg(all(target_arch = "wasm32", target_feature = "simd128"))] {
        #[inline(always)]
        pub fn simd_is_ascii(s: u8x16) -> bool {
            core::arch::wasm32::u8x16_bitmask(s.into()) == 0
        }
    } else if #[cfg(target_arch = "aarch64")] {
        #[inline(always)]
        pub fn simd_is_ascii(s: u8x16) -> bool {
            unsafe { core::arch::aarch64::vmaxvq_u8(s.into()) < 0x80 }
        }
    } else {
        #[inline(always)]
        pub fn simd_is_ascii(s: u8x16) -> bool {
            use core::simd::cmp::SimdPartialOrd;
            let highest_ascii = u8x16::splat(0x7F);
            !s.simd_gt(highest_ascii).any()
        }
    }
}
