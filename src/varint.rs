//! Varint and zigzag codecs used by protobuf wire routines.
//!
//! API split:
//! - Public entry points live in this module file; helpers are in `varint/*`.
//! - `encode*` / `decode*`: byte-level varint codecs for `u32`/`u64`
//! - `encoded_len*`: size estimation helpers
//! - `zigzag_*`: signed<->unsigned transforms for `sint32`/`sint64`
//!
//! Typical usage:
//! ```text
//! let mut out = Buf::new();
//! varint::encode32(&mut out, 150)?;
//! let (value, used) = varint::decode32(out.as_slice()).unwrap();
//! assert_eq!(value, 150);
//! assert_eq!(used, out.len());
//! ```

use core::mem::MaybeUninit;

use crate::buf::{Buf, BufAllocError};

pub(crate) use sealed::Varint;

mod sealed;
pub(crate) mod zigzag;

#[cfg(test)]
mod tests;

type Buffer = [MaybeUninit<u8>; 10];

/// Branchless computation of varint encoded length.
///
/// Formula: `(bit_width * 9) >> 6 + 1`
///
/// Safety: `bit_width()` ∈ [0,64], max `64*9=576`, `576>>6=9`, `9+1=10`. No overflow.
#[inline]
pub const fn encoded_len<N: [const] sealed::Varint>(value: N) -> u32 {
    <N as sealed::Varint>::encoded_len(value)
}

#[inline(always)]
#[must_use]
pub const fn encoded_len32(value: u32) -> u32 {
    encoded_len(value)
}

#[inline(always)]
#[must_use]
pub const fn encoded_len64(value: u64) -> u32 {
    encoded_len(value)
}

/// Decode a varint from the start of `data`.
/// Returns `(value, bytes_consumed)`, or `None` if data is truncated/invalid.
///
/// On success `bytes_consumed` is in `1..=data.len()`: a decoder never
/// reports more bytes than the input holds, so callers may re-slice past the
/// varint without re-checking bounds.
#[inline]
#[must_use]
pub fn decode<N: sealed::Varint>(data: &[u8]) -> Option<(N, u32)> {
    <N as sealed::Varint>::decode(data)
}

#[inline(always)]
#[must_use]
pub fn decode32(data: &[u8]) -> Option<(u32, u32)> {
    decode(data)
}

#[inline(always)]
#[must_use]
pub fn decode64(data: &[u8]) -> Option<(u64, u32)> {
    decode(data)
}

/// Encode a varint value, appending bytes to `buf`.
/// Returns the number of bytes written.
///
/// Encodes in place at the buffer tail — no scratch buffer, no second
/// copy: the length is known branchlessly up front, so the reserved
/// window is exact.
#[inline]
pub fn encode<N: sealed::Varint>(buf: &mut Buf, value: N) -> Result<u32, BufAllocError> {
    let len = <N as sealed::Varint>::encoded_len(value);
    let ptr = buf.reserve_tail(len)?;
    // SAFETY: `reserve_tail` provided `len` writable bytes at `ptr`, and
    // the kernel writes exactly `encoded_len` bytes (its contract).
    unsafe {
        let written = <N as sealed::Varint>::encode_to_ptr(ptr, value);
        debug_assert_eq!(written, len);
        buf.set_len(buf.len() + written);
    }
    Ok(len)
}

#[inline(always)]
pub fn encode32(buf: &mut Buf, value: u32) -> Result<u32, BufAllocError> {
    encode(buf, value)
}

#[inline(always)]
pub fn encode64(buf: &mut Buf, value: u64) -> Result<u32, BufAllocError> {
    encode(buf, value)
}

#[inline]
pub const fn zigzag_encode<U: [const] zigzag::Decode<S>, S: [const] zigzag::Encode<U>>(
    value: S,
) -> U {
    <S as zigzag::Encode<U>>::encode(value)
}

#[inline]
pub const fn zigzag_decode<S: [const] zigzag::Encode<U>, U: [const] zigzag::Decode<S>>(
    value: U,
) -> S {
    <U as zigzag::Decode<S>>::decode(value)
}

#[inline(always)]
#[must_use]
pub const fn zigzag_encode32(value: i32) -> u32 {
    zigzag_encode(value)
}

#[inline(always)]
#[must_use]
pub const fn zigzag_encode64(value: i64) -> u64 {
    zigzag_encode(value)
}

#[inline(always)]
#[must_use]
pub const fn zigzag_decode32(value: u32) -> i32 {
    zigzag_decode(value)
}

#[inline(always)]
#[must_use]
pub const fn zigzag_decode64(value: u64) -> i64 {
    zigzag_decode(value)
}
