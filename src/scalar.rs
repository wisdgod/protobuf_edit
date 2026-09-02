//! The typed scalar matrix: pure format theorems between wire
//! carriers (varint words, fixed bits) and schema-typed values, in
//! both directions.
//!
//! No state, no reader knowledge; domain judgments are pinned per
//! type, with no fallback defaults. The domain policy is deliberately
//! strict for the plain widths: a word outside the requested
//! type's domain is refused ([`OutOfDomain`]), never truncated —
//! where the permissive reference read would fold, say, an
//! over-wide `int32` word into its low 32 bits, that fold is the
//! caller's own cast to write. The one recorded exception is
//! `sint32`, whose reference reduction order (truncate, then
//! unzigzag) is itself the protocol semantic this module pins.
//! The zigzag bit transforms live in [`crate::varint`]; this
//! module owns their *semantic* assignment to `sint32`/`sint64`,
//! including the recorded reduction-order convention. Kind gating
//! (which record may be read as what) is the scenarios' business —
//! these functions only speak value classes.
//!
//! # Choosing a face
//!
//! Faces are named by schema type, not wire shape: take the
//! field's `.proto` scalar name, and hand its `decode_*` the
//! carrier your reader delivered — a varint wire word, I32 bits,
//! or I64 bits. Where a row below says "the value" or "the bits",
//! the carrier already is the reading and no face exists.
//!
//! | `.proto` type | Carrier | Decode | Encode |
//! |---|---|---|---|
//! | `uint32` | varint word | [`decode_uint32`] | the value, widened |
//! | `uint64` | varint word | [`decode_uint64`] | the value |
//! | `int32` | varint word | [`decode_int32`] | [`encode_int64`], widened |
//! | `int64` | varint word | [`decode_int64`] | [`encode_int64`] |
//! | `sint32` | varint word | [`decode_sint32`] | [`encode_sint32`] |
//! | `sint64` | varint word | [`decode_sint64`] | [`encode_sint64`] |
//! | `bool` | varint word | [`decode_bool`] | [`encode_bool`] |
//! | `enum` | varint word | [`decode_enum`] | [`encode_int64`], widened |
//! | `fixed32` | I32 bits | the bits | the bits |
//! | `sfixed32` | I32 bits | [`decode_sfixed32`] | `i32::cast_unsigned` |
//! | `float` | I32 bits | [`decode_float`] | [`encode_float`] |
//! | `fixed64` | I64 bits | the bits | the bits |
//! | `sfixed64` | I64 bits | [`decode_sfixed64`] | `i64::cast_unsigned` |
//! | `double` | I64 bits | [`decode_double`] | [`encode_double`] |
//!
//! The fallible faces are exactly the four strict domain
//! judgments — [`decode_uint32`], [`decode_int32`],
//! [`decode_enum`], [`decode_bool`]; everything else is total
//! over its carrier. Carriers come out of the readers
//! (`traverse`, `inspect`, `scan` — each behind its feature); on
//! the author side, `construct`'s typed pushes compose this
//! matrix already, so its callers rarely spell an `encode_*`
//! themselves.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::scalar::{OutOfDomain, decode_bool, decode_sint64, decode_uint32};
//!
//! // One varint wire word, read under different schema types.
//! assert_eq!(decode_uint32(150), Ok(150));
//! assert_eq!(decode_sint64(150), 75); // zigzag decode
//!
//! // Domain judgments are pinned per type and none defaults.
//! assert_eq!(decode_uint32(1 << 32), Err(OutOfDomain));
//! assert_eq!(decode_bool(2), Err(OutOfDomain));
//! ```
//!
//! # Recipes
//!
//! The pairing is always one shape — a reader's word face into
//! `decode_*`, or `encode_*` into an editor's command — and
//! [the crate root's recipes](crate) compile it against a live
//! editor; `construct`'s typed pushes are the encode side
//! pre-composed, as noted above.

use crate::varint::{unzigzag32, unzigzag64, zigzag32, zigzag64};

/// A wire value outside the requested type's domain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutOfDomain;

impl core::fmt::Display for OutOfDomain {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("wire value outside the requested type's domain")
    }
}

impl core::error::Error for OutOfDomain {}

/// Decodes a varint wire word as `uint32`.
///
/// In domain exactly when the word fits 32 bits.
///
/// # Errors
///
/// [`OutOfDomain`] for wire words above `u32::MAX`.
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "the bound widens losslessly and the narrowing follows the domain judgment; \
              const `From` is unavailable"
)]
pub const fn decode_uint32(wire: u64) -> Result<u32, OutOfDomain> {
    if wire <= u32::MAX as u64 { Ok(wire as u32) } else { Err(OutOfDomain) }
}

/// Decodes a varint wire word as `uint64`.
///
/// Every wire word is in domain.
#[inline]
#[must_use]
pub const fn decode_uint64(wire: u64) -> u64 {
    wire
}

/// Decodes a varint wire word as `int64`.
///
/// Two's-complement reinterpretation of the 64-bit word.
#[inline]
#[must_use]
pub const fn decode_int64(wire: u64) -> i64 {
    wire.cast_signed()
}

/// Decodes a varint wire word as `int32`.
///
/// On the wire an int32 is a 64-bit sign-extended varint; in
/// domain exactly when the value round-trips through `i32`.
///
/// # Errors
///
/// [`OutOfDomain`] for wire words outside `i32`'s range.
///
/// # Examples
///
/// ```
/// use protobuf_edit::scalar::{decode_int32, encode_int64};
///
/// // Negative int32 values ride the wire sign-extended to 64 bits.
/// let wire = encode_int64(-1);
/// assert_eq!(wire, u64::MAX);
/// assert_eq!(decode_int32(wire), Ok(-1));
/// assert!(decode_int32(1 << 31).is_err()); // past i32::MAX
/// ```
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "the bounds widen losslessly and the narrowing follows the domain judgment; \
              const `From` is unavailable"
)]
pub const fn decode_int32(wire: u64) -> Result<i32, OutOfDomain> {
    let wide = wire.cast_signed();
    if wide >= i32::MIN as i64 && wide <= i32::MAX as i64 {
        Ok(wide as i32)
    } else {
        Err(OutOfDomain)
    }
}

/// Decodes a varint wire word as an enum number.
///
/// `enum` carriers are `int32` on the wire.
///
/// # Errors
///
/// [`OutOfDomain`] for wire words outside `i32`'s range.
#[inline]
pub const fn decode_enum(wire: u64) -> Result<i32, OutOfDomain> {
    decode_int32(wire)
}

/// Decodes a varint wire word as `sint64`.
///
/// Zigzag decode.
#[inline]
#[must_use]
pub const fn decode_sint64(wire: u64) -> i64 {
    unzigzag64(wire)
}

/// Decodes a varint wire word as `sint32`.
///
/// **Truncate-then-decode** — the reference implementation's
/// reduction order (the two orders disagree on wire words above
/// 2^32 - 1).
///
/// # Examples
///
/// ```
/// use protobuf_edit::scalar::{decode_sint32, encode_sint32};
///
/// // Wire 2^32 + 3: truncate to 3, then decode to -2 — decoding
/// // first in 64 bits would disagree.
/// assert_eq!(decode_sint32((1 << 32) + 3), -2);
/// assert_eq!(decode_sint32(encode_sint32(i32::MIN)), i32::MIN);
/// ```
#[inline]
#[must_use]
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "protocol semantics, not a proven narrowing: sint32 reduces its wire word \
              by truncate-then-unzigzag, the reference implementation's order"
)]
pub const fn decode_sint32(wire: u64) -> i32 {
    unzigzag32(wire as u32)
}

/// Decodes a varint wire word as `bool`.
///
/// Exactly zero or one.
///
/// # Errors
///
/// [`OutOfDomain`] for wire words above one.
#[inline]
pub const fn decode_bool(wire: u64) -> Result<bool, OutOfDomain> {
    match wire {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(OutOfDomain),
    }
}

/// Decodes I32 bits as `float`.
///
/// Pure bit reinterpretation.
#[inline]
#[must_use]
pub const fn decode_float(bits: u32) -> f32 {
    f32::from_bits(bits)
}

/// Decodes I64 bits as `double`.
///
/// Pure bit reinterpretation.
#[inline]
#[must_use]
pub const fn decode_double(bits: u64) -> f64 {
    f64::from_bits(bits)
}

/// Decodes I32 bits as `sfixed32`.
///
/// Two's-complement reinterpretation.
#[inline]
#[must_use]
pub const fn decode_sfixed32(bits: u32) -> i32 {
    bits.cast_signed()
}

/// Decodes I64 bits as `sfixed64`.
///
/// Two's-complement reinterpretation.
#[inline]
#[must_use]
pub const fn decode_sfixed64(bits: u64) -> i64 {
    bits.cast_signed()
}

/// Encodes an `int32` or `int64` value as its varint wire word.
///
/// Sign-extends to the 64-bit wire.
#[inline]
#[must_use]
pub const fn encode_int64(value: i64) -> u64 {
    value.cast_unsigned()
}

/// Encodes a `sint64` value as its varint wire word.
///
/// Zigzag encode.
///
/// # Examples
///
/// ```
/// use protobuf_edit::scalar::{decode_sint64, encode_sint64};
///
/// assert_eq!(encode_sint64(-3), 5);
/// assert_eq!(decode_sint64(5), -3);
/// ```
#[inline]
#[must_use]
pub const fn encode_sint64(value: i64) -> u64 {
    zigzag64(value)
}

/// Encodes a `sint32` value as its varint wire word.
///
/// Zigzag in 32 bits, zero-extended.
#[inline]
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "the zigzagged word zero-extends losslessly; const `From` is unavailable"
)]
pub const fn encode_sint32(value: i32) -> u64 {
    zigzag32(value) as u64
}

/// Encodes a `bool` value as its varint wire word.
///
/// False and true are zero and one on the wire.
#[inline]
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "false and true are zero and one on the wire; const `From` is unavailable"
)]
pub const fn encode_bool(value: bool) -> u64 {
    value as u64
}

/// Encodes a `float` value as I32 bits.
#[inline]
#[must_use]
pub const fn encode_float(value: f32) -> u32 {
    value.to_bits()
}

/// Encodes a `double` value as I64 bits.
#[inline]
#[must_use]
pub const fn encode_double(value: f64) -> u64 {
    value.to_bits()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_pinned_per_type() {
        assert_eq!(decode_uint32(u64::from(u32::MAX)), Ok(u32::MAX));
        assert!(decode_uint32(1 << 32).is_err());
        // int32 negatives arrive as ten-byte sign-extended wires.
        assert_eq!(decode_int32(encode_int64(-1)), Ok(-1));
        assert!(decode_int32(1 << 31).is_err());
        assert_eq!(decode_enum(encode_int64(i64::from(i32::MIN))), Ok(i32::MIN));
        assert_eq!(decode_bool(1), Ok(true));
        assert!(decode_bool(2).is_err());
    }

    #[test]
    fn sint32_reduction_is_truncate_then_decode() {
        // Wire 2^32 + 3: truncate → 3 → decode → -2. The other
        // order would decode first in 64 bits and disagree — this
        // pins the recorded convention.
        assert_eq!(decode_sint32((1 << 32) + 3), -2);
        assert_eq!(decode_sint32(encode_sint32(i32::MIN)), i32::MIN);
        assert_eq!(decode_sint64(encode_sint64(-3)), -3);
    }

    #[test]
    fn every_encode_decode_pair_round_trips_over_its_domain_edges() {
        // Round-trip identity, judged on exactly the population
        // below: each type's domain edges plus a mid value (the
        // full 32/64-bit domains stay unswept — no cheap
        // exhaustive judge exists without a solver, which the
        // dependency policy excludes). The sint32 reduction pin
        // above covers the one non-injective direction, and the
        // bool domain is exhausted outright.
        for v in [i64::MIN, -1, 0, 1, i64::MAX] {
            assert_eq!(decode_int64(encode_int64(v)), v);
            assert_eq!(decode_sint64(encode_sint64(v)), v);
        }
        for v in [i32::MIN, -1, 0, 1, i32::MAX] {
            assert_eq!(decode_sint32(encode_sint32(v)), v);
            assert_eq!(decode_int32(encode_int64(i64::from(v))), Ok(v));
            assert_eq!(decode_enum(encode_int64(i64::from(v))), Ok(v));
        }
        for v in [0u32, 1, u32::MAX] {
            assert_eq!(decode_uint32(u64::from(v)), Ok(v));
        }
        for v in [false, true] {
            assert_eq!(decode_bool(encode_bool(v)), Ok(v));
        }
    }

    #[test]
    fn bit_reinterpretations_round_trip() {
        assert_eq!(decode_float(encode_float(1.0)), 1.0);
        assert_eq!(decode_double(encode_double(-0.5)), -0.5);
        assert_eq!(decode_sfixed32(u32::MAX), -1);
        assert_eq!(decode_sfixed64(u64::MAX), -1);
    }
}
