//! Packed element readers over a LEN payload the caller committed
//! to a packed family.
//!
//! Dialect-orthogonal: the packable domain is the numeric
//! primitives (the spec excludes LEN and groups), on which the two
//! dialects coincide — sharing is not merging two shapes, it is
//! recognizing there is one domain.
//!
//! Three concrete types, no trait and no per-element dispatch: the
//! element family is caller input (schema knowledge), constant
//! over the whole payload, and the *judgment structure* differs by
//! family — the fixed families prove "whole number of elements"
//! once at construction (iteration is then infallible and exactly
//! sized), while the varint family has no O(1) total judgment and
//! must judge per element. Wire words come out; typed semantics
//! (`sint32`, `float`, …) are the caller's composition with the
//! `scalar` matrix (feature `scalar`).
//!
//! "No partial success" (the spec's whole-element obligation)
//! means a ragged tail is never disguised as a clean end — it
//! surfaces as [`Cut`] at construction or a fault mid-iteration.
//! Already-yielded prefix values are provisional; field-level
//! commit is the caller's transaction.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::traverse::packed::{Fixed32s, Varints};
//!
//! // The element family is the caller's schema commitment: the
//! // same eight bytes under two families.
//! let payload = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
//! let words: Result<Vec<u64>, _> = Varints::over(&payload).collect();
//! assert_eq!(words.unwrap(), [1, 0, 0, 0, 2, 0, 0, 0]);
//! let units: Vec<u32> = Fixed32s::over(&payload).unwrap().collect();
//! assert_eq!(units, [1, 2]);
//! ```

use crate::admission::{self, admitted_u32};
use crate::varint::slice::{self, ReadFault};

/// Construction-time refusal: the payload is not a whole number of
/// fixed-width elements. Unit-shaped — the two quoted facts (the
/// payload length and the family width) are both in the caller's
/// hands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cut;

impl core::fmt::Display for Cut {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("payload is not a whole number of fixed-width elements")
    }
}

impl core::error::Error for Cut {}

/// A varint element refused (payload-relative coordinates).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u32,
    cause: ReadFault,
}

impl Fault {
    /// Offset of the element's first byte within the payload.
    #[inline]
    #[must_use]
    pub const fn at(self) -> u32 {
        self.at
    }

    /// The kernel's refusal.
    #[inline]
    #[must_use]
    pub const fn cause(self) -> ReadFault {
        self.cause
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "packed varint element at {}: {}", self.at, self.cause)
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Packed varint-family elements: wire words out, judged per
/// element (fused after the first fault).
///
/// # Examples
///
/// ```
/// use protobuf_edit::traverse::packed::Varints;
/// use protobuf_edit::varint::slice::ReadFault;
///
/// // A ragged tail is a fault, never a clean end.
/// let mut elems = Varints::over(&[0x01, 0x80]);
/// assert_eq!(elems.next(), Some(Ok(1)));
/// let fault = elems.next().unwrap().unwrap_err();
/// assert_eq!((fault.at(), fault.cause()), (1, ReadFault::Truncated));
/// assert_eq!(elems.next(), None); // fused
/// ```
#[derive(Clone)]
#[must_use = "only natural exhaustion proves the payload whole"]
pub struct Varints<'a> {
    data: &'a [u8],
    at: usize,
    done: bool,
}

impl<'a> Varints<'a> {
    /// Reads `payload` as packed varints.
    ///
    /// # Panics
    ///
    /// If `payload` exceeds the LEN class — impossible for
    /// crate-delivered payloads; the bound keeps [`Fault::at`]
    /// total in u32.
    #[inline]
    #[track_caller]
    pub const fn over(payload: &'a [u8]) -> Self {
        assert!(payload.len() <= admission::MAX, "Varints::over: payload exceeds the LEN class");
        Self { data: payload, at: 0, done: false }
    }
}

/// Elements ride `Ok`; the first refused element rides `Err` with
/// its payload-relative offset and fuses the iterator.
impl Iterator for Varints<'_> {
    type Item = Result<u64, Fault>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.at == self.data.len() {
            self.done = true;
            return None;
        }
        match slice::value64(self.data, self.at, self.data.len()) {
            Ok((value, width)) => {
                self.at += usize::from(width);
                Some(Ok(value))
            }
            Err(cause) => {
                self.done = true;
                Some(Err(Fault { at: admitted_u32(self.at), cause }))
            }
        }
    }
}

impl core::iter::FusedIterator for Varints<'_> {}

macro_rules! fixed_family {
    (
        $(#[$doc:meta])*
        $name:ident, $width:literal, $item:ty
    ) => {
        $(#[$doc])*
        #[derive(Clone)]
        #[must_use = "construction proved the shape; iterate to read"]
        pub struct $name<'a> {
            data: &'a [u8],
            at: usize,
        }

        impl<'a> $name<'a> {
            /// Admits `payload` if it is a whole number of
            /// elements; the one judgment every later step rides.
            ///
            /// # Errors
            ///
            /// [`Cut`] when the payload length is not a multiple
            /// of the element width.
            #[inline]
            pub const fn over(payload: &'a [u8]) -> Result<Self, Cut> {
                if payload.len() % $width != 0 {
                    return Err(Cut);
                }
                Ok(Self { data: payload, at: 0 })
            }
        }

        impl Iterator for $name<'_> {
            type Item = $item;

            #[inline]
            fn next(&mut self) -> Option<Self::Item> {
                if self.at == self.data.len() {
                    return None;
                }
                // SAFETY: construction proved `len % width == 0`
                // and `at` advances only by `width`, so `at < len`
                // implies `at + width <= len`; u8 bytes are always
                // initialized and `read_unaligned` carries no
                // alignment obligation.
                let raw = unsafe {
                    self.data.as_ptr().add(self.at).cast::<$item>().read_unaligned()
                };
                self.at += $width;
                Some(<$item>::from_le(raw))
            }

            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                let left = (self.data.len() - self.at) / $width;
                (left, Some(left))
            }
        }

        impl ExactSizeIterator for $name<'_> {}
        impl core::iter::FusedIterator for $name<'_> {}
    };
}

fixed_family! {
    /// Packed I32-family elements: four little-endian bytes out as
    /// bits, whole-payload judgment at construction.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::traverse::packed::{Cut, Fixed32s};
    ///
    /// let payload = [0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x7F];
    /// let elems = Fixed32s::over(&payload).unwrap();
    /// assert_eq!(elems.len(), 2); // exactly sized
    /// assert_eq!(elems.collect::<Vec<u32>>(), [1, 0x7FFF_FFFF]);
    /// // Seven bytes are not a whole number of elements.
    /// assert_eq!(Fixed32s::over(&payload[..7]).err(), Some(Cut));
    /// ```
    Fixed32s, 4, u32
}

fixed_family! {
    /// Packed I64-family elements: eight little-endian bytes out
    /// as bits, whole-payload judgment at construction.
    ///
    /// # Examples
    ///
    /// The bits pair with the scalar matrix for typed semantics
    /// (features: `scalar`):
    ///
    /// ```
    /// # #[cfg(feature = "scalar")] {
    /// use protobuf_edit::scalar;
    /// use protobuf_edit::traverse::packed::Fixed64s;
    ///
    /// // Bits out; typed semantics are the scalar matrix's.
    /// let payload = 1.5f64.to_le_bytes();
    /// let bits: Vec<u64> = Fixed64s::over(&payload).unwrap().collect();
    /// assert_eq!(bits, [1.5f64.to_bits()]);
    /// assert_eq!(scalar::decode_double(bits[0]), 1.5);
    /// # }
    /// ```
    Fixed64s, 8, u64
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn varint_words_come_out_and_padding_is_accepted() {
        // 1, 150, then 1 padded to two bytes: all lawful widths.
        let payload = [0x01, 0x96, 0x01, 0x81, 0x00];
        let words: Result<Vec<u64>, Fault> = Varints::over(&payload).collect();
        assert_eq!(words.unwrap(), [1, 150, 1]);
    }

    #[test]
    fn a_ragged_varint_tail_faults_once_then_fuses() {
        let payload = [0x01, 0x80];
        let mut it = Varints::over(&payload);
        assert_eq!(it.next(), Some(Ok(1)));
        assert_eq!(it.next(), Some(Err(Fault { at: 1, cause: ReadFault::Truncated })));
        assert_eq!(it.next(), None);
        assert_eq!(it.next(), None);
    }

    #[test]
    fn varint_class_forgery_is_refused() {
        // Ten bytes whose tenth exceeds the u64 class.
        let payload = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02];
        let mut it = Varints::over(&payload);
        assert_eq!(it.next(), Some(Err(Fault { at: 0, cause: ReadFault::OutOfClass })));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn empty_payloads_are_lawful_zero_element_sequences() {
        assert_eq!(Varints::over(&[]).count(), 0);
        assert_eq!(Fixed32s::over(&[]).unwrap().count(), 0);
        assert_eq!(Fixed64s::over(&[]).unwrap().count(), 0);
    }

    #[test]
    fn fixed_families_judge_wholeness_at_construction() {
        let payload = [0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x7F];
        let elems = Fixed32s::over(&payload).unwrap();
        assert_eq!(elems.len(), 2);
        assert_eq!(elems.collect::<Vec<u32>>(), [1, 0x7FFF_FFFF]);

        assert!(Fixed32s::over(&payload[..7]).is_err());
        assert!(Fixed64s::over(&payload[..7]).is_err());
        let wide = Fixed64s::over(&payload).unwrap();
        assert_eq!(wide.collect::<Vec<u64>>(), [0x7FFF_FFFF_0000_0001]);
    }
}
