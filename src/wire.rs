//! Protobuf wire-tag primitives and helpers.
//!
//! This module is intentionally minimal:
//! - Public entry points live in this module file; helpers are in `wire/*`.
//! - `Tag`/`FieldNumber`/`WireType` model protobuf tag metadata.
//! - `encode_tag*` and `decode_tag` only operate on tag prefixes.
//! - `FieldCursor` walks one complete message with zero allocation.
//! - Value encoding/decoding is handled by higher-level modules.
//!
//! Typical usage:
//! ```text
//! let tag = Tag::try_from_parts(1, WireType::Len).unwrap();
//! wire::encode_tag_value(&mut out, tag)?;
//! let (decoded, n) = wire::decode_tag(bytes).unwrap();
//! assert_eq!(decoded, tag);
//! ```

mod codec;
mod convert;
mod cursor;
#[cfg(feature = "group")]
mod group;
mod tag;

pub use codec::{decode_tag, encode_tag, encode_tag_value};
#[doc(hidden)]
pub use convert::{__field_number_checked, __tag_from_parts, __wire_type_from_digit};
pub use cursor::{CursorError, CursorErrorKind, FieldCursor, RawField, WireValue};
#[cfg(feature = "group")]
pub use group::find_group_end;
pub use tag::{FieldNumber, Tag, WireType, MAX_FIELD_NUMBER};

/// Replaces every integer in the input with a compile-time checked
/// `FieldNumber`, preserving the surrounding array/tuple structure.
///
/// ```
/// # use protobuf_edit::field_number;
/// let single = field_number!(1);            // FieldNumber
/// let path = field_number!([1, 2, 3]);      // [FieldNumber; 3]
/// let paths = field_number!([[1], [2]]);    // [[FieldNumber; 1]; 2]
/// let pair = field_number!((1, 2));         // (FieldNumber, FieldNumber)
/// # let _ = (single, path, paths, pair);
/// ```
///
/// Out-of-range numbers (0 or above 2^29 - 1) are compile errors.
#[macro_export]
macro_rules! field_number {
    ($n:literal) => {
        const { $crate::wire::__field_number_checked($n) }
    };
    ([$($elem:tt),* $(,)?]) => {
        [$($crate::field_number!($elem)),*]
    };
    (($($elem:tt),+ $(,)?)) => {
        ($($crate::field_number!($elem),)+)
    };
}

/// Builds compile-time checked `Tag`s from `(field number, wire type)` pairs.
///
/// The wire type is a bare ident (`Varint`, `I64`, `Len`, `I32`; with the
/// `group` feature also `SGroup`/`EGroup`) or a wire digit. No import of
/// `WireType` is needed at the call site. List forms replace each
/// parenthesized pair and preserve the surrounding structure:
///
/// ```
/// # use protobuf_edit::tag;
/// let t = tag!(1, Len);                       // Tag
/// let t2 = tag!(1, 2);                        // Tag, wire digit form
/// let path = tag!([(1, Len), (3, Varint)]);   // [Tag; 2]
/// let paths = tag!([[(1, Len)], [(3, 0)]]);   // [[Tag; 1]; 2]
/// # let _ = (t, t2, path, paths);
/// ```
///
/// Invalid field numbers and wire digits are compile errors; an unknown wire
/// type ident fails to resolve.
#[macro_export]
macro_rules! tag {
    ($field_number:literal, $wire_type:ident) => {
        const {
            $crate::wire::__tag_from_parts($field_number, $crate::wire::WireType::$wire_type)
        }
    };
    ($field_number:literal, $wire_digit:literal) => {
        const {
            $crate::wire::__tag_from_parts(
                $field_number,
                $crate::wire::__wire_type_from_digit($wire_digit),
            )
        }
    };
    (($field_number:literal, $wire_type:tt)) => {
        $crate::tag!($field_number, $wire_type)
    };
    ([$($elem:tt),* $(,)?]) => {
        [$($crate::tag!($elem)),*]
    };
    (($($elem:tt),+ $(,)?)) => {
        ($($crate::tag!($elem),)+)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_number_macro_preserves_structure() {
        let single = crate::field_number!(5);
        assert_eq!(single.as_inner(), 5);

        let path = crate::field_number!([1, 2, 3]);
        assert_eq!(path.map(FieldNumber::as_inner), [1, 2, 3]);

        let nested = crate::field_number!([[1], [2]]);
        assert_eq!(nested[0][0].as_inner(), 1);
        assert_eq!(nested[1][0].as_inner(), 2);

        let pair = crate::field_number!((1, 2));
        assert_eq!(pair.0.as_inner(), 1);
        assert_eq!(pair.1.as_inner(), 2);

        const MAX: FieldNumber = crate::field_number!(0x1F_FF_FF_FF);
        assert_eq!(MAX.as_inner(), MAX_FIELD_NUMBER);
    }

    #[test]
    fn tag_macro_forms() {
        let t = crate::tag!(1, Len);
        assert_eq!(t.field_number().as_inner(), 1);
        assert_eq!(t.wire_type(), WireType::Len);

        assert_eq!(crate::tag!(1, 2), t);
        assert_eq!(crate::tag!((1, Len)), t);

        let list = crate::tag!([(1, Len), (3, Varint)]);
        assert_eq!(list[0], t);
        assert_eq!(list[1], Tag::try_from_parts(3, WireType::Varint).unwrap());

        let nested = crate::tag!([[(1, Len)], [(3, 0)]]);
        assert_eq!(nested[0][0], t);
        assert_eq!(nested[1][0], Tag::try_from_parts(3, WireType::Varint).unwrap());

        let tuple = crate::tag!(((1, Len), (3, 2)));
        assert_eq!(tuple.0, t);
        assert_eq!(tuple.1, Tag::try_from_parts(3, WireType::Len).unwrap());
    }

    #[test]
    fn tag_envelope_boundaries() {
        // Smallest valid tag: field 1, wire type 0.
        assert!(Tag::new(8).is_some());
        // Largest valid tag: max field number, wire type 5.
        assert!(Tag::new(0xFFFF_FFFD).is_some());
        // Below the envelope: field number 0.
        for raw in 0..8 {
            assert!(Tag::new(raw).is_none());
        }
        // Above the envelope: wire types 6/7 of the max field number.
        assert!(Tag::new(0xFFFF_FFFE).is_none());
        assert!(Tag::new(0xFFFF_FFFF).is_none());
        // Inside the envelope but with an invalid wire type.
        assert!(Tag::new((1 << 3) | 6).is_none());
        assert!(Tag::new((1 << 3) | 7).is_none());
    }

    #[test]
    fn make_split_tag_roundtrip() {
        let tag = Tag::try_from_parts(15, WireType::Len).unwrap();
        let (field, wire) = tag.split();
        assert_eq!(field, FieldNumber::new(15).unwrap());
        assert_eq!(wire, WireType::Len);
    }

    #[test]
    #[cfg(feature = "group")]
    fn group_end_finder_handles_nested_groups() {
        use crate::buf::Buf;

        let mut buf = Buf::new();
        encode_tag(&mut buf, FieldNumber::new(1).unwrap(), WireType::SGroup).unwrap();
        encode_tag(&mut buf, FieldNumber::new(2).unwrap(), WireType::SGroup).unwrap();
        encode_tag(&mut buf, FieldNumber::new(2).unwrap(), WireType::EGroup).unwrap();
        encode_tag(&mut buf, FieldNumber::new(1).unwrap(), WireType::EGroup).unwrap();

        let (_, n) = decode_tag(buf.as_slice()).unwrap();
        let (end_start, end_after) =
            find_group_end(buf.as_slice(), n as usize, FieldNumber::new(1).unwrap()).unwrap();
        assert!(end_start < end_after);
        assert_eq!(end_after, buf.len() as usize);
    }
}
