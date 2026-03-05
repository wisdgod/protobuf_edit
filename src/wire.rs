//! Protobuf wire-tag primitives and helpers.
//!
//! This module is intentionally minimal:
//! - Public entry points live in this module file; helpers are in `wire/*`.
//! - `Tag`/`FieldNumber`/`WireType` model protobuf tag metadata.
//! - `encode_tag*` and `decode_tag` only operate on tag prefixes.
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
#[cfg(feature = "group")]
mod group;
mod tag;

pub use codec::{decode_tag, encode_tag, encode_tag_value};
#[cfg(feature = "group")]
pub use group::find_group_end;
pub use tag::{FieldNumber, Tag, WireType, MAX_FIELD_NUMBER};

#[macro_export]
#[allow_internal_unstable(panic_internals)]
macro_rules! tag {
    ($field_number:expr, $wire_type:expr) => {
        const {
            let Some(tag) = $crate::wire::Tag::try_from_parts($field_number, $wire_type) else {
                ::core::panicking::panic("invalid protobuf tag");
            };
            tag
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

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
