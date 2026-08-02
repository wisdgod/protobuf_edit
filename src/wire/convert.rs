//! Const checking helpers behind the `field_number!` and `tag!` macros.

use super::tag::{FieldNumber, Tag, WireType};

/// Builds a `FieldNumber`, panicking on out-of-range input.
///
/// Macro internal; inside a `const` block the panic is a compile error.
#[doc(hidden)]
#[must_use]
pub const fn __field_number_checked(field_number: u32) -> FieldNumber {
    match FieldNumber::new(field_number) {
        Some(n) => n,
        None => panic!("invalid protobuf field number"),
    }
}

/// Builds a `Tag`, panicking on an invalid field number.
///
/// Macro internal; inside a `const` block the panic is a compile error.
#[doc(hidden)]
#[must_use]
pub const fn __tag_from_parts(field_number: u32, wire_type: WireType) -> Tag {
    Tag::from_parts(__field_number_checked(field_number), wire_type)
}

/// Maps a wire digit (`0..=5`) to its `WireType`, panicking on invalid or
/// feature-gated digits.
///
/// Macro internal; inside a `const` block the panic is a compile error.
#[doc(hidden)]
#[must_use]
pub const fn __wire_type_from_digit(digit: u32) -> WireType {
    match WireType::from_low3(digit) {
        Some(wire_type) => wire_type,
        None => panic!("invalid protobuf wire type digit"),
    }
}
