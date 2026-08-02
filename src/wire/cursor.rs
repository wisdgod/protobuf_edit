//! Zero-allocation sequential field cursor over one complete message.
//!
//! `FieldCursor` walks wire fields in order. Each step yields the typed
//! decoded value, the exact raw byte span, and the field's start offset. The
//! cursor borrows the input and never allocates or copies.
//!
//! Nested descent is caller-driven: open a new `FieldCursor` over a
//! `WireValue::Len` payload. This keeps recursion depth and policy (which
//! subtrees to enter) entirely in the caller's hands.

use core::iter::FusedIterator;
use core::fmt;

use crate::varint;

use super::tag::{Tag, WireType};

const MAX_VARINT32_LEN: usize = 5;
const MAX_VARINT64_LEN: usize = 10;

/// Decoded value of one wire field, borrowing from the cursor input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireValue<'a> {
    Varint(u64),
    /// Little-endian fixed32 payload bytes.
    I32([u8; 4]),
    /// Little-endian fixed64 payload bytes.
    I64([u8; 8]),
    /// Length-delimited payload.
    Len(&'a [u8]),
    /// Group body bytes, between the start and end tags (both excluded).
    #[cfg(feature = "group")]
    Group(&'a [u8]),
}

/// One parsed field: tag, decoded value, exact raw span, and start offset.
#[derive(Clone, Copy, Debug)]
pub struct RawField<'a> {
    pub tag: Tag,
    pub value: WireValue<'a>,
    /// Complete raw field bytes: tag, any length prefix, and payload (for
    /// groups: start tag through end tag inclusive).
    pub raw: &'a [u8],
    /// Byte offset of the field start within the cursor input.
    pub offset: usize,
}

/// Reason a cursor step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CursorErrorKind {
    /// Tag varint decoded but encodes field number 0 or an unsupported wire
    /// type.
    InvalidTag,
    /// A varint (tag, value, or length prefix) has no terminator within its
    /// maximum length or overflows its target width.
    InvalidVarint,
    /// The input ends inside a field.
    Truncated,
    /// An end-group tag appeared with no open group, or a group body is
    /// malformed (missing or mismatched end tag).
    #[cfg(feature = "group")]
    MalformedGroup,
}

/// Cursor failure: what went wrong and at which input offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CursorError {
    /// Offset of the malformed unit within the cursor input.
    pub offset: usize,
    pub kind: CursorErrorKind,
}

impl CursorError {
    #[inline]
    const fn new(offset: usize, kind: CursorErrorKind) -> Self {
        Self { offset, kind }
    }
}

impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            CursorErrorKind::InvalidTag => "invalid tag",
            CursorErrorKind::InvalidVarint => "invalid varint",
            CursorErrorKind::Truncated => "truncated field",
            #[cfg(feature = "group")]
            CursorErrorKind::MalformedGroup => "malformed group",
        };
        write!(f, "{what} at offset {}", self.offset)
    }
}

impl core::error::Error for CursorError {}

/// Zero-allocation iterator over the fields of one complete message.
///
/// Yields `Result<RawField, CursorError>`; after the first error the cursor
/// is exhausted and yields `None`, so a failed walk never exposes fields past
/// the malformed unit.
#[derive(Clone, Copy, Debug)]
pub struct FieldCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> FieldCursor<'a> {
    #[inline]
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Byte offset the next field would start at.
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Bytes not yet consumed.
    #[inline]
    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        // SAFETY: `offset` only advances to positions validated against
        // `data.len()` (or exactly to `data.len()` on exhaustion/error).
        unsafe { self.data.split_at_unchecked(self.offset).1 }
    }
}

impl<'a> Iterator for FieldCursor<'a> {
    type Item = Result<RawField<'a>, CursorError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        match parse_field(self.data, self.offset) {
            Ok((field, next)) => {
                self.offset = next;
                Some(Ok(field))
            }
            Err(err) => {
                // Poison: stop iterating past the malformed unit.
                self.offset = self.data.len();
                Some(Err(err))
            }
        }
    }
}

impl FusedIterator for FieldCursor<'_> {}

/// Classifies a varint decode failure at `offset`.
///
/// `varint::decode*` only fails when the terminator is missing within the
/// maximum length or the final byte overflows the target width; with fewer
/// than `max_len` bytes available the only possible failure is running out of
/// input.
#[inline]
const fn varint_failure(offset: usize, available: usize, max_len: usize) -> CursorError {
    let kind = if available < max_len {
        CursorErrorKind::Truncated
    } else {
        CursorErrorKind::InvalidVarint
    };
    CursorError::new(offset, kind)
}

/// Parses one field starting at `start`; returns the field and the offset
/// right after it.
///
/// # Errors
/// - `InvalidTag`: tag decodes to field number 0 or an unsupported wire type.
/// - `InvalidVarint`: malformed tag/value/length varint.
/// - `Truncated`: input ends inside the field.
/// - `MalformedGroup` (feature `group`): stray end-group tag or unterminated
///   group body.
fn parse_field(data: &[u8], start: usize) -> Result<(RawField<'_>, usize), CursorError> {
    debug_assert!(start < data.len());

    let rest = &data[start..];
    let Some((raw_tag, tag_len)) = varint::decode32(rest) else {
        return Err(varint_failure(start, rest.len(), MAX_VARINT32_LEN));
    };
    let Some(tag) = Tag::new(raw_tag) else {
        return Err(CursorError::new(start, CursorErrorKind::InvalidTag));
    };
    let pos = start + tag_len as usize;

    let (value, end) = match tag.wire_type() {
        WireType::Varint => {
            let rest = &data[pos..];
            let Some((v, n)) = varint::decode64(rest) else {
                return Err(varint_failure(pos, rest.len(), MAX_VARINT64_LEN));
            };
            (WireValue::Varint(v), pos + n as usize)
        }
        WireType::I32 => {
            let Some(bytes) = data[pos..].first_chunk::<4>() else {
                return Err(CursorError::new(pos, CursorErrorKind::Truncated));
            };
            (WireValue::I32(*bytes), pos + 4)
        }
        WireType::I64 => {
            let Some(bytes) = data[pos..].first_chunk::<8>() else {
                return Err(CursorError::new(pos, CursorErrorKind::Truncated));
            };
            (WireValue::I64(*bytes), pos + 8)
        }
        WireType::Len => {
            let rest = &data[pos..];
            let Some((len, n)) = varint::decode32(rest) else {
                return Err(varint_failure(pos, rest.len(), MAX_VARINT32_LEN));
            };
            let payload_start = pos + n as usize;
            let len = len as usize;
            if data.len() - payload_start < len {
                return Err(CursorError::new(payload_start, CursorErrorKind::Truncated));
            }
            let payload_end = payload_start + len;
            (WireValue::Len(&data[payload_start..payload_end]), payload_end)
        }
        #[cfg(feature = "group")]
        WireType::SGroup => {
            let field_number = tag.field_number();
            let Some((end_tag_start, end_after)) = super::find_group_end(data, pos, field_number)
            else {
                return Err(CursorError::new(pos, CursorErrorKind::MalformedGroup));
            };
            (WireValue::Group(&data[pos..end_tag_start]), end_after)
        }
        #[cfg(feature = "group")]
        WireType::EGroup => {
            return Err(CursorError::new(start, CursorErrorKind::MalformedGroup));
        }
    };

    Ok((RawField { tag, value, raw: &data[start..end], offset: start }, end))
}

#[cfg(test)]
mod tests;
