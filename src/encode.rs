//! Borrowed message encoder with reverse one-pass output.
//!
//! Build a message as a borrowed tree of [`Field`]s (nested messages borrow
//! their child slices; no intermediate buffers exist), then:
//! - [`encode`] produces a `Buf` in one reverse pass,
//! - [`encode_into`] appends to an existing `Buf`,
//! - [`encoded_len`] computes the exact wire size when only the size is
//!   needed.
//!
//! Encoding walks the tree once, backwards ([`rev::RevBuf`]): a nested
//! message's body is written before its frame, so its length prefix is the
//! cursor's travel — no measuring pass, no per-level length re-derivation.
//! The output block grows geometrically (amortized allocation) instead of
//! being sized by a length pre-pass. [`encoded_len`] remains the recursive
//! measurement, costing O(fields × nesting depth) — pay it only when the
//! size itself is the product. Depth is capped at 100 levels, matching the
//! stream walkers.

use core::fmt;

use crate::buf::Buf;
use crate::varint;
use crate::wire::{FieldNumber, Tag, WireType};

mod rev;

/// Maximum nesting depth accepted by the encoder.
pub const MAX_ENCODE_DEPTH: usize = 100;

/// Protobuf message hard cap: lengths must stay below `i32::MAX` bytes.
const MAX_LEN: u32 = i32::MAX as u32;

/// One field value, borrowing payloads and nested messages from the caller.
#[derive(Clone, Copy, Debug)]
pub enum Value<'a> {
    Varint(u64),
    Fixed32(u32),
    Fixed64(u64),
    Bytes(&'a [u8]),
    Message(&'a [Field<'a>]),
}

impl Value<'_> {
    #[inline]
    const fn wire_type(&self) -> WireType {
        match self {
            Self::Varint(_) => WireType::Varint,
            Self::Fixed32(_) => WireType::I32,
            Self::Fixed64(_) => WireType::I64,
            Self::Bytes(_) | Self::Message(_) => WireType::Len,
        }
    }
}

/// One field: number plus borrowed value.
#[derive(Clone, Copy, Debug)]
pub struct Field<'a> {
    pub number: FieldNumber,
    pub value: Value<'a>,
}

impl<'a> Field<'a> {
    #[inline]
    #[must_use]
    pub const fn new(number: FieldNumber, value: Value<'a>) -> Self {
        Self { number, value }
    }
}

/// Encoder failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// A message, payload, or the total output exceeds `i32::MAX` bytes.
    LengthOverflow,
    /// Nesting exceeds [`MAX_ENCODE_DEPTH`].
    DepthLimitExceeded,
    /// The output buffer could not grow.
    AllocFailed,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::LengthOverflow => "encoded length exceeds the protobuf message cap",
            Self::DepthLimitExceeded => "message nesting exceeds the encoder depth limit",
            Self::AllocFailed => "output buffer allocation failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for EncodeError {}

impl From<crate::buf::BufAllocError> for EncodeError {
    #[inline]
    fn from(_: crate::buf::BufAllocError) -> Self {
        Self::AllocFailed
    }
}

/// Adds `add` to `total`, keeping it within the protobuf message cap.
#[inline]
const fn add_len(total: u32, add: u32) -> Result<u32, EncodeError> {
    let sum = match total.checked_add(add) {
        Some(sum) => sum,
        None => return Err(EncodeError::LengthOverflow),
    };
    if sum > MAX_LEN {
        return Err(EncodeError::LengthOverflow);
    }
    Ok(sum)
}

/// Converts a payload byte count, enforcing the message cap.
#[inline]
fn payload_len(len: usize) -> Result<u32, EncodeError> {
    match u32::try_from(len) {
        Ok(len) if len <= MAX_LEN => Ok(len),
        _ => Err(EncodeError::LengthOverflow),
    }
}

/// Exact encoded length of `fields` as one message body.
///
/// # Errors
/// `LengthOverflow` if any message or the total exceeds `i32::MAX` bytes;
/// `DepthLimitExceeded` past [`MAX_ENCODE_DEPTH`] levels of nesting.
pub fn encoded_len(fields: &[Field<'_>]) -> Result<u32, EncodeError> {
    message_len(fields, 0)
}

fn message_len(fields: &[Field<'_>], depth: usize) -> Result<u32, EncodeError> {
    if depth > MAX_ENCODE_DEPTH {
        return Err(EncodeError::DepthLimitExceeded);
    }

    let mut total = 0u32;
    for field in fields {
        let tag = Tag::from_parts(field.number, field.value.wire_type());
        total = add_len(total, varint::encoded_len32(tag.get()))?;
        total = match field.value {
            Value::Varint(v) => add_len(total, varint::encoded_len64(v))?,
            Value::Fixed32(_) => add_len(total, 4)?,
            Value::Fixed64(_) => add_len(total, 8)?,
            Value::Bytes(bytes) => {
                let len = payload_len(bytes.len())?;
                let total = add_len(total, varint::encoded_len32(len))?;
                add_len(total, len)?
            }
            Value::Message(inner) => {
                let len = message_len(inner, depth + 1)?;
                let total = add_len(total, varint::encoded_len32(len))?;
                add_len(total, len)?
            }
        };
    }
    Ok(total)
}

/// Encodes `fields` into a fresh `Buf` in one reverse pass.
///
/// The output block is grown geometrically during the walk; its spare
/// capacity rides along ([`Buf::shrink_to_fit`] reclaims it when the
/// result is held long-term).
///
/// # Errors
/// `LengthOverflow` if any message or the total exceeds `i32::MAX` bytes;
/// `DepthLimitExceeded` past [`MAX_ENCODE_DEPTH`] levels; `AllocFailed`
/// if growth is refused.
pub fn encode(fields: &[Field<'_>]) -> Result<Buf, EncodeError> {
    let mut rb = rev::RevBuf::new();
    write_message_rev(fields, 0, &mut rb)?;
    rb.finish()?;
    rb.take_buf()
}

/// Appends the encoded message to `out`.
///
/// # Errors
/// Same conditions as [`encode`].
pub fn encode_into(fields: &[Field<'_>], out: &mut Buf) -> Result<(), EncodeError> {
    let mut rb = rev::RevBuf::new();
    write_message_rev(fields, 0, &mut rb)?;
    out.extend_from_slice(rb.finish()?)?;
    Ok(())
}

/// Writes one message body backwards: fields in reverse order, each
/// value before its tag, so the finished tail reads forward. A nested
/// message's length prefix is the cursor travel of its body — measured,
/// not recomputed. Cap and allocation failures poison the buffer and
/// surface once in `RevBuf::finish`; only the depth check errors here.
fn write_message_rev(
    fields: &[Field<'_>],
    depth: usize,
    rb: &mut rev::RevBuf,
) -> Result<(), EncodeError> {
    if depth > MAX_ENCODE_DEPTH {
        return Err(EncodeError::DepthLimitExceeded);
    }

    for field in fields.iter().rev() {
        let tag = Tag::from_parts(field.number, field.value.wire_type());
        match field.value {
            Value::Varint(v) => rb.put_varint64(v),
            Value::Fixed32(v) => rb.put_bytes(&v.to_le_bytes()),
            Value::Fixed64(v) => rb.put_bytes(&v.to_le_bytes()),
            Value::Bytes(bytes) => {
                rb.put_bytes(bytes);
                rb.put_len(bytes.len());
            }
            Value::Message(inner) => {
                let mark = rb.written();
                write_message_rev(inner, depth + 1, rb)?;
                rb.put_len(rb.body_len(mark));
            }
        }
        rb.put_varint32(tag.get());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
