//! Define the shared error type used across editing and parsing APIs.

use core::fmt;

use crate::buf::BufAllocError;

/// Report decode, capacity, and wire-shape failures.
///
/// `Malformed` carries the byte offset of the failing unit within the buffer
/// that was being decoded (message-local for nested messages). The remaining
/// variants describe states rather than input positions and carry no offset
/// on purpose: fabricating one would be noise.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TreeError {
    /// Malformed wire bytes at `offset` within the buffer being decoded.
    Malformed { offset: u32 },
    /// The input ended inside a field. Incremental streams report this
    /// without an offset; complete-buffer decoders report `Malformed` with
    /// the position instead.
    Truncated,
    /// An id (`FieldId`/`MessageId`/`Ix`) does not refer to a live element
    /// of this tree, or the data recorded for it is unavailable.
    InvalidId,
    /// Recorded state (spans, raw caches, links) is internally inconsistent.
    /// Indicates a bug in this crate or a violated construction contract.
    Corrupted,
    /// Capacity, index space, or the protobuf size cap was exceeded, or an
    /// allocation failed.
    CapacityExceeded,
    /// A field number or tag construction input is out of range.
    InvalidTag,
    /// Typed access was used on a field of a different wire type.
    WireTypeMismatch,
}

impl TreeError {
    /// Shorthand for `Malformed` at a byte offset; saturates at `u32::MAX`
    /// (decode paths only produce offsets within the `i32::MAX` message cap).
    #[inline]
    #[must_use]
    pub(crate) fn malformed_at(offset: usize) -> Self {
        Self::Malformed { offset: u32::try_from(offset).unwrap_or(u32::MAX) }
    }

    /// Rebases a `Malformed` offset by `base`; other variants pass through.
    ///
    /// Used when an inner decoder reports offsets relative to a sub-slice.
    #[inline]
    #[must_use]
    pub(crate) fn offset_by(self, base: usize) -> Self {
        match self {
            Self::Malformed { offset } => Self::malformed_at(base.saturating_add(offset as usize)),
            other => other,
        }
    }

    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Malformed { .. } => "Malformed",
            Self::Truncated => "Truncated",
            Self::InvalidId => "InvalidId",
            Self::Corrupted => "Corrupted",
            Self::CapacityExceeded => "CapacityExceeded",
            Self::InvalidTag => "InvalidTag",
            Self::WireTypeMismatch => "WireTypeMismatch",
        }
    }
}

impl fmt::Debug for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { offset } => {
                f.debug_struct("Malformed").field("offset", offset).finish()
            }
            _ => f.write_str(self.label()),
        }
    }
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { offset } => write!(f, "malformed wire bytes at offset {offset}"),
            Self::Truncated => f.write_str("input ended inside a field"),
            Self::InvalidId => f.write_str("id does not refer to a live element"),
            Self::Corrupted => f.write_str("internal tree state is inconsistent"),
            Self::CapacityExceeded => f.write_str("capacity exceeded"),
            Self::InvalidTag => f.write_str("invalid tag"),
            Self::WireTypeMismatch => f.write_str("wire type mismatch"),
        }
    }
}

impl core::error::Error for TreeError {}

impl From<BufAllocError> for TreeError {
    #[inline]
    fn from(value: BufAllocError) -> Self {
        match value {
            BufAllocError::CapacityOverflow => Self::CapacityExceeded,
        }
    }
}

const _: () = {
    assert!(core::mem::size_of::<TreeError>() == 8);
    assert!(core::mem::size_of::<Result<(), TreeError>>() == 8);
};
