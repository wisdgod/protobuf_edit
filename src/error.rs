//! Define the shared error type used across editing and parsing APIs.

use core::fmt;

use crate::buf::BufAllocError;

#[derive(Clone, Copy, PartialEq, Eq)]
/// Report decode, capacity, and wire-shape failures.
pub enum TreeError {
    CapacityExceeded,
    DecodeError,
    InvalidTag,
    WireTypeMismatch,
}

impl TreeError {
    #[inline]
    const fn label(self) -> &'static str {
        match self {
            TreeError::CapacityExceeded => "CapacityExceeded",
            TreeError::DecodeError => "DecodeError",
            TreeError::InvalidTag => "InvalidTag",
            TreeError::WireTypeMismatch => "WireTypeMismatch",
        }
    }

    #[inline]
    const fn message(self) -> &'static str {
        match self {
            TreeError::CapacityExceeded => "capacity exceeded",
            TreeError::DecodeError => "decode error",
            TreeError::InvalidTag => "invalid tag",
            TreeError::WireTypeMismatch => "wire type mismatch",
        }
    }
}

impl fmt::Debug for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl From<BufAllocError> for TreeError {
    #[inline]
    fn from(value: BufAllocError) -> Self {
        match value {
            BufAllocError::CapacityOverflow => TreeError::CapacityExceeded,
        }
    }
}
