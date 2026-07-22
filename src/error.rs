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
            Self::CapacityExceeded => "CapacityExceeded",
            Self::DecodeError => "DecodeError",
            Self::InvalidTag => "InvalidTag",
            Self::WireTypeMismatch => "WireTypeMismatch",
        }
    }

    #[inline]
    const fn message(self) -> &'static str {
        match self {
            Self::CapacityExceeded => "capacity exceeded",
            Self::DecodeError => "decode error",
            Self::InvalidTag => "invalid tag",
            Self::WireTypeMismatch => "wire type mismatch",
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
            BufAllocError::CapacityOverflow => Self::CapacityExceeded,
        }
    }
}
