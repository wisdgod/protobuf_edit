//! The groupless wire language: four codes.
//!
//! Group codes are *well-formed wire outside this language* — a
//! capability judgment distinct from the format's unassigned codes,
//! so consumers can fault them distinctly.
//!
//! Both directions are typed: [`classify`] judges into payload-free
//! verdicts (the holder already has the [`Low3`] it classified),
//! and [`head_word`] is the only public emission face — no path
//! composes a group or unassigned code in this dialect.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::wire::groupless::{RecordKind, TagClass, classify, head_word};
//! use protobuf_edit::wire::{FieldNumber, Low3};
//!
//! let field = FieldNumber::new(1).unwrap();
//! assert_eq!(head_word(field, RecordKind::I32), 0x0D);
//!
//! // Group codes refuse as capability, apart from unassigned codes.
//! assert_eq!(classify(Low3::from_word(0x0B)), TagClass::GroupCode);
//! assert_eq!(classify(Low3::from_word(0x0E)), TagClass::Unassigned);
//! ```

use super::{FieldNumber, Low3, tag_word};

/// Wire kinds a record head can carry in this dialect (four).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordKind {
    /// Variable-width integer payload.
    Varint,
    /// Eight-byte little-endian payload.
    I64,
    /// Length-prefixed payload.
    Len,
    /// Four-byte little-endian payload.
    I32,
}

impl RecordKind {
    /// The code this kind occupies on the wire (emission direction).
    #[inline]
    pub const fn low3(self) -> Low3 {
        let code: u8 = match self {
            Self::Varint => 0,
            Self::I64 => 1,
            Self::Len => 2,
            Self::I32 => 5,
        };
        // SAFETY: every literal above is within 0..=7.
        unsafe { Low3::new_unchecked(code) }
    }
}

/// The kind's canonical name — `Varint`, `I64`, `Len`, `I32` —
/// spelled here once so error prose and UIs quote the vocabulary
/// instead of leaning on `Debug` output.
impl core::fmt::Display for RecordKind {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Varint => "Varint",
            Self::I64 => "I64",
            Self::Len => "Len",
            Self::I32 => "I32",
        })
    }
}

/// This dialect's complete judgment of a tag's code bits. Verdicts
/// are payload-free: the caller still holds the classified [`Low3`]
/// (fault vocabularies quote it from there).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TagClass {
    /// Heads a record of this kind.
    Record(RecordKind),
    /// A group code (3 or 4): well-formed wire, outside this
    /// language — the capability-refusal class.
    GroupCode,
    /// Unassigned by the format (codes 6 and 7).
    Unassigned,
}

/// The four-code fact table (group codes refused, not absent).
const TABLE: [TagClass; 8] = [
    TagClass::Record(RecordKind::Varint),
    TagClass::Record(RecordKind::I64),
    TagClass::Record(RecordKind::Len),
    TagClass::GroupCode,
    TagClass::GroupCode,
    TagClass::Record(RecordKind::I32),
    TagClass::Unassigned,
    TagClass::Unassigned,
];

/// Classifies code bits: a table lookup, total over [`Low3`].
#[inline]
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "the three code bits index losslessly; const `From` is unavailable"
)]
pub const fn classify(low3: Low3) -> TagClass {
    // In bounds by type: Low3's pattern type restricts the index
    // to 0..=7, so the language-level index check can never fire.
    // Whether it is compiled at all — and whether the lookup is a
    // branchless load — is the performance epoch's standing
    // instrument question, not this comment's claim.
    TABLE[low3.as_inner() as usize]
}

/// The head tag word of a record (the typed emission face).
#[inline]
#[must_use]
pub const fn head_word(field: FieldNumber, kind: RecordKind) -> u32 {
    tag_word(field, kind.low3())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_the_groupless_judgment() {
        let rows: [(u8, TagClass); 8] = [
            (0, TagClass::Record(RecordKind::Varint)),
            (1, TagClass::Record(RecordKind::I64)),
            (2, TagClass::Record(RecordKind::Len)),
            (3, TagClass::GroupCode),
            (4, TagClass::GroupCode),
            (5, TagClass::Record(RecordKind::I32)),
            (6, TagClass::Unassigned),
            (7, TagClass::Unassigned),
        ];
        for (code, class) in rows {
            assert_eq!(classify(Low3::new(code).unwrap()), class);
        }
    }

    #[test]
    fn emission_direction_inverts_classification() {
        for kind in [RecordKind::Varint, RecordKind::I64, RecordKind::Len, RecordKind::I32] {
            assert_eq!(classify(kind.low3()), TagClass::Record(kind));
        }
    }
}
