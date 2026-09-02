//! The wire vocabulary stratum: contract types for the quantities
//! every scenario speaks, and the two dialect tables.
//!
//! Contracts live on types (construction proves the range once;
//! every later use is judgment-free): [`FieldNumber`] admits exactly
//! the field numbers the format assigns, [`PayloadLen`] exactly the
//! LEN length class, [`Low3`] exactly a tag word's three code bits.
//! The dialect split is two coexisting tables, not a parameter:
//! `grouped` speaks all six codes (groups framed by tags),
//! `groupless` the groupless subset in which group codes are
//! well-formed wire outside the language. The contract types are
//! unconditional; each dialect table compiles exactly when a
//! scenario cell of its dialect consumes it or its direct feature
//! (`wire-grouped`, `wire-groupless`) selects it.
//!
//! # Choosing a face
//!
//! Most callers meet these types pre-composed: the scenario
//! modules speak them in their signatures and re-judge nothing.
//! Reach in directly when you drive the [`crate::varint`] kernels
//! yourself.
//!
//! - Judging a word you read: [`Low3::from_word`] and the
//!   dialect's classify (`grouped::classify`,
//!   `groupless::classify`) for the kind;
//!   [`FieldNumber::from_word`] for the field, whose `None` is
//!   the field-zero verdict your fault vocabulary names.
//! - Emitting a head: the dialect's `head_word`
//!   (`grouped::head_word`, `groupless::head_word`;
//!   `grouped::group_end_word` closes a group frame) — the only
//!   word-composition faces, so an unassigned code cannot be
//!   spelled.
//! - Supplying quantities at your own boundary:
//!   [`FieldNumber::new`] and [`PayloadLen::new`] — admission
//!   once, judgment-free holders downstream.
//!
//! The two tables disagree on exactly the group codes —
//! `groupless::TagClass::GroupCode` is the route-to-the-twin
//! signal — and read the same everywhere else.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "wire-grouped")] {
//! use protobuf_edit::wire::grouped::{RecordKind, TagClass, classify};
//! use protobuf_edit::wire::{FieldNumber, Low3, PayloadLen};
//!
//! // A real tag word: field 2, code 2 (LEN) — `0x12`.
//! let field = FieldNumber::from_word(0x12).unwrap();
//! assert_eq!(field.as_inner(), 2);
//! let class = classify(Low3::from_word(0x12));
//! assert_eq!(class, TagClass::Record(RecordKind::Len));
//!
//! // Admission is the one judgment: out of range never constructs.
//! assert_eq!(PayloadLen::new(2_147_483_648), None);
//! # }
//! ```
//!
//! # Recipes
//!
//! The hand-rolled read chain — a kernel word into
//! [`FieldNumber::from_word`] and [`Low3::from_word`], then the
//! dialect's classify for the dispatch — is compiled end to end in
//! [the crate root's examples](crate); the scenario modules are
//! that chain pre-composed, with state and fault vocabularies
//! attached.

#[cfg(any(
    test,
    feature = "wire-grouped",
    feature = "select-grouped",
    feature = "traverse-grouped",
    feature = "scan-grouped",
    feature = "route-grouped",
    feature = "rewrite-grouped",
    feature = "inplace-grouped",
    feature = "fixed-inplace-grouped",
    feature = "rewire-grouped",
    feature = "transcode-grouped",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "inspect-grouped",
    feature = "fixed-inspect-grouped",
    feature = "retain-grouped",
    feature = "collect-grouped",
    feature = "patch-grouped",
    feature = "fixed-patch-grouped",
    feature = "adopt-grouped",
    feature = "amend-grouped",
    feature = "intake-grouped",
    feature = "markup-grouped",
    feature = "draft-grouped",
    feature = "review-grouped",
    feature = "session-grouped",
    feature = "stream-adopt-grouped",
    feature = "stream-draft-grouped",
    feature = "stream-intake-grouped",
    feature = "survey-grouped",
    feature = "replay-rewrite-grouped",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "overhaul-grouped",
    feature = "construct-grouped",
    feature = "maintain-grouped",
    feature = "refit-grouped",
    feature = "commission-grouped",
))]
pub mod grouped;
#[cfg(any(
    test,
    feature = "wire-groupless",
    feature = "select-groupless",
    feature = "traverse-groupless",
    feature = "scan-groupless",
    feature = "route-groupless",
    feature = "rewrite-groupless",
    feature = "inplace-groupless",
    feature = "fixed-inplace-groupless",
    feature = "rewire-groupless",
    feature = "transcode-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "splice-groupless",
    feature = "inspect-groupless",
    feature = "fixed-inspect-groupless",
    feature = "retain-groupless",
    feature = "collect-groupless",
    feature = "patch-groupless",
    feature = "fixed-patch-groupless",
    feature = "adopt-groupless",
    feature = "amend-groupless",
    feature = "intake-groupless",
    feature = "markup-groupless",
    feature = "draft-groupless",
    feature = "review-groupless",
    feature = "session-groupless",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-groupless",
    feature = "stream-intake-groupless",
    feature = "survey-groupless",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-groupless",
    feature = "overhaul-groupless",
    feature = "maintain-groupless",
    feature = "refit-groupless",
    feature = "commission-groupless",
    feature = "construct-groupless"
))]
pub mod groupless;

crate::_macro::define_valid_range_type! {
    /// A protobuf field number: `1..=2^29 - 1`.
    ///
    /// Field zero is unassigned by the format and the tag word's
    /// upper bound caps the rest; admission happens once, at
    /// construction, so every holder downstream is judgment-free.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::wire::FieldNumber;
    ///
    /// assert_eq!(FieldNumber::new(3).map(|f| f.as_inner()), Some(3));
    /// assert_eq!(FieldNumber::new(0), None); // unassigned
    /// assert_eq!(FieldNumber::new(1 << 29), None); // past the cap
    /// ```
    ///
    /// Literals want a `const`: the admission runs at compile time
    /// and an out-of-range number is a build error, not a runtime
    /// panic.
    ///
    /// ```
    /// use protobuf_edit::wire::FieldNumber;
    ///
    /// const SERIAL: FieldNumber = FieldNumber::new(1).unwrap();
    /// assert_eq!(SERIAL.as_inner(), 1);
    /// ```
    #[must_use]
    pub struct FieldNumber(u32 as u32 in 1..=536_870_911) with min, max, new;

    /// A LEN payload length: `0..=2^31 - 1` (the length class).
    ///
    /// Reading kernels construct it after the class judgment;
    /// suppliers (builders, replacements) construct it at the
    /// system boundary. Aggregation and comparison downstream are
    /// judgment-free.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::wire::PayloadLen;
    ///
    /// assert_eq!(PayloadLen::new(0), Some(PayloadLen::MIN));
    /// assert_eq!(PayloadLen::new(2_147_483_647), Some(PayloadLen::MAX));
    /// assert_eq!(PayloadLen::new(2_147_483_648), None); // past the class
    /// ```
    #[must_use]
    pub struct PayloadLen(u32 as u32 in 0..=2_147_483_647) with min, max, new;

    /// The low three bits of a tag word: `0..=7`.
    ///
    /// Total over its domain — every tag word yields one — so the
    /// dialect tables can classify by lookup with no impossible arm.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::wire::Low3;
    ///
    /// // `0x1D` heads field 3 with code 5 (I32).
    /// assert_eq!(Low3::from_word(0x1D).as_inner(), 5);
    /// assert_eq!(Low3::new(8), None); // three bits only
    /// ```
    #[must_use]
    pub struct Low3(u8 as u8 in 0..=7) with min, max, new, new_unchecked;
}

// The unchecked length face compiles exactly where a proven caller
// lives: the reading kernels and their consumers re-admit values a
// class judgment already bounded, and the equal-length transcoders
// re-admit lengths carried whole from admitted input. The list is
// the union of those consumers' own gates (`varint::slice`,
// `varint::carry`, and the transcode cells). The range literals
// restate the declaration above; the face reads none of them, and
// the `MAX` assertion below pins the real bound.
#[cfg(any(
    test,
    feature = "varint-slice",
    feature = "varint-carry",
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "traverse-grouped",
    feature = "traverse-groupless",
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "patch-grouped",
    feature = "fixed-patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless",
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
))]
impl PayloadLen {
    crate::_macro::define_valid_range_face!(new_unchecked: PayloadLen(u32 as u32));
}

// The macro takes literals; the length class is semantically
// int32's non-negative range — tied here so the literal cannot
// drift from its meaning.
const _: () = assert!(PayloadLen::MAX.as_inner() == i32::MAX.cast_unsigned());

// The niches pay for themselves: `Option` of each is free.
const _: () = assert!(core::mem::size_of::<Option<FieldNumber>>() == 4);
const _: () = assert!(core::mem::size_of::<Option<PayloadLen>>() == 4);
const _: () = assert!(core::mem::size_of::<Option<Low3>>() == 1);

impl FieldNumber {
    /// Extracts the field number from a whole tag word (`None` for
    /// field zero — the caller's fault vocabulary names that case).
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::wire::FieldNumber;
    ///
    /// // `0x18` heads field 3 (code 0).
    /// assert_eq!(FieldNumber::from_word(0x18), FieldNumber::new(3));
    /// assert_eq!(FieldNumber::from_word(0x05), None); // field zero
    /// ```
    #[inline]
    #[must_use]
    pub const fn from_word(word: u32) -> Option<Self> {
        Self::new(word >> 3)
    }
}

impl Low3 {
    /// The code bits of a whole tag word. Total: masking proves the
    /// range.
    #[inline]
    #[allow(
        clippy::as_conversions,
        reason = "masking to three bits keeps the word inside the byte domain"
    )]
    pub const fn from_word(word: u32) -> Self {
        // SAFETY: `word & 7` is within 0..=7 by construction.
        unsafe { Self::new_unchecked((word & 7) as u8) }
    }
}

/// Composes a tag word from proven parts (crate-internal: the
/// public emission faces are the dialects' typed builders, which
/// cannot name an unassigned code). Cannot overflow: the field's
/// upper bound leaves exactly three bits of headroom. The builders
/// are the only consumers, so the face compiles exactly when a
/// dialect table does — the gate is the union of the two tables'
/// lists above.
#[cfg(any(
    test,
    feature = "wire-grouped",
    feature = "wire-groupless",
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "traverse-grouped",
    feature = "traverse-groupless",
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "patch-grouped",
    feature = "fixed-patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "code bits widen losslessly into the tag word; const `From` is unavailable"
)]
pub(crate) const fn tag_word(field: FieldNumber, code: Low3) -> u32 {
    (field.as_inner() << 3) | code.as_inner() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_bounds_are_the_format_classes() {
        assert!(FieldNumber::new(0).is_none());
        assert_eq!(FieldNumber::new(1), Some(FieldNumber::MIN));
        assert_eq!(FieldNumber::new((1 << 29) - 1), Some(FieldNumber::MAX));
        assert!(FieldNumber::new(1 << 29).is_none());

        assert_eq!(PayloadLen::new(0), Some(PayloadLen::MIN));
        assert_eq!(PayloadLen::new(i32::MAX as u32), Some(PayloadLen::MAX));
        assert!(PayloadLen::new(1 << 31).is_none());

        assert_eq!(Low3::new(7), Some(Low3::MAX));
        assert!(Low3::new(8).is_none());
    }

    #[test]
    fn tag_word_round_trips_at_the_extremes() {
        let field = FieldNumber::MAX;
        let word = tag_word(field, Low3::MAX);
        assert_eq!(word, u32::MAX >> 3 << 3 | 7);
        assert_eq!(FieldNumber::from_word(word), Some(field));
        assert_eq!(Low3::from_word(word).as_inner(), 7);

        let word = tag_word(FieldNumber::MIN, Low3::MIN);
        assert_eq!(word, 8);
        assert_eq!(FieldNumber::from_word(0b0000_0101), None); // field 0
    }

    #[test]
    fn dialect_builders_are_the_only_public_word_faces() {
        // grouped: head kinds and the end tag; groupless: head
        // kinds only — no public path composes an unassigned (or,
        // in groupless, group) code into a word.
        let f = FieldNumber::new(1).unwrap();
        assert_eq!(crate::wire::grouped::head_word(f, grouped::RecordKind::Group), 0x0B);
        assert_eq!(crate::wire::grouped::group_end_word(f), 0x0C);
        assert_eq!(crate::wire::groupless::head_word(f, groupless::RecordKind::I32), 0x0D);
    }
}
