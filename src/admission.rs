//! The buffered-admission stratum: the length-class fact, stated
//! once, with the coordinate projections every buffered gate cites.
//!
//! The fact: a buffered scenario admits its input only at or below
//! [`MAX`] — `i32::MAX` bytes, the LEN class top and the reference
//! reader's single-message hard bound; a serialized message beyond
//! 2 GiB has no lawful producer
//! (<https://protobuf.dev/programming-guides/proto-limits/>). The
//! cap costs nothing and buys the coordinate class: every stored or
//! computed byte coordinate and byte count lives in `0..=i32::MAX`,
//! so a coordinate plus an extent sums to at most `2^32 - 2` — u32
//! addition cannot wrap (the const pin below) — and `u32 → usize`
//! indexing is lossless on the crate's 32/64-bit targets (the
//! `compile_error!` pin in the crate root). Range alone proves
//! nothing about order: two in-class coordinates may be
//! reverse-ordered, so subtraction is delivered only through the
//! ordered operation ([`Coord::extent_from`]), which judges the
//! order it needs.
//!
//! The class rides types where evidence is stored and consumed:
//! [`Coord`] (a byte position in an admitted buffer) and
//! [`Extent`] (a byte count within one), minted where a scan or
//! admission gate proves the class, stored through rows and
//! frames, spent by span construction — no panicking bridge
//! anywhere on that path. Gate shapes stay with their machines —
//! inspect's public `Admitted` proof carrier, traverse's
//! `Oversize` refusal, patch's `open` folding, and the session's
//! tighter sealed-carrier cap (below [`MAX`], so its coordinates
//! inhabit the same class) are each point's own face. This module
//! owns the shared fact, its types, and its projections, nothing
//! else.

/// The admission bound in byte-length form: the LEN class top.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "traverse-grouped",
    feature = "traverse-groupless",
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
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless",
))]
pub const MAX: usize = usize_of(crate::wire::PayloadLen::MAX.as_inner());

/// Lossless index projection for coordinate-class `u32` lengths and
/// offsets.
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "u32 widens losslessly into usize on the crate's 32/64-bit targets"
)]
pub const fn usize_of(value: u32) -> usize {
    value as usize
}

/// Narrows an admission-bounded byte count or coordinate back into
/// the class. The debug assertion attributes a violation to the
/// caller that broke the admission contract, not to this
/// projection.
#[inline]
#[track_caller]
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "traverse-grouped",
    feature = "traverse-groupless",
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
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless",
))]
#[allow(
    clippy::as_conversions,
    reason = "the caller's admission proof bounds the value at MAX (= i32::MAX), \
              so it fits u32"
)]
pub const fn admitted_u32(value: usize) -> u32 {
    debug_assert!(value <= MAX);
    value as u32
}

#[cfg(any(
    test,
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "transfer-rewrite-grouped",
    feature = "transfer-rewrite-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
crate::_macro::define_valid_range_type! {
    /// A byte position in an admitted buffer: the coordinate class
    /// `0..=i32::MAX` as a type, minted where a scan or admission
    /// gate proves the class, stored through rows and frames, and
    /// spent where the class fact is consumed (span construction),
    /// so the arithmetic there is judgment-free by type instead of
    /// by prose.
    #[must_use]
    #[allow(
        clippy::redundant_pub_crate,
        reason = "the public-type census reads `pub struct` textually as public surface; \
                  crate vocabulary inside this private module is spelled pub(crate) so \
                  the roster stays true"
    )]
    pub(crate) struct Coord(u32 as u32 in 0..=2_147_483_647);
}

#[cfg(any(
    test,
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
crate::_macro::define_valid_range_type! {
    /// A byte count within an admitted buffer: the same class as
    /// [`Coord`] with the count meaning — distinct from the wire's
    /// [`PayloadLen`](crate::wire::PayloadLen), which shares the
    /// range as a LEN-grammar fact, not an admission fact.
    #[must_use]
    #[allow(
        clippy::redundant_pub_crate,
        reason = "the public-type census reads `pub struct` textually as public surface; \
                  crate vocabulary inside this private module is spelled pub(crate) so \
                  the roster stays true"
    )]
    pub(crate) struct Extent(u32 as u32 in 0..=2_147_483_647) with new_unchecked;
}

// The checked doors and the class extrema are the offline tree
// builders' faces; the selection and editor-scan walks mint through
// the unchecked coordinate door alone, under their own walk proofs
// (the extent's unchecked door serves both closures, so it rides
// the declaration above). Faces sharing a gate share one impl, and
// every face reads the bounds off the declaration itself — the
// invocations restate nothing.
#[cfg(any(
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "transfer-rewrite-grouped",
    feature = "transfer-rewrite-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
impl Coord {
    crate::_macro::define_valid_range_face!(new_unchecked: Coord(u32 as u32));
}
#[cfg(any(
    test,
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "transfer-rewrite-grouped",
    feature = "transfer-rewrite-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
impl Coord {
    crate::_macro::define_valid_range_face!(min: Coord(u32 as u32));
}
#[cfg(any(
    test,
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless"
))]
impl Coord {
    crate::_macro::define_valid_range_face!(max: Coord(u32 as u32));
    crate::_macro::define_valid_range_face!(new: Coord(u32 as u32));
}
#[cfg(any(
    test,
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless"
))]
impl Extent {
    crate::_macro::define_valid_range_face!(max: Extent(u32 as u32));
    crate::_macro::define_valid_range_face!(new: Extent(u32 as u32));
}

#[cfg(any(
    test,
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless"
))]
impl Coord {
    /// Ordered subtraction, the one door to the width between two
    /// coordinates: `end.extent_from(start)` judges `start <= end`
    /// — range alone cannot, two in-class coordinates may be
    /// reverse-ordered — and the difference of two in-class values
    /// is itself in class.
    #[inline]
    #[must_use]
    pub const fn extent_from(self, start: Self) -> Option<Extent> {
        if start.as_inner() <= self.as_inner() {
            // SAFETY: `0 <= self - start <= self <= i32::MAX` — the
            // order was just judged and the class bounds the rest.
            Some(unsafe { Extent::new_unchecked(self.as_inner() - start.as_inner()) })
        } else {
            None
        }
    }

    /// Bounded addition — coordinate plus extent: the u32 sum
    /// cannot wrap (the class maxima sum to `2^32 - 2`, pinned
    /// below), and the result is a coordinate exactly when it
    /// stays at or below the admission bound.
    #[inline]
    #[must_use]
    pub const fn advanced_by(self, by: Extent) -> Option<Self> {
        Self::new(self.as_inner() + by.as_inner())
    }
}

#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
impl Extent {
    /// A LEN-class payload length as an extent: both classes top at
    /// the admission bound (the module [`MAX`] derives from
    /// [`PayloadLen::MAX`](crate::wire::PayloadLen::MAX), and the
    /// maxima equality is pinned below), so the mint is total.
    #[inline]
    pub const fn from_len(len: crate::wire::PayloadLen) -> Self {
        // SAFETY: `PayloadLen` and `Extent` share the class top —
        // the pinned maxima equality — so every LEN-class value is
        // in the extent class.
        unsafe { Self::new_unchecked(len.as_inner()) }
    }

    /// A width-class byte count as an extent: framing words, fixed
    /// values, and provisional zero extents all live in `u8`, whose
    /// whole domain sits below the class top, so the mint is total.
    #[inline]
    #[allow(clippy::as_conversions, reason = "u8 widens losslessly into u32; From is not const")]
    pub const fn from_width(width: u8) -> Self {
        // SAFETY: `u8::MAX` (255) is below the class top (2³¹ - 1).
        unsafe { Self::new_unchecked(width as u32) }
    }
}

// The class pins. Maxima: both tops are the admission bound, tied
// to the length class. No-wrap: the maxima sum to 2^32 - 2, so
// coordinate-plus-extent addition stays in u32 for every in-class
// pair. Order: the ordered subtraction refuses a reversed pair and
// admits an equal one; the bounded addition refuses past the bound
// and admits at it.
#[cfg(any(
    test,
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless"
))]
const _: () = {
    assert!(Coord::MAX.as_inner() == i32::MAX.cast_unsigned());
    assert!(Extent::MAX.as_inner() == crate::wire::PayloadLen::MAX.as_inner());
    assert!(Coord::MAX.as_inner() as u64 + Extent::MAX.as_inner() as u64 == u32::MAX as u64 - 1);
    assert!(Coord::MIN.extent_from(Coord::MAX).is_none());
    assert!(matches!(Coord::MAX.extent_from(Coord::MAX), Some(zero) if zero.as_inner() == 0));
    assert!(Coord::MAX.advanced_by(Extent::new(1).unwrap()).is_none());
    assert!(matches!(
        Coord::MIN.advanced_by(Extent::MAX),
        Some(top) if top.as_inner() == Coord::MAX.as_inner()
    ));
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_class_admits_exactly_the_admission_range() {
        assert_eq!(Coord::new(0), Some(Coord::MIN));
        assert_eq!(Coord::new(i32::MAX.cast_unsigned()), Some(Coord::MAX));
        assert_eq!(Coord::new(i32::MAX.cast_unsigned() + 1), None);
        assert_eq!(Extent::new(i32::MAX.cast_unsigned()), Some(Extent::MAX));
        assert_eq!(Extent::new(1 << 31), None);
    }

    #[test]
    fn ordered_subtraction_judges_the_order_it_needs() {
        let start = Coord::new(3).unwrap();
        let end = Coord::new(8).unwrap();
        assert_eq!(end.extent_from(start).map(Extent::as_inner), Some(5));
        assert_eq!(end.extent_from(end).map(Extent::as_inner), Some(0));
        // Two in-class coordinates, reverse-ordered: range alone
        // would have accepted the wrapping subtraction.
        assert_eq!(start.extent_from(end), None);
    }

    #[test]
    fn bounded_addition_judges_the_bound_and_cannot_wrap() {
        let coord = Coord::new(i32::MAX.cast_unsigned() - 1).unwrap();
        assert_eq!(coord.advanced_by(Extent::new(1).unwrap()), Some(Coord::MAX));
        assert_eq!(coord.advanced_by(Extent::new(2).unwrap()), None);
        // The extreme pair stays in u32 by the class fact.
        assert_eq!(Coord::MAX.advanced_by(Extent::MAX), None);
    }
}
