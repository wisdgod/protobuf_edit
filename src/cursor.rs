//! The checked cursor engines: the private stratum behind the
//! `traverse` faces, driven directly by the select, rewrite,
//! inplace, convert, and splice walks.
//!
//! One engine per dialect, each a single-pass walk over one
//! buffered slice: admission caps the input at the LEN class so
//! every coordinate fits `u32`, the step faces are monomorphized
//! per acceptance standard (`step::<MINIMAL>`), and the first
//! refusal fuses the walk. The `traverse` module re-exports these
//! types as its public faces; the selector, rewriter, in-place
//! editor, converter, and splicer walks instantiate their own
//! acceptance engines through the crate-side step face without
//! compiling those faces.

/// Admission refusal: the input exceeds the
/// [`i32::MAX` input cap](crate::Span) — the LEN length class top —
/// under which every walk coordinate fits `u32`. Unit-shaped — the
/// refused length is in the caller's hands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Oversize;

impl core::fmt::Display for Oversize {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("input exceeds the LEN-class traversal cap")
    }
}

impl core::error::Error for Oversize {}

#[cfg(any(
    feature = "select-grouped",
    feature = "rewrite-grouped",
    feature = "inplace-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "traverse-grouped"
))]
crate::_macro::define_valid_range_type! {
    /// The grouped cursor's in-band nesting bound: how deep group
    /// frames may nest before the walk refuses.
    ///
    /// Deliberately narrower in meaning than [`crate::DepthLimit`]:
    /// the cursor hands LEN payloads to the consumer without
    /// descending, so group tags — the one nesting the walk itself
    /// tracks — are all that spend from this bound. The domain is
    /// the same nesting-policy domain, so a total limit converts
    /// `From` a [`crate::DepthLimit`] without failure.
    #[must_use]
    pub struct GroupDepth(u16 as u16 in 1..=10_000) with min, max, new_unchecked;
}

#[cfg(feature = "traverse-grouped")]
impl GroupDepth {
    // The checked constructor is the traverse face's own door: the
    // consuming walks mint the bound `From` a total
    // [`crate::DepthLimit`] instead.
    crate::_macro::define_valid_range_face!(new: GroupDepth(u16 as u16));

    /// The C++ and Java reference readers' recursion limit (100).
    pub const REFERENCE: Self = Self::new(100).unwrap();
}

#[cfg(any(
    feature = "select-grouped",
    feature = "rewrite-grouped",
    feature = "inplace-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "traverse-grouped"
))]
impl From<crate::DepthLimit> for GroupDepth {
    /// Total-depth policy carried into the in-band-group meaning —
    /// the domains coincide, so the conversion cannot fail.
    #[inline]
    fn from(limit: crate::DepthLimit) -> Self {
        const _: () = {
            assert!(GroupDepth::MIN.as_inner() == crate::DepthLimit::MIN.as_inner());
            assert!(GroupDepth::MAX.as_inner() == crate::DepthLimit::MAX.as_inner());
        };
        // SAFETY: the bounds above pin the two domains equal, so
        // every DepthLimit value lies in GroupDepth's range.
        unsafe { Self::new_unchecked(limit.as_inner()) }
    }
}

#[cfg(any(
    feature = "select-grouped",
    feature = "rewrite-grouped",
    feature = "inplace-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "traverse-grouped"
))]
pub mod grouped;
#[cfg(any(
    feature = "select-groupless",
    feature = "rewrite-groupless",
    feature = "inplace-groupless",
    feature = "fixed-inplace-groupless",
    feature = "convert-grouped",
    feature = "splice-groupless",
    feature = "traverse-groupless"
))]
pub mod groupless;
