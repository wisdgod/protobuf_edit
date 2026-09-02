/// One declared face of a [`define_valid_range_type!`] wrapper —
/// the keyword arms below are the whole face vocabulary. Every arm
/// expands to bare associated items: the declaration spells its
/// `with` faces inside the wrapper's one inherent `impl`, and a
/// gated face lands inside an `impl` block at its consumer. No arm
/// restates the range — the bounds are read from the declaration's
/// own `LOW`/`HIGH`, so a gated invocation cannot drift from the
/// pattern it admits into.
#[allow_internal_unsafe]
#[allow_internal_unstable(pattern_types, pattern_type_macro, structural_match)]
macro_rules! define_valid_range_face {
    (min: $name:ident($int:ident as $uint:ident)) => {
        /// The smallest admitted value.
        pub const MIN: $name = {
            // SAFETY: the declaration's own lower end is in range;
            // the bound and the wrapper share one width.
            #[allow(
                clippy::missing_transmute_annotations,
                reason = "both sides are macro-fixed — the declaration's `LOW` in, \
                          the generated wrapper out through the constant's type"
            )]
            unsafe {
                ::core::mem::transmute($name::LOW)
            }
        };
    };
    (max: $name:ident($int:ident as $uint:ident)) => {
        /// The largest admitted value.
        pub const MAX: $name = {
            // SAFETY: the declaration's own upper end is in range;
            // the bound and the wrapper share one width.
            #[allow(
                clippy::missing_transmute_annotations,
                reason = "both sides are macro-fixed — the declaration's `HIGH` in, \
                          the generated wrapper out through the constant's type"
            )]
            unsafe {
                ::core::mem::transmute($name::HIGH)
            }
        };
    };
    (new: $name:ident($int:ident as $uint:ident)) => {
        /// Admits `val` when it lies within the valid range —
        /// the single judgment every holder relies on.
        #[inline]
        pub const fn new(val: $int) -> Option<Self> {
            #[allow(
                clippy::as_conversions,
                reason = "the bounds compare in the unsigned domain; the \
                          reinterpretation is same-width"
            )]
            let uval = val as $uint;
            if uval >= Self::LOW && uval <= Self::HIGH {
                // SAFETY: just checked the inclusive range
                #[allow(
                    clippy::missing_transmute_annotations,
                    reason = "both sides are macro-fixed — `$int` in, the generated \
                              wrapper out through `Option<Self>`; spelling them would \
                              only restate the declaration this arm expands from"
                )]
                Some(unsafe { ::core::mem::transmute(val) })
            } else {
                None
            }
        }
    };
    (new_unchecked: $name:ident($int:ident as $uint:ident)) => {
        /// # Safety
        /// Immediate language UB if `val` is not within the valid range.
        #[inline]
        pub(crate) const unsafe fn new_unchecked(val: $int) -> Self {
            #[allow(
                clippy::as_conversions,
                reason = "the bounds compare in the unsigned domain; the \
                          reinterpretation is same-width"
            )]
            {
                ::core::debug_assert!(
                    val as $uint >= Self::LOW && val as $uint <= Self::HIGH,
                    "new_unchecked was handed a value outside the valid range"
                );
            }
            // SAFETY: the caller guarantees `val` lies in the valid range.
            unsafe { ::core::mem::transmute(val) }
        }
    };
}

pub(crate) use define_valid_range_face;

/// Generates a `#[repr(transparent)]` wrapper over a pattern type
/// restricted to `$low..=$high` — the crate's contract-type
/// generator, mirroring `core::num::niche_types`
/// (<https://github.com/rust-lang/rust/blob/main/library/core/src/num/niche_types.rs>).
///
/// Admission happens once, in `new`; the pattern type's niche makes
/// `Option` of every instance free.
///
/// Every wrapper carries one inherent `impl` holding the declared
/// bounds, the faces spelled in its `with` list, and `as_inner`
/// (the comparison, hash, and debug impls read through it). A face
/// consumed by only some cells is left off the `with` list and
/// invoked behind its own gate at the consumer, inside an
/// `impl` block there — so each face exists exactly where a
/// consumer does, and every face reads the bounds declared here.
#[allow_internal_unsafe]
#[allow_internal_unstable(pattern_types, pattern_type_macro, structural_match)]
macro_rules! define_valid_range_type {
    ($(
        $(#[$m:meta])*
        $vis:vis struct $name:ident($int:ident as $uint:ident in $low:literal..=$high:literal)
            $(with $($face:ident),+)?;
    )+) => {$(
        #[derive(Clone, Copy)]
        #[repr(transparent)]
        $(#[$m])*
        $vis struct $name(::core::pattern_type!($int is $low..=$high));

        impl ::core::cmp::Eq for $name {}

        const _: () = {
            // With the `valid_range` attributes, it's always specified as unsigned
            ::core::assert!(<$uint>::MIN == 0);
            let ulow: $uint = $low;
            let uhigh: $uint = $high;
            ::core::assert!(ulow <= uhigh);

            ::core::assert!(::core::mem::size_of::<$int>() == ::core::mem::size_of::<$uint>());
        };

        impl $name {
            /// The declared lower bound, in the comparison
            /// (unsigned) domain. Faces read the bounds from here,
            /// never from a restatement: a gated invocation that
            /// could restate them could also drift, and a drifted
            /// bound admits out-of-pattern values.
            #[allow(
                dead_code,
                reason = "which faces a cell compiles is the per-site gates' \
                          business, invisible to this declaration"
            )]
            const LOW: $uint = $low;
            /// The declared upper bound; see `LOW`.
            #[allow(
                dead_code,
                reason = "which faces a cell compiles is the per-site gates' \
                          business, invisible to this declaration"
            )]
            const HIGH: $uint = $high;

            $($($crate::_macro::define_valid_range_face!($face: $name($int as $uint));)+)?

            /// The underlying integer (range-proven by existence).
            #[inline]
            pub const fn as_inner(self) -> $int {
                // SAFETY: widening direction — every value of the
                // restricted pattern type is a valid `$int`.
                unsafe { ::core::mem::transmute(self) }
            }
        }

        impl ::core::marker::StructuralPartialEq for $name {}

        impl ::core::cmp::PartialEq for $name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.as_inner() == other.as_inner()
            }
        }

        impl ::core::cmp::Ord for $name {
            #[inline]
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                ::core::cmp::Ord::cmp(&self.as_inner(), &other.as_inner())
            }
        }

        impl ::core::cmp::PartialOrd for $name {
            #[inline]
            fn partial_cmp(&self, other: &Self) -> ::core::option::Option<::core::cmp::Ordering> {
                ::core::option::Option::Some(::core::cmp::Ord::cmp(self, other))
            }
        }

        impl ::core::hash::Hash for $name {
            fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
                ::core::hash::Hash::hash(&self.as_inner(), state);
            }
        }

        impl ::core::fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                <$int as ::core::fmt::Debug>::fmt(&self.as_inner(), f)
            }
        }
    )+};
}

pub(crate) use define_valid_range_type;
