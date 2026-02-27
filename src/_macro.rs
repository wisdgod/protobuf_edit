/// See: https://github.com/rust-lang/rust/blob/main/library/core/src/num/niche_types.rs
/// [`core::num::niche_types`]
#[allow_internal_unsafe]
#[allow_internal_unstable(rustc_attrs, structural_match)]
macro_rules! define_valid_range_type {
    ($(
        $(#[$m:meta])*
        $vis:vis struct $name:ident($int:ident as $uint:ident in $low:literal..=$high:literal);
    )+) => {$(
        #[derive(Clone, Copy, Eq)]
        #[repr(transparent)]
        #[rustc_layout_scalar_valid_range_start($low)]
        #[rustc_layout_scalar_valid_range_end($high)]
        $(#[$m])*
        $vis struct $name($int);

        const _: () = {
            // With the `valid_range` attributes, it's always specified as unsigned
            ::core::assert!(<$uint>::MIN == 0);
            let ulow: $uint = $low;
            let uhigh: $uint = $high;
            ::core::assert!(ulow <= uhigh);

            ::core::assert!(::core::mem::size_of::<$int>() == ::core::mem::size_of::<$uint>());
        };

        impl $name {
            pub const MIN: $name = unsafe { $name($low as $int) };
            pub const MAX: $name = unsafe { $name($high as $int) };

            #[inline]
            pub const fn new(val: $int) -> Option<Self> {
                if (val as $uint) >= ($low as $uint) && (val as $uint) <= ($high as $uint) {
                    // SAFETY: just checked the inclusive range
                    Some(unsafe { $name(val) })
                } else {
                    None
                }
            }

            /// Constructs an instance of this type from the underlying integer
            /// primitive without checking whether its zero.
            ///
            /// # Safety
            /// Immediate language UB if `val` is not within the valid range for this
            /// type, as it violates the validity invariant.
            #[inline]
            pub const unsafe fn new_unchecked(val: $int) -> Self {
                // SAFETY: Caller promised that `val` is within the valid range.
                unsafe { $name(val) }
            }

            #[inline]
            pub const fn as_inner(self) -> $int {
                // SAFETY: This is a transparent wrapper, so unwrapping it is sound
                // (Not using `.0` due to MCP#807.)
                unsafe { ::core::mem::transmute(self) }
            }
        }

        // This is required to allow matching a constant.  We don't get it from a derive
        // because the derived `PartialEq` would do a field projection, which is banned
        // by <https://github.com/rust-lang/compiler-team/issues/807>.
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
            // Required method
            fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
                ::core::hash::Hash::hash(&self.as_inner(), state);
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                <$int as ::core::fmt::Debug>::fmt(&self.as_inner(), f)
            }
        }
    )+};
}
