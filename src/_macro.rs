/// See: https://github.com/rust-lang/rust/blob/main/library/core/src/num/niche_types.rs
/// [`core::num::niche_types`]
#[allow_internal_unsafe]
#[allow_internal_unstable(pattern_types, pattern_type_macro, structural_match)]
macro_rules! define_valid_range_type {
    ($(
        $(#[$m:meta])*
        $vis:vis struct $name:ident($int:ident as $uint:ident in $low:literal..=$high:literal);
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
            pub const MIN: $name = unsafe { ::core::mem::transmute($low as $int) };
            pub const MAX: $name = unsafe { ::core::mem::transmute($high as $int) };

            #[inline]
            pub const fn new(val: $int) -> Option<Self> {
                if (val as $uint) >= ($low as $uint) && (val as $uint) <= ($high as $uint) {
                    // SAFETY: just checked the inclusive range
                    Some(unsafe { ::core::mem::transmute(val) })
                } else {
                    None
                }
            }

            /// # Safety
            /// Immediate language UB if `val` is not within the valid range.
            #[inline]
            pub const unsafe fn new_unchecked(val: $int) -> Self {
                unsafe { ::core::mem::transmute(val) }
            }

            #[inline]
            pub const fn as_inner(self) -> $int {
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
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                <$int as ::core::fmt::Debug>::fmt(&self.as_inner(), f)
            }
        }
    )+};
}
