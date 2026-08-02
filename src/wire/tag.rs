pub const MAX_FIELD_NUMBER: u32 = 0x1F_FF_FF_FF;

define_valid_range_type!(
    /// Valid protobuf field number.
    ///
    /// Range: 1..=(1<<29)-1.
    pub struct FieldNumber(u32 as u32 in 1..=0x1F_FF_FF_FF);

    /// Raw tag storage constrained to the contiguous validity envelope.
    ///
    /// The smallest valid tag is `(1 << 3) | 0 = 8` and the largest is
    /// `(MAX_FIELD_NUMBER << 3) | 5 = 0xFFFF_FFFD`, so values outside
    /// `8..=0xFFFF_FFFD` are free niches (ten of them). The envelope cannot
    /// express the low-3-bit wire-type constraint; `Tag::new` remains the
    /// only checked entry point for full validity.
    struct TagInner(u32 as u32 in 8..=0xFF_FF_FF_FD);
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
/// Protobuf wire type encoded in the low 3 bits of a tag value.
pub enum WireType {
    Varint = 0,
    I64 = 1,
    Len = 2,
    #[cfg(feature = "group")]
    SGroup = 3,
    #[cfg(feature = "group")]
    EGroup = 4,
    I32 = 5,
}

impl WireType {
    #[inline]
    #[must_use]
    pub const fn from_low3(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Varint),
            1 => Some(Self::I64),
            2 => Some(Self::Len),
            #[cfg(feature = "group")]
            3 => Some(Self::SGroup),
            #[cfg(feature = "group")]
            4 => Some(Self::EGroup),
            5 => Some(Self::I32),
            _ => None,
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
/// Protobuf tag value: `(field_number << 3) | wire_type`.
///
/// Stored as a range-typed `u32` in `8..=0xFFFF_FFFD`, so `Option<Tag>` (and
/// further nestings) stay 4 bytes via the spare niches.
pub struct Tag(TagInner);

impl Tag {
    #[inline]
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        let Some(_wire_type) = WireType::from_low3(raw & 0x07) else {
            return None;
        };
        let Some(_field_number) = FieldNumber::new(raw >> 3) else {
            return None;
        };
        // SAFETY: field number 1..=2^29-1 puts `raw` in 8..=0xFFFF_FFFA plus
        // a valid wire type (<= 5) keeps it within the envelope.
        Some(Self(unsafe { TagInner::new_unchecked(raw) }))
    }

    #[inline]
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.as_inner()
    }

    #[inline]
    #[must_use]
    pub const fn from_parts(field_number: FieldNumber, wire_type: WireType) -> Self {
        let raw = (field_number.as_inner() << 3) | (wire_type as u32);
        // SAFETY: field_number >= 1 makes raw >= 8; field_number <= 2^29-1
        // and wire_type <= 5 make raw <= 0xFFFF_FFFD.
        unsafe { Self(TagInner::new_unchecked(raw)) }
    }

    #[inline]
    #[must_use]
    pub const fn try_from_parts(field_number: u32, wire_type: WireType) -> Option<Self> {
        let Some(field_number) = FieldNumber::new(field_number) else {
            return None;
        };
        Some(Self::from_parts(field_number, wire_type))
    }

    #[inline]
    #[must_use]
    pub const fn split(self) -> (FieldNumber, WireType) {
        let raw = self.get();
        let Some(wire_type) = WireType::from_low3(raw & 0x07) else {
            unsafe { core::hint::unreachable_unchecked() }
        };
        // SAFETY: Tag invariants guarantee field number is within FieldNumber range.
        let field_number = unsafe { FieldNumber::new_unchecked(raw >> 3) };
        (field_number, wire_type)
    }

    #[inline]
    #[must_use]
    pub const fn field_number(self) -> FieldNumber {
        self.split().0
    }

    #[inline]
    #[must_use]
    pub const fn wire_type(self) -> WireType {
        self.split().1
    }
}

impl From<(FieldNumber, WireType)> for Tag {
    #[inline]
    fn from(value: (FieldNumber, WireType)) -> Self {
        Self::from_parts(value.0, value.1)
    }
}

impl From<Tag> for u32 {
    #[inline]
    fn from(value: Tag) -> Self {
        value.get()
    }
}

impl TryFrom<u32> for Tag {
    type Error = ();

    #[inline]
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(())
    }
}

impl TryFrom<(u32, WireType)> for Tag {
    type Error = ();

    #[inline]
    fn try_from(value: (u32, WireType)) -> Result<Self, Self::Error> {
        Self::try_from_parts(value.0, value.1).ok_or(())
    }
}

impl core::fmt::Debug for Tag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (number, wire_type) = self.split();
        f.debug_struct("Tag")
            .field("number", &number.as_inner())
            .field("wire_type", &wire_type)
            .finish()
    }
}

const _: () = {
    // The 8..=0xFFFF_FFFD envelope leaves ten niches, so nested `Option`s of
    // `Tag` stay pointer-free and 4 bytes wide.
    assert!(core::mem::size_of::<Option<Tag>>() == 4);
    assert!(core::mem::size_of::<Option<Option<Option<Tag>>>>() == 4);
};
