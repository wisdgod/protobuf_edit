use core::num::NonZeroU32;

pub const MAX_FIELD_NUMBER: u32 = 0x1F_FF_FF_FF;

define_valid_range_type!(
    /// Valid protobuf field number.
    ///
    /// Range: 1..=(1<<29)-1.
    pub struct FieldNumber(u32 as u32 in 1..=0x1F_FF_FF_FF);
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// Non-zero protobuf tag value: `(field_number << 3) | wire_type`.
pub struct Tag(NonZeroU32);

impl Tag {
    #[inline]
    pub const fn new(raw: u32) -> Option<Self> {
        let Some(nz) = NonZeroU32::new(raw) else {
            return None;
        };
        let Some(_wire_type) = WireType::from_low3(raw & 0x07) else {
            return None;
        };
        let Some(_field_number) = FieldNumber::new(raw >> 3) else {
            return None;
        };
        Some(Self(nz))
    }

    #[inline]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    #[inline]
    pub const fn as_nonzero(self) -> NonZeroU32 {
        self.0
    }

    #[inline]
    pub const fn from_parts(field_number: FieldNumber, wire_type: WireType) -> Self {
        let raw = (field_number.as_inner() << 3) | (wire_type as u32);
        // SAFETY: FieldNumber is non-zero and wire_type fits low 3 bits.
        unsafe { Self(NonZeroU32::new_unchecked(raw)) }
    }

    #[inline]
    pub const fn try_from_parts(field_number: u32, wire_type: WireType) -> Option<Self> {
        let Some(field_number) = FieldNumber::new(field_number) else {
            return None;
        };
        Some(Self::from_parts(field_number, wire_type))
    }

    #[inline]
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
    pub const fn field_number(self) -> FieldNumber {
        self.split().0
    }

    #[inline]
    pub const fn wire_type(self) -> WireType {
        self.split().1
    }
}

impl From<(FieldNumber, WireType)> for Tag {
    #[inline]
    fn from(value: (FieldNumber, WireType)) -> Self {
        Tag::from_parts(value.0, value.1)
    }
}

impl From<Tag> for NonZeroU32 {
    #[inline]
    fn from(value: Tag) -> Self {
        value.as_nonzero()
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
        Tag::new(value).ok_or(())
    }
}

impl TryFrom<(u32, WireType)> for Tag {
    type Error = ();

    #[inline]
    fn try_from(value: (u32, WireType)) -> Result<Self, Self::Error> {
        Tag::try_from_parts(value.0, value.1).ok_or(())
    }
}
