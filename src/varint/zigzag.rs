use super::Varint;

pub const trait Encode<Unsigned: Varint>: Copy {
    fn encode(self) -> Unsigned;
}

pub const trait Decode<Signed>: Varint {
    fn decode(self) -> Signed;
}

macro_rules! impl_zigzag {
    ($signed:ty, $unsigned:ty, $shift:expr) => {
        impl const Encode<$unsigned> for $signed {
            #[inline]
            fn encode(self) -> $unsigned {
                ((self << 1) ^ (self >> $shift)) as $unsigned
            }
        }

        impl const Decode<$signed> for $unsigned {
            #[inline]
            fn decode(self) -> $signed {
                ((self >> 1) as $signed) ^ (-((self & 1) as $signed))
            }
        }
    };
}

impl_zigzag!(i32, u32, 31);
impl_zigzag!(i64, u64, 63);
