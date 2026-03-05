use alloc::vec::Vec;
use core::fmt;
use core::mem::MaybeUninit;

use crate::buf::Buf;
use crate::error::TreeError;
use crate::fx::FxHashMap;
use crate::varint;
use crate::wire::Tag;

define_valid_range_type!(
    /// Valid field index in arena.
    ///
    /// `u16::MAX` is reserved as `Option<Ix>::None`.
    pub struct Ix(u16 as u16 in 0..=65534);
);

pub const MAX_FIELDS: usize = Ix::MAX.as_inner() as usize + 1;

pub type Link = Option<Ix>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
/// Target container capacities used by `Document::with_capacities` and decode planning.
pub struct Capacities {
    pub fields: usize,
    pub varints: usize,
    pub fixed32s: usize,
    pub fixed64s: usize,
    pub lendels: usize,
    #[cfg(feature = "group")]
    pub groups: usize,
    pub query: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Head/tail links for one repeated tag chain.
pub struct Bucket {
    pub head: Link,
    pub tail: Link,
}

impl Bucket {
    #[inline]
    pub const fn empty() -> Self {
        Self { head: None, tail: None }
    }
}

/// Arena-backed protobuf message document.
#[derive(Clone)]
pub struct Document {
    pub(super) varints: Vec<Varint>,
    pub(super) fixed32s: Vec<Fixed32>,
    pub(super) fixed64s: Vec<Fixed64>,
    pub(super) lendels: Vec<LengthDelimited>,
    #[cfg(feature = "group")]
    pub(super) groups: Vec<Group>,
    pub(super) fields: Vec<Field>,
    pub(super) query: FxHashMap<Tag, Bucket>,
}

/// WireType::Varint payload slot.
#[derive(Clone)]
pub struct Varint {
    pub value: u64,
    pub raw: RawVarint64,
}

/// WireType::I32 payload slot.
#[derive(Clone)]
pub struct Fixed32 {
    pub value: u32,
}

/// WireType::I64 payload slot.
#[derive(Clone)]
pub struct Fixed64 {
    pub value: u64,
}

/// WireType::Len payload slot.
#[derive(Clone)]
pub struct LengthDelimited {
    pub buf: Buf,
    pub raw: RawVarint32,
}

#[cfg(feature = "group")]
/// WireType::SGroup payload slot (group body bytes only).
#[derive(Clone)]
pub struct Group {
    pub buf: Buf,
}

/// Node metadata stored in insertion order.
#[derive(Clone)]
pub struct Field {
    pub tag: Tag,
    pub index: Ix,
    pub removed: bool,
    pub prev: Link,
    pub next: Link,
    pub raw: RawVarint32,
}

/// Raw varint-32 bytes packed as `[u8; 4] + tail`.
///
/// Tail layout (`u8`):
/// - low 4 bits: the 5th raw byte payload bits (only used when len == 5)
/// - bits 4..=6: length (`1..=5`)
/// - bit 7: reserved
#[derive(Clone, Copy)]
pub struct RawVarint32 {
    head: [MaybeUninit<u8>; 4],
    tail: u8,
}

impl RawVarint32 {
    pub const MAX_LEN: u8 = 5;
    const LEN_MASK: u8 = 0b0111_0000;
    const LEN_SHIFT: u8 = 4;
    const LAST_BYTE_MASK: u8 = 0b0000_1111;

    #[inline]
    const fn new_uninit() -> Self {
        Self { head: [MaybeUninit::uninit(); 4], tail: 0 }
    }

    #[inline]
    pub const fn len(&self) -> u8 {
        (self.tail & Self::LEN_MASK) >> Self::LEN_SHIFT
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn from_u32(value: u32) -> Self {
        let mut encoded = [MaybeUninit::uninit(); 10];
        let n = <u32 as varint::Varint>::encode(&mut encoded, value) as usize;
        let bytes = unsafe { core::slice::from_raw_parts(encoded.as_ptr().cast::<u8>(), n) };
        unsafe { Self::from_slice_unchecked(bytes) }
    }

    #[inline]
    pub fn from_data(data: &[u8]) -> Result<(u32, u32, Self), TreeError> {
        let (value, consumed) = varint::decode32(data).ok_or(TreeError::DecodeError)?;
        // SAFETY: decode32 guarantees consumed ∈ 1..=5 and validates the terminal byte range.
        let raw = unsafe { Self::from_slice_unchecked(&data[..consumed as usize]) };
        Ok((value, consumed, raw))
    }

    /// # Safety
    /// - `raw.len()` must be in `1..=5`
    /// - when `raw.len() == 5`, `raw[4]` must satisfy `raw[4] & !0x0F == 0`
    #[inline]
    pub unsafe fn from_slice_unchecked(raw: &[u8]) -> Self {
        let len = raw.len();
        debug_assert!(len > 0 && len <= Self::MAX_LEN as usize);

        let mut out = Self::new_uninit();
        for (dst, src) in out.head.iter_mut().zip(raw.iter().copied()) {
            *dst = MaybeUninit::new(src);
        }

        let len_bits = (len as u8) << Self::LEN_SHIFT;
        out.tail = if len == 5 {
            let last = raw[4];
            debug_assert!((last & !Self::LAST_BYTE_MASK) == 0);
            len_bits | last
        } else {
            len_bits
        };
        out
    }

    #[inline]
    pub fn to_array(self) -> ([u8; 5], usize) {
        let len = core::cmp::min(self.len() as usize, Self::MAX_LEN as usize);
        let mut out = [0u8; 5];
        let copy_len = core::cmp::min(len, 4);
        for (idx, byte) in out.iter_mut().take(copy_len).enumerate() {
            *byte = unsafe { self.head[idx].assume_init() };
        }
        if len == 5 {
            out[4] = self.tail & Self::LAST_BYTE_MASK;
        }
        (out, len)
    }
}

impl Default for RawVarint32 {
    #[inline]
    fn default() -> Self {
        Self::new_uninit()
    }
}

impl fmt::Debug for RawVarint32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (bytes, len) = self.to_array();
        f.debug_struct("RawVarint32").field("len", &len).field("bytes", &&bytes[..len]).finish()
    }
}

/// Raw varint-64 bytes packed as `[u8; 9] + tail`.
///
/// Tail layout (`u8`):
/// - low 1 bit: the 10th raw byte payload bit (only used when len == 10)
/// - bits 1..=4: length (`1..=10`)
/// - bits 5..=7: reserved
#[derive(Clone, Copy)]
pub struct RawVarint64 {
    head: [MaybeUninit<u8>; 9],
    tail: u8,
}

impl RawVarint64 {
    pub const MAX_LEN: u8 = 10;
    const LEN_MASK: u8 = 0b0001_1110;
    const LEN_SHIFT: u8 = 1;
    const LAST_BYTE_MASK: u8 = 0b0000_0001;

    #[inline]
    const fn new_uninit() -> Self {
        Self { head: [MaybeUninit::uninit(); 9], tail: 0 }
    }

    #[inline]
    pub const fn len(&self) -> u8 {
        (self.tail & Self::LEN_MASK) >> Self::LEN_SHIFT
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn from_u64(value: u64) -> Self {
        let mut encoded = [MaybeUninit::uninit(); 10];
        let n = <u64 as varint::Varint>::encode(&mut encoded, value) as usize;
        let bytes = unsafe { core::slice::from_raw_parts(encoded.as_ptr().cast::<u8>(), n) };
        unsafe { Self::from_slice_unchecked(bytes) }
    }

    #[inline]
    pub fn from_data(data: &[u8]) -> Result<(u64, u32, Self), TreeError> {
        let (value, consumed) = varint::decode64(data).ok_or(TreeError::DecodeError)?;
        // SAFETY: decode64 guarantees consumed ∈ 1..=10 and validates the terminal byte range.
        let raw = unsafe { Self::from_slice_unchecked(&data[..consumed as usize]) };
        Ok((value, consumed, raw))
    }

    /// # Safety
    /// - `raw.len()` must be in `1..=10`
    /// - when `raw.len() == 10`, `raw[9]` must satisfy `raw[9] & !0x01 == 0`
    #[inline]
    pub unsafe fn from_slice_unchecked(raw: &[u8]) -> Self {
        let len = raw.len();
        debug_assert!(len > 0 && len <= Self::MAX_LEN as usize);

        let mut out = Self::new_uninit();
        for (dst, src) in out.head.iter_mut().zip(raw.iter().copied()) {
            *dst = MaybeUninit::new(src);
        }

        let len_bits = (len as u8) << Self::LEN_SHIFT;
        out.tail = if len == 10 {
            let last = raw[9];
            debug_assert!((last & !Self::LAST_BYTE_MASK) == 0);
            len_bits | last
        } else {
            len_bits
        };
        out
    }

    #[inline]
    pub fn to_array(self) -> ([u8; 10], usize) {
        let len = core::cmp::min(self.len() as usize, Self::MAX_LEN as usize);
        let mut out = [0u8; 10];
        let copy_len = core::cmp::min(len, 9);
        for (idx, byte) in out.iter_mut().take(copy_len).enumerate() {
            *byte = unsafe { self.head[idx].assume_init() };
        }
        if len == 10 {
            out[9] = self.tail & Self::LAST_BYTE_MASK;
        }
        (out, len)
    }
}

impl Default for RawVarint64 {
    #[inline]
    fn default() -> Self {
        Self::new_uninit()
    }
}

impl fmt::Debug for RawVarint64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (bytes, len) = self.to_array();
        f.debug_struct("RawVarint64").field("len", &len).field("bytes", &&bytes[..len]).finish()
    }
}

const _: () = {
    assert!(core::mem::size_of::<Option<Ix>>() == core::mem::size_of::<u16>());
};
