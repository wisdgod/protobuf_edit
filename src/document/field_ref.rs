use crate::varint;
use crate::wire::{FieldNumber, Tag, WireType};

use super::{BorrowedDocument, Capacities, Field, Ix, Document, TreeError};

#[derive(Clone, Copy)]
/// Immutable view of one field in a `Document`.
pub struct FieldRef<'a> {
    tree: &'a Document,
    ix: Ix,
}

/// Iterator over live fields in insertion order.
pub struct FieldRefIter<'a> {
    tree: &'a Document,
    next: u16,
    end: u16,
}

impl<'a> FieldRefIter<'a> {
    #[inline]
    fn new(tree: &'a Document) -> Self {
        debug_assert!(tree.fields.len() <= super::MAX_FIELDS);
        let end = tree.fields.len() as u16;
        Self { tree, next: 0, end }
    }
}

impl<'a> Iterator for FieldRefIter<'a> {
    type Item = FieldRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < self.end {
            let idx = self.next;
            self.next += 1;

            // SAFETY: `idx < end == tree.fields.len() <= MAX_FIELDS`, so `idx` is in the `Ix`
            // valid range and points to a live field slot.
            let ix = unsafe { Ix::new_unchecked(idx) };
            // SAFETY: `ix` comes from a bounds-checked range over `tree.fields`.
            let field = unsafe { self.tree.field_unchecked(ix) };
            if field.removed {
                continue;
            }
            // SAFETY: `ix` comes from a bounds-checked range over `tree.fields`.
            return Some(unsafe { FieldRef::new_unchecked(self.tree, ix) });
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.end - self.next) as usize;
        (0, Some(remaining))
    }
}

impl core::iter::FusedIterator for FieldRefIter<'_> {}

struct PackedVarint32Iter<'a> {
    data: &'a [u8],
    done: bool,
}

impl<'a> PackedVarint32Iter<'a> {
    #[inline]
    const fn new(data: &'a [u8]) -> Self {
        Self { data, done: false }
    }
}

impl<'a> Iterator for PackedVarint32Iter<'a> {
    type Item = Result<u32, TreeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.data.is_empty() {
            self.done = true;
            return None;
        }
        match varint::decode32(self.data) {
            Some((v, n)) => {
                self.data = &self.data[n as usize..];
                Some(Ok(v))
            }
            None => {
                self.done = true;
                Some(Err(TreeError::DecodeError))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        (0, Some(self.data.len()))
    }
}

impl core::iter::FusedIterator for PackedVarint32Iter<'_> {}

struct PackedVarint64Iter<'a> {
    data: &'a [u8],
    done: bool,
}

impl<'a> PackedVarint64Iter<'a> {
    #[inline]
    const fn new(data: &'a [u8]) -> Self {
        Self { data, done: false }
    }
}

impl<'a> Iterator for PackedVarint64Iter<'a> {
    type Item = Result<u64, TreeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.data.is_empty() {
            self.done = true;
            return None;
        }
        match varint::decode64(self.data) {
            Some((v, n)) => {
                self.data = &self.data[n as usize..];
                Some(Ok(v))
            }
            None => {
                self.done = true;
                Some(Err(TreeError::DecodeError))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.done {
            return (0, Some(0));
        }
        (0, Some(self.data.len()))
    }
}

impl core::iter::FusedIterator for PackedVarint64Iter<'_> {}

struct PackedFixed32Iter<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> PackedFixed32Iter<'a> {
    #[inline]
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, end: data.len() }
    }
}

impl<'a> Iterator for PackedFixed32Iter<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.end {
            return None;
        }
        let chunk = &self.data[self.pos..self.pos + 4];
        let bytes: [u8; 4] = chunk.try_into().expect("exact 4 byte chunk");
        self.pos += 4;
        Some(u32::from_le_bytes(bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.end - self.pos) / 4;
        (remaining, Some(remaining))
    }
}

impl<'a> DoubleEndedIterator for PackedFixed32Iter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.pos == self.end {
            return None;
        }
        self.end -= 4;
        let chunk = &self.data[self.end..self.end + 4];
        let bytes: [u8; 4] = chunk.try_into().expect("exact 4 byte chunk");
        Some(u32::from_le_bytes(bytes))
    }
}

impl<'a> ExactSizeIterator for PackedFixed32Iter<'a> {
    fn len(&self) -> usize {
        (self.end - self.pos) / 4
    }
}

impl core::iter::FusedIterator for PackedFixed32Iter<'_> {}

struct PackedFixed64Iter<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> PackedFixed64Iter<'a> {
    #[inline]
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0, end: data.len() }
    }
}

impl<'a> Iterator for PackedFixed64Iter<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.end {
            return None;
        }
        let chunk = &self.data[self.pos..self.pos + 8];
        let bytes: [u8; 8] = chunk.try_into().expect("exact 8 byte chunk");
        self.pos += 8;
        Some(u64::from_le_bytes(bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.end - self.pos) / 8;
        (remaining, Some(remaining))
    }
}

impl<'a> DoubleEndedIterator for PackedFixed64Iter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.pos == self.end {
            return None;
        }
        self.end -= 8;
        let chunk = &self.data[self.end..self.end + 8];
        let bytes: [u8; 8] = chunk.try_into().expect("exact 8 byte chunk");
        Some(u64::from_le_bytes(bytes))
    }
}

impl<'a> ExactSizeIterator for PackedFixed64Iter<'a> {
    fn len(&self) -> usize {
        (self.end - self.pos) / 8
    }
}

impl core::iter::FusedIterator for PackedFixed64Iter<'_> {}

impl<'a> FieldRef<'a> {
    #[inline]
    pub(super) const unsafe fn new_unchecked(tree: &'a Document, ix: Ix) -> Self {
        Self { tree, ix }
    }

    #[inline]
    pub const fn ix(self) -> Ix {
        self.ix
    }

    #[inline]
    fn field(self) -> &'a Field {
        // SAFETY: FieldRef guarantees `ix` is in-bounds for `tree.fields`.
        unsafe { self.tree.field_unchecked(self.ix) }
    }

    #[inline]
    fn slot(self) -> Ix {
        self.field().index
    }

    #[inline]
    pub fn tag(self) -> Tag {
        self.field().tag
    }

    #[inline]
    pub fn field_number(self) -> FieldNumber {
        self.tag().field_number()
    }

    #[inline]
    pub fn wire_type(self) -> WireType {
        self.tag().wire_type()
    }

    #[inline]
    pub fn removed(self) -> bool {
        self.field().removed
    }

    #[inline]
    pub fn as_uint64(self) -> Option<u64> {
        if self.wire_type() != WireType::Varint {
            return None;
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee varints slot is valid.
        Some(unsafe { self.tree.varint_unchecked(slot).value })
    }

    #[inline]
    pub fn as_uint32(self) -> Option<u32> {
        self.as_uint64().map(|v| v as u32)
    }

    #[inline]
    pub fn as_int64(self) -> Option<i64> {
        self.as_uint64().map(|v| v as i64)
    }

    #[inline]
    pub fn as_int32(self) -> Option<i32> {
        self.as_uint32().map(|v| v as i32)
    }

    #[inline]
    pub fn as_sint32(self) -> Option<i32> {
        self.as_uint32().map(varint::zigzag_decode32)
    }

    #[inline]
    pub fn as_sint64(self) -> Option<i64> {
        self.as_uint64().map(varint::zigzag_decode64)
    }

    #[inline]
    pub fn as_bool(self) -> Option<bool> {
        self.as_uint64().map(|v| v != 0)
    }

    #[inline]
    pub fn as_fixed32(self) -> Option<u32> {
        if self.wire_type() != WireType::I32 {
            return None;
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee fixed32 slot is valid.
        Some(unsafe { self.tree.fixed32_unchecked(slot).value })
    }

    #[inline]
    pub fn as_fixed64(self) -> Option<u64> {
        if self.wire_type() != WireType::I64 {
            return None;
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee fixed64 slot is valid.
        Some(unsafe { self.tree.fixed64_unchecked(slot).value })
    }

    #[inline]
    pub fn as_float(self) -> Option<f32> {
        self.as_fixed32().map(f32::from_bits)
    }

    #[inline]
    pub fn as_double(self) -> Option<f64> {
        self.as_fixed64().map(f64::from_bits)
    }

    #[inline]
    pub fn as_sfixed32(self) -> Option<i32> {
        self.as_fixed32().map(|v| v as i32)
    }

    #[inline]
    pub fn as_sfixed64(self) -> Option<i64> {
        self.as_fixed64().map(|v| v as i64)
    }

    #[inline]
    pub fn as_bytes(self) -> Option<&'a [u8]> {
        if self.wire_type() != WireType::Len {
            return None;
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee length-delimited slot is valid.
        Some(unsafe { self.tree.lendel_unchecked(slot).buf.as_slice() })
    }

    #[inline]
    #[cfg(feature = "group")]
    pub fn as_group_bytes(self) -> Option<&'a [u8]> {
        if self.wire_type() != WireType::SGroup {
            return None;
        }
        let slot = self.slot();
        // SAFETY: group feature + field invariants guarantee groups slot is valid.
        Some(unsafe { self.tree.group_unchecked(slot).buf.as_slice() })
    }

    pub fn as_message(self) -> Result<BorrowedDocument<'a>, TreeError> {
        self.as_message_opt_capacities(None)
    }

    pub fn as_message_with_capacities(
        self,
        capacities: Capacities,
    ) -> Result<BorrowedDocument<'a>, TreeError> {
        self.as_message_opt_capacities(Some(capacities))
    }

    fn as_message_opt_capacities(
        self,
        capacities: Option<Capacities>,
    ) -> Result<BorrowedDocument<'a>, TreeError> {
        match self.wire_type() {
            WireType::Len => BorrowedDocument::from_bytes_opt_capacities(
                self.as_bytes().expect("wire_type check guarantees bytes payload"),
                capacities,
            ),
            #[cfg(feature = "group")]
            WireType::SGroup => BorrowedDocument::from_bytes_opt_capacities(
                self.as_group_bytes().expect("wire_type check guarantees group payload"),
                capacities,
            ),
            _ => Err(TreeError::WireTypeMismatch),
        }
    }

    #[inline]
    fn packed_payload(self) -> Result<&'a [u8], TreeError> {
        self.as_bytes().ok_or(TreeError::WireTypeMismatch)
    }

    pub fn packed_uint32(
        self,
    ) -> Result<impl core::iter::FusedIterator<Item = Result<u32, TreeError>> + 'a, TreeError> {
        Ok(PackedVarint32Iter::new(self.packed_payload()?))
    }

    pub fn packed_uint64(
        self,
    ) -> Result<impl core::iter::FusedIterator<Item = Result<u64, TreeError>> + 'a, TreeError> {
        Ok(PackedVarint64Iter::new(self.packed_payload()?))
    }

    pub fn packed_int32(
        self,
    ) -> Result<impl core::iter::FusedIterator<Item = Result<i32, TreeError>> + 'a, TreeError> {
        Ok(self.packed_uint32()?.map(|r| r.map(|v| v as i32)))
    }

    pub fn packed_int64(
        self,
    ) -> Result<impl core::iter::FusedIterator<Item = Result<i64, TreeError>> + 'a, TreeError> {
        Ok(self.packed_uint64()?.map(|r| r.map(|v| v as i64)))
    }

    pub fn packed_sint32(
        self,
    ) -> Result<impl core::iter::FusedIterator<Item = Result<i32, TreeError>> + 'a, TreeError> {
        Ok(self.packed_uint32()?.map(|r| r.map(varint::zigzag_decode32)))
    }

    pub fn packed_sint64(
        self,
    ) -> Result<impl core::iter::FusedIterator<Item = Result<i64, TreeError>> + 'a, TreeError> {
        Ok(self.packed_uint64()?.map(|r| r.map(varint::zigzag_decode64)))
    }

    pub fn packed_bool(
        self,
    ) -> Result<impl core::iter::FusedIterator<Item = Result<bool, TreeError>> + 'a, TreeError>
    {
        Ok(self.packed_uint32()?.map(|r| r.map(|v| v != 0)))
    }

    pub fn packed_fixed32(
        self,
    ) -> Result<
        impl DoubleEndedIterator<Item = u32> + ExactSizeIterator + core::iter::FusedIterator + 'a,
        TreeError,
    > {
        let data = self.packed_payload()?;
        if data.len() % 4 != 0 {
            return Err(TreeError::DecodeError);
        }
        Ok(PackedFixed32Iter::new(data))
    }

    pub fn packed_fixed64(
        self,
    ) -> Result<
        impl DoubleEndedIterator<Item = u64> + ExactSizeIterator + core::iter::FusedIterator + 'a,
        TreeError,
    > {
        let data = self.packed_payload()?;
        if data.len() % 8 != 0 {
            return Err(TreeError::DecodeError);
        }
        Ok(PackedFixed64Iter::new(data))
    }

    pub fn packed_sfixed32(
        self,
    ) -> Result<
        impl DoubleEndedIterator<Item = i32> + ExactSizeIterator + core::iter::FusedIterator + 'a,
        TreeError,
    > {
        Ok(self.packed_fixed32()?.map(|v| v as i32))
    }

    pub fn packed_sfixed64(
        self,
    ) -> Result<
        impl DoubleEndedIterator<Item = i64> + ExactSizeIterator + core::iter::FusedIterator + 'a,
        TreeError,
    > {
        Ok(self.packed_fixed64()?.map(|v| v as i64))
    }

    pub fn packed_float(
        self,
    ) -> Result<
        impl DoubleEndedIterator<Item = f32> + ExactSizeIterator + core::iter::FusedIterator + 'a,
        TreeError,
    > {
        Ok(self.packed_fixed32()?.map(f32::from_bits))
    }

    pub fn packed_double(
        self,
    ) -> Result<
        impl DoubleEndedIterator<Item = f64> + ExactSizeIterator + core::iter::FusedIterator + 'a,
        TreeError,
    > {
        Ok(self.packed_fixed64()?.map(f64::from_bits))
    }
}

impl Document {
    #[inline]
    pub fn field_refs(&self) -> FieldRefIter<'_> {
        FieldRefIter::new(self)
    }

    #[inline]
    pub fn field_ref(&self, ix: Ix) -> Option<FieldRef<'_>> {
        let idx = ix.as_inner() as usize;
        if idx >= self.fields.len() {
            return None;
        }
        // SAFETY: bounds checked above.
        Some(unsafe { FieldRef::new_unchecked(self, ix) })
    }

    #[inline]
    pub fn first_ref(&self, tag: Tag) -> Option<FieldRef<'_>> {
        self.field_ref(self.first_live_ix(tag)?)
    }

    #[inline]
    pub fn first_ref_by_parts(
        &self,
        field_number: u32,
        wire_type: WireType,
    ) -> Option<FieldRef<'_>> {
        let tag = Tag::try_from_parts(field_number, wire_type)?;
        self.first_ref(tag)
    }

    #[inline]
    pub fn last_ref(&self, tag: Tag) -> Option<FieldRef<'_>> {
        self.field_ref(self.last_live_ix(tag)?)
    }

    #[inline]
    pub fn last_ref_by_parts(
        &self,
        field_number: u32,
        wire_type: WireType,
    ) -> Option<FieldRef<'_>> {
        let tag = Tag::try_from_parts(field_number, wire_type)?;
        self.last_ref(tag)
    }
}
