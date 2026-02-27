use crate::data_structures::Buf;
use crate::varint;
use crate::wire::{Tag, WireType};

use super::{
    BorrowedDocument, Capacities, Field, FieldRef, Ix, Document, RawVarint32, RawVarint64,
    TreeError,
};

/// Mutable view of one field in a `Document`.
pub struct FieldMut<'a> {
    tree: &'a mut Document,
    ix: Ix,
}

impl<'a> FieldMut<'a> {
    #[inline]
    pub(super) const unsafe fn new_unchecked(tree: &'a mut Document, ix: Ix) -> Self {
        Self { tree, ix }
    }

    #[inline]
    pub const fn ix(&self) -> Ix {
        self.ix
    }

    #[inline]
    fn field(&self) -> &Field {
        // SAFETY: FieldMut guarantees `ix` is in-bounds for `tree.fields`.
        unsafe { self.tree.field_unchecked(self.ix) }
    }

    #[inline]
    fn field_mut(&mut self) -> &mut Field {
        // SAFETY: FieldMut guarantees `ix` is in-bounds for `tree.fields`.
        unsafe { self.tree.field_unchecked_mut(self.ix) }
    }

    #[inline]
    fn slot(&self) -> Ix {
        self.field().index
    }

    #[inline]
    pub fn tag(&self) -> Tag {
        self.field().tag
    }

    #[inline]
    pub fn wire_type(&self) -> WireType {
        self.tag().wire_type()
    }

    #[inline]
    pub fn removed(&self) -> bool {
        self.field().removed
    }

    #[inline]
    pub fn as_ref(&self) -> FieldRef<'_> {
        // SAFETY: `FieldMut` guarantees `ix` is valid.
        unsafe { FieldRef::new_unchecked(self.tree, self.ix) }
    }

    #[inline]
    pub fn mark_removed(&mut self) {
        self.field_mut().removed = true;
    }

    pub fn uint64(&mut self, f: impl FnOnce(&mut u64)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee varints slot is valid.
        let varint = unsafe { self.tree.varint_unchecked_mut(slot) };
        f(&mut varint.value);
        varint.raw = RawVarint64::from_u64(varint.value);
        Ok(())
    }

    pub fn uint32(&mut self, f: impl FnOnce(&mut u32)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee varints slot is valid.
        let varint = unsafe { self.tree.varint_unchecked_mut(slot) };
        let mut value = varint.value as u32;
        f(&mut value);
        varint.value = value as u64;
        varint.raw = RawVarint64::from_u64(varint.value);
        Ok(())
    }

    pub fn int32(&mut self, f: impl FnOnce(&mut i32)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee varints slot is valid.
        let varint = unsafe { self.tree.varint_unchecked_mut(slot) };
        let mut value = varint.value as i32;
        f(&mut value);
        varint.value = value as u64;
        varint.raw = RawVarint64::from_u64(varint.value);
        Ok(())
    }

    pub fn int64(&mut self, f: impl FnOnce(&mut i64)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee varints slot is valid.
        let varint = unsafe { self.tree.varint_unchecked_mut(slot) };
        let mut value = varint.value as i64;
        f(&mut value);
        varint.value = value as u64;
        varint.raw = RawVarint64::from_u64(varint.value);
        Ok(())
    }

    pub fn sint32(&mut self, f: impl FnOnce(&mut i32)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee varints slot is valid.
        let varint = unsafe { self.tree.varint_unchecked_mut(slot) };
        let mut value = varint::zigzag_decode32(varint.value as u32);
        f(&mut value);
        varint.value = varint::zigzag_encode32(value) as u64;
        varint.raw = RawVarint64::from_u64(varint.value);
        Ok(())
    }

    pub fn sint64(&mut self, f: impl FnOnce(&mut i64)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee varints slot is valid.
        let varint = unsafe { self.tree.varint_unchecked_mut(slot) };
        let mut value = varint::zigzag_decode64(varint.value);
        f(&mut value);
        varint.value = varint::zigzag_encode64(value);
        varint.raw = RawVarint64::from_u64(varint.value);
        Ok(())
    }

    pub fn bool(&mut self, f: impl FnOnce(&mut bool)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee varints slot is valid.
        let varint = unsafe { self.tree.varint_unchecked_mut(slot) };
        let mut value = varint.value != 0;
        f(&mut value);
        varint.value = value as u64;
        varint.raw = RawVarint64::from_u64(varint.value);
        Ok(())
    }

    pub fn fixed32(&mut self, f: impl FnOnce(&mut u32)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::I32 {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee fixed32 slot is valid.
        f(&mut unsafe { self.tree.fixed32_unchecked_mut(slot) }.value);
        Ok(())
    }

    pub fn sfixed32(&mut self, f: impl FnOnce(&mut i32)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::I32 {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee fixed32 slot is valid.
        let fixed = unsafe { self.tree.fixed32_unchecked_mut(slot) };
        let mut value = fixed.value as i32;
        f(&mut value);
        fixed.value = value as u32;
        Ok(())
    }

    pub fn float(&mut self, f: impl FnOnce(&mut f32)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::I32 {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee fixed32 slot is valid.
        let fixed = unsafe { self.tree.fixed32_unchecked_mut(slot) };
        let mut value = f32::from_bits(fixed.value);
        f(&mut value);
        fixed.value = value.to_bits();
        Ok(())
    }

    pub fn fixed64(&mut self, f: impl FnOnce(&mut u64)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::I64 {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee fixed64 slot is valid.
        f(&mut unsafe { self.tree.fixed64_unchecked_mut(slot) }.value);
        Ok(())
    }

    pub fn sfixed64(&mut self, f: impl FnOnce(&mut i64)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::I64 {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee fixed64 slot is valid.
        let fixed = unsafe { self.tree.fixed64_unchecked_mut(slot) };
        let mut value = fixed.value as i64;
        f(&mut value);
        fixed.value = value as u64;
        Ok(())
    }

    pub fn double(&mut self, f: impl FnOnce(&mut f64)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::I64 {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee fixed64 slot is valid.
        let fixed = unsafe { self.tree.fixed64_unchecked_mut(slot) };
        let mut value = f64::from_bits(fixed.value);
        f(&mut value);
        fixed.value = value.to_bits();
        Ok(())
    }

    pub fn bytes(&mut self, f: impl FnOnce(&mut Buf)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::Len {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee lendels slot is valid.
        let lendel = unsafe { self.tree.lendel_unchecked_mut(slot) };
        f(&mut lendel.buf);
        lendel.raw = RawVarint32::from_u32(lendel.buf.len());
        Ok(())
    }

    #[inline]
    fn packed_buf_mut(&mut self) -> Result<&mut Buf, TreeError> {
        if self.wire_type() != WireType::Len {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: field wire type + slot invariants guarantee lendels slot is valid.
        Ok(&mut unsafe { self.tree.lendel_unchecked_mut(slot) }.buf)
    }

    pub fn push_packed_uint32(&mut self, value: u32) -> Result<(), TreeError> {
        let buf = self.packed_buf_mut()?;
        let _ = varint::encode32(buf, value)?;
        let slot = self.slot();
        // SAFETY: packed_buf_mut wire check guarantees valid lendel slot.
        let lendel = unsafe { self.tree.lendel_unchecked_mut(slot) };
        lendel.raw = RawVarint32::from_u32(lendel.buf.len());
        Ok(())
    }

    pub fn push_packed_uint64(&mut self, value: u64) -> Result<(), TreeError> {
        let buf = self.packed_buf_mut()?;
        let _ = varint::encode64(buf, value)?;
        let slot = self.slot();
        // SAFETY: packed_buf_mut wire check guarantees valid lendel slot.
        let lendel = unsafe { self.tree.lendel_unchecked_mut(slot) };
        lendel.raw = RawVarint32::from_u32(lendel.buf.len());
        Ok(())
    }

    pub fn push_packed_int32(&mut self, value: i32) -> Result<(), TreeError> {
        self.push_packed_uint32(value as u32)
    }

    pub fn push_packed_int64(&mut self, value: i64) -> Result<(), TreeError> {
        self.push_packed_uint64(value as u64)
    }

    pub fn push_packed_sint32(&mut self, value: i32) -> Result<(), TreeError> {
        self.push_packed_uint32(varint::zigzag_encode32(value))
    }

    pub fn push_packed_sint64(&mut self, value: i64) -> Result<(), TreeError> {
        self.push_packed_uint64(varint::zigzag_encode64(value))
    }

    pub fn push_packed_bool(&mut self, value: bool) -> Result<(), TreeError> {
        self.push_packed_uint32(value as u32)
    }

    pub fn push_packed_fixed32(&mut self, value: u32) -> Result<(), TreeError> {
        let buf = self.packed_buf_mut()?;
        buf.extend_from_slice(&value.to_le_bytes())?;
        let slot = self.slot();
        // SAFETY: packed_buf_mut wire check guarantees valid lendel slot.
        let lendel = unsafe { self.tree.lendel_unchecked_mut(slot) };
        lendel.raw = RawVarint32::from_u32(lendel.buf.len());
        Ok(())
    }

    pub fn push_packed_fixed64(&mut self, value: u64) -> Result<(), TreeError> {
        let buf = self.packed_buf_mut()?;
        buf.extend_from_slice(&value.to_le_bytes())?;
        let slot = self.slot();
        // SAFETY: packed_buf_mut wire check guarantees valid lendel slot.
        let lendel = unsafe { self.tree.lendel_unchecked_mut(slot) };
        lendel.raw = RawVarint32::from_u32(lendel.buf.len());
        Ok(())
    }

    pub fn push_packed_sfixed32(&mut self, value: i32) -> Result<(), TreeError> {
        self.push_packed_fixed32(value as u32)
    }

    pub fn push_packed_sfixed64(&mut self, value: i64) -> Result<(), TreeError> {
        self.push_packed_fixed64(value as u64)
    }

    pub fn push_packed_float(&mut self, value: f32) -> Result<(), TreeError> {
        self.push_packed_fixed32(value.to_bits())
    }

    pub fn push_packed_double(&mut self, value: f64) -> Result<(), TreeError> {
        self.push_packed_fixed64(value.to_bits())
    }

    #[cfg(feature = "group")]
    pub fn group_bytes(&mut self, f: impl FnOnce(&mut Buf)) -> Result<(), TreeError> {
        if self.wire_type() != WireType::SGroup {
            return Err(TreeError::WireTypeMismatch);
        }
        let slot = self.slot();
        // SAFETY: group feature + field invariants guarantee groups slot is valid.
        f(&mut unsafe { self.tree.group_unchecked_mut(slot) }.buf);
        Ok(())
    }

    pub(super) fn replace_nested_payload(&mut self, payload: Buf) -> Result<(), TreeError> {
        match self.wire_type() {
            WireType::Len => {
                let slot = self.slot();
                // SAFETY: field invariants guarantee lendels slot is valid.
                let lendel = unsafe { self.tree.lendel_unchecked_mut(slot) };
                lendel.buf = payload;
                lendel.raw = RawVarint32::from_u32(lendel.buf.len());
                Ok(())
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let slot = self.slot();
                // SAFETY: group feature + field invariants guarantee groups slot is valid.
                unsafe { self.tree.group_unchecked_mut(slot) }.buf = payload;
                Ok(())
            }
            _ => Err(TreeError::WireTypeMismatch),
        }
    }

    pub fn message(
        &mut self,
        f: impl FnOnce(&mut Document) -> Result<(), TreeError>,
    ) -> Result<(), TreeError> {
        self.message_opt_capacities(None, f)
    }

    pub fn message_with_capacities(
        &mut self,
        capacities: Capacities,
        f: impl FnOnce(&mut Document) -> Result<(), TreeError>,
    ) -> Result<(), TreeError> {
        self.message_opt_capacities(Some(capacities), f)
    }

    fn message_opt_capacities(
        &mut self,
        capacities: Option<Capacities>,
        f: impl FnOnce(&mut Document) -> Result<(), TreeError>,
    ) -> Result<(), TreeError> {
        match self.wire_type() {
            WireType::Len => {
                let slot = self.slot();
                // SAFETY: field invariants guarantee lendels slot is valid for Len fields.
                let bytes = unsafe { self.tree.lendel_unchecked(slot).buf.as_slice() };
                let mut nested = BorrowedDocument::from_bytes_opt_capacities(bytes, capacities)?;
                f(&mut nested)?;
                self.replace_nested_payload(nested.to_buf()?)
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let slot = self.slot();
                // SAFETY: group feature + field invariants guarantee groups slot is valid.
                let bytes = unsafe { self.tree.group_unchecked(slot).buf.as_slice() };
                let mut nested = BorrowedDocument::from_bytes_opt_capacities(bytes, capacities)?;
                f(&mut nested)?;
                self.replace_nested_payload(nested.to_buf()?)
            }
            _ => Err(TreeError::WireTypeMismatch),
        }
    }
}

impl Document {
    #[inline]
    pub fn field_mut(&mut self, ix: Ix) -> Option<FieldMut<'_>> {
        let idx = ix.as_inner() as usize;
        if idx >= self.fields.len() {
            return None;
        }
        // SAFETY: bounds checked above.
        Some(unsafe { FieldMut::new_unchecked(self, ix) })
    }

    #[inline]
    pub fn first_mut(&mut self, tag: Tag) -> Option<FieldMut<'_>> {
        let ix = self.first_live_ix(tag)?;
        self.field_mut(ix)
    }

    #[inline]
    pub fn first_mut_by_parts(
        &mut self,
        field_number: u32,
        wire_type: WireType,
    ) -> Option<FieldMut<'_>> {
        let tag = Tag::try_from_parts(field_number, wire_type)?;
        self.first_mut(tag)
    }

    #[inline]
    pub fn last_mut(&mut self, tag: Tag) -> Option<FieldMut<'_>> {
        let ix = self.last_live_ix(tag)?;
        self.field_mut(ix)
    }

    #[inline]
    pub fn last_mut_by_parts(
        &mut self,
        field_number: u32,
        wire_type: WireType,
    ) -> Option<FieldMut<'_>> {
        let tag = Tag::try_from_parts(field_number, wire_type)?;
        self.last_mut(tag)
    }
}
