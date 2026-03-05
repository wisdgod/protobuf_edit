//! Arena-backed protobuf message document with stable insertion order and tag-based lookup.
//!
//! Core properties:
//! - fields are stored in insertion order
//! - repeated fields are linked by per-tag head/tail buckets
//! - scalar payload pools are split by wire type for compact storage
//!
//! Typical usage:
//! ```text
//! let mut doc = Document::new();
//! doc.push_varint(field_number, 42)?;
//! doc.push_length_delimited(field_number2, payload)?;
//! let bytes = doc.to_buf()?;
//! let decoded = Document::from_bytes(bytes.as_slice())?;
//! let borrowed = BorrowedDocument::from_bytes(bytes.as_slice())?;
//! ```

use core::intrinsics::unlikely;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::buf::Buf;
use crate::error::TreeError;
use crate::fx::FxHashMap;
use crate::wire::{FieldNumber, Tag, WireType};

mod codec;
mod field_mut;
mod field_ref;
mod helpers;
mod planned;
mod repeated;
mod types;

pub use field_mut::FieldMut;
pub use field_ref::FieldRef;
pub use repeated::RepeatedRefIter;
pub(crate) use types::{RawVarint32, RawVarint64};
pub use types::{
    Bucket, Capacities, Field, Fixed32, Fixed64, Ix, LengthDelimited, Link, MAX_FIELDS, Document,
    Varint,
};
#[cfg(feature = "group")]
pub use types::Group;

use self::helpers::checked_push_plan;

/// Lifetime-bound wrapper for borrowed decode mode.
///
/// This keeps borrowed payload buffers tied to the source byte slice lifetime.
/// Most access APIs are inherited through `Deref<Target = Document>`.
pub struct BorrowedDocument<'a> {
    doc: Document,
    _borrowed: PhantomData<&'a [u8]>,
}

impl<'a> BorrowedDocument<'a> {
    #[inline]
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, TreeError> {
        Self::from_bytes_opt_capacities(data, None)
    }

    #[inline]
    pub fn from_bytes_with_capacities(
        data: &'a [u8],
        capacities: Capacities,
    ) -> Result<Self, TreeError> {
        Self::from_bytes_opt_capacities(data, Some(capacities))
    }

    #[inline]
    fn from_bytes_opt_capacities(
        data: &'a [u8],
        capacities: Option<Capacities>,
    ) -> Result<Self, TreeError> {
        let doc = Document::from_bytes_borrowed(data, capacities)?;
        Ok(Self { doc, _borrowed: PhantomData })
    }

    #[inline]
    pub fn into_owned(mut self) -> Document {
        self.doc.make_payloads_owned();
        self.doc
    }
}

impl Deref for BorrowedDocument<'_> {
    type Target = Document;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.doc
    }
}

impl DerefMut for BorrowedDocument<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.doc
    }
}

impl Default for Document {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Document {
    #[inline]
    pub fn new() -> Self {
        Self {
            varints: alloc::vec::Vec::new(),
            fixed32s: alloc::vec::Vec::new(),
            fixed64s: alloc::vec::Vec::new(),
            lendels: alloc::vec::Vec::new(),
            #[cfg(feature = "group")]
            groups: alloc::vec::Vec::new(),
            fields: alloc::vec::Vec::new(),
            query: FxHashMap::default(),
        }
    }

    #[inline]
    pub fn with_capacities(capacities: Capacities) -> Self {
        let mut doc = Self::new();
        doc.reserve_capacities(capacities);
        doc
    }

    #[inline]
    pub fn reserve_capacities(&mut self, capacities: Capacities) {
        // Treat capacities as target totals, not "additional".
        self.fields.reserve(capacities.fields.saturating_sub(self.fields.len()));
        self.varints.reserve(capacities.varints.saturating_sub(self.varints.len()));
        self.fixed32s.reserve(capacities.fixed32s.saturating_sub(self.fixed32s.len()));
        self.fixed64s.reserve(capacities.fixed64s.saturating_sub(self.fixed64s.len()));
        self.lendels.reserve(capacities.lendels.saturating_sub(self.lendels.len()));
        #[cfg(feature = "group")]
        self.groups.reserve(capacities.groups.saturating_sub(self.groups.len()));
        self.query.reserve(capacities.query.saturating_sub(self.query.len()));
    }

    #[inline]
    pub(super) fn make_payloads_owned(&mut self) {
        for lendel in &mut self.lendels {
            lendel.buf.make_owned();
        }
        #[cfg(feature = "group")]
        for group in &mut self.groups {
            group.buf.make_owned();
        }
    }

    // Safety contract for unchecked accessors:
    // - `ix`/`slot` must point to a live element in the corresponding storage vector.
    // - `Field.index` must always refer to the pool matching `Field.tag.wire_type()`.
    // - Linked-list pointers in `fields[*].prev/next` must stay coherent with `query`.
    // - Borrowed payload buffers must not outlive the source bytes.
    // Breaking any item above may cause immediate UB in unchecked access paths.
    #[inline(always)]
    pub(super) unsafe fn field_unchecked(&self, ix: Ix) -> &Field {
        self.fields.get_unchecked(ix.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn field_unchecked_mut(&mut self, ix: Ix) -> &mut Field {
        self.fields.get_unchecked_mut(ix.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn varint_unchecked(&self, slot: Ix) -> &Varint {
        self.varints.get_unchecked(slot.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn varint_unchecked_mut(&mut self, slot: Ix) -> &mut Varint {
        self.varints.get_unchecked_mut(slot.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn fixed32_unchecked(&self, slot: Ix) -> &Fixed32 {
        self.fixed32s.get_unchecked(slot.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn fixed32_unchecked_mut(&mut self, slot: Ix) -> &mut Fixed32 {
        self.fixed32s.get_unchecked_mut(slot.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn fixed64_unchecked(&self, slot: Ix) -> &Fixed64 {
        self.fixed64s.get_unchecked(slot.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn fixed64_unchecked_mut(&mut self, slot: Ix) -> &mut Fixed64 {
        self.fixed64s.get_unchecked_mut(slot.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn lendel_unchecked(&self, slot: Ix) -> &LengthDelimited {
        self.lendels.get_unchecked(slot.as_inner() as usize)
    }

    #[inline(always)]
    pub(super) unsafe fn lendel_unchecked_mut(&mut self, slot: Ix) -> &mut LengthDelimited {
        self.lendels.get_unchecked_mut(slot.as_inner() as usize)
    }

    #[cfg(feature = "group")]
    #[inline(always)]
    pub(super) unsafe fn group_unchecked(&self, slot: Ix) -> &Group {
        self.groups.get_unchecked(slot.as_inner() as usize)
    }

    #[cfg(feature = "group")]
    #[inline(always)]
    pub(super) unsafe fn group_unchecked_mut(&mut self, slot: Ix) -> &mut Group {
        self.groups.get_unchecked_mut(slot.as_inner() as usize)
    }

    #[inline]
    pub fn bucket(&self, tag: Tag) -> Option<&Bucket> {
        self.query.get(&tag)
    }

    #[inline]
    pub fn bucket_by_parts(&self, field_number: u32, wire_type: WireType) -> Option<&Bucket> {
        let tag = Tag::try_from_parts(field_number, wire_type)?;
        self.bucket(tag)
    }

    #[inline]
    pub fn field_head(&self, tag: Tag) -> Option<Ix> {
        self.bucket(tag).and_then(|bucket| bucket.head)
    }

    #[inline]
    pub fn field_tail(&self, tag: Tag) -> Option<Ix> {
        self.bucket(tag).and_then(|bucket| bucket.tail)
    }

    #[inline]
    pub const fn make_tag(field_number: FieldNumber, wire_type: WireType) -> Tag {
        Tag::from_parts(field_number, wire_type)
    }

    #[inline]
    pub const fn make_tag_u32(field_number: u32, wire_type: WireType) -> Option<Tag> {
        Tag::try_from_parts(field_number, wire_type)
    }

    pub fn push_varint(&mut self, field_number: FieldNumber, value: u64) -> Result<Ix, TreeError> {
        self.push_varint_with_raw(field_number, value, RawVarint64::from_u64(value))
    }

    pub(super) fn push_varint_with_raw(
        &mut self,
        field_number: FieldNumber,
        value: u64,
        raw: RawVarint64,
    ) -> Result<Ix, TreeError> {
        if raw.is_empty() {
            return Err(TreeError::DecodeError);
        }
        let (tag, slot, field_ix) = checked_push_plan(
            field_number,
            WireType::Varint,
            self.varints.len(),
            self.fields.len(),
        )?;
        self.varints.push(Varint { value, raw });
        self.push_field_with_ix(tag, slot, field_ix);
        Ok(field_ix)
    }

    pub fn push_varint_u32(&mut self, field_number: u32, value: u64) -> Result<Ix, TreeError> {
        let field_number = FieldNumber::new(field_number).ok_or(TreeError::InvalidTag)?;
        self.push_varint(field_number, value)
    }

    pub fn push_fixed32(&mut self, field_number: FieldNumber, value: u32) -> Result<Ix, TreeError> {
        let (tag, slot, field_ix) =
            checked_push_plan(field_number, WireType::I32, self.fixed32s.len(), self.fields.len())?;
        self.fixed32s.push(Fixed32 { value });
        self.push_field_with_ix(tag, slot, field_ix);
        Ok(field_ix)
    }

    pub fn push_fixed32_u32(&mut self, field_number: u32, value: u32) -> Result<Ix, TreeError> {
        let field_number = FieldNumber::new(field_number).ok_or(TreeError::InvalidTag)?;
        self.push_fixed32(field_number, value)
    }

    pub fn push_fixed64(&mut self, field_number: FieldNumber, value: u64) -> Result<Ix, TreeError> {
        let (tag, slot, field_ix) =
            checked_push_plan(field_number, WireType::I64, self.fixed64s.len(), self.fields.len())?;
        self.fixed64s.push(Fixed64 { value });
        self.push_field_with_ix(tag, slot, field_ix);
        Ok(field_ix)
    }

    pub fn push_fixed64_u32(&mut self, field_number: u32, value: u64) -> Result<Ix, TreeError> {
        let field_number = FieldNumber::new(field_number).ok_or(TreeError::InvalidTag)?;
        self.push_fixed64(field_number, value)
    }

    pub fn push_length_delimited(
        &mut self,
        field_number: FieldNumber,
        buf: Buf,
    ) -> Result<Ix, TreeError> {
        let raw = RawVarint32::from_u32(buf.len());
        self.push_length_delimited_with_raw(field_number, buf, raw)
    }

    pub(super) fn push_length_delimited_with_raw(
        &mut self,
        field_number: FieldNumber,
        buf: Buf,
        raw: RawVarint32,
    ) -> Result<Ix, TreeError> {
        if raw.is_empty() {
            return Err(TreeError::DecodeError);
        }
        let (tag, slot, field_ix) =
            checked_push_plan(field_number, WireType::Len, self.lendels.len(), self.fields.len())?;
        self.lendels.push(LengthDelimited { buf, raw });
        self.push_field_with_ix(tag, slot, field_ix);
        Ok(field_ix)
    }

    pub fn push_length_delimited_u32(
        &mut self,
        field_number: u32,
        buf: Buf,
    ) -> Result<Ix, TreeError> {
        let field_number = FieldNumber::new(field_number).ok_or(TreeError::InvalidTag)?;
        self.push_length_delimited(field_number, buf)
    }

    #[cfg(feature = "group")]
    pub fn push_group(&mut self, field_number: FieldNumber, buf: Buf) -> Result<Ix, TreeError> {
        let (tag, slot, field_ix) = checked_push_plan(
            field_number,
            WireType::SGroup,
            self.groups.len(),
            self.fields.len(),
        )?;
        self.groups.push(Group { buf });
        self.push_field_with_ix(tag, slot, field_ix);
        Ok(field_ix)
    }

    #[cfg(feature = "group")]
    pub fn push_group_u32(&mut self, field_number: u32, buf: Buf) -> Result<Ix, TreeError> {
        let field_number = FieldNumber::new(field_number).ok_or(TreeError::InvalidTag)?;
        self.push_group(field_number, buf)
    }

    #[inline]
    pub fn mark_removed(&mut self, ix: Ix) {
        self.fields[ix.as_inner() as usize].removed = true;
    }

    pub(super) fn first_live_ix(&self, tag: Tag) -> Option<Ix> {
        let mut cursor = self.field_head(tag)?;
        loop {
            let field = &self.fields[cursor.as_inner() as usize];
            if !field.removed {
                return Some(cursor);
            }
            cursor = field.next?;
        }
    }

    pub(super) fn last_live_ix(&self, tag: Tag) -> Option<Ix> {
        let mut cursor = self.field_tail(tag)?;
        loop {
            let field = &self.fields[cursor.as_inner() as usize];
            if !field.removed {
                return Some(cursor);
            }
            cursor = field.prev?;
        }
    }

    pub(super) fn push_field_with_ix(&mut self, tag: Tag, slot: Ix, field_ix: Ix) {
        let expect_len = field_ix.as_inner() as usize;
        if unlikely(self.fields.len() != expect_len) {
            panic!("field index pre-check violated: {} != {}", self.fields.len(), expect_len);
        }

        let mut field = Field {
            tag,
            index: slot,
            removed: false,
            prev: None,
            next: None,
            raw: RawVarint32::from_u32(tag.get()),
        };

        let (fields, query) = (&mut self.fields, &mut self.query);
        let bucket = query.entry(tag).or_insert(Bucket::empty());
        if let Some(tail_ix) = bucket.tail {
            // SAFETY: tail_ix comes from the bucket linked-list we maintain.
            unsafe { fields.get_unchecked_mut(tail_ix.as_inner() as usize).next = Some(field_ix) };
            field.prev = bucket.tail;
        } else {
            bucket.head = Some(field_ix);
        }
        bucket.tail = Some(field_ix);

        fields.push(field);
    }
}

#[cfg(test)]
mod tests;
