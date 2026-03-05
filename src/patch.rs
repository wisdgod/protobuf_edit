//! Span-based protobuf message patcher with lazy payload edits.
//!
//! This module builds a wire-level view of a protobuf message by eagerly scanning
//! fields and recording byte spans into the original input. Payload edits are
//! tracked separately and only materialized when saving, allowing unchanged
//! fields to be copied verbatim from the source bytes.

use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::document::{RawVarint32, RawVarint64};
use crate::fx::FxHashMap;
use crate::{Buf, Tag, TreeError, WireType};

mod parse;
mod query;
mod save;
mod txn;

pub use query::FieldsByTag;
pub use txn::Txn;

define_valid_range_type!(
    /// Unique field identifier inside a `Patch`.
    ///
    /// `u32::MAX` is reserved as `Option<FieldId>::None`.
    pub struct FieldId(u32 as u32 in 0..=4294967294);
);

define_valid_range_type!(
    /// Unique message identifier inside a `Patch`.
    ///
    /// `u32::MAX` is reserved as `Option<MessageId>::None`.
    pub struct MessageId(u32 as u32 in 0..=4294967294);
);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
/// Half-open byte range inside a message source buffer.
pub struct Span {
    start: u32,
    end: u32,
}

impl Span {
    #[inline]
    pub const fn new(start: u32, end: u32) -> Option<Self> {
        if start <= end { Some(Self { start, end }) } else { None }
    }

    #[inline]
    pub const fn start(self) -> u32 {
        self.start
    }

    #[inline]
    pub const fn end(self) -> u32 {
        self.end
    }

    #[inline]
    pub const fn len(self) -> u32 {
        self.end - self.start
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Span").field(&self.start).field(&self.end).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Component spans of one wire field.
pub struct FieldSpans {
    pub field: Span,
    pub tag: Span,
    pub value: ValueSpans,
}

impl FieldSpans {
    #[inline]
    pub const fn payload(self) -> Span {
        match self.value {
            ValueSpans::Varint { value }
            | ValueSpans::I32 { value }
            | ValueSpans::I64 { value } => value,
            ValueSpans::Len { payload, .. } => payload,
            #[cfg(feature = "group")]
            ValueSpans::Group { body, .. } => body,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Value-specific spans within a field.
pub enum ValueSpans {
    Varint {
        value: Span,
    },
    I32 {
        value: Span,
    },
    I64 {
        value: Span,
    },
    Len {
        len: Span,
        payload: Span,
    },
    #[cfg(feature = "group")]
    Group {
        body: Span,
        end_tag: Span,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StoredSpans {
    field: Span,
    tag_len: u8,
    aux_len: u8,
    payload_len: u32,
}

impl StoredSpans {
    #[inline]
    fn tag_span(self) -> Result<Span, TreeError> {
        let start = self.field.start();
        let end = start.checked_add(self.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
        Span::new(start, end).ok_or(TreeError::DecodeError)
    }

    #[inline]
    fn expand(self, wire: WireType) -> Result<FieldSpans, TreeError> {
        Ok(FieldSpans { field: self.field, tag: self.tag_span()?, value: self.value_spans(wire)? })
    }

    #[inline]
    fn value_spans(self, wire: WireType) -> Result<ValueSpans, TreeError> {
        match wire {
            WireType::Varint => {
                let start = self.field.start();
                let value_start =
                    start.checked_add(self.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
                let value =
                    Span::new(value_start, self.field.end()).ok_or(TreeError::DecodeError)?;
                Ok(ValueSpans::Varint { value })
            }
            WireType::I32 => {
                let end = self.field.end();
                let start = end.checked_sub(4).ok_or(TreeError::DecodeError)?;
                let value = Span::new(start, end).ok_or(TreeError::DecodeError)?;
                Ok(ValueSpans::I32 { value })
            }
            WireType::I64 => {
                let end = self.field.end();
                let start = end.checked_sub(8).ok_or(TreeError::DecodeError)?;
                let value = Span::new(start, end).ok_or(TreeError::DecodeError)?;
                Ok(ValueSpans::I64 { value })
            }
            WireType::Len => {
                let start = self.field.start();
                let len_start =
                    start.checked_add(self.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
                let len_end = len_start
                    .checked_add(self.aux_len as u32)
                    .ok_or(TreeError::CapacityExceeded)?;
                let len = Span::new(len_start, len_end).ok_or(TreeError::DecodeError)?;

                let payload_start = len_end;
                let payload_end = payload_start
                    .checked_add(self.payload_len)
                    .ok_or(TreeError::CapacityExceeded)?;
                let payload =
                    Span::new(payload_start, payload_end).ok_or(TreeError::DecodeError)?;
                debug_assert_eq!(payload_end, self.field.end());
                Ok(ValueSpans::Len { len, payload })
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let start = self.field.start();
                let body_start =
                    start.checked_add(self.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
                let body_end = self
                    .field
                    .end()
                    .checked_sub(self.aux_len as u32)
                    .ok_or(TreeError::DecodeError)?;
                let body = Span::new(body_start, body_end).ok_or(TreeError::DecodeError)?;
                let end_tag =
                    Span::new(body_end, self.field.end()).ok_or(TreeError::DecodeError)?;
                Ok(ValueSpans::Group { body, end_tag })
            }
            #[cfg(feature = "group")]
            WireType::EGroup => Err(TreeError::DecodeError),
        }
    }

    #[inline]
    fn payload_span(self, wire: WireType) -> Result<Span, TreeError> {
        match wire {
            WireType::Len => {
                let ValueSpans::Len { payload, .. } = self.value_spans(wire)? else {
                    return Err(TreeError::DecodeError);
                };
                Ok(payload)
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let ValueSpans::Group { body, .. } = self.value_spans(wire)? else {
                    return Err(TreeError::DecodeError);
                };
                Ok(body)
            }
            _ => Err(TreeError::WireTypeMismatch),
        }
    }
}

/// Span-aware message patch rooted at a source buffer.
///
/// `Patch::from_bytes` clones the input bytes into an owned `Buf`. For a
/// lifetime-bound zero-copy view, use `BorrowedPatch`.
pub struct Patch {
    root: MessageId,
    source: Buf,
    messages: Vec<MessageNode>,
    fields: Vec<FieldNode>,
    read_cache: ReadCache,
    txn: Option<TxnState>,
}

#[derive(Clone, Default)]
struct ReadCache {
    enabled: bool,
    varints: Vec<Cell<Option<u64>>>,
}

impl ReadCache {
    fn enable(&mut self, fields_len: usize) -> Result<(), TreeError> {
        if self.enabled {
            return Ok(());
        }
        self.varints.clear();
        self.varints.try_reserve(fields_len).map_err(|_| TreeError::CapacityExceeded)?;
        for _ in 0..fields_len {
            self.varints.push(Cell::new(None));
        }
        self.enabled = true;
        Ok(())
    }

    fn disable(&mut self) {
        self.enabled = false;
        self.varints.clear();
    }

    fn truncate_fields(&mut self, fields_len: usize) {
        if !self.enabled {
            return;
        }
        self.varints.truncate(fields_len);
    }

    fn get_varint(&self, field_idx: usize) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        self.varints.get(field_idx).and_then(|cell| cell.get())
    }

    fn set_varint(&self, field_idx: usize, value: u64) {
        if !self.enabled {
            return;
        }
        if let Some(cell) = self.varints.get(field_idx) {
            cell.set(Some(value));
        } else {
            debug_assert!(false, "read cache field index out of bounds");
        }
    }
}

#[derive(Clone)]
struct MessageNode {
    source: MessageSource,
    parent_field: Option<FieldId>,
    fields_in_order: Vec<FieldId>,
    query: FxHashMap<Tag, TagBucket>,
}

#[derive(Clone, Copy, Default)]
struct TagBucket {
    head: Option<FieldId>,
    tail: Option<FieldId>,
    len: u32,
}

#[derive(Clone)]
enum MessageSource {
    Root { start: u32, end: u32 },
    Owned { bytes: Buf },
}

impl MessageSource {
    fn bytes<'a>(&'a self, root: &'a [u8]) -> &'a [u8] {
        match self {
            MessageSource::Root { start, end } => {
                let start = *start as usize;
                let end = *end as usize;
                &root[start..end]
            }
            MessageSource::Owned { bytes } => bytes.as_slice(),
        }
    }
}

#[derive(Clone)]
struct FieldNode {
    msg: MessageId,
    tag: Tag,
    prev_by_tag: Option<FieldId>,
    next_by_tag: Option<FieldId>,
    raw_tag: RawVarint32,
    spans: Option<StoredSpans>,
    edit: Option<PayloadEdit>,
    child: Option<MessageId>,
    deleted: bool,
}

#[derive(Clone, Copy)]
struct VarintEdit {
    value: u64,
    raw: RawVarint64,
}

impl VarintEdit {
    #[inline]
    fn new(value: u64) -> Self {
        Self { value, raw: RawVarint64::from_u64(value) }
    }
}

#[derive(Clone)]
enum PayloadEdit {
    Varint(VarintEdit),
    I32(u32),
    I64(u64),
    Bytes(Buf),
}

/// Lifetime-bound wrapper for borrowed root source bytes.
///
/// This keeps `Patch` tied to the input slice lifetime while still using the
/// same internal representation.
pub struct BorrowedPatch<'a> {
    patch: Patch,
    _borrowed: PhantomData<&'a [u8]>,
}

impl<'a> BorrowedPatch<'a> {
    #[inline]
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, TreeError> {
        // SAFETY: `BorrowedPatch` ties the borrowed payload lifetime to `'a`.
        let source = unsafe { Buf::from_borrowed_slice(data) };
        Ok(Self { patch: Patch::from_buf(source)?, _borrowed: PhantomData })
    }

    #[inline]
    pub fn into_owned(mut self) -> Patch {
        self.patch.source.make_owned();
        self.patch
    }
}

impl Deref for BorrowedPatch<'_> {
    type Target = Patch;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.patch
    }
}

impl DerefMut for BorrowedPatch<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.patch
    }
}

#[derive(Clone)]
enum UndoAction {
    FieldEdit { field: FieldId, prev: Option<PayloadEdit> },
    FieldDeleted { field: FieldId, prev: bool },
    FieldChild { field: FieldId, prev: Option<MessageId> },
    InsertField { msg: MessageId, field: FieldId },
}

#[derive(Clone)]
struct TxnState {
    orig_messages_len: usize,
    orig_fields_len: usize,
    undo_log: Vec<UndoAction>,
}

impl Patch {
    /// Enables per-field caches for read APIs.
    ///
    /// When enabled, `Patch::varint` memoizes decoded values from the message source bytes.
    pub fn enable_read_cache(&mut self) -> Result<(), TreeError> {
        self.read_cache.enable(self.fields.len())
    }

    /// Disables read caches and drops cached values.
    pub fn disable_read_cache(&mut self) {
        self.read_cache.disable();
    }

    #[inline]
    pub const fn read_cache_enabled(&self) -> bool {
        self.read_cache.enabled
    }

    #[inline]
    pub const fn root(&self) -> MessageId {
        self.root
    }

    #[inline]
    pub fn root_bytes(&self) -> &[u8] {
        self.source.as_slice()
    }

    pub fn message_bytes(&self, msg: MessageId) -> Result<&[u8], TreeError> {
        let msg = self.message(msg)?;
        Ok(msg.source.bytes(self.source.as_slice()))
    }

    /// Returns the absolute byte span of `msg` within the root source buffer.
    ///
    /// Messages backed by owned bytes (inserted/edited payloads) have no stable
    /// location inside the original root source and return `None`.
    pub fn message_root_span(&self, msg: MessageId) -> Result<Option<Span>, TreeError> {
        let msg = self.message(msg)?;
        match &msg.source {
            MessageSource::Root { start, end } => {
                Span::new(*start, *end).ok_or(TreeError::DecodeError).map(Some)
            }
            MessageSource::Owned { .. } => Ok(None),
        }
    }

    /// Maps a message-local `span` to an absolute span in the root source buffer.
    ///
    /// Returns `None` if `msg` is backed by owned bytes instead of the root source.
    pub fn message_span_to_root(
        &self,
        msg: MessageId,
        span: Span,
    ) -> Result<Option<Span>, TreeError> {
        let Some(msg_span) = self.message_root_span(msg)? else {
            return Ok(None);
        };
        if span.end() > msg_span.len() {
            return Err(TreeError::DecodeError);
        }
        let base = msg_span.start();
        let start = base.checked_add(span.start()).ok_or(TreeError::CapacityExceeded)?;
        let end = base.checked_add(span.end()).ok_or(TreeError::CapacityExceeded)?;
        if end > msg_span.end() {
            return Err(TreeError::DecodeError);
        }
        Ok(Span::new(start, end))
    }

    pub fn message_parent_field(&self, msg: MessageId) -> Result<Option<FieldId>, TreeError> {
        Ok(self.message(msg)?.parent_field)
    }

    pub fn message_fields(&self, msg: MessageId) -> Result<&[FieldId], TreeError> {
        Ok(self.message(msg)?.fields_in_order.as_slice())
    }

    pub fn field_tag(&self, field: FieldId) -> Result<Tag, TreeError> {
        Ok(self.field(field)?.tag)
    }

    /// Returns whether `field` is currently marked deleted.
    #[inline]
    pub fn field_is_deleted(&self, field: FieldId) -> Result<bool, TreeError> {
        Ok(self.field(field)?.deleted)
    }

    pub fn field_parent_message(&self, field: FieldId) -> Result<MessageId, TreeError> {
        Ok(self.field(field)?.msg)
    }

    pub fn field_spans(&self, field: FieldId) -> Result<Option<FieldSpans>, TreeError> {
        let node = self.field(field)?;
        let Some(spans) = node.spans else {
            return Ok(None);
        };
        Ok(Some(spans.expand(node.tag.wire_type())?))
    }

    /// Returns field spans mapped to absolute root-source coordinates.
    ///
    /// Inserted fields and fields inside owned child messages return `None`.
    pub fn field_root_spans(&self, field: FieldId) -> Result<Option<FieldSpans>, TreeError> {
        let node = self.field(field)?;
        let Some(spans) = node.spans else {
            return Ok(None);
        };
        let Some(msg_span) = self.message_root_span(node.msg)? else {
            return Ok(None);
        };
        let base = msg_span.start();
        let expanded = spans.expand(node.tag.wire_type())?;
        let out = FieldSpans {
            field: span_offset_by(expanded.field, base)?,
            tag: span_offset_by(expanded.tag, base)?,
            value: value_spans_offset_by(expanded.value, base)?,
        };
        Ok(Some(out))
    }

    #[inline]
    pub fn field_child_message(&self, field: FieldId) -> Result<Option<MessageId>, TreeError> {
        Ok(self.field(field)?.child)
    }

    pub fn clear_field_edit(&mut self, field: FieldId) -> Result<(), TreeError> {
        if self.field(field)?.spans.is_none() {
            return self.delete_field(field);
        }

        let idx = field.as_inner() as usize;
        let Patch { txn, fields, .. } = self;
        let node = fields.get_mut(idx).ok_or(TreeError::DecodeError)?;

        let prev_edit = node.edit.take();
        if prev_edit.is_none() {
            return Ok(());
        }
        if let Some(state) = txn.as_mut() {
            state.undo_log.push(UndoAction::FieldEdit { field, prev: prev_edit });
        }

        match node.tag.wire_type() {
            WireType::Len => {
                let prev_child = node.child.take();
                if let Some(state) = txn.as_mut() {
                    state.undo_log.push(UndoAction::FieldChild { field, prev: prev_child });
                }
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let prev_child = node.child.take();
                if let Some(state) = txn.as_mut() {
                    state.undo_log.push(UndoAction::FieldChild { field, prev: prev_child });
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn delete_field(&mut self, field: FieldId) -> Result<(), TreeError> {
        let idx = field.as_inner() as usize;
        let Patch { txn, fields, .. } = self;
        let node = fields.get_mut(idx).ok_or(TreeError::DecodeError)?;

        let prev_deleted = core::mem::replace(&mut node.deleted, true);
        let prev_edit = node.edit.take();
        let prev_child = node.child.take();

        if let Some(state) = txn.as_mut() {
            state.undo_log.push(UndoAction::FieldDeleted { field, prev: prev_deleted });
            state.undo_log.push(UndoAction::FieldEdit { field, prev: prev_edit });
            state.undo_log.push(UndoAction::FieldChild { field, prev: prev_child });
        }
        Ok(())
    }

    pub fn insert_varint(
        &mut self,
        msg: MessageId,
        tag: Tag,
        value: u64,
    ) -> Result<FieldId, TreeError> {
        if tag.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        self.insert_field_with_edit(msg, tag, PayloadEdit::Varint(VarintEdit::new(value)))
    }

    pub fn insert_i32_bits(
        &mut self,
        msg: MessageId,
        tag: Tag,
        bits: u32,
    ) -> Result<FieldId, TreeError> {
        if tag.wire_type() != WireType::I32 {
            return Err(TreeError::WireTypeMismatch);
        }
        self.insert_field_with_edit(msg, tag, PayloadEdit::I32(bits))
    }

    pub fn insert_i64_bits(
        &mut self,
        msg: MessageId,
        tag: Tag,
        bits: u64,
    ) -> Result<FieldId, TreeError> {
        if tag.wire_type() != WireType::I64 {
            return Err(TreeError::WireTypeMismatch);
        }
        self.insert_field_with_edit(msg, tag, PayloadEdit::I64(bits))
    }

    pub fn insert_bytes(
        &mut self,
        msg: MessageId,
        tag: Tag,
        payload: Buf,
    ) -> Result<FieldId, TreeError> {
        match tag.wire_type() {
            WireType::Len => {}
            #[cfg(feature = "group")]
            WireType::SGroup => {}
            _ => return Err(TreeError::WireTypeMismatch),
        }
        self.insert_field_with_edit(msg, tag, PayloadEdit::Bytes(payload))
    }

    pub fn set_varint(&mut self, field: FieldId, value: u64) -> Result<(), TreeError> {
        let idx = field.as_inner() as usize;
        let Patch { txn, fields, .. } = self;
        let node = fields.get_mut(idx).ok_or(TreeError::DecodeError)?;
        if node.tag.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        let prev_edit = node.edit.replace(PayloadEdit::Varint(VarintEdit::new(value)));
        if let Some(state) = txn.as_mut() {
            state.undo_log.push(UndoAction::FieldEdit { field, prev: prev_edit });
        }
        Ok(())
    }

    pub fn set_i32_bits(&mut self, field: FieldId, bits: u32) -> Result<(), TreeError> {
        let idx = field.as_inner() as usize;
        let Patch { txn, fields, .. } = self;
        let node = fields.get_mut(idx).ok_or(TreeError::DecodeError)?;
        if node.tag.wire_type() != WireType::I32 {
            return Err(TreeError::WireTypeMismatch);
        }
        let prev_edit = node.edit.replace(PayloadEdit::I32(bits));
        if let Some(state) = txn.as_mut() {
            state.undo_log.push(UndoAction::FieldEdit { field, prev: prev_edit });
        }
        Ok(())
    }

    pub fn set_i64_bits(&mut self, field: FieldId, bits: u64) -> Result<(), TreeError> {
        let idx = field.as_inner() as usize;
        let Patch { txn, fields, .. } = self;
        let node = fields.get_mut(idx).ok_or(TreeError::DecodeError)?;
        if node.tag.wire_type() != WireType::I64 {
            return Err(TreeError::WireTypeMismatch);
        }
        let prev_edit = node.edit.replace(PayloadEdit::I64(bits));
        if let Some(state) = txn.as_mut() {
            state.undo_log.push(UndoAction::FieldEdit { field, prev: prev_edit });
        }
        Ok(())
    }

    pub fn set_bytes(&mut self, field: FieldId, payload: Buf) -> Result<(), TreeError> {
        let idx = field.as_inner() as usize;
        let Patch { txn, fields, .. } = self;
        let node = fields.get_mut(idx).ok_or(TreeError::DecodeError)?;
        match node.tag.wire_type() {
            WireType::Len => {}
            #[cfg(feature = "group")]
            WireType::SGroup => {}
            _ => return Err(TreeError::WireTypeMismatch),
        }
        let prev_edit = node.edit.replace(PayloadEdit::Bytes(payload));
        let prev_child = node.child.take();
        if let Some(state) = txn.as_mut() {
            state.undo_log.push(UndoAction::FieldEdit { field, prev: prev_edit });
            state.undo_log.push(UndoAction::FieldChild { field, prev: prev_child });
        }
        Ok(())
    }

    pub fn varint(&self, field: FieldId) -> Result<u64, TreeError> {
        let node = self.field(field)?;
        if node.tag.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        if let Some(PayloadEdit::Varint(edit)) = node.edit.as_ref() {
            return Ok(edit.value);
        }
        let field_idx = field.as_inner() as usize;
        if let Some(cached) = self.read_cache.get_varint(field_idx) {
            return Ok(cached);
        }
        let Some(spans) = node.spans else {
            return Err(TreeError::DecodeError);
        };
        let msg_bytes = self.message_bytes(node.msg)?;
        let start = spans.field.start();
        let value_start =
            start.checked_add(spans.tag_len as u32).ok_or(TreeError::CapacityExceeded)?;
        let value = Span::new(value_start, spans.field.end()).ok_or(TreeError::DecodeError)?;
        let data = slice_span(msg_bytes, value)?;
        let (v, _used) = crate::varint::decode64(data).ok_or(TreeError::DecodeError)?;
        self.read_cache.set_varint(field_idx, v);
        Ok(v)
    }

    pub fn i32_bits(&self, field: FieldId) -> Result<u32, TreeError> {
        let node = self.field(field)?;
        if node.tag.wire_type() != WireType::I32 {
            return Err(TreeError::WireTypeMismatch);
        }
        if let Some(PayloadEdit::I32(bits)) = node.edit.as_ref() {
            return Ok(*bits);
        }
        let Some(spans) = node.spans else {
            return Err(TreeError::DecodeError);
        };
        let msg_bytes = self.message_bytes(node.msg)?;
        let end = spans.field.end();
        let start = end.checked_sub(4).ok_or(TreeError::DecodeError)?;
        let value = Span::new(start, end).ok_or(TreeError::DecodeError)?;
        let data = slice_span(msg_bytes, value)?;
        let b: [u8; 4] = data.try_into().map_err(|_| TreeError::DecodeError)?;
        Ok(u32::from_le_bytes(b))
    }

    pub fn i64_bits(&self, field: FieldId) -> Result<u64, TreeError> {
        let node = self.field(field)?;
        if node.tag.wire_type() != WireType::I64 {
            return Err(TreeError::WireTypeMismatch);
        }
        if let Some(PayloadEdit::I64(bits)) = node.edit.as_ref() {
            return Ok(*bits);
        }
        let Some(spans) = node.spans else {
            return Err(TreeError::DecodeError);
        };
        let msg_bytes = self.message_bytes(node.msg)?;
        let end = spans.field.end();
        let start = end.checked_sub(8).ok_or(TreeError::DecodeError)?;
        let value = Span::new(start, end).ok_or(TreeError::DecodeError)?;
        let data = slice_span(msg_bytes, value)?;
        let b: [u8; 8] = data.try_into().map_err(|_| TreeError::DecodeError)?;
        Ok(u64::from_le_bytes(b))
    }

    pub fn bytes(&self, field: FieldId) -> Result<&[u8], TreeError> {
        let node = self.field(field)?;
        let wire = node.tag.wire_type();
        match wire {
            WireType::Len => {}
            #[cfg(feature = "group")]
            WireType::SGroup => {}
            _ => return Err(TreeError::WireTypeMismatch),
        }
        if let Some(PayloadEdit::Bytes(buf)) = node.edit.as_ref() {
            return Ok(buf.as_slice());
        }
        let Some(spans) = node.spans else {
            return Err(TreeError::DecodeError);
        };
        let msg_bytes = self.message_bytes(node.msg)?;
        let payload = spans.payload_span(wire)?;
        slice_span(msg_bytes, payload)
    }

    fn message(&self, id: MessageId) -> Result<&MessageNode, TreeError> {
        let idx = id.as_inner() as usize;
        self.messages.get(idx).ok_or(TreeError::DecodeError)
    }

    fn message_mut(&mut self, id: MessageId) -> Result<&mut MessageNode, TreeError> {
        let idx = id.as_inner() as usize;
        self.messages.get_mut(idx).ok_or(TreeError::DecodeError)
    }

    fn insert_field_with_edit(
        &mut self,
        msg: MessageId,
        tag: Tag,
        edit: PayloadEdit,
    ) -> Result<FieldId, TreeError> {
        let prev_by_tag = self.message(msg)?.query.get(&tag).and_then(|bucket| bucket.tail);
        let field_id = Self::alloc_field(
            &mut self.fields,
            &mut self.read_cache,
            FieldNode {
                msg,
                tag,
                prev_by_tag,
                next_by_tag: None,
                raw_tag: RawVarint32::from_u32(tag.get()),
                spans: None,
                edit: Some(edit),
                child: None,
                deleted: false,
            },
        )?;

        if let Some(prev) = prev_by_tag {
            let prev_idx = prev.as_inner() as usize;
            let prev_node = self.fields.get_mut(prev_idx).ok_or(TreeError::DecodeError)?;
            prev_node.next_by_tag = Some(field_id);
        }

        let msg_node = self.message_mut(msg)?;
        msg_node.fields_in_order.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        msg_node.fields_in_order.push(field_id);

        let bucket = msg_node.query.entry(tag).or_insert_with(TagBucket::default);
        debug_assert_eq!(bucket.tail, prev_by_tag);
        debug_assert_eq!(bucket.head.is_none(), bucket.len == 0);
        if bucket.len == 0 {
            bucket.head = Some(field_id);
        }
        bucket.tail = Some(field_id);
        bucket.len = bucket.len.checked_add(1).ok_or(TreeError::CapacityExceeded)?;

        if let Some(state) = self.txn.as_mut() {
            state.undo_log.push(UndoAction::InsertField { msg, field: field_id });
        }
        Ok(field_id)
    }

    fn field(&self, id: FieldId) -> Result<&FieldNode, TreeError> {
        let idx = id.as_inner() as usize;
        self.fields.get(idx).ok_or(TreeError::DecodeError)
    }
}

impl Clone for Patch {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            source: self.source.clone(),
            messages: self.messages.clone(),
            fields: self.fields.clone(),
            read_cache: self.read_cache.clone(),
            txn: None,
        }
    }
}

#[inline]
fn slice_span(bytes: &[u8], span: Span) -> Result<&[u8], TreeError> {
    let start = span.start() as usize;
    let end = span.end() as usize;
    if end > bytes.len() {
        return Err(TreeError::DecodeError);
    }
    Ok(&bytes[start..end])
}

#[inline]
fn span_offset_by(span: Span, base: u32) -> Result<Span, TreeError> {
    let start = base.checked_add(span.start()).ok_or(TreeError::CapacityExceeded)?;
    let end = base.checked_add(span.end()).ok_or(TreeError::CapacityExceeded)?;
    Span::new(start, end).ok_or(TreeError::DecodeError)
}

#[inline]
fn value_spans_offset_by(value: ValueSpans, base: u32) -> Result<ValueSpans, TreeError> {
    match value {
        ValueSpans::Varint { value } => {
            Ok(ValueSpans::Varint { value: span_offset_by(value, base)? })
        }
        ValueSpans::I32 { value } => Ok(ValueSpans::I32 { value: span_offset_by(value, base)? }),
        ValueSpans::I64 { value } => Ok(ValueSpans::I64 { value: span_offset_by(value, base)? }),
        ValueSpans::Len { len, payload } => Ok(ValueSpans::Len {
            len: span_offset_by(len, base)?,
            payload: span_offset_by(payload, base)?,
        }),
        #[cfg(feature = "group")]
        ValueSpans::Group { body, end_tag } => Ok(ValueSpans::Group {
            body: span_offset_by(body, base)?,
            end_tag: span_offset_by(end_tag, base)?,
        }),
    }
}

#[cfg(test)]
mod tests;
