//! Span-based protobuf message patcher with lazy payload edits.
//!
//! This module builds a wire-level view of a protobuf message by eagerly scanning
//! fields and recording byte spans into the original input. Payload edits are
//! tracked separately and only materialized when saving, allowing unchanged
//! fields to be copied verbatim from the source bytes.

use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::{Buf, Tag, TreeError, WireType};

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

#[derive(Clone, Copy)]
struct MessageSaveInfo {
    len: u32,
    dirty: bool,
}

struct SavePlan {
    messages: Vec<Option<MessageSaveInfo>>,
}

impl SavePlan {
    fn new(messages_len: usize) -> Result<Self, TreeError> {
        let mut messages = Vec::new();
        messages.try_reserve(messages_len).map_err(|_| TreeError::CapacityExceeded)?;
        messages.resize(messages_len, None);
        Ok(Self { messages })
    }

    fn get(&self, msg: MessageId) -> Result<Option<MessageSaveInfo>, TreeError> {
        let idx = msg.as_inner() as usize;
        Ok(*self.messages.get(idx).ok_or(TreeError::DecodeError)?)
    }

    fn set(&mut self, msg: MessageId, info: MessageSaveInfo) -> Result<(), TreeError> {
        let idx = msg.as_inner() as usize;
        let slot = self.messages.get_mut(idx).ok_or(TreeError::DecodeError)?;
        *slot = Some(info);
        Ok(())
    }
}

#[derive(Clone)]
struct MessageNode {
    source: MessageSource,
    parent_field: Option<FieldId>,
    fields_in_order: Vec<FieldId>,
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
    spans: Option<FieldSpans>,
    edit: Option<PayloadEdit>,
    child: Option<MessageId>,
    deleted: bool,
}

#[derive(Clone)]
enum PayloadEdit {
    Varint(u64),
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

/// Iterates over fields in `msg` that match `tag`.
#[derive(Clone)]
pub struct FieldsByTag<'a> {
    patch: &'a Patch,
    tag: Tag,
    remaining: &'a [FieldId],
}

impl Iterator for FieldsByTag<'_> {
    type Item = FieldId;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some((&field, rest)) = self.remaining.split_first() {
            self.remaining = rest;
            let idx = field.as_inner() as usize;
            let Some(node) = self.patch.fields.get(idx) else {
                debug_assert!(false, "FieldsByTag iterator field id out of bounds");
                continue;
            };
            if node.tag == self.tag {
                return Some(field);
            }
        }
        None
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining.len()))
    }
}

impl FusedIterator for FieldsByTag<'_> {}

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
    pub fn from_bytes(data: &[u8]) -> Result<Self, TreeError> {
        let mut source = Buf::new();
        source.extend_from_slice(data)?;
        Self::from_buf(source)
    }

    pub fn from_buf(source: Buf) -> Result<Self, TreeError> {
        let source_len = source.len() as usize;
        let Some(end) = u32::try_from(source_len).ok() else {
            return Err(TreeError::CapacityExceeded);
        };

        let mut out = Self {
            root: MessageId::MIN,
            source,
            messages: Vec::new(),
            fields: Vec::new(),
            read_cache: ReadCache::default(),
            txn: None,
        };
        let root = out.parse_message_node(MessageSource::Root { start: 0, end }, None)?;
        out.root = root;
        Ok(out)
    }

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

    pub fn fields_by_tag(&self, msg: MessageId, tag: Tag) -> Result<FieldsByTag<'_>, TreeError> {
        let msg = self.message(msg)?;
        Ok(FieldsByTag { patch: self, tag, remaining: msg.fields_in_order.as_slice() })
    }

    pub fn field_tag(&self, field: FieldId) -> Result<Tag, TreeError> {
        Ok(self.field(field)?.tag)
    }

    pub fn field_parent_message(&self, field: FieldId) -> Result<MessageId, TreeError> {
        Ok(self.field(field)?.msg)
    }

    pub fn field_spans(&self, field: FieldId) -> Result<Option<FieldSpans>, TreeError> {
        Ok(self.field(field)?.spans)
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
        let out = FieldSpans {
            field: span_offset_by(spans.field, base)?,
            tag: span_offset_by(spans.tag, base)?,
            value: value_spans_offset_by(spans.value, base)?,
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
        self.insert_field_with_edit(msg, tag, PayloadEdit::Varint(value))
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
        let prev_edit = node.edit.replace(PayloadEdit::Varint(value));
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

    pub fn parse_child_message(&mut self, field: FieldId) -> Result<MessageId, TreeError> {
        let node = self.field(field)?;
        match node.tag.wire_type() {
            WireType::Len => {}
            #[cfg(feature = "group")]
            WireType::SGroup => {}
            _ => return Err(TreeError::WireTypeMismatch),
        }

        let parent_msg = node.msg;
        if let Some(existing) = node.child {
            return Ok(existing);
        }

        let parent_msg_source = self.message(parent_msg)?.source.clone();
        let child_source = match (node.edit.as_ref(), node.spans) {
            (Some(PayloadEdit::Bytes(buf)), _spans) => MessageSource::Owned { bytes: buf.clone() },
            (Some(_), _spans) => return Err(TreeError::WireTypeMismatch),
            (None, Some(spans)) => {
                let payload_span = match spans.value {
                    ValueSpans::Len { payload, .. } => payload,
                    #[cfg(feature = "group")]
                    ValueSpans::Group { body, .. } => body,
                    _ => return Err(TreeError::WireTypeMismatch),
                };

                let parent_bytes = self.message_bytes(parent_msg)?;
                let payload_bytes = slice_span(parent_bytes, payload_span)?;
                match parent_msg_source {
                    MessageSource::Root { start, .. } => {
                        let start = start
                            .checked_add(payload_span.start())
                            .ok_or(TreeError::CapacityExceeded)?;
                        let end = start
                            .checked_add(payload_span.len())
                            .ok_or(TreeError::CapacityExceeded)?;
                        MessageSource::Root { start, end }
                    }
                    MessageSource::Owned { .. } => {
                        let mut bytes = Buf::new();
                        bytes.extend_from_slice(payload_bytes)?;
                        MessageSource::Owned { bytes }
                    }
                }
            }
            (None, None) => return Err(TreeError::DecodeError),
        };

        let child = self.parse_message_node(child_source, Some(field))?;
        let idx = field.as_inner() as usize;
        let Patch { txn, fields, .. } = self;
        let node = fields.get_mut(idx).ok_or(TreeError::DecodeError)?;
        let prev_child = node.child.replace(child);
        if let Some(state) = txn.as_mut() {
            state.undo_log.push(UndoAction::FieldChild { field, prev: prev_child });
        }
        Ok(child)
    }

    pub fn varint(&self, field: FieldId) -> Result<u64, TreeError> {
        let node = self.field(field)?;
        if node.tag.wire_type() != WireType::Varint {
            return Err(TreeError::WireTypeMismatch);
        }
        if let Some(PayloadEdit::Varint(v)) = node.edit.as_ref() {
            return Ok(*v);
        }
        let field_idx = field.as_inner() as usize;
        if let Some(cached) = self.read_cache.get_varint(field_idx) {
            return Ok(cached);
        }
        let Some(spans) = node.spans else {
            return Err(TreeError::DecodeError);
        };
        let msg_bytes = self.message_bytes(node.msg)?;
        let ValueSpans::Varint { value } = spans.value else {
            return Err(TreeError::DecodeError);
        };
        let data = slice_span(msg_bytes, value)?;
        let (v, _used) = crate::varint::decode64(data).ok_or(TreeError::DecodeError)?;
        self.read_cache.set_varint(field_idx, v);
        Ok(v)
    }

    pub fn bytes(&self, field: FieldId) -> Result<&[u8], TreeError> {
        let node = self.field(field)?;
        match node.tag.wire_type() {
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
        let payload = spans.payload();
        slice_span(msg_bytes, payload)
    }

    pub fn save(&self) -> Result<Buf, TreeError> {
        let mut plan = SavePlan::new(self.messages.len())?;
        let root_info = self.save_message_info(self.root, &mut plan)?;
        let mut out = Buf::with_capacity(root_info.len)?;
        self.write_message(self.root, &mut plan, &mut out)?;
        debug_assert_eq!(out.len(), root_info.len);
        Ok(out)
    }

    pub fn save_and_reparse(&self) -> Result<Self, TreeError> {
        Self::from_buf(self.save()?)
    }

    fn save_message_info(
        &self,
        msg: MessageId,
        plan: &mut SavePlan,
    ) -> Result<MessageSaveInfo, TreeError> {
        if let Some(info) = plan.get(msg)? {
            return Ok(info);
        }

        let msg_node = self.message(msg)?;
        let mut len: u32 = 0;
        let mut dirty = false;

        for &field_id in &msg_node.fields_in_order {
            let field = self.field(field_id)?;
            if field.deleted {
                dirty = true;
                continue;
            }

            let child_dirty = match field.child {
                Some(child) => self.save_message_info(child, plan)?.dirty,
                None => false,
            };

            if field.edit.is_none()
                && !child_dirty
                && let Some(spans) = field.spans
            {
                len = len.checked_add(spans.field.len()).ok_or(TreeError::CapacityExceeded)?;
                continue;
            }

            dirty = true;
            let field_len = self.save_field_len(field, plan)?;
            len = len.checked_add(field_len).ok_or(TreeError::CapacityExceeded)?;
        }

        let info = MessageSaveInfo { len, dirty };
        plan.set(msg, info)?;
        Ok(info)
    }

    fn save_field_len(&self, node: &FieldNode, plan: &mut SavePlan) -> Result<u32, TreeError> {
        let tag_len = match node.spans {
            Some(spans) => spans.tag.len(),
            None => crate::varint::encoded_len32(node.tag.get()),
        };

        let value_len = match node.tag.wire_type() {
            WireType::Varint => {
                let Some(PayloadEdit::Varint(v)) = node.edit.as_ref() else {
                    return Err(TreeError::DecodeError);
                };
                crate::varint::encoded_len64(*v)
            }
            WireType::I32 => {
                let Some(PayloadEdit::I32(_bits)) = node.edit.as_ref() else {
                    return Err(TreeError::DecodeError);
                };
                4
            }
            WireType::I64 => {
                let Some(PayloadEdit::I64(_bits)) = node.edit.as_ref() else {
                    return Err(TreeError::DecodeError);
                };
                8
            }
            WireType::Len => {
                let (orig_len_bytes, orig_payload_len) = match node.spans {
                    Some(spans) => {
                        let ValueSpans::Len { len, payload } = spans.value else {
                            return Err(TreeError::DecodeError);
                        };
                        (Some(len.len()), payload.len())
                    }
                    None => (None, 0),
                };

                let payload_len = if let Some(child) = node.child {
                    self.save_message_info(child, plan)?.len
                } else {
                    match node.edit.as_ref() {
                        Some(PayloadEdit::Bytes(buf)) => buf.len(),
                        None => return Err(TreeError::DecodeError),
                        Some(_) => return Err(TreeError::DecodeError),
                    }
                };

                let len_prefix_len = match orig_len_bytes {
                    Some(len_bytes) if payload_len == orig_payload_len => len_bytes,
                    _ => crate::varint::encoded_len32(payload_len),
                };
                len_prefix_len.checked_add(payload_len).ok_or(TreeError::CapacityExceeded)?
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                let end_tag_len = match node.spans {
                    Some(spans) => {
                        let ValueSpans::Group { end_tag, .. } = spans.value else {
                            return Err(TreeError::DecodeError);
                        };
                        end_tag.len()
                    }
                    None => {
                        let (field_number, _wire_type) = node.tag.split();
                        crate::varint::encoded_len32(
                            Tag::from_parts(field_number, WireType::EGroup).get(),
                        )
                    }
                };

                let body_len = if let Some(child) = node.child {
                    self.save_message_info(child, plan)?.len
                } else {
                    match node.edit.as_ref() {
                        Some(PayloadEdit::Bytes(buf)) => buf.len(),
                        None => return Err(TreeError::DecodeError),
                        Some(_) => return Err(TreeError::DecodeError),
                    }
                };
                body_len.checked_add(end_tag_len).ok_or(TreeError::CapacityExceeded)?
            }
            #[cfg(feature = "group")]
            WireType::EGroup => return Err(TreeError::DecodeError),
        };

        tag_len.checked_add(value_len).ok_or(TreeError::CapacityExceeded)
    }

    fn write_message(
        &self,
        msg: MessageId,
        plan: &mut SavePlan,
        out: &mut Buf,
    ) -> Result<(), TreeError> {
        let msg_node = self.message(msg)?;
        let msg_bytes = msg_node.source.bytes(self.source.as_slice());

        for &field_id in &msg_node.fields_in_order {
            let field = self.field(field_id)?;
            if field.deleted {
                continue;
            }

            let child_dirty = match field.child {
                Some(child) => self.save_message_info(child, plan)?.dirty,
                None => false,
            };

            if field.edit.is_none()
                && !child_dirty
                && let Some(spans) = field.spans
            {
                let chunk = slice_span(msg_bytes, spans.field)?;
                out.extend_from_slice(chunk)?;
                continue;
            }

            self.write_field(msg_bytes, field_id, plan, out)?;
        }

        Ok(())
    }

    fn write_field(
        &self,
        msg_bytes: &[u8],
        field: FieldId,
        plan: &mut SavePlan,
        out: &mut Buf,
    ) -> Result<(), TreeError> {
        let node = self.field(field)?;
        match node.spans {
            Some(spans) => {
                let tag_bytes = slice_span(msg_bytes, spans.tag)?;
                out.extend_from_slice(tag_bytes)?;
            }
            None => {
                crate::wire::encode_tag_value(out, node.tag)?;
            }
        }

        match node.tag.wire_type() {
            WireType::Varint => {
                let Some(PayloadEdit::Varint(v)) = node.edit.as_ref() else {
                    return Err(TreeError::DecodeError);
                };
                let _ = crate::varint::encode64(out, *v)?;
            }
            WireType::I32 => {
                let Some(PayloadEdit::I32(bits)) = node.edit.as_ref() else {
                    return Err(TreeError::DecodeError);
                };
                out.extend_from_slice(&bits.to_le_bytes())?;
            }
            WireType::I64 => {
                let Some(PayloadEdit::I64(bits)) = node.edit.as_ref() else {
                    return Err(TreeError::DecodeError);
                };
                out.extend_from_slice(&bits.to_le_bytes())?;
            }
            WireType::Len => {
                self.write_len_field(msg_bytes, node, plan, out)?;
            }
            #[cfg(feature = "group")]
            WireType::SGroup => {
                self.write_group_field(msg_bytes, node, plan, out)?;
            }
            #[cfg(feature = "group")]
            WireType::EGroup => return Err(TreeError::DecodeError),
        }
        Ok(())
    }

    fn write_len_field(
        &self,
        msg_bytes: &[u8],
        node: &FieldNode,
        plan: &mut SavePlan,
        out: &mut Buf,
    ) -> Result<(), TreeError> {
        let (orig_len_span, orig_payload_len) = match node.spans {
            Some(spans) => {
                let ValueSpans::Len { len, payload } = spans.value else {
                    return Err(TreeError::DecodeError);
                };
                (Some(len), payload.len())
            }
            None => (None, 0),
        };

        let payload_len = if let Some(child) = node.child {
            self.save_message_info(child, plan)?.len
        } else {
            match node.edit.as_ref() {
                Some(PayloadEdit::Bytes(buf)) => buf.len(),
                None => return Err(TreeError::DecodeError),
                Some(_) => return Err(TreeError::DecodeError),
            }
        };

        match orig_len_span {
            Some(len_span) if payload_len == orig_payload_len => {
                let len_bytes = slice_span(msg_bytes, len_span)?;
                out.extend_from_slice(len_bytes)?;
            }
            _ => {
                let _ = crate::varint::encode32(out, payload_len)?;
            }
        }

        if let Some(child) = node.child {
            self.write_message(child, plan, out)?;
            return Ok(());
        }

        let Some(PayloadEdit::Bytes(payload)) = node.edit.as_ref() else {
            return Err(TreeError::DecodeError);
        };
        out.extend_from_slice(payload.as_slice())?;
        Ok(())
    }

    #[cfg(feature = "group")]
    fn write_group_field(
        &self,
        msg_bytes: &[u8],
        node: &FieldNode,
        plan: &mut SavePlan,
        out: &mut Buf,
    ) -> Result<(), TreeError> {
        let end_tag_span = match node.spans {
            Some(spans) => {
                let ValueSpans::Group { end_tag, .. } = spans.value else {
                    return Err(TreeError::DecodeError);
                };
                Some(end_tag)
            }
            None => None,
        };

        if let Some(child) = node.child {
            self.write_message(child, plan, out)?;
        } else {
            let Some(PayloadEdit::Bytes(body)) = node.edit.as_ref() else {
                return Err(TreeError::DecodeError);
            };
            out.extend_from_slice(body.as_slice())?;
        }

        match end_tag_span {
            Some(span) => {
                let end_tag_bytes = slice_span(msg_bytes, span)?;
                out.extend_from_slice(end_tag_bytes)?;
            }
            None => {
                let (field_number, _wire_type) = node.tag.split();
                crate::wire::encode_tag_value(
                    out,
                    Tag::from_parts(field_number, WireType::EGroup),
                )?;
            }
        }
        Ok(())
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
        let _ = self.message(msg)?;
        let field_id = Self::alloc_field(
            &mut self.fields,
            &mut self.read_cache,
            FieldNode { msg, tag, spans: None, edit: Some(edit), child: None, deleted: false },
        )?;

        let msg_node = self.message_mut(msg)?;
        msg_node.fields_in_order.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        msg_node.fields_in_order.push(field_id);
        if let Some(state) = self.txn.as_mut() {
            state.undo_log.push(UndoAction::InsertField { msg, field: field_id });
        }
        Ok(field_id)
    }

    fn field(&self, id: FieldId) -> Result<&FieldNode, TreeError> {
        let idx = id.as_inner() as usize;
        self.fields.get(idx).ok_or(TreeError::DecodeError)
    }

    fn parse_message_node(
        &mut self,
        source: MessageSource,
        parent_field: Option<FieldId>,
    ) -> Result<MessageId, TreeError> {
        let orig_messages_len = self.messages.len();
        let orig_fields_len = self.fields.len();

        let parsed = (|| {
            let next = self.messages.len();
            let Some(id_u32) = u32::try_from(next).ok() else {
                return Err(TreeError::CapacityExceeded);
            };
            if id_u32 == MessageId::MAX.as_inner() {
                return Err(TreeError::CapacityExceeded);
            }
            let msg_id = unsafe { MessageId::new_unchecked(id_u32) };

            let bytes = source.bytes(self.source.as_slice());

            let mut fields_in_order = Vec::new();

            let mut offset = 0usize;
            while offset < bytes.len() {
                let field_start = offset;
                let (tag, tag_len) =
                    crate::wire::decode_tag(&bytes[offset..]).ok_or(TreeError::DecodeError)?;
                offset = offset.checked_add(tag_len as usize).ok_or(TreeError::CapacityExceeded)?;
                if offset > bytes.len() {
                    return Err(TreeError::DecodeError);
                }
                let tag_span =
                    Span::new(field_start as u32, offset as u32).ok_or(TreeError::DecodeError)?;

                let spans = match tag.wire_type() {
                    WireType::Varint => {
                        let val_start = offset;
                        let (_v, used) = crate::varint::decode64(&bytes[offset..])
                            .ok_or(TreeError::DecodeError)?;
                        offset =
                            offset.checked_add(used as usize).ok_or(TreeError::CapacityExceeded)?;
                        if offset > bytes.len() {
                            return Err(TreeError::DecodeError);
                        }
                        let value = Span::new(val_start as u32, offset as u32)
                            .ok_or(TreeError::DecodeError)?;
                        let field = Span::new(field_start as u32, offset as u32)
                            .ok_or(TreeError::DecodeError)?;
                        FieldSpans { field, tag: tag_span, value: ValueSpans::Varint { value } }
                    }
                    WireType::I64 => {
                        let val_start = offset;
                        let val_end = offset.checked_add(8).ok_or(TreeError::CapacityExceeded)?;
                        if val_end > bytes.len() {
                            return Err(TreeError::DecodeError);
                        }
                        offset = val_end;
                        let value = Span::new(val_start as u32, val_end as u32)
                            .ok_or(TreeError::DecodeError)?;
                        let field = Span::new(field_start as u32, val_end as u32)
                            .ok_or(TreeError::DecodeError)?;
                        FieldSpans { field, tag: tag_span, value: ValueSpans::I64 { value } }
                    }
                    WireType::Len => {
                        let len_start = offset;
                        let (len, used) = crate::varint::decode32(&bytes[offset..])
                            .ok_or(TreeError::DecodeError)?;
                        offset =
                            offset.checked_add(used as usize).ok_or(TreeError::CapacityExceeded)?;
                        let len_span = Span::new(len_start as u32, offset as u32)
                            .ok_or(TreeError::DecodeError)?;

                        let payload_start = offset;
                        let payload_end = payload_start
                            .checked_add(len as usize)
                            .ok_or(TreeError::CapacityExceeded)?;
                        if payload_end > bytes.len() {
                            return Err(TreeError::DecodeError);
                        }
                        offset = payload_end;
                        let payload = Span::new(payload_start as u32, payload_end as u32)
                            .ok_or(TreeError::DecodeError)?;
                        let field = Span::new(field_start as u32, payload_end as u32)
                            .ok_or(TreeError::DecodeError)?;
                        FieldSpans {
                            field,
                            tag: tag_span,
                            value: ValueSpans::Len { len: len_span, payload },
                        }
                    }
                    #[cfg(feature = "group")]
                    WireType::SGroup => {
                        let (field_number, _wire_type) = tag.split();
                        let body_start = offset;
                        let (end_tag_start, end_after) =
                            crate::wire::find_group_end(bytes, body_start, field_number)
                                .ok_or(TreeError::DecodeError)?;
                        offset = end_after;

                        let body = Span::new(body_start as u32, end_tag_start as u32)
                            .ok_or(TreeError::DecodeError)?;
                        let end_tag = Span::new(end_tag_start as u32, end_after as u32)
                            .ok_or(TreeError::DecodeError)?;
                        let field = Span::new(field_start as u32, end_after as u32)
                            .ok_or(TreeError::DecodeError)?;
                        FieldSpans {
                            field,
                            tag: tag_span,
                            value: ValueSpans::Group { body, end_tag },
                        }
                    }
                    #[cfg(feature = "group")]
                    WireType::EGroup => return Err(TreeError::DecodeError),
                    WireType::I32 => {
                        let val_start = offset;
                        let val_end = offset.checked_add(4).ok_or(TreeError::CapacityExceeded)?;
                        if val_end > bytes.len() {
                            return Err(TreeError::DecodeError);
                        }
                        offset = val_end;
                        let value = Span::new(val_start as u32, val_end as u32)
                            .ok_or(TreeError::DecodeError)?;
                        let field = Span::new(field_start as u32, val_end as u32)
                            .ok_or(TreeError::DecodeError)?;
                        FieldSpans { field, tag: tag_span, value: ValueSpans::I32 { value } }
                    }
                };

                let field_id = Self::alloc_field(
                    &mut self.fields,
                    &mut self.read_cache,
                    FieldNode {
                        msg: msg_id,
                        tag,
                        spans: Some(spans),
                        edit: None,
                        child: None,
                        deleted: false,
                    },
                )?;

                if fields_in_order.len() == fields_in_order.capacity() {
                    fields_in_order.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
                }
                fields_in_order.push(field_id);
            }

            self.messages.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
            self.messages.push(MessageNode { source, parent_field, fields_in_order });
            Ok(msg_id)
        })();

        match parsed {
            Ok(id) => Ok(id),
            Err(err) => {
                self.messages.truncate(orig_messages_len);
                self.fields.truncate(orig_fields_len);
                self.read_cache.truncate_fields(orig_fields_len);
                Err(err)
            }
        }
    }

    fn alloc_field(
        fields: &mut Vec<FieldNode>,
        read_cache: &mut ReadCache,
        node: FieldNode,
    ) -> Result<FieldId, TreeError> {
        debug_assert!(!read_cache.enabled || read_cache.varints.len() == fields.len());

        let next = fields.len();
        let Some(id_u32) = u32::try_from(next).ok() else {
            return Err(TreeError::CapacityExceeded);
        };
        if id_u32 == FieldId::MAX.as_inner() {
            return Err(TreeError::CapacityExceeded);
        }
        if read_cache.enabled {
            read_cache.varints.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        }
        fields.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        fields.push(node);
        if read_cache.enabled {
            read_cache.varints.push(Cell::new(None));
        }
        Ok(unsafe { FieldId::new_unchecked(id_u32) })
    }

    fn txn_begin(&mut self) {
        assert!(self.txn.is_none(), "nested Patch txn is not supported");
        self.txn = Some(TxnState {
            orig_messages_len: self.messages.len(),
            orig_fields_len: self.fields.len(),
            undo_log: Vec::new(),
        });
    }

    fn txn_commit(&mut self) {
        let _ = self.txn.take();
    }

    fn txn_rollback(&mut self) {
        let Some(state) = self.txn.take() else {
            return;
        };

        for action in state.undo_log.into_iter().rev() {
            match action {
                UndoAction::FieldEdit { field, prev } => {
                    let idx = field.as_inner() as usize;
                    if let Some(node) = self.fields.get_mut(idx) {
                        node.edit = prev;
                    } else {
                        debug_assert!(false, "txn undo field edit out of bounds");
                    }
                }
                UndoAction::FieldDeleted { field, prev } => {
                    let idx = field.as_inner() as usize;
                    if let Some(node) = self.fields.get_mut(idx) {
                        node.deleted = prev;
                    } else {
                        debug_assert!(false, "txn undo field deleted out of bounds");
                    }
                }
                UndoAction::FieldChild { field, prev } => {
                    let idx = field.as_inner() as usize;
                    if let Some(node) = self.fields.get_mut(idx) {
                        node.child = prev;
                    } else {
                        debug_assert!(false, "txn undo field child out of bounds");
                    }
                }
                UndoAction::InsertField { msg, field } => {
                    let msg_idx = msg.as_inner() as usize;
                    let Some(msg_node) = self.messages.get_mut(msg_idx) else {
                        debug_assert!(false, "txn undo insert msg out of bounds");
                        continue;
                    };

                    let popped = msg_node.fields_in_order.pop();
                    debug_assert_eq!(popped, Some(field), "txn undo insert order mismatch");
                }
            }
        }

        self.messages.truncate(state.orig_messages_len);
        self.fields.truncate(state.orig_fields_len);
        self.read_cache.truncate_fields(state.orig_fields_len);
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

/// Transaction that rolls back on drop unless committed.
pub struct Txn<'a> {
    tree: &'a mut Patch,
    committed: bool,
}

impl<'a> Txn<'a> {
    pub fn begin(tree: &'a mut Patch) -> Self {
        tree.txn_begin();
        Self { tree, committed: false }
    }

    #[inline]
    pub fn tree(&mut self) -> &mut Patch {
        self.tree
    }

    pub fn commit(mut self) {
        self.tree.txn_commit();
        self.committed = true;
    }

    pub fn rollback(mut self) {
        self.tree.txn_rollback();
        self.committed = true;
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.tree.txn_rollback();
        }
    }
}

#[cfg(test)]
mod tests;
