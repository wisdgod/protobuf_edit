use crate::error::TreeError;
use crate::wire::{Tag, WireType};

use super::{
    slice_span, span_offset_by, value_spans_offset_by, FieldId, FieldNode, FieldSpans, MessageId,
    MessageNode, MessageSource, Patch, PayloadEdit, Span,
};

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

    pub(crate) fn message(&self, id: MessageId) -> Result<&MessageNode, TreeError> {
        let idx = id.as_inner() as usize;
        self.messages.get(idx).ok_or(TreeError::DecodeError)
    }

    pub(crate) fn message_mut(&mut self, id: MessageId) -> Result<&mut MessageNode, TreeError> {
        let idx = id.as_inner() as usize;
        self.messages.get_mut(idx).ok_or(TreeError::DecodeError)
    }

    pub(crate) fn field(&self, id: FieldId) -> Result<&FieldNode, TreeError> {
        let idx = id.as_inner() as usize;
        self.fields.get(idx).ok_or(TreeError::DecodeError)
    }
}
