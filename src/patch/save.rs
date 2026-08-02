use alloc::vec::Vec;

use crate::buf::Buf;
use crate::error::TreeError;
use crate::wire::WireType;

use super::{slice_span, FieldId, FieldNode, MessageId, Patch, PayloadEdit, Span, StoredSpans};

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
        Ok(*self.messages.get(idx).ok_or(TreeError::InvalidId)?)
    }

    fn set(&mut self, msg: MessageId, info: MessageSaveInfo) -> Result<(), TreeError> {
        let idx = msg.as_inner() as usize;
        let slot = self.messages.get_mut(idx).ok_or(TreeError::InvalidId)?;
        *slot = Some(info);
        Ok(())
    }
}

impl Patch {
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

        for field_id in msg_node.field_ids() {
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
                && let Some(spans) = field.spans()
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
        let tag_len = match node.spans() {
            Some(spans) => u32::from(spans.tag_len),
            None if !node.raw_tag.is_empty() => u32::from(node.raw_tag.len()),
            None => crate::varint::encoded_len32(node.tag.get()),
        };

        let value_len = match node.tag.wire_type() {
            WireType::Varint => {
                let Some(PayloadEdit::Varint(edit)) = self.field_edit(node) else {
                    return Err(TreeError::Corrupted);
                };
                u32::from(edit.raw.len())
            }
            WireType::I32 => {
                let Some(PayloadEdit::I32(_bits)) = self.field_edit(node) else {
                    return Err(TreeError::Corrupted);
                };
                4
            }
            WireType::I64 => {
                let Some(PayloadEdit::I64(_bits)) = self.field_edit(node) else {
                    return Err(TreeError::Corrupted);
                };
                8
            }
            WireType::Len => {
                let (orig_len_bytes, orig_payload_len) = node
                    .spans()
                    .map_or((None, 0), |spans| (Some(u32::from(spans.aux_len)), spans.payload_len));

                let payload_len = if let Some(child) = node.child {
                    self.save_message_info(child, plan)?.len
                } else {
                    match self.field_edit(node) {
                        Some(PayloadEdit::Bytes(buf)) => buf.len(),
                        None | Some(_) => return Err(TreeError::Corrupted),
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
                let end_tag_len = match node.spans() {
                    Some(spans) => spans.aux_len as u32,
                    None => {
                        let (field_number, _wire_type) = node.tag.split();
                        crate::varint::encoded_len32(
                            crate::Tag::from_parts(field_number, WireType::EGroup).get(),
                        )
                    }
                };

                let body_len = if let Some(child) = node.child {
                    self.save_message_info(child, plan)?.len
                } else {
                    match self.field_edit(node) {
                        Some(PayloadEdit::Bytes(buf)) => buf.len(),
                        None => return Err(TreeError::Corrupted),
                        Some(_) => return Err(TreeError::Corrupted),
                    }
                };
                body_len.checked_add(end_tag_len).ok_or(TreeError::CapacityExceeded)?
            }
            #[cfg(feature = "group")]
            WireType::EGroup => return Err(TreeError::Corrupted),
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

        let mut pending_copy: Option<super::Span> = None;

        for field_id in msg_node.field_ids() {
            let field = self.field(field_id)?;
            if field.deleted {
                if let Some(span) = pending_copy.take() {
                    let chunk = slice_span(msg_bytes, span)?;
                    out.extend_from_slice(chunk)?;
                }
                continue;
            }

            let child_dirty = match field.child {
                Some(child) => self.save_message_info(child, plan)?.dirty,
                None => false,
            };

            if field.edit.is_none()
                && !child_dirty
                && let Some(spans) = field.spans()
            {
                let span = spans.field;
                pending_copy = match pending_copy {
                    Some(prev) if prev.end() == span.start() => Some(
                        super::Span::new(prev.start(), span.end()).ok_or(TreeError::Corrupted)?,
                    ),
                    Some(prev) => {
                        let chunk = slice_span(msg_bytes, prev)?;
                        out.extend_from_slice(chunk)?;
                        Some(span)
                    }
                    None => Some(span),
                };
                continue;
            }

            if let Some(span) = pending_copy.take() {
                let chunk = slice_span(msg_bytes, span)?;
                out.extend_from_slice(chunk)?;
            }
            self.write_field(msg_bytes, field_id, plan, out)?;
        }

        if let Some(span) = pending_copy.take() {
            let chunk = slice_span(msg_bytes, span)?;
            out.extend_from_slice(chunk)?;
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
        match node.spans() {
            Some(spans) => {
                let tag_span = spans.tag_span()?;
                let tag_bytes = slice_span(msg_bytes, tag_span)?;
                out.extend_from_slice(tag_bytes)?;
            }
            None => {
                if node.raw_tag.is_empty() {
                    crate::wire::encode_tag_value(out, node.tag)?;
                } else {
                    let (bytes, len) = node.raw_tag.to_array();
                    out.extend_from_slice(&bytes[..len])?;
                }
            }
        }

        match node.tag.wire_type() {
            WireType::Varint => {
                let Some(PayloadEdit::Varint(edit)) = self.field_edit(node) else {
                    return Err(TreeError::Corrupted);
                };
                let (bytes, len) = edit.raw.to_array();
                out.extend_from_slice(&bytes[..len])?;
            }
            WireType::I32 => {
                let Some(PayloadEdit::I32(bits)) = self.field_edit(node) else {
                    return Err(TreeError::Corrupted);
                };
                out.extend_from_slice(&bits.to_le_bytes())?;
            }
            WireType::I64 => {
                let Some(PayloadEdit::I64(bits)) = self.field_edit(node) else {
                    return Err(TreeError::Corrupted);
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
            WireType::EGroup => return Err(TreeError::Corrupted),
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
        let (orig_len_span, orig_payload_len) = match node.spans() {
            Some(spans) => (Some(stored_len_prefix_span(spans)?), spans.payload_len),
            None => (None, 0),
        };

        let payload_len = if let Some(child) = node.child {
            self.save_message_info(child, plan)?.len
        } else {
            match self.field_edit(node) {
                Some(PayloadEdit::Bytes(buf)) => buf.len(),
                None | Some(_) => return Err(TreeError::Corrupted),
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

        let Some(PayloadEdit::Bytes(payload)) = self.field_edit(node) else {
            return Err(TreeError::Corrupted);
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
        let end_tag_span = match node.spans() {
            Some(spans) => Some(stored_group_end_tag_span(spans)?),
            None => None,
        };

        if let Some(child) = node.child {
            self.write_message(child, plan, out)?;
        } else {
            let Some(PayloadEdit::Bytes(body)) = self.field_edit(node) else {
                return Err(TreeError::Corrupted);
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
                    crate::Tag::from_parts(field_number, WireType::EGroup),
                )?;
            }
        }
        Ok(())
    }
}

#[inline]
fn stored_len_prefix_span(spans: StoredSpans) -> Result<Span, TreeError> {
    let start = spans.field.start();
    let len_start =
        start.checked_add(u32::from(spans.tag_len)).ok_or(TreeError::CapacityExceeded)?;
    let len_end =
        len_start.checked_add(u32::from(spans.aux_len)).ok_or(TreeError::CapacityExceeded)?;
    Span::new(len_start, len_end).ok_or(TreeError::Corrupted)
}

#[cfg(feature = "group")]
#[inline]
fn stored_group_end_tag_span(spans: StoredSpans) -> Result<Span, TreeError> {
    let end = spans.field.end();
    let start = end.checked_sub(spans.aux_len as u32).ok_or(TreeError::Corrupted)?;
    Span::new(start, end).ok_or(TreeError::Corrupted)
}
