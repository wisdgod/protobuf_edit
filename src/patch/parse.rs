use alloc::vec::Vec;
use core::cell::Cell;

use crate::buf::Buf;
use crate::document::RawVarint32;
use crate::error::TreeError;
use crate::wire::WireType;

use super::{
    slice_span, FieldId, FieldNode, FieldRange, MessageId, MessageNode, MessageSource, Patch,
    PayloadEdit, Span, StoredSpans, UndoAction,
};

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
            edits: Vec::new(),
            query: crate::fx::FxHashMap::default(),
            read_cache: super::ReadCache::default(),
            txn: None,
        };
        let root = out.parse_message_node(MessageSource::Root { start: 0, end }, None)?;
        out.root = root;
        Ok(out)
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
        let node = self.field(field)?;
        let child_source = match (self.field_edit(node), node.spans()) {
            (Some(PayloadEdit::Bytes(buf)), _spans) => MessageSource::Owned { bytes: buf.clone() },
            (Some(_), _spans) => return Err(TreeError::WireTypeMismatch),
            (None, Some(spans)) => {
                let payload_span = spans.payload_span(node.tag.wire_type())?;

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
            (None, None) => return Err(TreeError::InvalidId),
        };

        let child = self.parse_message_node(child_source, Some(field))?;
        let idx = field.as_inner() as usize;
        let Self { txn, fields, .. } = self;
        let node = fields.get_mut(idx).ok_or(TreeError::InvalidId)?;
        let prev_child = node.child.replace(child);
        if let Some(state) = txn.as_mut() {
            state.undo_log.push(UndoAction::FieldChild { field, prev: prev_child });
        }
        Ok(child)
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

            let fields_start =
                u32::try_from(self.fields.len()).map_err(|_| TreeError::CapacityExceeded)?;

            let mut offset = 0usize;
            while offset < bytes.len() {
                let field_start = offset;
                let (tag, tag_len) = crate::wire::decode_tag(&bytes[offset..])
                    .ok_or_else(|| TreeError::malformed_at(offset))?;
                let tag_len = u8::try_from(tag_len).map_err(|_| TreeError::Corrupted)?;
                offset = offset.checked_add(tag_len as usize).ok_or(TreeError::CapacityExceeded)?;
                if offset > bytes.len() {
                    return Err(TreeError::malformed_at(field_start));
                }

                let spans = match tag.wire_type() {
                    WireType::Varint => {
                        let (_v, used) = crate::varint::decode64(&bytes[offset..])
                            .ok_or_else(|| TreeError::malformed_at(offset))?;
                        offset =
                            offset.checked_add(used as usize).ok_or(TreeError::CapacityExceeded)?;
                        if offset > bytes.len() {
                            // decode64 never reads past its input slice.
                            return Err(TreeError::Corrupted);
                        }
                        let field = Span::new(field_start as u32, offset as u32)
                            .ok_or(TreeError::Corrupted)?;
                        StoredSpans { field, tag_len, aux_len: 0, payload_len: 0 }
                    }
                    WireType::I64 => {
                        let val_end = offset.checked_add(8).ok_or(TreeError::CapacityExceeded)?;
                        if val_end > bytes.len() {
                            return Err(TreeError::malformed_at(offset));
                        }
                        offset = val_end;
                        let field = Span::new(field_start as u32, val_end as u32)
                            .ok_or(TreeError::Corrupted)?;
                        StoredSpans { field, tag_len, aux_len: 0, payload_len: 0 }
                    }
                    WireType::Len => {
                        let (len, used) = crate::varint::decode32(&bytes[offset..])
                            .ok_or_else(|| TreeError::malformed_at(offset))?;
                        offset =
                            offset.checked_add(used as usize).ok_or(TreeError::CapacityExceeded)?;
                        let used = u8::try_from(used).map_err(|_| TreeError::Corrupted)?;

                        let payload_start = offset;
                        let payload_end = payload_start
                            .checked_add(len as usize)
                            .ok_or(TreeError::CapacityExceeded)?;
                        if payload_end > bytes.len() {
                            return Err(TreeError::malformed_at(payload_start));
                        }
                        offset = payload_end;
                        let field = Span::new(field_start as u32, payload_end as u32)
                            .ok_or(TreeError::Corrupted)?;
                        StoredSpans { field, tag_len, aux_len: used, payload_len: len }
                    }
                    #[cfg(feature = "group")]
                    WireType::SGroup => {
                        let (field_number, _wire_type) = tag.split();
                        let body_start = offset;
                        let (end_tag_start, end_after) =
                            crate::wire::find_group_end(bytes, body_start, field_number)
                                .ok_or_else(|| TreeError::malformed_at(body_start))?;
                        offset = end_after;

                        let end_tag_len =
                            end_after.checked_sub(end_tag_start).ok_or(TreeError::Corrupted)?;
                        let end_tag_len =
                            u8::try_from(end_tag_len).map_err(|_| TreeError::Corrupted)?;
                        let field = Span::new(field_start as u32, end_after as u32)
                            .ok_or(TreeError::Corrupted)?;
                        StoredSpans { field, tag_len, aux_len: end_tag_len, payload_len: 0 }
                    }
                    #[cfg(feature = "group")]
                    WireType::EGroup => return Err(TreeError::malformed_at(field_start)),
                    WireType::I32 => {
                        let val_end = offset.checked_add(4).ok_or(TreeError::CapacityExceeded)?;
                        if val_end > bytes.len() {
                            return Err(TreeError::malformed_at(offset));
                        }
                        offset = val_end;
                        let field = Span::new(field_start as u32, val_end as u32)
                            .ok_or(TreeError::Corrupted)?;
                        StoredSpans { field, tag_len, aux_len: 0, payload_len: 0 }
                    }
                };

                let number = tag.field_number();
                let prev_by_num = self.query.get(&(msg_id, number)).and_then(|bucket| bucket.tail);
                let field_id = Self::alloc_field(
                    &mut self.fields,
                    &mut self.read_cache,
                    FieldNode {
                        msg: msg_id,
                        tag,
                        prev_by_num,
                        next_by_num: None,
                        raw_tag: RawVarint32::default(),
                        spans,
                        edit: None,
                        child: None,
                        deleted: false,
                    },
                )?;

                if let Some(prev) = prev_by_num {
                    let prev_idx = prev.as_inner() as usize;
                    let prev_node = self.fields.get_mut(prev_idx).ok_or(TreeError::Corrupted)?;
                    debug_assert_eq!(prev_node.next_by_num, None);
                    prev_node.next_by_num = Some(field_id);
                }

                let bucket = self.query.entry((msg_id, number)).or_default();
                debug_assert_eq!(bucket.tail, prev_by_num);
                debug_assert_eq!(bucket.head.is_none(), bucket.len == 0);
                if bucket.len == 0 {
                    bucket.head = Some(field_id);
                }
                bucket.tail = Some(field_id);
                bucket.len = bucket.len.checked_add(1).ok_or(TreeError::CapacityExceeded)?;
            }

            let fields_end =
                u32::try_from(self.fields.len()).map_err(|_| TreeError::CapacityExceeded)?;
            self.messages.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
            self.messages.push(MessageNode {
                source,
                parent_field,
                parsed: FieldRange { start: fields_start, end: fields_end },
                inserted: Vec::new(),
                subtree_dirty: false,
            });
            Ok(msg_id)
        })();

        match parsed {
            Ok(id) => Ok(id),
            Err(err) => {
                self.messages.truncate(orig_messages_len);
                self.fields.truncate(orig_fields_len);
                self.read_cache.truncate_fields(orig_fields_len);
                // Cold path: drop the failed message's index entries.
                self.query.retain(|(msg, _), _| (msg.as_inner() as usize) < orig_messages_len);
                Err(err)
            }
        }
    }

    pub(super) fn alloc_field(
        fields: &mut Vec<FieldNode>,
        read_cache: &mut super::ReadCache,
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
}
