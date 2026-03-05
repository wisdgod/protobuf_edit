use crate::document::RawVarint32;
use crate::error::TreeError;
use crate::wire::{Tag, WireType};
use crate::Buf;

use super::{FieldId, FieldNode, MessageId, Patch, PayloadEdit, TagBucket, UndoAction, VarintEdit};

impl Patch {
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
}
