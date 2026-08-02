use alloc::vec::Vec;
use core::cell::Cell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::document::{RawVarint32, RawVarint64};
use crate::error::TreeError;
use crate::fx::FxHashMap;
use crate::wire::{FieldNumber, Tag};
use crate::Buf;

use super::{FieldId, MessageId, StoredSpans};

define_valid_range_type!(
    /// Index into the payload-edit side pool.
    ///
    /// `u32::MAX` is reserved as `Option<EditIx>::None`.
    pub(crate) struct EditIx(u32 as u32 in 0..=4_294_967_294);
);

/// Span-aware message patch rooted at a source buffer.
///
/// `Patch::from_bytes` clones the input bytes into an owned `Buf`. For a
/// lifetime-bound zero-copy view, use `BorrowedPatch`.
pub struct Patch {
    pub(crate) root: MessageId,
    pub(crate) source: Buf,
    pub(crate) messages: Vec<MessageNode>,
    pub(crate) fields: Vec<FieldNode>,
    /// Payload-edit side pool referenced by `FieldNode::edit`.
    ///
    /// Slots orphaned by replaced or cleared edits stay allocated until the
    /// `Patch` drops; they are 32-byte values bounded by user edit actions.
    pub(crate) edits: Vec<PayloadEdit>,
    /// Shared field-number index: one map per `Patch` instead of one per
    /// message. Chains link fields with the same number regardless of wire
    /// type (the number is the field's identity; the wire type is its
    /// representation).
    pub(crate) query: FxHashMap<(MessageId, FieldNumber), NumBucket>,
    pub(crate) read_cache: ReadCache,
    pub(crate) txn: Option<TxnState>,
}

impl Patch {
    /// Resolves a field's payload edit from the side pool.
    #[inline]
    pub(crate) fn field_edit(&self, node: &FieldNode) -> Option<&PayloadEdit> {
        node.edit.map(|ix| &self.edits[ix.as_inner() as usize])
    }

    /// Stores `value` into the side pool for a field currently at `slot`.
    ///
    /// Overwrites the current slot in place when that cannot break undo:
    /// either no transaction is active, or the slot was created inside the
    /// active transaction (pre-transaction slot values must survive for
    /// rollback). Returns the new slot index.
    pub(crate) fn store_edit(
        edits: &mut Vec<PayloadEdit>,
        txn: Option<&TxnState>,
        slot: Option<EditIx>,
        value: PayloadEdit,
    ) -> Result<EditIx, TreeError> {
        if let Some(ix) = slot {
            let idx = ix.as_inner() as usize;
            let in_place = txn.is_none_or(|state| idx >= state.orig_edits_len);
            if in_place {
                edits[idx] = value;
                return Ok(ix);
            }
        }
        let next = edits.len();
        let Some(ix) = u32::try_from(next).ok().and_then(EditIx::new) else {
            return Err(TreeError::CapacityExceeded);
        };
        edits.try_reserve(1).map_err(|_| TreeError::CapacityExceeded)?;
        edits.push(value);
        Ok(ix)
    }
}

#[derive(Clone, Default)]
pub struct ReadCache {
    pub(crate) enabled: bool,
    pub(crate) varints: Vec<Cell<Option<u64>>>,
}

impl ReadCache {
    pub(crate) fn enable(&mut self, fields_len: usize) -> Result<(), TreeError> {
        if self.enabled {
            return Ok(());
        }
        self.varints.clear();
        self.varints.try_reserve(fields_len).map_err(|_| TreeError::CapacityExceeded)?;
        self.varints.resize(fields_len, Cell::new(None));
        self.enabled = true;
        Ok(())
    }

    pub(crate) fn disable(&mut self) {
        self.enabled = false;
        self.varints.clear();
    }

    pub(crate) fn truncate_fields(&mut self, fields_len: usize) {
        if !self.enabled {
            return;
        }
        self.varints.truncate(fields_len);
    }

    pub(crate) fn get_varint(&self, field_idx: usize) -> Option<u64> {
        if !self.enabled {
            return None;
        }
        self.varints.get(field_idx).and_then(core::cell::Cell::get)
    }

    pub(crate) fn set_varint(&self, field_idx: usize, value: u64) {
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

/// Contiguous arena id range `[start, end)` of one message's parsed fields.
///
/// Valid because `parse_message_node` allocates a message's fields
/// consecutively in the shared arena.
#[derive(Clone, Copy)]
pub(crate) struct FieldRange {
    pub(crate) start: u32,
    pub(crate) end: u32,
}

#[derive(Clone)]
pub struct MessageNode {
    pub(crate) source: MessageSource,
    pub(crate) parent_field: Option<FieldId>,
    /// Fields created by the parse pass.
    pub(crate) parsed: FieldRange,
    /// Fields inserted after parse, in insertion order. `Vec::new()` never
    /// allocates, so only messages that actually receive inserts pay for one.
    pub(crate) inserted: Vec<FieldId>,
}

/// Head/tail links and length of one same-field-number chain.
#[derive(Clone, Copy, Default)]
pub struct NumBucket {
    pub(crate) head: Option<FieldId>,
    pub(crate) tail: Option<FieldId>,
    pub(crate) len: u32,
}

#[derive(Clone)]
pub enum MessageSource {
    Root { start: u32, end: u32 },
    Owned { bytes: Buf },
}

impl MessageSource {
    pub(crate) fn bytes<'a>(&'a self, root: &'a [u8]) -> &'a [u8] {
        match self {
            Self::Root { start, end } => {
                let start = *start as usize;
                let end = *end as usize;
                &root[start..end]
            }
            Self::Owned { bytes } => bytes.as_slice(),
        }
    }
}

#[derive(Clone)]
pub struct FieldNode {
    pub(crate) msg: MessageId,
    pub(crate) tag: Tag,
    /// Previous field with the same field number in the same message.
    pub(crate) prev_by_num: Option<FieldId>,
    /// Next field with the same field number in the same message.
    pub(crate) next_by_num: Option<FieldId>,
    pub(crate) raw_tag: RawVarint32,
    /// Recorded wire spans; `StoredSpans::EMPTY` for inserted fields.
    pub(crate) spans: StoredSpans,
    /// Slot in the `Patch::edits` side pool, if this field has an overlay.
    pub(crate) edit: Option<EditIx>,
    pub(crate) child: Option<MessageId>,
    pub(crate) deleted: bool,
}

impl FieldNode {
    /// Recorded spans, or `None` for fields inserted after parse.
    #[inline]
    pub(crate) fn spans(&self) -> Option<StoredSpans> {
        self.spans.to_opt()
    }
}

const _: () = {
    assert!(core::mem::size_of::<FieldNode>() == 48);
};

#[derive(Clone, Copy)]
pub struct VarintEdit {
    pub(crate) value: u64,
    pub(crate) raw: RawVarint64,
}

impl VarintEdit {
    #[inline]
    pub(crate) fn new(value: u64) -> Self {
        Self { value, raw: RawVarint64::from_u64(value) }
    }
}

#[derive(Clone)]
pub enum PayloadEdit {
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
    #[must_use]
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

#[derive(Clone, Copy)]
pub enum UndoAction {
    FieldEdit { field: FieldId, prev: Option<EditIx> },
    FieldDeleted { field: FieldId, prev: bool },
    FieldChild { field: FieldId, prev: Option<MessageId> },
    InsertField { msg: MessageId, field: FieldId },
}

#[derive(Clone)]
pub struct TxnState {
    pub(crate) orig_messages_len: usize,
    pub(crate) orig_fields_len: usize,
    pub(crate) orig_edits_len: usize,
    pub(crate) undo_log: Vec<UndoAction>,
}

impl Clone for Patch {
    fn clone(&self) -> Self {
        Self {
            root: self.root,
            source: self.source.clone(),
            messages: self.messages.clone(),
            fields: self.fields.clone(),
            edits: self.edits.clone(),
            query: self.query.clone(),
            read_cache: self.read_cache.clone(),
            txn: None,
        }
    }
}
