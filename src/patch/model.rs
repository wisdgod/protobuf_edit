use alloc::vec::Vec;
use core::cell::Cell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};

use crate::document::{RawVarint32, RawVarint64};
use crate::error::TreeError;
use crate::fx::FxHashMap;
use crate::wire::Tag;
use crate::Buf;

use super::{FieldId, MessageId, StoredSpans};

/// Span-aware message patch rooted at a source buffer.
///
/// `Patch::from_bytes` clones the input bytes into an owned `Buf`. For a
/// lifetime-bound zero-copy view, use `BorrowedPatch`.
pub struct Patch {
    pub(crate) root: MessageId,
    pub(crate) source: Buf,
    pub(crate) messages: Vec<MessageNode>,
    pub(crate) fields: Vec<FieldNode>,
    pub(crate) read_cache: ReadCache,
    pub(crate) txn: Option<TxnState>,
}

#[derive(Clone, Default)]
pub(crate) struct ReadCache {
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
        for _ in 0..fields_len {
            self.varints.push(Cell::new(None));
        }
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
        self.varints.get(field_idx).and_then(|cell| cell.get())
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

#[derive(Clone)]
pub(crate) struct MessageNode {
    pub(crate) source: MessageSource,
    pub(crate) parent_field: Option<FieldId>,
    pub(crate) fields_in_order: Vec<FieldId>,
    pub(crate) query: FxHashMap<Tag, TagBucket>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct TagBucket {
    pub(crate) head: Option<FieldId>,
    pub(crate) tail: Option<FieldId>,
    pub(crate) len: u32,
}

#[derive(Clone)]
pub(crate) enum MessageSource {
    Root { start: u32, end: u32 },
    Owned { bytes: Buf },
}

impl MessageSource {
    pub(crate) fn bytes<'a>(&'a self, root: &'a [u8]) -> &'a [u8] {
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
pub(crate) struct FieldNode {
    pub(crate) msg: MessageId,
    pub(crate) tag: Tag,
    pub(crate) prev_by_tag: Option<FieldId>,
    pub(crate) next_by_tag: Option<FieldId>,
    pub(crate) raw_tag: RawVarint32,
    pub(crate) spans: Option<StoredSpans>,
    pub(crate) edit: Option<PayloadEdit>,
    pub(crate) child: Option<MessageId>,
    pub(crate) deleted: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct VarintEdit {
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
pub(crate) enum PayloadEdit {
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
pub(crate) enum UndoAction {
    FieldEdit { field: FieldId, prev: Option<PayloadEdit> },
    FieldDeleted { field: FieldId, prev: bool },
    FieldChild { field: FieldId, prev: Option<MessageId> },
    InsertField { msg: MessageId, field: FieldId },
}

#[derive(Clone)]
pub(crate) struct TxnState {
    pub(crate) orig_messages_len: usize,
    pub(crate) orig_fields_len: usize,
    pub(crate) undo_log: Vec<UndoAction>,
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
