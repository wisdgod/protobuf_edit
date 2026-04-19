use core::mem;
use core::ops::{Deref, DerefMut};

use crate::buf::Buf;

use super::{Capacities, Document, Ix, RawVarint32, TreeError};

#[derive(Clone, Copy)]
enum PayloadKind {
    Len,
    #[cfg(feature = "group")]
    Group,
}

/// RAII guard for editing a nested protobuf message without closures.
///
/// Created by `FieldMut::decode_message`. The guard decodes the nested payload
/// and exposes it as a `Document` via `Deref`/`DerefMut`. Call `finish()` to
/// re-encode the modified document back into the parent. Dropping without
/// `finish()` restores the original bytes.
pub struct MessageGuard<'a> {
    // SAFETY: field order matters for drop. `doc` contains Bufs that may borrow
    // from `source`. Rust drops fields in declaration order, so `doc` drops
    // first (releasing borrowed pointers), then `source` drops (freeing the
    // backing memory).
    doc: Document,
    source: Buf,
    parent: &'a mut Document,
    slot: Ix,
    kind: PayloadKind,
    finished: bool,
}

impl<'a> MessageGuard<'a> {
    /// Construct a guard by swapping out the parent's lendel buffer.
    ///
    /// # Safety
    /// `slot` must be a valid index into `parent.lendels`.
    pub(super) unsafe fn new(
        parent: &'a mut Document,
        slot: Ix,
        capacities: Option<Capacities>,
    ) -> Result<Self, TreeError> {
        let lendel = parent.lendel_unchecked_mut(slot);
        let mut source = mem::take(&mut lendel.buf);
        // `from_bytes_borrowed` stores raw pointers into `source`. If `source`
        // uses inline storage, those pointers become dangling when this struct
        // is moved (the inline bytes live inside the Buf union itself). Force
        // spill to heap so the backing memory address is move-stable.
        if source.ensure_heap().is_err() {
            parent.lendel_unchecked_mut(slot).buf = source;
            return Err(TreeError::CapacityExceeded);
        }

        match Document::from_bytes_borrowed(source.as_slice(), capacities) {
            Ok(doc) => {
                Ok(Self { doc, source, parent, slot, kind: PayloadKind::Len, finished: false })
            }
            Err(e) => {
                parent.lendel_unchecked_mut(slot).buf = source;
                Err(e)
            }
        }
    }

    #[cfg(feature = "group")]
    /// Construct a guard by swapping out the parent's group buffer.
    ///
    /// # Safety
    /// `slot` must be a valid index into `parent.groups`.
    pub(super) unsafe fn new_group(
        parent: &'a mut Document,
        slot: Ix,
        capacities: Option<Capacities>,
    ) -> Result<Self, TreeError> {
        let group = parent.group_unchecked_mut(slot);
        let mut source = mem::take(&mut group.buf);
        if source.ensure_heap().is_err() {
            parent.group_unchecked_mut(slot).buf = source;
            return Err(TreeError::CapacityExceeded);
        }

        match Document::from_bytes_borrowed(source.as_slice(), capacities) {
            Ok(doc) => {
                Ok(Self { doc, source, parent, slot, kind: PayloadKind::Group, finished: false })
            }
            Err(e) => {
                parent.group_unchecked_mut(slot).buf = source;
                Err(e)
            }
        }
    }

    /// Re-encode the modified document and write it back to the parent field.
    pub fn finish(mut self) -> Result<(), TreeError> {
        self.finish_inner()?;
        self.finished = true;
        Ok(())
    }

    fn finish_inner(&mut self) -> Result<(), TreeError> {
        let encoded = self.doc.to_buf()?;
        match self.kind {
            PayloadKind::Len => {
                // SAFETY: slot validity is guaranteed by construction.
                let lendel = unsafe { self.parent.lendel_unchecked_mut(self.slot) };
                lendel.buf = encoded;
                lendel.raw = RawVarint32::from_u32(lendel.buf.len());
            }
            #[cfg(feature = "group")]
            PayloadKind::Group => {
                // SAFETY: slot validity is guaranteed by construction.
                unsafe { self.parent.group_unchecked_mut(self.slot) }.buf = encoded;
            }
        }
        Ok(())
    }

    fn restore(&mut self) {
        let source = mem::take(&mut self.source);
        match self.kind {
            PayloadKind::Len => {
                // SAFETY: slot validity is guaranteed by construction.
                let lendel = unsafe { self.parent.lendel_unchecked_mut(self.slot) };
                lendel.buf = source;
            }
            #[cfg(feature = "group")]
            PayloadKind::Group => {
                // SAFETY: slot validity is guaranteed by construction.
                unsafe { self.parent.group_unchecked_mut(self.slot) }.buf = source;
            }
        }
    }
}

impl Deref for MessageGuard<'_> {
    type Target = Document;

    #[inline]
    fn deref(&self) -> &Document {
        &self.doc
    }
}

impl DerefMut for MessageGuard<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Document {
        &mut self.doc
    }
}

impl Drop for MessageGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.restore();
        }
    }
}
