use core::iter::FusedIterator;

use crate::{Tag, TreeError};

use super::{FieldId, MessageId, Patch};

/// Iterates over field ids matching one tag within one message.
#[derive(Clone)]
pub struct FieldsByTag<'a> {
    patch: &'a Patch,
    next: Option<FieldId>,
    remaining: u32,
}

impl Iterator for FieldsByTag<'_> {
    type Item = FieldId;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let field = self.next?;
        let field_idx = field.as_inner() as usize;
        let node = self.patch.fields.get(field_idx)?;
        self.next = node.next_by_tag;
        self.remaining = self.remaining.saturating_sub(1);
        Some(field)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining as usize;
        (len, Some(len))
    }
}

impl ExactSizeIterator for FieldsByTag<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.remaining as usize
    }
}
impl FusedIterator for FieldsByTag<'_> {}

impl Patch {
    pub fn fields_by_tag(&self, msg: MessageId, tag: Tag) -> Result<FieldsByTag<'_>, TreeError> {
        let msg = self.message(msg)?;
        let bucket = msg.query.get(&tag).copied().unwrap_or_default();
        Ok(FieldsByTag { patch: self, next: bucket.head, remaining: bucket.len })
    }
}
