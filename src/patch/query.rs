use core::iter::FusedIterator;

use crate::error::TreeError;
use crate::wire::FieldNumber;

use super::{FieldId, MessageId, Patch};

/// Iterates over the live fields with one field number within one message.
///
/// Fields marked deleted are skipped; wire type is not part of the key, so
/// occurrences with different wire types appear in one chain in wire order.
#[derive(Clone)]
pub struct FieldsByNumber<'a> {
    patch: &'a Patch,
    next: Option<FieldId>,
    remaining: u32,
}

impl Iterator for FieldsByNumber<'_> {
    type Item = FieldId;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let field = self.next?;
            let field_idx = field.as_inner() as usize;
            let node = self.patch.fields.get(field_idx)?;
            self.next = node.next_by_num;
            self.remaining = self.remaining.saturating_sub(1);
            if !node.deleted {
                return Some(field);
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Deleted fields stay in the chain, so the length is only an upper
        // bound.
        (0, Some(self.remaining as usize))
    }
}

impl FusedIterator for FieldsByNumber<'_> {}

impl Patch {
    /// Live fields with `number` in `msg`, in wire order.
    ///
    /// # Errors
    /// `InvalidId` if `msg` does not refer to a live message.
    pub fn fields_by_number(
        &self,
        msg: MessageId,
        number: FieldNumber,
    ) -> Result<FieldsByNumber<'_>, TreeError> {
        let _ = self.message(msg)?;
        let bucket = self.query.get(&(msg, number)).copied().unwrap_or_default();
        Ok(FieldsByNumber { patch: self, next: bucket.head, remaining: bucket.len })
    }
}
