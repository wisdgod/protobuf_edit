use crate::wire::{Tag, WireType};

use super::{FieldMut, FieldRef, Link, Document, TreeError};

/// Iterator over live repeated fields for one tag, in insertion order.
pub struct RepeatedRefIter<'a> {
    tree: &'a Document,
    next: Link,
}

impl<'a> RepeatedRefIter<'a> {
    #[inline]
    pub(super) const fn new(tree: &'a Document, next: Link) -> Self {
        Self { tree, next }
    }
}

impl<'a> Iterator for RepeatedRefIter<'a> {
    type Item = FieldRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(ix) = self.next {
            // SAFETY: `ix` comes from the linked-list we maintain.
            let field = unsafe { self.tree.field_unchecked(ix) };
            self.next = field.next;
            if field.removed {
                continue;
            }
            // SAFETY: `ix` comes from the linked-list we maintain.
            return Some(unsafe { FieldRef::new_unchecked(self.tree, ix) });
        }
        None
    }
}

impl Document {
    #[inline]
    pub fn repeated_refs(&self, tag: Tag) -> RepeatedRefIter<'_> {
        let next = self.bucket(tag).and_then(|bucket| bucket.head);
        RepeatedRefIter::new(self, next)
    }

    #[inline]
    pub fn repeated_refs_by_parts(
        &self,
        field_number: u32,
        wire_type: WireType,
    ) -> Option<RepeatedRefIter<'_>> {
        let tag = Tag::try_from_parts(field_number, wire_type)?;
        Some(self.repeated_refs(tag))
    }

    pub fn repeated_visit_mut(
        &mut self,
        tag: Tag,
        mut f: impl FnMut(FieldMut<'_>) -> Result<(), TreeError>,
    ) -> Result<(), TreeError> {
        let mut cursor = self.bucket(tag).and_then(|bucket| bucket.head);
        while let Some(ix) = cursor {
            cursor = self.fields[ix.as_inner() as usize].next;
            let field = self.field_mut(ix).expect("linked-list ix is guaranteed to be valid");
            f(field)?;
        }
        Ok(())
    }

    pub fn repeated_visit_mut_by_parts(
        &mut self,
        field_number: u32,
        wire_type: WireType,
        f: impl FnMut(FieldMut<'_>) -> Result<(), TreeError>,
    ) -> Result<(), TreeError> {
        let tag = Tag::try_from_parts(field_number, wire_type).ok_or(TreeError::InvalidTag)?;
        self.repeated_visit_mut(tag, f)?;
        Ok(())
    }
}
