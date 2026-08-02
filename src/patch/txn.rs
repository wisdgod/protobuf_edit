use alloc::vec::Vec;

use super::{Patch, TxnState, UndoAction};

/// Transaction that rolls back on drop unless committed.
pub struct Txn<'a> {
    tree: &'a mut Patch,
    committed: bool,
}

impl<'a> Txn<'a> {
    pub fn begin(tree: &'a mut Patch) -> Self {
        tree.txn_begin();
        Self { tree, committed: false }
    }

    #[inline]
    pub const fn tree(&mut self) -> &mut Patch {
        self.tree
    }

    pub fn commit(mut self) {
        self.tree.txn_commit();
        self.committed = true;
    }

    pub fn rollback(mut self) {
        self.tree.txn_rollback();
        self.committed = true;
    }
}

impl Drop for Txn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.tree.txn_rollback();
        }
    }
}

impl Patch {
    /// Returns whether a transaction is active.
    #[inline]
    #[must_use]
    pub const fn txn_active(&self) -> bool {
        self.txn.is_some()
    }

    /// Begins a transaction.
    ///
    /// Panics if a transaction is already active.
    pub fn txn_begin(&mut self) {
        self.txn_begin_impl();
    }

    /// Commits the active transaction.
    pub fn txn_commit(&mut self) {
        self.txn_commit_impl();
    }

    /// Rolls back the active transaction.
    pub fn txn_rollback(&mut self) {
        self.txn_rollback_impl();
    }

    fn txn_begin_impl(&mut self) {
        assert!(self.txn.is_none(), "nested Patch txn is not supported");
        self.txn = Some(TxnState {
            orig_messages_len: self.messages.len(),
            orig_fields_len: self.fields.len(),
            orig_edits_len: self.edits.len(),
            undo_log: Vec::new(),
        });
    }

    fn txn_commit_impl(&mut self) {
        let _ = self.txn.take();
    }

    fn txn_rollback_impl(&mut self) {
        let Some(state) = self.txn.take() else {
            return;
        };

        for action in state.undo_log.into_iter().rev() {
            match action {
                UndoAction::FieldEdit { field, prev } => {
                    let idx = field.as_inner() as usize;
                    if let Some(node) = self.fields.get_mut(idx) {
                        node.edit = prev;
                    } else {
                        debug_assert!(false, "txn undo field edit out of bounds");
                    }
                }
                UndoAction::FieldDeleted { field, prev } => {
                    let idx = field.as_inner() as usize;
                    if let Some(node) = self.fields.get_mut(idx) {
                        node.deleted = prev;
                    } else {
                        debug_assert!(false, "txn undo field deleted out of bounds");
                    }
                }
                UndoAction::FieldChild { field, prev } => {
                    let idx = field.as_inner() as usize;
                    if let Some(node) = self.fields.get_mut(idx) {
                        node.child = prev;
                    } else {
                        debug_assert!(false, "txn undo field child out of bounds");
                    }
                }
                UndoAction::InsertField { msg, field } => {
                    let field_idx = field.as_inner() as usize;
                    let Some(field_node) = self.fields.get(field_idx) else {
                        debug_assert!(false, "txn undo insert field out of bounds");
                        continue;
                    };
                    let number = field_node.tag.field_number();
                    let prev_by_num = field_node.prev_by_num;

                    let msg_idx = msg.as_inner() as usize;
                    let Some(msg_node) = self.messages.get_mut(msg_idx) else {
                        debug_assert!(false, "txn undo insert msg out of bounds");
                        continue;
                    };

                    let popped = msg_node.fields_in_order.pop();
                    debug_assert_eq!(popped, Some(field), "txn undo insert order mismatch");

                    let should_remove = if let Some(bucket) = self.query.get_mut(&(msg, number)) {
                        debug_assert_eq!(bucket.tail, Some(field), "txn undo query tail mismatch");
                        debug_assert!(bucket.len > 0, "txn undo query len underflow");

                        if let Some(prev) = prev_by_num {
                            let prev_idx = prev.as_inner() as usize;
                            if let Some(prev_node) = self.fields.get_mut(prev_idx) {
                                prev_node.next_by_num = None;
                            } else {
                                debug_assert!(false, "txn undo prev_by_num out of bounds");
                            }
                        } else {
                            bucket.head = None;
                        }
                        bucket.tail = prev_by_num;
                        bucket.len -= 1;
                        bucket.len == 0
                    } else {
                        debug_assert!(false, "txn undo query bucket missing");
                        false
                    };
                    if should_remove {
                        let _ = self.query.remove(&(msg, number));
                    }
                }
            }
        }

        self.messages.truncate(state.orig_messages_len);
        self.fields.truncate(state.orig_fields_len);
        // Pre-transaction slots were never overwritten in place (see
        // `Patch::store_edit`), so restored `edit` indices still hold their
        // original values; transaction-era slots are reclaimed here.
        self.edits.truncate(state.orig_edits_len);
        // Index entries for child messages parsed during the transaction die
        // with their messages; surviving messages' buckets were already
        // restored by the undo log above. Cold path.
        let orig_messages_len = state.orig_messages_len;
        self.query.retain(|(msg, _), _| (msg.as_inner() as usize) < orig_messages_len);
        self.read_cache.truncate_fields(state.orig_fields_len);
    }
}
