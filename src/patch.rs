//! Span-based protobuf message patcher with lazy payload edits.
//!
//! This module builds a wire-level view of a protobuf message by eagerly scanning
//! fields and recording byte spans into the original input. Payload edits are
//! tracked separately and only materialized when saving, allowing unchanged
//! fields to be copied verbatim from the source bytes.

mod access;
mod edit;
mod ids;
mod model;
mod parse;
mod query;
mod save;
mod spans;
mod txn;

pub use access::MessageFields;
pub use ids::{FieldId, MessageId};
pub use model::{BorrowedPatch, Patch};
pub use query::FieldsByNumber;
pub use spans::{FieldSpans, Span, ValueSpans};
pub use txn::Txn;

pub(crate) use model::{
    FieldNode, FieldRange, MessageNode, MessageSource, PayloadEdit, ReadCache, TxnState,
    UndoAction, VarintEdit,
};
pub(crate) use spans::{slice_span, span_offset_by, value_spans_offset_by, StoredSpans};

/// Cold sink for `Patch`-invariant violations. Covers three families
/// that hold by construction and never depend on user input:
///
/// - spans re-derivation: spans were recorded by the parse pass over
///   these very bytes, and neither the spans nor the backing bytes
///   mutate afterwards (edits live in the side pool);
/// - internal ids: a `FieldId` from a live node's links or a message's
///   `field_ids()`, and a `MessageId` from `FieldNode::child` /
///   `Patch::root`, always index live arena slots (transaction rollback
///   truncates ids strictly newer than every surviving reference);
/// - edit-state coherence: a re-encoded field's `PayloadEdit` variant
///   matches its wire type (`set_edit_checked` gates every write).
///
/// Reaching this is a `Patch` bug, not an input condition: debug builds
/// panic, release builds prune the path.
#[inline(always)]
pub(crate) fn invariant_violated() -> ! {
    debug_assert!(false, "Patch invariant violated");
    // SAFETY: per the families above — established at construction and
    // preserved by every mutation path.
    unsafe { core::hint::unreachable_unchecked() }
}

#[cfg(test)]
mod tests;
