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

pub use ids::{FieldId, MessageId};
pub use model::{BorrowedPatch, Patch};
pub use query::FieldsByTag;
pub use spans::{FieldSpans, Span, ValueSpans};
pub use txn::Txn;

pub(crate) use model::{
    FieldNode, MessageNode, MessageSource, PayloadEdit, ReadCache, TagBucket, TxnState, UndoAction,
    VarintEdit,
};
pub(crate) use spans::{slice_span, span_offset_by, value_spans_offset_by, StoredSpans};

#[cfg(test)]
mod tests;
