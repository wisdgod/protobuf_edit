//! The groupless review's transfer siblings.
//!
//! The same editing review faces plus whole-record relocation and
//! external import, emitted as their own machines so the base
//! review pays none of the capability's carried state or dispatch.
//!
//! Two machines split the payload-backing policies exactly like the
//! base siblings: [`TransferReview`] copies payloads and imported
//! records into its store (no payload lifetime binds the caller),
//! and [`TransferBorrowReview`] retains borrowed payload slices
//! and borrowed imported records — every owner must outlive the
//! machine. Both add the transfer faces: `copy_record` and
//! `move_record` relocate whole designated records, `copy_payload`
//! and `move_payload` relocate LEN interiors, and
//! `copy_record_from` imports one designated external record. A
//! move is one command, one pending step, one revert. The transfer
//! algebra rides its own edit states; the store forms, coordinate
//! classes, handles, and anchors are the base review's, shared
//! unchanged.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::review::transfer::{Edit, Transition};
use crate::review::{At32, BorrowStore, Handle, RowId, Store, StoreFault, ValueAt, admit};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
pub use crate::review::command::InsertAt;
pub use crate::review::transfer::{EditStatus, PayloadTarget};

#[cfg(test)]
mod tests;

crate::revise::groupless::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        OpenFault, RecordSpans, Refusal, SaveFault, SaveSpans,
    ),
    capability: transfer,
    tenure: borrow,
    acceptance: canonical,
    product: vec,
    Machine: TransferReview,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "TransferReview::open(&msg)",
    doc_mod: "protobuf_edit::review::groupless::transfer",
}

crate::revise::groupless::revising_machine! {
    #[doc = " An editing review with the transfer capability over one"]
    #[doc = " borrowed slice."]
    #[doc = ""]
    #[doc = " [`Review`](super::Review)'s faces plus whole-record"]
    #[doc = " relocation, payload relocation, and external import, with"]
    #[doc = " payloads and imported records copied into the machine at"]
    #[doc = " the command — temporaries welcome, no payload lifetime on"]
    #[doc = " the type."]
    #[doc = ""]
    #[doc = " Handles stay valid for the review's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: every command logs one step — a move included — and"]
    #[doc = " [`TransferReview::revert`] restores the save-observable state"]
    #[doc = " of the previous step."]
    machine TransferReview<'m> { source: &'m [u8] }
    capability: transfer,
    tenure: borrow,
    acceptance: canonical,
    product: vec,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "TransferReview::open(&msg)",
    doc_mod: "protobuf_edit::review::groupless::transfer",
}

crate::revise::groupless::revising_machine! {
    views,
    Machine: TransferReview,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "TransferReview::open(&msg)",
    doc_mod: "protobuf_edit::review::groupless::transfer",
}

crate::revise::groupless::revising_machine! {
    #[doc = " An editing review with the transfer capability, with"]
    #[doc = " borrowed payloads."]
    #[doc = ""]
    #[doc = " [`TransferReview`]'s sibling for callers whose payload"]
    #[doc = " bytes outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload`, `insert_payload`, and `copy_record_from` take"]
    #[doc = " `&'p [u8]` and retain the slice — no staging copy — as a"]
    #[doc = " fresh immutable slot per install; earlier installs keep"]
    #[doc = " their slots, so a revert restores the exact prior state."]
    #[doc = " Every payload and imported-record owner must outlive the"]
    #[doc = " review, and `'p` rides the type beside the source borrow."]
    #[doc = " Everything else is [`TransferReview`]'s contract."]
    machine TransferBorrowReview<'m, 'p> { source: &'m [u8] }
    capability: transfer,
    payload: borrow,
    tenure: borrow,
    acceptance: canonical,
    product: vec,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "TransferBorrowReview::open(&msg)",
    doc_mod: "protobuf_edit::review::groupless::transfer",
}

// The machine layouts, pinned exactly on every pointer width:
// the transfer twins
// carry the base machines' fields over the same stores, so the
// absolutes match the base pins; any drift lands here for review.
const _: () = assert!(
    core::mem::size_of::<TransferReview<'_>>() == core::mem::size_of::<super::Review<'_>>()
);
const _: () = assert!(
    core::mem::size_of::<TransferBorrowReview<'_, '_>>()
        == core::mem::size_of::<super::BorrowReview<'_, '_>>()
);

crate::revise::groupless::revising_machine! {
    frames for TransferReview<'m> (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "TransferReview::open(&msg)",
    doc_mod: "protobuf_edit::review::groupless::transfer",
    frame_doc: [],
    sized_doc: [],
}
