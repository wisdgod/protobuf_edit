//! The grouped markup's transfer siblings.
//!
//! The same editing markup faces plus whole-record relocation and
//! external import, emitted as their own machines so the base
//! markup pays none of the capability's carried state or dispatch.
//!
//! Two machines split the payload-backing policies exactly like the
//! base siblings: [`TransferMarkup`] copies payloads and imported
//! records into its store (no payload lifetime binds the caller),
//! and [`TransferBorrowMarkup`] retains borrowed payload slices
//! and borrowed imported records — every owner must outlive the
//! machine. Both add the transfer faces: `copy_record` and
//! `move_record` relocate whole designated records, `copy_payload`
//! and `move_payload` relocate LEN interiors, and
//! `copy_record_from` imports one designated external record. A
//! move is one command, one pending step, one revert. The transfer
//! algebra rides its own edit states; the store forms, coordinate
//! classes, handles, and anchors are the base markup's, shared
//! unchanged.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::markup::transfer::{Edit, Transition};
use crate::markup::{At32, BorrowStore, Handle, RowId, Store, StoreFault, ValueAt, admit};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
pub use crate::markup::command::InsertAt;
pub use crate::markup::transfer::{EditStatus, PayloadTarget};

#[cfg(test)]
mod tests;

crate::revise::grouped::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        OpenFault, RecordSpans, SaveFault, SaveSpans,
    ),
    capability: transfer,
    tenure: borrow,
    acceptance: tolerant,
    product: vec,
    Machine: TransferMarkup,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "TransferMarkup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing markup with the transfer capability over one"]
    #[doc = " borrowed slice."]
    #[doc = ""]
    #[doc = " [`Markup`](super::Markup)'s faces plus whole-record"]
    #[doc = " relocation, payload relocation, and external import, with"]
    #[doc = " payloads and imported records copied into the machine at"]
    #[doc = " the command — temporaries welcome, no payload lifetime on"]
    #[doc = " the type."]
    #[doc = ""]
    #[doc = " Handles stay valid for the markup's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: every command logs one step — a move included — and"]
    #[doc = " [`TransferMarkup::revert`] restores the save-observable state"]
    #[doc = " of the previous step."]
    machine TransferMarkup<'m> { source: &'m [u8] }
    capability: transfer,
    tenure: borrow,
    acceptance: tolerant,
    product: vec,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "TransferMarkup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    views,
    Machine: TransferMarkup,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "TransferMarkup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing markup with the transfer capability, with"]
    #[doc = " borrowed payloads."]
    #[doc = ""]
    #[doc = " [`TransferMarkup`]'s sibling for callers whose payload"]
    #[doc = " bytes outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload`, `insert_payload`, and `copy_record_from` take"]
    #[doc = " `&'p [u8]` and retain the slice — no staging copy — as a"]
    #[doc = " fresh immutable slot per install; earlier installs keep"]
    #[doc = " their slots, so a revert restores the exact prior state."]
    #[doc = " Every payload and imported-record owner must outlive the"]
    #[doc = " markup, and `'p` rides the type beside the source borrow."]
    #[doc = " Everything else is [`TransferMarkup`]'s contract."]
    machine TransferBorrowMarkup<'m, 'p> { source: &'m [u8] }
    capability: transfer,
    payload: borrow,
    tenure: borrow,
    acceptance: tolerant,
    product: vec,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "TransferBorrowMarkup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped::transfer",
}

// The machine layouts, pinned exactly on every pointer width:
// the transfer twins
// carry the base machines' fields over the same stores, so the
// absolutes match the base pins; any drift lands here for review.
const _: () = assert!(
    core::mem::size_of::<TransferMarkup<'_>>() == core::mem::size_of::<super::Markup<'_>>()
);
const _: () = assert!(
    core::mem::size_of::<TransferBorrowMarkup<'_, '_>>()
        == core::mem::size_of::<super::BorrowMarkup<'_, '_>>()
);

crate::revise::grouped::revising_machine! {
    frames for TransferMarkup<'m> (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "TransferMarkup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped::transfer",
    frame_doc: [],
    sized_doc: [],
}
