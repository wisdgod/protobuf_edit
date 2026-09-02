//! The groupless draft's transfer siblings.
//!
//! The same editing draft faces plus whole-record relocation and
//! external import, emitted as their own machines so the base
//! draft pays none of the capability's carried state or dispatch.
//!
//! Two machines split the payload-backing policies exactly like the
//! base siblings: [`TransferDraft`] copies payloads and imported
//! records into its store (no payload lifetime binds the caller),
//! and [`TransferBorrowDraft`] retains borrowed payload slices
//! and borrowed imported records — every owner must outlive the
//! machine. Both add the transfer faces: `copy_record` and
//! `move_record` relocate whole designated records, `copy_payload`
//! and `move_payload` relocate LEN interiors, and
//! `copy_record_from` imports one designated external record. A
//! move is one command, one pending step, one revert. The transfer
//! algebra rides its own edit states; the store forms, coordinate
//! classes, handles, and anchors are the base draft's, shared
//! unchanged.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::draft::transfer::{Edit, Transition};
use crate::draft::{At32, BorrowStore, Handle, RowId, Store, StoreFault, ValueAt, admit};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
pub use crate::draft::command::InsertAt;
pub use crate::draft::transfer::{EditStatus, PayloadTarget};

#[cfg(test)]
mod tests;

crate::revise::groupless::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        OpenFault, RecordSpans, Refusal, SaveFault, SaveSpans,
    ),
    capability: transfer,
    tenure: vec,
    acceptance: tolerant,
    product: vec,
    Machine: TransferDraft,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "TransferDraft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::groupless::transfer",
}

crate::revise::groupless::revising_machine! {
    #[doc = " An editing draft with the transfer capability over one"]
    #[doc = " moved-in buffer."]
    #[doc = ""]
    #[doc = " [`Draft`](super::Draft)'s faces plus whole-record"]
    #[doc = " relocation, payload relocation, and external import, with"]
    #[doc = " payloads and imported records copied into the machine at"]
    #[doc = " the command — temporaries welcome, no payload lifetime on"]
    #[doc = " the type."]
    #[doc = ""]
    #[doc = " Handles stay valid for the draft's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: every command logs one step — a move included — and"]
    #[doc = " [`TransferDraft::revert`] restores the save-observable state"]
    #[doc = " of the previous step."]
    machine TransferDraft { source: Vec<u8> }
    capability: transfer,
    tenure: vec,
    acceptance: tolerant,
    product: vec,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "TransferDraft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::groupless::transfer",
}

crate::revise::groupless::revising_machine! {
    views,
    Machine: TransferDraft,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "TransferDraft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::groupless::transfer",
}

crate::revise::groupless::revising_machine! {
    #[doc = " An editing draft with the transfer capability, with"]
    #[doc = " borrowed payloads."]
    #[doc = ""]
    #[doc = " [`TransferDraft`]'s sibling for callers whose payload"]
    #[doc = " bytes outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload`, `insert_payload`, and `copy_record_from` take"]
    #[doc = " `&'p [u8]` and retain the slice — no staging copy — as a"]
    #[doc = " fresh immutable slot per install; earlier installs keep"]
    #[doc = " their slots, so a revert restores the exact prior state."]
    #[doc = " Every payload and imported-record owner must outlive the"]
    #[doc = " draft, and `'p` rides the type beside the moved-in source."]
    #[doc = " Everything else is [`TransferDraft`]'s contract."]
    machine TransferBorrowDraft<'p> { source: Vec<u8> }
    capability: transfer,
    payload: borrow,
    tenure: vec,
    acceptance: tolerant,
    product: vec,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "TransferBorrowDraft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::groupless::transfer",
}

// The machine layouts, pinned exactly on every pointer width:
// the transfer twins
// carry the base machines' fields over the same stores, so the
// absolutes match the base pins; any drift lands here for review.
const _: () =
    assert!(core::mem::size_of::<TransferDraft>() == core::mem::size_of::<super::Draft>());
const _: () = assert!(
    core::mem::size_of::<TransferBorrowDraft<'_>>()
        == core::mem::size_of::<super::BorrowDraft<'_>>()
);

crate::revise::groupless::revising_machine! {
    frames for TransferDraft (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "TransferDraft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::groupless::transfer",
    frame_doc: [],
    sized_doc: [],
}
