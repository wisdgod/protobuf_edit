//! The grouped session's transfer siblings.
//!
//! The same editing session faces plus whole-record relocation and
//! external import, emitted as their own machines so the base
//! session pays none of the capability's carried state or
//! dispatch.
//!
//! Two machines split the payload-backing policies exactly like the
//! base siblings: [`TransferSession`] copies payloads and imported
//! records into its store (no payload lifetime binds the caller),
//! and [`TransferBorrowSession`] retains borrowed payload slices
//! and borrowed imported records — every owner must outlive the
//! machine. Both add the transfer faces: `copy_record` and
//! `move_record` relocate whole designated records, `copy_payload`
//! and `move_payload` relocate LEN interiors, and
//! `copy_record_from` imports one designated external record. A
//! move is one command, one pending step, one revert. The transfer
//! algebra rides its own edit states; the store forms, coordinate
//! classes, handles, and anchors are the base session's, shared
//! unchanged.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::session::transfer::{Edit, Transition};
use crate::session::{
    At32, BorrowStore, DocBytes, Handle, LoadFault, RawDoc, RowId, Store, StoreFault, ValueAt,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
// The priced wrapper's arms name the ceiling by its shared-layer
// ident; the transfer profile's own theorem stands in for it here.
#[cfg(feature = "priced-transfer-session-grouped")]
use crate::session::TRANSFER_PRICE_CEILING as PRICE_CEILING;

pub use crate::session::command::InsertAt;
pub use crate::session::transfer::{EditStatus, PayloadTarget};

#[cfg(test)]
mod tests;

crate::revise::grouped::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        OpenFault, PriceFault, RecordSpans, Refusal, SaveFault,
        SaveSpans,
    ),
    capability: transfer,
    tenure: carrier,
    acceptance: canonical,
    product: carrier,
    Machine: TransferSession,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "TransferSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing session with the transfer capability over one"]
    #[doc = " sealed document."]
    #[doc = ""]
    #[doc = " [`Session`](super::Session)'s faces plus whole-record"]
    #[doc = " relocation, payload relocation, and external import, with"]
    #[doc = " payloads and imported records copied into the machine at"]
    #[doc = " the command — temporaries welcome, no payload lifetime on"]
    #[doc = " the type."]
    #[doc = ""]
    #[doc = " Handles stay valid for the session's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: every command logs one step — a move included — and"]
    #[doc = " [`TransferSession::revert`] restores the save-observable state"]
    #[doc = " of the previous step."]
    #[doc = ""]
    #[doc = " `!Send + !Sync` like the [`DocBytes`] it owns: editing is"]
    #[doc = " single-threaded by design."]
    #[doc = ""]
    #[doc = " ```compile_fail"]
    #[doc = " fn sendable<T: Send>() {}"]
    #[doc = " sendable::<protobuf_edit::session::grouped::TransferSession>();"]
    #[doc = " ```"]
    machine TransferSession { source: DocBytes }
    capability: transfer,
    tenure: carrier,
    acceptance: canonical,
    product: carrier,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "TransferSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    views,
    Machine: TransferSession,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "TransferSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::grouped::transfer",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing session with the transfer capability, with"]
    #[doc = " borrowed payloads."]
    #[doc = ""]
    #[doc = " [`TransferSession`]'s sibling for callers whose payload"]
    #[doc = " bytes outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload`, `insert_payload`, and `copy_record_from` take"]
    #[doc = " `&'p [u8]` and retain the slice — no staging copy — as a"]
    #[doc = " fresh immutable slot per install; earlier installs keep"]
    #[doc = " their slots, so a revert restores the exact prior state."]
    #[doc = " Every payload and imported-record owner must outlive the"]
    #[doc = " session, and `'p` rides the type. Everything else is"]
    #[doc = " [`TransferSession`]'s contract."]
    #[doc = ""]
    #[doc = " `!Send + !Sync` like the [`DocBytes`] it owns: editing is"]
    #[doc = " single-threaded by design."]
    #[doc = ""]
    #[doc = " ```compile_fail"]
    #[doc = " fn sendable<T: Send>() {}"]
    #[doc = " sendable::<protobuf_edit::session::grouped::TransferBorrowSession<'static>>();"]
    #[doc = " ```"]
    machine TransferBorrowSession<'p> { source: DocBytes }
    capability: transfer,
    payload: borrow,
    tenure: carrier,
    acceptance: canonical,
    product: carrier,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "TransferBorrowSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::grouped::transfer",
}

// The machine layouts, pinned exactly on every pointer width:
// the transfer twins
// carry the base machines' fields over the same stores, so the
// absolutes match the base pins; any drift lands here for review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<TransferSession>() == if w64 { 280 } else { 148 });
    assert!(core::mem::size_of::<TransferBorrowSession<'_>>() == if w64 { 256 } else { 136 });
};

crate::revise::grouped::revising_machine! {
    frames for TransferSession (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "TransferSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::grouped::transfer",
    frame_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`TransferSession`] it exclusively"]
        #[doc = " borrows: editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::grouped::transfer::PayloadFrame<'static>>();"]
        #[doc = " ```"]
    ],
    sized_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`TransferSession`] it exclusively"]
        #[doc = " borrows: editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::grouped::transfer::SizedPayloadFrame<'static>>();"]
        #[doc = " ```"]
    ],
}

#[cfg(feature = "priced-transfer-session-grouped")]
crate::revise::grouped::revising_machine! {
    #[doc = " An editing session with the transfer capability that knows"]
    #[doc = " its exact save price at all times: [`TransferSession`]'s"]
    #[doc = " faces with the price settled at every command instead of"]
    #[doc = " walked at every ask."]
    #[doc = ""]
    #[doc = " Each command runs the wrapped gates first and derives its own"]
    #[doc = " price delta before anything is reserved; a move settles both"]
    #[doc = " sides in its one logged step, and a revert settles the same"]
    #[doc = " climb from the log's restored state with zero allocation."]
    #[doc = " Designation aliasing multiplies emitted bytes without growing"]
    #[doc = " any byte column, so this machine's ledger arithmetic runs"]
    #[doc = " under the transfer profile's own per-row ceiling theorem, not"]
    #[doc = " the base cell's per-zone one."]
    #[doc = " [`PricedTransferSession::save_len`] answers in O(1) while"]
    #[doc = " every rewritten body sits in the length class. The doors are"]
    #[doc = " [`TransferSession::into_priced`] and"]
    #[doc = " [`PricedTransferSession::into_session`]; saves keep the base"]
    #[doc = " two-pass machinery."]
    #[doc = ""]
    #[doc = " `!Send + !Sync` like the [`TransferSession`] it wraps: editing"]
    #[doc = " is single-threaded by design."]
    #[doc = ""]
    #[doc = " ```compile_fail"]
    #[doc = " fn sendable<T: Send>() {}"]
    #[doc = " sendable::<protobuf_edit::session::grouped::PricedTransferSession>();"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " # Examples"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::session::grouped::TransferSession;"]
    #[doc = ""]
    #[doc = " // varint f1=150 · LEN f2 \"hi\""]
    #[doc = " let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];"]
    #[doc = " let session = TransferSession::open_copy(&msg).unwrap();"]
    #[doc = " let Ok(mut priced) = session.into_priced() else { unreachable!() };"]
    #[doc = ""]
    #[doc = " // Every command settles the price; save_len answers in O(1)."]
    #[doc = " let record = priced.top().next().unwrap();"]
    #[doc = " priced.set_varint(record, 7).unwrap();"]
    #[doc = " assert_eq!(priced.save_len(), Ok(6));"]
    #[doc = " assert_eq!(priced.save().unwrap().len(), 6);"]
    #[doc = ""]
    #[doc = " // The inverse door releases the transfer session, undo intact."]
    #[doc = " let mut session = priced.into_session();"]
    #[doc = " assert_eq!(session.pending(), 1);"]
    #[doc = " session.revert();"]
    #[doc = " assert_eq!(session.save().unwrap()[..], msg[..]);"]
    #[doc = " ```"]
    machine PricedTransferSession over TransferSession,
    capability: transfer,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "TransferSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::grouped::transfer",
}

// The priced wrapper's layout, pinned exactly per pointer width:
// the wrapped
// machine, the ledger map's control block, the total, and the
// padded census word — the base priced pin plus the wrapped
// machine's own delta. A size pin, not a field-semantics proof.
#[cfg(feature = "priced-transfer-session-grouped")]
const _: () = assert!(
    core::mem::size_of::<PricedTransferSession>()
        == core::mem::size_of::<TransferSession>()
            + if cfg!(target_pointer_width = "64") { 48 } else { 28 }
);

#[cfg(feature = "priced-transfer-session-grouped")]
crate::revise::grouped::revising_machine! {
    frames for PricedTransferSession over TransferSession (PricedPayloadFrame, PricedSizedPayloadFrame),
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "TransferSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::grouped::transfer",
    frame_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`PricedTransferSession`] it"]
        #[doc = " exclusively borrows: editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::grouped::transfer::PricedPayloadFrame<'static>>();"]
        #[doc = " ```"]
    ],
    sized_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`PricedTransferSession`] it"]
        #[doc = " exclusively borrows: editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::grouped::transfer::PricedSizedPayloadFrame<'static>>();"]
        #[doc = " ```"]
    ],
}
