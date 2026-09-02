//! The groupless amend's transfer sibling.
//!
//! The same commit-only editing faces plus whole-record relocation
//! and external import under canonical-minimal admission, emitted
//! as its own machine so the base amend pays none of the
//! capability's carried state or dispatch.
//!
//! One machine carries both import policies on the mixed payload
//! store: `copy_record_from` retains the designated record's bytes
//! borrowed (the backing must outlive the amend), and
//! `copy_record_from_copy` stages one exact record-length copy at
//! the command for designations that cannot outlive the call —
//! canonical admission makes both take `CanonicalRecordRef`, so
//! every import zone is proven minimal. The local transfer faces —
//! `copy_record`, `move_record`, `copy_payload`, `move_payload` —
//! stage zero bytes: the rows carry coordinates into the machine's
//! own source. The store forms, coordinate classes, handles, and
//! anchors are the base amend's, shared unchanged.

use alloc::vec::Vec;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::amend::{Handle, PayloadAt, PayloadStore, RowId, WordAt, WordStore, admit, parts_len_usize};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

pub use crate::amend::transfer::PayloadTarget;
pub use crate::amend::{EditStatus, InsertAt};

#[cfg(test)]
mod tests;

crate::editor::groupless::one_shot_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        FrameFault, OpenFault, PayloadWrite, RecordSpans, Refusal,
        SaveFault, SaveSpans, SizedPayloadWrite,
    ),
    capability: transfer,
    acceptance: canonical,
    noun: "amend",
    a_noun: "an amend",
    A_noun: "An amend",
}

crate::editor::groupless::one_shot_machine! {
    /// A one-shot editing amend with the transfer capability over
    /// one borrowed source under canonical-minimal admission.
    ///
    /// [`Amend`](super::Amend)'s command and save faces plus
    /// whole-record relocation, payload relocation, and external
    /// import on the mixed payload supply.
    ///
    /// Plain data over `&'a [u8]`, `Send` like the base machine.
    /// Handles stay valid for the amend's life; rows and stored
    /// values are never reclaimed (the commit-only trade). `'p`
    /// backs the borrowed payloads and borrowed imported records —
    /// each is held until the save copies it into the output; the
    /// `_copy` faces stage a copy at the command instead.
    machine TransferAmend<'a, 'p> { source: &'a [u8] }
    capability: transfer,
    payloads: PayloadStore<'p>,
    backing: mixed(PayloadWrite, SizedPayloadWrite),
    payload: 'p,
    tenure: borrow,
    acceptance: canonical,
    noun: "amend",
    a_noun: "an amend",
    A_noun: "An amend",
    doc_mod: "protobuf_edit::amend::groupless::transfer",
    doc_open: "TransferAmend::open(&msg, DepthLimit::REFERENCE)",
    doc_open_empty: "TransferAmend::open(&[], DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`amend`](super::super)'s recipes.",
}

// The machine layout, pinned exactly on every pointer width: the transfer sibling
// carries the base machine's fields over the same stores, so the
// absolute matches the base pin; any drift lands here for review.
const _: () = assert!(
    core::mem::size_of::<TransferAmend<'_, '_>>() == core::mem::size_of::<super::Amend<'_, '_>>()
);
