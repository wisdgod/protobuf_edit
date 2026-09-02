//! The groupless patch's transfer sibling.
//!
//! The same commit-only editing faces plus whole-record relocation
//! and external import, emitted as its own machine so the base
//! patch pays none of the capability's carried state or dispatch.
//!
//! One machine carries both import policies on the mixed payload
//! store: `copy_record_from` retains the designated record's bytes
//! borrowed (the backing must outlive the patch), and
//! `copy_record_from_copy` stages one exact record-length copy at
//! the command for designations that cannot outlive the call. The
//! local transfer faces — `copy_record`, `move_record`,
//! `copy_payload`, `move_payload` — stage zero bytes: the rows
//! carry coordinates into the machine's own source. The store
//! forms, coordinate classes, handles, and anchors are the base
//! patch's, shared unchanged.

use alloc::vec::Vec;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::patch::{Handle, PayloadAt, PayloadStore, RowId, WordAt, WordStore, admit, parts_len_usize};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

pub use crate::patch::transfer::PayloadTarget;
pub use crate::patch::{EditStatus, InsertAt};

#[cfg(test)]
mod tests;

crate::editor::groupless::one_shot_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        FrameFault, OpenFault, PayloadWrite, RecordSpans, Refusal,
        SaveFault, SaveSpans, SizedPayloadWrite,
    ),
    capability: transfer,
    acceptance: tolerant,
    noun: "patch",
    a_noun: "a patch",
    A_noun: "A patch",
}

crate::editor::groupless::one_shot_machine! {
    /// A one-shot editing patch with the transfer capability over
    /// one borrowed source.
    ///
    /// [`Patch`](super::Patch)'s command and save faces plus
    /// whole-record relocation, payload relocation, and external
    /// import on the mixed payload supply.
    ///
    /// Plain data over `&'a [u8]`, `Send` like the base machine.
    /// Handles stay valid for the patch's life; rows and stored
    /// values are never reclaimed (the commit-only trade). `'p`
    /// backs the borrowed payloads and borrowed imported records —
    /// each is held until the save copies it into the output; the
    /// `_copy` faces stage a copy at the command instead.
    machine TransferPatch<'a, 'p> { source: &'a [u8] }
    capability: transfer,
    payloads: PayloadStore<'p>,
    backing: mixed(PayloadWrite, SizedPayloadWrite),
    payload: 'p,
    tenure: borrow,
    acceptance: tolerant,
    noun: "patch",
    a_noun: "a patch",
    A_noun: "A patch",
    doc_mod: "protobuf_edit::patch::groupless::transfer",
    doc_open: "TransferPatch::open(&msg, DepthLimit::REFERENCE)",
    doc_open_empty: "TransferPatch::open(&[], DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`patch`](super::super)'s recipes.",
}

// The machine layout, pinned exactly on every pointer width: the transfer sibling
// carries the base machine's fields over the same stores, so the
// absolute matches the base pin; any drift lands here for review.
const _: () = assert!(
    core::mem::size_of::<TransferPatch<'_, '_>>() == core::mem::size_of::<super::Patch<'_, '_>>()
);
