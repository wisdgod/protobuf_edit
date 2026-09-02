//! The groupless one-shot patch: borrowed input, width-carrying
//! rows, commit-only edits, and a byte-fidelity save into a
//! caller-owned `Vec<u8>`.
//!
//! This dialect speaks the four-code wire language: group codes
//! are well-formed wire outside it, refused as a capability
//! judgment ([`Refusal::GroupCode`]) distinct from grammar faults
//! — at the root that refusal stops the open, inside a payload it
//! is a resident verdict and the payload stays readable as bytes.
//!
//! Admission is tolerant: padded tags, length prefixes, and varint
//! values are lawful input, so every framing width the scan meets
//! is stored on the row as an input fact and every untouched span
//! reproduces its padding byte-exactly at save. The root layer is
//! flat and eager; LEN payloads stay opaque until
//! [`Patch::descend`], whose verdict is resident. Descent is an
//! explicit commitment: nothing here speculates a payload into a
//! message.
//!
//! Commands commit: there is no revision log and no way to restore a
//! deleted record — dropping the patch discards the plan. Every
//! mutation is still transactional in itself: every judgment comes
//! before the first state change, so an `Err` from any command
//! leaves the patch's observable state untouched. Allocation
//! refusal aborts rather than erring — the shared-layer partition
//! rule ([`crate::patch`]): a one-shot machine holds nothing a
//! re-run cannot rebuild.
//!
//! The fidelity contract, face by face: records no command touched
//! ride into the output bit-exact, padding included; a replaced
//! record keeps its source tag bytes verbatim; a LEN prefix rides
//! verbatim while its body length is unchanged and is re-authored
//! minimally only when the length moved; library-authored
//! constructs emit minimally.
//!
//! The canonical contract, one face family: `save_canonical`,
//! `save_canonical_into`, and `save_canonical_sink` minimally emit
//! every varint construct in the materialized commitment closure.
//! The opacity boundary is explicit descent: bytes inside an
//! un-descended, faulted, or refused LEN may happen to form padded
//! protobuf words — they are payload bytes, not records, and pass
//! unchanged behind re-derived outer framing; a successful descend
//! commits them into the closure and the next canonical save
//! normalizes them.
//!
//! Coordinates: write · buffered · offline · groupless · tolerant (type-level) · borrowed · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::patch::groupless::Patch;
//!
//! // varint f1=150 (value padded to two bytes) · LEN f2 "hi"
//! let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
//! let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
//!
//! let tops: Vec<_> = patch.top().collect();
//! patch.set_payload(tops[1], b"no").unwrap();
//!
//! // The padded varint rode verbatim; the same-length payload
//! // kept its prefix.
//! let mut out = Vec::new();
//! patch.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x6E, 0x6F]);
//! ```

use alloc::vec::Vec;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::patch::{
    BorrowedPayloadStore, CopiedPayloadStore, Handle, PayloadAt, PayloadStore, RowId, WordAt,
    WordStore, admit, parts_len_usize,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

pub use crate::patch::{EditStatus, InsertAt};

#[cfg(feature = "transfer-patch-groupless")]
pub mod transfer;

#[cfg(feature = "transfer-patch-groupless")]
pub use transfer::TransferPatch;

#[cfg(test)]
mod tests;

crate::editor::groupless::one_shot_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        FrameFault, OpenFault, PayloadWrite, RecordSpans, Refusal,
        SaveFault, SaveSpans, SizedPayloadWrite,
    ),
    capability: plain,
    acceptance: tolerant,
    noun: "patch",
    a_noun: "a patch",
    A_noun: "A patch",
}

crate::editor::groupless::one_shot_machine! {
    /// A one-shot editing patch over one borrowed source.
    ///
    /// Plain data over `&'a [u8]`: no share counting, no interior
    /// mutability — the machine is `Send` because there is nothing to
    /// engineer around, and the saved product is the caller's own
    /// `Vec<u8>`. Handles stay valid for the patch's life; rows and
    /// stored values are never reclaimed (re-setting a copied payload
    /// leaves the old bytes behind inert — the commit-only trade). `'p`
    /// backs the borrowed payloads (`set_payload`, `insert_payload`):
    /// each is held until the save copies it into the output. The two
    /// lifetimes are independent — the source and a payload owner may
    /// die in either order once the patch is gone. The canonical-output
    /// faces (the `save_canonical` family) ride every payload-backing
    /// form — this one, [`BorrowPatch`], and [`CopyPatch`] — without changing any
    /// form's lifetime or allocation profile.
    /// The transfer sibling `TransferPatch` (feature
    /// `transfer-patch-groupless`) adds whole-record relocation,
    /// payload relocation, and external import on this same
    /// mixed supply.
    machine Patch<'a, 'p> { source: &'a [u8] }
    capability: plain,
    payloads: PayloadStore<'p>,
    backing: mixed(PayloadWrite, SizedPayloadWrite),
    payload: 'p,
    tenure: borrow,
    acceptance: tolerant,
    noun: "patch",
    a_noun: "a patch",
    A_noun: "A patch",
    doc_mod: "protobuf_edit::patch::groupless",
    doc_open: "Patch::open(&msg, DepthLimit::REFERENCE)",
    doc_open_empty: "Patch::open(&[], DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`patch`](super)'s recipes.",
}

crate::editor::groupless::one_shot_machine! {
    /// The borrowed-only patch: every authored payload is borrowed
    /// until the save copies it once into the output.
    ///
    /// [`Patch`]'s command and save faces over the borrowed supply
    /// alone. No copied column exists, so neither the `_copy` faces
    /// nor the staged frames do, and the payload store is one `Vec`
    /// lighter; everything else — vocabulary, doors, the fidelity
    /// contract — is the mixed machine's.
    ///
    /// Plain data over `&'a [u8]`, `Send` like its mixed sibling;
    /// `'p` backs the borrowed payloads, so every payload owner
    /// must outlive the patch. The canonical-output faces ride this
    /// form exactly as the mixed machine's, changing neither its
    /// lifetimes nor its allocation profile.
    machine BorrowPatch<'a, 'p> { source: &'a [u8] }
    capability: plain,
    payloads: BorrowedPayloadStore<'p>,
    backing: borrowed(mixed: Patch),
    payload: 'p,
    tenure: borrow,
    acceptance: tolerant,
    noun: "patch",
    a_noun: "a patch",
    A_noun: "A patch",
    doc_mod: "protobuf_edit::patch::groupless",
    doc_open: "BorrowPatch::open(&msg, DepthLimit::REFERENCE)",
    doc_open_empty: "BorrowPatch::open(&[], DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`patch`](super)'s recipes.",
}

crate::editor::groupless::one_shot_machine! {
    /// The copy-only patch: every authored payload is staged by
    /// copy at the command.
    ///
    /// [`Patch`]'s command and save faces over the copied supply
    /// alone — a payload slot is a bare extent, no slot tag exists,
    /// and no payload lifetime binds the caller: `'a` alone
    /// remains, backing the borrowed source. Temporaries are
    /// welcome everywhere; the mixed machine's borrowed default is
    /// the zero-staging path.
    ///
    /// Plain data over `&'a [u8]`, `Send` like its mixed sibling.
    /// The canonical-output faces ride this form exactly as the
    /// mixed machine's, changing neither its lifetime nor its
    /// allocation profile.
    machine CopyPatch<'a> { source: &'a [u8] }
    capability: plain,
    payloads: CopiedPayloadStore,
    backing: copied(mixed: Patch, CopyPayloadWrite, SizedCopyPayloadWrite),
    tenure: borrow,
    acceptance: tolerant,
    noun: "patch",
    a_noun: "a patch",
    A_noun: "A patch",
    doc_mod: "protobuf_edit::patch::groupless",
    doc_open: "CopyPatch::open(&msg, DepthLimit::REFERENCE)",
    doc_open_empty: "CopyPatch::open(&[], DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`patch`](super)'s recipes.",
}

// The thin siblings' savings, pinned at the machine level on every
// pointer width (the 32-bit layout gate is a check build, and only
// unconditional assertions reach it): the borrowed-only store drops
// the copied column whole — one Vec of three words, 24 bytes on
// 64-bit pointers and 12 on 32-bit — and the copy-only machine
// keeps the mixed footprint over untagged extent slots.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(
        core::mem::size_of::<BorrowPatch<'_, '_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Patch<'_, '_>>()
    );
    assert!(core::mem::size_of::<CopyPatch<'_>>() == core::mem::size_of::<Patch<'_, '_>>());
};
