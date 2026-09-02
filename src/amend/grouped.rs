//! The grouped one-shot amend: borrowed input under
//! canonical-minimal admission, derived widths, commit-only edits,
//! and a byte-fidelity save into a caller-owned `Vec<u8>`.
//!
//! Admission is canonical-minimal: a padded tag, length prefix, or
//! varint value is lawful wire this machine refuses
//! ([`Refusal::NonMinimalTag`] and kin), so every admitted framing
//! word is minimal and no width column exists — spans derive from
//! the record's own facts. Group records materialize eagerly at
//! scan (the scan is the parse; the open-group chain is the row
//! arena itself); LEN payloads stay opaque until
//! [`Amend::descend`], whose verdict is resident — a wire fault or
//! a refusal inside a payload parks on the record and the amend
//! lives on. Descent is an explicit commitment: nothing here
//! speculates a payload into a message.
//!
//! Commands commit: there is no revision log and no way to restore a
//! deleted record — dropping the amend discards the plan. Every
//! mutation is still transactional in itself: every judgment comes
//! before the first state change, so an `Err` from any command
//! leaves the amend's observable state untouched. Allocation
//! refusal aborts rather than erring — the shared-layer partition
//! rule ([`crate::amend`]): a one-shot machine holds nothing a
//! re-run cannot rebuild.
//!
//! The fidelity contract, face by face: records no command touched
//! ride into the output bit-exact; a replaced record keeps its
//! source tag bytes verbatim; a LEN prefix rides verbatim while
//! its body length is unchanged and is re-authored minimally only
//! when the length moved; library-authored constructs emit
//! minimally — so saved documents re-ingest under the same
//! canonical admission.
//!
//! Coordinates: write · buffered · offline · grouped · canonical (type-level) · borrowed · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::amend::grouped::Amend;
//!
//! // varint f1=150 · group f2 { varint f3=1 }
//! let msg = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
//! let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
//!
//! // Groups materialize at scan: the interior is already there.
//! let tops: Vec<_> = amend.top().collect();
//! let inner = amend.children(tops[1]).next().unwrap();
//! amend.set_varint(inner, 9).unwrap();
//!
//! // Only the touched value moved; the rest rode verbatim.
//! let mut out = Vec::new();
//! amend.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x96, 0x01, 0x13, 0x18, 0x09, 0x14]);
//! ```

use alloc::vec::Vec;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::amend::{
    BorrowedPayloadStore, CopiedPayloadStore, Handle, PayloadAt, PayloadStore, RowId, WordAt,
    WordStore, admit, parts_len_usize,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

pub use crate::amend::{EditStatus, InsertAt};

#[cfg(feature = "transfer-amend-grouped")]
pub mod transfer;

#[cfg(feature = "transfer-amend-grouped")]
pub use transfer::TransferAmend;

#[cfg(test)]
mod tests;

crate::editor::grouped::one_shot_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        FrameFault, OpenFault, PayloadWrite, RecordSpans, Refusal,
        SaveFault, SaveSpans, SizedPayloadWrite,
    ),
    capability: plain,
    acceptance: canonical,
    noun: "amend",
    a_noun: "an amend",
    A_noun: "An amend",
}

crate::editor::grouped::one_shot_machine! {
    /// A one-shot editing amend over one borrowed source under
    /// canonical-minimal admission.
    ///
    /// Plain data over `&'a [u8]`: no share counting, no interior
    /// mutability — the machine is `Send` because there is nothing to
    /// engineer around, and the saved product is the caller's own
    /// `Vec<u8>`. Handles stay valid for the amend's life; rows and
    /// stored values are never reclaimed (re-setting a copied payload
    /// leaves the old bytes behind inert — the commit-only trade). `'p`
    /// backs the borrowed payloads (`set_payload`, `insert_payload`):
    /// each is held until the save copies it into the output. The two
    /// lifetimes are independent — the source and a payload owner may
    /// die in either order once the amend is gone.
    /// The thin payload-backing siblings are [`BorrowAmend`]
    /// (borrowed-only) and [`CopyAmend`] (copy-only); the
    /// transfer sibling `TransferAmend` (feature
    /// `transfer-amend-grouped`) adds whole-record relocation,
    /// payload relocation, and external import on this same
    /// mixed supply.
    machine Amend<'a, 'p> { source: &'a [u8] }
    capability: plain,
    payloads: PayloadStore<'p>,
    backing: mixed(PayloadWrite, SizedPayloadWrite),
    payload: 'p,
    tenure: borrow,
    acceptance: canonical,
    noun: "amend",
    a_noun: "an amend",
    A_noun: "An amend",
    doc_mod: "protobuf_edit::amend::grouped",
    doc_open: "Amend::open(&msg, DepthLimit::REFERENCE)",
    doc_open_empty: "Amend::open(&[], DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`amend`](super)'s recipes.",
}

crate::editor::grouped::one_shot_machine! {
    /// The borrowed-only amend: every authored payload is borrowed
    /// until the save copies it once into the output.
    ///
    /// [`Amend`]'s command and save faces over the borrowed supply
    /// alone. No copied column exists, so neither the `_copy` faces
    /// nor the staged frames do, and the payload store is one `Vec`
    /// lighter; everything else — vocabulary, doors, the fidelity
    /// contract — is the mixed machine's.
    ///
    /// Plain data over `&'a [u8]`, `Send` like its mixed sibling;
    /// `'p` backs the borrowed payloads, so every payload owner
    /// must outlive the amend.
    machine BorrowAmend<'a, 'p> { source: &'a [u8] }
    capability: plain,
    payloads: BorrowedPayloadStore<'p>,
    backing: borrowed(mixed: Amend),
    payload: 'p,
    tenure: borrow,
    acceptance: canonical,
    noun: "amend",
    a_noun: "an amend",
    A_noun: "An amend",
    doc_mod: "protobuf_edit::amend::grouped",
    doc_open: "BorrowAmend::open(&msg, DepthLimit::REFERENCE)",
    doc_open_empty: "BorrowAmend::open(&[], DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`amend`](super)'s recipes.",
}

crate::editor::grouped::one_shot_machine! {
    /// The copy-only amend: every authored payload is staged by
    /// copy at the command.
    ///
    /// [`Amend`]'s command and save faces over the copied supply
    /// alone — a payload slot is a bare extent, no slot tag exists,
    /// and no payload lifetime binds the caller: `'a` alone
    /// remains, backing the borrowed source. Temporaries are
    /// welcome everywhere; the mixed machine's borrowed default is
    /// the zero-staging path.
    ///
    /// Plain data over `&'a [u8]`, `Send` like its mixed sibling.
    machine CopyAmend<'a> { source: &'a [u8] }
    capability: plain,
    payloads: CopiedPayloadStore,
    backing: copied(mixed: Amend, CopyPayloadWrite, SizedCopyPayloadWrite),
    tenure: borrow,
    acceptance: canonical,
    noun: "amend",
    a_noun: "an amend",
    A_noun: "An amend",
    doc_mod: "protobuf_edit::amend::grouped",
    doc_open: "CopyAmend::open(&msg, DepthLimit::REFERENCE)",
    doc_open_empty: "CopyAmend::open(&[], DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`amend`](super)'s recipes.",
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
        core::mem::size_of::<BorrowAmend<'_, '_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Amend<'_, '_>>()
    );
    assert!(core::mem::size_of::<CopyAmend<'_>>() == core::mem::size_of::<Amend<'_, '_>>());
};
