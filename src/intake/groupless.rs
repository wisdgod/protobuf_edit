//! The groupless one-shot intake: owned input under transactional
//! tenure and canonical-minimal admission, derived widths,
//! commit-only edits, and a byte-fidelity save into a caller-owned
//! `Vec<u8>`.
//!
//! This dialect speaks the four-code wire language: group codes
//! are well-formed wire outside it, refused as a capability
//! judgment ([`Refusal::GroupCode`]) distinct from grammar faults
//! — at the root that refusal stops the open (the buffer rides
//! back beside it), inside a payload it is a resident verdict and
//! the payload stays readable as bytes.
//!
//! Admission is canonical-minimal: a padded tag, length prefix, or
//! varint value is lawful wire this machine refuses
//! ([`Refusal::NonMinimalTag`] and kin), so every admitted framing
//! word is minimal and no width column exists — spans derive from
//! the record's own facts. The root layer is flat and eager; LEN
//! payloads stay opaque until [`Intake::descend`], whose verdict
//! is resident. Descent is an explicit commitment: nothing here
//! speculates a payload into a message.
//!
//! Commands commit: there is no revision log and no way to restore a
//! deleted record — dropping the intake discards plan and source
//! together, and [`Intake::into_source`] releases the buffer
//! instead. Every mutation is still transactional in itself: every
//! judgment comes before the first state change, so an `Err` from
//! any command leaves the intake's observable state untouched.
//! Allocation refusal aborts rather than erring — the shared-layer
//! partition rule ([`crate::intake`]): a one-shot machine holds
//! nothing a re-run cannot rebuild.
//!
//! The fidelity contract, face by face: records no command touched
//! ride into the output bit-exact; a replaced record keeps its
//! source tag bytes verbatim; a LEN prefix rides verbatim while
//! its body length is unchanged and is re-authored minimally only
//! when the length moved; library-authored constructs emit
//! minimally — so saved documents re-ingest under the same
//! canonical admission.
//!
//! Coordinates: write · buffered · offline · groupless · canonical (type-level) · owned · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::intake::groupless::Intake;
//!
//! // varint f1=150 · LEN f2 "hi"
//! let msg = vec![0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
//!
//! let tops: Vec<_> = intake.top().collect();
//! intake.set_payload(tops[1], b"no").unwrap();
//!
//! // The untouched varint rode verbatim; the same-length payload
//! // kept its prefix.
//! let mut out = Vec::new();
//! intake.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x96, 0x01, 0x12, 0x02, 0x6E, 0x6F]);
//! ```

use alloc::vec::Vec;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::intake::{
    BorrowedPayloadStore, CopiedPayloadStore, Handle, PayloadAt, PayloadStore, RowId, WordAt,
    WordStore, admit, parts_len_usize,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

pub use crate::intake::{EditStatus, InsertAt};

#[cfg(feature = "transfer-intake-groupless")]
pub mod transfer;

#[cfg(feature = "transfer-intake-groupless")]
pub use transfer::TransferIntake;

#[cfg(test)]
mod tests;

crate::editor::groupless::one_shot_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        FrameFault, OpenFault, PayloadWrite, RecordSpans, Refusal,
        SaveFault, SaveSpans, SizedPayloadWrite,
    ),
    capability: plain,
    acceptance: canonical,
    noun: "intake",
    a_noun: "an intake",
    A_noun: "An intake",
}

crate::editor::groupless::one_shot_machine! {
    /// A one-shot editing intake holding tenure of its source under
    /// canonical-minimal admission.
    ///
    /// Plain data over an owned `Vec<u8>`: no share counting, no
    /// interior mutability — the machine is `Send` because there is
    /// nothing to engineer around, and the saved product is the
    /// caller's own `Vec<u8>`. No source lifetime exists, so a
    /// mid-edit intake moves, returns, and caches freely (rows
    /// address the source by `u32` offsets, never pointers). Handles
    /// stay valid for the intake's life; rows and stored values are
    /// never reclaimed (re-setting a copied payload leaves the old
    /// bytes behind inert — the commit-only trade). `'p` backs the
    /// borrowed payloads (`set_payload`, `insert_payload`): each is
    /// held until the save copies it into the output, and an intake
    /// with no borrowed payloads inhabits `Intake<'static>`.
    /// The thin payload-backing siblings are [`BorrowIntake`]
    /// (borrowed-only) and [`CopyIntake`] (copy-only); the
    /// transfer sibling `TransferIntake` (feature
    /// `transfer-intake-groupless`) adds whole-record relocation,
    /// payload relocation, and external import on this same
    /// mixed supply.
    machine Intake<'p> { source: Vec<u8> }
    capability: plain,
    payloads: PayloadStore<'p>,
    backing: mixed(PayloadWrite, SizedPayloadWrite),
    payload: 'p,
    tenure: own,
    acceptance: canonical,
    noun: "intake",
    a_noun: "an intake",
    A_noun: "An intake",
    doc_mod: "protobuf_edit::intake::groupless",
    doc_open: "Intake::open(msg.to_vec(), DepthLimit::REFERENCE)",
    doc_open_empty: "Intake::open(Vec::new(), DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`intake`](super)'s recipes.",
}

crate::editor::groupless::one_shot_machine! {
    /// The borrowed-only intake: every authored payload is borrowed
    /// until the save copies it once into the output.
    ///
    /// [`Intake`]'s command and save faces over the borrowed supply
    /// alone. No copied column exists, so neither the `_copy` faces
    /// nor the staged frames do, and the payload store is one `Vec`
    /// lighter; everything else — vocabulary, doors, transactional
    /// tenure — is the mixed machine's.
    ///
    /// Plain data over an owned `Vec<u8>`, `Send` like its mixed
    /// sibling; `'p` backs the borrowed payloads, so every payload
    /// owner must outlive the intake.
    machine BorrowIntake<'p> { source: Vec<u8> }
    capability: plain,
    payloads: BorrowedPayloadStore<'p>,
    backing: borrowed(mixed: Intake),
    payload: 'p,
    tenure: own,
    acceptance: canonical,
    noun: "intake",
    a_noun: "an intake",
    A_noun: "An intake",
    doc_mod: "protobuf_edit::intake::groupless",
    doc_open: "BorrowIntake::open(msg.to_vec(), DepthLimit::REFERENCE)",
    doc_open_empty: "BorrowIntake::open(Vec::new(), DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`intake`](super)'s recipes.",
}

crate::editor::groupless::one_shot_machine! {
    /// The copy-only intake: every authored payload is staged by
    /// copy at the command.
    ///
    /// [`Intake`]'s command and save faces over the copied supply
    /// alone — a payload slot is a bare extent, no slot tag exists,
    /// and no lifetime parameter remains at all: the source moves
    /// in and the payloads copy, so a mid-edit machine moves,
    /// returns, and caches with nothing pinning any caller frame.
    /// Temporaries are welcome everywhere; the mixed machine's
    /// borrowed default is the zero-staging path.
    ///
    /// Plain data over an owned `Vec<u8>`, `Send` like its mixed
    /// sibling.
    machine CopyIntake<> { source: Vec<u8> }
    capability: plain,
    payloads: CopiedPayloadStore,
    backing: copied(mixed: Intake, CopyPayloadWrite, SizedCopyPayloadWrite),
    tenure: own,
    acceptance: canonical,
    noun: "intake",
    a_noun: "an intake",
    A_noun: "An intake",
    doc_mod: "protobuf_edit::intake::groupless",
    doc_open: "CopyIntake::open(msg.to_vec(), DepthLimit::REFERENCE)",
    doc_open_empty: "CopyIntake::open(Vec::new(), DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`intake`](super)'s recipes.",
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
        core::mem::size_of::<BorrowIntake<'_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Intake<'_>>()
    );
    assert!(core::mem::size_of::<CopyIntake>() == core::mem::size_of::<Intake<'_>>());
};
