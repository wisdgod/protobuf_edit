//! The grouped one-shot adopt: owned input under transactional
//! tenure, width-carrying rows, commit-only edits, and a
//! byte-fidelity save into a caller-owned `Vec<u8>`.
//!
//! Admission is tolerant: padded tags, length prefixes, and varint
//! values are lawful input, so every framing width the scan meets
//! is stored on the row as an input fact and every untouched span
//! reproduces its padding byte-exactly at save. Group records
//! materialize eagerly at scan (the scan is the parse; the
//! open-group chain is the row arena itself); LEN payloads stay
//! opaque until [`Adopt::descend`], whose verdict is resident — a
//! wire fault or a refusal inside a payload parks on the record
//! and the adopt lives on. Descent is an explicit commitment:
//! nothing here speculates a payload into a message.
//!
//! Commands commit: there is no revision log and no way to restore a
//! deleted record — dropping the adopt discards plan and source
//! together, and [`Adopt::into_source`] releases the buffer
//! instead. Every mutation is still transactional in itself: every
//! judgment comes before the first state change, so an `Err` from
//! any command leaves the adopt's observable state untouched.
//! Allocation refusal aborts rather than erring — the shared-layer
//! partition rule ([`crate::adopt`]): a one-shot machine holds
//! nothing a re-run cannot rebuild.
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
//! Group interiors are in-band syntax and always sit in the
//! closure — padded group framing and padded interior records
//! normalize without any descent — while LEN interiors keep the
//! explicit-descent boundary: bytes inside an un-descended,
//! faulted, or refused LEN are payload bytes, not records, and
//! pass unchanged behind re-derived outer framing.
//!
//! Coordinates: write · buffered · offline · grouped · tolerant (type-level) · owned · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::adopt::grouped::Adopt;
//!
//! // varint f1=150 (value padded to two bytes) · group f2 { varint f3=1 }
//! let msg = vec![0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x01, 0x14];
//! let mut adopt = Adopt::open(msg, DepthLimit::REFERENCE).unwrap();
//!
//! // Groups materialize at scan: the interior is already there.
//! let tops: Vec<_> = adopt.top().collect();
//! let inner = adopt.children(tops[1]).next().unwrap();
//! adopt.set_varint(inner, 9).unwrap();
//!
//! // The padded varint rode verbatim; only the touched value moved.
//! let mut out = Vec::new();
//! adopt.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x09, 0x14]);
//! ```

use alloc::vec::Vec;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::adopt::{
    BorrowedPayloadStore, CopiedPayloadStore, Handle, PayloadAt, PayloadStore, RowId, WordAt,
    WordStore, admit, parts_len_usize,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

pub use crate::adopt::{EditStatus, InsertAt};

#[cfg(feature = "transfer-adopt-grouped")]
pub mod transfer;

#[cfg(feature = "transfer-adopt-grouped")]
pub use transfer::TransferAdopt;

#[cfg(test)]
mod tests;

crate::editor::grouped::one_shot_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        FrameFault, OpenFault, PayloadWrite, RecordSpans, Refusal,
        SaveFault, SaveSpans, SizedPayloadWrite,
    ),
    capability: plain,
    acceptance: tolerant,
    noun: "adopt",
    a_noun: "an adopt",
    A_noun: "An adopt",
}

crate::editor::grouped::one_shot_machine! {
    /// A one-shot editing adopt holding tenure of its source.
    ///
    /// Plain data over an owned `Vec<u8>`: no share counting, no
    /// interior mutability — the machine is `Send` because there is
    /// nothing to engineer around, and the saved product is the
    /// caller's own `Vec<u8>`. No source lifetime exists, so a
    /// mid-edit adopt moves, returns, and caches freely (rows address
    /// the source by `u32` offsets, never pointers). Handles stay
    /// valid for the adopt's life; rows and stored values are never
    /// reclaimed (re-setting a copied payload leaves the old bytes
    /// behind inert — the commit-only trade). `'p` backs the borrowed
    /// payloads (`set_payload`, `insert_payload`): each is held until
    /// the save copies it into the output, and an adopt with no
    /// borrowed payloads inhabits `Adopt<'static>`. The
    /// canonical-output faces (the `save_canonical` family) ride
    /// every payload-backing form — this one, [`BorrowAdopt`], and [`CopyAdopt`]
    /// — without changing any form's lifetime or allocation profile.
    /// The transfer sibling `TransferAdopt` (feature
    /// `transfer-adopt-grouped`) adds whole-record relocation,
    /// payload relocation, and external import on this same
    /// mixed supply.
    machine Adopt<'p> { source: Vec<u8> }
    capability: plain,
    payloads: PayloadStore<'p>,
    backing: mixed(PayloadWrite, SizedPayloadWrite),
    payload: 'p,
    tenure: own,
    acceptance: tolerant,
    noun: "adopt",
    a_noun: "an adopt",
    A_noun: "An adopt",
    doc_mod: "protobuf_edit::adopt::grouped",
    doc_open: "Adopt::open(msg.to_vec(), DepthLimit::REFERENCE)",
    doc_open_empty: "Adopt::open(Vec::new(), DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`adopt`](super)'s recipes.",
}

crate::editor::grouped::one_shot_machine! {
    /// The borrowed-only adopt: every authored payload is borrowed
    /// until the save copies it once into the output.
    ///
    /// [`Adopt`]'s command and save faces over the borrowed supply
    /// alone. No copied column exists, so neither the `_copy` faces
    /// nor the staged frames do, and the payload store is one `Vec`
    /// lighter; everything else — vocabulary, doors, transactional
    /// tenure — is the mixed machine's.
    ///
    /// Plain data over an owned `Vec<u8>`, `Send` like its mixed
    /// sibling; `'p` backs the borrowed payloads, so every payload
    /// owner must outlive the adopt. The canonical-output faces ride
    /// this form exactly as the mixed machine's, changing neither
    /// its lifetime nor its allocation profile.
    machine BorrowAdopt<'p> { source: Vec<u8> }
    capability: plain,
    payloads: BorrowedPayloadStore<'p>,
    backing: borrowed(mixed: Adopt),
    payload: 'p,
    tenure: own,
    acceptance: tolerant,
    noun: "adopt",
    a_noun: "an adopt",
    A_noun: "An adopt",
    doc_mod: "protobuf_edit::adopt::grouped",
    doc_open: "BorrowAdopt::open(msg.to_vec(), DepthLimit::REFERENCE)",
    doc_open_empty: "BorrowAdopt::open(Vec::new(), DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`adopt`](super)'s recipes.",
}

crate::editor::grouped::one_shot_machine! {
    /// The copy-only adopt: every authored payload is staged by
    /// copy at the command.
    ///
    /// [`Adopt`]'s command and save faces over the copied supply
    /// alone — a payload slot is a bare extent, no slot tag exists,
    /// and no lifetime parameter remains at all: the source moves
    /// in and the payloads copy, so a mid-edit machine moves,
    /// returns, and caches with nothing pinning any caller frame.
    /// Temporaries are welcome everywhere; the mixed machine's
    /// borrowed default is the zero-staging path.
    ///
    /// Plain data over an owned `Vec<u8>`, `Send` like its mixed
    /// sibling. The canonical-output faces ride this form exactly
    /// as the mixed machine's, changing neither its (absent)
    /// lifetimes nor its allocation profile.
    machine CopyAdopt<> { source: Vec<u8> }
    capability: plain,
    payloads: CopiedPayloadStore,
    backing: copied(mixed: Adopt, CopyPayloadWrite, SizedCopyPayloadWrite),
    tenure: own,
    acceptance: tolerant,
    noun: "adopt",
    a_noun: "an adopt",
    A_noun: "An adopt",
    doc_mod: "protobuf_edit::adopt::grouped",
    doc_open: "CopyAdopt::open(msg.to_vec(), DepthLimit::REFERENCE)",
    doc_open_empty: "CopyAdopt::open(Vec::new(), DepthLimit::REFERENCE)",
    doc_recipes: " The growth-free price-reserve-save composition lives in [`adopt`](super)'s recipes.",
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
        core::mem::size_of::<BorrowAdopt<'_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Adopt<'_>>()
    );
    assert!(core::mem::size_of::<CopyAdopt>() == core::mem::size_of::<Adopt<'_>>());
};
