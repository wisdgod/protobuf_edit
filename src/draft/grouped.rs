//! The grouped editing draft: handle-based edits with precise
//! undo over one moved-in buffer, saved in two passes with the
//! one-shot patch's byte fidelity.
//!
//! Admission is tolerant: padded tags, length prefixes, and varint
//! values are lawful input, so every framing width the scan meets
//! is stored on the row as an input fact — a group row carries its
//! end tag's width — and every untouched span reproduces its
//! padding byte-exactly at save. Group records materialize eagerly
//! at scan (the scan is the parse; the open-group chain is the row
//! arena itself, so nesting costs no stack); LEN payloads stay
//! opaque until [`Draft::descend`], whose verdict is resident —
//! a wire fault inside a payload parks on the slot and the draft
//! lives on.
//!
//! The fidelity contract, face by face: records no live edit
//! touches ride into the output bit-exact, padding included; a
//! replaced record keeps its source tag bytes verbatim; a LEN
//! prefix rides verbatim while its body length is unchanged and is
//! re-authored minimally only when the length moved; a scanned
//! group's open and end tags ride verbatim whatever happens
//! inside; command-authored records emit minimally. Reverting a
//! command restores the fidelity reading exactly — `revert_all`
//! makes the save the source again, padding included.
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
//! Every mutation is transactional: admission judgments come
//! first, every reservation is fallible, and once the store push
//! (or, for storeless commands, the last reservation) succeeds the
//! remaining suffix cannot fail — an `Err` from any command leaves
//! the draft's observable state untouched. Allocation refusals
//! surface as structured errors ([`OpenFault::Resource`],
//! [`EditFault::Resource`], [`SaveFault::Resource`]); nothing in this
//! module aborts on allocator pressure.
//!
//! Coordinates: write · buffered · offline · grouped · tolerant (type-level) · owned · revisable.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::draft::grouped::Draft;
//!
//! // varint f1=150 (value padded) · group f2 { varint f3=1 }
//! let msg = vec![0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x01, 0x14];
//! let mut draft = Draft::open(msg).unwrap();
//!
//! // Groups materialize at scan: the interior is already there.
//! let tops: Vec<_> = draft.top().collect();
//! let inner = draft.children(tops[1]).unwrap().next().unwrap();
//! assert_eq!(draft.varint_word(inner).unwrap(), 1);
//!
//! // Replace the group's interior value: the group framing and
//! // the padded sibling ride verbatim through the save.
//! draft.set_varint(inner, 7).unwrap();
//! let saved = draft.save().unwrap();
//! assert_eq!(saved, [0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x07, 0x14]);
//! ```

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::draft::{
    At32, BorrowStore, Edit, Handle, MixStore, RowId, Store, StoreFault, Transition, ValueAt, admit,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
pub use crate::draft::command::{EditStatus, InsertAt};

#[cfg(feature = "transfer-draft-grouped")]
pub mod transfer;

#[cfg(feature = "transfer-draft-grouped")]
pub use transfer::{TransferBorrowDraft, TransferDraft};

#[cfg(test)]
mod tests;

crate::revise::grouped::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        OpenFault, RecordSpans, SaveFault, SaveSpans,
    ),
    capability: plain,
    tenure: vec,
    acceptance: tolerant,
    product: vec,
    Machine: Draft,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "Draft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::grouped",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing draft over one moved-in buffer."]
    #[doc = ""]
    #[doc = " Handles stay valid for the draft's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: [`Draft::revert`] walks the log backwards and restores"]
    #[doc = " the save-observable state of the previous step — byte"]
    #[doc = " fidelity included, padding and all; orphaned handles are not"]
    #[doc = " revived."]
    #[doc = ""]
    #[doc = " Draft storage grows monotonically: rows and stored values are"]
    #[doc = " never reclaimed (the handle contract names them for the"]
    #[doc = " draft's life), and each descend of a re-sealed container"]
    #[doc = " mints fresh interior rows, a fresh layer descriptor, and — for"]
    #[doc = " source-backed payloads — a fresh run entry, leaving the"]
    #[doc = " orphaned ones behind inert. Each replace → revert → re-descend"]
    #[doc = " cycle therefore re-mints the whole interior; a long-lived"]
    #[doc = " editor budgets for that growth or reopens the document at its"]
    #[doc = " checkpoints."]
    #[doc = ""]
    #[doc = " Plain data over an owned `Vec<u8>`: no share counting, no"]
    #[doc = " interior mutability — the machine is `Send + Sync` because"]
    #[doc = " there is nothing to engineer around, and a mid-edit draft"]
    #[doc = " moves, returns, and caches (rows address the source by `u32`"]
    #[doc = " offsets, never pointers)."]
    #[doc = ""]
    #[doc = " The canonical-output faces (the `save_canonical` family)"]
    #[doc = " ride every payload-backing form — this one, [`BorrowDraft`],"]
    #[doc = " and [`MixDraft`] — without changing any form's lifetime or"]
    #[doc = " allocation profile."]
    #[doc = ""]
    #[doc = " The transfer siblings `TransferDraft` and"]
    #[doc = " `TransferBorrowDraft` (feature `transfer-draft-grouped`) add"]
    #[doc = " relocation and import."]
    machine Draft { source: Vec<u8> }
    capability: plain,
    tenure: vec,
    acceptance: tolerant,
    product: vec,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "Draft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::grouped",
}

crate::revise::grouped::revising_machine! {
    views,
    Machine: Draft,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "Draft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::grouped",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing draft over one moved-in buffer, with borrowed"]
    #[doc = " payloads: [`Draft`]'s sibling for callers whose payload bytes"]
    #[doc = " outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload` and `insert_payload` take `&'p [u8]` and retain"]
    #[doc = " the slice — no staging copy — as a fresh immutable slot per"]
    #[doc = " install; earlier installs keep their slots, so a revert"]
    #[doc = " restores the exact prior payload, and the save's byte"]
    #[doc = " fidelity — padding included — reads exactly as [`Draft`]'s."]
    #[doc = " The price is the profile: every payload owner must outlive"]
    #[doc = " the draft, `'p` rides the type, and the staged payload frames"]
    #[doc = " (which exist to copy chunks in) have no place here. Saves"]
    #[doc = " copy each live payload once into the owned product;"]
    #[doc = " `save_sink` hands the slices through; the saved buffer"]
    #[doc = " carries no borrow."]
    #[doc = ""]
    #[doc = " Everything else is [`Draft`]'s contract: transactional tenure"]
    #[doc = " at both doors, exact undo, handles orphaned only by a payload"]
    #[doc = " replacement, and monotone storage growth."]
    #[doc = ""]
    #[doc = " Plain data over an owned `Vec<u8>` and shared slices: no"]
    #[doc = " share counting, no interior mutability — the machine is"]
    #[doc = " `Send + Sync` like its copy-only sibling, and a mid-edit"]
    #[doc = " draft moves, returns, and caches."]
    #[doc = ""]
    #[doc = " # Examples"]
    #[doc = ""]
    #[doc = " Fidelity around a borrowed install: untouched padded framing"]
    #[doc = " rides verbatim, and reverting restores the source bytes"]
    #[doc = " exactly:"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::draft::grouped::BorrowDraft;"]
    #[doc = ""]
    #[doc = " let payload = [0x08, 0x07];"]
    #[doc = ""]
    #[doc = " // varint f1=150 (value padded to three bytes) · LEN f2 \"a\""]
    #[doc = " let source = vec![0x08, 0x96, 0x81, 0x00, 0x12, 0x01, 0x61];"]
    #[doc = " let mut draft = BorrowDraft::open(source.clone()).unwrap();"]
    #[doc = " let tops: Vec<_> = draft.top().collect();"]
    #[doc = " draft.set_payload(tops[1], &payload).unwrap();"]
    #[doc = ""]
    #[doc = " // The padded varint rides verbatim beside the replacement."]
    #[doc = " let saved = draft.save().unwrap();"]
    #[doc = " assert_eq!(saved, [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x08, 0x07]);"]
    #[doc = ""]
    #[doc = " draft.revert();"]
    #[doc = " assert_eq!(draft.save().unwrap(), source);"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " The canonical-output faces ride this form exactly as the"]
    #[doc = " copy-only sibling's, changing neither its lifetimes nor its"]
    #[doc = " allocation profile."]
    machine BorrowDraft<'p> { source: Vec<u8> }
    capability: plain,
    payload: borrow,
    tenure: vec,
    acceptance: tolerant,
    product: vec,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "BorrowDraft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::grouped",
}

// The machine layouts, pinned exactly, with the cross-form
// delta retained. Size pins, not field-semantics proofs: the delta
// alone would stay green under a same-sized field substitution in
// both forms, so the absolutes force any layout change through
// review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<Draft>() == if w64 { 288 } else { 152 });
    assert!(core::mem::size_of::<BorrowDraft<'_>>() == if w64 { 264 } else { 140 });
    assert!(
        core::mem::size_of::<BorrowDraft<'_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Draft>()
    );
};

crate::revise::grouped::revising_machine! {
    #[doc = " An editing draft over one moved-in buffer, with per-install"]
    #[doc = " payload backing: [`Draft`]'s sibling for callers who mix"]
    #[doc = " long-lived payload slices with transient ones on one handle"]
    #[doc = " arena and one revision log."]
    #[doc = ""]
    #[doc = " Each install selects its backing at the face. The unsuffixed"]
    #[doc = " faces (`set_payload`, `insert_payload`) take `&'p [u8]` and"]
    #[doc = " retain the slice — no staging copy, the"]
    #[doc = " owner must outlive the draft. Their `_copy` twins"]
    #[doc = " (`set_payload_copy`, `insert_payload_copy`) and the staged"]
    #[doc = " payload frames (`begin_set_payload` and kin, which exist to"]
    #[doc = " copy chunks in and so carry no `_copy` suffix) copy the bytes"]
    #[doc = " into the draft, so temporaries pass through them freely."]
    #[doc = " Either way each install appends one immutable slot; earlier"]
    #[doc = " installs keep theirs, whichever backing they chose, so a"]
    #[doc = " revert restores the exact prior payload — and the save's byte"]
    #[doc = " fidelity, padding included, reads exactly as [`Draft`]'s."]
    #[doc = " Saves copy each live payload once into the owned product"]
    #[doc = " (`save_sink` hands slices through); the saved buffer carries"]
    #[doc = " no borrow."]
    #[doc = ""]
    #[doc = " Everything else is [`Draft`]'s contract: transactional tenure"]
    #[doc = " at both doors, exact undo, handles orphaned only by a payload"]
    #[doc = " replacement, and monotone storage growth."]
    #[doc = ""]
    #[doc = " Plain data over an owned `Vec<u8>`, retained slices, and"]
    #[doc = " copied bytes: no share counting, no interior mutability — the"]
    #[doc = " machine is `Send + Sync` like both its siblings, and a"]
    #[doc = " mid-edit draft moves, returns, and caches."]
    #[doc = ""]
    #[doc = " # Examples"]
    #[doc = ""]
    #[doc = " Borrowed and copied installs interleave on one log, and each"]
    #[doc = " revert restores the exact prior payload — fidelity included:"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::draft::grouped::MixDraft;"]
    #[doc = ""]
    #[doc = " let template = [0x08, 0x01];"]
    #[doc = ""]
    #[doc = " // varint f1=150 (value padded to three bytes) · LEN f2 \"a\""]
    #[doc = " let source = vec![0x08, 0x96, 0x81, 0x00, 0x12, 0x01, 0x61];"]
    #[doc = " let mut draft = MixDraft::open(source.clone()).unwrap();"]
    #[doc = " let tops: Vec<_> = draft.top().collect();"]
    #[doc = " draft.set_payload(tops[1], &template).unwrap();"]
    #[doc = " {"]
    #[doc = "     // The transient owner dies right after the call."]
    #[doc = "     let transient = vec![0x08, 0x07];"]
    #[doc = "     draft.set_payload_copy(tops[1], &transient).unwrap();"]
    #[doc = " }"]
    #[doc = ""]
    #[doc = " // The padded varint rides verbatim beside the replacement."]
    #[doc = " let saved = draft.save().unwrap();"]
    #[doc = " assert_eq!(saved, [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x08, 0x07]);"]
    #[doc = ""]
    #[doc = " // Undo restores the borrowed install, then the source."]
    #[doc = " draft.revert();"]
    #[doc = " assert_eq!(draft.save().unwrap(), [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x08, 0x01]);"]
    #[doc = " draft.revert();"]
    #[doc = " assert_eq!(draft.save().unwrap(), source);"]
    #[doc = " ```"]
    machine MixDraft<'p> { source: Vec<u8> }
    capability: plain,
    payload: mixed,
    tenure: vec,
    acceptance: tolerant,
    product: vec,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "MixDraft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::grouped",
}

// The mixed machine's layout, pinned exactly at the copy
// form's absolute (the mixed store matches the copied store's five
// headers). A size pin, not a field-semantics proof: any layout
// change lands here for review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<MixDraft<'_>>() == if w64 { 288 } else { 152 });
    assert!(core::mem::size_of::<MixDraft<'_>>() == core::mem::size_of::<Draft>());
};

crate::revise::grouped::revising_machine! {
    frames for Draft (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "Draft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::grouped",
    frame_doc: [],
    sized_doc: [],
}

crate::revise::grouped::revising_machine! {
    frames for MixDraft<'p> (MixPayloadFrame, MixSizedPayloadFrame),
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
    door: "MixDraft::open_copy(&msg)",
    doc_mod: "protobuf_edit::draft::grouped",
    frame_doc: [],
    sized_doc: [],
}
