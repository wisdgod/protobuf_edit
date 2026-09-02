//! The grouped editing markup: handle-based edits with precise
//! undo over one borrowed slice, saved in two passes with the
//! one-shot patch's byte fidelity.
//!
//! Admission is tolerant: padded tags, length prefixes, and varint
//! values are lawful input, so every framing width the scan meets
//! is stored on the row as an input fact — a group row carries its
//! end tag's width — and every untouched span reproduces its
//! padding byte-exactly at save. Group records materialize eagerly
//! at scan (the scan is the parse; the open-group chain is the row
//! arena itself, so nesting costs no stack); LEN payloads stay
//! opaque until [`Markup::descend`], whose verdict is resident —
//! a wire fault inside a payload parks on the slot and the markup
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
//! the markup's observable state untouched. Allocation refusals
//! surface as structured errors ([`OpenFault::Resource`],
//! [`EditFault::Resource`], [`SaveFault::Resource`]); nothing in this
//! module aborts on allocator pressure.
//!
//! Coordinates: write · buffered · offline · grouped · tolerant (type-level) · borrowed · revisable.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::markup::grouped::Markup;
//!
//! // varint f1=150 (value padded) · group f2 { varint f3=1 }
//! let msg = [0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x01, 0x14];
//! let mut markup = Markup::open(&msg).unwrap();
//!
//! // Groups materialize at scan: the interior is already there.
//! let tops: Vec<_> = markup.top().collect();
//! let inner = markup.children(tops[1]).unwrap().next().unwrap();
//! assert_eq!(markup.varint_word(inner).unwrap(), 1);
//!
//! // Replace the group's interior value: the group framing and
//! // the padded sibling ride verbatim through the save.
//! markup.set_varint(inner, 7).unwrap();
//! let saved = markup.save().unwrap();
//! assert_eq!(saved, [0x08, 0x96, 0x81, 0x00, 0x13, 0x18, 0x07, 0x14]);
//! ```

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::markup::{
    At32, BorrowStore, Edit, Handle, MixStore, RowId, Store, StoreFault, Transition, ValueAt, admit,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
pub use crate::markup::command::{EditStatus, InsertAt};

#[cfg(feature = "transfer-markup-grouped")]
pub mod transfer;

#[cfg(feature = "transfer-markup-grouped")]
pub use transfer::{TransferBorrowMarkup, TransferMarkup};

#[cfg(test)]
mod tests;

crate::revise::grouped::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        OpenFault, RecordSpans, SaveFault, SaveSpans,
    ),
    capability: plain,
    tenure: borrow,
    acceptance: tolerant,
    product: vec,
    Machine: Markup,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "Markup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing markup over one borrowed slice."]
    #[doc = ""]
    #[doc = " Handles stay valid for the markup's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: [`Markup::revert`] walks the log backwards and restores"]
    #[doc = " the save-observable state of the previous step — byte"]
    #[doc = " fidelity included, padding and all; orphaned handles are not"]
    #[doc = " revived."]
    #[doc = ""]
    #[doc = " Markup storage grows monotonically: rows and stored values are"]
    #[doc = " never reclaimed (the handle contract names them for the"]
    #[doc = " markup's life), and each descend of a re-sealed container"]
    #[doc = " mints fresh interior rows, a fresh layer descriptor, and — for"]
    #[doc = " source-backed payloads — a fresh run entry, leaving the"]
    #[doc = " orphaned ones behind inert. Each replace → revert → re-descend"]
    #[doc = " cycle therefore re-mints the whole interior; a long-lived"]
    #[doc = " editor budgets for that growth or reopens the document at its"]
    #[doc = " checkpoints."]
    #[doc = ""]
    #[doc = " Plain data over a borrowed `&[u8]`: no share counting, no"]
    #[doc = " interior mutability — the machine is `Send + Sync` because"]
    #[doc = " there is nothing to engineer around, and a mid-edit markup"]
    #[doc = " moves, returns, and caches within the borrow's extent (rows"]
    #[doc = " address the source by `u32` offsets, never pointers)."]
    #[doc = ""]
    #[doc = " The canonical-output faces (the `save_canonical` family)"]
    #[doc = " ride every payload-backing form — this one, [`BorrowMarkup`],"]
    #[doc = " and [`MixMarkup`] — without changing any form's lifetime or"]
    #[doc = " allocation profile."]
    #[doc = ""]
    #[doc = " The transfer siblings `TransferMarkup` and"]
    #[doc = " `TransferBorrowMarkup` (feature `transfer-markup-grouped`) add"]
    #[doc = " relocation and import."]
    machine Markup<'m> { source: &'m [u8] }
    capability: plain,
    tenure: borrow,
    acceptance: tolerant,
    product: vec,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "Markup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped",
}

// The machine layout, pinned exactly — a size pin, not a
// field-semantics proof: any layout change lands here for review.
const _: () = assert!(
    core::mem::size_of::<Markup<'_>>() == if cfg!(target_pointer_width = "64") { 280 } else { 148 }
);

crate::revise::grouped::revising_machine! {
    #[doc = " An editing markup over one borrowed slice, with borrowed"]
    #[doc = " payloads: [`Markup`]'s sibling for callers whose payload"]
    #[doc = " bytes outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload` and `insert_payload` take `&'p [u8]` and retain"]
    #[doc = " the slice — no staging copy — as a fresh immutable slot per"]
    #[doc = " install; earlier installs keep their slots, so a revert"]
    #[doc = " restores the exact prior payload. The price is the profile:"]
    #[doc = " every payload owner must outlive the markup, `'p` rides the"]
    #[doc = " type beside the source borrow, and the staged payload frames"]
    #[doc = " (which exist to copy chunks in) have no place here. Saves"]
    #[doc = " copy each live payload once into the owned product;"]
    #[doc = " `save_sink` hands the slices through; the saved bytes carry"]
    #[doc = " no borrow."]
    #[doc = ""]
    #[doc = " Everything else is [`Markup`]'s contract: tolerant admission, byte fidelity for"]
    #[doc = " untouched records, exact undo, and monotonic storage — and"]
    #[doc = " it stays plain `Send + Sync` data over its two borrows."]
    #[doc = ""]
    #[doc = " The canonical-output faces ride this form exactly as the"]
    #[doc = " copy-only sibling's, changing neither its lifetimes nor its"]
    #[doc = " allocation profile."]
    machine BorrowMarkup<'m, 'p> { source: &'m [u8] }
    capability: plain,
    payload: borrow,
    tenure: borrow,
    acceptance: tolerant,
    product: vec,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "BorrowMarkup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped",
}

// The machine layouts, pinned exactly, with the cross-form
// delta retained. Size pins, not field-semantics proofs: the delta
// alone would stay green under a same-sized field substitution in
// both forms, so the absolutes force any layout change through
// review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<BorrowMarkup<'_, '_>>() == if w64 { 256 } else { 136 });
    assert!(
        core::mem::size_of::<BorrowMarkup<'_, '_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Markup>()
    );
};

crate::revise::grouped::revising_machine! {
    #[doc = " An editing markup over one borrowed slice, with per-install"]
    #[doc = " payload backing."]
    #[doc = ""]
    #[doc = " [`Markup`]'s sibling for callers who mix long-lived payload"]
    #[doc = " slices with transient ones on one handle arena and one"]
    #[doc = " revision log."]
    #[doc = ""]
    #[doc = " Each install selects its backing at the face. The unsuffixed"]
    #[doc = " faces (`set_payload`, `insert_payload`) take `&'p [u8]` and"]
    #[doc = " retain the slice — no staging copy, the"]
    #[doc = " owner must outlive the markup. Their `_copy` twins"]
    #[doc = " (`set_payload_copy`, `insert_payload_copy`) and the staged"]
    #[doc = " payload frames (`begin_set_payload` and kin, which exist to"]
    #[doc = " copy chunks in and so carry no `_copy` suffix) copy the bytes"]
    #[doc = " into the markup, so temporaries pass through them freely."]
    #[doc = " Either way each install appends one immutable slot; earlier"]
    #[doc = " installs keep theirs, whichever backing they chose, so a"]
    #[doc = " revert restores the exact prior payload — and the save's byte"]
    #[doc = " fidelity, padding included, reads exactly as [`Markup`]'s."]
    #[doc = " Saves copy each live payload once into the owned product;"]
    #[doc = " the saved bytes carry no borrow."]
    #[doc = ""]
    #[doc = " `'m` and `'p` are independent: either may outlive the other,"]
    #[doc = " provided both cover the machine's use. Everything else is"]
    #[doc = " [`Markup`]'s contract: tolerant admission, byte fidelity for"]
    #[doc = " untouched records, exact undo, and monotonic storage — and it"]
    #[doc = " stays plain `Send + Sync` data over its borrows."]
    #[doc = ""]
    #[doc = " The canonical-output faces ride this form exactly as its"]
    #[doc = " siblings', changing neither its lifetimes nor its allocation"]
    #[doc = " profile."]
    #[doc = ""]
    #[doc = " # Examples"]
    #[doc = ""]
    #[doc = " The source may outlive the payload owners:"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::markup::grouped::MixMarkup;"]
    #[doc = ""]
    #[doc = " // LEN f2 \"a\"; the source outlives the payload owner."]
    #[doc = " let source = [0x12, 0x01, 0x61];"]
    #[doc = " let saved = {"]
    #[doc = "     let payload = vec![0x08, 0x01];"]
    #[doc = "     let mut markup = MixMarkup::open(&source).unwrap();"]
    #[doc = "     let record = markup.top().next().unwrap();"]
    #[doc = "     markup.set_payload(record, &payload).unwrap();"]
    #[doc = "     markup.save().unwrap()"]
    #[doc = " };"]
    #[doc = " assert_eq!(saved, [0x12, 0x02, 0x08, 0x01]);"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " And the payload owners may outlive the source:"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::markup::grouped::MixMarkup;"]
    #[doc = ""]
    #[doc = " // The payload owner outlives the source buffer."]
    #[doc = " let payload = vec![0x08, 0x01];"]
    #[doc = " let saved = {"]
    #[doc = "     let source = vec![0x12, 0x01, 0x61];"]
    #[doc = "     let mut markup = MixMarkup::open(&source).unwrap();"]
    #[doc = "     let record = markup.top().next().unwrap();"]
    #[doc = "     markup.set_payload(record, &payload).unwrap();"]
    #[doc = "     {"]
    #[doc = "         // A transient owner passes through the copying twin."]
    #[doc = "         let transient = vec![0x08, 0x07];"]
    #[doc = "         markup.set_payload_copy(record, &transient).unwrap();"]
    #[doc = "     }"]
    #[doc = "     markup.revert();"]
    #[doc = "     markup.save().unwrap()"]
    #[doc = " };"]
    #[doc = " assert_eq!(saved, [0x12, 0x02, 0x08, 0x01]);"]
    #[doc = " ```"]
    machine MixMarkup<'m, 'p> { source: &'m [u8] }
    capability: plain,
    payload: mixed,
    tenure: borrow,
    acceptance: tolerant,
    product: vec,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "MixMarkup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped",
}

// The mixed machine's layout, pinned exactly at the copy
// form's absolute (the mixed store matches the copied store's five
// headers). A size pin, not a field-semantics proof: any layout
// change lands here for review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<MixMarkup<'_, '_>>() == if w64 { 280 } else { 148 });
    assert!(core::mem::size_of::<MixMarkup<'_, '_>>() == core::mem::size_of::<Markup>());
};

crate::revise::grouped::revising_machine! {
    views,
    Machine: Markup,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "Markup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped",
}

crate::revise::grouped::revising_machine! {
    frames for Markup<'m> (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "Markup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped",
    frame_doc: [],
    sized_doc: [],
}

crate::revise::grouped::revising_machine! {
    frames for MixMarkup<'m, 'p> (MixPayloadFrame, MixSizedPayloadFrame),
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
    door: "MixMarkup::open(&msg)",
    doc_mod: "protobuf_edit::markup::grouped",
    frame_doc: [],
    sized_doc: [],
}
