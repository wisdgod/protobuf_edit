//! The grouped editing review: handle-based edits with precise
//! undo over one borrowed slice under canonical-minimal admission,
//! saved in two passes.
//!
//! Admission is canonical-minimal: tags, length prefixes, and
//! varint values are accepted only at their own encoded width, so
//! every width downstream is derived from the value it carries and
//! never stored or re-judged. Group records materialize eagerly
//! at scan (the scan is the parse; the open-group chain is the row
//! arena itself, so nesting costs no stack); LEN payloads stay
//! opaque until [`Review::descend`], whose verdict is resident —
//! a wire fault or a refusal inside a payload parks on the slot
//! and the review lives on.
//!
//! Every mutation is transactional: admission judgments come
//! first, every reservation is fallible, and once the store push
//! (or, for storeless commands, the last reservation) succeeds the
//! remaining suffix cannot fail — an `Err` from any command leaves
//! the review's observable state untouched. Allocation refusals
//! surface as structured errors ([`OpenFault::Resource`],
//! [`EditFault::Resource`], [`SaveFault::Resource`]); nothing in this
//! module aborts on allocator pressure.
//!
//! Coordinates: write · buffered · offline · grouped · canonical (type-level) · borrowed · revisable.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::review::grouped::Review;
//!
//! // varint f1=150 · group f2 { varint f3=1 }
//! let msg = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
//! let mut review = Review::open(&msg).unwrap();
//!
//! // Groups materialize at scan: the interior is already there.
//! let tops: Vec<_> = review.top().collect();
//! let inner = review.children(tops[1]).unwrap().next().unwrap();
//! assert_eq!(review.varint_word(inner).unwrap(), 1);
//!
//! // Replace the group's interior value: everything untouched
//! // rides verbatim through the save.
//! review.set_varint(inner, 7).unwrap();
//! let saved = review.save().unwrap();
//! assert_eq!(saved, [0x08, 0x96, 0x01, 0x13, 0x18, 0x07, 0x14]);
//! ```

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::review::{
    At32, BorrowStore, Edit, Handle, MixStore, RowId, Store, StoreFault, Transition, ValueAt, admit,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
pub use crate::review::command::{EditStatus, InsertAt};

#[cfg(feature = "transfer-review-grouped")]
pub mod transfer;

#[cfg(feature = "transfer-review-grouped")]
pub use transfer::{TransferBorrowReview, TransferReview};

#[cfg(test)]
mod tests;

crate::revise::grouped::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        OpenFault, RecordSpans, Refusal, SaveFault, SaveSpans,
    ),
    capability: plain,
    tenure: borrow,
    acceptance: canonical,
    product: vec,
    Machine: Review,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "Review::open(&msg)",
    doc_mod: "protobuf_edit::review::grouped",
}

crate::revise::grouped::revising_machine! {
    #[doc = " An editing review over one borrowed slice under"]
    #[doc = " canonical-minimal admission."]
    #[doc = ""]
    #[doc = " Handles stay valid for the review's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: [`Review::revert`] walks the log backwards and restores"]
    #[doc = " the save-observable state of the previous step; orphaned"]
    #[doc = " handles are not revived."]
    #[doc = ""]
    #[doc = " Review storage grows monotonically: rows and stored values are"]
    #[doc = " never reclaimed (the handle contract names them for the"]
    #[doc = " review's life), and each descend of a re-sealed container"]
    #[doc = " mints fresh interior rows, a fresh layer descriptor, and — for"]
    #[doc = " source-backed payloads — a fresh run entry, leaving the"]
    #[doc = " orphaned ones behind inert. Each replace → revert → re-descend"]
    #[doc = " cycle therefore re-mints the whole interior; a long-lived"]
    #[doc = " editor budgets for that growth or reopens the document at its"]
    #[doc = " checkpoints."]
    #[doc = ""]
    #[doc = " Plain data over a borrowed `&[u8]`: no share counting, no"]
    #[doc = " interior mutability — the machine is `Send + Sync` because"]
    #[doc = " there is nothing to engineer around, and a mid-edit review"]
    #[doc = " moves, returns, and caches within the borrow's extent (rows"]
    #[doc = " address the source by `u32` offsets, never pointers)."]
    #[doc = ""]
    #[doc = " The payload-backing siblings are [`BorrowReview`] (retains"]
    #[doc = " borrowed payload slices) and [`MixReview`] (backing chosen"]
    #[doc = " per install); the transfer siblings `TransferReview` and"]
    #[doc = " `TransferBorrowReview` (feature `transfer-review-grouped`)"]
    #[doc = " add relocation and import."]
    machine Review<'m> { source: &'m [u8] }
    capability: plain,
    tenure: borrow,
    acceptance: canonical,
    product: vec,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "Review::open(&msg)",
    doc_mod: "protobuf_edit::review::grouped",
}

// The machine layout, pinned exactly — a size pin, not a
// field-semantics proof: any layout change lands here for review.
const _: () = assert!(
    core::mem::size_of::<Review<'_>>() == if cfg!(target_pointer_width = "64") { 280 } else { 148 }
);

crate::revise::grouped::revising_machine! {
    #[doc = " An editing review over one borrowed slice, with borrowed"]
    #[doc = " payloads: [`Review`]'s sibling for callers whose payload"]
    #[doc = " bytes outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload` and `insert_payload` take `&'p [u8]` and retain"]
    #[doc = " the slice — no staging copy — as a fresh immutable slot per"]
    #[doc = " install; earlier installs keep their slots, so a revert"]
    #[doc = " restores the exact prior payload. The price is the profile:"]
    #[doc = " every payload owner must outlive the review, `'p` rides the"]
    #[doc = " type beside the source borrow, and the staged payload frames"]
    #[doc = " (which exist to copy chunks in) have no place here. Saves"]
    #[doc = " copy each live payload once into the owned product;"]
    #[doc = " `save_sink` hands the slices through; the saved bytes carry"]
    #[doc = " no borrow."]
    #[doc = ""]
    #[doc = " Everything else is [`Review`]'s contract: canonical admission, minimality"]
    #[doc = " refusals at the door, exact undo, and monotonic storage —"]
    #[doc = " and it stays plain `Send + Sync` data over its two borrows."]
    machine BorrowReview<'m, 'p> { source: &'m [u8] }
    capability: plain,
    payload: borrow,
    tenure: borrow,
    acceptance: canonical,
    product: vec,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "BorrowReview::open(&msg)",
    doc_mod: "protobuf_edit::review::grouped",
}

// The machine layouts, pinned exactly, with the cross-form
// delta retained. Size pins, not field-semantics proofs: the delta
// alone would stay green under a same-sized field substitution in
// both forms, so the absolutes force any layout change through
// review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<BorrowReview<'_, '_>>() == if w64 { 256 } else { 136 });
    assert!(
        core::mem::size_of::<BorrowReview<'_, '_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Review>()
    );
};

crate::revise::grouped::revising_machine! {
    #[doc = " An editing review over one borrowed slice, with per-install"]
    #[doc = " payload backing."]
    #[doc = ""]
    #[doc = " [`Review`]'s sibling for callers who mix long-lived payload"]
    #[doc = " slices with transient ones on one handle arena and one"]
    #[doc = " revision log."]
    #[doc = ""]
    #[doc = " Each install selects its backing at the face. The unsuffixed"]
    #[doc = " faces (`set_payload`, `insert_payload`) take `&'p [u8]` and"]
    #[doc = " retain the slice — no staging copy, the"]
    #[doc = " owner must outlive the review. Their `_copy` twins"]
    #[doc = " (`set_payload_copy`, `insert_payload_copy`) and the staged"]
    #[doc = " payload frames (`begin_set_payload` and kin, which exist to"]
    #[doc = " copy chunks in and so carry no `_copy` suffix) copy the bytes"]
    #[doc = " into the review, so temporaries pass through them freely."]
    #[doc = " Either way each install appends one immutable slot; earlier"]
    #[doc = " installs keep theirs, whichever backing they chose, so a"]
    #[doc = " revert restores the exact prior payload. Saves copy each live"]
    #[doc = " payload once into the owned product; the saved bytes carry no"]
    #[doc = " borrow."]
    #[doc = ""]
    #[doc = " `'m` and `'p` are independent: either may outlive the other,"]
    #[doc = " provided both cover the machine's use. Everything else is"]
    #[doc = " [`Review`]'s contract: canonical admission, minimality"]
    #[doc = " refusals at the door, exact undo, and monotonic storage — and"]
    #[doc = " it stays plain `Send + Sync` data over its borrows."]
    #[doc = ""]
    #[doc = " # Examples"]
    #[doc = ""]
    #[doc = " The source may outlive the payload owners:"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::review::grouped::MixReview;"]
    #[doc = ""]
    #[doc = " // LEN f2 \"a\"; the source outlives the payload owner."]
    #[doc = " let source = [0x12, 0x01, 0x61];"]
    #[doc = " let saved = {"]
    #[doc = "     let payload = vec![0x08, 0x01];"]
    #[doc = "     let mut review = MixReview::open(&source).unwrap();"]
    #[doc = "     let record = review.top().next().unwrap();"]
    #[doc = "     review.set_payload(record, &payload).unwrap();"]
    #[doc = "     review.save().unwrap()"]
    #[doc = " };"]
    #[doc = " assert_eq!(saved, [0x12, 0x02, 0x08, 0x01]);"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " And the payload owners may outlive the source:"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::review::grouped::MixReview;"]
    #[doc = ""]
    #[doc = " // The payload owner outlives the source buffer."]
    #[doc = " let payload = vec![0x08, 0x01];"]
    #[doc = " let saved = {"]
    #[doc = "     let source = vec![0x12, 0x01, 0x61];"]
    #[doc = "     let mut review = MixReview::open(&source).unwrap();"]
    #[doc = "     let record = review.top().next().unwrap();"]
    #[doc = "     review.set_payload(record, &payload).unwrap();"]
    #[doc = "     {"]
    #[doc = "         // A transient owner passes through the copying twin."]
    #[doc = "         let transient = vec![0x08, 0x07];"]
    #[doc = "         review.set_payload_copy(record, &transient).unwrap();"]
    #[doc = "     }"]
    #[doc = "     review.revert();"]
    #[doc = "     review.save().unwrap()"]
    #[doc = " };"]
    #[doc = " assert_eq!(saved, [0x12, 0x02, 0x08, 0x01]);"]
    #[doc = " ```"]
    machine MixReview<'m, 'p> { source: &'m [u8] }
    capability: plain,
    payload: mixed,
    tenure: borrow,
    acceptance: canonical,
    product: vec,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "MixReview::open(&msg)",
    doc_mod: "protobuf_edit::review::grouped",
}

// The mixed machine's layout, pinned exactly at the copy
// form's absolute (the mixed store matches the copied store's five
// headers). A size pin, not a field-semantics proof: any layout
// change lands here for review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<MixReview<'_, '_>>() == if w64 { 280 } else { 148 });
    assert!(core::mem::size_of::<MixReview<'_, '_>>() == core::mem::size_of::<Review>());
};

crate::revise::grouped::revising_machine! {
    views,
    Machine: Review,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "Review::open(&msg)",
    doc_mod: "protobuf_edit::review::grouped",
}

crate::revise::grouped::revising_machine! {
    frames for Review<'m> (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "Review::open(&msg)",
    doc_mod: "protobuf_edit::review::grouped",
    frame_doc: [],
    sized_doc: [],
}

crate::revise::grouped::revising_machine! {
    frames for MixReview<'m, 'p> (MixPayloadFrame, MixSizedPayloadFrame),
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
    door: "MixReview::open(&msg)",
    doc_mod: "protobuf_edit::review::grouped",
    frame_doc: [],
    sized_doc: [],
}
