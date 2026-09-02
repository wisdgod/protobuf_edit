//! The groupless editing session: handle-based edits with precise
//! undo over one buffered document, saved in two passes.
//!
//! This dialect speaks the four-code wire language: group codes
//! are well-formed wire outside it, refused as a capability
//! judgment ([`Refusal::GroupCode`]) distinct from grammar faults
//! — at the root that refusal stops the open, inside a payload it
//! is a resident verdict and the payload stays readable as bytes.
//!
//! Admission is canonical-minimal: tags, length prefixes, and
//! varint values are accepted only at their own encoded width, so
//! every width downstream is derived from the value it carries and
//! never stored or re-judged. The root layer is flat and eager;
//! LEN payloads stay opaque until [`Session::descend`], whose
//! verdict is resident.
//!
//! Every mutation is transactional: admission judgments come
//! first, every reservation is fallible, and once the store push
//! (or, for storeless commands, the last reservation) succeeds the
//! remaining suffix cannot fail — an `Err` from any command leaves
//! the session's observable state untouched. Allocation refusals
//! surface as structured errors ([`OpenFault::Resource`],
//! [`EditFault::Resource`], [`SaveFault::Resource`]); nothing in this
//! module aborts on allocator pressure.
//!
//! Coordinates: write · buffered · offline · groupless · canonical (type-level) · owned · revisable.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::session::groupless::Session;
//!
//! // varint f1=150 · LEN f2 "hi"
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut session = Session::open_copy(&msg).unwrap();
//! let tops: Vec<_> = session.top().collect();
//! assert_eq!(session.payload_bytes(tops[1]).unwrap(), [0x68, 0x69]);
//!
//! session.set_payload(tops[1], &[0x79, 0x6F]).unwrap();
//! let saved = session.save().unwrap();
//! assert_eq!(saved[..], [0x08, 0x96, 0x01, 0x12, 0x02, 0x79, 0x6F]);
//! ```

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::Span;
use crate::admission::usize_of;
use crate::session::{
    At32, BorrowStore, DocBytes, Edit, Handle, LoadFault, MixStore, RawDoc, RowId, Store,
    StoreFault, Transition, ValueAt,
};
#[cfg(feature = "priced-session-groupless")]
use crate::session::PRICE_CEILING;
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64, push64};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
pub use crate::session::command::{EditStatus, InsertAt};

#[cfg(feature = "transfer-session-groupless")]
pub mod transfer;

#[cfg(feature = "transfer-session-groupless")]
pub use transfer::{TransferBorrowSession, TransferSession};
#[cfg(feature = "priced-transfer-session-groupless")]
pub use transfer::PricedTransferSession;

#[cfg(test)]
mod tests;

crate::revise::groupless::revising_machine! {
    vocabulary(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        OpenFault, PriceFault, RecordSpans, Refusal, SaveFault,
        SaveSpans,
    ),
    capability: plain,
    tenure: carrier,
    acceptance: canonical,
    product: carrier,
    Machine: Session,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "Session::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
}

crate::revise::groupless::revising_machine! {
    #[doc = " An editing session over one sealed document."]
    #[doc = ""]
    #[doc = " Handles stay valid for the session's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo is"]
    #[doc = " exact: [`Session::revert`] walks the log backwards and restores"]
    #[doc = " the save-observable state of the previous step; orphaned"]
    #[doc = " handles are not revived."]
    #[doc = ""]
    #[doc = " Session storage grows monotonically: rows and stored values are"]
    #[doc = " never reclaimed (the handle contract names them for the"]
    #[doc = " session's life), and each descend of a re-sealed container"]
    #[doc = " mints fresh interior rows, a fresh layer descriptor, and — for"]
    #[doc = " source-backed payloads — a fresh run entry, leaving the"]
    #[doc = " orphaned ones behind inert. Each replace → revert → re-descend"]
    #[doc = " cycle therefore re-mints the whole interior; a long-lived"]
    #[doc = " editor budgets for that growth or reopens the document at its"]
    #[doc = " checkpoints."]
    #[doc = ""]
    #[doc = " The payload-backing siblings are [`BorrowSession`] (retains"]
    #[doc = " borrowed payload slices) and [`MixSession`] (backing chosen"]
    #[doc = " per install); the transfer siblings `TransferSession` and"]
    #[doc = " `TransferBorrowSession` (feature `transfer-session-groupless`)"]
    #[doc = " add relocation and import, and the priced wrapper"]
    #[doc = " `PricedSession` (feature `priced-session-groupless`) settles"]
    #[doc = " the save price per command over this same form."]
    #[doc = ""]
    #[doc = " `!Send + !Sync` like the [`DocBytes`] it owns: editing is"]
    #[doc = " single-threaded by design."]
    #[doc = ""]
    #[doc = " ```compile_fail"]
    #[doc = " fn sendable<T: Send>() {}"]
    #[doc = " sendable::<protobuf_edit::session::groupless::Session>();"]
    #[doc = " ```"]
    machine Session { source: DocBytes }
    capability: plain,
    tenure: carrier,
    acceptance: canonical,
    product: carrier,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "Session::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
}

crate::revise::groupless::revising_machine! {
    views,
    Machine: Session,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "Session::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
}

crate::revise::groupless::revising_machine! {
    #[doc = " An editing session over one sealed document, with borrowed"]
    #[doc = " payloads: [`Session`]'s sibling for callers whose payload"]
    #[doc = " bytes outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload` and `insert_payload` take `&'p [u8]` and retain"]
    #[doc = " the slice — no staging copy — as a fresh immutable slot per"]
    #[doc = " install; earlier installs keep their slots, so a revert"]
    #[doc = " restores the exact prior payload. The price is the profile:"]
    #[doc = " every payload owner must outlive the session, `'p` rides the"]
    #[doc = " type, and the staged payload frames (which exist to copy"]
    #[doc = " chunks in) have no place here. Saves copy each live payload"]
    #[doc = " once into the owned product; `save_sink` hands the slices"]
    #[doc = " through; the saved document carries no borrow."]
    #[doc = ""]
    #[doc = " Everything else is [`Session`]'s contract: handles stay valid"]
    #[doc = " until a payload replacement orphans the rows parsed out of"]
    #[doc = " the old payload, undo is exact, and storage grows"]
    #[doc = " monotonically — rows, slots, and stored values are never"]
    #[doc = " reclaimed while the session lives."]
    #[doc = ""]
    #[doc = " `!Send + !Sync` like the [`DocBytes`] it owns: editing is"]
    #[doc = " single-threaded by design."]
    #[doc = ""]
    #[doc = " ```compile_fail"]
    #[doc = " fn sendable<T: Send>() {}"]
    #[doc = " sendable::<protobuf_edit::session::groupless::BorrowSession<'static>>();"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " # Examples"]
    #[doc = ""]
    #[doc = " Independent owners back independent installs, and the machine"]
    #[doc = " moves while they live:"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::session::groupless::BorrowSession;"]
    #[doc = ""]
    #[doc = " let alpha = vec![0x08, 0x01];"]
    #[doc = " let beta = [0x08, 0x02];"]
    #[doc = ""]
    #[doc = " // LEN f2 \"a\""]
    #[doc = " let mut session = BorrowSession::open_copy(&[0x12, 0x01, 0x61]).unwrap();"]
    #[doc = " let record = session.top().next().unwrap();"]
    #[doc = " session.set_payload(record, &alpha).unwrap();"]
    #[doc = " let first = session.save().unwrap();"]
    #[doc = ""]
    #[doc = " session.set_payload(record, &beta).unwrap();"]
    #[doc = " assert_eq!(session.pending(), 2);"]
    #[doc = ""]
    #[doc = " // The machine moves; the borrows ride along."]
    #[doc = " let mut moved = session;"]
    #[doc = " assert_eq!(moved.save().unwrap()[..], [0x12, 0x02, 0x08, 0x02]);"]
    #[doc = ""]
    #[doc = " // Undo restores the earlier install's exact bytes."]
    #[doc = " moved.revert();"]
    #[doc = " assert_eq!(moved.save().unwrap()[..], first[..]);"]
    #[doc = " ```"]
    machine BorrowSession<'p> { source: DocBytes }
    capability: plain,
    payload: borrow,
    tenure: carrier,
    acceptance: canonical,
    product: carrier,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "BorrowSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
}

// The machine layouts, pinned exactly, with the cross-form
// delta retained. Size pins, not field-semantics proofs: the delta
// alone would stay green under a same-sized field substitution in
// both forms, so the absolutes force any layout change through
// review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<Session>() == if w64 { 280 } else { 148 });
    assert!(core::mem::size_of::<BorrowSession<'_>>() == if w64 { 256 } else { 136 });
    assert!(
        core::mem::size_of::<BorrowSession<'_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Session>()
    );
};

crate::revise::groupless::revising_machine! {
    #[doc = " An editing session over one sealed document, with per-install"]
    #[doc = " payload backing."]
    #[doc = ""]
    #[doc = " [`Session`]'s sibling for callers who mix long-lived payload"]
    #[doc = " slices with transient ones on one handle arena and one"]
    #[doc = " revision log."]
    #[doc = ""]
    #[doc = " Each install selects its backing at the face. The unsuffixed"]
    #[doc = " faces (`set_payload`, `insert_payload`) take `&'p [u8]` and"]
    #[doc = " retain the slice — no staging copy, the"]
    #[doc = " owner must outlive the session. Their `_copy` twins"]
    #[doc = " (`set_payload_copy`, `insert_payload_copy`) and the staged"]
    #[doc = " payload frames (`begin_set_payload` and kin, which exist to"]
    #[doc = " copy chunks in and so carry no `_copy` suffix) copy the bytes"]
    #[doc = " into the session, so temporaries pass through them freely."]
    #[doc = " Either way each install appends one immutable slot; earlier"]
    #[doc = " installs keep theirs, whichever backing they chose, so a"]
    #[doc = " revert restores the exact prior payload — install a borrowed"]
    #[doc = " template, copy a transient over it, install another borrow,"]
    #[doc = " and two reverts walk back through both. Saves copy each live"]
    #[doc = " payload once into the owned product (`save_sink` hands slices"]
    #[doc = " through); the saved document carries no borrow. No priced"]
    #[doc = " typestate door: the price-settling wrapper rides the"]
    #[doc = " copy-only [`Session`] alone."]
    #[doc = ""]
    #[doc = " Everything else is [`Session`]'s contract: handles stay valid"]
    #[doc = " until a payload replacement orphans the rows parsed out of"]
    #[doc = " the old payload, undo is exact, and storage grows"]
    #[doc = " monotonically — rows, slots, and stored values are never"]
    #[doc = " reclaimed while the session lives."]
    #[doc = ""]
    #[doc = " `!Send + !Sync` like the [`DocBytes`] it owns: editing is"]
    #[doc = " single-threaded by design."]
    #[doc = ""]
    #[doc = " ```compile_fail"]
    #[doc = " fn sendable<T: Send>() {}"]
    #[doc = " sendable::<protobuf_edit::session::groupless::MixSession<'static>>();"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " # Examples"]
    #[doc = ""]
    #[doc = " Borrowed and copied installs interleave on one log, and each"]
    #[doc = " revert restores the exact prior payload:"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::session::groupless::MixSession;"]
    #[doc = ""]
    #[doc = " let template = vec![0x08, 0x01];"]
    #[doc = ""]
    #[doc = " // LEN f2 \"a\""]
    #[doc = " let mut session = MixSession::open_copy(&[0x12, 0x01, 0x61]).unwrap();"]
    #[doc = " let record = session.top().next().unwrap();"]
    #[doc = " session.set_payload(record, &template).unwrap();"]
    #[doc = " {"]
    #[doc = "     // The transient owner dies right after the call."]
    #[doc = "     let transient = vec![0x08, 0x07];"]
    #[doc = "     session.set_payload_copy(record, &transient).unwrap();"]
    #[doc = " }"]
    #[doc = " assert_eq!(session.save().unwrap()[..], [0x12, 0x02, 0x08, 0x07]);"]
    #[doc = ""]
    #[doc = " // Undo restores the borrowed install, then the source."]
    #[doc = " session.revert();"]
    #[doc = " assert_eq!(session.save().unwrap()[..], [0x12, 0x02, 0x08, 0x01]);"]
    #[doc = " session.revert();"]
    #[doc = " assert_eq!(session.save().unwrap()[..], [0x12, 0x01, 0x61]);"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " A borrowed payload must outlive the session — the type"]
    #[doc = " refuses an owner that dies while the machine can still read"]
    #[doc = " the slot (`set_payload_copy` is the escape hatch for"]
    #[doc = " temporaries):"]
    #[doc = ""]
    #[doc = " ```compile_fail,E0597"]
    #[doc = " use protobuf_edit::session::groupless::MixSession;"]
    #[doc = ""]
    #[doc = " let msg = [0x12, 0x01, 0x61];"]
    #[doc = " let mut session = MixSession::open_copy(&msg).unwrap();"]
    #[doc = " let record = session.top().next().unwrap();"]
    #[doc = " {"]
    #[doc = "     let transient = vec![0x08, 0x07];"]
    #[doc = "     session.set_payload(record, &transient).unwrap();"]
    #[doc = " } // the owner dies here; the session still holds the borrow"]
    #[doc = " session.save().unwrap();"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " And a retained owner may not be mutated while the machine can"]
    #[doc = " still read the slot — the install borrows it for the"]
    #[doc = " session's remaining life:"]
    #[doc = ""]
    #[doc = " ```compile_fail,E0502"]
    #[doc = " use protobuf_edit::session::groupless::MixSession;"]
    #[doc = ""]
    #[doc = " let msg = [0x12, 0x01, 0x61];"]
    #[doc = " let mut payload = vec![0x08, 0x07];"]
    #[doc = " let mut session = MixSession::open_copy(&msg).unwrap();"]
    #[doc = " let record = session.top().next().unwrap();"]
    #[doc = " session.set_payload(record, &payload).unwrap();"]
    #[doc = " payload.clear(); // the session still holds the borrow"]
    #[doc = " session.save().unwrap();"]
    #[doc = " ```"]
    machine MixSession<'p> { source: DocBytes }
    capability: plain,
    payload: mixed,
    tenure: carrier,
    acceptance: canonical,
    product: carrier,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "MixSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
}

// The mixed machine's layout, pinned exactly at the copy
// form's absolute (the mixed store matches the copied store's five
// headers). A size pin, not a field-semantics proof: any layout
// change lands here for review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<MixSession<'_>>() == if w64 { 280 } else { 148 });
    assert!(core::mem::size_of::<MixSession<'_>>() == core::mem::size_of::<Session>());
};

#[cfg(feature = "priced-session-groupless")]
crate::revise::groupless::revising_machine! {
    #[doc = " An editing session that knows its exact save price at all"]
    #[doc = " times: [`Session`]'s faces with the price settled at every"]
    #[doc = " command instead of walked at every ask."]
    #[doc = ""]
    #[doc = " Each command runs the wrapped gates first and derives its own"]
    #[doc = " price delta before anything is reserved. A price-neutral"]
    #[doc = " command — fixed-width replacement always, any other command"]
    #[doc = " whose derived delta is zero — commits with no ledger work at"]
    #[doc = " all; a price-moving one pays one reservation walk plus one"]
    #[doc = " settling climb over the record's ancestor chain, both"]
    #[doc = " O(depth): the walk reserves exactly the ledger entries still"]
    #[doc = " missing, the climb updates a body, judges the length class,"]
    #[doc = " and moves the prefix width per level."]
    #[doc = " [`PricedSession::save_len`] answers in O(1) while every"]
    #[doc = " rewritten body sits in the length class."]
    #[doc = " Commands never refuse or saturate on caps: the accounting is"]
    #[doc = " exact through over-cap states, and the fault surfaces where"]
    #[doc = " the plain session surfaces it — at the save faces, byte-exact."]
    #[doc = " A revert settles the same climb from the log's restored state,"]
    #[doc = " with zero allocation. The doors are"]
    #[doc = " [`Session::into_priced`] and"]
    #[doc = " [`PricedSession::into_session`]. [`PricedSession::save`] runs"]
    #[doc = " one native emit walk fed by the settled ledger while every"]
    #[doc = " body sits in the length class — no sizing walk; the other"]
    #[doc = " save faces and the over-cap tiers keep the base two-pass"]
    #[doc = " machinery."]
    #[doc = ""]
    #[doc = " `!Send + !Sync` like the [`Session`] it wraps: editing is"]
    #[doc = " single-threaded by design."]
    #[doc = ""]
    #[doc = " ```compile_fail"]
    #[doc = " fn sendable<T: Send>() {}"]
    #[doc = " sendable::<protobuf_edit::session::groupless::PricedSession>();"]
    #[doc = " ```"]
    #[doc = ""]
    #[doc = " # Examples"]
    #[doc = ""]
    #[doc = " ```"]
    #[doc = " use protobuf_edit::session::groupless::Session;"]
    #[doc = ""]
    #[doc = " // varint f1=150 · LEN f2 \"hi\""]
    #[doc = " let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];"]
    #[doc = " let session = Session::open_copy(&msg).unwrap();"]
    #[doc = " let Ok(mut priced) = session.into_priced() else { unreachable!() };"]
    #[doc = ""]
    #[doc = " // Every command settles the price; save_len answers in O(1)."]
    #[doc = " let record = priced.top().next().unwrap();"]
    #[doc = " priced.set_varint(record, 7).unwrap();"]
    #[doc = " assert_eq!(priced.save_len(), Ok(6));"]
    #[doc = " assert_eq!(priced.save().unwrap().len(), 6);"]
    #[doc = ""]
    #[doc = " // The inverse door releases the plain session, undo intact."]
    #[doc = " let mut session = priced.into_session();"]
    #[doc = " assert_eq!(session.pending(), 1);"]
    #[doc = " session.revert();"]
    #[doc = " assert_eq!(session.save().unwrap()[..], msg[..]);"]
    #[doc = " ```"]
    machine PricedSession over Session,
    capability: plain,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "Session::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
}

// The priced wrapper's layout, pinned exactly per pointer width:
// the wrapped
// machine, the ledger map's control block, the total, and the
// padded census word. A size pin, not a field-semantics proof —
// any layout change (the map's internals included) lands here for
// review.
#[cfg(feature = "priced-session-groupless")]
const _: () = assert!(
    core::mem::size_of::<PricedSession>()
        == if cfg!(target_pointer_width = "64") { 328 } else { 176 }
);

#[cfg(feature = "priced-session-groupless")]
crate::revise::groupless::revising_machine! {
    frames for PricedSession over Session (PricedPayloadFrame, PricedSizedPayloadFrame),
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "Session::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
    frame_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`PricedSession`] it exclusively"]
        #[doc = " borrows: editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::groupless::PricedPayloadFrame<'static>>();"]
        #[doc = " ```"]
    ],
    sized_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`PricedSession`] it exclusively"]
        #[doc = " borrows: editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::groupless::PricedSizedPayloadFrame<'static>>();"]
        #[doc = " ```"]
    ],
}

crate::revise::groupless::revising_machine! {
    frames for Session (PayloadFrame, SizedPayloadFrame, FrameFault),
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "Session::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
    frame_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`Session`] it exclusively borrows:"]
        #[doc = " editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::groupless::PayloadFrame<'static>>();"]
        #[doc = " ```"]
    ],
    sized_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`Session`] it exclusively borrows:"]
        #[doc = " editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::groupless::SizedPayloadFrame<'static>>();"]
        #[doc = " ```"]
    ],
}

crate::revise::groupless::revising_machine! {
    frames for MixSession<'p> (MixPayloadFrame, MixSizedPayloadFrame),
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
    door: "MixSession::open_copy(&msg)",
    doc_mod: "protobuf_edit::session::groupless",
    frame_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`MixSession`] it exclusively"]
        #[doc = " borrows: editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::groupless::MixPayloadFrame<'static, 'static>>();"]
        #[doc = " ```"]
    ],
    sized_doc: [
        #[doc = ""]
        #[doc = " `!Send + !Sync` like the [`MixSession`] it exclusively"]
        #[doc = " borrows: editing is single-threaded by design."]
        #[doc = ""]
        #[doc = " ```compile_fail"]
        #[doc = " fn sendable<T: Send>() {}"]
        #[doc = " sendable::<protobuf_edit::session::groupless::MixSizedPayloadFrame<'static, 'static>>();"]
        #[doc = " ```"]
    ],
}
