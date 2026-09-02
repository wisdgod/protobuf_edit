//! The shared review layer: the value store, the edit algebra,
//! and the coordinate types both dialect reviews build on.
//!
//! A review is the editing session's borrowed twin: the same
//! command set, revision log, canonical-minimal admission, and
//! two-pass save, over a `&[u8]` the caller keeps. A padded tag,
//! length prefix, or varint value is lawful wire this machine
//! refuses at the door (each dialect's `Refusal` names the sites),
//! so every admitted framing word is minimal and no width column
//! exists — spans derive from the record's own facts. Reverting
//! every command restores the source reading exactly.
//!
//! Tenure never transfers: `open` borrows the slice and copies
//! zero bytes, a refusal leaves the caller's buffer untouched (it
//! was never taken), and `source` answers the borrow at its full
//! lifetime — there is no release door because nothing was held.
//! The machine carries the borrow's lifetime, so it pins the
//! source buffer in place for its own life; an editor that must
//! outlive the buffer is `session` (the canonical revisable twin
//! over a sealed carrier).
//!
//! Allocation policy: every growth edge in this scenario is
//! fallible. The store and the reviews' arenas grow through
//! `try_reserve`, the save's output reserves fallibly, and a
//! refusal surfaces as a structured `Err` (the dialects'
//! `OpenFault`/`EditFault`/`SaveFault`) — never an abort: a review
//! carries revisable interactive state across turns, the fallible
//! side of the crate root's partition rule.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other. Descending a LEN is the Commit pole of
//! the per-LEN interpretation axis: an explicit commitment that
//! the payload parses as records — a write machine never
//! speculates.
//!
//! Output acceptance: admission proves the source minimal and
//! authored words emit minimal, so every save re-ingests under the
//! same canonical door — outputs chain — with one caller-declared
//! exception: an authored payload's interior passes through
//! unchanged.
//!
//! Coordinates: write · buffered · offline · canonical (type-level) · borrowed · revisable.
//!
//! # Choosing a face
//!
//! - Opening: `Review::open` borrows the slice and scans its top
//!   layer — zero copies, and a refusal never touched the buffer.
//!   Admission is canonical-minimal — the tolerant revisable
//!   editor over a borrowed slice is `markup` (feature
//!   `markup-*`), the commit-only canonical editor over a borrowed
//!   slice is `amend`, and the owned revisable twin is `session`.
//! - Commands: `set_varint`/`set_i32`/`set_i64`/`set_payload`
//!   replace values; `insert_varint`/`insert_i32`/`insert_i64`/
//!   `insert_payload` (the grouped review adds `insert_group`)
//!   author records; `delete` shrouds and `undelete` restores
//!   exactly; `clear_edit` clears a replacement back to the
//!   scanned state.
//! - Revision — the axis the one-shot editors lack: every command
//!   logs one step; `revert` pops the last, `revert_all` empties
//!   the log, `pending` counts it.
//! - Saving: `save` emits a fresh `Vec<u8>`; `save_into` appends
//!   the same bytes to a buffer the caller keeps; `save_sink`
//!   hands the same bytes to a caller sink slice by slice, no
//!   output buffer (every fault precedes the first handoff, so
//!   the sink receives nothing on `Err`); `save_len` prices any
//!   of them without emitting, and `save_spans` maps every
//!   emitted record to its output span — the cross-save identity
//!   supply.
//! - Payload backing, by type: `Review` copies payloads at the
//!   command — temporaries welcome, no payload lifetime on the
//!   type. Its sibling `BorrowReview<'p>` retains borrowed slices
//!   instead — no staging copy, and every payload owner outlives
//!   the review — and `MixReview<'p>` selects the backing per
//!   install; the recipes below work the borrowed and mixed
//!   profiles.
//! - Relocation and import: the dialect's `transfer` submodule
//!   (feature `transfer-review-*`) ships `TransferReview`
//!   (copying) and `TransferBorrowReview` (borrowing) — the same
//!   faces plus `copy_record`/`move_record` for whole records,
//!   `copy_payload`/`move_payload` for LEN interiors, and
//!   `copy_record_from` importing one designated record from
//!   another document; a move is one command, one pending step,
//!   one revert.
//! - Hex-view supply: `span`/`source_spans` give record geometry
//!   (derived from the record's own facts — admission proved the
//!   framing minimal), and `narrowest` answers "which record
//!   covers this byte".
//!
//! Both dialect reviews ship the same faces; the crate root's
//! feature guide picks the dialect.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "review-groupless")] {
//! use protobuf_edit::review::groupless::{OpenFault, Refusal, Review};
//!
//! // varint f1=150, its value padded to three bytes: lawful wire
//! // the canonical door refuses.
//! let padded = [0x08, 0x96, 0x81, 0x00];
//! let Err(fault) = Review::open(&padded) else { unreachable!() };
//! assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalValue { at: 1, .. })));
//!
//! // Minimal wire admits; edits log and revert exactly.
//! let msg = [0x08, 0x96, 0x01];
//! let mut review = Review::open(&msg).unwrap();
//! let record = review.top().next().unwrap();
//! review.set_varint(record, 7).unwrap();
//! assert_eq!(review.save().unwrap(), [0x08, 0x07]);
//!
//! // Revision restores the source reading exactly.
//! review.revert();
//! assert_eq!(review.save().unwrap(), msg);
//! # }
//! ```
//!
//! # Recipes
//!
//! The undo bracket — a hand-rolled transaction over the revision
//! log: mark `pending` before a compound edit, and on failure pop
//! back to the mark:
//!
//! ```
//! # #[cfg(feature = "review-groupless")] {
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::review::groupless::{InsertAt, Review};
//!
//! let msg = [0x08, 0x2A];
//! let mut review = Review::open(&msg).unwrap();
//! let record = review.top().next().unwrap();
//! review.set_varint(record, 7).unwrap(); // the committed prefix
//!
//! let mark = review.pending();
//! let f2 = FieldNumber::new(2).unwrap();
//! review.insert_varint(InsertAt::TailOf(None), f2, 1).unwrap();
//! review.insert_varint(InsertAt::TailOf(None), f2, 2).unwrap();
//! // The compound edit is abandoned: unwind to the mark, exactly.
//! while review.pending() > mark {
//!     review.revert();
//! }
//! assert_eq!(review.save().unwrap(), [0x08, 0x07]);
//! # }
//! ```
//!
//! The borrowed-payload profile: a template that outlives both the
//! document slice and the review installs without a staging copy:
//!
//! ```
//! # #[cfg(feature = "review-groupless")] {
//! use protobuf_edit::review::groupless::BorrowReview;
//!
//! let template = vec![0x08, 0x2A];
//! // LEN f2 "a".
//! let source = [0x12, 0x01, 0x61];
//! let mut review = BorrowReview::open(&source).unwrap();
//! let record = review.top().next().unwrap();
//! review.set_payload(record, &template).unwrap();
//! // The replacement re-authors the prefix; the source tag rides.
//! assert_eq!(review.save().unwrap(), [0x12, 0x02, 0x08, 0x2A]);
//! review.revert_all();
//! assert_eq!(review.save().unwrap(), source);
//! # }
//! ```
#![cfg_attr(
    feature = "review-groupless",
    doc = "
A borrowed payload must outlive the review — the type refuses
an owner that dies while the machine can still read the slot
(the copy-only `Review` is the escape hatch for temporaries):

```compile_fail,E0597
use protobuf_edit::review::groupless::BorrowReview;

let source = [0x12, 0x01, 0x61];
let mut review = BorrowReview::open(&source).unwrap();
let record = review.top().next().unwrap();
{
    let transient = vec![0x08, 0x07];
    review.set_payload(record, &transient).unwrap();
} // the owner dies here; the review still holds the borrow
review.save().unwrap();
```"
)]
#![cfg_attr(
    feature = "review-groupless",
    doc = "
And a retained owner may not be mutated while the machine can
still read the slot — the install borrows it for the machine's
remaining life:

```compile_fail,E0502
use protobuf_edit::review::groupless::BorrowReview;

let source = [0x12, 0x01, 0x61];
let mut payload = vec![0x08, 0x07];
let mut review = BorrowReview::open(&source).unwrap();
let record = review.top().next().unwrap();
review.set_payload(record, &payload).unwrap();
payload.clear(); // the review still holds the borrow
review.save().unwrap();
```"
)]
//!
//! The mixed-backing profile: `MixReview` selects the backing per
//! install — the unsuffixed faces retain like the borrowed
//! sibling, the `_copy` twins and staged frames copy like the base
//! machine — so a long-lived template and a dying temporary
//! interleave on one revision log:
//!
//! ```
//! # #[cfg(feature = "review-groupless")] {
//! use protobuf_edit::review::groupless::MixReview;
//!
//! let template = vec![0x08, 0x2A];
//! let source = [0x12, 0x01, 0x61];
//! let mut review = MixReview::open(&source).unwrap();
//! let record = review.top().next().unwrap();
//! review.set_payload(record, &template).unwrap();
//! {
//!     let transient = vec![0x08, 0x07];
//!     review.set_payload_copy(record, &transient).unwrap();
//! } // the temporary's owner dies; the copied slot keeps its bytes
//! assert_eq!(review.save().unwrap(), [0x12, 0x02, 0x08, 0x07]);
//! review.revert();
//! assert_eq!(review.save().unwrap(), [0x12, 0x02, 0x08, 0x2A]);
//! # }
//! ```
use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::admission::{self, usize_of};
#[cfg(feature = "review-grouped")]
pub mod grouped;
#[cfg(feature = "review-groupless")]
pub mod groupless;

crate::revise::revising_store! {
    coordinates,
    tenure: borrow,
    acceptance: canonical,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
}

crate::revise::revising_store! {
    layer plain,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
}

#[cfg(any(feature = "transfer-review-grouped", feature = "transfer-review-groupless"))]
crate::revise::revising_store! {
    layer transfer,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
}

crate::revise::revising_store! {
    store borrow,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
}

crate::revise::revising_store! {
    store mixed,
    noun: "review",
    a_noun: "a review",
    A_noun: "A review",
}
