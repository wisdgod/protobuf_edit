//! The shared markup layer: the value store, the edit algebra,
//! and the coordinate types both dialect markups build on.
//!
//! A markup is the editing draft's borrowed twin: the same command
//! set, revision log, tolerant admission, and two-pass fidelity
//! save, over a `&[u8]` the caller keeps. Padded tags, length
//! prefixes, and varint values are lawful input; every framing
//! width the scan meets is stored on the row as an input fact, and
//! untouched records ride saves byte-exactly — padding included —
//! while authored words emit minimal. Reverting every command
//! restores the source reading exactly.
//!
//! Tenure never transfers: `open` borrows the slice and copies
//! zero bytes, a refusal leaves the caller's buffer untouched (it
//! was never taken), and `source` answers the borrow at its full
//! lifetime — there is no release door because nothing was held.
//! The machine carries the borrow's lifetime, so it pins the
//! source buffer in place for its own life; an editor that must
//! outlive the buffer is `draft` (the same faces over a moved-in
//! `Vec<u8>`).
//!
//! Allocation policy: every growth edge in this scenario is
//! fallible. The store and the markups' arenas grow through
//! `try_reserve`, the save's output reserves fallibly, and a
//! refusal surfaces as a structured `Err` (the dialects'
//! `OpenFault`/`EditFault`/`SaveFault`) — never an abort: a markup
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
//! Output acceptance: `save`/`save_into`/`save_sink` guarantee
//! `Tolerant` — authored words are minimal and untouched bytes ride
//! verbatim, so that output closes under `CanonicalMinimal` exactly
//! when the source carried no padding.
//! `save_canonical`/`save_canonical_into`/`save_canonical_sink`
//! guarantee `CanonicalMinimal`: every varint construct in the
//! materialized commitment closure re-emits minimally;
//! non-materialized (unopened/faulted/refused) and authored LEN
//! interiors are opaque declarations.
//!
//! Coordinates: write · buffered · offline · tolerant (type-level) · borrowed · revisable.
//!
//! # Choosing a face
//!
//! - Opening: `Markup::open` borrows the slice and scans its top
//!   layer — zero copies, and a refusal never touched the buffer.
//!   Admission is tolerant — the canonical-admission revisable
//!   editor is `session` (feature `session-*`), the commit-only
//!   tolerant editor over a borrowed slice is `patch`, and the
//!   owned revisable twin is `draft`.
//! - Commands: `set_varint`/`set_i32`/`set_i64`/`set_payload`
//!   replace values; `insert_varint`/`insert_i32`/`insert_i64`/
//!   `insert_payload` (the grouped markup adds `insert_group`)
//!   author records; `delete` shrouds and `undelete` restores
//!   exactly; `clear_edit` clears a replacement back to the
//!   scanned state — its padded spelling included.
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
//! - Canonical output: the `save_canonical` family emits the same
//!   records under `CanonicalMinimal`. It walks the whole
//!   materialized commitment closure — no verbatim fast path, so
//!   even a clean markup pays the full sizing and emit walks —
//!   worth it exactly when a consumer requires minimal framing
//!   from a possibly padded source. A source already admitted
//!   canonically wants the review cell instead, whose ordinary
//!   saves carry that guarantee at fidelity cost.
//! - Payload backing, by type: `Markup` copies payloads at the
//!   command — temporaries welcome, no payload lifetime on the
//!   type. Its sibling `BorrowMarkup<'p>` retains borrowed slices
//!   instead — no staging copy, and every payload owner outlives
//!   the markup — and `MixMarkup<'p>` selects the backing per
//!   install; the recipes below work the borrowed and mixed
//!   profiles.
//! - Relocation and import: the dialect's `transfer` submodule
//!   (feature `transfer-markup-*`) ships `TransferMarkup`
//!   (copying) and `TransferBorrowMarkup` (borrowing) — the same
//!   faces plus `copy_record`/`move_record` for whole records,
//!   `copy_payload`/`move_payload` for LEN interiors, and
//!   `copy_record_from` importing one designated record from
//!   another document; a move is one command, one pending step,
//!   one revert.
//! - Hex-view supply: `span`/`source_spans` give record geometry
//!   at the widths the scan actually met, and `narrowest` answers
//!   "which record covers this byte".
//!
//! Both dialect markups ship the same faces; the crate root's
//! feature guide picks the dialect.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "markup-groupless")] {
//! use protobuf_edit::markup::groupless::Markup;
//!
//! // varint f1=150, its value padded to three bytes: tolerant
//! // admission carries the spelling as a stored width fact.
//! let msg = [0x08, 0x96, 0x81, 0x00];
//! let mut markup = Markup::open(&msg).unwrap();
//! let record = markup.top().next().unwrap();
//! assert_eq!(markup.varint_word(record).unwrap(), 150);
//!
//! // Untouched records ride saves verbatim, padding included.
//! assert_eq!(markup.save().unwrap(), msg);
//!
//! // A replacement re-authors the value minimally — the source
//! // tag still rides verbatim.
//! markup.set_varint(record, 7).unwrap();
//! assert_eq!(markup.save().unwrap(), [0x08, 0x07]);
//!
//! // Revision restores byte fidelity exactly.
//! markup.revert();
//! assert_eq!(markup.save().unwrap(), msg);
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
//! # #[cfg(feature = "markup-groupless")] {
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::markup::groupless::{InsertAt, Markup};
//!
//! let msg = [0x08, 0x2A];
//! let mut markup = Markup::open(&msg).unwrap();
//! let record = markup.top().next().unwrap();
//! markup.set_varint(record, 7).unwrap(); // the committed prefix
//!
//! let mark = markup.pending();
//! let f2 = FieldNumber::new(2).unwrap();
//! markup.insert_varint(InsertAt::TailOf(None), f2, 1).unwrap();
//! markup.insert_varint(InsertAt::TailOf(None), f2, 2).unwrap();
//! // The compound edit is abandoned: unwind to the mark, exactly.
//! while markup.pending() > mark {
//!     markup.revert();
//! }
//! assert_eq!(markup.save().unwrap(), [0x08, 0x07]);
//! # }
//! ```
//!
//! The borrowed-payload profile: a template that outlives both the
//! document slice and the markup installs without a staging copy:
//!
//! ```
//! # #[cfg(feature = "markup-groupless")] {
//! use protobuf_edit::markup::groupless::BorrowMarkup;
//!
//! let template = vec![0x08, 0x2A];
//! // LEN f2 "a", its prefix padded to two bytes.
//! let source = [0x12, 0x81, 0x00, 0x61];
//! let mut markup = BorrowMarkup::open(&source).unwrap();
//! let record = markup.top().next().unwrap();
//! markup.set_payload(record, &template).unwrap();
//! // The replacement re-authors the prefix; the source tag rides.
//! assert_eq!(markup.save().unwrap(), [0x12, 0x02, 0x08, 0x2A]);
//! markup.revert_all();
//! assert_eq!(markup.save().unwrap(), source);
//! # }
//! ```
#![cfg_attr(
    feature = "markup-groupless",
    doc = "
A borrowed payload must outlive the markup — the type refuses
an owner that dies while the machine can still read the slot
(the copy-only `Markup` is the escape hatch for temporaries):

```compile_fail,E0597
use protobuf_edit::markup::groupless::BorrowMarkup;

let source = [0x12, 0x01, 0x61];
let mut markup = BorrowMarkup::open(&source).unwrap();
let record = markup.top().next().unwrap();
{
    let transient = vec![0x08, 0x07];
    markup.set_payload(record, &transient).unwrap();
} // the owner dies here; the markup still holds the borrow
markup.save().unwrap();
```"
)]
#![cfg_attr(
    feature = "markup-groupless",
    doc = "
And a retained owner may not be mutated while the machine can
still read the slot — the install borrows it for the machine's
remaining life:

```compile_fail,E0502
use protobuf_edit::markup::groupless::BorrowMarkup;

let source = [0x12, 0x01, 0x61];
let mut payload = vec![0x08, 0x07];
let mut markup = BorrowMarkup::open(&source).unwrap();
let record = markup.top().next().unwrap();
markup.set_payload(record, &payload).unwrap();
payload.clear(); // the markup still holds the borrow
markup.save().unwrap();
```"
)]
//!
//! The mixed-backing profile: `MixMarkup` selects the backing per
//! install — the unsuffixed faces retain like the borrowed
//! sibling, the `_copy` twins and staged frames copy like the base
//! machine — so a long-lived template and a dying temporary
//! interleave on one revision log:
//!
//! ```
//! # #[cfg(feature = "markup-groupless")] {
//! use protobuf_edit::markup::groupless::MixMarkup;
//!
//! let template = vec![0x08, 0x2A];
//! let source = [0x12, 0x01, 0x61];
//! let mut markup = MixMarkup::open(&source).unwrap();
//! let record = markup.top().next().unwrap();
//! markup.set_payload(record, &template).unwrap();
//! {
//!     let transient = vec![0x08, 0x07];
//!     markup.set_payload_copy(record, &transient).unwrap();
//! } // the temporary's owner dies; the copied slot keeps its bytes
//! assert_eq!(markup.save().unwrap(), [0x12, 0x02, 0x08, 0x07]);
//! markup.revert();
//! assert_eq!(markup.save().unwrap(), [0x12, 0x02, 0x08, 0x2A]);
//! # }
//! ```
use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::admission::{self, usize_of};
#[cfg(feature = "markup-grouped")]
pub mod grouped;
#[cfg(feature = "markup-groupless")]
pub mod groupless;

crate::revise::revising_store! {
    coordinates,
    tenure: borrow,
    acceptance: tolerant,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
}

crate::revise::revising_store! {
    layer plain,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
}

#[cfg(any(feature = "transfer-markup-grouped", feature = "transfer-markup-groupless"))]
crate::revise::revising_store! {
    layer transfer,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
}

crate::revise::revising_store! {
    store borrow,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
}

crate::revise::revising_store! {
    store mixed,
    noun: "markup",
    a_noun: "a markup",
    A_noun: "A markup",
}
