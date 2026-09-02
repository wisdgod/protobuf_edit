//! The shared one-shot intake layer: the authored-value store, the
//! command vocabulary, and the coordinate types both dialect
//! machines build on.
//!
//! An intake takes tenure of its source (`Vec<u8>`, zero copy — the
//! buffer moves in) under canonical-minimal admission: padded tags,
//! length prefixes, and varint values refuse at open, so every
//! admitted framing word is minimal and no width is stored — spans
//! derive from the record's own facts. Authored payloads are
//! borrowed (`&'p [u8]`, zero copy until save), and the save lands
//! once in a caller-owned `Vec<u8>`. Tenure is transactional at
//! both doors: a refused open returns the buffer intact beside the
//! fault, and `into_source` releases it from a live machine — both
//! moves, zero copies. Owning the source is the point: no lifetime
//! pins a caller frame, so a mid-edit intake moves, returns, and
//! caches (rows address the source by `u32` offsets, never
//! pointers). The tolerant editor over a moved-in buffer is `adopt`
//! (feature `adopt-*`); the borrowed one-shot patch (feature
//! `patch-*`) keeps its zero-copy `&'a` identity for callers whose
//! buffer outlives the whole edit.
//!
//! There is no undo: commands commit, and dropping the intake
//! discards plan and source together. Everything no command
//! touched rides into the output byte-exact. Descending a LEN is
//! the Commit pole of the per-LEN interpretation axis: an explicit
//! commitment that the payload parses as records — a write machine
//! never speculates.
//!
//! Output acceptance: admission is canonical-minimal and authored
//! words are minimal, so saved documents re-ingest under
//! `CanonicalMinimal` — with one caller-declared exception: an
//! authored payload's interior passes through unchanged.
//!
//! Allocation policy: allocation refusal aborts (the global
//! allocation handler); it is never an `Err`. Under the crate
//! root's partition rule, an intake sits on the abort side:
//! everything it holds — the moved-in source, rows, staged
//! payloads — is the in-flight product of this one editing job, so
//! an abort's loss ends with the job, as for the other one-shot
//! jobs (`construct`, `rewrite`, `patch`, `adopt`); the revising
//! editors, which carry revisable interactive state across turns,
//! are the fallible side. Structured `Err`s here are coordinate
//! and admission judgments (domain exhaustion, size caps), never
//! resource refusals.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other.
//!
//! Coordinates: write · buffered · offline · canonical (type-level) · owned · commit-only.
//!
//! # Choosing a face
//!
//! - Opening: `Intake::open` moves the buffer in and scans its top
//!   layer; a refusal — padded framing included — returns the
//!   buffer with the fault. A source the caller keeps is the
//!   borrowed patch's shape (feature `patch-*`); tolerant
//!   admission is the adopt's (feature `adopt-*`); revision (undo)
//!   under canonical admission is the session's (feature
//!   `session-*`).
//! - Commands, by what changes: `set_varint`/`set_i32`/`set_i64`/
//!   `set_payload` replace an existing record's value side;
//!   `insert_varint`/`insert_i32`/`insert_i64`/`insert_payload`
//!   (the grouped intake adds `insert_group`) author records into
//!   an [`InsertAt`] gap; `delete` removes records whole.
//! - Payloads: `set_payload` and `insert_payload` borrow their
//!   argument until the save, where its single copy lands in the
//!   output — so the payload owner must outlive the intake; the
//!   `_copy` twins (`set_payload_copy`, `insert_payload_copy`)
//!   stage a copy at the command instead, for temporaries.
//! - Payload backing, by type: `Intake` carries all three
//!   supplies; its thin siblings pin one each — `BorrowIntake`
//!   borrowed-only (no `_copy` faces, no frames, one `Vec`
//!   lighter) and `CopyIntake` copy-only (every payload copies at
//!   the command; no lifetime parameters remain at all).
//! - Relocation and import: the dialect's `transfer` submodule
//!   (feature `transfer-intake-*`) ships `TransferIntake` — the
//!   same faces plus `copy_record`/`move_record` for whole
//!   records, `copy_payload`/`move_payload` for LEN interiors, and
//!   `copy_record_from` (with a `_copy` twin) importing one
//!   designated record from another document.
//! - Descent: reading a LEN payload is `payload_bytes`; editing
//!   *inside* one is `descend` first — the explicit Commit above.
//! - Saving: `save` allocates the output; `save_into` appends to
//!   your buffer; `save_sink` hands the same bytes to a caller
//!   sink slice by slice — choose the `Vec` faces when the product
//!   accumulates locally, the sink face when the bytes leave
//!   through a writer and an intermediate buffer would only be
//!   copied out again (one sizing pass runs first and its priced
//!   bodies feed the emission, so an `Err` hands the sink
//!   nothing); `save_len` prices the save without emitting —
//!   reserve it exactly and `save_into` never grows the buffer —
//!   and `save_spans` maps every live record to its output span,
//!   the cross-save identity supply (spans survive the save-reopen
//!   gap that handles do not).
//! - Releasing: `into_source` gives the moved-in buffer back,
//!   pending edits discarded — the open door's inverse.
//!
//! Both dialect machines ship the same faces. For batch edits
//! selected by path pattern rather than by handle → `rewrite`
//! (feature `rewrite-*`).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "intake-grouped")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::intake::grouped::Intake;
//!
//! // Move a document in, replace one value, save into a caller Vec.
//! let msg = vec![0x08, 0x96, 0x01, 0x10, 0x2A];
//! let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
//! let first = intake.top().next().unwrap();
//! intake.set_varint(first, 7).unwrap();
//! let mut out = Vec::new();
//! intake.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x07, 0x10, 0x2A]);
//! # }
//! ```
//!
//! # Recipes
//!
//! The tenure identity, end to end: a function builds a mid-edit
//! intake and returns it — no caller frame is pinned, the plan and
//! the source travel together, and the save happens wherever the
//! machine lands:
//!
//! ```
//! # #[cfg(feature = "intake-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::intake::groupless::Intake;
//!
//! fn stage_edit(msg: Vec<u8>) -> Intake<'static> {
//!     let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
//!     let first = intake.top().next().unwrap();
//!     intake.set_varint(first, 7).unwrap();
//!     intake // mid-edit, moved out whole
//! }
//!
//! let staged = stage_edit(vec![0x08, 0x01, 0x10, 0x2A]);
//! assert_eq!(staged.save().unwrap(), [0x08, 0x07, 0x10, 0x2A]);
//! # }
//! ```
//!
//! The canonical gate, end to end: padded wire refuses at the door
//! with the buffer intact, and everything this machine saves
//! re-opens under the same admission — outputs chain:
//!
//! ```
//! # #[cfg(feature = "intake-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::intake::groupless::{Intake, OpenFault, Refusal};
//!
//! // Field 1 varint 1, tag padded to two bytes.
//! let padded = vec![0x88, 0x00, 0x01];
//! let Err((back, fault)) = Intake::open(padded, DepthLimit::REFERENCE) else {
//!     unreachable!()
//! };
//! assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 })));
//! assert_eq!(back, [0x88, 0x00, 0x01]);
//!
//! // A minimal document round-trips through save and reopen.
//! let msg = vec![0x08, 0x96, 0x01];
//! let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
//! let first = intake.top().next().unwrap();
//! intake.set_varint(first, 300).unwrap();
//! let saved = intake.save().unwrap();
//! assert!(Intake::open(saved, DepthLimit::REFERENCE).is_ok());
//! # }
//! ```
//!
//! Price, reserve, save — the growth-free save from the saving
//! bullet above. An intake with no edits prices at
//! `source().len()` in O(1); the two split once an edit lands, and
//! from there only `save_len` is exact:
//!
//! ```
//! # #[cfg(feature = "intake-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::intake::groupless::Intake;
//!
//! let msg = vec![0x08, 0x01, 0x10, 0x2A];
//! let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
//! // Clean: the save is the source.
//! assert_eq!(intake.save_len().unwrap() as usize, intake.source().len());
//!
//! let first = intake.top().next().unwrap();
//! intake.set_varint(first, 300).unwrap(); // one value byte grows to two
//! let len = intake.save_len().unwrap();
//! assert_eq!(len as usize, intake.source().len() + 1);
//!
//! let mut out = Vec::with_capacity(len as usize);
//! intake.save_into(&mut out).unwrap();
//! assert_eq!(out.len(), len as usize);
//! # }
//! ```
//!
//! The repair pair: a payload that refuses descent parks a
//! resident verdict, and replacing it wholesale clears the
//! verdict — the surrounding document rides untouched:
//!
//! ```
//! # #[cfg(feature = "intake-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::intake::groupless::{Descent, Intake};
//!
//! // LEN f2 whose payload cuts a record short.
//! let msg = vec![0x12, 0x01, 0x08];
//! let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
//! let broken = intake.top().next().unwrap();
//! assert!(matches!(intake.descend(broken).unwrap(), Descent::Faulted(_)));
//!
//! intake.set_payload(broken, &[0x08, 0x01]).unwrap();
//! assert_eq!(intake.save().unwrap(), [0x12, 0x02, 0x08, 0x01]);
//! # }
//! ```
#![cfg_attr(
    feature = "intake-groupless",
    doc = "
A borrowed payload must outlive the intake — the type refuses
an owner that dies before the save (the `_copy` twins are the
escape hatch for that case):

```compile_fail,E0505
use protobuf_edit::DepthLimit;
use protobuf_edit::intake::groupless::Intake;

let msg = vec![0x12, 0x01, 0xAB];
let mut intake = Intake::open(msg, DepthLimit::REFERENCE).unwrap();
let record = intake.top().next().unwrap();
let payload = vec![0x08, 0x01];
intake.set_payload(record, &payload).unwrap();
drop(payload); // the intake still holds the borrow
let out = intake.save().unwrap();
```"
)]

use alloc::vec::Vec;

use crate::admission::{self, usize_of};

#[cfg(feature = "intake-grouped")]
pub mod grouped;
#[cfg(feature = "intake-groupless")]
pub mod groupless;

crate::editor::one_shot_store! {
    capability: plain,
    noun: "intake",
    A_noun: "An intake",
}

#[cfg(any(feature = "transfer-intake-grouped", feature = "transfer-intake-groupless"))]
crate::editor::one_shot_store! {
    capability: transfer,
    noun: "intake",
}
