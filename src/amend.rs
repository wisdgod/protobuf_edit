//! The shared one-shot amend layer: the authored-value store, the
//! command vocabulary, and the coordinate types both dialect
//! machines build on.
//!
//! An amend borrows its source (`&'a [u8]`, zero copy at open)
//! under canonical-minimal admission: padded tags, length
//! prefixes, and varint values refuse at open, so every admitted
//! framing word is minimal and no width is stored — spans derive
//! from the record's own facts. Authored payloads are borrowed
//! (`&'p [u8]`, zero copy until save), and the save lands once in
//! a caller-owned `Vec<u8>`. There is no undo: commands commit,
//! and dropping the amend discards the plan. Everything no command
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
//! root's partition rule, an amend sits on the abort side:
//! everything it holds — rows, staged payloads — is the in-flight
//! product of this one editing job, so an abort's loss ends with
//! the job, as for the other one-shot jobs (`construct`,
//! `rewrite`, `patch`, `intake`); the revising editors, which
//! carry revisable interactive state across turns, are the
//! fallible side.
//! Input scale does not move the line: a pinned multi-gigabyte
//! source survives an abort exactly like a small one (the source
//! is borrowed, never consumed). Structured `Err`s here are
//! coordinate and admission judgments (domain exhaustion, size
//! caps), never resource refusals.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other.
//!
//! Coordinates: write · buffered · offline · canonical (type-level) · borrowed · commit-only.
//!
//! # Choosing a face
//!
//! - Opening: `Amend::open` borrows the source and scans its top
//!   layer; a refusal — padded framing included — never touched
//!   the buffer. Tolerant admission over a borrowed source is the
//!   patch's shape (feature `patch-*`); canonical admission over a
//!   moved-in buffer is the intake's (feature `intake-*`);
//!   revision (undo) under canonical admission is the session's
//!   (feature `session-*`).
//! - Commands, by what changes: `set_varint`/`set_i32`/`set_i64`/
//!   `set_payload` replace an existing record's value side;
//!   `insert_varint`/`insert_i32`/`insert_i64`/`insert_payload`
//!   (the grouped amend adds `insert_group`) author records into
//!   an [`InsertAt`] gap; `delete` removes records whole.
//! - Payloads: `set_payload` and `insert_payload` borrow their
//!   argument until the save, where its single copy lands in the
//!   output — so the payload owner must outlive the amend; the
//!   `_copy` twins (`set_payload_copy`, `insert_payload_copy`)
//!   stage a copy at the command instead, for temporaries.
//! - Payload backing, by type: `Amend` carries all three supplies;
//!   its thin siblings pin one each — `BorrowAmend` borrowed-only
//!   (no `_copy` faces, no frames, one `Vec` lighter) and
//!   `CopyAmend` copy-only (every payload copies at the command;
//!   no payload lifetime binds the caller).
//! - Relocation and import: the dialect's `transfer` submodule
//!   (feature `transfer-amend-*`) ships `TransferAmend` — the same
//!   faces plus `copy_record`/`move_record` for whole records,
//!   `copy_payload`/`move_payload` for LEN interiors, and
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
//!
//! Both dialect machines ship the same faces. For batch edits
//! selected by path pattern rather than by handle → `rewrite`
//! (feature `rewrite-*`).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "amend-grouped")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::amend::grouped::Amend;
//!
//! // Borrow a document, replace one value, save into a caller Vec.
//! let msg = [0x08, 0x96, 0x01, 0x10, 0x2A];
//! let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
//! let first = amend.top().next().unwrap();
//! amend.set_varint(first, 7).unwrap();
//! let mut out = Vec::new();
//! amend.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x07, 0x10, 0x2A]);
//! # }
//! ```
//!
//! # Recipes
//!
//! The canonical gate, end to end: padded wire refuses at the door
//! with the buffer untouched, and everything this machine saves
//! re-opens under the same admission — outputs chain:
//!
//! ```
//! # #[cfg(feature = "amend-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::amend::groupless::{Amend, OpenFault, Refusal};
//!
//! // Field 1 varint 1, tag padded to two bytes.
//! let padded = [0x88, 0x00, 0x01];
//! let Err(fault) = Amend::open(&padded, DepthLimit::REFERENCE) else { unreachable!() };
//! assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 })));
//!
//! // A minimal document round-trips through save and reopen.
//! let msg = [0x08, 0x96, 0x01];
//! let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
//! let first = amend.top().next().unwrap();
//! amend.set_varint(first, 300).unwrap();
//! let saved = amend.save().unwrap();
//! assert!(Amend::open(&saved, DepthLimit::REFERENCE).is_ok());
//! # }
//! ```
//!
//! Price, reserve, save — the growth-free save from the saving
//! bullet above. An amend with no edits prices at `source().len()`
//! in O(1); the two split once an edit lands, and from there only
//! `save_len` is exact:
//!
//! ```
//! # #[cfg(feature = "amend-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::amend::groupless::Amend;
//!
//! let msg = [0x08, 0x01, 0x10, 0x2A];
//! let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
//! // Clean: the save is the source.
//! assert_eq!(amend.save_len().unwrap() as usize, amend.source().len());
//!
//! let first = amend.top().next().unwrap();
//! amend.set_varint(first, 300).unwrap(); // one value byte grows to two
//! let len = amend.save_len().unwrap();
//! assert_eq!(len as usize, amend.source().len() + 1);
//!
//! let mut out = Vec::with_capacity(len as usize);
//! amend.save_into(&mut out).unwrap();
//! assert_eq!(out.len(), len as usize);
//! # }
//! ```
//!
//! The repair pair: a payload that refuses descent parks a
//! resident verdict, and replacing it wholesale is the path that
//! clears the verdict — the surrounding document rides untouched:
//!
//! ```
//! # #[cfg(feature = "amend-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::amend::groupless::{Amend, Descent};
//!
//! // LEN f2 whose payload cuts a record short.
//! let msg = [0x12, 0x01, 0x08];
//! let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
//! let broken = amend.top().next().unwrap();
//! assert!(matches!(amend.descend(broken).unwrap(), Descent::Faulted(_)));
//!
//! amend.set_payload(broken, &[0x08, 0x01]).unwrap();
//! assert_eq!(amend.save().unwrap(), [0x12, 0x02, 0x08, 0x01]);
//! # }
//! ```
#![cfg_attr(
    feature = "amend-groupless",
    doc = "
A borrowed payload must outlive the amend — the type refuses an
owner that dies before the save (the `_copy` twins are the
escape hatch for that case):

```compile_fail,E0505
use protobuf_edit::DepthLimit;
use protobuf_edit::amend::groupless::Amend;

let msg = [0x12, 0x01, 0xAB];
let mut amend = Amend::open(&msg, DepthLimit::REFERENCE).unwrap();
let record = amend.top().next().unwrap();
let payload = vec![0x08, 0x01];
amend.set_payload(record, &payload).unwrap();
drop(payload); // the amend still holds the borrow
let out = amend.save().unwrap();
```"
)]

use alloc::vec::Vec;

use crate::admission::{self, usize_of};

#[cfg(feature = "amend-grouped")]
pub mod grouped;
#[cfg(feature = "amend-groupless")]
pub mod groupless;

crate::editor::one_shot_store! {
    capability: plain,
    noun: "amend",
    A_noun: "An amend",
}

#[cfg(any(feature = "transfer-amend-grouped", feature = "transfer-amend-groupless"))]
crate::editor::one_shot_store! {
    capability: transfer,
    noun: "amend",
}
