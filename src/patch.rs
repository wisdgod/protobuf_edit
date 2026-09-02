//! The shared one-shot patch layer: the authored-value store, the
//! command vocabulary, and the coordinate types both dialect
//! patches build on.
//!
//! A patch borrows its source (`&'a [u8]`, zero copy at open) and
//! its authored payloads (`&'p [u8]`, zero copy until save),
//! carries every framing width that the scan actually met as a
//! stored input fact, and saves once into a caller-owned `Vec<u8>`. There
//! is no undo: commands commit, and dropping the patch discards the
//! plan. Everything no command touched rides into the output
//! byte-exact — padded framing included. Descending a LEN is the
//! Commit pole of the per-LEN interpretation axis: an explicit
//! commitment that the payload parses as records — a write machine
//! never speculates.
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
//! Allocation policy: allocation refusal aborts (the global
//! allocation handler); it is never an `Err`. Under the crate
//! root's partition rule, a patch sits on the abort side:
//! everything it holds — rows, staged payloads — is the in-flight
//! product of this one editing job, so an abort's loss ends with
//! the job, as for the other one-shot jobs (`construct`,
//! `rewrite`); the revising editors, which carry revisable
//! interactive state across turns, are the fallible side. Input
//! scale does not move the line: a pinned multi-gigabyte source
//! survives an abort exactly like a small one (the source is
//! borrowed, never consumed). Structured `Err`s here are
//! coordinate and admission judgments (domain exhaustion, size
//! caps), never resource refusals.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other.
//!
//! Coordinates: write · buffered · offline · tolerant (type-level) · borrowed · commit-only.
//!
//! # Choosing a face
//!
//! - Opening: `Patch::open` borrows the source and scans its top
//!   layer; owned documents and revision (undo) are the session's
//!   shape — feature `session-*`.
//! - Commands, by what changes: `set_varint`/`set_i32`/`set_i64`/
//!   `set_payload` replace an existing record's value side;
//!   `insert_varint`/`insert_i32`/`insert_i64`/`insert_payload`
//!   (the grouped patch adds `insert_group`) author records into
//!   an [`InsertAt`] gap; `delete` removes records whole.
//! - Payloads: `set_payload` and `insert_payload` borrow their
//!   argument until the save, where its single copy lands in the
//!   output — so the payload owner must outlive the patch; the
//!   `_copy` twins (`set_payload_copy`, `insert_payload_copy`)
//!   stage a copy at the command instead, for temporaries.
//! - Payload backing, by type: `Patch` carries all three supplies;
//!   its thin siblings pin one each — `BorrowPatch` borrowed-only
//!   (no `_copy` faces, no frames, one `Vec` lighter) and
//!   `CopyPatch` copy-only (every payload copies at the command;
//!   no payload lifetime binds the caller).
//! - Relocation and import: the dialect's `transfer` submodule
//!   (feature `transfer-patch-*`) ships `TransferPatch` — the same
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
//!   copied out again (its pricing walk runs first, so an `Err`
//!   hands the sink nothing); `save_len` prices the save without
//!   emitting — reserve it exactly and `save_into` never grows
//!   the buffer — and `save_spans` maps every live record to its
//!   output span, the cross-save identity supply (spans survive
//!   the save-reopen gap that handles do not).
//! - Canonical output: the `save_canonical` family emits the same
//!   records under `CanonicalMinimal`. It walks the whole
//!   materialized commitment closure — no verbatim fast path, so
//!   even a clean patch pays the full sizing and emit walks —
//!   worth it exactly when a consumer requires minimal framing
//!   from a possibly padded source. A source already admitted
//!   canonically wants the amend/intake cells instead, whose
//!   ordinary saves carry that guarantee at fidelity cost.
//!
//! Both dialect patches ship the same faces. For batch edits
//! selected by path pattern rather than by handle → `rewrite`
//! (feature `rewrite-*`).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "patch-grouped")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::patch::grouped::Patch;
//!
//! // Borrow a document, replace one value, save into a caller Vec.
//! let msg = [0x08, 0x96, 0x01, 0x10, 0x2A];
//! let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
//! let first = patch.top().next().unwrap();
//! patch.set_varint(first, 7).unwrap();
//! let mut out = Vec::new();
//! patch.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x07, 0x10, 0x2A]);
//! # }
//! ```
//!
//! # Recipes
//!
//! One editing job, end to end: open, locate (`top` and its
//! `by_field` filter), descend only the container being edited —
//! the commitment above, not browsing — command, then save into a
//! buffer the caller keeps reusing:
//!
//! ```
//! # #[cfg(feature = "patch-groupless")] {
//! use protobuf_edit::patch::groupless::{Descent, Patch};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // varint f1=1 · LEN f2 wrapping { varint f1=1 }
//! let msg = [0x08, 0x01, 0x12, 0x02, 0x08, 0x01];
//! let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
//! let f2 = FieldNumber::new(2).unwrap();
//! let container = patch.top().by_field(f2).next().unwrap();
//! let Descent::Opened { first: Some(inner) } = patch.descend(container).unwrap() else {
//!     unreachable!()
//! };
//! patch.set_varint(inner, 7).unwrap();
//!
//! let mut out = Vec::new();
//! patch.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x01, 0x12, 0x02, 0x08, 0x07]);
//!
//! // Repeated saves amortize the buffer: clear, save again.
//! patch.set_varint(inner, 8).unwrap();
//! out.clear();
//! patch.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x01, 0x12, 0x02, 0x08, 0x08]);
//! # }
//! ```
//!
//! Price, reserve, save — the growth-free save from the saving
//! bullet above. A patch with no edits prices at `source().len()`
//! in O(1); the two split once an edit lands, and from there only
//! `save_len` is exact:
//!
//! ```
//! # #[cfg(feature = "patch-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::patch::groupless::Patch;
//!
//! let msg = [0x08, 0x01, 0x10, 0x2A];
//! let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
//! // Clean: the save is the source.
//! assert_eq!(patch.save_len().unwrap() as usize, patch.source().len());
//!
//! let first = patch.top().next().unwrap();
//! patch.set_varint(first, 300).unwrap(); // one value byte grows to two
//! let len = patch.save_len().unwrap();
//! assert_eq!(len as usize, patch.source().len() + 1);
//!
//! let mut out = Vec::with_capacity(len as usize);
//! patch.save_into(&mut out).unwrap();
//! assert_eq!(out.len(), len as usize);
//! # }
//! ```
//!
//! The repair pair: a payload that refuses descent parks a
//! resident verdict, and replacing it wholesale is the path that
//! clears the verdict — the surrounding document rides untouched:
//!
//! ```
//! # #[cfg(feature = "patch-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::patch::groupless::{Descent, Patch};
//!
//! // LEN f2 whose payload cuts a record short.
//! let msg = [0x12, 0x01, 0x08];
//! let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
//! let broken = patch.top().next().unwrap();
//! assert!(matches!(patch.descend(broken).unwrap(), Descent::Faulted(_)));
//!
//! patch.set_payload(broken, &[0x08, 0x01]).unwrap();
//! assert_eq!(patch.save().unwrap(), [0x12, 0x02, 0x08, 0x01]);
//! # }
//! ```
#![cfg_attr(
    feature = "patch-groupless",
    doc = "
A borrowed payload must outlive the patch — the type refuses an
owner that dies before the save (the `_copy` twins are the
escape hatch for that case):

```compile_fail,E0505
use protobuf_edit::DepthLimit;
use protobuf_edit::patch::groupless::Patch;

let msg = [0x12, 0x01, 0xAB];
let mut patch = Patch::open(&msg, DepthLimit::REFERENCE).unwrap();
let record = patch.top().next().unwrap();
let payload = vec![0x08, 0x01];
patch.set_payload(record, &payload).unwrap();
drop(payload); // the patch still holds the borrow
let out = patch.save().unwrap();
```"
)]

use alloc::vec::Vec;

use crate::admission::{self, usize_of};

#[cfg(feature = "patch-grouped")]
pub mod grouped;
#[cfg(feature = "patch-groupless")]
pub mod groupless;

crate::editor::one_shot_store! {
    capability: plain,
    noun: "patch",
    A_noun: "A patch",
}

#[cfg(any(feature = "transfer-patch-grouped", feature = "transfer-patch-groupless"))]
crate::editor::one_shot_store! {
    capability: transfer,
    noun: "patch",
}
