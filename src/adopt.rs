//! The shared one-shot adopt layer: the authored-value store, the
//! command vocabulary, and the coordinate types both dialect
//! machines build on.
//!
//! An adopt takes tenure of its source (`Vec<u8>`, zero copy — the
//! buffer moves in) and borrows its authored payloads (`&'p [u8]`,
//! zero copy until save), carries every framing width that the
//! scan actually met as a stored input fact, and saves once into a
//! caller-owned `Vec<u8>`. Tenure is transactional at both doors:
//! a refused open returns the buffer intact beside the fault, and
//! `into_source` releases it from a live machine — both moves,
//! zero copies. Owning the source is the point: no lifetime pins a
//! caller frame, so a mid-edit adopt moves, returns, and caches
//! (rows address the source by `u32` offsets, never pointers — the
//! borrowed patch's own row shape, so ownership adds no
//! self-reference). The borrowed one-shot patch (feature
//! `patch-*`) keeps its zero-copy `&'a` identity for callers whose
//! buffer outlives the whole edit.
//!
//! There is no undo: commands commit, and dropping the adopt
//! discards plan and source together. Everything no command
//! touched rides into the output byte-exact — padded framing
//! included. Descending a LEN is the Commit pole of the per-LEN
//! interpretation axis: an explicit commitment that the payload
//! parses as records — a write machine never speculates.
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
//! root's partition rule, an adopt sits on the abort side:
//! everything it holds — the moved-in source, rows, staged
//! payloads — is the in-flight product of this one editing job, so
//! an abort's loss ends with the job, as for the other one-shot
//! jobs (`construct`, `rewrite`, `patch`); the revising editors,
//! which carry revisable interactive state across turns, are the
//! fallible side. Structured `Err`s here are coordinate and
//! admission judgments (domain exhaustion, size caps), never
//! resource refusals.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other.
//!
//! Coordinates: write · buffered · offline · tolerant (type-level) · owned · commit-only.
//!
//! # Choosing a face
//!
//! - Opening: `Adopt::open` moves the buffer in and scans its top
//!   layer; a refusal returns the buffer with the fault. A source
//!   the caller keeps is the borrowed patch's shape (feature
//!   `patch-*`); revision (undo) is the session's (feature
//!   `session-*`).
//! - Commands, by what changes: `set_varint`/`set_i32`/`set_i64`/
//!   `set_payload` replace an existing record's value side;
//!   `insert_varint`/`insert_i32`/`insert_i64`/`insert_payload`
//!   (the grouped adopt adds `insert_group`) author records into
//!   an [`InsertAt`] gap; `delete` removes records whole.
//! - Payloads: `set_payload` and `insert_payload` borrow their
//!   argument until the save, where its single copy lands in the
//!   output — so the payload owner must outlive the adopt; the
//!   `_copy` twins (`set_payload_copy`, `insert_payload_copy`)
//!   stage a copy at the command instead, for temporaries.
//! - Payload backing, by type: `Adopt` carries all three supplies;
//!   its thin siblings pin one each — `BorrowAdopt` borrowed-only
//!   (no `_copy` faces, no frames, one `Vec` lighter) and
//!   `CopyAdopt` copy-only (every payload copies at the command;
//!   no lifetime parameters remain at all).
//! - Relocation and import: the dialect's `transfer` submodule
//!   (feature `transfer-adopt-*`) ships `TransferAdopt` — the same
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
//!   even a clean adopt pays the full sizing and emit walks —
//!   worth it exactly when a consumer requires minimal framing
//!   from a possibly padded source. A source already admitted
//!   canonically wants the amend/intake cells instead, whose
//!   ordinary saves carry that guarantee at fidelity cost.
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
//! # #[cfg(feature = "adopt-grouped")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::adopt::grouped::Adopt;
//!
//! // Move a document in, replace one value, save into a caller Vec.
//! let msg = vec![0x08, 0x96, 0x01, 0x10, 0x2A];
//! let mut adopt = Adopt::open(msg, DepthLimit::REFERENCE).unwrap();
//! let first = adopt.top().next().unwrap();
//! adopt.set_varint(first, 7).unwrap();
//! let mut out = Vec::new();
//! adopt.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x07, 0x10, 0x2A]);
//! # }
//! ```
//!
//! # Recipes
//!
//! The tenure identity, end to end: a function builds a mid-edit
//! adopt and returns it — no caller frame is pinned, the plan and
//! the source travel together, and the save happens wherever the
//! machine lands:
//!
//! ```
//! # #[cfg(feature = "adopt-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::adopt::groupless::Adopt;
//!
//! fn stage_edit(msg: Vec<u8>) -> Adopt<'static> {
//!     let mut adopt = Adopt::open(msg, DepthLimit::REFERENCE).unwrap();
//!     let first = adopt.top().next().unwrap();
//!     adopt.set_varint(first, 7).unwrap();
//!     adopt // mid-edit, moved out whole
//! }
//!
//! let staged = stage_edit(vec![0x08, 0x01, 0x10, 0x2A]);
//! assert_eq!(staged.save().unwrap(), [0x08, 0x07, 0x10, 0x2A]);
//! # }
//! ```
//!
//! One editing job, end to end: open, locate (`top` and its
//! `by_field` filter), descend only the container being edited —
//! the commitment above, not browsing — command, then save into a
//! buffer the caller keeps reusing:
//!
//! ```
//! # #[cfg(feature = "adopt-groupless")] {
//! use protobuf_edit::adopt::groupless::{Adopt, Descent};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // varint f1=1 · LEN f2 wrapping { varint f1=1 }
//! let msg = vec![0x08, 0x01, 0x12, 0x02, 0x08, 0x01];
//! let mut adopt = Adopt::open(msg, DepthLimit::REFERENCE).unwrap();
//! let f2 = FieldNumber::new(2).unwrap();
//! let container = adopt.top().by_field(f2).next().unwrap();
//! let Descent::Opened { first: Some(inner) } = adopt.descend(container).unwrap() else {
//!     unreachable!()
//! };
//! adopt.set_varint(inner, 7).unwrap();
//!
//! let mut out = Vec::new();
//! adopt.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x01, 0x12, 0x02, 0x08, 0x07]);
//!
//! // Repeated saves amortize the buffer: clear, save again.
//! adopt.set_varint(inner, 8).unwrap();
//! out.clear();
//! adopt.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x01, 0x12, 0x02, 0x08, 0x08]);
//! # }
//! ```
//!
//! Price, reserve, save — the growth-free save from the saving
//! bullet above. An adopt with no edits prices at `source().len()`
//! in O(1); the two split once an edit lands, and from there only
//! `save_len` is exact:
//!
//! ```
//! # #[cfg(feature = "adopt-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::adopt::groupless::Adopt;
//!
//! let msg = vec![0x08, 0x01, 0x10, 0x2A];
//! let mut adopt = Adopt::open(msg, DepthLimit::REFERENCE).unwrap();
//! // Clean: the save is the source.
//! assert_eq!(adopt.save_len().unwrap() as usize, adopt.source().len());
//!
//! let first = adopt.top().next().unwrap();
//! adopt.set_varint(first, 300).unwrap(); // one value byte grows to two
//! let len = adopt.save_len().unwrap();
//! assert_eq!(len as usize, adopt.source().len() + 1);
//!
//! let mut out = Vec::with_capacity(len as usize);
//! adopt.save_into(&mut out).unwrap();
//! assert_eq!(out.len(), len as usize);
//! # }
//! ```
//!
//! The repair pair: a payload that refuses descent parks a
//! resident verdict, and replacing it wholesale clears the
//! verdict — the surrounding document rides untouched:
//!
//! ```
//! # #[cfg(feature = "adopt-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::adopt::groupless::{Adopt, Descent};
//!
//! // LEN f2 whose payload cuts a record short.
//! let msg = vec![0x12, 0x01, 0x08];
//! let mut adopt = Adopt::open(msg, DepthLimit::REFERENCE).unwrap();
//! let broken = adopt.top().next().unwrap();
//! assert!(matches!(adopt.descend(broken).unwrap(), Descent::Faulted(_)));
//!
//! adopt.set_payload(broken, &[0x08, 0x01]).unwrap();
//! assert_eq!(adopt.save().unwrap(), [0x12, 0x02, 0x08, 0x01]);
//! # }
//! ```
#![cfg_attr(
    feature = "adopt-groupless",
    doc = "
A borrowed payload must outlive the adopt — the type refuses an
owner that dies before the save (the `_copy` twins are the
escape hatch for that case):

```compile_fail,E0505
use protobuf_edit::DepthLimit;
use protobuf_edit::adopt::groupless::Adopt;

let msg = vec![0x12, 0x01, 0xAB];
let mut adopt = Adopt::open(msg, DepthLimit::REFERENCE).unwrap();
let record = adopt.top().next().unwrap();
let payload = vec![0x08, 0x01];
adopt.set_payload(record, &payload).unwrap();
drop(payload); // the adopt still holds the borrow
let out = adopt.save().unwrap();
```"
)]

use alloc::vec::Vec;

use crate::admission::{self, usize_of};

#[cfg(feature = "adopt-grouped")]
pub mod grouped;
#[cfg(feature = "adopt-groupless")]
pub mod groupless;

crate::editor::one_shot_store! {
    capability: plain,
    noun: "adopt",
    A_noun: "An adopt",
}

#[cfg(any(feature = "transfer-adopt-grouped", feature = "transfer-adopt-groupless"))]
crate::editor::one_shot_store! {
    capability: transfer,
    noun: "adopt",
}
