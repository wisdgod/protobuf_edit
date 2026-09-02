//! The shared drafting layer: the value store, the edit algebra,
//! and the coordinate types both dialect drafts build on.
//!
//! A draft is the editing session's tolerant twin over a moved-in
//! buffer: the same command set, revision log, and two-pass save,
//! with admission widened to the reference readers' tolerant
//! domain. Padded tags, length prefixes, and varint values are
//! lawful input; every framing width the scan meets is stored on
//! the row as an input fact, and untouched records ride saves
//! byte-exactly — padding included — while authored words emit
//! minimal (the one-shot patch's fidelity contract, under
//! revision). Reverting every command restores the source bytes
//! exactly.
//!
//! Tenure is transactional at both doors, as for `adopt`: `open`
//! moves the caller's `Vec<u8>` in and a refusal returns it intact
//! beside the fault; `into_source` releases it from a live draft.
//! `open_copy` folds copy-then-open for the borrowed common case.
//!
//! Allocation policy: every growth edge in this scenario is
//! fallible. The store and the drafts' arenas grow through
//! `try_reserve`, the save's output reserves fallibly, and a
//! refusal surfaces as a structured `Err` (the dialects'
//! `OpenFault`/`EditFault`/`SaveFault`) — never an abort: a draft
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
//! Coordinates: write · buffered · offline · tolerant (type-level) · owned · revisable.
//!
//! # Choosing a face
//!
//! - Opening: `Draft::open` moves the buffer in and scans its top
//!   layer; a refusal returns the buffer with the fault.
//!   `Draft::open_copy` copies a borrowed slice first. Admission
//!   is tolerant — the canonical-admission revisable editor is
//!   `session` (feature `session-*`), the commit-only tolerant
//!   editors are `patch` (borrowed) and `adopt` (owned).
//! - Commands: `set_varint`/`set_i32`/`set_i64`/`set_payload`
//!   replace values; `insert_varint`/`insert_i32`/`insert_i64`/
//!   `insert_payload` (the grouped draft adds `insert_group`)
//!   author records; `delete` shrouds and `undelete` restores
//!   exactly; `clear_edit` clears a replacement back to the
//!   scanned state — its padded spelling included.
//! - Revision — the axis the one-shot editors lack: every command
//!   logs one step; `revert` pops the last, `revert_all` empties
//!   the log, `pending` counts it.
//! - Saving: `save` emits a fresh `Vec<u8>` — output that
//!   re-opens, so drafts chain through `open`'s move door;
//!   `save_into` appends the same bytes to a buffer the caller
//!   keeps; `save_sink` hands the same bytes to a caller sink
//!   slice by slice, no output buffer (every fault precedes the
//!   first handoff, so the sink receives nothing on `Err`);
//!   `save_len` prices any of them without emitting, and
//!   `save_spans` maps every emitted record to its output span —
//!   the cross-save identity supply.
//! - Canonical output: the `save_canonical` family emits the same
//!   records under `CanonicalMinimal`. It walks the whole
//!   materialized commitment closure — no verbatim fast path, so
//!   even a clean draft pays the full sizing and emit walks —
//!   worth it exactly when a consumer requires minimal framing
//!   from a possibly padded source. A source already admitted
//!   canonically wants the session cell instead, whose ordinary
//!   saves carry that guarantee at fidelity cost.
//! - Payload backing, by type: `Draft` copies payloads at the
//!   command — temporaries welcome, no payload lifetime on the
//!   type, and the staged frames (`begin_set_payload` and kin)
//!   ride the copying store. Its sibling `BorrowDraft<'p>`
//!   retains borrowed slices instead: `set_payload` and
//!   `insert_payload` take `&'p [u8]` and append one immutable
//!   slot per install — no staging copy, no staged frames, and
//!   every payload owner must outlive the draft. Undo is the same
//!   algebra: earlier installs keep their slots, so a revert
//!   restores the exact prior payload — the byte-fidelity reading
//!   included, padding and all. Saves copy each live payload once
//!   into the owned product (`save_sink` hands the slices
//!   through), so the saved buffer carries no borrow. The third
//!   sibling `MixDraft<'p>` selects the backing per install: its
//!   unsuffixed faces retain like `BorrowDraft`, its `_copy` twins
//!   and staged frames copy like `Draft`, and every install
//!   appends one immutable slot on one revision log — long-lived
//!   templates and dying temporaries interleave.
//! - Relocation and import: the dialect's `transfer` submodule
//!   (feature `transfer-draft-*`) ships `TransferDraft` (copying)
//!   and `TransferBorrowDraft` (borrowing) — the same faces plus
//!   `copy_record`/`move_record` for whole records,
//!   `copy_payload`/`move_payload` for LEN interiors, and
//!   `copy_record_from` importing one designated record from
//!   another document; a move is one command, one pending step,
//!   one revert.
//! - Hex-view supply: `span`/`source_spans` give record geometry
//!   at the widths the scan actually met, and `narrowest` answers
//!   "which record covers this byte".
//! - Releasing: `into_source` gives the moved-in buffer back,
//!   pending edits discarded — the open door's inverse.
//!
//! Both dialect drafts ship the same faces; the crate root's
//! feature guide picks the dialect.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "draft-groupless")] {
//! use protobuf_edit::draft::groupless::Draft;
//!
//! // varint f1=150, its value padded to three bytes: tolerant
//! // admission carries the spelling as a stored width fact.
//! let mut draft = Draft::open(vec![0x08, 0x96, 0x81, 0x00]).unwrap();
//! let record = draft.top().next().unwrap();
//! assert_eq!(draft.varint_word(record).unwrap(), 150);
//!
//! // Untouched records ride saves verbatim, padding included.
//! assert_eq!(draft.save().unwrap(), [0x08, 0x96, 0x81, 0x00]);
//!
//! // A replacement re-authors the value minimally — the source
//! // tag still rides verbatim.
//! draft.set_varint(record, 7).unwrap();
//! assert_eq!(draft.save().unwrap(), [0x08, 0x07]);
//!
//! // Revision restores byte fidelity exactly.
//! draft.revert();
//! assert_eq!(draft.save().unwrap(), [0x08, 0x96, 0x81, 0x00]);
//! # }
//! ```
//!
//! # Recipes
//!
//! Drafts chain through their saves: the output moves straight
//! into the next draft's open door — no copy, and the tenure
//! refusal shape stays transactional across the chain:
//!
//! ```
//! # #[cfg(feature = "draft-groupless")] {
//! use protobuf_edit::draft::groupless::Draft;
//!
//! let mut draft = Draft::open(vec![0x08, 0x96, 0x81, 0x00]).unwrap();
//! let record = draft.top().next().unwrap();
//! draft.set_varint(record, 7).unwrap();
//!
//! let mut next = Draft::open(draft.save().unwrap()).unwrap();
//! let record = next.top().next().unwrap();
//! next.set_varint(record, 8).unwrap();
//! assert_eq!(next.save().unwrap(), [0x08, 0x08]);
//! # }
//! ```
//!
//! The undo bracket — a hand-rolled transaction over the revision
//! log: mark `pending` before a compound edit, and on failure pop
//! back to the mark:
//!
//! ```
//! # #[cfg(feature = "draft-groupless")] {
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::draft::groupless::{Draft, InsertAt};
//!
//! let mut draft = Draft::open(vec![0x08, 0x2A]).unwrap();
//! let record = draft.top().next().unwrap();
//! draft.set_varint(record, 7).unwrap(); // the committed prefix
//!
//! let mark = draft.pending();
//! let f2 = FieldNumber::new(2).unwrap();
//! draft.insert_varint(InsertAt::TailOf(None), f2, 1).unwrap();
//! draft.insert_varint(InsertAt::TailOf(None), f2, 2).unwrap();
//! // The compound edit is abandoned: unwind to the mark, exactly.
//! while draft.pending() > mark {
//!     draft.revert();
//! }
//! assert_eq!(draft.save().unwrap(), [0x08, 0x07]);
//! # }
//! ```
//!
//! The borrowed-payload profile: a long-lived template outlives
//! every draft built over it, its slices install without a staging
//! copy, and reverting every command restores the padded source
//! byte-exactly:
//!
//! ```
//! # #[cfg(feature = "draft-groupless")] {
//! use protobuf_edit::draft::groupless::BorrowDraft;
//!
//! let template = vec![0x08, 0x2A];
//! // LEN f2 "a", its prefix padded to two bytes.
//! let source = vec![0x12, 0x81, 0x00, 0x61];
//! let mut draft = BorrowDraft::open(source.clone()).unwrap();
//! let record = draft.top().next().unwrap();
//! draft.set_payload(record, &template).unwrap();
//! // The replacement re-authors the prefix (the length moved);
//! // the source tag still rides verbatim.
//! assert_eq!(draft.save().unwrap(), [0x12, 0x02, 0x08, 0x2A]);
//! draft.revert_all();
//! assert_eq!(draft.save().unwrap(), source);
//! # }
//! ```
#![cfg_attr(
    feature = "draft-groupless",
    doc = "
A borrowed payload must outlive the draft — the type refuses an
owner that dies while the machine can still read the slot (the
copy-only `Draft` is the escape hatch for temporaries):

```compile_fail,E0597
use protobuf_edit::draft::groupless::BorrowDraft;

let mut draft = BorrowDraft::open(vec![0x12, 0x01, 0x61]).unwrap();
let record = draft.top().next().unwrap();
{
    let transient = vec![0x08, 0x07];
    draft.set_payload(record, &transient).unwrap();
} // the owner dies here; the draft still holds the borrow
draft.save().unwrap();
```"
)]
#![cfg_attr(
    feature = "draft-groupless",
    doc = "
And a retained owner may not be mutated while the machine can
still read the slot — the install borrows it for the machine's
remaining life:

```compile_fail,E0502
use protobuf_edit::draft::groupless::BorrowDraft;

let mut payload = vec![0x08, 0x07];
let mut draft = BorrowDraft::open(vec![0x12, 0x01, 0x61]).unwrap();
let record = draft.top().next().unwrap();
draft.set_payload(record, &payload).unwrap();
payload.clear(); // the draft still holds the borrow
draft.save().unwrap();
```"
)]

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::admission::{self, usize_of};
#[cfg(feature = "draft-grouped")]
pub mod grouped;
#[cfg(feature = "draft-groupless")]
pub mod groupless;

crate::revise::revising_store! {
    coordinates,
    tenure: vec,
    acceptance: tolerant,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
}

crate::revise::revising_store! {
    layer plain,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
}

#[cfg(any(feature = "transfer-draft-grouped", feature = "transfer-draft-groupless"))]
crate::revise::revising_store! {
    layer transfer,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
}

crate::revise::revising_store! {
    store borrow,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
}

crate::revise::revising_store! {
    store mixed,
    noun: "draft",
    a_noun: "a draft",
    A_noun: "A draft",
}
