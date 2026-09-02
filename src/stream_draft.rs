//! The shared stream-ingest drafting layer: the value store, the
//! edit algebra, and the coordinate types both dialect machines
//! build on.
//!
//! This cell is the tolerant revisable draft's stream-presence
//! sibling: the input document arrives in chunks, and each cell's
//! `Ingest` phase parses those chunks as they arrive — one fused
//! pass that copies every byte into the owned source and builds the
//! final row arena, root layer, and source run in the same
//! source-level pass.
//! A successful `finish` seals the accumulated source and publishes
//! the finished drafting machine; from there the faces are the
//! buffered draft's: the session's command set and revision log
//! with the one-shot patch's byte fidelity, two-pass saves,
//! canonical saves, transactional release through `into_source`.
//! The ingest phase itself has no query, command, save, or undo
//! face — revision begins after the seal, and the cell's only input
//! door is `feed`.
//!
//! What the fused pass buys, as source-level traffic: a
//! collect-then-open composition reads the incoming bytes once to
//! copy them and then re-reads the retained framing bytes in the
//! buffered root scan. Direct ingest examines each byte once, at
//! the moment it copies it, so the traffic saved is exactly that
//! post-collection read — near the whole input for parse-dense
//! documents, and correspondingly small for opaque-heavy documents
//! whose root scan skips most bytes.
//! `finish` is, at the source level, state judgments and moves
//! alone: no reparse step, no walk over the accumulated length.
//!
//! Tenure is transactional at every door: a refused chunk
//! is either untouched (`ChunkDisposition::Unabsorbed` — nothing of
//! it was read) or absorbed whole (`ChunkDisposition::Absorbed` —
//! the accumulated source ends with it), never split; the
//! accumulated source rides back beside the fault, and
//! `into_source` releases it from a live ingest. Dropping a live
//! `Ingest` abandons the job.
//!
//! Allocation policy: every growth edge in this scenario is
//! fallible — the source reservation at each feed, the row arena at
//! each publish, and the root source run at the seal all grow
//! through `try_reserve`, and a refusal surfaces as a structured
//! resource fault with the accumulated source returned — never an
//! abort: the finished draft carries revisable interactive state
//! across turns, the fallible side of the crate root's partition
//! rule, and its construction honors the same discipline.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other or with any buffered cell.
//!
//! Coordinates: write · stream · offline · tolerant (type-level) · owned · revisable.
//!
//! # Choosing a face
//!
//! - Ingesting: `Ingest::new` starts the job (`with_capacity` pins
//!   one exact source allocation when the total is known); `feed`
//!   accepts each chunk; `finish` seals and publishes the
//!   copy-default drafting machine — `finish_borrow` seals the same
//!   parts into the borrowed-payload sibling.
//! - Relocation and import: `Ingest::finish_transfer` (feature
//!   `transfer-stream-draft-*`) seals the same parts into
//!   `TransferDraft` and `finish_transfer_borrow` into
//!   `TransferBorrowDraft` (the dialect's `transfer` submodule) —
//!   the same faces plus `copy_record`/`move_record` for whole
//!   records, `copy_payload`/`move_payload` for LEN interiors, and
//!   `copy_record_from` importing one designated record from
//!   another document; a move is one command, one pending step,
//!   one revert.
//! - A source already buffered wants the buffered cell (feature
//!   `draft-*`): its `open` is one root scan with no per-chunk
//!   state. Commit-only editing over a stream is the stream
//!   adopt's (feature `stream-adopt-*`).
//! - Abandoning: `Ingest::into_source` releases the accumulated
//!   bytes from a live job; a failure returns them beside the
//!   fault.
//! - Everything after the seal — commands, undo, saves, spans,
//!   descent, release — reads exactly as the buffered draft's
//!   faces.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "stream-draft-groupless")] {
//! use protobuf_edit::stream_draft::groupless::Ingest;
//!
//! // varint f1=150 · varint f2=42, arriving in two chunks that cut
//! // the first value.
//! let mut ingest = Ingest::new();
//! ingest.feed(&[0x08, 0x96]).unwrap();
//! ingest.feed(&[0x01, 0x10, 0x2A]).unwrap();
//!
//! let mut draft = ingest.finish().unwrap();
//! let first = draft.top().next().unwrap();
//! draft.set_varint(first, 7).unwrap();
//! assert_eq!(draft.save().unwrap(), [0x08, 0x07, 0x10, 0x2A]);
//!
//! // Revision restores the fed bytes exactly.
//! draft.revert();
//! assert_eq!(draft.save().unwrap(), [0x08, 0x96, 0x01, 0x10, 0x2A]);
//! # }
//! ```

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::admission::{self, usize_of};
#[cfg(feature = "stream-draft-grouped")]
pub mod grouped;
#[cfg(feature = "stream-draft-groupless")]
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

#[cfg(any(feature = "transfer-stream-draft-grouped", feature = "transfer-stream-draft-groupless"))]
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
