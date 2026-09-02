//! The shared stream-ingest adopt layer: the authored-value store,
//! the command vocabulary, and the coordinate types both dialect
//! machines build on.
//!
//! This cell is the one-shot adopt's stream-presence sibling: the
//! input document arrives in chunks, and each cell's `Ingest`
//! phase parses those chunks as they arrive — one fused pass that
//! copies every byte into the owned source and builds the final row
//! arena in the same source-level pass. A successful `finish` seals the
//! accumulated source and publishes the finished editing machine;
//! from there the faces are the buffered adopt's: commit-only
//! commands, byte-fidelity saves, canonical saves, transactional
//! release through `into_source`. The ingest phase itself has no
//! query, command, or save face — editing begins after the seal,
//! and the cell's only input door is `feed`.
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
//! is either untouched (`ChunkDisposition::Unabsorbed` — nothing
//! of it was read) or absorbed whole (`ChunkDisposition::Absorbed`
//! — the accumulated source ends with it), never split; the
//! accumulated source rides back beside the fault, and
//! `into_source` releases it from a live ingest.
//! Dropping a live `Ingest` abandons the job.
//!
//! Allocation policy: allocation refusal aborts (the global
//! allocation handler); it is never an `Err`. Under the crate
//! root's partition rule, this cell sits on the abort side with its
//! buffered sibling: everything the ingest holds — the growing
//! source, rows — is the in-flight product of one construction job,
//! so an abort's loss ends with the job. Structured `Err`s here are
//! wire, capability, and coordinate judgments, never resource
//! refusals. (`Ingest` and the finished editor types are this
//! module's dialect submodules'; the shared layer holds the store
//! and coordinate strata.)
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other or with any buffered cell.
//!
//! Coordinates: write · stream · offline · tolerant (type-level) · owned · commit-only.
//!
//! # Choosing a face
//!
//! - Ingesting: `Ingest::new` starts the job (`with_capacity` pins
//!   one exact source allocation when the total is known); `feed`
//!   accepts each chunk; `finish` seals and publishes the mixed
//!   editing machine — `finish_borrow`/`finish_copy` seal the same
//!   parts into the thin payload-backing siblings.
//! - Relocation and import: `Ingest::finish_transfer` (feature
//!   `transfer-stream-adopt-*`) seals the same parts into
//!   `TransferAdopt` in the dialect's `transfer` submodule — the
//!   same faces plus `copy_record`/`move_record` for whole
//!   records, `copy_payload`/`move_payload` for LEN interiors, and
//!   `copy_record_from` (with a `_copy` twin) importing one
//!   designated record from another document.
//! - A source already buffered wants the buffered cell (feature
//!   `adopt-*`): its `open` is one root scan with no per-chunk
//!   state. Revision (undo) over a stream is the stream draft's
//!   (feature `stream-draft-*`).
//! - Abandoning: `Ingest::into_source` releases the accumulated
//!   bytes from a live job; a failure returns them beside the
//!   fault.
//! - Everything after the seal — commands, saves, spans, descent,
//!   release — reads exactly as the buffered adopt's faces.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "stream-adopt-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::stream_adopt::groupless::Ingest;
//!
//! // varint f1=150 · varint f2=42, arriving in two chunks that cut
//! // the first value.
//! let mut ingest = Ingest::new(DepthLimit::REFERENCE);
//! ingest.feed(&[0x08, 0x96]).unwrap();
//! ingest.feed(&[0x01, 0x10, 0x2A]).unwrap();
//!
//! let mut adopt = ingest.finish().unwrap();
//! let first = adopt.top().next().unwrap();
//! adopt.set_varint(first, 7).unwrap();
//! assert_eq!(adopt.save().unwrap(), [0x08, 0x07, 0x10, 0x2A]);
//! # }
//! ```

use alloc::vec::Vec;

use crate::admission::{self, usize_of};

#[cfg(feature = "stream-adopt-grouped")]
pub mod grouped;
#[cfg(feature = "stream-adopt-groupless")]
pub mod groupless;

crate::editor::one_shot_store! {
    capability: plain,
    noun: "adopt",
    A_noun: "An adopt",
}

#[cfg(any(feature = "transfer-stream-adopt-grouped", feature = "transfer-stream-adopt-groupless"))]
crate::editor::one_shot_store! {
    capability: transfer,
    noun: "adopt",
}
