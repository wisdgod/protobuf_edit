//! The shared stream-ingest intake layer: the authored-value store,
//! the command vocabulary, and the coordinate types both dialect
//! machines build on.
//!
//! This cell is the one-shot intake's stream-presence sibling: the
//! input document arrives in chunks, and each cell's `Ingest`
//! phase parses those chunks as they arrive — one fused pass that
//! copies every byte into the owned source, judges every framing
//! word and varint value canonical-minimal the moment its last
//! byte arrives, and builds the final row arena in the same
//! source-level pass. A successful `finish` seals the accumulated
//! source and publishes the finished editing machine; from there
//! the faces are the buffered intake's: commit-only commands,
//! byte-fidelity saves, transactional release through
//! `into_source`. The ingest phase itself has no query, command,
//! or save face — editing begins after the seal, and the cell's
//! only input door is `feed`.
//!
//! Admission is canonical-minimal: a padded tag, length prefix, or
//! varint value is lawful wire that this cell refuses — judged at
//! collection time, across chunk boundaries through the carry — so
//! every admitted framing word is minimal and the finished rows
//! store no width column; spans derive from the record's own
//! facts, and saved documents re-ingest under the same admission.
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
//! `into_source` releases it from a live ingest. Dropping a live
//! `Ingest` abandons the job.
//!
//! Allocation policy: allocation refusal aborts (the global
//! allocation handler); it is never an `Err`. Under the crate
//! root's partition rule, this cell sits on the abort side with its
//! buffered sibling: everything the ingest holds — the growing
//! source, rows — is the in-flight product of one construction job,
//! so an abort's loss ends with the job. Structured `Err`s here are
//! wire, policy, and coordinate judgments, never resource
//! refusals. (`Ingest` and the finished editor types are this
//! module's dialect submodules'; the shared layer holds the store
//! and coordinate strata.)
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other or with any buffered cell.
//!
//! Coordinates: write · stream · offline · canonical (type-level) · owned · commit-only.
//!
//! # Choosing a face
//!
//! - Ingesting: `Ingest::new` starts the job (`with_capacity` pins
//!   one exact source allocation when the total is known); `feed`
//!   accepts each chunk; `finish` seals and publishes the mixed
//!   editing machine — `finish_borrow`/`finish_copy` seal the same
//!   parts into the thin payload-backing siblings.
//! - Relocation and import: `Ingest::finish_transfer` (feature
//!   `transfer-stream-intake-*`) seals the same parts into
//!   `TransferIntake` in the dialect's `transfer` submodule — the
//!   same faces plus `copy_record`/`move_record` for whole
//!   records, `copy_payload`/`move_payload` for LEN interiors, and
//!   `copy_record_from` (with a `_copy` twin) importing one
//!   designated record from another document.
//! - A source already buffered wants the buffered cell (feature
//!   `intake-*`): its `open` is one root scan with no per-chunk
//!   state. Tolerant admission over a stream is the stream
//!   adopt's (feature `stream-adopt-*`).
//! - Abandoning: `Ingest::into_source` releases the accumulated
//!   bytes from a live job; a failure returns them beside the
//!   fault.
//! - Everything after the seal — commands, saves, spans, descent,
//!   release — reads exactly as the buffered intake's faces.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "stream-intake-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::stream_intake::groupless::Ingest;
//!
//! // varint f1=150 · varint f2=42, arriving in two chunks that cut
//! // the first value.
//! let mut ingest = Ingest::new(DepthLimit::REFERENCE);
//! ingest.feed(&[0x08, 0x96]).unwrap();
//! ingest.feed(&[0x01, 0x10, 0x2A]).unwrap();
//!
//! let mut intake = ingest.finish().unwrap();
//! let first = intake.top().next().unwrap();
//! intake.set_varint(first, 7).unwrap();
//! assert_eq!(intake.save().unwrap(), [0x08, 0x07, 0x10, 0x2A]);
//! # }
//! ```

use alloc::vec::Vec;

use crate::admission::{self, usize_of};

#[cfg(feature = "stream-intake-grouped")]
pub mod grouped;
#[cfg(feature = "stream-intake-groupless")]
pub mod groupless;

crate::editor::one_shot_store! {
    capability: plain,
    noun: "intake",
    A_noun: "An intake",
}

#[cfg(any(
    feature = "transfer-stream-intake-grouped",
    feature = "transfer-stream-intake-groupless"
))]
crate::editor::one_shot_store! {
    capability: transfer,
    noun: "intake",
}
