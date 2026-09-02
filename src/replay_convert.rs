//! Dialect-crossing conversion over a stable-replay source
//! (write · sequential-repeatable · static).
//!
//! The buffered converter's job class run in walks: the feature
//! suffix names the OUTPUT dialect, so each cell walks the
//! opposite dialect's language and retains zero source bytes —
//! working memory scales with record structure, never source
//! length.
//!
//! Two independent cells, two directions (each linked only under
//! its own feature; plain names here so either cell documents
//! alone):
//!
//! - `groupless` walks the grouped language and re-frames every
//!   group as a LEN record (same field, measured body, minimal
//!   framing). No policy exists to declare: group punctuation
//!   identifies every source group by syntax, so the whole
//!   population converts — a constructor parameter would be dead
//!   configuration. Every LEN payload rides opaque; conversion
//!   never descends one.
//! - `grouped` walks the groupless language and re-frames the
//!   LEN records a compiled [`path::Program`](crate::path::Program)
//!   designates as groups (framing tags, no length prefix). The
//!   law is three-way: a **designated** LEN converts; a
//!   **routed-but-untargeted** LEN is committed and descended
//!   exactly as `replay_rewrite`'s crossings — it stays LEN, and
//!   its prefix re-settles when interior conversions change its
//!   extent; only an **unrouted** LEN rides opaque. Designation is
//!   required: LEN payloads are opaque bytes until the caller
//!   commits them to be messages, and re-framing is exactly such a
//!   commitment.
//!
//! Every face is two walks. Pass one measures and compiles a
//! source-anchored script (every document fault surfaces there —
//! ahead of the first handoff on the sink face, ahead of the
//! first appended byte on the Vec faces), pass two folds it
//! against a fresh walk through the splicing pump — parsing
//! nothing; the Vec faces reserve exactly once at the script's
//! compiled out-length, and the fold allocates nothing. Pass
//! two's whole fault alphabet is the supply's refusals and the
//! length-shaped tear (each cell's `JobFault::Torn`); the
//! equal-length content tear inside an extent the fold only
//! copies is not detectable at this cost profile — byte identity
//! across walks is the supply trait's documented obligation.
//!
//! Working memory beyond the output, per cell: a depth-bounded
//! frame stack, and per job the compiled script (O(structure):
//! verbatim runs, framing edits, prefix slots) retained between
//! walks — the fold allocates nothing. The `grouped` cell adds its
//! designation program's per-layer matcher tables (rebuilt per job
//! from the caller's program), with crossing metadata on the frame
//! stack and the boxed fault trail allocated only on the cold
//! refusal path. No face holds an occurrence index or a retained
//! source copy.
//!
//! Fidelity: every record the conversion does not re-frame rides
//! byte-verbatim — padded encodings included under `Tolerant` —
//! and every word the conversion authors (replacement framing,
//! minted or resized prefixes) is minimal. Each cell's module doc
//! states its exact closure sentence over the output language.
//!
//! Allocation policy: every allocation here is single-job working
//! memory — the script and its slots, the frame stack, the matcher
//! tables, and the output buffer — grown under the global
//! allocator's panic/abort discipline, with zero fallible
//! reservations. A job holds nothing a re-run cannot replay from
//! the caller's own source.
//!
//! Coordinates: write · sequential-repeatable · static · crossing · Standard (value-level) · commit-only.
//!
//! # Choosing a face
//!
//! Each cell ships three free-function faces, doors ordered as
//! `replay_splice`'s (`source` first, the grouped cell's `program`
//! second, then `Standard`, `DepthLimit`, the destination last),
//! each returning the job receipt (`Stats`):
//!
//! - `convert` runs one job into a fresh buffer — absent on `Err`,
//!   so no partial product exists.
//! - `convert_into` appends into yours, truncated back to its
//!   entry mark on any refusal — the reuse face for batch loops.
//! - `convert_sink` hands borrowed views forward as they emit; a
//!   refusal reports the exact handed prefix
//!   ([`Handed`](crate::replay_source::Handed)) — pass-one faults
//!   precede every handoff, a pass-two fault names what the sink
//!   received, and the prefix carries no validity promise.
//!
//! Elsewhere: the same crossing over a resident buffer →
//! `convert`; keeping the dialect while editing over a replay
//! source → `replay_rewrite` / `replay_splice`; changing
//! acceptance standards at equal length → `transcode` (each behind
//! its feature). The degenerate direction needs no machine here
//! either: an unchanged groupless-lawful document is already
//! grouped-lawful (the four-code language is a sub-language of the
//! six-code one), so *re-reading* it under grouped machines is a
//! zero-cost composition — the `grouped` cell exists for actual
//! re-framing.
//!
//! # Recipes
//!
//! A legacy migration is one pass each way, straight off the
//! supply: the groupless cell re-frames every group, and the
//! grouped cell re-frames designated fields back under a compiled
//! program — on canonical input the round trip is a byte fixed
//! point:
//!
//! ```
//! # #[cfg(all(feature = "replay-convert-grouped", feature = "replay-convert-groupless"))] {
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! // group f1 { varint f2 = 5 } — the legacy spelling.
//! let legacy = [0x0B, 0x10, 0x05, 0x0C];
//!
//! let (modern, stats) = protobuf_edit::replay_convert::groupless::convert(
//!     &mut SliceSource::new(&legacy),
//!     Standard::Tolerant,
//!     DepthLimit::REFERENCE,
//! )
//! .unwrap();
//! assert_eq!(modern, [0x0A, 0x02, 0x10, 0x05]); // f1 as a LEN
//! assert_eq!(stats.converted(), 1);
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f1)]];
//! let (again, _) = protobuf_edit::replay_convert::grouped::convert(
//!     &mut SliceSource::new(&modern),
//!     Program::over(&paths).unwrap(),
//!     Standard::Tolerant,
//!     DepthLimit::REFERENCE,
//! )
//! .unwrap();
//! assert_eq!(again, legacy);
//! # }
//! ```

#[cfg(feature = "replay-convert-grouped")]
pub mod grouped;
#[cfg(feature = "replay-convert-groupless")]
pub mod groupless;
