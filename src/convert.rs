//! Dialect-crossing conversion (write · buffered · static).
//!
//! The one scenario pair whose output dialect is not its input's:
//! the feature suffix names the OUTPUT, so each cell reads through
//! the opposite dialect's cursor.
//!
//! Two independent cells, two directions (each linked only under
//! its own feature; plain names here so either cell documents
//! alone):
//!
//! - `groupless` reads the grouped language and re-frames every
//!   group as a LEN record (same field, measured body, minimal
//!   framing). No policy exists to declare: group punctuation
//!   identifies every source group by syntax, so the whole
//!   population converts — a constructor parameter would be dead
//!   configuration.
//! - `grouped` reads the groupless language and re-frames the
//!   LEN records a compiled [`path::Program`](crate::path::Program)
//!   designates as groups (framing tags, no length prefix).
//!   Designation is required here: LEN payloads are opaque bytes
//!   until the caller commits them to be messages, and re-framing
//!   is exactly such a commitment.
//!
//! A group body's length is unknown until its end tag, so an
//! authored prefix must either be measured ahead or settled online
//! (reserve it at a met width, patch it once the body lands, as
//! this crate's own splicer emits). The groupless cell's Vec faces
//! settle online — one walk, each prefix backpatched at its
//! group's exit; the two-pass form's second walk priced out
//! against it (bench: `convert_groups_100k`). The sink faces are
//! buffered two-pass jobs (measure, then emit) either way: the
//! measured total is the sink face's whole preflight (every fault
//! precedes the first handoff, so the sink receives nothing on
//! `Err`). The grouped cell's Vec faces stay two-pass too — its
//! measuring pass is what mints the clean-subtree skip ledger.
//!
//! Working memory beyond the output, per cell: the groupless
//! cell's Vec faces keep one unsettled prefix position per *open*
//! group (depth-bounded); its sink face keeps one measured body
//! length per converted group; the grouped cell keeps one slot per
//! *crossed* LEN — clean ones included (the slot is the emit
//! pass's skip ledger) — plus its designation program's per-layer
//! matcher tables. The measuring passes carry a depth-bounded
//! frame stack; no face holds an occurrence index or a retained
//! source copy. Conversion never descends a LEN payload
//! on its own: interiors it was not told about ride verbatim,
//! opaque, exactly as everywhere else in this crate (a group
//! hidden inside an undesignated LEN payload is the payload
//! author's domain).
//!
//! Fidelity: every record the conversion does not re-frame rides
//! verbatim — padded encodings included under `Tolerant` — and
//! every word the conversion authors (replacement framing) is
//! minimal. Each cell's module doc states its exact closure
//! sentence over the output language.
//!
//! Allocation policy: every allocation here is single-job working
//! memory — the length ledger or open-hole stack, the frame stack,
//! and the output buffer — grown under the global allocator's
//! panic/abort discipline, with zero fallible reservations. A job holds
//! nothing a re-run cannot replay from the caller's own inputs.
//!
//! Coordinates: write · buffered · static · crossing · Standard (value-level) · borrowed · commit-only.
//!
//! # Choosing a face
//!
//! Each cell ships a `Converter` (configuration judged once at
//! `new`, jobs downstream reuse it) with three job faces:
//! `convert` runs one job into a fresh buffer; `convert_into`
//! appends into yours (untouched on `Err`) — the reuse face for
//! batch loops; `convert_sink` hands the same bytes to a caller
//! sink slice by slice, preflighted: every fault precedes the
//! first handoff, so the sink receives nothing on `Err`.
//!
//! Elsewhere: keeping the dialect while editing records → `rewrite`
//! / `patch` / `session`; changing acceptance standards at equal
//! length → `transcode`; the same crossing over a
//! sequential-repeatable source → `replay_convert` (each behind
//! its feature); and the degenerate direction that needs
//! no machine — an unchanged groupless-lawful document is
//! already grouped-lawful (the four-code language is a sub-language
//! of the six-code one), so *re-reading* it under grouped machines
//! is a zero-cost composition, no conversion involved. The
//! `grouped` cell exists for actual re-framing.
//!
//! # Recipes
//!
//! A legacy migration is one pass each way: the groupless cell
//! re-frames every group, and the grouped cell re-frames designated
//! fields back under a compiled program — on canonical input the
//! round trip is a byte fixed point:
//!
//! ```
//! # #[cfg(all(feature = "convert-grouped", feature = "convert-groupless"))] {
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! // group f1 { varint f2 = 5 } — the legacy spelling.
//! let legacy = [0x0B, 0x10, 0x05, 0x0C];
//!
//! let away = protobuf_edit::convert::groupless::Converter::new(
//!     Standard::Tolerant,
//!     DepthLimit::REFERENCE,
//! );
//! let (modern, stats) = away.convert(&legacy).unwrap();
//! assert_eq!(modern, [0x0A, 0x02, 0x10, 0x05]); // f1 as a LEN
//! assert_eq!(stats.converted(), 1);
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f1)]];
//! let back = protobuf_edit::convert::grouped::Converter::new(
//!     Standard::Tolerant,
//!     DepthLimit::REFERENCE,
//!     Program::over(&paths).unwrap(),
//! );
//! let (again, _) = back.convert(&modern).unwrap();
//! assert_eq!(again, legacy);
//! # }
//! ```

#[cfg(feature = "convert-grouped")]
pub mod grouped;
#[cfg(feature = "convert-groupless")]
pub mod groupless;
