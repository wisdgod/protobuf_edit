//! The borrowed single-pass traversal cursor: the dynamic-decode
//! substrate (read · buffered · online).
//!
//! One cursor walks one buffered message and delivers each record
//! exactly once — the field number plus the decoded observation
//! (wire word, borrowed payload, or group punctuation). LEN
//! payloads are Opaque here — the machine's one interpretation
//! pole: whether a payload nests a message is schema knowledge
//! the cursor does not presume, so descent is the consumer's own
//! recommitment — its own cursor over the delivered slice, with
//! packed element reading as [`packed`].
//!
//! Every varint rides the checked slice-kernel faces
//! ([`crate::varint::slice`]) — the walk judges outside bytes, so
//! the extent contract is asserted, not assumed. The tolerant
//! cursors read width-tolerant (padded encodings deliver identical
//! words) and forgery-strict (out-of-class terminals refuse); each
//! dialect also ships a `CanonicalCursor` twin that refuses every
//! non-minimal varint width — acceptance is the entry type, so the
//! tolerant walk stores no standard and branches on none. The
//! dialects are independent concrete types: `grouped` pairs group
//! tags and bounds their nesting; `groupless` refuses group codes
//! as a capability judgment.
//!
//! Allocation policy: the grouped cursors' open-group stack grows
//! by the standard `Vec` panic/abort path; the groupless cursors
//! and the packed readers allocate nothing.
//!
//! Coordinates: read · buffered · online · tolerant (type-level) · canonical (type-level) · borrowed.
//!
//! # Choosing a face
//!
//! - Foreign bytes: `Cursor::over` — the one admission judgment
//!   (the grouped cursor also takes its `GroupDepth` bound there).
//! - Canonical-minimal acceptance: `CanonicalCursor::over` — the
//!   same walk and admission, refusing padded widths where the
//!   stream scanner's canonical validator would.
//! - A LEN payload this walk delivered: `Cursor::within` — the
//!   payload is in class by construction, so the recommitment
//!   carries no refusal to handle.
//! - A packed payload you committed to: [`packed::Varints`] for
//!   varint elements; fixed-width elements are plain
//!   `chunks_exact` reads and need no reader.
//! - Record geometry without a tree: `pos` differences measure
//!   whole records, and `tag_width`/`prefix_width` split the last
//!   delivered head.
//!
//! Both dialect cursors ship the same faces. Elsewhere: the whole
//! tree at once, with spans and faults kept as data → `inspect`;
//! chunked input → `scan`; editing what you walk → `patch` or
//! `session` (each behind its feature).
//!
//! # Examples
//!
//! Walk examples live with the dialect cursors (`grouped`,
//! `groupless`); the dialect-orthogonal packed readers:
//!
//! ```
//! use protobuf_edit::traverse::packed::Varints;
//!
//! // A LEN payload the caller committed to packed varints.
//! let payload = [0x01, 0x96, 0x01, 0x02];
//! let words: Result<Vec<u64>, _> = Varints::over(&payload).collect();
//! assert_eq!(words.unwrap(), [1, 150, 2]);
//! ```
//!
//! # Recipes
//!
//! The free lookahead a `Copy` cursor buys: probe ahead on a copy
//! and the original has not moved — no reopen, no rewalk:
//!
//! ```
//! # #[cfg(feature = "traverse-groupless")] {
//! use protobuf_edit::traverse::groupless::{Cursor, EntryKind};
//!
//! // varint f1=150 · LEN f2 "hi"
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut cursor = Cursor::over(&msg).unwrap();
//!
//! let probe = cursor; // a snapshot, not a restart
//! assert_eq!(probe.count(), 2);
//! let first = cursor.next().unwrap().unwrap();
//! assert!(matches!(first.kind(), EntryKind::Varint(150)));
//! # }
//! ```
//!
//! Raw record bytes without a tree: bracket [`Iterator::next`]
//! with `pos` — the difference is one whole record, sliced from
//! the walked bytes (verbatim re-emission material):
//!
//! ```
//! # #[cfg(feature = "traverse-groupless")] {
//! use protobuf_edit::traverse::groupless::Cursor;
//!
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut cursor = Cursor::over(&msg).unwrap();
//! let mut raw = Vec::new();
//! let mut start = cursor.pos();
//! while let Some(entry) = cursor.next() {
//!     entry.unwrap();
//!     raw.push(&msg[start as usize..cursor.pos() as usize]);
//!     start = cursor.pos();
//! }
//! // The slices tile the message exactly.
//! assert_eq!(raw.concat(), msg);
//! # }
//! ```
//!
//! A packed payload is a LEN the caller commits to one element
//! family: the walk delivers the payload, [`packed::Varints`] (or
//! [`packed::Fixed32s`]/[`packed::Fixed64s`]) reads the elements:
//!
//! ```
//! # #[cfg(feature = "traverse-groupless")] {
//! use protobuf_edit::traverse::groupless::{Cursor, EntryKind};
//! use protobuf_edit::traverse::packed::Varints;
//!
//! // LEN f4 holding packed varints 3 and 270.
//! let msg = [0x22, 0x03, 0x03, 0x8E, 0x02];
//! let mut cursor = Cursor::over(&msg).unwrap();
//! let entry = cursor.next().unwrap().unwrap();
//! let EntryKind::Len(payload) = entry.kind() else { unreachable!() };
//!
//! let words: Result<Vec<u64>, _> = Varints::over(payload).collect();
//! assert_eq!(words.unwrap(), [3, 270]);
//! # }
//! ```

#[cfg(feature = "traverse-grouped")]
pub mod grouped;
#[cfg(feature = "traverse-groupless")]
pub mod groupless;
pub mod packed;

pub use crate::Stage;
pub use crate::cursor::Oversize;

#[cfg(feature = "traverse-grouped")]
pub use crate::cursor::GroupDepth;
