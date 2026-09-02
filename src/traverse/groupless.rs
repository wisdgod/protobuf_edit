//! The groupless traversal: four codes, group codes refused as
//! capability.
//!
//! A groupless cursor has no cross-record group state: every
//! record stands alone, so the walk keeps no stack, allocates
//! nothing, and takes no depth bound — one would be dead
//! configuration, since LEN recursion depth is the consumer's own
//! recursion choice. Group codes are well-formed wire outside this
//! language — they fault distinctly from the format's unassigned
//! codes, so a consumer can route such documents to the grouped
//! dialect. LEN payloads stay opaque (module doc of
//! [`crate::traverse`]).
//!
//! Acceptance is the entry type: [`Cursor`] walks width-tolerant,
//! [`CanonicalCursor`] additionally refuses every non-minimal
//! varint width — the type picks the engine instance, so neither
//! twin stores a standard or branches on one.
//!
//! Coordinates: read · buffered · online · groupless · tolerant (type-level) · canonical (type-level) · borrowed.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::traverse::groupless::{Cursor, EntryKind, FaultKind};
//!
//! // Field 1, varint 150; field 2, LEN "abc".
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x03, b'a', b'b', b'c'];
//! let entries = Cursor::over(&msg).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
//! assert_eq!(entries.len(), 2);
//! assert_eq!(entries[0].kind(), EntryKind::Varint(150));
//! assert_eq!(entries[1].kind(), EntryKind::Len(b"abc"));
//!
//! // A group tag is well-formed wire outside this language.
//! let fault = Cursor::over(&[0x0B]).unwrap().next().unwrap().unwrap_err();
//! assert!(matches!(fault.kind(), FaultKind::GroupCode { .. }));
//! ```

pub use crate::cursor::groupless::{CanonicalCursor, Cursor, Entry, EntryKind, Fault, FaultKind};
