//! The grouped traversal: all six codes, group tags paired in the
//! walk.
//!
//! Groups carry no length prefix — finding the end *is* parsing
//! the body — so delivering peeled group slices would scan every
//! body once in the cursor and again in the recursing consumer.
//! Groups therefore walk as in-band enter/exit entries: LEN is
//! sliceable, groups are only walkable, and the API asymmetry is
//! the format's own. The open stack verifies each pairing and is
//! bounded by the cursor's [`GroupDepth`](crate::traverse::GroupDepth). LEN payloads stay
//! opaque (module doc of [`crate::traverse`]).
//!
//! Acceptance is the entry type: [`Cursor`] walks width-tolerant,
//! [`CanonicalCursor`] additionally refuses every non-minimal
//! varint width — the type picks the engine instance, so neither
//! twin stores a standard or branches on one.
//!
//! Coordinates: read · buffered · online · grouped · tolerant (type-level) · canonical (type-level) · borrowed.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::traverse::GroupDepth;
//! use protobuf_edit::traverse::grouped::{Cursor, EntryKind};
//!
//! // Field 1 group wrapping one varint record: field 2, value 150.
//! let msg = [0x0B, 0x10, 0x96, 0x01, 0x0C];
//! let entries = Cursor::over(&msg, GroupDepth::REFERENCE)
//!     .unwrap()
//!     .collect::<Result<Vec<_>, _>>()
//!     .unwrap();
//! let walk: Vec<_> = entries
//!     .iter()
//!     .map(|entry| (entry.field().as_inner(), entry.kind()))
//!     .collect();
//! assert_eq!(walk, [
//!     (1, EntryKind::GroupEnter),
//!     (2, EntryKind::Varint(150)),
//!     (1, EntryKind::GroupExit),
//! ]);
//! ```

pub use crate::cursor::grouped::{CanonicalCursor, Cursor, Entry, EntryKind, Fault, FaultKind};
