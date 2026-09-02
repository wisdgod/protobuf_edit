//! Path-program record selection (read · buffered · static), per
//! wire dialect — the dialect-orthogonal shared layer.
//!
//! One job: borrowed input bytes, a compiled
//! [`Program`](crate::path::Program), one pass, borrowed matches
//! out. Zero retention — no handles, no index, no cross-job state;
//! re-running is the only replay. The program precedes the
//! document: admission judged its shape once, so jobs are
//! judgment-free, and a `static` program pays even that judgment
//! at compile time.
//!
//! Selection is a read, so overlap fans out instead of faulting:
//! every path targeting a record delivers its own match, in
//! ascending [`PathId`](crate::path::PathId) order, and converging
//! wildcard states of one path deliver once. Paths commit exactly
//! as they do for the rewriter: every LEN a pattern crosses is
//! committed to be a message, a parse fault inside it is a real
//! fault carrying the crossing trail, and the caller's
//! [`DepthLimit`](crate::DepthLimit) bounds committed nesting. A
//! LEN that is both a selection target and a route delivers its
//! payload first, then its interior's matches follow (pre-order —
//! the payload is in hand at the head).
//!
//! The dialect modules read through the crate's private cursor
//! engines — the same walks the `traverse` faces re-export —
//! so selecting a select cell compiles no traverse surface.
//!
//! Allocation policy: every allocation here is single-job working
//! memory — the compiled path layers, the walk's layer stack, the
//! pending-delivery scratch, and the fault trail (fault path only)
//! — grown under the global allocator's panic/abort discipline,
//! with zero fallible reservations. Delivery allocates nothing:
//! matches borrow the input.
//!
//! Coordinates: read · buffered · static · tolerant (type-level) · canonical (type-level) · borrowed.
//!
//! # Choosing a face
//!
//! One authoring face, two job faces split by acceptance:
//!
//! - [`Program::over`](crate::path::Program::over) (the [`crate::path`]
//!   stratum) judges the paths' static shape once; compile one
//!   program and run it across documents.
//! - `Matches::over` admits one document and returns the fused
//!   match iterator — drop it to stop early, drain it for the
//!   full selection.
//! - `CanonicalMatches::over` is the canonical-minimal twin: the
//!   same walk refusing every non-minimal varint width. The entry
//!   type picks the engine, so the tolerant iterator stores no
//!   standard and branches on none.
//!
//! Both dialects ship the same faces. Elsewhere: rewriting what a
//! program designates → `rewrite`; walking every record without a
//! program → `traverse`; the same programs over chunked arrival →
//! `route` (each behind its feature). Choosing between the
//! selection twins is the presence axis: bytes in hand → select
//! here; bytes arriving chunked → route — both exist, the
//! consumer chooses.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "select-groupless")] {
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::select::groupless::{MatchKind, Matches};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Select every top-level field 2 record.
//! let field2 = FieldNumber::new(2).unwrap();
//! let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(field2)]];
//! let program = Program::over(&paths).unwrap();
//!
//! // varint f1=150 · LEN f2 "hi" · varint f2=7
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69, 0x10, 0x07];
//! let matches: Vec<_> = Matches::over(&msg, &program, DepthLimit::REFERENCE)
//!     .unwrap()
//!     .collect::<Result<_, _>>()
//!     .unwrap();
//! assert_eq!(matches.len(), 2);
//! assert_eq!(matches[0].kind(), MatchKind::Len(b"hi"));
//! assert_eq!(matches[1].kind(), MatchKind::Varint(7));
//! # }
//! ```
//!
//! # Recipes
//!
//! A process-reused selection: the program lives in a `static`
//! (its judgment ran at compile time — building it is the
//! doctest's own proof), and each request runs a judgment-free
//! job over its bytes:
//!
//! ```
//! # #[cfg(feature = "select-groupless")] {
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::select::groupless::Matches;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! const F1: FieldNumber = FieldNumber::new(1).unwrap();
//! const F3: FieldNumber = FieldNumber::new(3).unwrap();
//! static ROUTE: [FieldNumber; 1] = [F3];
//! static PATHS: [&[Segment<'static>]; 1] =
//!     [&[Segment::AnyDepth { descend: &ROUTE }, Segment::Field(F1)]];
//! static PROGRAM: Program<'static> = match Program::over(&PATHS) {
//!     Ok(program) => program,
//!     Err(_) => panic!("the paths are lawful"),
//! };
//!
//! // varint f1=1 · LEN f3 { varint f1=2 }
//! let request = [0x08, 0x01, 0x1A, 0x02, 0x08, 0x02];
//! let mut values = Vec::new();
//! for hit in Matches::over(&request, &PROGRAM, DepthLimit::REFERENCE).unwrap() {
//!     values.push(hit.unwrap().span().start());
//! }
//! assert_eq!(values, [0, 4]);
//! # }
//! ```

use crate::Span;
use crate::admission::{Coord, Extent};

/// One delivered record's whole-input span, from coordinates the
/// walk read in source order.
///
/// The walks admit their input at the LEN class (`Matches::over`),
/// every layer window nests inside that input, and `head` was read
/// before `end` along one monotone walk — the evidence the mints
/// below redeem, so a delivery pays no ordering or bound judgment.
#[inline]
const fn walk_span(head: u32, end: u32) -> Span {
    // SAFETY: `head <= end` — both are whole-input coordinates of
    // one walk, captured in source order — and both lie inside the
    // admitted input (`<= admission::MAX`), so each value is in the
    // coordinate class and their difference is in the extent class.
    let (start, width) = unsafe { (Coord::new_unchecked(head), Extent::new_unchecked(end - head)) };
    Span::of(start, width)
}

/// Admission refusal: the input exceeds the
/// [`i32::MAX` input cap](crate::Span) — the LEN length class top —
/// under which every walk coordinate fits `u32`. Unit-shaped — the
/// refused length is in the caller's hands.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Oversize;

impl core::fmt::Display for Oversize {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("input exceeds the LEN-class selection cap")
    }
}

impl core::error::Error for Oversize {}

#[cfg(feature = "select-grouped")]
pub mod grouped;
#[cfg(feature = "select-groupless")]
pub mod groupless;
