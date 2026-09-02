//! Streaming path-program rewiring (write · stream · static), per
//! wire dialect — the dialect-orthogonal shared layer.
//!
//! Chunked bytes in, edited bytes out (push-style, to the caller's
//! `FnMut(&[u8])`), routed by a compiled [`crate::path::Program`] with one
//! action bound per path at authoring — the router's drive with the
//! transcoder's emission duty. Zero retention, and **zero buffering
//! of stream content**: the staging ledger is one staged tag (≤ 5 B)
//! plus the varint carry (≤ 10 B) — payloads never enter the
//! machine (pass = forwarding chunk sub-slices, delete = counting).
//! The matcher's layer tables are O(program), and each record costs
//! one probe.
//!
//! The action algebra is the zero-cascade set — equal-length edits
//! at any depth, free structural edits where no LEN ancestor is
//! entered (the root and, in the grouped dialect, pure group
//! chains). "May I drop here" is answered at authoring, never
//! asked at runtime: each dialect's `Actions::over`
//! judges every (path, action) binding against the paths' own
//! shapes, and a variable-length action whose match nevertheless
//! lands under an entered LEN (a wildcard that descended, or a
//! grouped crossing the document made a LEN) is the caller's
//! schema declaration proven wrong — faulted loudly at the record,
//! like every mismatch between a declaration and the document.
//!
//! Emission timing is the transcoder's theorem: no byte of a
//! record is emitted before that record's action settles, so
//! scalars settle at value completion, LEN records at length-word
//! completion, grouped records at tag completion. A targeted LEN
//! is opaque — its action covers the whole record and no path
//! descends it; an untargeted LEN with paths continuing into it is
//! committed (entered) and walked.
//!
//! Output validity: after `finish` returns `Ok`, the bytes derived
//! from the input are lawful wire; bytes injected by actions
//! ([`Action::Insert`], [`Value::Len`] replacements) are the
//! caller's declaration — accounted, not parsed — so the
//! whole-output promise is conditional on every injection being
//! lawful at its position. A faulted or abandoned job's prefix
//! carries no promise (re-running is undo).
//!
//! Output acceptance: kept bytes ride at their met widths; varint
//! rewrites re-emit minimally at free positions and hold the
//! record's width under an entered LEN (padded under `Tolerant`,
//! exact under `CanonicalMinimal`), so the output re-ingests under
//! the declared standard — modulo the injected-bytes condition
//! above.
//!
//! Allocation policy: the dialects' container stacks and the
//! matcher's layer tables are the only growth here (stream content
//! is never buffered), and they grow under the global allocator's
//! panic/abort discipline, with zero fallible reservations. The
//! machine holds no caller state a re-run cannot replay, so
//! allocation refusal is never a structured `Err`.
//!
//! Coordinates: write · stream · static · Standard (value-level) · commit-only.
//!
//! # Choosing a face
//!
//! One machine per dialect: admit the (path, action) bindings once
//! with `Actions::over` (const-capable — a static table pays its
//! judgment at compile time), construct the `Rewirer` with the
//! declared [`Standard`] and depth bound,
//! `feed` each chunk with your sink, `finish` to declare EOF.
//!
//! The action vocabulary ([`Action`]) is deliberately static data:
//!
//! - [`Action::Rewrite`] carries a typed [`Value`] — the
//!   equal-length edits, lawful at any depth (varints re-author
//!   width-safely, fixed words are width-free, LEN replacements
//!   must match the announced length).
//! - [`Action::Delete`] and [`Action::Insert`] are the free-layer
//!   structural edits; insertion is terminal — the bytes emit
//!   before the record and the record rides as if unmatched.
//!
//! Elsewhere: per-record *decisions* over a stream (a rule asked
//! with values in hand) are `transcode`; buffered variable-length
//! editing under rules is `rewrite` or `splice`; the read twin of
//! this machine — same drive, delivery instead of emission — is
//! `route` (each behind its feature).
//!
//! # Examples
//!
//! Deleting a root record and rewriting a nested one, over chunked
//! input (features: `rewire-groupless`):
//!
//! ```
//! # #[cfg(feature = "rewire-groupless")] {
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::rewire::groupless::{Actions, Rewirer};
//! use protobuf_edit::rewire::{Action, Value};
//! use protobuf_edit::rewire::Standard;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! let f = |n| FieldNumber::new(n).unwrap();
//! // Path 0: drop root field 1. Path 1: rewrite [2].[3] to 9.
//! let inner: [Segment<'_>; 2] = [Segment::Field(f(2)), Segment::Field(f(3))];
//! let outer: [Segment<'_>; 1] = [Segment::Field(f(1))];
//! let paths: [&[Segment<'_>]; 2] = [&outer, &inner];
//! let program = Program::over(&paths).unwrap();
//! let actions = [Action::Delete, Action::Rewrite(Value::Varint(9))];
//! let actions = Actions::over(&program, &actions).unwrap();
//!
//! // varint f1=7 · LEN f2 { varint f3=150 }
//! let msg = [0x08, 0x07, 0x12, 0x03, 0x18, 0x96, 0x01];
//! let mut out = Vec::new();
//! let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
//! let mut rw = Rewirer::new(&actions, Standard::Tolerant, DepthLimit::REFERENCE);
//! rw.feed(&msg[..3], &mut sink).unwrap();
//! rw.feed(&msg[3..], &mut sink).unwrap();
//! rw.finish().unwrap();
//! // f1 gone; f2's interior rewritten equal-width is impossible
//! // for 150→9 (two bytes → one), so the locked rewrite pads
//! // under Tolerant: [0x18, 0x89, 0x00] keeps the record's width.
//! assert_eq!(out, [0x12, 0x03, 0x18, 0x89, 0x00]);
//! # }
//! ```
//!
//! # Recipes
//!
//! One admitted table serves any number of streams: the program and
//! its bindings are judged once, and each connection runs its own
//! judgment-free machine over its chunks:
//!
//! ```
//! # #[cfg(feature = "rewire-groupless")] {
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::rewire::groupless::{Actions, Rewirer};
//! use protobuf_edit::rewire::Action;
//! use protobuf_edit::rewire::Standard;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f1)]];
//! let program = Program::over(&paths).unwrap();
//! let actions = Actions::over(&program, &[Action::Delete]).unwrap();
//!
//! // Two streams, one table: drop every root f1 from each.
//! for (msg, kept) in [
//!     (&[0x08, 0x07, 0x10, 0x2A][..], &[0x10, 0x2A][..]),
//!     (&[0x18, 0x01, 0x08, 0x63][..], &[0x18, 0x01][..]),
//! ] {
//!     let mut out = Vec::new();
//!     let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
//!     let mut rw = Rewirer::new(&actions, Standard::Tolerant, DepthLimit::REFERENCE);
//!     for chunk in msg.chunks(3) {
//!         rw.feed(chunk, &mut sink).unwrap();
//!     }
//!     rw.finish().unwrap();
//!     assert_eq!(out, kept);
//! }
//! # }
//! ```

use core::num::NonZeroU32;

use crate::path::Program;
#[cfg(feature = "rewire-groupless")]
use crate::path::Segment;
use crate::pump::FixedKind;
use crate::wire::{FieldNumber, PayloadLen};

pub use crate::Standard;

// ─── the per-path action vocabulary (shared by both dialects) ───

/// One path's bound action — static data, judged at
/// `Actions::over`, applied without a runtime ask.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action<'r> {
    /// Replace the matched record's value, equal-length: lawful at
    /// any depth. Varints re-emit minimally at free positions and
    /// hold the source width under an entered LEN; fixed words
    /// carry no width question; LEN payloads must match the
    /// announced length. The value's kind must match the record's
    /// — a mismatch is each dialect's runtime `KindMismatch`
    /// fault (kinds are document facts, not path facts).
    Rewrite(Value<'r>),
    /// Remove the matched record (a grouped dialect group target
    /// vanishes with its whole tree). Free-layer only.
    Delete,
    /// Emit these pre-encoded bytes before the matched record; the
    /// record then rides as if unmatched (insertion is terminal —
    /// no re-ask exists to compose with). The bytes are the
    /// caller's declaration: accounted, not parsed. Free-layer
    /// only.
    Insert(&'r [u8]),
}

/// A replacement value, typed by the record kind it may lawfully
/// answer.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Value<'r> {
    /// A varint record's new value.
    Varint(u64),
    /// An I32 record's new little-endian bits.
    I32(u32),
    /// An I64 record's new little-endian bits.
    I64(u64),
    /// A LEN record's new payload — must equal the announced
    /// length at the match (equal-length is the zero-cascade law's
    /// depth-free replacement), and the bytes are the caller's
    /// declaration: accounted, not parsed.
    Len(&'r [u8]),
}

/// An action-binding refusal at `Actions::over`.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ActionError {
    /// The action table and the program disagree on the path
    /// count: every path binds exactly one action, by index.
    CountMismatch {
        /// The program's path count.
        paths: u16,
        /// The action table's length.
        actions: usize,
    },
    /// A variable-length action ([`Action::Delete`] /
    /// [`Action::Insert`]) on a path none of whose matches can sit
    /// at a free position — in the groupless dialect every crossed
    /// container is an entered LEN, so a `Field`-prefixed path
    /// puts every match under one, and the action could never
    /// lawfully fire. (Grouped admission never mints this: any
    /// crossing may be a group there, so the judgment moves to the
    /// match.)
    CascadeUnsound {
        /// The offending path's index.
        path: u16,
    },
    /// A [`Value::Len`] replacement longer than the LEN class
    /// admits (`PayloadLen::MAX`): no announced length could ever
    /// equal it.
    OversizeReplacement {
        /// The offending path's index.
        path: u16,
    },
}

impl core::fmt::Display for ActionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::CountMismatch { paths, actions } => {
                write!(f, "{actions} actions bound against {paths} paths")
            }
            Self::CascadeUnsound { path } => write!(
                f,
                "path {path}: a variable-length action, but every match sits under an entered LEN"
            ),
            Self::OversizeReplacement { path } => {
                write!(f, "path {path}: a LEN replacement longer than the LEN class admits")
            }
        }
    }
}

impl core::error::Error for ActionError {}

// ─── the shared admission core (crate-internal) ───

/// The dialect-orthogonal binding judgments: the count equation
/// and the replacement size class. Each dialect's `Actions::over`
/// runs this first, then its own cascade clause.
pub(crate) const fn judge_bindings(
    program: &Program<'_>,
    actions: &[Action<'_>],
) -> Result<(), ActionError> {
    let paths = program.segments();
    if actions.len() != paths.len() {
        // Lossless: `Program::over` admitted the count to u16.
        #[allow(clippy::as_conversions, reason = "an admitted path count narrows losslessly")]
        return Err(ActionError::CountMismatch {
            paths: paths.len() as u16,
            actions: actions.len(),
        });
    }
    let mut index = 0;
    while index < actions.len() {
        if let Action::Rewrite(Value::Len(bytes)) = actions[index]
            && bytes.len() > crate::admission::usize_of(PayloadLen::MAX.as_inner())
        {
            #[allow(
                clippy::as_conversions,
                reason = "an index below the u16 count narrows losslessly"
            )]
            return Err(ActionError::OversizeReplacement { path: index as u16 });
        }
        index += 1;
    }
    Ok(())
}

/// The groupless cascade clause: a variable-length action needs at
/// least one shape-possible free match, and in the groupless
/// dialect only a zero-crossing match is free — every prefix
/// segment must be skippable, which a `Field` segment never is.
#[cfg(feature = "rewire-groupless")]
pub(crate) const fn judge_groupless_cascade(
    program: &Program<'_>,
    actions: &[Action<'_>],
) -> Result<(), ActionError> {
    let paths = program.segments();
    let mut index = 0;
    while index < actions.len() {
        if matches!(actions[index], Action::Delete | Action::Insert(_)) {
            let path = paths[index];
            let mut seg = 0;
            // The last segment is the target (`Program::over`
            // admitted it as `Field`); only the prefix crosses.
            while seg + 1 < path.len() {
                if let Segment::Field(_) = path[seg] {
                    #[allow(
                        clippy::as_conversions,
                        reason = "an index below the u16 count narrows losslessly"
                    )]
                    return Err(ActionError::CascadeUnsound { path: index as u16 });
                }
                seg += 1;
            }
        }
        index += 1;
    }
    Ok(())
}

// ─── the resume modes (private; shared by both dialects) ───

/// Where to resume when the next chunk arrives (suppression is
/// stack state, not a mode, and terminality is the pump's latch,
/// not a resume position).
pub(crate) enum Mode {
    /// Expecting a record head (the carry may hold a cut prefix).
    Head,
    /// A varint value in flight.
    VarintValue {
        /// The record's field.
        field: FieldNumber,
    },
    /// A LEN length word in flight.
    LenWord {
        /// The record's field.
        field: FieldNumber,
    },
    /// A fixed payload collecting (4 or 8 bytes).
    FixedTail {
        /// The record's field.
        field: FieldNumber,
        /// The fixed width.
        kind: FixedKind,
    },
    /// Counted verbatim forwarding (a passed or kept payload).
    /// Nonzero by construction: a zero-length payload completes at
    /// its head, so a counting mode always owes.
    Forward {
        /// Bytes still owed.
        remaining: NonZeroU32,
    },
    /// Counted swallowing (a deleted, replaced, or suppressed
    /// payload).
    Swallow {
        /// Bytes still owed.
        remaining: NonZeroU32,
    },
}

const _: () = assert!(core::mem::size_of::<Mode>() == 8);

#[cfg(feature = "rewire-grouped")]
pub mod grouped;
#[cfg(feature = "rewire-groupless")]
pub mod groupless;
