//! One-pass streaming transcoding (write · stream · online), per
//! wire dialect — the dialect-orthogonal shared layer.
//!
//! Chunked bytes in, transformed bytes out (push-style, to the
//! caller's `FnMut(&[u8])`), judged record by record through a
//! rule program. Zero retention, and **zero buffering of stream
//! content**: the staging ledger is one staged tag (≤ 5 B) plus
//! the varint carry (≤ 10 B) — payloads never enter the machine
//! (pass = forwarding chunk sub-slices, drop = counting, redirect
//! = handing sub-slices to the rule).
//!
//! The emission-timing theorem all shapes derive from: no byte of
//! a record is emitted before that record's verdict settles
//! (dropping an emitted tag is impossible), so scalars ask at
//! value completion, LEN at length-word completion, groups at tag
//! completion. Per LEN the interpretation poles are Commit (walk
//! in) and Opaque (every other verb: the payload streams by count,
//! never parsed) — a transform machine cannot speculate, since
//! bytes that failed a parse are already emitted or gone. This
//! machine's transform set is exactly the zero-cascade one —
//! equal-length rewrites at any depth, free structural edits where
//! no LEN ancestor is entered (the root and
//! pure group chains) — and variable-length-in-context is the
//! `Divert` composition point: the rule buys its own buffer.
//!
//! Output validity: after `finish` returns `Ok`, the bytes derived
//! from the input are lawful wire (the machine re-verified them
//! while walking); bytes injected by rule actions (`Insert`,
//! `Divert` flushes, tails) are the caller's declaration — the
//! machine accounts their lengths but does not parse them, so the
//! whole-output promise is conditional on every injection being
//! lawful at its position. A faulted or abandoned job's prefix
//! carries no promise (re-running is undo).
//!
//! Output acceptance: kept bytes ride at their met widths and
//! rewrites hold the record's width (padded under `Tolerant`,
//! exact under `CanonicalMinimal`), so the output re-ingests under
//! the declared standard — modulo the injected-bytes condition
//! above.
//!
//! Allocation policy: the dialects' container stacks are the only
//! growth here (stream content is never buffered), and they grow
//! under the global allocator's panic/abort discipline, with zero
//! fallible reservations. The machine holds no caller state a
//! re-run cannot replay, so allocation refusal is never a
//! structured `Err`.
//!
//! Coordinates: write · stream · online · Standard (value-level) · commit-only.
//!
//! # Choosing a face
//!
//! One machine per dialect: construct with the declared
//! [`Standard`] and depth bound, `feed`
//! each chunk with your rule and sink, `finish` to declare EOF.
//! The choice lives in the rule:
//!
//! - `impl Rule for ()` is the bit-identical transcoder — the
//!   starting point every rule refines.
//! - Scalar asks answer [`FreeScalar`] at the root and pure group
//!   chains, [`LockedScalar`] under an entered LEN: the type
//!   removes the variable-length verbs where the length algebra
//!   is sealed, so "may I drop here" is never a runtime question.
//! - LEN asks answer [`FreeLen`]/[`LockedLen`]: `Commit` walks
//!   in; the Opaque verbs never parse the payload — `Pass`
//!   forwards it, `Replace` swaps it equal-length, `Transform`
//!   streams it through the rule under a length account, and the
//!   free-layer `Divert`/`Drop` are the variable-length
//!   compositions (the rule buys its own buffer).
//!
//! The grouped rule adds group asks; otherwise both dialects ship
//! the same faces. Elsewhere: a verdict with no output is `scan`,
//! which drives the same stepping pump; buffered variable-length
//! editing is `rewrite`, `patch`, or `session`; changing the wire
//! dialect itself is `convert` buffered and `replay_convert` over
//! a stable-replay source (each behind its feature).
//!
//! # Examples
//!
//! The all-default rule is the bit-identical transcoder — padding
//! included (under [`Standard::Tolerant`],
//! kept records ride byte-faithfully):
//!
//! ```
//! # #[cfg(feature = "transcode-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::transcode::Standard;
//! use protobuf_edit::transcode::groupless::Transcoder;
//!
//! // varint f1=150 (padded to three bytes) · LEN f2 "hi"
//! let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
//! let mut out = Vec::new();
//! let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
//! let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
//! t.feed(&msg[..5], &mut (), &mut sink).unwrap();
//! t.feed(&msg[5..], &mut (), &mut sink).unwrap();
//! t.finish(&mut (), &mut sink).unwrap();
//! assert_eq!(out, msg);
//! # }
//! ```
//!
//! # Recipes
//!
//! In-place replacement of any length at the free layer:
//! [`FreeScalar::Insert`] emits the replacement and asks again for
//! the same record, and answering [`FreeScalar::Drop`] on the
//! re-ask swallows the original — the composition those variants
//! document, compiled:
//!
//! ```
//! # #[cfg(feature = "transcode-groupless")] {
//! use protobuf_edit::transcode::Standard;
//! use protobuf_edit::transcode::FreeScalar;
//! use protobuf_edit::transcode::groupless::{Rule, Transcoder};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Swap field 1's varint for a LEN record: emit, then drop.
//! struct Swap {
//!     inserted: bool,
//! }
//! impl Rule for Swap {
//!     fn on_varint(
//!         &mut self,
//!         _at: u64,
//!         field: FieldNumber,
//!         _value: u64,
//!         _width: u8,
//!     ) -> FreeScalar<'_, u64> {
//!         if field.as_inner() != 1 {
//!             return FreeScalar::Keep;
//!         }
//!         if self.inserted {
//!             FreeScalar::Drop
//!         } else {
//!             self.inserted = true;
//!             FreeScalar::Insert(&[0x12, 0x02, 0x68, 0x69])
//!         }
//!     }
//! }
//!
//! // varint f1=7 · varint f2=1
//! let msg = [0x08, 0x07, 0x10, 0x01];
//! let mut out = Vec::new();
//! let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
//! let mut rule = Swap { inserted: false };
//! let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
//! t.feed(&msg, &mut rule, &mut sink).unwrap();
//! t.finish(&mut rule, &mut sink).unwrap();
//! assert_eq!(out, [0x12, 0x02, 0x68, 0x69, 0x10, 0x01]);
//! # }
//! ```

use core::num::NonZeroU32;

use crate::pump::FixedKind;
use crate::wire::{FieldNumber, PayloadLen};

pub use crate::Standard;

// ─── the rule's answer vocabularies (shared by both dialects) ───

/// A free-layer scalar verdict (no LEN ancestor entered: the root
/// and pure group chains).
#[must_use = "the verdict determines this record's output"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreeScalar<'a, T> {
    /// Source bytes ride verbatim (padding preserved).
    Keep,
    /// The value is re-emitted minimally; the tag rides verbatim.
    Rewrite(T),
    /// The record vanishes.
    Drop,
    /// Emit these pre-encoded bytes, then ask again for the same
    /// record (`Insert` then `Drop` composes an in-place
    /// replacement of any length).
    Insert(&'a [u8]),
    /// [`Insert`](Self::Insert)'s streaming form: emit exactly
    /// this many pre-encoded bytes pulled from the rule's own
    /// chunk source (`Rule::on_source`), then ask again for the
    /// same record. The account is consumed at the verdict and
    /// nothing is retained; a source that closes short or hands a
    /// chunk past the account is the rule's own breach.
    InsertSource(PayloadLen),
}

/// A locked-layer scalar verdict (an entered LEN ancestor seals
/// the length algebra): the variable-length verbs cannot be
/// spelled.
#[must_use = "the verdict determines this record's output"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockedScalar<T> {
    /// Source bytes ride verbatim.
    Keep,
    /// Equal-length rewrite: under `Standard::Tolerant` the new
    /// value pads to the source width (must fit); under
    /// `CanonicalMinimal` its minimal width must equal the source
    /// width (the output must re-ingest under the declared
    /// standard).
    Rewrite(T),
}

/// A free-layer LEN verdict.
///
/// One verb is the Commit pole ([`Commit`](Self::Commit)); the
/// verbs that never parse the payload are the Opaque pole times an
/// output action — Opaque × forward ([`Pass`](Self::Pass)),
/// × replace ([`Replace`](Self::Replace)), × transform
/// ([`Transform`](Self::Transform)), × redirect
/// ([`Divert`](Self::Divert)), × swallow ([`Drop`](Self::Drop)).
/// [`Insert`](Self::Insert) sits outside the axis: it emits before
/// the record's verdict settles.
#[must_use = "the verdict determines this record's output"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FreeLen<'a> {
    /// Whole record verbatim; the payload streams through without
    /// parsing (counted forwarding).
    Pass,
    /// Commit the payload as a message and walk in (asks inside
    /// are locked).
    Commit,
    /// Equal-length whole-payload replacement (tag and prefix ride
    /// verbatim; the replacement must match the announced length).
    Replace(&'a [u8]),
    /// Framed equal-length streaming transform: fragments go to
    /// `Rule::on_fragment`/`on_flush`, returned bytes emit in
    /// place, and the announced length is enforced as an account.
    Transform,
    /// The record leaves the output; fragments go to the rule,
    /// whose returned bytes emit at the record's position with no
    /// length account (the free-layer variable-length composition
    /// point — the rule owns any buffering).
    Divert,
    /// The record vanishes (payload swallowed by count).
    Drop,
    /// Emit these bytes, then ask again.
    Insert(&'a [u8]),
    /// [`Insert`](Self::Insert)'s streaming form: emit exactly
    /// this many pre-encoded bytes pulled from the rule's own
    /// chunk source (`Rule::on_source`), then ask again for the
    /// same record ([`FreeScalar::InsertSource`]'s account
    /// contract).
    InsertSource(PayloadLen),
    /// [`Replace`](Self::Replace)'s streaming form: the
    /// equal-length whole-payload replacement pulled from the
    /// rule's own chunk source — the announced length is the
    /// account, consumed exactly once, retained never.
    ReplaceSource,
}

/// A locked-layer LEN verdict: only the length-preserving verbs
/// (the Commit pole, and Opaque × {forward, replace, transform} —
/// the same axis [`FreeLen`] spells out).
#[must_use = "the verdict determines this record's output"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockedLen<'a> {
    /// Whole record verbatim.
    Pass,
    /// Commit and walk in.
    Commit,
    /// Equal-length whole-payload replacement.
    Replace(&'a [u8]),
    /// Framed equal-length streaming transform.
    Transform,
}

/// The settling vocabulary of a LEN verdict — what remains once
/// `Insert` has been peeled by the ask loop (emission precedes the
/// re-ask, so no settling arm ever sees it). The free vocabulary
/// narrows by that loop; the locked one embeds whole.
pub(crate) enum LenVerb<'a> {
    /// Whole record verbatim, payload forwarded by count.
    Pass,
    /// Commit the payload and walk in.
    Commit,
    /// Equal-length whole-payload replacement.
    Replace(&'a [u8]),
    /// Equal-length whole-payload replacement pulled from the
    /// rule's chunk source after the settling returns (the verb
    /// borrows the rule, so the pull rides a continuation).
    ReplaceSource,
    /// Framed equal-length streaming transform (accounted).
    Transform,
    /// Redirect with no account; the record leaves the output.
    Divert,
    /// The record vanishes, payload swallowed by count.
    Drop,
}

impl<'a> LockedLen<'a> {
    /// Widens into the settling vocabulary (total: the locked
    /// subset is already narrowed by construction).
    pub(crate) const fn into_verb(self) -> LenVerb<'a> {
        match self {
            Self::Pass => LenVerb::Pass,
            Self::Commit => LenVerb::Commit,
            Self::Replace(bytes) => LenVerb::Replace(bytes),
            Self::Transform => LenVerb::Transform,
        }
    }
}

/// A LEN settling's continuation: a zero-length redirect completes
/// at its head, but the flush ask must wait for the verdict
/// borrow to end (the settling verb may borrow the rule) — and a
/// source-pulled replacement asks the rule for chunks under the
/// same constraint.
pub(crate) enum Settled {
    /// Nothing pending.
    Done,
    /// Run the flush ask now (`owed` = the transform account, or
    /// none for divert).
    FlushRedirect {
        /// The emission account still owed (Transform) or none
        /// (Divert).
        owed: Option<PayloadLen>,
    },
    /// Pull the announced length from the rule's chunk source now.
    PumpSource,
}

// ─── the resume modes (private; the staged-head ledger lives
// with the pump stratum, shared with the rewirer) ───

/// Where to resume when the next chunk arrives (shared by both
/// dialects; suppression is stack state, not a mode, and
/// terminality is the pump's latch, not a resume position).
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
    /// Counted verbatim forwarding (a passed LEN payload).
    /// Nonzero by construction: a zero-length payload completes at
    /// its head, so a counting mode always owes.
    Forward {
        /// Bytes still owed.
        remaining: NonZeroU32,
    },
    /// Counted swallowing (a dropped, replaced, or suppressed
    /// payload).
    Swallow {
        /// Bytes still owed.
        remaining: NonZeroU32,
    },
    /// Counted redirection to the rule.
    Redirect {
        /// Bytes still owed from the source payload.
        remaining: NonZeroU32,
        /// The emission account (Transform) or none (Divert).
        owed: Option<PayloadLen>,
        /// The record's field (fault coordinates).
        field: FieldNumber,
        /// The record head's offset (fault coordinates).
        start: u64,
    },
}

const _: () = assert!(core::mem::size_of::<Mode>() == 24);

#[cfg(feature = "transcode-grouped")]
pub mod grouped;
#[cfg(feature = "transcode-groupless")]
pub mod groupless;
