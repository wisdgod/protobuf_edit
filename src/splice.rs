//! Online rule-driven splicing: buffered input, one ask per
//! record, variable-length edits with every LEN cascade settled
//! exactly.
//!
//! The consumer's `Rule` (each dialect's trait) answers one
//! verdict per delivered record — no path compilation, no
//! measuring pass,
//! no row arena. Variable-length answers (any-length `Replace`,
//! `Drop`, `Insert`) are lawful at any depth: a committed
//! container's new interior length is knowable exactly at its
//! close and never before (verdicts are consumer code, fired once
//! at delivery), so the Vec faces ride each committed prefix at
//! its met width and settle at the close — nothing on unchanged
//! length, an in-place backpatch on unchanged width, one memmove
//! of the just-closed interior on a width change. Changed framing
//! re-authors minimally; unchanged framing rides verbatim — the
//! family law every sibling editor honors.
//!
//! Bytes already handed to a sink cannot be taken back for
//! backpatching, so the sink face's contract is zero handoff on
//! `Err`: the same ask walk instead builds a sealed source-ordered
//! overlay (source ranges, staged authored bytes, prefix slots
//! filled at each close), then an infallible range fold hands the
//! windows over. The emitter carries no rule reference, so a
//! second ask is unspellable.
//!
//! Verdict vocabularies are per record kind, so an ill-typed
//! verdict is unspellable — no `KindMismatch` fault class exists.
//! `Insert` is terminal: bytes before the record, the record then
//! rides verbatim, in one returned verdict (the bytes may carry
//! any number of records). A committed container takes tail bytes
//! at its ask ([`Len::Commit`]), staged and emitted at the close —
//! the only staging copy the Vec faces ever make.
//!
//! Coordinates: write · buffered · online · Standard (value-level) · borrowed · commit-only.
//!
//! # Choosing a face
//!
//! Each dialect ships three faces behind one walk front:
//! `splice` (fresh buffer), `splice_into` (append to a caller
//! buffer, truncate-to-mark on `Err`), `splice_sink` (borrowed
//! windows, nothing handed on `Err`). The transfer overlay
//! (feature `transfer-splice-*`) adds `splice_sources`/
//! `splice_sources_into`/`splice_sources_sink`: the same walk
//! under a `SourceRule`, whose verdicts may also relocate the
//! asked record or its payload into an `OnlineGap` destination.
//! Elsewhere: static path programs over buffered bytes →
//! `rewrite`; handle-driven edits → `patch` / `session`;
//! streaming equal-length rewriting → `transcode` (each behind
//! its feature).
//!
//! # Recipes
//!
//! A payload-derived replacement — the buffered privilege: the ask
//! hands the payload, the rule computes the new bytes into its own
//! scratch and answers from it:
//!
//! ```
//! # #[cfg(feature = "splice-groupless")] {
//! use protobuf_edit::splice::groupless::{splice, Rule};
//! use protobuf_edit::splice::Len;
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! struct Upper(Vec<u8>);
//! impl Rule for Upper {
//!     fn on_len<'a>(
//!         &'a mut self,
//!         _at: u32,
//!         field: FieldNumber,
//!         payload: &'a [u8],
//!     ) -> Len<'a> {
//!         if field == FieldNumber::new(2).unwrap() {
//!             self.0 = payload.to_ascii_uppercase();
//!             Len::Replace(&self.0)
//!         } else {
//!             Len::Pass
//!         }
//!     }
//! }
//!
//! // varint f1 · LEN f2 "hi" — the edit grows nothing here, but
//! // any length is lawful: cascades settle on the way out.
//! let msg = [0x08, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let out = splice(&msg, &mut Upper(Vec::new()), Standard::Tolerant, DepthLimit::REFERENCE)
//!     .unwrap();
//! assert_eq!(out, [0x08, 0x01, 0x12, 0x02, 0x48, 0x49]);
//! # }
//! ```
//!
//! Editing and observing are one pass — verdicts and collection
//! share the rule's state, so a drop can keep what it removed:
//!
//! ```
//! # #[cfg(feature = "splice-groupless")] {
//! use protobuf_edit::splice::groupless::{splice, Rule};
//! use protobuf_edit::splice::Scalar;
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! struct Evict(Vec<u64>);
//! impl Rule for Evict {
//!     fn on_varint(&mut self, _at: u32, field: FieldNumber, value: u64) -> Scalar<'_, u64> {
//!         if field == FieldNumber::new(9).unwrap() {
//!             self.0.push(value);
//!             Scalar::Drop
//!         } else {
//!             Scalar::Keep
//!         }
//!     }
//! }
//!
//! // f9 = 7 · f1 = 1 · f9 = 8: both nines leave, both are kept.
//! let msg = [0x48, 0x07, 0x08, 0x01, 0x48, 0x08];
//! let mut rule = Evict(Vec::new());
//! let out = splice(&msg, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(out, [0x08, 0x01]);
//! assert_eq!(rule.0, [7, 8]);
//! # }
//! ```

/// A scalar record's verdict: the value kind `V` is the ask
/// method's own (varint and I64 words are `u64`, I32 words `u32`),
/// so a rewrite can never carry a foreign kind.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scalar<'a, V> {
    /// The record rides verbatim.
    Keep,
    /// The record re-emits: tag verbatim, the new value at minimal
    /// width (fixed kinds have one width).
    Rewrite(V),
    /// The record vanishes.
    Drop,
    /// The bytes land before the record, which then rides verbatim
    /// — one terminal verdict, no re-ask. The bytes are the
    /// caller's declaration: accounted, never parsed.
    Insert(&'a [u8]),
}

impl<'a, V> Scalar<'a, V> {
    /// Maps the rewrite payload, carrying the other verdicts over
    /// — the walks' fixed-kind funnel.
    pub(crate) fn map<W>(self, f: impl FnOnce(V) -> W) -> Scalar<'a, W> {
        match self {
            Self::Keep => Scalar::Keep,
            Self::Rewrite(value) => Scalar::Rewrite(f(value)),
            Self::Drop => Scalar::Drop,
            Self::Insert(bytes) => Scalar::Insert(bytes),
        }
    }
}

/// A LEN record's verdict. The ask hands the payload slice — the
/// buffered privilege — so a transformation is [`Replace`] bytes
/// computed from it.
///
/// [`Replace`]: Self::Replace
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Len<'a> {
    /// The whole record rides verbatim, unparsed and unasked.
    Pass,
    /// Enter the payload and ask per interior record; the length
    /// prefix settles at the close. `tail` bytes (a declaration,
    /// like an insert's) are staged at this ask and land after the
    /// last interior record, inside the container.
    Commit {
        /// Bytes appended at the container's close, `None` for a
        /// plain commit.
        tail: Option<&'a [u8]>,
    },
    /// The payload is replaced whole, any length: tag verbatim,
    /// minimal prefix, the bytes.
    Replace(&'a [u8]),
    /// The record vanishes.
    Drop,
    /// The bytes land before the record, which then rides verbatim
    /// — one terminal verdict, no re-ask.
    Insert(&'a [u8]),
}

mod back;

// The source-transfer stratum: the source-aware verdict overlay
// and its sealed custody engine, emitted only under the transfer
// capability.
#[cfg(any(feature = "transfer-splice-grouped", feature = "transfer-splice-groupless"))]
pub mod transfer;

#[cfg(any(feature = "transfer-splice-grouped", feature = "transfer-splice-groupless"))]
pub use transfer::{OnlineGap, SourceLen, SourceScalar};

#[cfg(feature = "splice-grouped")]
pub mod grouped;
#[cfg(feature = "splice-groupless")]
pub mod groupless;
