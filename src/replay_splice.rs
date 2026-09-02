//! Online rule-driven splicing over a stable replay source.
//!
//! One ask per record in the measuring walk, variable-length
//! edits with every LEN cascade settled exactly, and an emission
//! walk that re-reads the source instead of retaining it.
//!
//! The consumer's `Rule` (each dialect's trait) answers scalar
//! verdicts value in hand, exactly as the buffered twin does. LEN
//! records differ: the supply hands no whole payload (making one
//! contiguous would retain source bytes), so the interaction is
//! two typed phases. At the head the rule makes the irrevocable
//! interpretation declaration ([`Head`]): ride the payload opaque,
//! observe its bytes view by view, or commit into it and take the
//! interior asks. At the close an undescended record gives its one
//! output verdict ([`Close`]) from whatever state the fragments
//! accumulated. A committed payload cannot late-downgrade to
//! opaque, and an opaque payload cannot retroactively expose child
//! records — the phase types spell neither.
//!
//! Answer slices are staged by copy at the ask (the machine owes
//! the rule nothing after the call returns), so the job retains
//! O(answered bytes), never O(source). Pass one compiles the edit
//! script; pass two folds it against a fresh walk and parses
//! nothing — the rule is absent from the emitter, so a second ask
//! is unspellable. A rule needing a whole payload collects it
//! explicitly from its [`Head::Observe`] fragments.
//!
//! Coordinates: write · sequential-repeatable · online · Standard (value-level) · commit-only.
//!
//! # Choosing a face
//!
//! Each dialect ships three faces behind one walk front: `splice`
//! (a fresh buffer, absent on `Err`), `splice_into` (append to a
//! caller buffer, truncate-to-mark on `Err`), `splice_sink`
//! (borrowed windows; a refusal names the exact handed prefix).
//! Elsewhere: buffered per-record verdicts with the payload in
//! hand → `splice`; static path programs over a replay source →
//! `replay_rewrite`; changing the wire dialect itself over a
//! replay source → `replay_convert` (each behind its feature).
//!
//! # Recipes
//!
//! A payload-derived replacement without the buffered privilege:
//! observe the fragments, collect, and answer at the close:
//!
//! ```
//! # #[cfg(feature = "replay-splice-groupless")] {
//! use protobuf_edit::replay_splice::groupless::{Rule, splice};
//! use protobuf_edit::replay_splice::{Close, Head};
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::wire::PayloadLen;
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! struct Upper(Vec<u8>);
//! impl Rule for Upper {
//!     fn on_len(&mut self, _at: u64, field: FieldNumber, _len: PayloadLen) -> Head<'_> {
//!         if field == FieldNumber::new(2).unwrap() {
//!             self.0.clear();
//!             Head::Observe
//!         } else {
//!             Head::Opaque
//!         }
//!     }
//!     fn on_fragment(&mut self, _at: u64, view: &[u8]) {
//!         self.0.extend_from_slice(view);
//!     }
//!     fn on_close(&mut self, _at: u64, _field: FieldNumber) -> Close<'_> {
//!         self.0.make_ascii_uppercase();
//!         Close::Replace(&self.0)
//!     }
//! }
//!
//! // varint f1 · LEN f2 "hi"
//! let msg = [0x08, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut source = SliceSource::new(&msg);
//! let out = splice(&mut source, &mut Upper(Vec::new()), Standard::Tolerant,
//!     DepthLimit::REFERENCE).unwrap();
//! assert_eq!(out, [0x08, 0x01, 0x12, 0x02, 0x48, 0x49]);
//! # }
//! ```
//!
//! Editing and observing are one pass — verdicts and collection
//! share the rule's state, so a drop can keep what it removed:
//!
//! ```
//! # #[cfg(feature = "replay-splice-groupless")] {
//! use protobuf_edit::replay_splice::Scalar;
//! use protobuf_edit::replay_splice::groupless::{Rule, splice};
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! struct Evict(Vec<u64>);
//! impl Rule for Evict {
//!     fn on_varint(&mut self, _at: u64, field: FieldNumber, value: u64) -> Scalar<'_, u64> {
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
//! let mut source = SliceSource::new(&msg);
//! let out = splice(&mut source, &mut rule, Standard::Tolerant, DepthLimit::REFERENCE)
//!     .unwrap();
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
    /// caller's declaration: accounted, never parsed, staged by
    /// copy at this ask.
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

/// A LEN record's head declaration — phase one, irrevocable.
///
/// The supply hands no payload here (a contiguous slice would
/// retain source bytes); the two opaque forms take their one
/// output verdict at the close.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Head<'a> {
    /// The payload rides toward its close verdict unobserved — the
    /// walk seeks past it, so an unobserved record costs no read.
    Opaque,
    /// The payload's bytes are handed view by view (`on_fragment`)
    /// on the way to the close verdict; the views are the supply's
    /// own, borrowed per call.
    Observe,
    /// Enter the payload and ask per interior record; the length
    /// prefix settles at the close, and no close verdict fires — a
    /// committed record cannot late-downgrade. `tail` bytes (a
    /// declaration, like an insert's) are staged by copy at this
    /// ask and land after the last interior record, inside the
    /// container.
    Commit {
        /// Bytes appended at the container's close, `None` for a
        /// plain commit.
        tail: Option<&'a [u8]>,
    },
}

/// An undescended LEN record's close verdict — phase two, the one
/// output-settling answer for a [`Head::Opaque`] or
/// [`Head::Observe`] declaration.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Close<'a> {
    /// The whole record rides verbatim.
    Pass,
    /// The payload is replaced whole, any length: tag verbatim,
    /// minimal prefix, the bytes (staged by copy at this ask).
    Replace(&'a [u8]),
    /// The record vanishes.
    Drop,
    /// The bytes land before the record, which then rides verbatim
    /// — staged by copy at this ask.
    Insert(&'a [u8]),
}

#[cfg(feature = "replay-splice-grouped")]
pub mod grouped;
#[cfg(feature = "replay-splice-groupless")]
pub mod groupless;
