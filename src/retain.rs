//! Self-contained schema-less inspection of one owned protobuf
//! message (read · buffered · offline · owned), per wire dialect.
//!
//! The detachable twin of the borrowed inspector: the buffer moves
//! in, one parse builds the same preorder row table, and the
//! product owns everything it answers from — no borrow pins the
//! caller's frame, so the product moves, returns, caches, and
//! crosses threads (`Send + Sync`: an immutable owned index).
//! Rows address the source by `u32` coordinates, never pointers,
//! so ownership adds no self-reference and no new unsafe class.
//! The borrowed inspector (feature `inspect-*`, product
//! `inspect::Tree` against this module's `Retained`) keeps its
//! zero-copy `&'a` identity for callers whose buffer outlives
//! every query.
//!
//! Dialects are sibling modules, not parameters: `grouped` walks
//! groups structurally; `groupless` refuses group codes as a
//! capability judgment. This shared layer holds only
//! dialect-orthogonal vocabulary: admission, handles, and the
//! schema-supply face. Dialect-sensitive vocabulary (kinds,
//! faults, products) stays per dialect, unshared.
//!
//! The [`i32::MAX` input cap](crate::Span): admission bounds the
//! source at `i32::MAX` bytes — the LEN length class top and the
//! reference reader's single-message hard bound — so every stored
//! or computed coordinate lives in `0..=i32::MAX` and any two
//! coordinates add without overflowing `u32`. Admission is
//! judged inside the parse doors (an owned buffer carries no
//! reusable admission proof: it moves into exactly one product),
//! and a refusal returns the buffer intact — the transactional
//! tenure every owned-ingest door in this crate honors.
//!
//! Allocation policy: the parse product and the machine's working
//! stacks grow through the standard infallible `Vec` paths (panic
//! or abort on allocator refusal); wire violations are never
//! resource errors — they stay in the product as its fault.
//!
//! Coordinates: read · buffered · offline · Standard (value-level) · owned.
//!
//! # Choosing a face
//!
//! One entry chain per dialect: `Retained::parse` — the owned
//! buffer, a depth bound, an advisor — yields the product for
//! every buffer admission accepts, and the only refusal returns
//! the buffer with [`Oversize`]. Wire violations live *in* the
//! product (`fault`, `is_complete`), so a viewer renders the
//! lawful prefix of a broken document instead of handling an
//! error. `Retained::parse_standard` also takes the
//! acceptance [`Standard`](crate::Standard) and picks a
//! monomorphized engine once at entry — `parse` is exactly its
//! tolerant instance, and rows store actual widths under both
//! standards (span geometry needs them either way).
//!
//! The advisor argument is the schema dial, exactly the borrowed
//! inspector's: [`NoAdvice`] spells zero knowledge (every LEN
//! payload speculates); implement [`Advisor`] to pin the sites you
//! know — [`Advice::Commit`], [`Advice::Opaque`], or
//! [`Advice::Speculate`] per (ancestry, field).
//!
//! Query faces by question: structure (`top`, `children`,
//! `descendants`, `Children::by_field`), values (`varint_word`,
//! `i32_bits`, `i64_bits`, `payload_bytes`, `record_bytes`), and
//! hex-view geometry (`span`, `source_spans`, `narrowest`). The
//! source stays reachable: `bytes()` borrows it, `into_bytes()`
//! releases it — a moved-in buffer is never stranded.
//!
//! Both dialect products ship the same faces. Elsewhere: the
//! zero-copy borrowed tree over a caller-kept buffer → `inspect`;
//! one pass without materializing → `traverse`; chunked input →
//! `scan` (each behind its feature).
//!
//! # Examples
//!
//! The product outlives every caller frame — the borrowed
//! inspector's queries with none of its pins:
//!
//! ```
//! # #[cfg(feature = "retain-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::retain::NoAdvice;
//! use protobuf_edit::retain::groupless::Retained;
//!
//! fn build() -> Retained {
//!     // varint f1=150 · LEN f2 "hi" — the buffer moves in; no
//!     // borrow leaves this frame.
//!     let msg = vec![0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//!     Retained::parse(msg, DepthLimit::REFERENCE, &mut NoAdvice).unwrap()
//! }
//!
//! let tree = build();
//! assert!(tree.is_complete());
//! let first = tree.top().next().unwrap();
//! assert_eq!(tree.varint_word(first), Some(150));
//! # }
//! ```
//!
//! # Recipes
//!
//! The product is `Send + Sync`, so a parse hands off to another
//! thread whole — index and source together, zero copies
//! (features: `retain-groupless`):
//!
//! ```
//! # #[cfg(feature = "retain-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::retain::NoAdvice;
//! use protobuf_edit::retain::groupless::Retained;
//!
//! let msg = vec![0x08, 0x2A, 0x12, 0x02, 0x68, 0x69];
//! let tree = Retained::parse(msg, DepthLimit::REFERENCE, &mut NoAdvice).unwrap();
//! let answer = std::thread::spawn(move || {
//!     let id = tree.top().nth(1).unwrap();
//!     tree.payload_bytes(id).to_vec()
//! })
//! .join()
//! .unwrap();
//! assert_eq!(answer, [0x68, 0x69]);
//! # }
//! ```
//!
//! The buffer round-trips: a refusal returns it beside the
//! [`Oversize`] mark, and `into_bytes` releases it from a finished
//! product — both moves, zero copies:
//!
//! ```
//! # #[cfg(feature = "retain-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::retain::NoAdvice;
//! use protobuf_edit::retain::groupless::Retained;
//!
//! let msg = vec![0x08, 0x2A];
//! let tree = Retained::parse(msg, DepthLimit::REFERENCE, &mut NoAdvice).unwrap();
//! let msg: Vec<u8> = tree.into_bytes();
//! assert_eq!(msg, [0x08, 0x2A]);
//! # }
//! ```

use crate::{DepthLimit, FieldNumber};
pub use crate::Stage;

/// The one parse refusal: the buffer exceeds the
/// [`i32::MAX` input cap](crate::Span) — the LEN length class top
/// and the reference reader's single-message hard bound.
///
/// The mark is returned beside the untouched buffer, so a refusal
/// costs the caller nothing but the call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Oversize;

impl core::fmt::Display for Oversize {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("buffer exceeds the coordinate class")
    }
}

impl core::error::Error for Oversize {}

crate::_macro::define_valid_range_type! {
    /// An index into one retained parse product.
    ///
    /// Distinct from offsets and counts at the type level. Handles
    /// are slice-like: out-of-range use panics; a stale handle from
    /// another product that happens to be in range reads that
    /// product's answer — memory-safe, semantically the caller's
    /// fault.
    ///
    /// The class is admission-derived: every row spends at least its
    /// head tag byte and admission caps the input at `i32::MAX`
    /// bytes, so row indices stay in class and `Option<NodeId>` is
    /// free (the parent link needs no sentinel).
    #[must_use]
    pub struct NodeId(u32 as u32 in 0..=0x7FFF_FFFE) with min, max, new, new_unchecked;
}

impl NodeId {
    /// The row-table index this id names.
    #[inline]
    pub(crate) const fn index(self) -> usize {
        crate::admission::usize_of(self.as_inner())
    }
}

/// Admits a source length into the coordinate class; `None` iff it
/// exceeds `i32::MAX` bytes.
#[inline]
pub(crate) const fn admit(len: usize) -> Option<u32> {
    if len > crate::admission::MAX {
        return None;
    }
    Some(crate::admission::admitted_u32(len))
}

/// A parse-produced row count or row index back in the coordinate
/// class: every row spends at least one admitted byte, so row
/// counts stay within the admission bound.
#[inline]
pub(crate) const fn row_u32(count: usize) -> u32 {
    crate::admission::admitted_u32(count)
}

/// Mints the id of a parse-produced row index (in class by the
/// admission-derived row-count bound; see [`NodeId`]).
pub(crate) const fn mint(index: u32) -> NodeId {
    debug_assert!(index <= NodeId::MAX.as_inner());
    // SAFETY: every row spends at least one input byte and admission
    // caps the input, so parse-produced indices stay in class.
    unsafe { NodeId::new_unchecked(index) }
}

/// Row-table reserve derived from the input length: field-dense
/// traffic runs a couple dozen bytes per record, so an eighth of
/// the input length covers such tables in one allocation while
/// keeping the transient overshoot proportionate. The cap bounds
/// the seed, and the finished product shrinks to fit (the borrowed
/// inspector's reserve policy — this parse is the same engine
/// over an owned source).
pub(crate) const fn rows_reserve(len: u32) -> usize {
    const CAP: usize = 1 << 16;
    let eighth = crate::admission::usize_of(len / 8);
    if eighth < CAP { eighth } else { CAP }
}

/// Frame-stack reserve: the caller's bound when tight, a shallow
/// floor otherwise (deeper nesting grows on demand).
pub(crate) fn frames_reserve(limit: DepthLimit) -> usize {
    usize::from(limit.as_inner()).min(16)
}

/// The caller's per-LEN interpretation pole, supplied from schema
/// knowledge.
///
/// Not a performance hint: [`Commit`](Self::Commit) and
/// [`Opaque`](Self::Opaque) are caller contracts, and supplying them
/// changes fault ownership, never how any byte is judged.
#[must_use = "the advice decides how the LEN payload is interpreted"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Advice {
    /// Try-parse: a message attempt where any internal fault
    /// silently concludes "bytes" — the machine takes the risk, so
    /// no fault leaks. The pole for zero schema knowledge.
    Speculate,
    /// Committed message. Inside a committed chain from the root
    /// the promise is absolute and faults inside are real; under a
    /// speculating ancestor it is conditional — the ancestor may
    /// itself be bytes — and faults unwind that ancestor instead.
    Commit,
    /// Committed opaque bytes: the payload is never parsed, so no
    /// fault can exist inside it.
    Opaque,
}

/// The field path of the containers enclosing the advised site.
///
/// Root → leaf, excluding the field being advised on (that field
/// is the query's second argument). A borrowed view lent for one
/// `advise` call: the machine keeps the underlying path current
/// only while the advisor runs.
#[derive(Clone, Copy, Debug)]
pub struct Ancestry<'p> {
    path: &'p [FieldNumber],
}

impl<'p> Ancestry<'p> {
    /// Crate-internal: dialect machines lend their path stacks.
    pub(crate) const fn new(path: &'p [FieldNumber]) -> Self {
        Self { path }
    }

    /// Number of enclosing containers.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.path.len()
    }

    /// True at root level.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.path.is_empty()
    }

    /// The enclosing fields, outermost first.
    #[inline]
    pub fn fields(&self) -> impl DoubleEndedIterator<Item = FieldNumber> + ExactSizeIterator + '_ {
        self.path.iter().copied()
    }
}

/// Partial-schema supply, consulted at every LEN record head (empty
/// payloads included: an empty `Message` still declares one nesting
/// level and counts against the caller's depth bound).
///
/// The parser does not promise call count or order: sites inside
/// speculation are consulted and may later unwind, and unwinding
/// does not undo advisor state. Implementations must answer as a
/// pure function of `(ancestry, field)`.
pub trait Advisor {
    /// The caller's knowledge about the LEN payload at
    /// `ancestry` / `field`.
    fn advise(&mut self, ancestry: Ancestry<'_>, field: FieldNumber) -> Advice;
}

/// Zero schema, spelled explicitly at call sites: every LEN payload
/// speculates.
#[derive(Clone, Copy, Default, Debug)]
pub struct NoAdvice;

impl Advisor for NoAdvice {
    #[inline]
    fn advise(&mut self, _ancestry: Ancestry<'_>, _field: FieldNumber) -> Advice {
        Advice::Speculate
    }
}

#[cfg(feature = "retain-grouped")]
pub mod grouped;
#[cfg(feature = "retain-groupless")]
pub mod groupless;
