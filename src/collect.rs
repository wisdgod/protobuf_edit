//! Stream-collect schema-less inspection: chunks parsed as they
//! arrive into one owned source (read · stream · offline · owned),
//! per wire dialect.
//!
//! The stream-arrival twin of the buffered owned inspector
//! (feature `retain-*`): the document arrives in chunks, each
//! `feed` copies its chunk into the growing owned source and
//! parses it in the same source-level pass, and the consuming
//! `finish` seals the accumulated bytes and the finished preorder
//! row table into the standing queryable product — the same index
//! and query contract the buffered cell mints, over a source that
//! was never whole in the caller's hands. As source-level traffic:
//! collecting into a `Vec` first and then parsing reads the parsed
//! bytes twice — once to copy, once to parse; the fused feed
//! examines each byte once, at the moment it copies it, so the
//! saving is exactly that post-collection read — near the whole
//! input for parse-dense documents whose LEN interiors are
//! selected, and correspondingly small for opaque-heavy documents.
//!
//! `finish` is total and seal-only: end-of-stream judgments
//! (truncated words, short fixed payloads, unclosed root groups,
//! an underfilled root-level LEN) become the product's fault —
//! never an error — and no source byte is read again at the seal.
//! Wire faults met mid-stream are product data for the same
//! reason: a fault clips the index, and every later successful
//! feed is still absorbed whole into the source, so the finished
//! product owns the complete supplied stream beside its fault.
//! The one structured feed refusal is [`FeedOversize`] — the
//! stream would leave the `i32::MAX` input cap — judged before any
//! byte of the refused chunk is read.
//!
//! Dialects are sibling modules, not parameters: `grouped` walks
//! groups structurally; `groupless` refuses group codes as a
//! capability judgment. This shared layer holds only
//! dialect-orthogonal vocabulary: the node handle, the
//! schema-supply face, and the feed refusals. Dialect-sensitive
//! vocabulary (kinds, faults, products, collectors) stays per
//! dialect, unshared.
//!
//! The [`i32::MAX` input cap](crate::Span): feed admission bounds
//! the accumulated source at `i32::MAX` bytes — the LEN length
//! class top and the reference reader's single-message hard bound —
//! so every stored or computed coordinate lives in `0..=i32::MAX`
//! and any two coordinates add without overflowing `u32`.
//! A refused feed returns the accumulated source intact beside
//! the mark and spends the collector; the caller's chunk was
//! never read.
//!
//! Allocation policy: the growing source, the row arena, and the
//! working stacks grow through the standard infallible `Vec` paths
//! (panic or abort on allocator refusal); everything a collector
//! holds is the in-flight product of one collection job, so an
//! abort's loss ends with that job. Wire violations are never
//! resource errors — they stay in the product as its fault.
//!
//! Coordinates: read · stream · offline · Standard (value-level) · owned.
//!
//! # Choosing a face
//!
//! One entry chain per dialect: `Collector::new` — the acceptance
//! [`Standard`](crate::Standard), a depth bound, an advisor —
//! then `feed` per chunk and the consuming `finish` for the
//! product (`with_capacity` pins one exact source allocation when
//! the total is known). `finish` never fails; `feed`'s one error
//! is the input cap. `Collector::into_source` abandons a
//! live job and releases the accumulated bytes — a construct cut
//! mid-word needs no reconstruction, its bytes already live in the
//! backing.
//!
//! The advisor argument is the schema dial, exactly the buffered
//! inspectors': [`NoAdvice`] spells zero knowledge (every LEN
//! payload speculates); implement [`Advisor`] to pin the sites you
//! know — [`Advice::Commit`], [`Advice::Opaque`], or
//! [`Advice::Speculate`] per (ancestry, field). Answers must be a
//! pure function of `(ancestry, field)`: the collector may consult
//! a site while parsing ahead of stream proof, so call count and
//! order are not a contract.
//!
//! Elsewhere: a source already buffered wants the buffered owned
//! inspector (feature `retain-*`) — its one-shot parse carries no
//! per-chunk state; chunked verdicts without a standing index →
//! `scan`; a chunked document you intend to *edit* → the
//! stream-ingest editors (features `stream-adopt-*`,
//! `stream-draft-*`).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "collect-groupless")] {
//! use protobuf_edit::collect::NoAdvice;
//! use protobuf_edit::collect::groupless::Collector;
//! use protobuf_edit::{DepthLimit, Standard};
//!
//! // varint f1=150 · LEN f2 "hi", arriving in chunks that cut the
//! // first value: chunk edges never show in the product.
//! let mut advice = NoAdvice;
//! let mut collector =
//!     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
//! collector.feed(&[0x08, 0x96]).unwrap();
//! collector.feed(&[0x01, 0x12, 0x02, 0x68, 0x69]).unwrap();
//!
//! let tree = collector.finish();
//! assert!(tree.is_complete());
//! let first = tree.top().next().unwrap();
//! assert_eq!(tree.varint_word(first), Some(150));
//! # }
//! ```
//!
//! # Recipes
//!
//! The finished product is `Send + Sync` — collection hands off to
//! another thread whole, index and source together, zero copies
//! (features: `collect-groupless`):
//!
//! ```
//! # #[cfg(feature = "collect-groupless")] {
//! use protobuf_edit::collect::NoAdvice;
//! use protobuf_edit::collect::groupless::Collector;
//! use protobuf_edit::{DepthLimit, Standard};
//!
//! let mut advice = NoAdvice;
//! let mut collector =
//!     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
//! for chunk in [0x08, 0x2A, 0x12, 0x02, 0x68, 0x69].chunks(3) {
//!     collector.feed(chunk).unwrap();
//! }
//! let tree = collector.finish();
//! let answer = std::thread::spawn(move || {
//!     let id = tree.top().nth(1).unwrap();
//!     tree.payload_bytes(id).to_vec()
//! })
//! .join()
//! .unwrap();
//! assert_eq!(answer, [0x68, 0x69]);
//! # }
//! ```

use alloc::vec::Vec;

use crate::{DepthLimit, FieldNumber};
pub use crate::Stage;

crate::_macro::define_valid_range_type! {
    /// An index into one collected parse product.
    ///
    /// Distinct from offsets and counts at the type level. Handles
    /// are slice-like: out-of-range use panics; a stale handle from
    /// another product that happens to be in range reads that
    /// product's answer — memory-safe, semantically the caller's
    /// fault.
    ///
    /// The class is admission-derived: every row spends at least its
    /// head tag byte and feed admission caps the stream at
    /// `i32::MAX` bytes, so row indices stay in class and
    /// `Option<NodeId>` is free (the parent link needs no sentinel).
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
    // SAFETY: every row spends at least one input byte and feed
    // admission caps the stream, so parse-produced indices stay in
    // class.
    unsafe { NodeId::new_unchecked(index) }
}

/// Row-table reserve derived from the stream length seen so far:
/// field-dense traffic runs a couple dozen bytes per record, so an
/// eighth of the length covers such tables in one allocation while
/// keeping the transient overshoot proportionate. The cap bounds
/// the seed, and the finished product shrinks to fit (the buffered
/// owned inspector's policy — this collection builds the same rows
/// over the same coordinate class).
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
/// The collector does not promise call count or order: sites inside
/// speculation are consulted and may later unwind, a site may be
/// consulted while the stream has yet to prove its enclosing
/// extent, and unwinding does not undo advisor state.
/// Implementations must answer as a pure function of
/// `(ancestry, field)` — this is exactly what keeps the finished
/// index independent of how the stream was chunked.
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

/// The one feed refusal: the chunk would run the accumulated
/// source past the [`i32::MAX` input cap](crate::Span).
///
/// Judged before any byte of the refused chunk is read, so custody
/// is exact: the error owns all previously successful feeds —
/// [`into_source`](Self::into_source) releases them — and the
/// caller still owns the refused chunk; appending it to the
/// released bytes reconstructs the offered stream exactly. The
/// collector is spent once this is returned.
#[must_use]
pub struct FeedOversize {
    source: Vec<u8>,
    attempted_end: u64,
}

impl FeedOversize {
    /// Crate-internal: the dialect feed doors mint the refusal.
    pub(crate) const fn new(source: Vec<u8>, attempted_end: u64) -> Self {
        Self { source, attempted_end }
    }

    /// The accumulated source: every previously successful feed,
    /// none of the refused chunk.
    #[inline]
    #[must_use]
    pub fn source(&self) -> &[u8] {
        &self.source
    }

    /// Where the refused stream would have ended (accumulated
    /// length plus the refused chunk's).
    #[inline]
    #[must_use]
    pub const fn attempted_end(&self) -> u64 {
        self.attempted_end
    }

    /// Releases the accumulated source — a move, zero copies.
    #[inline]
    #[must_use]
    pub fn into_source(self) -> Vec<u8> {
        self.source
    }
}

impl core::fmt::Debug for FeedOversize {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FeedOversize")
            .field("attempted_end", &self.attempted_end)
            .field("source_len", &self.source.len())
            .finish()
    }
}

impl core::fmt::Display for FeedOversize {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "stream end {} exceeds the coordinate class", self.attempted_end)
    }
}

impl core::error::Error for FeedOversize {}

/// The one construction refusal: a source capacity hint beyond the
/// [`i32::MAX` input cap](crate::Span) — no lawful stream can fill
/// such a reservation, so it refuses before allocating.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapacityOversize {
    requested: u64,
}

impl CapacityOversize {
    /// Crate-internal: the dialect capacity doors mint the refusal.
    pub(crate) const fn new(requested: u64) -> Self {
        Self { requested }
    }

    /// The refused capacity hint.
    #[inline]
    #[must_use]
    pub const fn requested(&self) -> u64 {
        self.requested
    }
}

impl core::fmt::Display for CapacityOversize {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "capacity of {} bytes exceeds the coordinate class", self.requested)
    }
}

impl core::error::Error for CapacityOversize {}

#[cfg(feature = "collect-grouped")]
pub mod grouped;
#[cfg(feature = "collect-groupless")]
pub mod groupless;
