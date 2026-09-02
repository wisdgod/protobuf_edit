//! The groupless stream collector: group codes are a capability
//! refusal.
//!
//! Chunks arrive through [`Collector::feed`]; each feed admits the
//! whole chunk against the coordinate class before reading a byte,
//! reserves room for it, then examines each deciding byte once, as
//! source-level traffic — one append into the reserved final
//! backing and one fold into the bankless word carry per byte —
//! while opaque payloads, fixed tails, skipped speculation
//! remainders, and post-fault suffixes append in bulk. Rows publish exactly as the buffered
//! owned inspector publishes them: full depth, advisor-driven —
//! opaque leaves, speculative descent with absorber demotion,
//! committed descent — so the consuming [`Collector::finish`]
//! seals the accumulated source and the finished preorder rows
//! into the same product one buffered parse would have built over
//! the concatenated bytes. No byte is read again at the seal.
//!
//! A stream does not know its end until `finish`, and that changes
//! exactly one judgment: a LEN record met at the root layer cannot
//! be checked against the document end the way the buffered parse
//! checks it first of all. The collector holds one open root-layer
//! LEN transaction — an O(1) checkpoint of the row, stack, and
//! path marks taken before advice or row publication. While the
//! declared endpoint is unproven, parsing continues normally
//! inside the declared extent; an unabsorbed fault met there is
//! *deferred* (the clip that would normally run is delayed, and
//! later bytes copy without parsing) because the buffered parse
//! would never have reached it if the stream ends short. When
//! bytes arrive through the declared endpoint the extent is
//! proven: the checkpoint is discarded and a deferred fault
//! commits with its ordinary clip. When `finish` arrives first,
//! the checkpoint restores — speculative rows truncate, registers
//! restore — and the product carries the outer `LenOverrun` with
//! the exact bytes the stream actually left, precisely the
//! buffered verdict. A declared endpoint past the coordinate class
//! can never be filled by an admissible stream, so it enters
//! copy-only collection at once, consulting nothing. At most one
//! such transaction can be open: entering the LEN seals a finite
//! extent for everything inside it, so a second root-layer LEN
//! only exists after the first resolves.
//!
//! Custody is transactional at the feed: a wire fault met
//! mid-chunk clips the index and still absorbs the whole chunk —
//! the fault is product data, and every later successful feed
//! keeps absorbing, so the finished product owns the complete
//! supplied stream beside its fault (buffered parity: an owned
//! parse holds the whole buffer even when its index stops early).
//! The only feed error is the pre-read coordinate refusal
//! ([`FeedOversize`]), which returns every previously absorbed
//! byte and spends the collector; the refused chunk was never
//! read. Speculation unwinds across chunk edges without re-reading
//! a byte: truncation back to the absorber row, register
//! restoration, and an in-feed skip to the absorber's endpoint.
//!
//! This dialect speaks the four-code wire language: a group code
//! (3 or 4) is well-formed wire *outside this language* — refusing
//! it is this dialect's correctness feature, typed distinctly from
//! the format's unassigned codes.
//!
//! Coordinates: read · stream · offline · groupless · Standard (value-level) · owned.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::collect::NoAdvice;
//! use protobuf_edit::collect::groupless::Collector;
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! // varint f1=150 · LEN f2 "hi", fed byte by byte: chunk edges
//! // never show in the product.
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut advice = NoAdvice;
//! let mut collector =
//!     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
//! for byte in msg {
//!     collector.feed(&[byte]).unwrap();
//! }
//! let tree = collector.finish();
//! assert!(tree.is_complete());
//!
//! let field2 = FieldNumber::new(2).unwrap();
//! let hits: Vec<_> = tree.top().by_field(field2).collect();
//! assert_eq!(hits.len(), 1);
//! assert_eq!(tree.payload_bytes(hits[0]), [0x68, 0x69]);
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::iter::FusedIterator;
use core::num::NonZeroU8;

use super::{
    Advice, Advisor, Ancestry, CapacityOversize, FeedOversize, NodeId, Stage, frames_reserve, mint,
    row_u32, rows_reserve,
};
use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::varint::slice::ReadFault;
use crate::varint::{
    CONT_BIT, PAYLOAD_BITS, PAYLOAD_MASK, StepWidth, ValueWidth, WordWidth, encoded_len32,
    encoded_len64,
};
use crate::wire::groupless::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, FaultClass, Span, Standard};
// ─── the law ───

/// One law violation: where, and which law.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u32,
    kind: FaultKind,
}

impl Fault {
    /// First byte of the offending wire construct.
    #[inline]
    #[must_use]
    pub const fn at(self) -> u32 {
        self.at
    }

    /// The violated law.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> FaultKind {
        self.kind
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.at)
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.kind)
    }
}

/// The refusal classes, sectioned by [`FaultClass`] (grammar
/// sites, then policy, then capability); [`class`](Self::class)
/// answers the section.
///
/// Wire-declared quantities are quoted as their wire types; a bad
/// record never reaches the row table, so its field number travels
/// with the fault — inside the [`Stage`] coordinate for varint
/// reads (the tag stage carries none: no field exists yet), on the
/// variant elsewhere. Group grammar variants do not exist in this
/// dialect's vocabulary — not unreachable, absent. End-of-stream
/// truncations are judged at `finish` and quote the same
/// vocabulary a buffered parse quotes at its extent end.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    // ─ grammar: varint sites ─
    /// A varint construct refused at one of the record's stages
    /// (tag: five-byte window, u32 word class; length prefix:
    /// five-byte window, 2^31 − 1 length class; value: ten-byte
    /// window, u64 class).
    Read {
        /// The construct the read was serving.
        stage: Stage,
        /// The kernel's refusal.
        cause: ReadFault,
    },
    /// A tag decoded to field number zero.
    FieldZero {
        /// The code bits the zero-field tag carried.
        code: Low3,
    },
    /// A tag carried a code unassigned by the format (6 or 7).
    Unassigned {
        /// The tag's field number (judged before the code).
        field: FieldNumber,
        /// The unassigned code.
        code: Low3,
    },
    /// A declared length punctures the enclosing seal — for a
    /// root-layer record, the seal the stream's end declared.
    LenOverrun {
        /// The record's field number.
        field: FieldNumber,
        /// The declared payload length.
        declared: PayloadLen,
        /// Bytes actually left in the enclosing extent.
        zone_left: u32,
    },
    // ─ grammar: fixed value site ─
    /// The extent ended inside a fixed-width payload.
    FixedTruncated {
        /// The record's field number.
        field: FieldNumber,
        /// The width the kind requires (4 or 8).
        needed: u8,
    },
    // ─ policy: the caller's bound and the declared standard ─
    /// Opening this container would exceed the caller's declared
    /// [`DepthLimit`]. `Advice::Speculate` sites demote to opaque
    /// instead; this fault is for `Advice::Commit` claims.
    DepthExceeded {
        /// The container's field number.
        field: FieldNumber,
        /// The bound that refused.
        limit: DepthLimit,
    },
    /// A tag wider than minimal ([`Standard::CanonicalMinimal`]
    /// collections only; speculation absorbs it like any wire
    /// fault).
    NonMinimalTag,
    /// A length prefix wider than minimal (canonical collections
    /// only).
    NonMinimalLen {
        /// The record's field number.
        field: FieldNumber,
    },
    /// A value varint wider than minimal (canonical collections
    /// only).
    NonMinimalValue {
        /// The record's field number.
        field: FieldNumber,
    },
    // ─ capability: the dialect boundary ─
    /// A tag carried a group code (3 or 4): well-formed wire
    /// outside this dialect's language — the capability refusal.
    GroupCode {
        /// The tag's field number.
        field: FieldNumber,
        /// The group code (3 or 4).
        code: Low3,
    },
}

impl FaultKind {
    /// The refusal's [`FaultClass`] — which repair the fault asks
    /// for. Policy membership names its configuration datum on the
    /// variant (the [`DepthLimit`] bound; the `NonMinimal*` family
    /// is the collection's declared [`Standard`]).
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Read { .. }
            | Self::FieldZero { .. }
            | Self::Unassigned { .. }
            | Self::LenOverrun { .. }
            | Self::FixedTruncated { .. } => FaultClass::Grammar,
            Self::DepthExceeded { .. }
            | Self::NonMinimalTag
            | Self::NonMinimalLen { .. }
            | Self::NonMinimalValue { .. } => FaultClass::Policy,
            Self::GroupCode { .. } => FaultClass::Capability,
        }
    }
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Read { stage, cause } => {
                let (window, class) = match stage {
                    Stage::Tag => {
                        f.write_str("tag")?;
                        ("five", "u32 word class")
                    }
                    Stage::LenPrefix { field } => {
                        write!(f, "length prefix of field {}", field.as_inner())?;
                        ("five", "length class")
                    }
                    Stage::Value { field } => {
                        write!(f, "varint value of field {}", field.as_inner())?;
                        ("ten", "u64 class")
                    }
                };
                match cause {
                    ReadFault::Truncated => f.write_str(" truncated by its extent"),
                    ReadFault::TooWide => {
                        write!(f, " continues past the {window}-byte window")
                    }
                    ReadFault::OutOfClass => write!(f, " exceeds the {class}"),
                }
            }
            Self::FieldZero { code } => {
                write!(f, "tag names field zero (code {})", code.as_inner())
            }
            Self::Unassigned { field, code } => {
                write!(f, "field {} carries unassigned code {}", field.as_inner(), code.as_inner())
            }
            Self::LenOverrun { field, declared, zone_left } => write!(
                f,
                "field {} declares {} payload bytes but its extent holds {zone_left}",
                field.as_inner(),
                declared.as_inner()
            ),
            Self::FixedTruncated { field, needed } => write!(
                f,
                "field {} needs {needed} fixed payload bytes past its extent",
                field.as_inner()
            ),
            Self::DepthExceeded { field, limit } => write!(
                f,
                "container of field {} nests beyond the bound of {}",
                field.as_inner(),
                limit.as_inner()
            ),
            Self::NonMinimalTag => f.write_str("tag is wider than its minimal encoding"),
            Self::NonMinimalLen { field } => write!(
                f,
                "length prefix of field {} is wider than its minimal encoding",
                field.as_inner()
            ),
            Self::NonMinimalValue { field } => write!(
                f,
                "varint value of field {} is wider than its minimal encoding",
                field.as_inner()
            ),
            Self::GroupCode { field, code } => write!(
                f,
                "field {} carries group code {}: outside the groupless language",
                field.as_inner(),
                code.as_inner()
            ),
        }
    }
}

impl core::error::Error for FaultKind {}

// ─── the rows ───

/// One record, packed to 24 bytes. Private: the product projects
/// it.
///
/// Partition theorem: a record's bytes are `tag ⊎ delim ⊎ payload`;
/// in this dialect the delimiter has one meaning — LEN's length
/// prefix, preceding the payload (the group end tag left with the
/// language) — and scalars carry `None`. Both the record span and
/// the payload span are one branch-free formula. Widths are stored
/// input facts: padding is accepted and span arithmetic must
/// reproduce it byte-exactly.
/// Declaration order fixes the memory order: the coordinate columns
/// tie with the parent link on niche size, so the stable field sort
/// keeps them exactly here.
#[derive(Clone, Copy)]
struct Row {
    /// Payload extent. LEN: declared; Varint: the value's encoded
    /// width; I32/I64: 4/8. All in the coordinate class.
    payload_len: Extent,
    /// Enclosing container (`None`: root level — the niche is the
    /// sentinel, typed).
    parent: Option<NodeId>,
    /// Head tag's first byte.
    start: Coord,
    /// Rows in this row's subtree, excluding itself. Preorder
    /// contiguity: the subtree is exactly the next `descendants`
    /// rows; the next sibling is `i + 1 + descendants`.
    descendants: u32,
    /// The head tag's field number.
    field: FieldNumber,
    /// The record kind (the dialect table's vocabulary, verbatim).
    kind: RecordKind,
    /// The head tag's actual input width.
    tag_width: WordWidth,
    /// LEN: the length prefix's actual width. Scalars: `None` —
    /// in this dialect `kind == Len ⟺ delim_width.is_some()`.
    delim_width: Option<WordWidth>,
}

const _: () = assert!(core::mem::size_of::<Row>() == 24);
const _: () = assert!(core::mem::size_of::<Fault>() == 20);

impl Row {
    /// Widths as coordinate-class integers.
    fn tag_w(&self) -> u32 {
        u32::from(self.tag_width.as_inner())
    }

    fn delim_w(&self) -> u32 {
        self.delim_width.map_or(0, |w| u32::from(w.as_inner()))
    }

    /// The whole-record span (head tag through the record's last
    /// byte): every segment sits in wire order, one formula.
    fn span(&self) -> Span {
        // SAFETY: the partition theorem — the record's segments tile
        // its span inside the admitted source, so the width sum is
        // in class.
        let width = unsafe {
            Extent::new_unchecked(self.tag_w() + self.delim_w() + self.payload_len.as_inner())
        };
        Span::of(self.start, width)
    }

    /// The payload span. Branch-free: the delimiter always precedes
    /// the payload in this dialect (scalars store zero), so no kind
    /// dispatch exists.
    fn payload_span(&self) -> Span {
        let start = self.start.as_inner() + self.tag_w() + self.delim_w();
        // SAFETY: the partition theorem — the payload starts inside
        // the record's span, which lies in the admitted source.
        Span::of(unsafe { Coord::new_unchecked(start) }, self.payload_len)
    }
}

// ─── the product ───

/// Where a record's bytes lie in the source, split by role.
///
/// One call, kind-indexed: segments that do not exist for the record's
/// kind do not exist in the type (no group variants in this
/// dialect), and each variant's segments partition the record's
/// span exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordSpans {
    /// A varint record: head tag, value bytes.
    Varint {
        /// The head tag.
        tag: Span,
        /// The value bytes.
        value: Span,
    },
    /// A fixed 64-bit record: head tag, eight value bytes.
    I64 {
        /// The head tag.
        tag: Span,
        /// The value bytes.
        value: Span,
    },
    /// A LEN record: head tag, length prefix, payload.
    Len {
        /// The head tag.
        tag: Span,
        /// The length prefix.
        prefix: Span,
        /// The payload bytes.
        payload: Span,
    },
    /// A fixed 32-bit record: head tag, four value bytes.
    I32 {
        /// The head tag.
        tag: Span,
        /// The value bytes.
        value: Span,
    },
}

/// The finished collection: the accumulated source and a preorder
/// row table over it, plus at most one fault — self-contained,
/// `Send + Sync` (an immutable owned index), movable and cacheable
/// for free.
///
/// A faulted product is not an error case — it is the legal
/// prefix, open containers clipped to the fault boundary, the
/// complete collected source, and the fault. The type is its own
/// provenance proof: `source` and `rows` are private, minted
/// together by the one collection, and immutable for the product's
/// life — the unsafe discharges in the value queries cite exactly
/// this invariant. Rows hold `u32` coordinates, never pointers, so
/// moving the product moves nothing but the two owners.
///
/// The only constructor is the consuming [`Collector::finish`]:
/// this cell's input presence is the stream, so no buffered parse
/// door exists on this type (the buffered cell is feature
/// `retain-groupless`).
///
/// Node ids are plain indices in parse order, slice-style: passing
/// an id at or beyond [`node_count`](Self::node_count) panics.
/// `Option` returns carry domain answers, never id validation.
pub struct Retained {
    source: Vec<u8>,
    rows: Box<[Row]>,
    /// End of the indexed prefix (clipped LEN rows keep their
    /// declared, sealed spans, which may extend past it).
    indexed_end: u32,
    fault: Option<Fault>,
}

impl Retained {
    /// The fault, if the committed zone stopped the collection's
    /// index early (the source still holds every absorbed byte).
    #[inline]
    #[must_use]
    pub const fn fault(&self) -> Option<Fault> {
        self.fault
    }

    /// True when the whole stream parsed without a fault.
    #[inline]
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.fault.is_none()
    }

    /// The owned source bytes; all spans index into these.
    #[inline]
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.source
    }

    /// Releases the source buffer — every absorbed byte, zero
    /// copies. The index is dropped; spans and ids taken earlier
    /// remain plain numbers over the returned bytes.
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.source
    }

    /// End of the indexed prefix (equals the source length iff the
    /// collection consumed everything).
    #[inline]
    #[must_use]
    pub const fn indexed_end(&self) -> u32 {
        self.indexed_end
    }

    /// Number of rows; valid ids are `0..node_count`.
    #[inline]
    #[must_use]
    pub const fn node_count(&self) -> u32 {
        row_u32(self.rows.len())
    }

    /// True when no records were indexed.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The public id gate: every id-taking query passes here, and
    /// the slice index is the documented forgery panic.
    #[track_caller]
    fn row(&self, id: NodeId) -> &Row {
        &self.rows[id.index()]
    }

    /// The row of an internally proven id.
    ///
    /// # Safety
    /// `id` must be in-table: minted by this collection (row
    /// pushes, partition points) or read out of a row's parent
    /// link.
    unsafe fn row_unchecked(&self, id: NodeId) -> &Row {
        // SAFETY: the caller's proof, restated.
        unsafe { self.rows.get_unchecked(id.index()) }
    }

    // ─ navigation ─

    /// Iterates the top-layer records.
    #[inline]
    pub fn top(&self) -> Children<'_> {
        Children { rows: &self.rows, next: 0, end: self.node_count() }
    }

    /// Iterates `id`'s direct children (empty for leaves and
    /// unparsed payloads).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[track_caller]
    pub fn children(&self, id: NodeId) -> Children<'_> {
        let r = self.row(id);
        let first = id.as_inner() + 1;
        Children { rows: &self.rows, next: first, end: first + r.descendants }
    }

    /// The enclosing container (`None`: root level).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.row(id).parent
    }

    /// Walks the parent chain from `id` (exclusive) to a root.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[track_caller]
    pub fn ancestors(&self, id: NodeId) -> Ancestors<'_> {
        Ancestors { rows: &self.rows, cur: self.row(id).parent }
    }

    /// The record's field number.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[track_caller]
    pub fn field(&self, id: NodeId) -> FieldNumber {
        self.row(id).field
    }

    /// The record's wire kind.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn kind(&self, id: NodeId) -> RecordKind {
        self.row(id).kind
    }

    /// Iterates all records in parse (preorder) order.
    #[inline]
    pub const fn nodes(&self) -> Nodes<'_> {
        Nodes { next: 0, end: self.node_count(), _rows: core::marker::PhantomData }
    }

    /// Iterates `id`'s whole subtree, excluding `id` itself.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[track_caller]
    pub fn descendants(&self, id: NodeId) -> Nodes<'_> {
        let r = self.row(id);
        let first = id.as_inner() + 1;
        Nodes { next: first, end: first + r.descendants, _rows: core::marker::PhantomData }
    }

    /// The narrowest record whose span contains `pos` (`None`: the
    /// byte belongs to no indexed record).
    ///
    /// Preorder starts increase strictly, record spans nest or are
    /// disjoint (seals forbid partial overlap): binary search for
    /// the last start at or before `pos`, then walk the parent
    /// chain to the first containing span.
    #[inline]
    #[must_use]
    pub fn narrowest(&self, pos: u32) -> Option<NodeId> {
        let started_before = self.rows.partition_point(|r| r.start.as_inner() <= pos);
        let mut cur = mint(row_u32(started_before.checked_sub(1)?));
        loop {
            // SAFETY: the first id is minted from a nonzero
            // partition point over the table; every later id is a
            // row's parent link, minted in-table by the collection.
            let r = unsafe { self.row_unchecked(cur) };
            if pos < r.span().end() {
                return Some(cur);
            }
            cur = r.parent?;
        }
    }

    // ─ spans ─

    /// The whole-record span (head tag through the record's last
    /// byte). Every segment sits in wire order — one formula, no
    /// commutation. A clipped LEN keeps its declared, sealed span.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[track_caller]
    pub fn span(&self, id: NodeId) -> Span {
        self.row(id).span()
    }

    /// The record's geometry: every segment in one kind-indexed
    /// answer. Widths are the stored input facts (padded encodings
    /// reproduce byte-exactly).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::collect::NoAdvice;
    /// use protobuf_edit::collect::groupless::{Collector, RecordSpans};
    /// use protobuf_edit::{DepthLimit, Standard};
    ///
    /// // LEN f2 "hi": tag, length prefix, payload — in wire order.
    /// let mut advice = NoAdvice;
    /// let mut collector =
    ///     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    /// collector.feed(&[0x12, 0x02, 0x68, 0x69]).unwrap();
    /// let tree = collector.finish();
    /// let id = tree.top().next().unwrap();
    /// let RecordSpans::Len { tag, prefix, payload } = tree.source_spans(id) else {
    ///     unreachable!()
    /// };
    /// assert_eq!((tag.start(), tag.end()), (0, 1));
    /// assert_eq!((prefix.start(), prefix.end()), (1, 2));
    /// assert_eq!((payload.start(), payload.end()), (2, 4));
    /// ```
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn source_spans(&self, id: NodeId) -> RecordSpans {
        let r = self.row(id);
        // SAFETY (all mints below): the partition theorem — the
        // record's segments tile its span inside the admitted
        // source, so every segment bound is in class.
        let tag = Span::of(r.start, Extent::from_width(r.tag_width.as_inner()));
        let payload = r.payload_len;
        match r.kind {
            RecordKind::Varint => RecordSpans::Varint {
                tag,
                value: Span::of(unsafe { Coord::new_unchecked(tag.end()) }, payload),
            },
            RecordKind::I64 => RecordSpans::I64 {
                tag,
                value: Span::of(unsafe { Coord::new_unchecked(tag.end()) }, payload),
            },
            RecordKind::Len => {
                let prefix = Span::of(
                    unsafe { Coord::new_unchecked(tag.end()) },
                    // The prefix width is a stored input fact; a LEN
                    // always met one.
                    Extent::from_width(r.delim_width.map_or(0, WordWidth::as_inner)),
                );
                RecordSpans::Len {
                    tag,
                    prefix,
                    payload: Span::of(unsafe { Coord::new_unchecked(prefix.end()) }, payload),
                }
            }
            RecordKind::I32 => RecordSpans::I32 {
                tag,
                value: Span::of(unsafe { Coord::new_unchecked(tag.end()) }, payload),
            },
        }
    }

    // ─ bytes and words ─

    /// The record's bytes (borrows the product's own source).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn record_bytes(&self, id: NodeId) -> &[u8] {
        let span = self.row(id).span();
        // SAFETY: the product invariant — rows were minted by the
        // collection over these same admitted, immutable bytes, and
        // record spans lie within them.
        unsafe { self.source.get_unchecked(span.as_range()) }
    }

    /// Designates the record for cross-machine transfer: the exact
    /// record bytes bound to their proved field, kind, and framing
    /// geometry (borrows the product's own source, so a consumer
    /// retaining the designation cannot outlive this product).
    /// Completeness is part of the designation's contract, so only
    /// records whose whole extent lies inside the indexed prefix
    /// mint; the canonical proof is not carried — a consumer that
    /// needs it asks `try_canonical` on the designation itself.
    ///
    /// # Errors
    ///
    /// [`Fault::IncompleteRecord`](crate::source::groupless::Fault::IncompleteRecord)
    /// when the record's extent runs past the indexed prefix (a
    /// clipped row at the fault boundary).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::collect::NoAdvice;
    /// use protobuf_edit::collect::groupless::Collector;
    /// use protobuf_edit::{DepthLimit, Standard};
    ///
    /// let mut advice = NoAdvice;
    /// let mut collector =
    ///     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    /// collector.feed(&[0x08, 0x96, 0x01]).unwrap();
    /// let tree = collector.finish();
    /// let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
    /// assert_eq!(record.as_bytes(), [0x08, 0x96, 0x01]);
    /// ```
    #[track_caller]
    pub fn record_ref(
        &self,
        id: NodeId,
    ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault> {
        let r = self.row(id);
        if r.span().end() > self.indexed_end {
            return Err(crate::source::groupless::Fault::IncompleteRecord { at: self.indexed_end });
        }
        Ok(crate::source::groupless::RecordRef::mint(
            self.record_bytes(id),
            r.field,
            r.kind,
            r.tag_width,
            r.delim_width,
            r.payload_len.as_inner(),
            false,
        ))
    }

    /// The payload bytes (borrows the product's own source).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn payload_bytes(&self, id: NodeId) -> &[u8] {
        let span = self.row(id).payload_span();
        // SAFETY: as `record_bytes` — payload spans are sub-spans of
        // record spans.
        unsafe { self.source.get_unchecked(span.as_range()) }
    }

    /// The varint value as a raw wire word (`None`: not a VARINT
    /// record), tolerant of the source's padding. `crate::scalar`
    /// maps wire words to schema-typed values.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn varint_word(&self, id: NodeId) -> Option<u64> {
        let r = self.row(id);
        if !matches!(r.kind, RecordKind::Varint) {
            return None;
        }
        let at = r.start.as_inner() + r.tag_w();
        // SAFETY: the product invariant — a Varint row's payload is
        // the window a bounded in-class read admitted during the
        // collection, over these same immutable bytes.
        Some(unsafe { crate::varint::slice::value64_unchecked(&self.source, usize_of(at)) })
    }

    /// The eight little-endian payload bytes as raw bits (`None`:
    /// not an I64 record). `crate::scalar` interprets them.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn i64_bits(&self, id: NodeId) -> Option<u64> {
        let r = self.row(id);
        if !matches!(r.kind, RecordKind::I64) {
            return None;
        }
        let at = usize_of(r.start.as_inner() + r.tag_w());
        // SAFETY: the product invariant — I64 rows are minted only
        // after the collection proved eight in-extent payload
        // bytes. `[u8; 8]` aligns to 1.
        let bits = unsafe { self.source.as_ptr().add(at).cast::<[u8; 8]>().read() };
        Some(u64::from_le_bytes(bits))
    }

    /// The four little-endian payload bytes as raw bits (`None`:
    /// not an I32 record). `crate::scalar` interprets them.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn i32_bits(&self, id: NodeId) -> Option<u32> {
        let r = self.row(id);
        if !matches!(r.kind, RecordKind::I32) {
            return None;
        }
        let at = usize_of(r.start.as_inner() + r.tag_w());
        // SAFETY: as `i64_bits`, four proven bytes.
        let bits = unsafe { self.source.as_ptr().add(at).cast::<[u8; 4]>().read() };
        Some(u32::from_le_bytes(bits))
    }

    /// The whole private construction state as comparable scalars:
    /// every row field in table order, the indexed end, and the
    /// fault (position plus its exact `Debug` form). Test-only —
    /// the finished-index differential compares it against the
    /// buffered twin's identically shaped snapshot.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Snapshot {
        let rows = self
            .rows
            .iter()
            .map(|r| {
                (
                    r.start.as_inner(),
                    r.payload_len.as_inner(),
                    r.parent.map(NodeId::as_inner),
                    r.descendants,
                    r.field,
                    r.kind,
                    r.tag_width.as_inner(),
                    r.delim_width.map(WordWidth::as_inner),
                )
            })
            .collect();
        let fault = self.fault.map(|f| (f.at(), alloc::format!("{:?}", f.kind())));
        (rows, self.indexed_end, fault)
    }
}

/// The comparable construction state: rows as scalar tuples, the
/// indexed end, and the fault's position beside its `Debug` form.
#[cfg(test)]
pub(crate) type Snapshot = (
    Vec<(u32, u32, Option<u32>, u32, FieldNumber, RecordKind, u8, Option<u8>)>,
    u32,
    Option<(u32, alloc::string::String)>,
);

// ─── iterators ───

/// One layer's records in wire order (the top layer or one
/// container's children), walked by subtree hops
/// (`next = cur + 1 + descendants`).
///
/// `ExactSizeIterator` and `DoubleEndedIterator` are structurally
/// unavailable: the member count is not O(1), and the last member
/// has no O(1) address.
#[must_use]
#[derive(Clone)]
pub struct Children<'t> {
    rows: &'t [Row],
    next: u32,
    end: u32,
}

impl<'t> Children<'t> {
    /// Narrows to the records of one field, preserving wire order.
    /// A field with no records in the run yields nothing.
    #[inline]
    pub fn by_field(self, field: FieldNumber) -> impl Iterator<Item = NodeId> + 't {
        let rows = self.rows;
        self.filter(move |id| {
            // SAFETY: `Children` yields in-table ids only (see
            // `next`).
            unsafe { rows.get_unchecked(id.index()) }.field == field
        })
    }
}

impl Iterator for Children<'_> {
    type Item = NodeId;

    #[inline]
    fn next(&mut self) -> Option<NodeId> {
        if self.next >= self.end {
            return None;
        }
        let id = self.next;
        // SAFETY: `id < end`, and `end <= rows.len()` by
        // construction — a run is bounded by its enclosing subtree
        // range, whose rows the collection physically pushed.
        let descendants = unsafe { self.rows.get_unchecked(usize_of(id)) }.descendants;
        self.next = id + 1 + descendants;
        Some(mint(id))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Nonempty runs yield at least one sibling; each sibling
        // occupies at least one row, bounding from above.
        let width = usize_of(self.end.saturating_sub(self.next));
        (usize::from(width > 0), Some(width))
    }
}

impl FusedIterator for Children<'_> {}

/// Walks the parent chain (a node's ancestors, nearest first).
/// Parent indices strictly decrease, bounding `size_hint` from
/// above; the exact length needs the walk, so no
/// `ExactSizeIterator`.
#[must_use]
#[derive(Clone)]
pub struct Ancestors<'t> {
    rows: &'t [Row],
    cur: Option<NodeId>,
}

impl Iterator for Ancestors<'_> {
    type Item = NodeId;

    #[inline]
    fn next(&mut self) -> Option<NodeId> {
        let id = self.cur?;
        // SAFETY: the chain starts at a checked row's parent link
        // and every later id is again a parent link — all minted
        // in-table by the collection.
        self.cur = unsafe { self.rows.get_unchecked(id.index()) }.parent;
        Some(id)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.cur.map_or((0, Some(0)), |id| (1, Some(id.index() + 1)))
    }
}

impl FusedIterator for Ancestors<'_> {}

/// Walks a contiguous preorder row range: the whole table
/// ([`Retained::nodes`]) or one subtree ([`Retained::descendants`])
/// — two demands, one shape. Exact: the range width is the count.
#[must_use]
#[derive(Clone)]
pub struct Nodes<'t> {
    next: u32,
    end: u32,
    _rows: core::marker::PhantomData<&'t [Row]>,
}

impl Iterator for Nodes<'_> {
    type Item = NodeId;

    #[inline]
    fn next(&mut self) -> Option<NodeId> {
        if self.next >= self.end {
            return None;
        }
        let id = self.next;
        self.next += 1;
        Some(mint(id))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = usize_of(self.end - self.next);
        (n, Some(n))
    }
}

impl DoubleEndedIterator for Nodes<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<NodeId> {
        if self.next >= self.end {
            return None;
        }
        self.end -= 1;
        Some(mint(self.end))
    }
}

impl ExactSizeIterator for Nodes<'_> {}
impl FusedIterator for Nodes<'_> {}

// ─── the machine ───

/// The root layer's zone sentinel: a stream's end is unknown until
/// `finish`, so the root extent has no endpoint. Feed admission
/// keeps every actual coordinate at or below `i32::MAX`, and a
/// declared endpoint is at most `i32::MAX + (2^31 − 1)`, so the
/// sentinel collides with neither.
const ROOT_ZONE: u32 = u32::MAX;

/// The coordinate class in stream form: what every feed's end is
/// admitted against.
const CAP: u64 = crate::admission::MAX as u64;
#[allow(
    clippy::as_conversions,
    reason = "the admission cap widens losslessly into the stream coordinate space"
)]
const _: () = assert!(CAP == i32::MAX as u64);

/// The word in flight across chunk edges: assembled payload bits
/// and the byte count consumed so far. The raw bytes are not
/// banked here — they already live in the reserved final backing,
/// appended as they were loaded — and the word's start is the
/// accumulated length minus the width.
#[derive(Clone, Copy)]
struct WordCarry {
    acc: u64,
    width: u8,
}

impl WordCarry {
    const fn new() -> Self {
        Self { acc: 0, width: 0 }
    }
}

/// A record head whose value side is still in flight: everything
/// the row mint needs once the extent completes.
#[derive(Clone, Copy)]
struct PendingHead {
    /// Source offset of the head tag.
    start: u32,
    field: FieldNumber,
    /// The head tag's actual input width.
    tag_width: WordWidth,
}

impl PendingHead {
    /// The value side's source offset.
    fn value_at(self) -> u32 {
        self.start + u32::from(self.tag_width.as_inner())
    }
}

/// The two fixed-width payload kinds, with their widths.
#[derive(Clone, Copy)]
enum FixedKind {
    I32,
    I64,
}

impl FixedKind {
    const fn needed(self) -> NonZeroU8 {
        match self {
            Self::I32 => const { NonZeroU8::new(4).unwrap() },
            Self::I64 => const { NonZeroU8::new(8).unwrap() },
        }
    }

    const fn record_kind(self) -> RecordKind {
        match self {
            Self::I32 => RecordKind::I32,
            Self::I64 => RecordKind::I64,
        }
    }
}

/// The parse position a chunk edge can cut — nothing more: rows
/// publish whole when their extents complete.
#[derive(Clone, Copy)]
enum Resume {
    /// Between records; the carry may hold a partial tag.
    Head,
    /// A varint record's value is in flight.
    VarintValue {
        /// The completed head.
        head: PendingHead,
    },
    /// A LEN record's length prefix is in flight.
    LenWord {
        /// The completed head.
        head: PendingHead,
    },
    /// A fixed payload is being collected.
    Fixed {
        /// The completed head.
        head: PendingHead,
        /// Which fixed kind (the publish kind and the fault's
        /// `needed`).
        kind: FixedKind,
        /// Payload bytes still owed.
        remaining: NonZeroU8,
    },
    /// Bytes through `end` copy without parsing: an opaque or
    /// demoted LEN body, a failed speculation's remainder, or a
    /// deferred fault's copy-to-endpoint run. Parsing resumes at
    /// `end`.
    SkipTo {
        /// The skip's exclusive endpoint.
        end: u32,
    },
}

/// One open LEN extent — the only container this dialect has, so
/// the frame needs no kind vocabulary. The frame simultaneously
/// carries the parent link (`row`), the open field, and the restore
/// state for the two live registers ([`Core::zone`],
/// [`Core::nearest_absorber`]) — pushing saves them, popping
/// restores them, and no walk ever recomputes them.
#[derive(Clone, Copy)]
struct Frame {
    row: NodeId,
    /// The open container's field (what the machine lends to
    /// [`Ancestry`]).
    field: FieldNumber,
    /// The enclosing extent's end, restored on close.
    prev_zone: u32,
    /// The enclosing nearest-absorber register, restored on close.
    prev_absorber: Option<usize>,
}

/// A judged violation, plus where the uncommitted transaction
/// began (`cut`): clipping uses `cut`, so a container never
/// swallows the bad record's tag bytes.
struct Failure {
    fault: Fault,
    cut: u32,
}

/// The open root-layer LEN transaction: an O(1) checkpoint taken
/// before advice or row publication, held until the stream proves
/// or refutes the declared endpoint.
///
/// At most one is open — entering the LEN seals a finite extent
/// for everything inside it, so a second root-layer LEN only
/// exists after this one resolves — and no absorber can enclose it
/// (an enclosing speculative LEN would have installed a finite
/// zone), so restoration re-arms the root registers directly.
struct RootLenTxn {
    /// Row count at the checkpoint (restoration truncates here).
    rows_base: u32,
    /// Stack depth at the checkpoint (root-layer, so zero in this
    /// dialect; the grouped dialect keeps open group frames under
    /// it).
    stack_base: u16,
    /// Materialized advisor-path length at the checkpoint.
    path_base: u16,
    /// The LEN record's head tag offset (the clip's `cut`).
    record_start: u32,
    /// The length prefix's offset (the overrun fault's position).
    prefix_start: u32,
    /// The declared body's first byte.
    payload_start: u32,
    /// The declared endpoint the stream must reach to prove the
    /// extent.
    payload_end: u32,
    /// The record's field number.
    field: FieldNumber,
    /// The declared payload length.
    declared: PayloadLen,
    state: RootLenState,
}

/// How far the open transaction has been judged.
enum RootLenState {
    /// The declared extent is being parsed (or skipped) while the
    /// stream works toward the endpoint.
    Parsing,
    /// An unabsorbed fault was met inside the unproven extent: the
    /// buffered parse would never reach it if the stream ends
    /// short, so its clip is delayed and bytes copy without
    /// parsing until the endpoint proves it real.
    Deferred(Failure),
    /// The declared endpoint exceeds the coordinate class: no
    /// admissible stream can fill it, so nothing inside is
    /// consulted or parsed — bytes copy until `finish` constructs
    /// the overrun.
    GuaranteedOverrun,
}

/// Whether the machine is still parsing or committed a fault and
/// now only collects.
enum ParseState {
    /// Parsing; the payload names what a chunk edge cut.
    Live(Resume),
    /// A committed fault clipped the index: every later byte is
    /// absorbed without parsing, and `finish` publishes the fault.
    FaultTail(Failure),
}

/// One word verdict from the fused fold, generic over the window's
/// width domain.
enum StepWord<W> {
    /// Terminated in class; the carry is reset.
    Done {
        /// The assembled word (zero when the fold was width-only).
        value: u64,
        /// The word's consumed width.
        width: W,
    },
    /// The chunk ran out first; feed the next one.
    More,
    /// The sealed extent ended mid-word. Terminal for the word.
    Cut,
    /// Ran past the domain window still continuing.
    TooWide,
    /// The terminal byte at full width exceeds the domain class.
    OutOfClass,
}

/// Appends one byte into capacity the feed already reserved.
///
/// # Safety
/// `source` has spare capacity for at least one more byte — the
/// feed door reserved the whole chunk before the first load.
#[inline(always)]
unsafe fn push_reserved(source: &mut Vec<u8>, byte: u8) {
    let len = source.len();
    debug_assert!(len < source.capacity());
    // SAFETY: one spare byte exists past `len` (this function's
    // contract), and the write initializes it before the raise.
    unsafe {
        source.as_mut_ptr().add(len).write(byte);
        source.set_len(len + 1);
    }
}

/// Bulk-appends bytes into capacity the feed already reserved.
///
/// # Safety
/// `source` has spare capacity for at least `bytes.len()` more
/// bytes — the feed door reserved the whole chunk before the first
/// load.
#[inline]
unsafe fn extend_reserved(source: &mut Vec<u8>, bytes: &[u8]) {
    let len = source.len();
    debug_assert!(bytes.len() <= source.capacity() - len);
    // SAFETY: the spare capacity covers the copy (this function's
    // contract), the borrowed chunk cannot overlap the owned
    // backing, and the raise covers exactly the initialized bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), source.as_mut_ptr().add(len), bytes.len());
        source.set_len(len + bytes.len());
    }
}

/// Appends a resolved word's bytes into capacity the feed already
/// reserved: one unconditional `LANES`-byte window copy (eight or
/// two overlapping eight-byte lanes), so short words never pay a
/// dispatched memcpy.
///
/// # Safety
/// `src` is readable for `LANES` bytes, `width <= LANES`, and
/// `source` has spare capacity for at least `LANES` more bytes.
#[inline(always)]
unsafe fn word_reserved(source: &mut Vec<u8>, src: *const u8, width: usize, lanes: usize) {
    debug_assert!(lanes == 8 || lanes == 10);
    let len = source.len();
    debug_assert!(width <= lanes && lanes <= source.capacity() - len);
    // SAFETY: `lanes` readable source bytes and `lanes` spare
    // destination bytes (this function's contract); the raise
    // covers exactly the word's own initialized prefix.
    unsafe {
        let dst = source.as_mut_ptr().add(len);
        core::ptr::copy_nonoverlapping(src, dst, 8);
        if lanes == 10 {
            core::ptr::copy_nonoverlapping(src.add(2), dst.add(2), 8);
        }
        source.set_len(len + width);
    }
}

/// The live collection state behind the terminal-use shell.
struct Core<'a, A: Advisor> {
    source: Vec<u8>,
    rows: Vec<Row>,
    /// The innermost extent's exclusive end ([`ROOT_ZONE`] at the
    /// root layer) — maintained by open and close, never
    /// recomputed.
    zone: u32,
    /// The word in flight across chunk edges.
    word: WordCarry,
    state: ParseState,
    stack: Vec<Frame>,
    /// The open containers' fields, materialized lazily from the
    /// frame stack when an advisor is consulted (`path[i]` mirrors
    /// `stack[i].field` for every materialized index); closes
    /// truncate it back in step.
    path: Vec<FieldNumber>,
    /// Stack index of the innermost `Advice::Speculate` LEN (the
    /// frame a speculation failure unwinds to), maintained by open
    /// and close for an O(1) dispose. `Commit` frames are not
    /// absorbing, and the root is implicitly committed.
    nearest_absorber: Option<usize>,
    /// The open root-layer LEN transaction, when one exists.
    root_len: Option<RootLenTxn>,
    standard: Standard,
    limit: DepthLimit,
    advice: &'a mut A,
}

impl<'a, A: Advisor> Core<'a, A> {
    /// The parse position: every consumed byte was appended, so
    /// the position is the accumulated length (a skip's target may
    /// lie ahead of it).
    const fn pos(&self) -> u32 {
        admitted_u32(self.source.len())
    }

    fn parent_row(&self) -> Option<NodeId> {
        self.stack.last().map(|f| f.row)
    }

    /// One frame per nesting level: the frame count is the depth.
    fn at_depth_limit(&self) -> bool {
        self.stack.len() >= usize::from(self.limit.as_inner())
    }

    /// Consults the advisor, materializing the enclosing fields it
    /// is owed. Amortized O(1): each frame's field is copied at
    /// most once per residency on the stack.
    fn consult(&mut self, field: FieldNumber) -> Advice {
        if self.path.len() < self.stack.len() {
            self.path.extend(self.stack[self.path.len()..].iter().map(|f| f.field));
        }
        self.advice.advise(Ancestry::new(&self.path), field)
    }

    /// Pushes an open LEN and saves the live registers in it.
    fn open(&mut self, row: NodeId, field: FieldNumber, zone: u32, absorbing: bool) {
        self.stack.push(Frame {
            row,
            field,
            prev_zone: self.zone,
            prev_absorber: self.nearest_absorber,
        });
        self.zone = zone;
        if absorbing {
            self.nearest_absorber = Some(self.stack.len() - 1);
        }
    }

    /// Terminal write of a closing container: its subtree is
    /// exactly the rows pushed since it.
    fn seal_descendants(&mut self, row: NodeId) {
        let idx = row.index();
        let descendants = row_u32(self.rows.len() - 1 - idx);
        // SAFETY: frame rows are in-table (minted before the frame
        // pushed and never truncated while it lives).
        unsafe { self.rows.get_unchecked_mut(idx) }.descendants = descendants;
    }

    fn push_leaf(
        &mut self,
        at: u32,
        field: FieldNumber,
        kind: RecordKind,
        tag_width: WordWidth,
        payload_len: Extent,
        delim_width: Option<WordWidth>,
    ) {
        // SAFETY: every caller passes the record head's offset,
        // which the feed gates held below the collection cap —
        // inside the admitted source, so the offset is in class.
        let start = unsafe { Coord::new_unchecked(at) };
        self.rows.push(Row {
            start,
            payload_len,
            parent: self.parent_row(),
            descendants: 0,
            field,
            kind,
            tag_width,
            delim_width,
        });
    }

    /// Continues the word in flight with bytes from `rest`.
    /// Bounded by the innermost zone — a word never reads across a
    /// sealed extent, and the seal's verdict is `Cut` without
    /// consuming.
    ///
    /// A fresh word whose window (the tighter of the chunk and the
    /// seal) resolves it whole reads through the slice kernel —
    /// one bounds story, one bulk append — instead of the per-byte
    /// pump; the resumable per-byte lane below owns kernel
    /// truncations (chunk and seal edges) and cross-feed
    /// continuations. `CAP_K` restates `W::CAP` as the kernel's
    /// const parameter (asserted equal below).
    /// The tolerant value instance runs with `FOLD = false`: it
    /// sizes the value without assembling it (both lanes hand a
    /// zero word there). A terminated read mints its counted width
    /// in the verdict's window domain `W`.
    fn step_word<W: StepWidth, const CAP_K: u32, const LAST_MAX: u8, const FOLD: bool>(
        &mut self,
        rest: &mut &[u8],
    ) -> StepWord<W> {
        const {
            assert!(W::CAP <= 10 && LAST_MAX < CONT_BIT);
            assert!(CAP_K == W::CAP as u32, "the kernel cap restates the window cap");
        };
        // The lane width: the whole copy window the fast lane pays
        // unconditionally (words are at most `CAP_K` wide, so one
        // eight-byte lane covers the five-byte domains and two
        // overlapping lanes cover the ten-byte one). A `let` from
        // the const parameter: inlining folds it flat.
        let lanes: usize = if CAP_K <= 8 { 8 } else { 10 };
        if self.word.width == 0 && rest.len() >= lanes && usize_of(self.zone - self.pos()) >= lanes
        {
            match crate::varint::slice::tolerant::<CAP_K, LAST_MAX>(rest, 0, lanes) {
                Ok((value, width)) => {
                    // SAFETY: the feed door reserved the whole
                    // chunk (>= LANES spare), `rest` holds at
                    // least `LANES` readable bytes, and the
                    // kernel's width is at most `CAP_K <= LANES`.
                    unsafe {
                        word_reserved(&mut self.source, rest.as_ptr(), usize::from(width), lanes);
                    }
                    *rest = &rest[usize::from(width)..];
                    // SAFETY: the kernel terminated inside its
                    // window, so `1 <= width && width <= W::CAP`.
                    let width = unsafe { W::met_unchecked(width) };
                    return StepWord::Done { value: if FOLD { value } else { 0 }, width };
                }
                Err(ReadFault::TooWide) => {
                    self.kernel_refused::<CAP_K>(rest);
                    return StepWord::TooWide;
                }
                Err(ReadFault::OutOfClass) => {
                    self.kernel_refused::<CAP_K>(rest);
                    return StepWord::OutOfClass;
                }
                // The window ends while the word could still
                // complete: a chunk or seal edge — the per-byte
                // lane resolves it (More, or Cut at the seal).
                Err(ReadFault::Truncated) => {}
            }
        }
        loop {
            // The seal is judged ahead of the chunk: a word still
            // continuing at its zone's end is cut at the earliest
            // deterministic point, chunk edges notwithstanding —
            // no future byte can belong to it.
            if self.pos() == self.zone {
                return StepWord::Cut;
            }
            let Some((&byte, tail)) = rest.split_first() else {
                return StepWord::More;
            };
            // SAFETY: the feed door reserved the whole chunk before
            // the drive started, and every prior append consumed a
            // chunk byte — spare capacity covers this one.
            unsafe { push_reserved(&mut self.source, byte) };
            *rest = tail;
            if FOLD {
                self.word.acc |=
                    (u64::from(byte) & PAYLOAD_MASK) << (PAYLOAD_BITS * u32::from(self.word.width));
            }
            self.word.width += 1;
            if byte < CONT_BIT {
                if self.word.width == W::CAP && byte > LAST_MAX {
                    return StepWord::OutOfClass;
                }
                // SAFETY: a terminated in-window read: the carry
                // re-enters this loop only below the cap (`More`
                // exits below it; every capped verdict disposes
                // the carry), and each byte increments the width
                // once, so `1 <= width && width <= W::CAP`.
                let width = unsafe { W::met_unchecked(self.word.width) };
                let done = StepWord::Done { value: self.word.acc, width };
                self.word = WordCarry::new();
                return done;
            }
            if self.word.width == W::CAP {
                return StepWord::TooWide;
            }
        }
    }

    /// Disposes of a judged failure. Three sinks, in precedence
    /// order: the nearest absorbing frame concludes its speculation
    /// as "bytes" (truncation — `descendants` is written only at
    /// close, so no written state needs repair — then an in-feed
    /// skip to the absorber's endpoint); an unproven root
    /// transaction defers the fault the buffered parse may never
    /// reach; a committed fault clips now and latches the fault
    /// tail.
    #[cold]
    fn dispose(&mut self, failure: Failure) {
        self.word = WordCarry::new();
        if let Some(idx) = self.nearest_absorber {
            let absorber = self.stack[idx];
            // The absorber's own zone end: the live zone while it
            // was innermost — the frame above it saved that as
            // `prev_zone`.
            let own_zone = self.stack.get(idx + 1).map_or(self.zone, |above| above.prev_zone);
            // The demoted LEN keeps its row (a sealed leaf:
            // descendants stayed 0, its declared span is an input
            // fact); everything it speculated over — rows, inner
            // frames, conditional Message promises — evaporates.
            self.rows.truncate(absorber.row.index() + 1);
            self.zone = absorber.prev_zone;
            self.nearest_absorber = absorber.prev_absorber;
            self.stack.truncate(idx);
            self.path.truncate(idx);
            self.state = ParseState::Live(Resume::SkipTo { end: own_zone });
            return;
        }
        let pos = self.pos();
        if let Some(txn) = &mut self.root_len
            && pos < txn.payload_end
        {
            // The buffered parse judges the outer endpoint before
            // it reads a byte of the body: while the stream has
            // not proven that endpoint, this fault may be one the
            // buffered parse never reaches. Freeze it — no clip,
            // no frame pops — and copy toward the endpoint.
            debug_assert!(matches!(txn.state, RootLenState::Parsing));
            let end = txn.payload_end;
            txn.state = RootLenState::Deferred(failure);
            self.state = ParseState::Live(Resume::SkipTo { end });
            return;
        }
        self.commit(failure);
    }

    /// Commits a fault: clips every open LEN with the same
    /// close-time writes as a normal pop (LEN rows keep their
    /// declared spans; only `descendants` needs the terminal
    /// write), discards any resolved root transaction, and latches
    /// the fault tail — later feeds absorb without parsing.
    #[cold]
    fn commit(&mut self, failure: Failure) {
        self.root_len = None;
        while let Some(frame) = self.stack.pop() {
            self.seal_descendants(frame.row);
        }
        self.path.clear();
        self.zone = ROOT_ZONE;
        self.nearest_absorber = None;
        self.word = WordCarry::new();
        self.state = ParseState::FaultTail(failure);
    }

    /// Fault disposition sinks: the fault value takes shape here,
    /// off the parse's hot dispatch — only judged scalars cross
    /// the call.
    #[cold]
    fn fault(&mut self, at: u32, cut: u32, kind: FaultKind) {
        self.dispose(Failure { fault: Fault { at, kind }, cut });
    }

    /// A varint read refusal at a stage, sunk like [`Self::fault`].
    #[cold]
    fn fault_read(&mut self, at: u32, cut: u32, stage: Stage, cause: ReadFault) {
        self.fault(at, cut, FaultKind::Read { stage, cause });
    }

    /// Closes every extent whose endpoint the parse position
    /// reached — a LEN closes clean in this dialect — and resolves
    /// the root transaction when the popped frame was its own.
    fn cascade(&mut self) {
        while self.pos() == self.zone {
            let Some(frame) = self.stack.pop() else {
                debug_assert!(false, "a finite zone without its frame");
                break;
            };
            self.seal_descendants(frame.row);
            self.zone = frame.prev_zone;
            self.nearest_absorber = frame.prev_absorber;
            self.path.truncate(self.stack.len());
            self.resolve_if_proven();
        }
    }

    /// Discards the root transaction once the stream has proven
    /// its declared endpoint: the parse position reached
    /// `payload_end` with the stack back at the checkpoint depth.
    fn resolve_if_proven(&mut self) {
        if let Some(txn) = &self.root_len
            && self.stack.len() == usize::from(txn.stack_base)
            && self.pos() >= txn.payload_end
        {
            debug_assert!(matches!(txn.state, RootLenState::Parsing));
            self.root_len = None;
        }
    }

    /// A skip's endpoint arrived: resolve the root transaction if
    /// this was its extent (a proven extent commits its deferred
    /// fault; a merely parsing one discards the checkpoint), then
    /// resume at the head.
    fn skip_arrived(&mut self, end: u32) {
        if let Some(txn) = self.root_len.take() {
            // A deferred transaction froze the parse: its own
            // copy-to-endpoint run is the only live skip, whatever
            // stack the freeze kept. A parsing transaction shares
            // its endpoint with interior skips, so the checkpoint
            // depth discriminates.
            let resolves = end == txn.payload_end
                && (matches!(txn.state, RootLenState::Deferred(_))
                    || self.stack.len() == usize::from(txn.stack_base));
            if resolves {
                match txn.state {
                    RootLenState::Parsing => {}
                    RootLenState::Deferred(failure) => {
                        // The extent is proven, so the frozen fault
                        // is exactly the buffered verdict: run its
                        // delayed clip.
                        self.commit(failure);
                        return;
                    }
                    RootLenState::GuaranteedOverrun => {
                        // Unreachable by arithmetic: that endpoint
                        // exceeds the coordinate class while the
                        // position is admission-bounded below it.
                        debug_assert!(false, "an overrun endpoint inside the coordinate class");
                    }
                }
            } else {
                // An interior skip (an opaque body inside the
                // transaction): the checkpoint stays open.
                self.root_len = Some(txn);
            }
        }
        self.state = ParseState::Live(Resume::Head);
    }

    /// Steps the head tag; a completed tag classifies and opens
    /// its value stage.
    #[allow(
        clippy::as_conversions,
        reason = "four full payload bytes and a fifth capped at 0x0F land exactly in u32"
    )]
    fn head<const MINIMAL: bool>(&mut self, rest: &mut &[u8]) {
        let (word, width) = match self
            .step_word::<WordWidth, { crate::varint::MAX_LEN32 }, { crate::varint::LAST32 }, true>(
                rest,
            ) {
            StepWord::Done { value, width } => (value as u32, width),
            StepWord::More => return,
            StepWord::Cut => {
                let at = self.word_start();
                return self.fault_read(at, at, Stage::Tag, ReadFault::Truncated);
            }
            StepWord::TooWide => {
                let at = self.word_start();
                return self.fault_read(at, at, Stage::Tag, ReadFault::TooWide);
            }
            StepWord::OutOfClass => {
                let at = self.word_start();
                return self.fault_read(at, at, Stage::Tag, ReadFault::OutOfClass);
            }
        };
        let start = self.pos() - width.w();
        if MINIMAL && width.w() > encoded_len32(word) {
            return self.fault(start, start, FaultKind::NonMinimalTag);
        }
        // Field zero is an identity judgment on the whole tag word
        // and precedes any kind judgment (corpus-pinned precedence).
        let low3 = Low3::from_word(word);
        let Some(field) = FieldNumber::from_word(word) else {
            return self.fault(start, start, FaultKind::FieldZero { code: low3 });
        };
        let head = PendingHead { start, field, tag_width: width };
        // The threaded dispatch: a classified head calls its value
        // stage directly — no state write, no trip through the
        // drive loop's dispatch — so a whole in-chunk record closes
        // in one descent. The value stages write the suspended
        // state themselves when the chunk drains mid-construct.
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                self.varint_value::<MINIMAL>(rest, head);
            }
            TagClass::Record(RecordKind::I64) => self.fixed_head(rest, head, FixedKind::I64),
            TagClass::Record(RecordKind::I32) => self.fixed_head(rest, head, FixedKind::I32),
            TagClass::Record(RecordKind::Len) => {
                self.len_word::<MINIMAL>(rest, head);
            }
            TagClass::GroupCode => {
                self.fault(start, start, FaultKind::GroupCode { field, code: low3 });
            }
            TagClass::Unassigned => {
                self.fault(start, start, FaultKind::Unassigned { field, code: low3 });
            }
        }
    }

    /// The start of the word in flight (its bytes are already in
    /// the backing).
    fn word_start(&self) -> u32 {
        self.pos() - u32::from(self.word.width)
    }

    /// Books a kernel-refused word (`TooWide`/`OutOfClass`): the
    /// capped bytes append in bulk and the carry takes the met
    /// width, so the refusal's coordinates ([`Self::word_start`])
    /// and its disposal read exactly as the per-byte lane's.
    #[cold]
    fn kernel_refused<const CAP_K: u32>(&mut self, rest: &mut &[u8]) {
        let (bytes, tail) = rest.split_at(usize_of(CAP_K));
        // SAFETY: the feed door reserved the whole chunk; the
        // word's bytes are a chunk prefix.
        unsafe { extend_reserved(&mut self.source, bytes) };
        *rest = tail;
        #[allow(clippy::as_conversions, reason = "the cap is at most ten")]
        {
            self.word.width = CAP_K as u8;
        }
    }

    /// Admits a fixed head against its extent — the seal is known,
    /// so a short extent refuses before any payload byte arrives,
    /// exactly where the buffered parse refuses it — then collects
    /// the payload directly (the threaded path).
    fn fixed_head(&mut self, rest: &mut &[u8], head: PendingHead, kind: FixedKind) {
        let needed = kind.needed();
        let after_tag = head.value_at();
        if after_tag + u32::from(needed.get()) > self.zone {
            let kind = FaultKind::FixedTruncated { field: head.field, needed: needed.get() };
            return self.fault(after_tag, head.start, kind);
        }
        self.fixed(rest, head, kind, needed);
    }

    /// Steps a varint record's value; completion publishes the
    /// row. The tolerant instance only sizes the value — the fold
    /// is compiled out — while the canonical one assembles it for
    /// the minimal-width judgment.
    fn varint_value<const MINIMAL: bool>(&mut self, rest: &mut &[u8], head: PendingHead) {
        let step = self
            .step_word::<ValueWidth, { crate::varint::MAX_LEN64 }, { crate::varint::LAST64 }, MINIMAL>(
                rest,
            );
        let (value, width) = match step {
            StepWord::Done { value, width } => (value, width),
            StepWord::More => {
                // Suspended mid-construct: the threaded dispatch
                // wrote no state, so the suspension books here.
                self.state = ParseState::Live(Resume::VarintValue { head });
                return;
            }
            StepWord::Cut => {
                let stage = Stage::Value { field: head.field };
                return self.fault_read(head.value_at(), head.start, stage, ReadFault::Truncated);
            }
            StepWord::TooWide => {
                let stage = Stage::Value { field: head.field };
                return self.fault_read(head.value_at(), head.start, stage, ReadFault::TooWide);
            }
            StepWord::OutOfClass => {
                let stage = Stage::Value { field: head.field };
                return self.fault_read(head.value_at(), head.start, stage, ReadFault::OutOfClass);
            }
        };
        if MINIMAL && width.w() > encoded_len64(value) {
            let kind = FaultKind::NonMinimalValue { field: head.field };
            return self.fault(head.value_at(), head.start, kind);
        }
        let payload_len = Extent::from_width(width.as_inner());
        self.push_leaf(
            head.start,
            head.field,
            RecordKind::Varint,
            head.tag_width,
            payload_len,
            None,
        );
        self.state = ParseState::Live(Resume::Head);
    }

    /// Steps a LEN length prefix; a completed prefix is judged for
    /// minimality first (the buffered order), then against its
    /// enclosing seal.
    #[allow(
        clippy::as_conversions,
        reason = "four full payload bytes and a fifth capped at 0x07 land inside the length class"
    )]
    fn len_word<const MINIMAL: bool>(&mut self, rest: &mut &[u8], head: PendingHead) {
        let step = self
            .step_word::<WordWidth, { crate::varint::MAX_LEN32 }, { crate::varint::LAST_LEN }, true>(
                rest,
            );
        let (value, width) = match step {
            StepWord::Done { value, width } => (value, width),
            StepWord::More => {
                // Suspended mid-construct: the threaded dispatch
                // wrote no state, so the suspension books here.
                self.state = ParseState::Live(Resume::LenWord { head });
                return;
            }
            StepWord::Cut => {
                let stage = Stage::LenPrefix { field: head.field };
                return self.fault_read(head.value_at(), head.start, stage, ReadFault::Truncated);
            }
            StepWord::TooWide => {
                let stage = Stage::LenPrefix { field: head.field };
                return self.fault_read(head.value_at(), head.start, stage, ReadFault::TooWide);
            }
            StepWord::OutOfClass => {
                let stage = Stage::LenPrefix { field: head.field };
                return self.fault_read(head.value_at(), head.start, stage, ReadFault::OutOfClass);
            }
        };
        if MINIMAL && width.w() > encoded_len32(value as u32) {
            let kind = FaultKind::NonMinimalLen { field: head.field };
            return self.fault(head.value_at(), head.start, kind);
        }
        // SAFETY: four full payload bytes carry 28 bits and the
        // fifth is capped at 0x07, so the value is at most
        // 0x7FFF_FFFF — inside the PayloadLen range.
        let declared = unsafe { PayloadLen::new_unchecked(value as u32) };
        self.len_head(head, declared, width);
    }

    /// Judges a completed LEN head's endpoint. A finite enclosing
    /// seal answers immediately, as the buffered parse answers it;
    /// the root layer's seal is the stream's unknown end, so the
    /// head opens the root transaction instead — checkpoint first,
    /// then the ordinary advice flow (or copy-only collection for
    /// an endpoint no admissible stream can fill).
    #[allow(
        clippy::as_conversions,
        reason = "declared endpoints widen losslessly for the class comparison"
    )]
    fn len_head(&mut self, head: PendingHead, declared: PayloadLen, prefix_width: WordWidth) {
        let prefix_start = head.value_at();
        let payload_start = prefix_start + u32::from(prefix_width.as_inner());
        // Both terms are admission/class-bounded, so the sum stays
        // within u32 (and below the root sentinel).
        let payload_end = payload_start + declared.as_inner();
        if self.zone == ROOT_ZONE {
            // The one-transaction law: entering a root-layer LEN
            // seals a finite extent for everything inside it, so no
            // second transaction can open before this one resolves.
            debug_assert!(self.root_len.is_none());
            let checkpoint = RootLenTxn {
                rows_base: row_u32(self.rows.len()),
                stack_base: stack_u16(self.stack.len()),
                path_base: stack_u16(self.path.len()),
                record_start: head.start,
                prefix_start,
                payload_start,
                payload_end,
                field: head.field,
                declared,
                state: RootLenState::Parsing,
            };
            if u64::from(payload_end) > CAP {
                // Guaranteed overrun: nothing inside is consulted
                // or parsed — the buffered parse would judge the
                // overrun before either.
                self.root_len =
                    Some(RootLenTxn { state: RootLenState::GuaranteedOverrun, ..checkpoint });
                self.state = ParseState::Live(Resume::SkipTo { end: payload_end });
                return;
            }
            self.root_len = Some(checkpoint);
        } else if payload_end > self.zone {
            let zone_left = self.zone - payload_start;
            let kind = FaultKind::LenOverrun { field: head.field, declared, zone_left };
            return self.fault(prefix_start, head.start, kind);
        }
        self.advised_len(head, declared, prefix_width, payload_end);
    }

    /// The advice flow of an endpoint-lawful LEN head — the
    /// buffered dispositions verbatim.
    fn advised_len(
        &mut self,
        head: PendingHead,
        declared: PayloadLen,
        prefix_width: WordWidth,
        payload_end: u32,
    ) {
        let advice = self.consult(head.field);
        match advice {
            Advice::Opaque => {
                self.push_leaf(
                    head.start,
                    head.field,
                    RecordKind::Len,
                    head.tag_width,
                    Extent::from_len(declared),
                    Some(prefix_width),
                );
                self.state = ParseState::Live(Resume::SkipTo { end: payload_end });
            }
            Advice::Speculate if self.at_depth_limit() => {
                // Too deep to speculate: demote to opaque — not a
                // document fault (the bytes may well be bytes).
                self.push_leaf(
                    head.start,
                    head.field,
                    RecordKind::Len,
                    head.tag_width,
                    Extent::from_len(declared),
                    Some(prefix_width),
                );
                self.state = ParseState::Live(Resume::SkipTo { end: payload_end });
            }
            Advice::Commit if self.at_depth_limit() => {
                let kind = FaultKind::DepthExceeded { field: head.field, limit: self.limit };
                self.fault(head.start, head.start, kind);
            }
            Advice::Speculate | Advice::Commit => {
                let absorbing = matches!(advice, Advice::Speculate);
                let row = mint(row_u32(self.rows.len()));
                self.push_leaf(
                    head.start,
                    head.field,
                    RecordKind::Len,
                    head.tag_width,
                    Extent::from_len(declared),
                    Some(prefix_width),
                );
                self.open(row, head.field, payload_end, absorbing);
                self.state = ParseState::Live(Resume::Head);
            }
        }
    }

    /// Collects a fixed payload in bulk; completion publishes.
    #[allow(clippy::as_conversions, reason = "the take is bounded by `remaining ≤ 8`, inside u8")]
    fn fixed(
        &mut self,
        rest: &mut &[u8],
        head: PendingHead,
        kind: FixedKind,
        remaining: NonZeroU8,
    ) {
        let take = usize::from(remaining.get()).min(rest.len());
        let (bytes, tail) = rest.split_at(take);
        // SAFETY: the feed door reserved the whole chunk; the take
        // is bounded by the chunk's own remainder.
        unsafe { extend_reserved(&mut self.source, bytes) };
        *rest = tail;
        match NonZeroU8::new(remaining.get() - take as u8) {
            Some(still) => {
                self.state = ParseState::Live(Resume::Fixed { head, kind, remaining: still })
            }
            None => {
                let payload_len = Extent::from_width(kind.needed().get());
                self.push_leaf(
                    head.start,
                    head.field,
                    kind.record_kind(),
                    head.tag_width,
                    payload_len,
                    None,
                );
                self.state = ParseState::Live(Resume::Head);
            }
        }
    }

    /// Copies skipped bytes in bulk — an opaque body, a failed
    /// speculation's remainder, or a deferred fault's tail — never
    /// wire-judging them.
    fn skip(&mut self, rest: &mut &[u8], end: u32) {
        let take = usize_of(end - self.pos()).min(rest.len());
        let (bytes, tail) = rest.split_at(take);
        // SAFETY: the feed door reserved the whole chunk; the take
        // is bounded by the chunk's own remainder.
        unsafe { extend_reserved(&mut self.source, bytes) };
        *rest = tail;
    }

    /// Drives the fused loop over one admitted, reservation-backed
    /// chunk. Faults never leave: they clip and latch internally,
    /// and the rest of the chunk keeps absorbing.
    ///
    /// The loop is threaded: at most one construct suspends across
    /// feeds, so the cold prologue re-enters it once, and the hot
    /// spine then closes whole records through the head's direct
    /// dispatch — the state is read once per record (a predictable
    /// discriminant test), not once per construct stage.
    fn drive<const MINIMAL: bool>(&mut self, mut rest: &[u8]) {
        match self.state {
            ParseState::FaultTail(_) => {
                // SAFETY: the feed door reserved the whole chunk;
                // the examined prefix consumed exactly its own
                // bytes, so the suffix fits.
                unsafe { extend_reserved(&mut self.source, rest) };
                return;
            }
            ParseState::Live(resume) => match resume {
                Resume::Head | Resume::SkipTo { .. } => {}
                Resume::VarintValue { head } => {
                    if rest.is_empty() && self.pos() < self.zone {
                        return;
                    }
                    self.varint_value::<MINIMAL>(&mut rest, head);
                }
                Resume::LenWord { head } => {
                    if rest.is_empty() && self.pos() < self.zone {
                        return;
                    }
                    self.len_word::<MINIMAL>(&mut rest, head);
                }
                Resume::Fixed { head, kind, remaining } => {
                    if rest.is_empty() {
                        return;
                    }
                    self.fixed(&mut rest, head, kind, remaining);
                }
            },
        }
        loop {
            // The rare exits first, so the hot case is one
            // predictable test: a skip run, a suspension (the
            // chunk is drained), or a latched fault.
            match self.state {
                ParseState::Live(Resume::Head) => {}
                ParseState::Live(Resume::SkipTo { end }) => {
                    if self.pos() == end {
                        self.skip_arrived(end);
                        continue;
                    }
                    if rest.is_empty() {
                        return;
                    }
                    self.skip(&mut rest, end);
                    continue;
                }
                ParseState::FaultTail(_) => {
                    // SAFETY: the feed door reserved the whole
                    // chunk; the examined prefix consumed exactly
                    // its own bytes, so the suffix fits.
                    unsafe { extend_reserved(&mut self.source, rest) };
                    return;
                }
                // Suspended mid-construct: the chunk is drained.
                ParseState::Live(_) => return,
            }
            // The threaded spine: the state is Head — cascade
            // sealed frames, park on a drained chunk only while
            // the position is strictly inside the zone (a word
            // standing at its seal is cut now — the verdict owes
            // nothing to future bytes), then thread one record.
            if self.word.width == 0 {
                self.cascade();
            }
            if rest.is_empty() && self.pos() < self.zone {
                return;
            }
            self.head::<MINIMAL>(&mut rest);
        }
    }

    /// Declares the stream's end and seals the product. Judgment
    /// order: an unproven root transaction restores its checkpoint
    /// and constructs the outer overrun (overriding any deferred
    /// interior fault — the buffered precedence); a committed
    /// fault keeps its clipped rows and the full accumulated
    /// source; a word or payload the end cut becomes the buffered
    /// extent-end fault; then the already-final rows box and the
    /// source moves — no byte is read again.
    fn seal(mut self) -> Retained {
        let end = admitted_u32(self.source.len());
        if let Some(txn) = self.root_len.take() {
            // The stream ended short of the declared endpoint: the
            // buffered parse judges this before advice, descent,
            // or any interior fault, so the checkpoint restores —
            // speculative rows truncate, registers re-arm — and
            // the outer overrun stands with the bytes the stream
            // actually left.
            debug_assert!(u64::from(end) < u64::from(txn.payload_end));
            self.rows.truncate(usize_of(txn.rows_base));
            self.stack.truncate(usize::from(txn.stack_base));
            self.path.truncate(usize::from(txn.path_base));
            self.zone = ROOT_ZONE;
            self.nearest_absorber = None;
            let kind = FaultKind::LenOverrun {
                field: txn.field,
                declared: txn.declared,
                zone_left: end - txn.payload_start,
            };
            let fault = Fault { at: txn.prefix_start, kind };
            self.commit(Failure { fault, cut: txn.record_start });
        } else if let ParseState::Live(resume) = self.state {
            let eof = match resume {
                Resume::Head if self.word.width == 0 => {
                    // A clean boundary: in this dialect every open
                    // frame is a LEN whose endpoint lies at or
                    // inside the root transaction's, so a resolved
                    // transaction leaves the stack empty.
                    debug_assert!(self.stack.is_empty());
                    None
                }
                Resume::Head => {
                    let at = self.word_start();
                    Some(Failure {
                        fault: Fault {
                            at,
                            kind: FaultKind::Read {
                                stage: Stage::Tag,
                                cause: ReadFault::Truncated,
                            },
                        },
                        cut: at,
                    })
                }
                Resume::VarintValue { head } => Some(Failure {
                    fault: Fault {
                        at: head.value_at(),
                        kind: FaultKind::Read {
                            stage: Stage::Value { field: head.field },
                            cause: ReadFault::Truncated,
                        },
                    },
                    cut: head.start,
                }),
                Resume::LenWord { head } => Some(Failure {
                    fault: Fault {
                        at: head.value_at(),
                        kind: FaultKind::Read {
                            stage: Stage::LenPrefix { field: head.field },
                            cause: ReadFault::Truncated,
                        },
                    },
                    cut: head.start,
                }),
                Resume::Fixed { head, kind, .. } => Some(Failure {
                    fault: Fault {
                        at: head.value_at(),
                        kind: FaultKind::FixedTruncated {
                            field: head.field,
                            needed: kind.needed().get(),
                        },
                    },
                    cut: head.start,
                }),
                Resume::SkipTo { .. } => {
                    // Every skip's endpoint lies at or inside the
                    // root transaction's declared endpoint, and a
                    // skip whose endpoint the stream reached was
                    // consumed in the feed that supplied its last
                    // byte — so a skip live at the end implies an
                    // unresolved transaction, which the arm above
                    // already consumed.
                    debug_assert!(false, "a live skip at the stream end without its transaction");
                    // SAFETY: the invariant argued above.
                    unsafe { core::hint::unreachable_unchecked() }
                }
            };
            if let Some(failure) = eof {
                self.commit(failure);
            }
        }
        let (indexed_end, fault) = match self.state {
            ParseState::FaultTail(failure) => (failure.cut, Some(failure.fault)),
            ParseState::Live(_) => (end, None),
        };
        Retained { source: self.source, rows: self.rows.into_boxed_slice(), indexed_end, fault }
    }
}

/// A stack or path length back in the checkpoint's `u16` class:
/// depth is bounded by [`DepthLimit`]'s cap (10,000).
#[allow(clippy::as_conversions, reason = "depth is bounded by DepthLimit's cap, inside u16")]
const fn stack_u16(len: usize) -> u16 {
    debug_assert!(len <= 10_000);
    len as u16
}

// ─── the collector ───

/// The stream-collect phase: accepts chunks, parses them as they
/// arrive, and seals into the finished queryable product.
///
/// One fused pass: [`Collector::feed`] admits the whole chunk
/// against the coordinate class, reserves room for it, then
/// examines each deciding byte once, as source-level traffic — one
/// append into the reserved final backing and one fold into the
/// word carry per byte — while opaque, fixed, skipped, and
/// post-fault runs append in bulk. The phase
/// owns no query face; only the consuming [`Collector::finish`]
/// publishes the product those faces exist on, and it is total —
/// end-of-stream judgments become the product's fault.
///
/// The advisor is borrowed for the collector's life: one schema
/// supply answers every site however the stream is chunked.
///
/// Terminal states are final: after a returned [`FeedOversize`]
/// (or an advisor panic caught by the caller), the shell is spent,
/// and another `feed`/`finish`/`offset`/`into_source` call panics
/// (a caller bug, named). Dropping a live collector abandons the
/// job — allocations are freed, nothing is published.
#[must_use]
pub struct Collector<'a, A: Advisor> {
    core: Option<Core<'a, A>>,
}

// The shell spends through the option; the niche keeps the spent
// state free (asserted below, not assumed).
const _: () = assert!(
    core::mem::size_of::<Collector<'static, super::NoAdvice>>()
        == core::mem::size_of::<Core<'static, super::NoAdvice>>()
);

impl<'a, A: Advisor> Collector<'a, A> {
    /// Starts a collection job. All runtime behavior is declared
    /// here: the acceptance standard picks a monomorphized engine
    /// instance at every feed (a tolerant collection pays no width
    /// comparison), `depth` bounds container nesting with no
    /// default, and `advice` is consulted at every LEN record head
    /// (empty payloads included).
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::collect::NoAdvice;
    /// use protobuf_edit::collect::groupless::Collector;
    /// use protobuf_edit::{DepthLimit, Standard};
    ///
    /// let mut advice = NoAdvice;
    /// let mut collector =
    ///     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    /// collector.feed(&[0x08, 0x2A]).unwrap();
    /// assert_eq!(collector.offset(), 2);
    /// ```
    pub fn new(standard: Standard, depth: DepthLimit, advice: &'a mut A) -> Self {
        Self {
            core: Some(Core {
                source: Vec::new(),
                rows: Vec::new(),
                zone: ROOT_ZONE,
                word: WordCarry::new(),
                state: ParseState::Live(Resume::Head),
                stack: Vec::with_capacity(frames_reserve(depth)),
                path: Vec::new(),
                nearest_absorber: None,
                root_len: None,
                standard,
                limit: depth,
                advice,
            }),
        }
    }

    /// [`Collector::new`] with one initial source reservation — the
    /// door for framed streams whose total length is known:
    /// provided the cumulative feeds stay within `capacity`, the
    /// backing never regrows and the whole job runs on a single
    /// physical source allocation. `capacity` is an initial
    /// reservation, not a bound — a stream that outgrows it stays
    /// lawful and regrows the backing like [`Collector::new`]'s.
    /// The row arena seeds from the same hint.
    ///
    /// # Errors
    ///
    /// [`CapacityOversize`] when the hint exceeds the coordinate
    /// class (`i32::MAX` bytes) — no admissible stream can fill
    /// such a reservation, so it refuses before allocating.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::collect::NoAdvice;
    /// use protobuf_edit::collect::groupless::Collector;
    /// use protobuf_edit::{DepthLimit, Standard};
    ///
    /// let mut advice = NoAdvice;
    /// let mut collector = Collector::with_capacity(
    ///     Standard::Tolerant,
    ///     DepthLimit::REFERENCE,
    ///     &mut advice,
    ///     2,
    /// )
    /// .unwrap();
    /// collector.feed(&[0x08, 0x2A]).unwrap();
    /// assert_eq!(collector.finish().bytes(), [0x08, 0x2A]);
    /// ```
    #[allow(
        clippy::as_conversions,
        reason = "usize capacities widen losslessly into the stream coordinate space"
    )]
    pub fn with_capacity(
        standard: Standard,
        depth: DepthLimit,
        advice: &'a mut A,
        source_capacity: usize,
    ) -> Result<Self, CapacityOversize> {
        if source_capacity > crate::admission::MAX {
            return Err(CapacityOversize::new(source_capacity as u64));
        }
        let mut collector = Self::new(standard, depth, advice);
        // The live gate is vacuous on a fresh shell.
        if let Some(core) = collector.core.as_mut() {
            core.source.reserve_exact(source_capacity);
            core.rows.reserve(rows_reserve(admitted_u32(source_capacity)));
        }
        Ok(collector)
    }

    /// The absolute stream offset: bytes accepted so far.
    ///
    /// # Panics
    ///
    /// After a returned [`FeedOversize`] — the shell is spent,
    /// terminal like every other face.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn offset(&self) -> u32 {
        let Some(core) = self.core.as_ref() else { panic!("collector already terminal") };
        core.pos()
    }

    /// Feeds one chunk: coordinate admission before any byte is
    /// read, one reservation, then the fused copy/parse loop. A
    /// chunk edge is never a fault — a word cut here resumes on
    /// the next feed, and only [`Collector::finish`] declares the
    /// end. A wire fault met mid-chunk is product data, not an
    /// error: the index clips and the whole chunk (and every later
    /// successful feed) is still absorbed into the source.
    ///
    /// # Errors
    ///
    /// [`FeedOversize`] when the chunk would run the stream past
    /// the coordinate class (`i32::MAX` bytes) — judged whole,
    /// before any byte of the chunk is read, prior feeds returned
    /// exactly and the shell spent. The gate runs on every feed,
    /// fault-tail collection included.
    ///
    /// # Panics
    ///
    /// After a returned [`FeedOversize`] — the stream is over;
    /// feeding again is a caller bug.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::collect::NoAdvice;
    /// use protobuf_edit::collect::groupless::Collector;
    /// use protobuf_edit::{DepthLimit, Standard};
    ///
    /// // A varint value split across three feeds.
    /// let mut advice = NoAdvice;
    /// let mut collector =
    ///     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    /// collector.feed(&[0x08]).unwrap();
    /// collector.feed(&[0x96]).unwrap();
    /// collector.feed(&[0x01]).unwrap();
    /// let tree = collector.finish();
    /// assert_eq!(tree.node_count(), 1);
    /// ```
    #[track_caller]
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), FeedOversize> {
        self.feed_capped(chunk, CAP)
    }

    /// The feed body under an explicit coordinate cap: the public
    /// door passes the admission class; module tests drive the
    /// same path with a small cap so the refusal arm is judged
    /// without a class-sized fixture.
    #[track_caller]
    #[allow(
        clippy::as_conversions,
        reason = "slice lengths cap at isize::MAX, so the widened sum stays in u64"
    )]
    fn feed_capped(&mut self, chunk: &[u8], cap: u64) -> Result<(), FeedOversize> {
        // The core leaves the shell for the whole feed: a refusal
        // spends the shell into the error, and an advisor unwind
        // caught by the caller finds the shell spent instead of a
        // half-updated parse — one move, outside the per-byte loop.
        let Some(mut core) = self.core.take() else { panic!("collector already terminal") };
        let attempted_end = core.source.len() as u64 + chunk.len() as u64;
        if attempted_end > cap {
            return Err(FeedOversize::new(core.source, attempted_end));
        }
        core.source.reserve(chunk.len());
        // Raise the row seed toward the stream seen so far (the
        // buffered parse's heuristic, as far as stream knowledge
        // permits). `attempted_end ≤ cap ≤ MAX` fits the class.
        let want = rows_reserve(attempted_end as u32);
        if core.rows.capacity() < want {
            core.rows.reserve(want - core.rows.len());
        }
        match core.standard {
            Standard::Tolerant => core.drive::<false>(chunk),
            Standard::CanonicalMinimal => core.drive::<true>(chunk),
        }
        self.core = Some(core);
        Ok(())
    }

    /// Declares the stream's end and seals the product — total: an
    /// end-of-stream judgment (a cut word, a short fixed payload,
    /// an underfilled root-layer LEN) becomes the product's fault,
    /// with the complete accumulated source beside it. No source
    /// byte is read again: the seal judges carried state, boxes
    /// the finished rows, and moves the source.
    ///
    /// # Panics
    ///
    /// After a returned [`FeedOversize`] — the shell is spent.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::collect::NoAdvice;
    /// use protobuf_edit::collect::groupless::{Collector, FaultKind};
    /// use protobuf_edit::{DepthLimit, Standard};
    ///
    /// // A root-layer LEN declares two body bytes; the stream
    /// // ends after one. The buffered verdict — the outer
    /// // overrun — stands, not the partial interior word.
    /// let mut advice = NoAdvice;
    /// let mut collector =
    ///     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    /// collector.feed(&[0x12, 0x02, 0x08]).unwrap();
    /// let tree = collector.finish();
    /// let fault = tree.fault().unwrap();
    /// assert_eq!(fault.at(), 1);
    /// assert!(matches!(fault.kind(), FaultKind::LenOverrun { zone_left: 1, .. }));
    /// assert_eq!(tree.bytes(), [0x12, 0x02, 0x08]);
    /// ```
    #[must_use]
    #[track_caller]
    pub fn finish(mut self) -> Retained {
        let Some(core) = self.core.take() else { panic!("collector already terminal") };
        core.seal()
    }

    /// Abandons the job and releases the accumulated backing — a
    /// move, zero copies. A word cut mid-flight needs no
    /// reconstruction: its bytes are already in the backing.
    ///
    /// # Panics
    ///
    /// After a returned [`FeedOversize`] — the source already left
    /// with the refusal.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::collect::NoAdvice;
    /// use protobuf_edit::collect::groupless::Collector;
    /// use protobuf_edit::{DepthLimit, Standard};
    ///
    /// let mut advice = NoAdvice;
    /// let mut collector =
    ///     Collector::new(Standard::Tolerant, DepthLimit::REFERENCE, &mut advice);
    /// collector.feed(&[0x08, 0x96]).unwrap(); // a value still in flight
    /// assert_eq!(collector.into_source(), [0x08, 0x96]);
    /// ```
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn into_source(mut self) -> Vec<u8> {
        let Some(core) = self.core.take() else { panic!("collector already terminal") };
        core.source
    }
}

#[cfg(test)]
mod tests;
