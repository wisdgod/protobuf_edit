//! The groupless survey: group codes are a capability refusal.
//!
//! Groupless toolchains survey their own traffic; a group code
//! (3 or 4) is well-formed wire *outside this language* — refusing
//! it is this dialect's correctness feature, typed distinctly from
//! the format's unassigned codes. One index walk builds a preorder
//! row table, the product is total past the supply (legal prefix +
//! at most one resident fault), and detection stays blind to
//! commitment. Zero source bytes are retained: opaque payloads are
//! skipped through the supply's own seek, and every scalar word is
//! banked in its row as the walk decodes it to step.
//!
//! Without groups the partition theorem strengthens: the delimiter
//! (only LEN's length prefix remains) always *precedes* the
//! payload, so both the record span and the payload span are one
//! branch-free formula.
//!
//! Coordinates: read · sequential-repeatable · offline · groupless · Standard (value-level).
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::survey::NoAdvice;
//! use protobuf_edit::survey::groupless::Survey;
//! use protobuf_edit::wire::FieldNumber;
//!
//! // varint f1=150 · LEN f2 "hi"
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut tree =
//!     Survey::open(SliceSource::new(&msg), DepthLimit::REFERENCE, &mut NoAdvice).unwrap();
//! assert!(tree.is_complete());
//!
//! let first = tree.top().next().unwrap();
//! assert_eq!(tree.varint_word(first), Some(150));
//!
//! // Payload bytes are a fetch, not a borrow: a later walk
//! // delivers them.
//! let field2 = FieldNumber::new(2).unwrap();
//! let hit = tree.top().by_field(field2).next().unwrap();
//! let mut payload = Vec::new();
//! tree.read_payload(hit, &mut payload).unwrap();
//! assert_eq!(payload, b"hi");
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::iter::FusedIterator;

use super::{Advice, Advisor, Ancestry, FetchFault, NodeId, OpenFault, Stage, mint};
use crate::replay_pump::{GrabRead, Pump, StepRead};
use crate::replay_source::{
    Handed, ReplayFault, ReplayPhase, ReplayWalk, SourceSpan, StableReplaySource, SupplyFault,
};
use crate::varint::WordWidth;
use crate::wire::groupless::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, FaultClass, Standard};

// ─── the law ───

/// A varint read refusal in whole-source coordinates: the carry
/// kernel's refusal alphabet with the boundary folded into the
/// cause.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadFault {
    /// The innermost sealed extent ended mid-construct.
    SealCut,
    /// The source ended mid-construct.
    SourceEnd,
    /// Ran past the domain window still continuing.
    TooWide,
    /// The terminal byte exceeds the domain class.
    OutOfClass,
}

/// One law violation: where, and which law.
///
/// `at`'s meaning per kind: a [`FaultKind::Read`] names the
/// refused construct's first byte, except that a
/// [`ReadFault::SealCut`] names the sealed endpoint and a
/// [`ReadFault::SourceEnd`] names the source end; truncation
/// kinds name the source end; structural kinds name the judgment
/// point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u64,
    kind: FaultKind,
}

impl Fault {
    /// The coordinate (whole-source byte offset).
    #[inline]
    #[must_use]
    pub const fn at(self) -> u64 {
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
        write!(f, "{} at source offset {}", self.kind, self.at)
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
/// record never reaches the row table, so its field number
/// travels with the fault — inside the [`Stage`] coordinate for
/// varint reads (the tag stage carries none: no field exists
/// yet), on the variant elsewhere. Group grammar variants do not
/// exist in this dialect's vocabulary — not unreachable, absent.
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
    /// A declared length punctures the enclosing seal.
    LenOverrun {
        /// The record's field number.
        field: FieldNumber,
        /// The declared payload length.
        declared: PayloadLen,
        /// Bytes actually left in the enclosing extent.
        zone_left: u64,
    },
    // ─ grammar: fixed value site ─
    /// The extent (or the source) ended inside a fixed-width
    /// payload.
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
    /// A tag wider than minimal ([`Survey::open_standard`] under
    /// [`Standard::CanonicalMinimal`] only; speculation absorbs
    /// it like any wire fault).
    NonMinimalTag,
    /// A length prefix wider than minimal (canonical walks only).
    NonMinimalLen {
        /// The record's field number.
        field: FieldNumber,
    },
    /// A value varint wider than minimal (canonical walks only).
    NonMinimalValue {
        /// The record's field number.
        field: FieldNumber,
    },
    // ─ capability: the dialect boundary and the coordinate space ─
    /// A tag carried a group code (3 or 4): well-formed wire
    /// outside this dialect's language — the capability refusal.
    GroupCode {
        /// The tag's field number.
        field: FieldNumber,
        /// The group code (3 or 4).
        code: Low3,
    },
    /// A declared length the coordinate space cannot host: the
    /// payload's end would land on (or past) the reserved
    /// sentinel coordinate.
    LenUnsatisfiable {
        /// The record's field number.
        field: FieldNumber,
        /// The declared payload length.
        declared: PayloadLen,
    },
}

impl FaultKind {
    /// The refusal's [`FaultClass`] — which repair the fault asks
    /// for. Policy membership names its configuration datum on
    /// the variant (the [`DepthLimit`] bound; the `NonMinimal*`
    /// family is the walk's declared [`Standard`]).
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
            Self::GroupCode { .. } | Self::LenUnsatisfiable { .. } => FaultClass::Capability,
        }
    }
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Read { stage, cause } => {
                match cause {
                    ReadFault::SealCut => f.write_str("the sealed extent ends inside ")?,
                    ReadFault::SourceEnd => f.write_str("the source ended inside ")?,
                    ReadFault::TooWide | ReadFault::OutOfClass => {}
                }
                let (window, class) = match stage {
                    Stage::Tag => {
                        f.write_str("a tag")?;
                        ("five", "u32 word class")
                    }
                    Stage::LenPrefix { field } => {
                        write!(f, "the length prefix of field {}", field.as_inner())?;
                        ("five", "length class")
                    }
                    Stage::Value { field } => {
                        write!(f, "the varint value of field {}", field.as_inner())?;
                        ("ten", "u64 class")
                    }
                };
                match cause {
                    ReadFault::SealCut | ReadFault::SourceEnd => Ok(()),
                    ReadFault::TooWide => write!(f, " continues past the {window}-byte window"),
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
            Self::LenUnsatisfiable { field, declared } => write!(
                f,
                "field {} declares {} payload bytes the coordinate space cannot host",
                field.as_inner(),
                declared.as_inner()
            ),
        }
    }
}

impl core::error::Error for FaultKind {}

// ─── the rows ───

/// One record, packed to 40 bytes. Private: the product projects
/// it.
///
/// Partition theorem: a record's bytes are `tag ⊎ delim ⊎
/// payload`; in this dialect the delimiter has one meaning —
/// LEN's length prefix, preceding the payload — and scalars carry
/// `None`. Both the record span and the payload span are one
/// branch-free formula. Widths are stored input facts: padding is
/// accepted and span arithmetic must reproduce it byte-exactly.
///
/// The word column banks every scalar's decoded value (varint
/// word, or fixed bits zero-extended): the walk decodes to step,
/// and a value answered from the row costs no source walk — the
/// scalar queries stay infallible where the resident twins
/// re-read on demand. LEN rows leave it zero.
#[derive(Clone, Copy)]
struct Row {
    /// Head tag's first byte (whole-source offset).
    start: u64,
    /// Payload extent. LEN: declared; Varint: the value's encoded
    /// width; I32/I64: 4/8.
    payload_len: u64,
    /// The scalar's decoded word (zero for LEN rows).
    word: u64,
    /// Enclosing container (`None`: root level — the niche is the
    /// sentinel, typed).
    parent: Option<NodeId>,
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

const _: () = assert!(core::mem::size_of::<Row>() == 40);
const _: () = assert!(core::mem::size_of::<Fault>() == 24);

impl Row {
    /// Widths as whole-source integers.
    const fn tag_w(&self) -> u64 {
        self.tag_width.as_inner() as u64
    }

    const fn delim_w(&self) -> u64 {
        match self.delim_width {
            Some(width) => width.as_inner() as u64,
            None => 0,
        }
    }

    /// The whole-record span (head tag through the record's last
    /// byte): every segment sits in wire order, one formula.
    const fn span(&self) -> SourceSpan {
        SourceSpan::new(self.start, self.start + self.tag_w() + self.delim_w() + self.payload_len)
    }

    /// The payload span. Branch-free: the delimiter always
    /// precedes the payload in this dialect (scalars store zero),
    /// so no kind dispatch exists.
    const fn payload_span(&self) -> SourceSpan {
        let start = self.start + self.tag_w() + self.delim_w();
        SourceSpan::new(start, start + self.payload_len)
    }
}

// ─── the product ───

/// Where a record's bytes lie in the source, split by role.
///
/// One call, kind-indexed: segments that do not exist for the
/// record's kind do not exist in the type (no group variants in
/// this dialect), and each variant's segments partition the
/// record's span exactly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordSpans {
    /// A varint record: head tag, value bytes.
    Varint {
        /// The head tag.
        tag: SourceSpan,
        /// The value bytes.
        value: SourceSpan,
    },
    /// A fixed 64-bit record: head tag, eight value bytes.
    I64 {
        /// The head tag.
        tag: SourceSpan,
        /// The value bytes.
        value: SourceSpan,
    },
    /// A LEN record: head tag, length prefix, payload.
    Len {
        /// The head tag.
        tag: SourceSpan,
        /// The length prefix.
        prefix: SourceSpan,
        /// The payload bytes.
        payload: SourceSpan,
    },
    /// A fixed 32-bit record: head tag, four value bytes.
    I32 {
        /// The head tag.
        tag: SourceSpan,
        /// The value bytes.
        value: SourceSpan,
    },
}

/// The survey product: the source handle and a preorder row table
/// measured over it, plus at most one resident fault.
///
/// A faulted product is not an error case — it is the legal
/// prefix, open containers clipped to the fault boundary, and the
/// fault. Rows hold whole-source coordinates and decoded scalar
/// words, never source bytes: the product's memory is a function
/// of record structure alone, and the source handle is kept only
/// to serve later fetch walks.
///
/// Node ids are plain indices in walk order, slice-style: passing
/// an id at or beyond [`node_count`](Self::node_count) panics.
/// `Option` returns carry domain answers, never id validation.
pub struct Survey<S: StableReplaySource> {
    source: S,
    rows: Box<[Row]>,
    /// End of the indexed prefix (clipped LEN rows keep their
    /// declared, sealed spans, which may extend past it). Equals
    /// the source's measured total length iff the walk consumed
    /// everything ([`is_complete`](Self::is_complete)).
    indexed_end: u64,
    fault: Option<Fault>,
}

impl<S: StableReplaySource> Survey<S> {
    /// Walks the source once and builds the index. Wire
    /// violations are product, not error ([`Survey::fault`]); the
    /// structured refusals are the supply's own and the machine's
    /// capability ceilings, each returning the source beside the
    /// mark.
    ///
    /// `advice` is consulted at every LEN record head (empty
    /// payloads included); `depth` bounds container nesting with
    /// no default.
    ///
    /// # Errors
    ///
    /// `(source, OpenFault)` — the source beside the mark — when
    /// the supply refuses mid-walk, the record count would leave
    /// the row-index class, or the offset would leave the
    /// coordinate space.
    ///
    /// # Examples
    ///
    /// A group code is this dialect's capability refusal:
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::replay_source::SliceSource;
    /// use protobuf_edit::survey::NoAdvice;
    /// use protobuf_edit::survey::groupless::{FaultKind, Survey};
    ///
    /// // An empty group of field 1 — well-formed wire outside
    /// // this language.
    /// let msg = [0x0B, 0x0C];
    /// let tree =
    ///     Survey::open(SliceSource::new(&msg), DepthLimit::REFERENCE, &mut NoAdvice).unwrap();
    /// let fault = tree.fault().unwrap();
    /// assert_eq!(fault.at(), 0);
    /// assert!(matches!(fault.kind(), FaultKind::GroupCode { .. }));
    /// ```
    pub fn open<A: Advisor>(
        source: S,
        depth: DepthLimit,
        advice: &mut A,
    ) -> Result<Self, (S, OpenFault<S::Error>)> {
        Self::open_standard(source, Standard::Tolerant, depth, advice)
    }

    /// [`Survey::open`] under a declared acceptance [`Standard`]:
    /// the standard picks a monomorphized engine instance once at
    /// this entry, so a tolerant walk pays no width comparison
    /// and a canonical one judges every varint word against its
    /// minimal encoding — the `NonMinimal*` faults, at the
    /// construct's first byte. Width storage is unchanged under
    /// both standards: rows keep actual input widths because span
    /// geometry needs them either way.
    ///
    /// # Errors
    ///
    /// As [`Survey::open`].
    pub fn open_standard<A: Advisor>(
        mut source: S,
        standard: Standard,
        depth: DepthLimit,
        advice: &mut A,
    ) -> Result<Self, (S, OpenFault<S::Error>)> {
        let outcome = match source.begin() {
            Ok(walk) => {
                let machine = Machine {
                    pump: Pump::new(walk),
                    nearest_absorber: None,
                    stack: Vec::with_capacity(usize::from(depth.as_inner()).min(16)),
                    path: Vec::new(),
                    rows: Vec::new(),
                    limit: depth,
                    advice,
                };
                match standard {
                    Standard::Tolerant => machine.run::<false>(),
                    Standard::CanonicalMinimal => machine.run::<true>(),
                }
            }
            Err(fault) => Err(OpenFault::Source(ReplayFault::Rewind {
                phase: ReplayPhase::Index,
                source: fault,
            })),
        };
        match outcome {
            Ok(parts) => Ok(Self {
                source,
                rows: parts.rows,
                indexed_end: parts.indexed_end,
                fault: parts.fault,
            }),
            Err(abort) => Err((source, abort)),
        }
    }

    /// The fault, if the committed zone stopped the walk early.
    #[inline]
    #[must_use]
    pub const fn fault(&self) -> Option<Fault> {
        self.fault
    }

    /// True when the whole source walked without a fault.
    #[inline]
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.fault.is_none()
    }

    /// End of the indexed prefix. Equals the source's measured
    /// total length iff [`is_complete`](Self::is_complete).
    #[inline]
    #[must_use]
    pub const fn indexed_end(&self) -> u64 {
        self.indexed_end
    }

    /// Releases the source handle. The index is dropped; spans
    /// and ids taken earlier remain plain numbers over the
    /// source's byte sequence.
    #[inline]
    #[must_use]
    pub fn into_source(self) -> S {
        self.source
    }

    /// Number of rows; valid ids are `0..node_count`.
    #[inline]
    #[must_use]
    #[allow(
        clippy::as_conversions,
        reason = "every push was admitted against the row-index class, which fits u32"
    )]
    pub const fn node_count(&self) -> u32 {
        self.rows.len() as u32
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
    /// `id` must be in-table: minted by this walk (row pushes,
    /// partition points) or read out of a row's parent link.
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
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
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
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
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
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[track_caller]
    pub fn ancestors(&self, id: NodeId) -> Ancestors<'_> {
        Ancestors { rows: &self.rows, cur: self.row(id).parent }
    }

    /// The record's field number.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[track_caller]
    pub fn field(&self, id: NodeId) -> FieldNumber {
        self.row(id).field
    }

    /// The record's wire kind.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn kind(&self, id: NodeId) -> RecordKind {
        self.row(id).kind
    }

    /// Iterates all records in walk (preorder) order.
    #[inline]
    pub const fn nodes(&self) -> Nodes<'_> {
        Nodes { next: 0, end: self.node_count(), _rows: core::marker::PhantomData }
    }

    /// Iterates `id`'s whole subtree, excluding `id` itself.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[track_caller]
    pub fn descendants(&self, id: NodeId) -> Nodes<'_> {
        let r = self.row(id);
        let first = id.as_inner() + 1;
        Nodes { next: first, end: first + r.descendants, _rows: core::marker::PhantomData }
    }

    /// The narrowest record whose span contains `pos` (`None`:
    /// the byte belongs to no indexed record).
    ///
    /// Preorder starts increase strictly, record spans nest or
    /// are disjoint (seals forbid partial overlap): binary search
    /// for the last start at or before `pos`, then walk the
    /// parent chain to the first containing span.
    #[inline]
    #[must_use]
    #[allow(
        clippy::as_conversions,
        reason = "a nonzero partition point over the row table fits the row-index class"
    )]
    pub fn narrowest(&self, pos: u64) -> Option<NodeId> {
        let started_before = self.rows.partition_point(|r| r.start <= pos);
        let mut cur = mint(started_before.checked_sub(1)? as u32);
        loop {
            // SAFETY: the first id is minted from a nonzero
            // partition point over the table; every later id is a
            // row's parent link, minted in-table by the walk.
            let r = unsafe { self.row_unchecked(cur) };
            if pos < r.span().end() {
                return Some(cur);
            }
            cur = r.parent?;
        }
    }

    // ─ spans ─

    /// The whole-record span (head tag through the record's last
    /// byte). A clipped LEN keeps its declared, sealed span.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[track_caller]
    pub fn span(&self, id: NodeId) -> SourceSpan {
        self.row(id).span()
    }

    /// The record's geometry: every segment in one kind-indexed
    /// answer. Widths are the stored input facts (padded
    /// encodings reproduce byte-exactly).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn source_spans(&self, id: NodeId) -> RecordSpans {
        let r = self.row(id);
        let tag = SourceSpan::new(r.start, r.start + r.tag_w());
        match r.kind {
            RecordKind::Varint => RecordSpans::Varint {
                tag,
                value: SourceSpan::new(tag.end(), tag.end() + r.payload_len),
            },
            RecordKind::I64 => RecordSpans::I64 {
                tag,
                value: SourceSpan::new(tag.end(), tag.end() + r.payload_len),
            },
            RecordKind::Len => {
                let prefix = SourceSpan::new(tag.end(), tag.end() + r.delim_w());
                RecordSpans::Len {
                    tag,
                    prefix,
                    payload: SourceSpan::new(prefix.end(), prefix.end() + r.payload_len),
                }
            }
            RecordKind::I32 => RecordSpans::I32 {
                tag,
                value: SourceSpan::new(tag.end(), tag.end() + r.payload_len),
            },
        }
    }

    // ─ words ─

    /// The varint value as a raw wire word (`None`: not a VARINT
    /// record), tolerant of the source's padding — answered from
    /// the row, no source walk. `crate::scalar` maps wire words
    /// to schema-typed values.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn varint_word(&self, id: NodeId) -> Option<u64> {
        let r = self.row(id);
        matches!(r.kind, RecordKind::Varint).then_some(r.word)
    }

    /// The eight little-endian payload bytes as raw bits (`None`:
    /// not an I64 record) — answered from the row, no source
    /// walk. `crate::scalar` interprets them.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn i64_bits(&self, id: NodeId) -> Option<u64> {
        let r = self.row(id);
        matches!(r.kind, RecordKind::I64).then_some(r.word)
    }

    /// The four little-endian payload bytes as raw bits (`None`:
    /// not an I32 record) — answered from the row, no source
    /// walk. `crate::scalar` interprets them.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[inline]
    #[must_use]
    #[track_caller]
    #[allow(
        clippy::as_conversions,
        reason = "an I32 row's word column was banked from four bytes, so it fits u32"
    )]
    pub fn i32_bits(&self, id: NodeId) -> Option<u32> {
        let r = self.row(id);
        matches!(r.kind, RecordKind::I32).then_some(r.word as u32)
    }

    // ─ fetch faces ─

    /// The payload extent behind every fetch face, judged against
    /// the indexed prefix (the index walk never proved bytes past
    /// it, so no fetch reads them).
    fn fetch_span<E>(&self, id: NodeId) -> Result<SourceSpan, FetchFault<E>> {
        let span = self.row(id).payload_span();
        if span.end() > self.indexed_end {
            return Err(FetchFault::Incomplete { at: self.indexed_end });
        }
        Ok(span)
    }

    /// Reads the record's payload bytes into `out` (appended; the
    /// buffer truncates back to its entry length on any refusal —
    /// never poisoned, a retry is lawful). One fetch walk,
    /// verifying only that the source still reaches the extent's
    /// end: bytes that moved beneath unchanged coordinates are
    /// appended as they now read (the provider's byte-identity
    /// obligation, not a fetch judgment).
    ///
    /// # Errors
    ///
    /// [`FetchFault::Incomplete`] for an extent past the indexed
    /// prefix, [`FetchFault::Oversize`] for one past the address
    /// space, [`FetchFault::Torn`] when the source ends before a
    /// measured coordinate, [`FetchFault::Source`] for the
    /// supply's own refusals. On `Err`, `out` is byte-identical
    /// to entry.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[track_caller]
    pub fn read_payload(
        &mut self,
        id: NodeId,
        out: &mut Vec<u8>,
    ) -> Result<(), FetchFault<S::Error>> {
        let span = self.fetch_span(id)?;
        #[allow(
            clippy::as_conversions,
            reason = "usize::MAX widens losslessly to u64 for the ceiling judgment"
        )]
        if span.len() > usize::MAX as u64 {
            return Err(FetchFault::Oversize { len: span.len() });
        }
        let mark = out.len();
        #[allow(
            clippy::as_conversions,
            reason = "the extent was just judged to fit the address space"
        )]
        out.reserve(span.len() as usize);
        let outcome = fetch_extent(&mut self.source, span, |bytes| out.extend_from_slice(bytes));
        if let Err(handed) = outcome {
            out.truncate(mark);
            return Err(handed.fault);
        }
        Ok(())
    }

    /// Hands the record's payload bytes to `sink` as borrowed
    /// views, in order — the unbounded-extent face. One fetch
    /// walk, verifying only that the source still reaches the
    /// extent's end: bytes that moved beneath unchanged
    /// coordinates are handed as they now read (the provider's
    /// byte-identity obligation, not a fetch judgment).
    ///
    /// # Errors
    ///
    /// As [`Survey::read_payload`] minus the address-space
    /// ceiling; the refusal rides beside the exact byte count
    /// already handed over ([`Handed`]) — the prefix carries no
    /// validity promise.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[track_caller]
    pub fn payload_sink(
        &mut self,
        id: NodeId,
        sink: impl FnMut(&[u8]),
    ) -> Result<(), Handed<FetchFault<S::Error>>> {
        let span = match self.fetch_span(id) {
            Ok(span) => span,
            Err(fault) => return Err(Handed { handed: 0, fault }),
        };
        fetch_extent(&mut self.source, span, sink)
    }

    /// Hands many records' payload bytes to `sink`, each view
    /// tagged with its request's id — one source-ordered fetch
    /// walk for all of them, the face that makes k scattered
    /// reads cost one walk instead of k. Nested and overlapping
    /// extents are lawful: a byte covered by several requests is
    /// handed to each. The walk verifies only that the source
    /// still reaches each extent's end: bytes that moved beneath
    /// unchanged coordinates are handed as they now read (the
    /// provider's byte-identity obligation, not a fetch
    /// judgment).
    ///
    /// Requests are validated whole before the walk starts;
    /// delivery order is source order (by extent start,
    /// enclosing-first on ties), not argument order.
    ///
    /// # Errors
    ///
    /// As [`Survey::payload_sink`]; `handed` sums the bytes
    /// delivered across all requests before the refusal.
    ///
    /// # Panics
    ///
    /// Panics if any id `>= self.node_count()` — node ids are
    /// slice-style indices into this product.
    #[track_caller]
    pub fn fetch_payloads(
        &mut self,
        ids: &[NodeId],
        mut sink: impl FnMut(NodeId, &[u8]),
    ) -> Result<(), Handed<FetchFault<S::Error>>> {
        let mut requests = Vec::with_capacity(ids.len());
        for &id in ids {
            let span = match self.fetch_span(id) {
                Ok(span) => span,
                Err(fault) => return Err(Handed { handed: 0, fault }),
            };
            if !span.is_empty() {
                requests.push((span.start(), span.end(), id));
            }
        }
        requests.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

        let walk = match self.source.begin() {
            Ok(walk) => walk,
            Err(fault) => {
                return Err(Handed {
                    handed: 0,
                    fault: FetchFault::Source(ReplayFault::Rewind {
                        phase: ReplayPhase::Fetch,
                        source: fault,
                    }),
                });
            }
        };
        let mut pump = Pump::new(walk);
        let mut handed = 0u64;
        let fail = |pump: &Pump<S::Walk<'_>>, handed: u64, supply: SupplyFault<S::Error>| Handed {
            handed,
            fault: FetchFault::Source(ReplayFault::Read {
                phase: ReplayPhase::Fetch,
                at: pump.off,
                source: supply,
            }),
        };

        let mut active: Vec<(u64, NodeId)> = Vec::new();
        let mut next = 0usize;
        loop {
            if active.is_empty() {
                let Some(&(start, _, _)) = requests.get(next) else {
                    return Ok(());
                };
                let owed = start - pump.off;
                match pump.skip_bytes(owed) {
                    Ok(advanced) if advanced == owed => {}
                    Ok(_) => return Err(Handed { handed, fault: FetchFault::Torn { at: start } }),
                    Err(supply) => return Err(fail(&pump, handed, supply)),
                }
            }
            while let Some(&(start, end, id)) = requests.get(next) {
                if start > pump.off {
                    break;
                }
                active.push((end, id));
                next += 1;
            }
            // The nearest boundary: the closest active end or the
            // next request's start, whichever comes first.
            let mut boundary = active.iter().map(|&(end, _)| end).min().unwrap_or(u64::MAX);
            if let Some(&(start, _, _)) = requests.get(next) {
                boundary = boundary.min(start);
            }
            let owed = boundary - pump.off;
            let outcome = pump.copy_bytes(owed, |bytes| {
                for &(_, id) in &active {
                    sink(id, bytes);
                }
                #[allow(
                    clippy::as_conversions,
                    reason = "view lengths widen losslessly into byte counts"
                )]
                {
                    handed += (bytes.len() * active.len()) as u64;
                }
            });
            match outcome {
                Ok(advanced) if advanced == owed => {}
                Ok(_) => return Err(Handed { handed, fault: FetchFault::Torn { at: boundary } }),
                Err(supply) => return Err(fail(&pump, handed, supply)),
            }
            active.retain(|&(end, _)| end > boundary);
        }
    }
}

/// One fetch walk over one extent: begin, seek, deliver — the
/// single-handle faces' shared engine.
fn fetch_extent<S: StableReplaySource>(
    source: &mut S,
    span: SourceSpan,
    mut deliver: impl FnMut(&[u8]),
) -> Result<(), Handed<FetchFault<S::Error>>> {
    if span.is_empty() {
        return Ok(());
    }
    let walk = match source.begin() {
        Ok(walk) => walk,
        Err(fault) => {
            return Err(Handed {
                handed: 0,
                fault: FetchFault::Source(ReplayFault::Rewind {
                    phase: ReplayPhase::Fetch,
                    source: fault,
                }),
            });
        }
    };
    let mut pump = Pump::new(walk);
    let mut handed = 0u64;
    match pump.skip_bytes(span.start()) {
        Ok(advanced) if advanced == span.start() => {}
        Ok(_) => return Err(Handed { handed: 0, fault: FetchFault::Torn { at: span.start() } }),
        Err(supply) => {
            return Err(Handed {
                handed: 0,
                fault: FetchFault::Source(ReplayFault::Read {
                    phase: ReplayPhase::Fetch,
                    at: pump.off,
                    source: supply,
                }),
            });
        }
    }
    let outcome = pump.copy_bytes(span.len(), |bytes| {
        deliver(bytes);
        #[allow(clippy::as_conversions, reason = "view lengths widen losslessly into byte counts")]
        {
            handed += bytes.len() as u64;
        }
    });
    match outcome {
        Ok(advanced) if advanced == span.len() => Ok(()),
        Ok(_) => Err(Handed { handed, fault: FetchFault::Torn { at: span.end() } }),
        Err(supply) => Err(Handed {
            handed,
            fault: FetchFault::Source(ReplayFault::Read {
                phase: ReplayPhase::Fetch,
                at: pump.off,
                source: supply,
            }),
        }),
    }
}

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
    /// Narrows to the records of one field, preserving wire
    /// order. A field with no records in the run yields nothing.
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
        // range, whose rows the walk physically pushed.
        let descendants =
            unsafe { self.rows.get_unchecked(crate::admission::usize_of(id)) }.descendants;
        self.next = id + 1 + descendants;
        Some(mint(id))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Nonempty runs yield at least one sibling; each sibling
        // occupies at least one row, bounding from above.
        let width = crate::admission::usize_of(self.end.saturating_sub(self.next));
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
        // in-table by the walk.
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
/// ([`Survey::nodes`]) or one subtree ([`Survey::descendants`]) —
/// two demands, one shape. Exact: the range width is the count.
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
        let n = crate::admission::usize_of(self.end - self.next);
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

/// One open LEN extent — the only container this dialect has, so
/// the frame needs no kind vocabulary. The frame simultaneously
/// carries the parent link (`row`), the open field, and the
/// restore state for the two live registers (the pump's zone,
/// [`Machine::nearest_absorber`]) — pushing saves them, popping
/// restores them, and no walk ever recomputes them.
#[derive(Clone, Copy)]
struct Frame {
    row: NodeId,
    /// The open container's field (what the machine lends to
    /// [`Ancestry`]).
    field: FieldNumber,
    /// The enclosing extent's end, restored on close.
    prev_zone: u64,
    /// The enclosing nearest-absorber register, restored on
    /// close.
    prev_absorber: Option<usize>,
}

/// A judged violation, plus where the uncommitted transaction
/// began (`cut`): clipping uses `cut`, so a container never
/// swallows the bad record's tag bytes.
struct Failure {
    fault: Fault,
    cut: u64,
}

/// What the index walk hands back for the product to own beside
/// the source handle.
struct Parts {
    rows: Box<[Row]>,
    indexed_end: u64,
    fault: Option<Fault>,
}

/// One record-step's control flow.
enum Flow {
    /// The record landed (or a refusal was absorbed); walk on.
    Continue,
    /// The walk's clean end at the root.
    Finished,
}

/// Detection is blind to commitment: judgment code reads bytes,
/// bounds, and grammar state, never the absorber register —
/// disposition alone reads it.
struct Machine<'v, W: ReplayWalk, A: Advisor> {
    pump: Pump<W>,
    /// Stack index of the innermost `Advice::Speculate` LEN (the
    /// frame a speculation failure unwinds to), maintained by
    /// open and close for an O(1) dispose. `Commit` frames are
    /// not absorbing, and the root is implicitly committed.
    nearest_absorber: Option<usize>,
    stack: Vec<Frame>,
    /// The open containers' fields, materialized lazily from the
    /// frame stack when an advisor is consulted; closes truncate
    /// it back in step.
    path: Vec<FieldNumber>,
    rows: Vec<Row>,
    limit: DepthLimit,
    advice: &'v mut A,
}

/// A walk-stopping outcome: a committed-zone failure clips the
/// product; an abort is not a document property and returns
/// custody instead.
enum Stop<E> {
    Clip(Failure),
    Abort(OpenFault<E>),
}

impl<W: ReplayWalk, A: Advisor> Machine<'_, W, A> {
    fn parent_row(&self) -> Option<NodeId> {
        self.stack.last().map(|f| f.row)
    }

    /// One frame per nesting level: the frame count is the depth.
    fn at_depth_limit(&self) -> bool {
        self.stack.len() >= usize::from(self.limit.as_inner())
    }

    /// Consults the advisor, materializing the enclosing fields
    /// it is owed. Amortized O(1): each frame's field is copied
    /// at most once per residency on the stack.
    fn consult(&mut self, field: FieldNumber) -> Advice {
        if self.path.len() < self.stack.len() {
            self.path.extend(self.stack[self.path.len()..].iter().map(|f| f.field));
        }
        self.advice.advise(Ancestry::new(&self.path), field)
    }

    /// Pushes an open LEN and saves the live registers in it.
    fn open(&mut self, row: NodeId, field: FieldNumber, zone: u64, absorbing: bool) {
        self.stack.push(Frame {
            row,
            field,
            prev_zone: self.pump.zone,
            prev_absorber: self.nearest_absorber,
        });
        self.pump.zone = zone;
        if absorbing {
            self.nearest_absorber = Some(self.stack.len() - 1);
        }
    }

    /// Terminal write of a closing container: its subtree is
    /// exactly the rows pushed since it.
    #[allow(
        clippy::as_conversions,
        reason = "every push was admitted against the row-index class, so the count fits u32"
    )]
    fn seal_descendants(&mut self, row: NodeId) {
        let idx = row.index();
        let descendants = (self.rows.len() - 1 - idx) as u32;
        // SAFETY: frame rows are in-table (minted before the frame
        // pushed and never truncated while it lives).
        unsafe { self.rows.get_unchecked_mut(idx) }.descendants = descendants;
    }

    /// Closes the frame the extent end popped. Infallible: this
    /// dialect has no construct an extent end can leave
    /// unterminated.
    fn close_frame(&mut self, frame: Frame) {
        self.seal_descendants(frame.row);
        self.pump.zone = frame.prev_zone;
        self.nearest_absorber = frame.prev_absorber;
        self.path.truncate(self.stack.len());
    }

    /// Disposes of a judged failure: unwind to the nearest
    /// absorbing frame (the speculation this failure concludes as
    /// "bytes") and skip to its payload end — the source is never
    /// re-read — or stop for the clip. Unwind is truncation:
    /// `descendants` is written only at close, so no written
    /// state needs repair.
    fn dispose(&mut self, failure: Failure) -> Result<(), Stop<W::Error>> {
        let Some(idx) = self.nearest_absorber else {
            return Err(Stop::Clip(failure));
        };
        let absorber = self.stack[idx];
        // The absorber's own zone end: the live zone while it was
        // innermost — the frame above it saved that as
        // `prev_zone`.
        let own_zone = self.stack.get(idx + 1).map_or(self.pump.zone, |above| above.prev_zone);
        // The demoted LEN keeps its row (a sealed leaf:
        // descendants stayed 0, its declared span is an input
        // fact); everything it speculated over — rows, inner
        // frames, conditional Message promises — evaporates.
        self.rows.truncate(absorber.row.index() + 1);
        self.pump.zone = absorber.prev_zone;
        self.nearest_absorber = absorber.prev_absorber;
        self.stack.truncate(idx);
        self.path.truncate(idx);
        self.pump.clear_construct();
        // The rest of the absorbed payload is never read: skip to
        // its end. A short skip is the source ending inside the
        // extent — truncation, terminal (every enclosing extent
        // overruns the same end; the demoted row is the innermost
        // overrun candidate).
        let owed = own_zone - self.pump.off;
        match self.pump.skip_bytes(owed) {
            Ok(advanced) if advanced == owed => Ok(()),
            Ok(_) => {
                let fallback = Failure {
                    fault: Fault {
                        at: self.pump.off,
                        kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SourceEnd },
                    },
                    cut: self.pump.off,
                };
                Err(Stop::Clip(self.eof_clip(Some(absorber.row), fallback)))
            }
            Err(supply) => Err(Stop::Abort(self.supply_abort(supply))),
        }
    }

    /// The source ended while extents were still owed bytes — the
    /// truncation disposition, attributed as the buffered twin
    /// attributes it: an open LEN whose extent overruns the
    /// source's actual end is refused *at its open* (the resident
    /// parse would never have entered it), so the outermost such
    /// frame's record is dropped whole and quoted as the overrun.
    /// `overrun_row` names an extent-owning row that is not (or no
    /// longer) on the stack — a skipped opaque LEN, a demoted
    /// absorber — the innermost fallback when no frame is open.
    /// Without any open LEN the `fallback` failure stands.
    #[cold]
    #[allow(
        clippy::as_conversions,
        reason = "a LEN row's payload length was minted from the length class, so it \
                  narrows back losslessly"
    )]
    fn eof_clip(&mut self, overrun_row: Option<NodeId>, fallback: Failure) -> Failure {
        let Some(target) = self.stack.first().map(|frame| frame.row).or(overrun_row) else {
            return fallback;
        };
        // SAFETY: frame rows and the caller's overrun row are
        // in-table (minted by this walk; dispose truncates above
        // the absorber's own row).
        let row = *unsafe { self.row_at(target) };
        let payload_start = row.start + row.tag_w() + row.delim_w();
        // SAFETY: the row is a LEN (frames and the named fallbacks
        // are LEN rows), so its payload length was minted from a
        // `PayloadLen` and narrows back into the class.
        let declared = unsafe { PayloadLen::new_unchecked(row.payload_len as u32) };
        self.rows.truncate(target.index());
        // Every open frame sits at or inside the dropped record
        // (the target is the outermost frame when any is open), so
        // no frame survives to seal.
        self.stack.clear();
        Failure {
            fault: Fault {
                at: row.start + row.tag_w(),
                kind: FaultKind::LenOverrun {
                    field: row.field,
                    declared,
                    zone_left: self.pump.off - payload_start,
                },
            },
            cut: row.start,
        }
    }

    /// The row behind an internally proven id.
    ///
    /// # Safety
    /// `id` must be in-table.
    unsafe fn row_at(&self, id: NodeId) -> &Row {
        // SAFETY: the caller's proof, restated.
        unsafe { self.rows.get_unchecked(id.index()) }
    }

    /// Wraps a mid-walk supply refusal with the index phase and
    /// the first unread offset.
    #[cold]
    const fn supply_abort(&self, supply: SupplyFault<W::Error>) -> OpenFault<W::Error> {
        OpenFault::Source(ReplayFault::Read {
            phase: ReplayPhase::Index,
            at: self.pump.off,
            source: supply,
        })
    }

    /// Fault disposition sinks: the fault value takes shape here,
    /// off the walk's hot dispatch — only judged scalars cross
    /// the call.
    #[cold]
    fn halt(&mut self, at: u64, cut: u64, kind: FaultKind) -> Result<(), Stop<W::Error>> {
        self.dispose(Failure { fault: Fault { at, kind }, cut })
    }

    /// A varint read refusal at a stage, sunk like
    /// [`Self::halt`].
    #[cold]
    fn halt_read(
        &mut self,
        at: u64,
        cut: u64,
        stage: Stage,
        cause: ReadFault,
    ) -> Result<(), Stop<W::Error>> {
        self.halt(at, cut, FaultKind::Read { stage, cause })
    }

    /// Books one row, admitted against the row-index class.
    #[allow(
        clippy::as_conversions,
        reason = "the push was just admitted against the row-index class, which fits u32"
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "the arguments are one row's columns, spelled once at the one mint"
    )]
    fn push_row(
        &mut self,
        at: u64,
        field: FieldNumber,
        kind: RecordKind,
        tag_width: WordWidth,
        payload_len: u64,
        delim_width: Option<WordWidth>,
        word: u64,
    ) -> Result<NodeId, Stop<W::Error>> {
        if self.rows.len() > NodeId::MAX.index() {
            return Err(Stop::Abort(OpenFault::IndexOverflow { at }));
        }
        let id = mint(self.rows.len() as u32);
        self.rows.push(Row {
            start: at,
            payload_len,
            word,
            parent: self.parent_row(),
            descendants: 0,
            field,
            kind,
            tag_width,
            delim_width,
        });
        Ok(id)
    }

    /// Books one leaf row, its id unneeded — the scalar and
    /// opaque sites' face over [`Self::push_row`].
    #[allow(
        clippy::too_many_arguments,
        reason = "the arguments are one row's columns, spelled once at the one mint"
    )]
    fn push_leaf(
        &mut self,
        at: u64,
        field: FieldNumber,
        kind: RecordKind,
        tag_width: WordWidth,
        payload_len: u64,
        delim_width: Option<WordWidth>,
        word: u64,
    ) -> Result<(), Stop<W::Error>> {
        self.push_row(at, field, kind, tag_width, payload_len, delim_width, word).map(drop)
    }

    fn run<const MINIMAL: bool>(mut self) -> Result<Parts, OpenFault<W::Error>> {
        loop {
            debug_assert!(self.pump.off <= self.pump.zone);
            if self.pump.off == self.pump.zone {
                // The root zone is the unreachable sentinel, so a
                // met endpoint always has a frame to close.
                let Some(frame) = self.stack.pop() else {
                    unreachable!("the root zone is the coordinate space's sentinel")
                };
                self.close_frame(frame);
                continue;
            }
            match self.record::<MINIMAL>() {
                Ok(Flow::Continue) => {}
                Ok(Flow::Finished) => return Ok(self.finish(None)),
                Err(Stop::Clip(failure)) => return Ok(self.clip(failure)),
                Err(Stop::Abort(abort)) => return Err(abort),
            }
        }
    }

    /// Walks exactly one record at the cursor — or disposes of
    /// the judgment that refused it. One instance per acceptance
    /// standard: the tolerant instance folds every minimality
    /// test away.
    fn record<const MINIMAL: bool>(&mut self) -> Result<Flow, Stop<W::Error>> {
        const fn standard(minimal: bool) -> Standard {
            if minimal { Standard::CanonicalMinimal } else { Standard::Tolerant }
        }
        let std = const { standard(MINIMAL) };

        let at = self.pump.off;
        let (word, tag_width) = match self.pump.step_tag(std) {
            StepRead::Done { value, width } => (value, width),
            StepRead::End => {
                // Clean only at the root: an open LEN owes bytes,
                // and the outermost one's declared extent is the
                // lie the resident parse would have refused at its
                // open.
                if self.stack.is_empty() {
                    return Ok(Flow::Finished);
                }
                let fallback = Failure {
                    fault: Fault {
                        at: self.pump.off,
                        kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SourceEnd },
                    },
                    cut: self.pump.off,
                };
                return Err(Stop::Clip(self.eof_clip(None, fallback)));
            }
            StepRead::SealCut => {
                let start = self.pump.construct_start();
                self.halt_read(self.pump.off, start, Stage::Tag, ReadFault::SealCut)?;
                return Ok(Flow::Continue);
            }
            StepRead::SourceEnd => {
                let fallback = Failure {
                    fault: Fault {
                        at: self.pump.off,
                        kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SourceEnd },
                    },
                    cut: self.pump.construct_start(),
                };
                return Err(Stop::Clip(self.eof_clip(None, fallback)));
            }
            StepRead::TooWide => {
                let start = self.pump.construct_start();
                self.halt_read(start, start, Stage::Tag, ReadFault::TooWide)?;
                return Ok(Flow::Continue);
            }
            StepRead::OutOfClass => {
                let start = self.pump.construct_start();
                self.halt_read(start, start, Stage::Tag, ReadFault::OutOfClass)?;
                return Ok(Flow::Continue);
            }
            StepRead::NonMinimal { width } => {
                let start = self.pump.off - u64::from(width.w());
                self.halt(start, start, FaultKind::NonMinimalTag)?;
                return Ok(Flow::Continue);
            }
            StepRead::Exhausted => {
                return Err(Stop::Abort(OpenFault::OffsetExhausted { at: self.pump.off }));
            }
            StepRead::Fault(supply) => return Err(Stop::Abort(self.supply_abort(supply))),
        };

        // Field zero is an identity judgment on the whole tag word
        // and precedes any kind judgment.
        let low3 = Low3::from_word(word);
        let Some(field) = FieldNumber::from_word(word) else {
            self.halt(at, at, FaultKind::FieldZero { code: low3 })?;
            return Ok(Flow::Continue);
        };
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                self.varint_record::<MINIMAL>(at, field, tag_width)?;
            }
            TagClass::Record(kind @ (RecordKind::I64 | RecordKind::I32)) => {
                self.fixed_record(at, field, kind, tag_width)?;
            }
            TagClass::Record(RecordKind::Len) => {
                self.len_record::<MINIMAL>(at, field, tag_width)?;
            }
            TagClass::GroupCode => self.halt(at, at, FaultKind::GroupCode { field, code: low3 })?,
            TagClass::Unassigned => {
                self.halt(at, at, FaultKind::Unassigned { field, code: low3 })?;
            }
        }
        Ok(Flow::Continue)
    }

    /// VARINT: the walk decodes the value to step, so the row
    /// banks it — the scalar query then costs no source walk.
    fn varint_record<const MINIMAL: bool>(
        &mut self,
        at: u64,
        field: FieldNumber,
        tag_width: WordWidth,
    ) -> Result<(), Stop<W::Error>> {
        let std = if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant };
        let after_tag = self.pump.off;
        let (value, width) = match self.pump.step_value(std) {
            StepRead::Done { value, width } => (value, width),
            StepRead::SealCut => {
                return self.halt_read(
                    self.pump.off,
                    at,
                    Stage::Value { field },
                    ReadFault::SealCut,
                );
            }
            StepRead::SourceEnd => {
                let fallback = Failure {
                    fault: Fault {
                        at: self.pump.off,
                        kind: FaultKind::Read {
                            stage: Stage::Value { field },
                            cause: ReadFault::SourceEnd,
                        },
                    },
                    cut: at,
                };
                return Err(Stop::Clip(self.eof_clip(None, fallback)));
            }
            StepRead::TooWide => {
                return self.halt_read(after_tag, at, Stage::Value { field }, ReadFault::TooWide);
            }
            StepRead::OutOfClass => {
                return self.halt_read(
                    after_tag,
                    at,
                    Stage::Value { field },
                    ReadFault::OutOfClass,
                );
            }
            StepRead::NonMinimal { .. } => {
                return self.halt(after_tag, at, FaultKind::NonMinimalValue { field });
            }
            StepRead::End => unreachable!("interior steps judge a walk end as SourceEnd"),
            StepRead::Exhausted => {
                return Err(Stop::Abort(OpenFault::OffsetExhausted { at: self.pump.off }));
            }
            StepRead::Fault(supply) => return Err(Stop::Abort(self.supply_abort(supply))),
        };
        self.push_leaf(
            at,
            field,
            RecordKind::Varint,
            tag_width,
            u64::from(width.w()),
            None,
            value,
        )?;
        Ok(())
    }

    fn fixed_record(
        &mut self,
        at: u64,
        field: FieldNumber,
        kind: RecordKind,
        tag_width: WordWidth,
    ) -> Result<(), Stop<W::Error>> {
        let needed: u8 = if matches!(kind, RecordKind::I64) { 8 } else { 4 };
        let after_tag = self.pump.off;
        if self.pump.zone - self.pump.off < u64::from(needed) {
            return self.halt(after_tag, at, FaultKind::FixedTruncated { field, needed });
        }
        let grabbed = if matches!(kind, RecordKind::I64) {
            match self.pump.grab_fixed::<8>() {
                GrabRead::Done(value) => Some(u64::from_le_bytes(value)),
                GrabRead::SourceEnd => None,
                GrabRead::Exhausted => {
                    return Err(Stop::Abort(OpenFault::OffsetExhausted { at: self.pump.off }));
                }
                GrabRead::Fault(supply) => return Err(Stop::Abort(self.supply_abort(supply))),
            }
        } else {
            match self.pump.grab_fixed::<4>() {
                GrabRead::Done(value) => Some(u64::from(u32::from_le_bytes(value))),
                GrabRead::SourceEnd => None,
                GrabRead::Exhausted => {
                    return Err(Stop::Abort(OpenFault::OffsetExhausted { at: self.pump.off }));
                }
                GrabRead::Fault(supply) => return Err(Stop::Abort(self.supply_abort(supply))),
            }
        };
        let Some(word) = grabbed else {
            let fallback = Failure {
                fault: Fault { at: after_tag, kind: FaultKind::FixedTruncated { field, needed } },
                cut: at,
            };
            return Err(Stop::Clip(self.eof_clip(None, fallback)));
        };
        self.push_leaf(at, field, kind, tag_width, u64::from(needed), None, word)?;
        Ok(())
    }

    fn len_record<const MINIMAL: bool>(
        &mut self,
        at: u64,
        field: FieldNumber,
        tag_width: WordWidth,
    ) -> Result<(), Stop<W::Error>> {
        let std = if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant };
        let after_tag = self.pump.off;
        let (declared, prefix_width) = match self.pump.step_len(std) {
            StepRead::Done { value, width } => (value, width),
            StepRead::SealCut => {
                return self.halt_read(
                    self.pump.off,
                    at,
                    Stage::LenPrefix { field },
                    ReadFault::SealCut,
                );
            }
            StepRead::SourceEnd => {
                let fallback = Failure {
                    fault: Fault {
                        at: self.pump.off,
                        kind: FaultKind::Read {
                            stage: Stage::LenPrefix { field },
                            cause: ReadFault::SourceEnd,
                        },
                    },
                    cut: at,
                };
                return Err(Stop::Clip(self.eof_clip(None, fallback)));
            }
            StepRead::TooWide => {
                return self.halt_read(
                    after_tag,
                    at,
                    Stage::LenPrefix { field },
                    ReadFault::TooWide,
                );
            }
            StepRead::OutOfClass => {
                return self.halt_read(
                    after_tag,
                    at,
                    Stage::LenPrefix { field },
                    ReadFault::OutOfClass,
                );
            }
            StepRead::NonMinimal { .. } => {
                return self.halt(after_tag, at, FaultKind::NonMinimalLen { field });
            }
            StepRead::End => unreachable!("interior steps judge a walk end as SourceEnd"),
            StepRead::Exhausted => {
                return Err(Stop::Abort(OpenFault::OffsetExhausted { at: self.pump.off }));
            }
            StepRead::Fault(supply) => return Err(Stop::Abort(self.supply_abort(supply))),
        };
        let declared64 = u64::from(declared.as_inner());
        // The seal judgment: inside a seal the declared extent
        // must fit it; at the unbounded root the coordinate space
        // itself is the ceiling.
        if self.pump.zone == u64::MAX {
            if declared64 > (u64::MAX - 1) - self.pump.off {
                return self.halt(at, at, FaultKind::LenUnsatisfiable { field, declared });
            }
        } else if declared64 > self.pump.zone - self.pump.off {
            let zone_left = self.pump.zone - self.pump.off;
            return self.halt(after_tag, at, FaultKind::LenOverrun { field, declared, zone_left });
        }
        let payload_end = self.pump.off + declared64;
        let advice = self.consult(field);
        match advice {
            Advice::Opaque => self.opaque_len(at, field, tag_width, declared, prefix_width),
            Advice::Speculate if self.at_depth_limit() => {
                // Too deep to speculate: demote to opaque — not a
                // document fault (the bytes may well be bytes).
                self.opaque_len(at, field, tag_width, declared, prefix_width)
            }
            Advice::Commit if self.at_depth_limit() => {
                self.halt(at, at, FaultKind::DepthExceeded { field, limit: self.limit })
            }
            Advice::Speculate | Advice::Commit => {
                let absorbing = matches!(advice, Advice::Speculate);
                let row = self.push_row(
                    at,
                    field,
                    RecordKind::Len,
                    tag_width,
                    declared64,
                    Some(prefix_width),
                    0,
                )?;
                self.open(row, field, payload_end, absorbing);
                Ok(())
            }
        }
    }

    /// An opaque LEN: the row lands, the payload is skipped
    /// through the supply's own seek — never lent, never read. A
    /// short skip is the source ending inside the extent —
    /// truncation, terminal, attributed to the outermost
    /// overrunning extent (this row when nothing encloses it).
    fn opaque_len(
        &mut self,
        at: u64,
        field: FieldNumber,
        tag_width: WordWidth,
        declared: PayloadLen,
        prefix_width: WordWidth,
    ) -> Result<(), Stop<W::Error>> {
        let declared64 = u64::from(declared.as_inner());
        let row = self.push_row(
            at,
            field,
            RecordKind::Len,
            tag_width,
            declared64,
            Some(prefix_width),
            0,
        )?;
        match self.pump.skip_bytes(declared64) {
            Ok(advanced) if advanced == declared64 => Ok(()),
            Ok(_) => {
                let fallback = Failure {
                    fault: Fault {
                        at: self.pump.off,
                        kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SourceEnd },
                    },
                    cut: self.pump.off,
                };
                Err(Stop::Clip(self.eof_clip(Some(row), fallback)))
            }
            Err(supply) => Err(Stop::Abort(self.supply_abort(supply))),
        }
    }

    /// Stops: clips every open LEN with the same close-time
    /// writes as a normal pop. LEN rows keep their declared spans
    /// (the seal is an input fact independent of walk progress);
    /// only `descendants` needs the terminal write.
    fn clip(mut self, failure: Failure) -> Parts {
        while let Some(frame) = self.stack.pop() {
            self.seal_descendants(frame.row);
        }
        Parts {
            rows: self.rows.into_boxed_slice(),
            indexed_end: failure.cut,
            fault: Some(failure.fault),
        }
    }

    fn finish(self, fault: Option<Fault>) -> Parts {
        Parts { rows: self.rows.into_boxed_slice(), indexed_end: self.pump.off, fault }
    }
}

#[cfg(test)]
mod tests;
