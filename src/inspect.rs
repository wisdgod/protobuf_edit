//! Schema-less inspection of one in-memory protobuf message
//! (read · buffered · offline), per wire dialect.
//!
//! Dialects are sibling modules, not parameters: `grouped` walks
//! groups structurally; `groupless` refuses group codes as a
//! capability judgment. This shared layer holds only
//! dialect-orthogonal vocabulary — words whose meaning never touches
//! a dialect table: admission, handles, and the schema-supply face.
//! Dialect-sensitive vocabulary (kinds, faults, trees) stays per
//! dialect, unshared.
//!
//! The owned twin is `retain` (feature `retain-*`): its `Retained`
//! product answers this module's `Tree` queries over a moved-in
//! buffer — detachable, cacheable, `Send + Sync`.
//!
//! The [`i32::MAX` input cap](crate::Span), cited by every dialect:
//! [`Admitted`] bounds the input at `i32::MAX` bytes — the LEN
//! length class top and the reference reader's single-message hard
//! bound — so every stored or computed coordinate lives in
//! `0..=i32::MAX` and any two coordinates add without overflowing
//! `u32`.
//!
//! Allocation policy: the parse product and the machine's working
//! stacks grow through the standard infallible `Vec` paths (panic
//! or abort on allocator refusal); wire violations are never
//! resource errors — they stay in the product as its fault.
//!
//! Coordinates: read · buffered · offline · Standard (value-level) · borrowed.
//!
//! # Choosing a face
//!
//! One entry chain: [`Admitted::new`] is the only refusal, and
//! `Tree::parse` — the admitted bytes, a depth bound, an advisor
//! — always yields a tree. Wire violations live *in* the product
//! (`fault`, `is_complete`), so a viewer renders the lawful
//! prefix of a broken document instead of handling an error.
//! `Tree::parse_standard` additionally takes the acceptance
//! [`Standard`](crate::Standard) and picks a monomorphized engine
//! once at entry — `parse` is exactly its tolerant instance, and
//! rows store actual widths under both standards (span geometry
//! needs them either way).
//!
//! The advisor argument is the schema dial: [`NoAdvice`] spells
//! zero knowledge (every LEN payload speculates); implement
//! [`Advisor`] to pin the sites you know — [`Advice::Commit`],
//! [`Advice::Opaque`], or [`Advice::Speculate`] per
//! (ancestry, field).
//!
//! Query faces by question: structure (`top`, `children`,
//! `descendants`, `Children::by_field`), values (`varint_word`,
//! `i32_bits`, `i64_bits`, `payload_bytes`, `record_bytes`), and
//! hex-view geometry (`span`, `source_spans`, `narrowest`).
//!
//! Both dialect trees ship the same faces. Elsewhere: one pass
//! without materializing → `traverse`; chunked input → `scan`;
//! the same handle feel with editing verbs → `patch` and
//! `session` (each behind its feature).
//!
//! # Examples
//!
//! Supplying partial schema knowledge through an [`Advisor`]: the
//! caller pins field 2 as opaque bytes, which no speculation can
//! override.
//!
//! ```
//! # #[cfg(feature = "inspect-groupless")] {
//! use protobuf_edit::inspect::groupless::Tree;
//! use protobuf_edit::inspect::{Admitted, Advice, Advisor, Ancestry, NoAdvice};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! struct Schema;
//! impl Advisor for Schema {
//!     fn advise(&mut self, _outer: Ancestry<'_>, field: FieldNumber) -> Advice {
//!         if field.as_inner() == 2 { Advice::Opaque } else { Advice::Speculate }
//!     }
//! }
//!
//! // varint f1=150 · LEN f2 "hi" (bytes that also parse as a message)
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let admitted = Admitted::new(&msg).unwrap();
//!
//! // Advice::Opaque keeps the payload unparsed…
//! let advised = Tree::parse(admitted, DepthLimit::REFERENCE, &mut Schema);
//! let len_record = advised.top().nth(1).unwrap();
//! assert_eq!(advised.children(len_record).count(), 0);
//!
//! // …while zero advice speculates it into a nested record.
//! let speculated = Tree::parse(admitted, DepthLimit::REFERENCE, &mut NoAdvice);
//! let len_record = speculated.top().nth(1).unwrap();
//! assert_eq!(speculated.children(len_record).count(), 1);
//! # }
//! ```
//!
//! # Recipes
//!
//! The entry chain above, compiled: admit, parse, judge the fault
//! before consuming — the tree always exists, and the lawful
//! prefix stays browsable under a resident fault:
//!
//! ```
//! # #[cfg(feature = "inspect-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::inspect::groupless::Tree;
//! use protobuf_edit::inspect::{Admitted, NoAdvice};
//!
//! // varint f1=150, then a record cut short mid-value.
//! let msg = [0x08, 0x96, 0x01, 0x08];
//! let admitted = Admitted::new(&msg).unwrap();
//! let tree = Tree::parse(admitted, DepthLimit::REFERENCE, &mut NoAdvice);
//!
//! assert!(!tree.is_complete());
//! assert_eq!(tree.fault().unwrap().at(), 4);
//! let first = tree.top().next().unwrap();
//! assert_eq!(tree.varint_word(first), Some(150));
//! # }
//! ```
//!
//! The hex-view click: `narrowest` answers which record covers a
//! byte, `source_spans` names the segment under it, and the byte
//! faces hand the covered bytes over:
//!
//! ```
//! # #[cfg(feature = "inspect-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::inspect::groupless::{RecordSpans, Tree};
//! use protobuf_edit::inspect::{Admitted, NoAdvice};
//!
//! // varint f1=150 · LEN f2 whose payload stays bytes (it does
//! // not parse); the viewer clicks byte 5.
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x01, 0x02];
//! let admitted = Admitted::new(&msg).unwrap();
//! let tree = Tree::parse(admitted, DepthLimit::REFERENCE, &mut NoAdvice);
//!
//! let id = tree.narrowest(5).unwrap();
//! let RecordSpans::Len { payload, .. } = tree.source_spans(id) else {
//!     unreachable!()
//! };
//! assert!(payload.as_range().contains(&5));
//! assert_eq!(tree.payload_bytes(id), [0x01, 0x02]);
//! # }
//! ```

// The depth bound reaches this layer only through the heap
// machines' reserve heuristic; the fixed twin takes its bound at
// its own door.
#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
use crate::DepthLimit;
use crate::FieldNumber;
pub use crate::Stage;

/// Bytes admitted for inspection: length within the
/// [`i32::MAX` input cap](crate::Span), the reference reader's
/// single-message hard bound.
///
/// Construction is the admission judgment; every coordinate a parse
/// stores or computes downstream inherits the `u32` class from it.
/// Holding an `Admitted` is the proof the unsafe discharges in the
/// query faces cite. Value semantics are the admitted slice's:
/// two `Admitted` are equal iff their bytes are.
///
/// # Examples
///
/// ```
/// use protobuf_edit::inspect::Admitted;
///
/// let admitted = Admitted::new(&[0x08, 0x2A]).unwrap();
/// assert_eq!(admitted.len(), 2);
/// assert_eq!(admitted.bytes(), [0x08, 0x2A]);
/// ```
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Admitted<'a> {
    bytes: &'a [u8],
}

impl<'a> Admitted<'a> {
    /// Admits the bytes; `None` iff `bytes.len() > i32::MAX`.
    #[inline]
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() > crate::admission::MAX {
            return None;
        }
        Some(Self { bytes })
    }

    /// The admitted bytes.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Length in the coordinate class.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        crate::admission::admitted_u32(self.bytes.len())
    }

    /// True for the empty message.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The exclusive end as a typed coordinate: admission judged
    /// `len <= i32::MAX`, which is exactly the coordinate class.
    #[inline]
    pub(crate) const fn end(&self) -> crate::admission::Coord {
        // SAFETY: `new` judged `bytes.len() <= MAX`, the class top.
        unsafe { crate::admission::Coord::new_unchecked(self.len()) }
    }
}

crate::_macro::define_valid_range_type! {
    /// An index into one inspect parse product.
    ///
    /// Distinct from offsets and counts at the type level. Handles
    /// are slice-like: out-of-range use panics; a stale handle from
    /// another tree that happens to be in range reads that tree's
    /// answer — memory-safe, semantically the caller's fault.
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

crate::_macro::define_valid_range_type! {
    /// A count of rows in one inspect parse product — subtree
    /// sizes, table lengths, and the iterators' row-space
    /// boundaries and cursors (a cursor is the count of rows
    /// before it).
    ///
    /// Distinct from [`NodeId`] at the type level: an id names an
    /// existing row, a count may equal the table length — one past
    /// the last id, the pinned maxima offset below. The class is
    /// admission-derived like the id's: every row spends at least
    /// its head tag byte, so no product holds more rows than
    /// admitted bytes.
    #[must_use]
    pub(crate) struct RowCount(u32 as u32 in 0..=2_147_483_647) with min, max, new_unchecked;
}

impl RowCount {
    /// Mints a parse-produced row count (in class by the
    /// admission-derived bound in the type doc).
    #[inline]
    pub(crate) const fn of(rows: usize) -> Self {
        // SAFETY: every row spends at least one input byte and
        // admission caps the input, so parse-produced row counts
        // stay in class.
        unsafe { Self::new_unchecked(crate::admission::admitted_u32(rows)) }
    }
}

// The class pins: the count top is the admission byte cap (one
// byte per row at minimum), and ids stop one short of it (valid
// ids are `0..count`).
const _: () = {
    assert!(crate::admission::usize_of(RowCount::MAX.as_inner()) == crate::admission::MAX);
    assert!(NodeId::MAX.as_inner() == RowCount::MAX.as_inner() - 1);
};

/// Mints the id of a parse-produced row index (in class by the
/// admission-derived row-count bound; see [`NodeId`]).
pub(crate) const fn mint(index: u32) -> NodeId {
    debug_assert!(index <= NodeId::MAX.as_inner());
    // SAFETY: every row spends at least one input byte and admission
    // caps the input, so parse-produced indices stay in class.
    unsafe { NodeId::new_unchecked(index) }
}

/// Row-table reserve derived from the input length: field-dense
/// traffic runs a couple dozen bytes per record (a mixed 100 KiB
/// parse lands at ~15.6 B/row), so an eighth of the input length
/// covers such tables in one allocation while keeping the transient
/// overshoot proportionate — a chunky 100 KiB parse peaks at
/// 0.3 MiB here against 1.2 MiB at half the length, with parse
/// times flat across both, and even worst-case two-byte records
/// (where doubling growth resumes) pay no measurable time. The cap
/// bounds the seed; the finished product shrinks to fit. Heap
/// machinery: the fixed twin sizes its arena from the plan, so a
/// fixed-only build carries no reserve heuristics.
#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
pub(crate) const fn rows_reserve(len: u32) -> usize {
    const CAP: usize = 1 << 16;
    let eighth = crate::admission::usize_of(len / 8);
    if eighth < CAP { eighth } else { CAP }
}

/// Frame-stack reserve: the caller's bound when tight, a shallow
/// floor otherwise (deeper nesting grows on demand). Heap
/// machinery, as [`rows_reserve`].
#[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
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

#[cfg(feature = "inspect-grouped")]
pub mod grouped;
#[cfg(feature = "inspect-groupless")]
pub mod groupless;
