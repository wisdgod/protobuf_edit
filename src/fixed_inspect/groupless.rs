//! The fixed-scratch groupless inspector: group codes are a
//! capability refusal, working memory is the caller's slab.
//!
//! The machine is the heap inspector's
//! (`crate::inspect::groupless`) — one parse over [`Admitted`]
//! bytes builds a preorder row table, the product is total (legal
//! prefix + at most one fault), detection stays blind to
//! commitment, and a group code (3 or 4) is refused as this
//! dialect's capability judgment. What moves is the memory plane:
//! the row arena, the frame stack, and the path mirror are carved
//! from one caller slab at the door, and only row exhaustion can
//! refuse a parse ([`OpenFault::RowsExhausted`] — never a wrong
//! answer, see the family doc).
//!
//! Without groups the partition theorem strengthens: the delimiter
//! (only LEN's length prefix remains) always *precedes* the
//! payload, so both the record span and the payload span are one
//! branch-free formula — the grouped dialect's payload dispatch has
//! no reason to exist here.
//!
//! Coordinates: read · buffered · offline · groupless · Standard (value-level) · borrowed · fixed scratch.
//!
//! # Examples
//!
//! ```
//! use core::mem::MaybeUninit;
//! use protobuf_edit::fixed_inspect::groupless::{Plan, Tree};
//! use protobuf_edit::inspect::{Admitted, NoAdvice};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // varint f1=150 · LEN f2 "hi"
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let input = Admitted::new(&msg).unwrap();
//! let plan = Plan::new(4).unwrap();
//! let mut slab = [MaybeUninit::<u8>::uninit(); 256];
//! let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, &mut slab).unwrap();
//! assert!(tree.is_complete());
//!
//! let field2 = FieldNumber::new(2).unwrap();
//! let hits: Vec<_> = tree.top().by_field(field2).collect();
//! assert_eq!(hits.len(), 1);
//! assert_eq!(tree.payload_bytes(hits[0]), [0x68, 0x69]);
//! ```

use core::iter::FusedIterator;
use core::mem::MaybeUninit;

use super::{Budget, FrameAt, Gauge, OpenFault, StoreLane, WalkLane};
use crate::admission::{Coord, Extent, usize_of};
use crate::inspect::{Admitted, Advice, Advisor, Ancestry, NodeId, RowCount, Stage, mint};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, encoded_len32, encoded_len64};
use crate::wire::groupless::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, FaultClass, Span, Standard};
// ─── the law ───

/// One law violation: where, and which law.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: Coord,
    kind: FaultKind,
}

impl Fault {
    /// First byte of the offending wire construct.
    #[inline]
    #[must_use]
    pub const fn at(self) -> u32 {
        self.at.as_inner()
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
        write!(f, "{} at byte {}", self.kind, self.at())
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
/// dialect's vocabulary — not unreachable, absent.
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
        /// Bytes actually left in the enclosing extent: an
        /// admission-class count (`0..=i32::MAX`) that the declared
        /// length exceeded.
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
    /// A tag wider than minimal ([`Tree::parse_standard`] under
    /// [`Standard::CanonicalMinimal`] only; speculation absorbs it
    /// like any wire fault).
    NonMinimalTag,
    /// A length prefix wider than minimal (canonical parses only).
    NonMinimalLen {
        /// The record's field number.
        field: FieldNumber,
    },
    /// A value varint wider than minimal (canonical parses only).
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
    /// is the parse's declared [`Standard`]).
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

// ─── the machine's row ───

/// One record, packed to 24 bytes. Private: the tree projects it.
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
    descendants: RowCount,
    /// The head tag's field number.
    field: FieldNumber,
    /// The record kind (the dialect table's vocabulary, verbatim).
    kind: RecordKind,
    /// The head tag's actual input width.
    tag_width: WordWidth,
    /// LEN: the length prefix's actual width. Scalars: `None` —
    /// in this dialect `kind == Len ⟺ delim_width.is_some()` (the
    /// grouped dialect has no such equivalence: closed groups carry
    /// `Some` too).
    delim_width: Option<WordWidth>,
}

// The row and frame layouts the plan prices: every column is
// pointer-free, so the pins — and `Plan::bytes` — are one figure
// across 32/64-bit. The ladder's derived head alignment is the
// lanes' shared 4.
const _: () = assert!(core::mem::size_of::<Row>() == 24);
const _: () = assert!(core::mem::align_of::<Row>() == 4);
const _: () = assert!(core::mem::size_of::<Fault>() == 20);
const _: () = assert!(core::mem::size_of::<Frame>() == 16);
const _: () = assert!(core::mem::align_of::<Frame>() == 4);
const _: () = assert!(core::mem::size_of::<Option<FrameAt>>() == 2);
const _: () = assert!(TreeCaps::HEAD_ALIGN == 4);

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
        // its span inside the admitted input, so the width sum is in
        // class.
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
        // the record's span, which lies in the admitted input.
        Span::of(unsafe { Coord::new_unchecked(start) }, self.payload_len)
    }
}

// ─── the capacity contract ───

/// The count of distinct row-id values — the row-capacity ceiling
/// every plan judges at construction, so row minting stays in the
/// id class by contract (a full plan's top minted index is the
/// class top `0x7FFF_FFFE`).
const ROW_DOMAIN: u32 = 0x7FFF_FFFF;

/// The derived stack capacity: open frames on one parse path.
/// Every open frame owns a distinct live row (its row is pushed
/// before the frame opens; an unwind truncates frames to the
/// absorber whose row survives) and `at_depth_limit` gates every
/// open at the caller's bound, so both bound the stack; the
/// tighter one prices. The path mirror never outgrows the frame
/// stack (`path.len() <= stack.len()` always), so the same bound
/// serves both.
const fn stacks_cap(rows: u32, limit: DepthLimit) -> u32 {
    let bound = limit.as_inner() as u32;
    if rows < bound { rows } else { bound }
}

/// The capacity contract: the one role no configuration implies.
///
/// How many rows a document's parse holds at once is a fact about
/// the caller's documents — the plan declares exactly that count,
/// and the door derives the rest (frame stack and path mirror ride
/// the row count and the depth bound).
///
/// The count is **peak** demand, not the final row count:
/// speculative rows that a later unwind evaporates still occupied
/// the arena while the speculation ran, so `budget().rows.used` —
/// the high-water — is the number a sufficient plan must cover.
/// Zero rows is lawful (parses exactly the empty document).
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plan {
    rows: u32,
}

impl Plan {
    /// Judges the declared row capacity into the row-id domain
    /// (`0x7FFF_FFFF` admits — a full plan's top minted index is
    /// the id class top — and the next value refuses). `None` past
    /// the domain.
    #[inline]
    pub const fn new(rows: u32) -> Option<Self> {
        if rows > ROW_DOMAIN {
            return None;
        }
        Some(Self { rows })
    }

    /// The declared row capacity.
    #[inline]
    #[must_use]
    pub const fn rows(&self) -> u32 {
        self.rows
    }

    /// The exact slab demand under `limit`, sufficient for any slab
    /// address: worst-case head alignment is priced in, and the
    /// door refuses a shorter slab with [`OpenFault::SlabShort`] as
    /// a pure length compare — a luckier alignment never shrinks
    /// the demand. The depth bound prices the derived stacks, which
    /// is why the face takes it. One figure across 32/64-bit
    /// targets: every lane element is pointer-free.
    #[inline]
    #[must_use]
    pub const fn bytes(&self, limit: DepthLimit) -> u64 {
        self.caps(limit).priced()
    }

    /// The door's lane capacities: the declared row count plus the
    /// derived stacks — one construction, priced and carved alike.
    const fn caps(&self, limit: DepthLimit) -> TreeCaps {
        let stacks = stacks_cap(self.rows, limit);
        TreeCaps { rows: self.rows, frames: stacks, path: stacks }
    }
}

// The priced formula, pinned symbolically from the ladder's 4-byte
// alignment law (worst-case pad 3, zero interior padding): a layout
// regression moves a compile error, not a runtime price.
const _: () = {
    let plan = Plan { rows: 100 };
    assert!(plan.bytes(DepthLimit::REFERENCE) == 3 + 100 * 24 + 100 * (16 + 4));
    let tight = Plan { rows: 7 };
    assert!(tight.bytes(DepthLimit::MIN) == 3 + 7 * 24 + (16 + 4));
};

super::carve_ladder! { ($)
    /// Carves the tree door's working set: the row arena, the
    /// open-container frame stack, and the advisor's path mirror.
    carve_tree, caps TreeCaps, lanes TreeLanes {
        store rows: Row,
        walk frames: Frame,
        walk path: FieldNumber,
    }
}

// ─── the product ───

/// Where a record's bytes lie in the input, split by role.
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

/// The parse product: a preorder row table over admitted bytes,
/// plus at most one fault — the heap twin's product over a
/// caller-slab arena, id-identical to it within an adequate plan.
///
/// A faulted tree is not an error case — it is the legal prefix,
/// open containers clipped to the fault boundary, and the fault.
/// The type is its own provenance proof: `input` and `rows` are
/// private, minted together by the one parse, and immutable for the
/// tree's life (the row lane is exclusively borrowed for `'s`) —
/// the unsafe discharges in the value queries cite exactly this
/// invariant.
///
/// Node ids are plain indices in parse order, slice-style: passing
/// an id at or beyond [`node_count`](Self::node_count) panics.
/// `Option` returns carry domain answers, never id validation.
pub struct Tree<'a, 's> {
    input: Admitted<'a>,
    rows: StoreLane<'s, Row>,
    /// End of the indexed prefix (clipped LEN rows keep their
    /// declared, sealed spans, which may extend past it).
    indexed_end: Coord,
    fault: Option<Fault>,
    /// The frame stack's high-water, folded when the parse machine
    /// died (its lane died with the machine).
    frames: Gauge,
    /// The path mirror's high-water, as `frames`.
    path: Gauge,
}

impl<'a, 's> Tree<'a, 's> {
    /// Parses the admitted bytes over the caller's slab. Wire
    /// admission is the argument's type and wire faults are
    /// product, not error: the one refusal surface is the plan —
    /// a slab shorter than [`Plan::bytes`] refuses before anything
    /// is read, and a parse needing more rows than the plan
    /// declared aborts with no product published.
    ///
    /// `advice` is consulted at every LEN record head (empty
    /// payloads included); `depth` bounds container nesting with no
    /// default.
    ///
    /// # Errors
    ///
    /// [`OpenFault::SlabShort`] when the slab is shorter than the
    /// plan's priced demand (a pure length compare);
    /// [`OpenFault::RowsExhausted`] when the parse's peak row
    /// demand exceeds the plan.
    ///
    /// # Examples
    ///
    /// A group code is this dialect's capability refusal — in the
    /// product, exactly as in the heap twin:
    ///
    /// ```
    /// use core::mem::MaybeUninit;
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::fixed_inspect::groupless::{FaultKind, Plan, Tree};
    /// use protobuf_edit::inspect::{Admitted, NoAdvice};
    ///
    /// // An empty group of field 1 — well-formed wire outside
    /// // this language.
    /// let msg = [0x0B, 0x0C];
    /// let input = Admitted::new(&msg).unwrap();
    /// let plan = Plan::new(1).unwrap();
    /// let mut slab = [MaybeUninit::<u8>::uninit(); 64];
    /// let tree =
    ///     Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, &mut slab).unwrap();
    /// let fault = tree.fault().unwrap();
    /// assert_eq!(fault.at(), 0);
    /// assert!(matches!(fault.kind(), FaultKind::GroupCode { .. }));
    /// ```
    pub fn parse<A: Advisor>(
        input: Admitted<'a>,
        depth: DepthLimit,
        advice: &mut A,
        plan: &Plan,
        slab: &'s mut [MaybeUninit<u8>],
    ) -> Result<Self, OpenFault> {
        Self::parse_standard(input, Standard::Tolerant, depth, advice, plan, slab)
    }

    /// [`Tree::parse`] under a declared acceptance [`Standard`]:
    /// the standard picks a monomorphized engine instance once at
    /// this entry, so a tolerant parse pays no width comparison
    /// and a canonical one judges every varint word against its
    /// minimal encoding — the `NonMinimal*` faults, at the
    /// construct's first byte, exactly where the heap twin judges
    /// them.
    ///
    /// Width storage is unchanged under both standards: rows keep
    /// actual input widths because span geometry needs them either
    /// way. Minimality inside a speculated payload absorbs like
    /// any other wire fault — the payload concludes "bytes" — so
    /// the standard governs exactly what the committed zone
    /// promises.
    ///
    /// # Errors
    ///
    /// As [`Tree::parse`]: the plan's two refusals, never a wire
    /// verdict.
    ///
    /// # Examples
    ///
    /// ```
    /// use core::mem::MaybeUninit;
    /// use protobuf_edit::fixed_inspect::groupless::{FaultKind, Plan, Tree};
    /// use protobuf_edit::inspect::{Admitted, NoAdvice};
    /// use protobuf_edit::{DepthLimit, Standard};
    ///
    /// // 150 continuation-padded to three bytes: accepted
    /// // tolerant, refused canonical at the value's first byte.
    /// let msg = [0x08, 0x96, 0x81, 0x00];
    /// let input = Admitted::new(&msg).unwrap();
    /// let plan = Plan::new(1).unwrap();
    /// let mut slab = [MaybeUninit::<u8>::uninit(); 64];
    ///
    /// let tolerant = Tree::parse_standard(
    ///     input,
    ///     Standard::Tolerant,
    ///     DepthLimit::REFERENCE,
    ///     &mut NoAdvice,
    ///     &plan,
    ///     &mut slab,
    /// )
    /// .unwrap();
    /// assert!(tolerant.is_complete());
    ///
    /// let canonical = Tree::parse_standard(
    ///     input,
    ///     Standard::CanonicalMinimal,
    ///     DepthLimit::REFERENCE,
    ///     &mut NoAdvice,
    ///     &plan,
    ///     &mut slab,
    /// )
    /// .unwrap();
    /// let fault = canonical.fault().unwrap();
    /// assert_eq!(fault.at(), 1);
    /// assert!(matches!(fault.kind(), FaultKind::NonMinimalValue { .. }));
    /// ```
    pub fn parse_standard<A: Advisor>(
        input: Admitted<'a>,
        standard: Standard,
        depth: DepthLimit,
        advice: &mut A,
        plan: &Plan,
        slab: &'s mut [MaybeUninit<u8>],
    ) -> Result<Self, OpenFault> {
        let need = plan.bytes(depth);
        // Lossless: usize widens into u64 on the crate's targets.
        #[allow(clippy::as_conversions, reason = "see above")]
        let have = slab.len() as u64;
        if have < need {
            return Err(OpenFault::SlabShort { need, have });
        }
        let caps = plan.caps(depth);
        let lanes = carve_tree!(slab, &caps);
        let machine = Machine {
            input,
            cursor: Coord::MIN,
            zone: input.end(),
            nearest_absorber: None,
            stack: lanes.frames,
            path: lanes.path,
            rows: lanes.rows,
            frames_peak: 0,
            path_peak: 0,
            limit: depth,
            advice,
        };
        match standard {
            Standard::Tolerant => machine.run::<false>(),
            Standard::CanonicalMinimal => machine.run::<true>(),
        }
    }

    /// Per-lane high-water occupancy against capacity — the sizing
    /// loop's answer face, riding the product. `rows` is the
    /// plan-declared lane and its high-water is peak demand
    /// (evaporated speculative rows count); the derived lanes
    /// report how deep the document actually ran, informational
    /// (`used <= capacity` always).
    #[inline]
    #[must_use]
    pub const fn budget(&self) -> Budget {
        Budget { rows: self.rows.gauge(), frames: self.frames, path: self.path }
    }

    /// The row table — the initialized prefix of the carved arena,
    /// exactly the slice the heap twin's `Box<[Row]>` holds.
    const fn rows(&self) -> &[Row] {
        self.rows.inited()
    }

    /// The fault, if the committed zone stopped the parse early.
    #[inline]
    #[must_use]
    pub const fn fault(&self) -> Option<Fault> {
        self.fault
    }

    /// True when the whole input parsed without a fault.
    #[inline]
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.fault.is_none()
    }

    /// The admitted input bytes; all spans index into these.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.input.bytes()
    }

    /// End of the indexed prefix (equals the input length iff the
    /// parse consumed everything).
    #[inline]
    #[must_use]
    pub const fn indexed_end(&self) -> u32 {
        self.indexed_end.as_inner()
    }

    /// Number of rows; valid ids are `0..node_count`.
    #[inline]
    #[must_use]
    pub const fn node_count(&self) -> u32 {
        self.rows.len()
    }

    /// True when no records were indexed.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows.len() == 0
    }

    /// The public id gate: every id-taking query passes here, and
    /// the slice index is the documented forgery panic.
    #[track_caller]
    const fn row(&self, id: NodeId) -> &Row {
        &self.rows()[id.index()]
    }

    /// The row of an internally proven id.
    ///
    /// # Safety
    /// `id` must be in-table: minted by this parse (row pushes,
    /// partition points) or read out of a row's parent link.
    unsafe fn row_unchecked(&self, id: NodeId) -> &Row {
        // SAFETY: the caller's proof, restated.
        unsafe { self.rows().get_unchecked(id.index()) }
    }

    // ─ navigation ─

    /// Iterates the top-layer records.
    #[inline]
    pub const fn top(&self) -> Children<'_> {
        Children { rows: self.rows(), next: RowCount::MIN, end: RowCount::of(self.rows().len()) }
    }

    /// Iterates `id`'s direct children (empty for leaves and
    /// unparsed payloads).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[track_caller]
    pub const fn children(&self, id: NodeId) -> Children<'_> {
        let r = self.row(id);
        let first = id.as_inner() + 1;
        // SAFETY (both mints): `id` passed the row gate, so `first`
        // is at most the table length, and the parse sealed
        // `descendants` inside `id`'s subtree, so the sum is too —
        // both in class.
        let next = unsafe { RowCount::new_unchecked(first) };
        let end = unsafe { RowCount::new_unchecked(first + r.descendants.as_inner()) };
        Children { rows: self.rows(), next, end }
    }

    /// The enclosing container (`None`: root level).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.row(id).parent
    }

    /// Walks the parent chain from `id` (exclusive) to a root.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[track_caller]
    pub const fn ancestors(&self, id: NodeId) -> Ancestors<'_> {
        Ancestors { rows: self.rows(), cur: self.row(id).parent }
    }

    /// The record's field number.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[track_caller]
    pub const fn field(&self, id: NodeId) -> FieldNumber {
        self.row(id).field
    }

    /// The record's wire kind.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn kind(&self, id: NodeId) -> RecordKind {
        self.row(id).kind
    }

    /// Iterates all records in parse (preorder) order.
    #[inline]
    pub const fn nodes(&self) -> Nodes<'_> {
        Nodes {
            next: RowCount::MIN,
            end: RowCount::of(self.rows().len()),
            _rows: core::marker::PhantomData,
        }
    }

    /// Iterates `id`'s whole subtree, excluding `id` itself.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[track_caller]
    pub const fn descendants(&self, id: NodeId) -> Nodes<'_> {
        let r = self.row(id);
        let first = id.as_inner() + 1;
        // SAFETY (both mints): as `children` — the row gate bounds
        // `first` and the sealed subtree bounds the sum, both by
        // the table length.
        let next = unsafe { RowCount::new_unchecked(first) };
        let end = unsafe { RowCount::new_unchecked(first + r.descendants.as_inner()) };
        Nodes { next, end, _rows: core::marker::PhantomData }
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
        let started_before = self.rows().partition_point(|r| r.start.as_inner() <= pos);
        let mut cur = mint(RowCount::of(started_before.checked_sub(1)?).as_inner());
        loop {
            // SAFETY: the first id is minted from a nonzero
            // partition point over the table; every later id is a
            // row's parent link, minted in-table by the parse.
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
    /// commutation (unlike the grouped dialect's trailing group end
    /// tag). A clipped LEN keeps its declared, sealed span.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
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
    /// indices into this tree.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn source_spans(&self, id: NodeId) -> RecordSpans {
        let r = self.row(id);
        // SAFETY (all mints below): the partition theorem — the
        // record's segments tile its span inside the admitted input,
        // so every segment bound is in class.
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

    /// The record's bytes (borrows the input, not the tree).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn record_bytes(&self, id: NodeId) -> &'a [u8] {
        let span = self.row(id).span();
        // SAFETY: the Tree invariant — rows were minted by the parse
        // over these same admitted, immutable bytes, and record
        // spans lie within them.
        unsafe { self.bytes().get_unchecked(span.as_range()) }
    }

    /// Designates the record for cross-machine transfer: the exact
    /// record bytes bound to their proved field, kind, and framing
    /// geometry (borrows the input, not the tree). Completeness is
    /// part of the designation's contract, so only records whose
    /// whole extent lies inside the indexed prefix mint; the
    /// canonical proof is not carried — a consumer that needs it
    /// asks `try_canonical` on the designation itself.
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
    /// indices into this tree.
    #[track_caller]
    pub fn record_ref(
        &self,
        id: NodeId,
    ) -> Result<crate::source::groupless::RecordRef<'a>, crate::source::groupless::Fault> {
        let r = self.row(id);
        if r.span().end() > self.indexed_end.as_inner() {
            return Err(crate::source::groupless::Fault::IncompleteRecord {
                at: self.indexed_end.as_inner(),
            });
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

    /// The payload bytes (borrows the input, not the tree).
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn payload_bytes(&self, id: NodeId) -> &'a [u8] {
        let span = self.row(id).payload_span();
        // SAFETY: as `record_bytes` — payload spans are sub-spans of
        // record spans.
        unsafe { self.bytes().get_unchecked(span.as_range()) }
    }

    /// The varint value as a raw wire word (`None`: not a VARINT
    /// record), tolerant of the source's padding. `crate::scalar`
    /// maps wire words to schema-typed values.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn varint_word(&self, id: NodeId) -> Option<u64> {
        let r = self.row(id);
        if !matches!(r.kind, RecordKind::Varint) {
            return None;
        }
        let at = r.start.as_inner() + r.tag_w();
        // SAFETY: the Tree invariant — a Varint row's payload is the
        // window a bounded in-class read admitted during the parse,
        // over these same immutable bytes.
        Some(unsafe { slice::value64_unchecked(self.bytes(), usize_of(at)) })
    }

    /// The eight little-endian payload bytes as raw bits (`None`:
    /// not an I64 record). `crate::scalar` interprets them.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn i64_bits(&self, id: NodeId) -> Option<u64> {
        let r = self.row(id);
        if !matches!(r.kind, RecordKind::I64) {
            return None;
        }
        let at = usize_of(r.start.as_inner() + r.tag_w());
        // SAFETY: the Tree invariant — I64 rows are minted only
        // after the parse proved eight in-extent payload bytes.
        // `[u8; 8]` aligns to 1.
        let bits = unsafe { self.bytes().as_ptr().add(at).cast::<[u8; 8]>().read() };
        Some(u64::from_le_bytes(bits))
    }

    /// The four little-endian payload bytes as raw bits (`None`:
    /// not an I32 record). `crate::scalar` interprets them.
    ///
    /// # Panics
    ///
    /// Panics if `id >= self.node_count()` — node ids are slice-style
    /// indices into this tree.
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
        let bits = unsafe { self.bytes().as_ptr().add(at).cast::<[u8; 4]>().read() };
        Some(u32::from_le_bytes(bits))
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
    next: RowCount,
    end: RowCount,
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
        let id = self.next.as_inner();
        // SAFETY: `id < end`, and `end <= rows.len()` by
        // construction — a run is bounded by its enclosing subtree
        // range, whose rows the parse physically pushed.
        let descendants = unsafe { self.rows.get_unchecked(usize_of(id)) }.descendants;
        // SAFETY: the hop lands on the next sibling or the run's
        // end — still inside the enclosing subtree range, in class.
        self.next = unsafe { RowCount::new_unchecked(id + 1 + descendants.as_inner()) };
        Some(mint(id))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Nonempty runs yield at least one sibling; each sibling
        // occupies at least one row, bounding from above.
        let width = usize_of(self.end.as_inner().saturating_sub(self.next.as_inner()));
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
        // in-table by the parse.
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
/// ([`Tree::nodes`]) or one subtree ([`Tree::descendants`]) — two
/// demands, one shape. Exact: the range width is the count.
#[must_use]
#[derive(Clone)]
pub struct Nodes<'t> {
    next: RowCount,
    end: RowCount,
    _rows: core::marker::PhantomData<&'t [Row]>,
}

impl Iterator for Nodes<'_> {
    type Item = NodeId;

    #[inline]
    fn next(&mut self) -> Option<NodeId> {
        if self.next >= self.end {
            return None;
        }
        let id = self.next.as_inner();
        // SAFETY: `id < end`, so the increment stays at most `end`
        // — in class.
        self.next = unsafe { RowCount::new_unchecked(id + 1) };
        Some(mint(id))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = usize_of(self.end.as_inner() - self.next.as_inner());
        (n, Some(n))
    }
}

impl DoubleEndedIterator for Nodes<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<NodeId> {
        if self.next >= self.end {
            return None;
        }
        // SAFETY: `next < end`, so the decrement stays at or above
        // `next` — in class.
        self.end = unsafe { RowCount::new_unchecked(self.end.as_inner() - 1) };
        Some(mint(self.end.as_inner()))
    }
}

impl ExactSizeIterator for Nodes<'_> {}
impl FusedIterator for Nodes<'_> {}

// ─── the machine ───

/// One open LEN extent — the only container this dialect has, so
/// the frame needs no kind vocabulary. The frame simultaneously
/// carries the parent link (`row`), the open field, and the restore
/// state for the two live registers ([`Machine::zone`],
/// [`Machine::nearest_absorber`]) — pushing saves them, popping
/// restores them, and no walk ever recomputes them.
#[derive(Clone, Copy)]
struct Frame {
    row: NodeId,
    /// The open container's field (what the machine lends to
    /// [`Ancestry`]).
    field: FieldNumber,
    /// The enclosing extent's end, restored on close.
    prev_zone: Coord,
    /// The enclosing nearest-absorber register, restored on close.
    /// The stack coordinate rides [`FrameAt`]: the frame lives in a
    /// priced lane, and the two-byte class keeps it at 16 bytes.
    prev_absorber: Option<FrameAt>,
}

/// A judged violation, plus where the uncommitted transaction
/// began (`cut`): clipping uses `cut`, so a container never
/// swallows the bad record's tag bytes.
struct Failure {
    fault: Fault,
    cut: Coord,
}

/// The record loop's terminal signals: a committed-zone wire
/// failure stops the parse and clips (the product exists); the row
/// lane's exhaustion aborts the job (no product exists — absorbing
/// it would make the message-vs-bytes answer a function of the
/// plan).
enum Halt {
    /// A committed-zone failure: stop the parse and clip.
    Stop(Failure),
    /// The row arena is spent: abort with
    /// [`OpenFault::RowsExhausted`].
    Exhausted,
}

/// Detection is blind to commitment: judgment code reads bytes,
/// bounds, and grammar state, never the absorber register —
/// disposition alone reads it.
struct Machine<'a, 's, 'v, A: Advisor> {
    input: Admitted<'a>,
    cursor: Coord,
    /// The innermost extent's exclusive end (the top frame's zone;
    /// the input's length at root level) — maintained by open and
    /// close, never recomputed.
    zone: Coord,
    /// Stack index of the innermost `Advice::Speculate` LEN (the
    /// frame a speculation failure unwinds to), maintained by open
    /// and close for an O(1) dispose. `Commit` frames are not
    /// absorbing, and the root is implicitly committed.
    nearest_absorber: Option<FrameAt>,
    stack: WalkLane<'s, Frame>,
    /// The open containers' fields, materialized lazily from the
    /// frame stack when an advisor is consulted (`path[i]` mirrors
    /// `stack[i].field` for every materialized index); closes
    /// truncate it back in step.
    path: WalkLane<'s, FieldNumber>,
    rows: StoreLane<'s, Row>,
    /// The frame stack's high-water, folded at its one growth
    /// point (open) — the derived lanes' budget answer.
    frames_peak: usize,
    /// The path mirror's high-water, folded at its one growth
    /// point (consult).
    path_peak: usize,
    limit: DepthLimit,
    advice: &'v mut A,
}

impl<'a, 's, A: Advisor> Machine<'a, 's, '_, A> {
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
        while self.path.len() < self.stack.len() {
            let mirrored = self.stack.as_slice()[self.path.len()].field;
            // SAFETY: the path lane's capacity equals the frame
            // stack's, and the copy stops at the stack's length —
            // which the stack's own derivation bounds below that
            // shared capacity.
            unsafe { self.path.push_unchecked(mirrored) };
        }
        if self.path.len() > self.path_peak {
            self.path_peak = self.path.len();
        }
        self.advice.advise(Ancestry::new(self.path.as_slice()), field)
    }

    /// Pushes an open LEN and saves the live registers in it.
    fn open(&mut self, row: NodeId, field: FieldNumber, zone: Coord, absorbing: bool) {
        let frame =
            Frame { row, field, prev_zone: self.zone, prev_absorber: self.nearest_absorber };
        // SAFETY: `at_depth_limit` gated this open below the
        // caller's bound, and every open frame owns a distinct live
        // row pushed before it (this container's row included) —
        // so the new length stays at or below min(rows, limit), the
        // lane's carved capacity.
        unsafe { self.stack.push_unchecked(frame) };
        if self.stack.len() > self.frames_peak {
            self.frames_peak = self.stack.len();
        }
        self.zone = zone;
        if absorbing {
            self.nearest_absorber = Some(FrameAt::of(self.stack.len() - 1));
        }
    }

    /// Terminal write of a closing container: its subtree is
    /// exactly the rows pushed since it.
    const fn seal_descendants(&mut self, row: NodeId) {
        let descendants = RowCount::of(usize_of(self.rows.len()) - 1 - row.index());
        // Frame rows are in-table (minted before the frame pushed
        // and never truncated while it lives) — the lane's mint
        // provenance.
        self.rows.get_mut(row.as_inner()).descendants = descendants;
    }

    /// Disposes of a judged failure: unwind to the nearest
    /// absorbing frame (the speculation this failure concludes as
    /// "bytes"), or stop for the clip. Unwind is truncation —
    /// `descendants` is written only at close, so no written state
    /// needs repair.
    fn dispose(&mut self, failure: Failure) -> Result<(), Halt> {
        let Some(at) = self.nearest_absorber else {
            return Err(Halt::Stop(failure));
        };
        let idx = at.index();
        let absorber = self.stack.as_slice()[idx];
        // The absorber's own zone end: the live zone while it was
        // innermost — the frame above it saved that as `prev_zone`.
        let own_zone =
            self.stack.as_slice().get(idx + 1).map_or(self.zone, |above| above.prev_zone);
        // The demoted LEN keeps its row (a sealed leaf: descendants
        // stayed 0, its declared span is an input fact); everything
        // it speculated over — rows, inner frames, conditional
        // Message promises — evaporates. Order: restore the scalar
        // registers, truncate the path and the frame stack, and
        // only then truncate rows — the row mark moves only after
        // the doomed frames' ids have left the machine, which is
        // the store lane's truncation precondition (no held
        // coordinate crosses the mark: the surviving frames' rows
        // sit at or below the absorber's).
        self.cursor = own_zone;
        self.zone = absorber.prev_zone;
        self.nearest_absorber = absorber.prev_absorber;
        // The mirror may lag the stack (lazy materialization), so
        // clamp its mark to what was materialized.
        self.path.truncate(self.path.len().min(idx));
        self.stack.truncate(idx);
        self.rows.truncate(absorber.row.as_inner() + 1);
        Ok(())
    }

    /// Fault disposition sinks: the fault value takes shape here,
    /// off the parse's hot dispatch — only judged scalars cross
    /// the call.
    #[cold]
    fn halt(&mut self, at: u32, cut: u32, kind: FaultKind) -> Result<(), Halt> {
        // SAFETY (both mints): every position the machine reports
        // sits at or below the sealed zone end, which admission
        // bounds — in class.
        let fault = Fault { at: unsafe { Coord::new_unchecked(at) }, kind };
        self.dispose(Failure { fault, cut: unsafe { Coord::new_unchecked(cut) } })
    }

    /// A varint read refusal at a stage, sunk like [`Self::halt`].
    #[cold]
    fn halt_read(&mut self, at: u32, cut: u32, stage: Stage, cause: ReadFault) -> Result<(), Halt> {
        self.halt(at, cut, FaultKind::Read { stage, cause })
    }

    /// Closes the frame the extent end popped. Infallible: this
    /// dialect has no construct an extent end can leave
    /// unterminated.
    fn close_frame(&mut self, frame: Frame) {
        self.seal_descendants(frame.row);
        self.zone = frame.prev_zone;
        self.nearest_absorber = frame.prev_absorber;
        self.path.truncate(self.path.len().min(self.stack.len()));
    }

    fn run<const MINIMAL: bool>(mut self) -> Result<Tree<'a, 's>, OpenFault> {
        loop {
            debug_assert!(self.cursor <= self.zone);
            if self.cursor == self.zone {
                let Some(frame) = self.stack.pop() else {
                    return Ok(self.finish(None));
                };
                self.close_frame(frame);
                continue;
            }
            match self.record::<MINIMAL>() {
                Ok(()) => {}
                Err(Halt::Stop(failure)) => return Ok(self.clip(failure)),
                // No product is published and the lanes drop with
                // the machine — the slab holds no live state, its
                // contents unspecified; advisor effects stand.
                Err(Halt::Exhausted) => return Err(OpenFault::RowsExhausted),
            }
        }
    }

    /// Parses exactly one record at the cursor — or disposes of the
    /// judgment that refused it. One instance per acceptance
    /// standard: the tolerant instance folds every minimality test
    /// away; the canonical one judges each varint word between its
    /// read and its classification (the stream scanner's order, so
    /// a padded group or zero-field tag is a width refusal first).
    fn record<const MINIMAL: bool>(&mut self) -> Result<(), Halt> {
        let at = self.cursor.as_inner();
        let bytes = self.input.bytes();
        // SAFETY: zone ends are sealed within the admitted input
        // (a LEN seal is overrun-checked against its enclosing zone
        // at open, the root is the input's length), so
        // `self.zone <= bytes.len()`.
        let (word, tag_width) = match unsafe {
            slice::tag_word_trusted(bytes, usize_of(at), usize_of(self.zone.as_inner()))
        } {
            Ok(hit) => hit,
            Err(fault) => return self.halt_read(at, at, Stage::Tag, fault),
        };
        if MINIMAL && u32::from(tag_width) > encoded_len32(word) {
            return self.halt(at, at, FaultKind::NonMinimalTag);
        }
        // Field zero is an identity judgment on the whole tag word
        // and precedes any kind judgment (corpus-pinned precedence).
        let low3 = Low3::from_word(word);
        let Some(field) = FieldNumber::from_word(word) else {
            return self.halt(at, at, FaultKind::FieldZero { code: low3 });
        };
        // SAFETY: the kernel's tag window admits widths 1..=5.
        let tag_width = unsafe { WordWidth::met_unchecked(tag_width) };
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                self.varint_record::<MINIMAL>(at, field, tag_width)
            }
            TagClass::Record(kind @ (RecordKind::I64 | RecordKind::I32)) => {
                self.fixed_record(at, field, kind, tag_width)
            }
            TagClass::Record(RecordKind::Len) => self.len_record::<MINIMAL>(at, field, tag_width),
            TagClass::GroupCode => self.halt(at, at, FaultKind::GroupCode { field, code: low3 }),
            TagClass::Unassigned => self.halt(at, at, FaultKind::Unassigned { field, code: low3 }),
        }
    }

    /// VARINT: the value is sized in place, not kept — rows record
    /// spans, and `varint_word` re-reads on demand. The canonical
    /// instance decodes the value to judge its width; the tolerant
    /// one only sizes it.
    fn varint_record<const MINIMAL: bool>(
        &mut self,
        at: u32,
        field: FieldNumber,
        tag_width: WordWidth,
    ) -> Result<(), Halt> {
        let after_tag = at + u32::from(tag_width.as_inner());
        let width = if MINIMAL {
            // SAFETY: zone ends are sealed within the admitted
            // input (as in `record`).
            let (value, width) = match unsafe {
                slice::value64_trusted(
                    self.input.bytes(),
                    usize_of(after_tag),
                    usize_of(self.zone.as_inner()),
                )
            } {
                Ok(hit) => hit,
                Err(fault) => return self.halt_read(after_tag, at, Stage::Value { field }, fault),
            };
            if u32::from(width) > encoded_len64(value) {
                return self.halt(after_tag, at, FaultKind::NonMinimalValue { field });
            }
            width
        } else {
            // SAFETY: zone ends are sealed within the admitted
            // input (as in `record`).
            match unsafe {
                slice::width64_trusted(
                    self.input.bytes(),
                    usize_of(after_tag),
                    usize_of(self.zone.as_inner()),
                )
            } {
                Ok(hit) => hit,
                Err(fault) => return self.halt_read(after_tag, at, Stage::Value { field }, fault),
            }
        };
        self.push_leaf(at, field, RecordKind::Varint, tag_width, Extent::from_width(width), None)?;
        // SAFETY: the value's window was admitted inside the sealed
        // zone, so the advance stays at or below it — in class.
        self.cursor = unsafe { Coord::new_unchecked(after_tag + u32::from(width)) };
        Ok(())
    }

    fn fixed_record(
        &mut self,
        at: u32,
        field: FieldNumber,
        kind: RecordKind,
        tag_width: WordWidth,
    ) -> Result<(), Halt> {
        let after_tag = at + u32::from(tag_width.as_inner());
        let needed: u8 = if matches!(kind, RecordKind::I64) { 8 } else { 4 };
        if after_tag + u32::from(needed) > self.zone.as_inner() {
            return self.halt(after_tag, at, FaultKind::FixedTruncated { field, needed });
        }
        self.push_leaf(at, field, kind, tag_width, Extent::from_width(needed), None)?;
        // SAFETY: just judged the advance at or below the sealed
        // zone — in class.
        self.cursor = unsafe { Coord::new_unchecked(after_tag + u32::from(needed)) };
        Ok(())
    }

    fn len_record<const MINIMAL: bool>(
        &mut self,
        at: u32,
        field: FieldNumber,
        tag_width: WordWidth,
    ) -> Result<(), Halt> {
        let after_tag = at + u32::from(tag_width.as_inner());
        // SAFETY: zone ends are sealed within the admitted input
        // (as in `record`).
        let (declared, prefix_width) = match unsafe {
            slice::len_word_trusted(
                self.input.bytes(),
                usize_of(after_tag),
                usize_of(self.zone.as_inner()),
            )
        } {
            Ok(hit) => hit,
            Err(fault) => {
                return self.halt_read(after_tag, at, Stage::LenPrefix { field }, fault);
            }
        };
        if MINIMAL && u32::from(prefix_width) > encoded_len32(declared.as_inner()) {
            return self.halt(after_tag, at, FaultKind::NonMinimalLen { field });
        }
        // SAFETY: the kernel's prefix window admits widths 1..=5.
        let prefix_width = unsafe { WordWidth::met_unchecked(prefix_width) };
        let payload_start = after_tag + u32::from(prefix_width.as_inner());
        // Both terms are admission/class-bounded by i32::MAX, so
        // the sum stays within u32.
        let payload_end = payload_start + declared.as_inner();
        if payload_end > self.zone.as_inner() {
            let zone_left = self.zone.as_inner() - payload_start;
            return self.halt(after_tag, at, FaultKind::LenOverrun { field, declared, zone_left });
        }
        // SAFETY (both mints): just judged `payload_end` at or
        // below the sealed zone, and the start precedes the end —
        // both in class.
        let payload_end = unsafe { Coord::new_unchecked(payload_end) };
        let payload_start = unsafe { Coord::new_unchecked(payload_start) };
        let advice = self.consult(field);
        match advice {
            Advice::Opaque => {
                self.push_leaf(
                    at,
                    field,
                    RecordKind::Len,
                    tag_width,
                    Extent::from_len(declared),
                    Some(prefix_width),
                )?;
                self.cursor = payload_end;
                Ok(())
            }
            Advice::Speculate if self.at_depth_limit() => {
                // Too deep to speculate: demote to opaque — not a
                // document fault (the bytes may well be bytes).
                self.push_leaf(
                    at,
                    field,
                    RecordKind::Len,
                    tag_width,
                    Extent::from_len(declared),
                    Some(prefix_width),
                )?;
                self.cursor = payload_end;
                Ok(())
            }
            Advice::Commit if self.at_depth_limit() => {
                self.halt(at, at, FaultKind::DepthExceeded { field, limit: self.limit })
            }
            Advice::Speculate | Advice::Commit => {
                let absorbing = matches!(advice, Advice::Speculate);
                let row = mint(self.rows.len());
                self.push_leaf(
                    at,
                    field,
                    RecordKind::Len,
                    tag_width,
                    Extent::from_len(declared),
                    Some(prefix_width),
                )?;
                self.open(row, field, payload_end, absorbing);
                self.cursor = payload_start;
                Ok(())
            }
        }
    }

    /// Pushes one record row; the row arena is the plan's declared
    /// lane, so a spent capacity aborts the parse — exhaustion is
    /// never absorbed by a speculation (an absorbed exhaustion
    /// would make the message-vs-bytes verdict depend on the plan).
    fn push_leaf(
        &mut self,
        at: u32,
        field: FieldNumber,
        kind: RecordKind,
        tag_width: WordWidth,
        payload_len: Extent,
        delim_width: Option<WordWidth>,
    ) -> Result<(), Halt> {
        // SAFETY: every caller passes the record head's cursor,
        // which the run loop holds strictly below the sealed zone
        // end — inside the admitted input, so the offset is in
        // class.
        let start = unsafe { Coord::new_unchecked(at) };
        let row = Row {
            start,
            payload_len,
            parent: self.parent_row(),
            descendants: RowCount::MIN,
            field,
            kind,
            tag_width,
            delim_width,
        };
        if self.rows.push(row).is_none() {
            return Err(Halt::Exhausted);
        }
        Ok(())
    }

    /// Stops: clips every open LEN with the same close-time writes
    /// as a normal pop. LEN rows keep their declared spans (the
    /// seal is an input fact independent of parse progress); only
    /// `descendants` needs the terminal write.
    fn clip(mut self, failure: Failure) -> Tree<'a, 's> {
        while let Some(frame) = self.stack.pop() {
            self.seal_descendants(frame.row);
        }
        self.finish_at(failure.cut, Some(failure.fault))
    }

    const fn finish(self, fault: Option<Fault>) -> Tree<'a, 's> {
        let end = self.input.end();
        self.finish_at(end, fault)
    }

    const fn finish_at(self, indexed_end: Coord, fault: Option<Fault>) -> Tree<'a, 's> {
        // Lossless: both peaks are bounded by their lanes' carved
        // capacities, which derive from u32 counts.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "see above")]
        let (frames, path) = (
            Gauge { used: self.frames_peak as u32, capacity: self.stack.capacity() as u32 },
            Gauge { used: self.path_peak as u32, capacity: self.path.capacity() as u32 },
        );
        Tree { input: self.input, rows: self.rows, indexed_end, fault, frames, path }
    }
}
