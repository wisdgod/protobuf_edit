//! The grouped overhaul: groups are transparent containers.
//!
//! Groups are containers framed by tags — no length prefix — so
//! the open walk cannot skip them: it walks their interiors as
//! part of the layer, matching end tags against the open stack,
//! and their rows are standing from the start (a group descend
//! answers walk-free). LEN payloads keep the opaque-declaration
//! law: skipped through the supply's own seek until a descend
//! commits to them. Zero source bytes are retained either way;
//! every scalar word is banked in its row as the walk decodes it
//! to step.
//!
//! Group nesting spends the declared depth budget at the walk
//! that meets it — the open walk for source groups, the descend
//! walk for groups inside a LEN interior.
//!
//! Coordinates: write · sequential-repeatable · offline · grouped · tolerant (type-level) · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::overhaul::InsertAt;
//! use protobuf_edit::overhaul::grouped::Overhaul;
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::wire::FieldNumber;
//!
//! // group f1 { varint f2=1 } · varint f2=42
//! let msg = [0x0B, 0x10, 0x01, 0x0C, 0x10, 0x2A];
//! let mut editor =
//!     Overhaul::open(SliceSource::new(&msg), DepthLimit::REFERENCE).unwrap();
//!
//! // The group's interior is standing: no descend walk owed.
//! let tops: Vec<_> = editor.top().collect();
//! let inner = editor.children(tops[0]).next().unwrap();
//! editor.set_varint(inner, 7).unwrap();
//! editor
//!     .insert_varint(InsertAt::TailOf(Some(tops[0])), FieldNumber::new(3).unwrap(), 2)
//!     .unwrap();
//!
//! let saved = editor.save().unwrap();
//! assert_eq!(saved, [0x0B, 0x10, 0x07, 0x18, 0x02, 0x0C, 0x10, 0x2A]);
//! ```

use alloc::vec::Vec;

use super::{EditStatus, Handle, InsertAt, RowId, SaveFault, Stage, mint};
use crate::admission::usize_of;
use crate::replay_pump::{GrabRead, Pump, StepRead};
use crate::replay_script::{FoldFault, Script, fold};
use crate::replay_source::{
    Handed, ReplayFault, ReplayPhase, ReplayWalk, SourceSpan, StableReplaySource, SupplyFault,
};
use crate::varint::{WordWidth, encoded_len32, encoded_len64};
use crate::wire::grouped::{RecordKind, TagClass, classify};
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
/// This machine is the tolerant instance, so no minimality
/// judgments exist in its vocabulary. Wire-declared quantities
/// are quoted as their wire types; a bad record never reaches the
/// row table, so its field number travels with the fault — inside
/// the [`Stage`] coordinate for varint reads (the tag stage
/// carries none: no field exists yet), on the variant elsewhere.
/// Group framing has its own grammar section: end tags are
/// punctuation, never records, and every mispairing names the
/// fields on both sides of the break.
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
    /// A declared length punctures the enclosing seal (at the
    /// root: the source's actual end).
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
    // ─ grammar: group framing ─
    /// An end-of-group tag with no group open in this extent.
    GroupEndOrphan {
        /// The end tag's field number.
        found: FieldNumber,
    },
    /// An end-of-group tag whose field differs from the innermost
    /// open group's.
    GroupEndMismatch {
        /// The innermost open group's field.
        open: FieldNumber,
        /// The end tag's field.
        found: FieldNumber,
    },
    /// The extent (or the source) ended around an open group: its
    /// end tag never appeared (groups may not cross LEN
    /// boundaries).
    GroupUnclosed {
        /// The open group's field.
        open: FieldNumber,
    },
    // ─ policy: the caller's bound ─
    /// Opening this container would exceed the caller's declared
    /// [`DepthLimit`]. For a LEN it is a descend refusal, resident
    /// like any other parked verdict; for a group the walk that
    /// meets the nesting refuses whole (groups are scanned, never
    /// parked).
    DepthExceeded {
        /// The container's field number.
        field: FieldNumber,
        /// The bound that refused.
        limit: DepthLimit,
    },
    // ─ capability: the coordinate space ─
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
    /// the variant (the [`DepthLimit`] bound).
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Read { .. }
            | Self::FieldZero { .. }
            | Self::Unassigned { .. }
            | Self::LenOverrun { .. }
            | Self::FixedTruncated { .. }
            | Self::GroupEndOrphan { .. }
            | Self::GroupEndMismatch { .. }
            | Self::GroupUnclosed { .. } => FaultClass::Grammar,
            Self::DepthExceeded { .. } => FaultClass::Policy,
            Self::LenUnsatisfiable { .. } => FaultClass::Capability,
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
            Self::GroupEndOrphan { found } => {
                write!(f, "end tag names field {} but no group is open here", found.as_inner())
            }
            Self::GroupEndMismatch { open, found } => write!(
                f,
                "end tag names field {} while group field {} is open",
                found.as_inner(),
                open.as_inner()
            ),
            Self::GroupUnclosed { open } => {
                write!(f, "group of field {} never closes", open.as_inner())
            }
            Self::DepthExceeded { field, limit } => write!(
                f,
                "container of field {} nests beyond the bound of {}",
                field.as_inner(),
                limit.as_inner()
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

/// Why an editor refused to open.
///
/// Unlike the survey's resident fault, the one-shot editors
/// refuse an unlawful root layer whole (the buffered twins' law:
/// a document that cannot be saved back faithfully is refused
/// before any handle is minted); the source rides back beside
/// the mark.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenFault<E> {
    /// The root layer violates the wire grammar, the declared
    /// depth bound (source groups nest at the open walk), or the
    /// coordinate space's hosting judgment.
    Wire(Fault),
    /// The supply refused (transport or a detected snapshot
    /// break) during the index walk.
    Source(ReplayFault<E>),
    /// The record count would leave the row-index class.
    IndexOverflow {
        /// The source offset of the record that would not fit.
        at: u64,
    },
    /// The accumulated source offset would leave the addressable
    /// coordinate space (`u64::MAX − 1`).
    OffsetExhausted {
        /// The offset the refused view would have crossed.
        at: u64,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for OpenFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire(fault) => write!(f, "root layer: {fault}"),
            Self::Source(fault) => write!(f, "{fault}"),
            Self::IndexOverflow { at } => {
                write!(f, "the record at source offset {at} would leave the row-index class")
            }
            Self::OffsetExhausted { at } => {
                write!(f, "the source ran past the addressable space at offset {at}")
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for OpenFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(fault) => Some(fault),
            Self::Source(fault) => Some(fault),
            Self::IndexOverflow { .. } | Self::OffsetExhausted { .. } => None,
        }
    }
}

/// Why an edit command refused. Failure classes are judged in no
/// promised order within one call; on any `Err` the editor is
/// unchanged.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EditFault {
    /// The record's wire kind does not fit the command.
    KindMismatch {
        /// The record's actual kind.
        have: RecordKind,
    },
    /// The record is deleted; commit-only editing cannot restore
    /// it.
    DeletedTarget,
    /// The record's interior is open for editing; edit it in
    /// place or delete the record instead of replacing the
    /// payload wholesale.
    OpenedTarget,
    /// Descend the container before inserting into it.
    TargetUnopened,
    /// The record's payload is authored; there is no source
    /// interior to open.
    AuthoredPayload,
    /// The payload exceeds the length class.
    PayloadTooLarge {
        /// The refused payload length.
        len: usize,
    },
    /// The editor's edit storage is full; the refusal is
    /// permanent for this editor.
    IndexSpaceExhausted,
}

impl core::fmt::Display for EditFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::KindMismatch { have } => {
                write!(f, "the command expects another wire kind; the record is {have:?}")
            }
            Self::DeletedTarget => f.write_str("the record is deleted and cannot be restored"),
            Self::OpenedTarget => {
                f.write_str("the record's interior is open for editing; edit it in place")
            }
            Self::TargetUnopened => f.write_str("descend the container before inserting into it"),
            Self::AuthoredPayload => {
                f.write_str("the record's payload is authored; there is no source interior")
            }
            Self::PayloadTooLarge { len } => {
                write!(f, "payload of {len} bytes exceeds the length class")
            }
            Self::IndexSpaceExhausted => f.write_str("the editor's edit storage is full"),
        }
    }
}

impl core::error::Error for EditFault {}

/// Why a descend (or materialize) walk aborted without a
/// resident verdict.
///
/// Nothing about the *document* was judged — the target gate
/// refused, the supply refused, or the walk's length shape
/// contradicted the measured coordinates. The editor is exactly
/// as before the call (verdicts already parked by an earlier
/// extent of the same batch stand — each extent commits
/// atomically).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DescendFault<E> {
    /// The target gate refused (kind, deleted, authored).
    Edit(EditFault),
    /// The supply refused (transport or a detected snapshot
    /// break).
    Source(ReplayFault<E>),
    /// The walk met its end before a measured coordinate — a
    /// length-shaped tear.
    Torn {
        /// The measured coordinate the walk could not honor.
        at: u64,
    },
    /// The interior rows would leave the row-index class (the
    /// verdict is not parked).
    IndexOverflow {
        /// The source offset of the record that would not fit.
        at: u64,
    },
    /// The accumulated source offset would leave the addressable
    /// coordinate space (`u64::MAX − 1`).
    OffsetExhausted {
        /// The offset the refused view would have crossed.
        at: u64,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for DescendFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Edit(fault) => write!(f, "{fault}"),
            Self::Source(fault) => write!(f, "{fault}"),
            Self::Torn { at } => {
                write!(f, "the source tore against measured coordinate {at}")
            }
            Self::IndexOverflow { at } => {
                write!(f, "the record at source offset {at} would leave the row-index class")
            }
            Self::OffsetExhausted { at } => {
                write!(f, "the source ran past the addressable space at offset {at}")
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for DescendFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Edit(fault) => Some(fault),
            Self::Source(fault) => Some(fault),
            Self::Torn { .. } | Self::IndexOverflow { .. } | Self::OffsetExhausted { .. } => None,
        }
    }
}

/// A fetch refusal: the walk that was to answer a byte question
/// could not, and the editor is exactly as before the call
/// (the `Vec` face hands nothing; the sink face reports its
/// handed prefix).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FetchFault<E> {
    /// The record is not a LEN record, so no payload extent
    /// exists to fetch (scalar values are row-resident:
    /// `varint_word`, `i32_bits`, `i64_bits`; a group's interior
    /// is standing records, walked through `children`).
    KindMismatch {
        /// The record's actual kind.
        have: RecordKind,
    },
    /// The extent does not fit the address space, so the `Vec`
    /// face cannot stage it (the sink face has no such ceiling).
    Oversize {
        /// The extent's byte length.
        len: u64,
    },
    /// The walk met its end before a coordinate the index walk
    /// measured — a length-shaped tear, refused.
    Torn {
        /// The measured coordinate the walk could not reach.
        at: u64,
    },
    /// The supply refused (transport or a detected snapshot
    /// break).
    Source(ReplayFault<E>),
}

impl<E: core::fmt::Display> core::fmt::Display for FetchFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::KindMismatch { have } => {
                write!(f, "the fetch expects a LEN record; the record is {have:?}")
            }
            Self::Oversize { len } => {
                write!(f, "an extent of {len} bytes cannot stage in the address space")
            }
            Self::Torn { at } => {
                write!(f, "the source ended before the measured coordinate {at}")
            }
            Self::Source(fault) => write!(f, "{fault}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for FetchFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Source(fault) => Some(fault),
            Self::KindMismatch { .. } | Self::Oversize { .. } | Self::Torn { .. } => None,
        }
    }
}

// ─── verdicts and geometry ───

/// A descend verdict.
///
/// Parked verdicts are resident: they live on the record and
/// project unchanged on every later call — no further walk is
/// spent on a judged payload — while the payload stays readable
/// as bytes.
#[must_use = "the verdict reports whether the payload opened or a refusal parked"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Descent<'p> {
    /// The payload parsed; its first child, if any.
    Opened {
        /// First record of the interior layer.
        first: Option<Handle>,
    },
    /// The payload refused — a wire violation, the dialect
    /// capability, or the declared depth bound ([`FaultKind`]
    /// carries the class) — and the verdict parked (resident).
    ///
    /// A parked verdict is a document claim only under the
    /// provider's byte-identity obligation: the descend walk
    /// cannot see growth or displacement beneath its measured
    /// coordinates, so a breached obligation can park a fault the
    /// document's bytes never spelled.
    Parked(&'p Fault),
}

/// Source geometry of one scanned record.
///
/// The segments partition the record's span exactly, at the widths
/// the scan actually met — padded framing included. Coordinates
/// answer for the source bytes, not for any pending edit.
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
    /// A group: head tag, interior records, end tag.
    Group {
        /// The head tag.
        tag: SourceSpan,
        /// The interior records (the walk-measured extent).
        interior: SourceSpan,
        /// The end tag.
        end: SourceSpan,
    },
    /// A fixed 32-bit record: head tag, four value bytes.
    I32 {
        /// The head tag.
        tag: SourceSpan,
        /// The value bytes.
        value: SourceSpan,
    },
}

// ─── rows ───

/// `Row.state` bits 0–1: the base edit state.
const BASE_MASK: u8 = 0b11;
const BASE_INTACT: u8 = 0;
const BASE_REPLACED: u8 = 1;
const BASE_INSERTED: u8 = 2;
/// `Row.state`: deleted — the record vanishes whole at save,
/// subtree included. Orthogonal to the base: the value side stays
/// readable.
const FLAG_DELETED: u8 = 1 << 2;
/// `Row.state`: a LEN's payload parsed; `Row.kid` anchors the
/// interior chain.
const FLAG_OPENED: u8 = 1 << 3;
/// `Row.state`: a LEN's descend parked a resident verdict;
/// `Row.value` holds its fault-table index.
const FLAG_FAULTED: u8 = 1 << 4;
/// The subtree edit witness: this record, or one beneath it, was
/// replaced, deleted, or had an insertion spliced in. Monotone —
/// commit-only offers no path that clears an edit — so ancestors
/// accumulate it on the way up and the save's verbatim arm trusts
/// its absence.
const FLAG_TOUCHED: u8 = 1 << 5;

/// The base edit state, decoded from the row's state bits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Base {
    Intact,
    Replaced,
    Inserted,
}

/// One record, packed to 48 bytes. Private: the editor projects
/// it.
///
/// Partition theorem: a scanned record's bytes are `tag ⊎ delim ⊎
/// payload`; the delimiter is LEN's length prefix (preceding the
/// payload) or a group's end tag (following the interior) —
/// positions differ, the width sum does not, so the span-end
/// formula is one branch-free expression while the payload start
/// branches by kind. Scalars carry `None`. Widths are stored
/// input facts: padding is accepted and span arithmetic must
/// reproduce it byte-exactly. Authored rows carry no source
/// geometry; their emission is minimal by construction.
///
/// The word column banks every scalar's decoded value at the scan
/// and is overwritten in place by the value commands — the row is
/// its own value store, so scalar queries never walk and the save
/// re-encodes from the word alone.
#[derive(Clone, Copy)]
struct Row {
    /// Head tag's first byte (whole-source offset; authored rows:
    /// zero, never read).
    start: u64,
    /// Scanned payload extent. LEN: declared; Group: the measured
    /// interior span; Varint: the value's encoded width; I32/I64:
    /// 4/8. Authored rows: zero.
    payload_len: u64,
    /// The scalar's current word (LEN rows: zero).
    word: u64,
    /// Enclosing container (`None`: root level).
    parent: Option<RowId>,
    /// First record of the interior chain (opened LENs).
    kid: Option<RowId>,
    /// Next sibling in the chain.
    next: Option<RowId>,
    /// Payload-slot index (replaced/inserted LENs) or fault-table
    /// index (parked verdicts) — the two uses are disjoint states.
    value: u32,
    /// The head tag's field number.
    field: FieldNumber,
    /// The record kind (the dialect table's vocabulary, verbatim).
    kind: RecordKind,
    /// The head tag's actual input width (authored rows: 1,
    /// never read).
    tag_width: WordWidth,
    /// LEN: the length prefix's actual width. Group: the end
    /// tag's actual width, recorded at its close. Scalars and
    /// authored rows: `None`.
    delim_width: Option<WordWidth>,
    /// Base bits and the deleted/opened/faulted/touched flags.
    state: u8,
}

const _: () = assert!(core::mem::size_of::<Row>() == 48);
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

    /// End of the whole-record span (scanned rows only). The
    /// delimiter's position differs by kind — LEN's prefix
    /// precedes the payload, a group's end tag follows the
    /// interior — but the width sum is position-free.
    const fn span_end(&self) -> u64 {
        self.start + self.tag_w() + self.delim_w() + self.payload_len
    }

    /// The payload extent's start (scanned rows only): past the
    /// length prefix for LEN, right after the head tag for a
    /// group's interior.
    const fn payload_at(&self) -> u64 {
        match self.kind {
            RecordKind::Group => self.start + self.tag_w(),
            RecordKind::Varint | RecordKind::I64 | RecordKind::Len | RecordKind::I32 => {
                self.start + self.tag_w() + self.delim_w()
            }
        }
    }

    const fn base(&self) -> Base {
        match self.state & BASE_MASK {
            BASE_INTACT => Base::Intact,
            BASE_REPLACED => Base::Replaced,
            _ => Base::Inserted,
        }
    }

    const fn deleted(&self) -> bool {
        self.state & FLAG_DELETED != 0
    }

    const fn opened(&self) -> bool {
        self.state & FLAG_OPENED != 0
    }

    const fn faulted(&self) -> bool {
        self.state & FLAG_FAULTED != 0
    }

    /// True when the whole source span (subtree included) can
    /// ride the save verbatim: source-endorsed, not deleted, and
    /// no edit witnessed at or beneath it.
    const fn rides_verbatim(&self) -> bool {
        self.state & (BASE_MASK | FLAG_DELETED | FLAG_TOUCHED) == 0
    }

    /// True for source-endorsed rows (scanned, not authored):
    /// their spans are source geometry the save can skip or copy.
    const fn scanned(&self) -> bool {
        !matches!(self.base(), Base::Inserted)
    }
}

/// One authored payload of the mixed form: borrowed until the
/// save copies it into the output, or staged by copy at the
/// command.
#[derive(Clone, Copy)]
enum PayloadSlot<'p> {
    Borrowed(&'p [u8]),
    Copied {
        /// Arena range.
        start: usize,
        end: usize,
    },
}

/// Mints the next slot coordinate, admitted against the slot
/// index class.
fn mint_slot(len: usize) -> Result<u32, EditFault> {
    u32::try_from(len).ok().filter(|&at| at != u32::MAX).ok_or(EditFault::IndexSpaceExhausted)
}

/// The mixed form's authored store: the slot table and the
/// copied-byte arena behind the `_copy` faces.
struct Store<'p> {
    slots: Vec<PayloadSlot<'p>>,
    /// Copied payload bytes ([`PayloadSlot::Copied`] ranges).
    arena: Vec<u8>,
}

impl<'p> Store<'p> {
    const fn new() -> Self {
        Self { slots: Vec::new(), arena: Vec::new() }
    }

    /// Registers a borrowed payload; returns its slot.
    fn push_borrowed(&mut self, payload: &'p [u8]) -> Result<u32, EditFault> {
        let at = mint_slot(self.slots.len())?;
        self.slots.push(PayloadSlot::Borrowed(payload));
        Ok(at)
    }

    /// Stages a copied payload; returns its slot.
    fn push_copied(&mut self, payload: &[u8]) -> Result<u32, EditFault> {
        let at = mint_slot(self.slots.len())?;
        let start = self.arena.len();
        self.arena.extend_from_slice(payload);
        self.slots.push(PayloadSlot::Copied { start, end: self.arena.len() });
        Ok(at)
    }

    /// The authored bytes behind a payload slot.
    fn payload_of(&self, slot: u32) -> &[u8] {
        match self.slots[usize_of(slot)] {
            PayloadSlot::Borrowed(bytes) => bytes,
            PayloadSlot::Copied { start, end } => &self.arena[start..end],
        }
    }
}

/// The borrowed-only form's authored store: the slot table alone
/// — no copied column exists, which is the form's saved `Vec`
/// (the layout pin below the machines holds the delta).
struct BorrowStore<'p> {
    slots: Vec<&'p [u8]>,
}

impl<'p> BorrowStore<'p> {
    const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Registers a borrowed payload; returns its slot.
    fn push_borrowed(&mut self, payload: &'p [u8]) -> Result<u32, EditFault> {
        let at = mint_slot(self.slots.len())?;
        self.slots.push(payload);
        Ok(at)
    }

    /// The authored bytes behind a payload slot.
    fn payload_of(&self, slot: u32) -> &[u8] {
        self.slots[usize_of(slot)]
    }
}

/// The copy-only form's authored store: extent slots over the
/// copied-byte arena — no borrow arm, so no payload lifetime
/// binds the machine.
struct CopyStore {
    /// Arena ranges, one per slot.
    slots: Vec<(usize, usize)>,
    /// Copied payload bytes, end to end.
    arena: Vec<u8>,
}

impl CopyStore {
    const fn new() -> Self {
        Self { slots: Vec::new(), arena: Vec::new() }
    }

    /// Stages a copied payload; returns its slot.
    fn push_copied(&mut self, payload: &[u8]) -> Result<u32, EditFault> {
        let at = mint_slot(self.slots.len())?;
        let start = self.arena.len();
        self.arena.extend_from_slice(payload);
        self.slots.push((start, self.arena.len()));
        Ok(at)
    }

    /// The authored bytes behind a payload slot.
    fn payload_of(&self, slot: u32) -> &[u8] {
        let (start, end) = self.slots[usize_of(slot)];
        &self.arena[start..end]
    }
}

// ─── the editor (one arm per payload-backing form) ───

/// The public handle gate: every handle-taking face passes here,
/// and the slice index is the documented forgery panic.
#[track_caller]
const fn gate(rows: &[Row], handle: Handle) -> &Row {
    &rows[handle.0.index()]
}

/// Emits one overhaul machine form: the struct (its store form is
/// the parameter) and the whole face set — doors, observation,
/// descend and materialize, fetch, commands, and the saves. The
/// payload-command faces ride the `@payload` arms below, selected
/// per form.
macro_rules! overhaul_machine {
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident $(<$plt:lifetime>)?,
        store: $Store:ty,
        pay: $pay:ident $(,)?
    ) => {
        $(#[$mdoc])*
        pub struct $Machine<$($plt,)? S: StableReplaySource> {
            source: S,
            /// The measured total length (the open walk's end), the torn
            /// law's anchor for every later walk.
            total: u64,
            rows: Vec<Row>,
            /// First record of the top-layer chain.
            top: Option<RowId>,
            store: $Store,
            /// Parked descend verdicts.
            faults: Vec<Fault>,
            limit: DepthLimit,
            dirty: bool,
        }

        impl<$($plt,)? S: StableReplaySource> $Machine<$($plt,)? S> {
    /// Opens the editor: one walk scans the top layer — group
    /// interiors walked transparently (their rows are standing
    /// from here), LEN payloads staying opaque declarations,
    /// skipped through the supply's own seek — and measures the
    /// source's total length. An unlawful root layer refuses
    /// whole; the source rides back beside the mark.
    ///
    /// `depth` bounds container nesting, with no default: source
    /// groups spend it at this walk (they scan transparently),
    /// LEN interiors at their descend walks.
    ///
    /// # Errors
    ///
    /// `(source, OpenFault)` — the source beside the mark — when
    /// the root layer is unlawful (group nesting past the bound
    /// included), the supply refuses mid-walk, the record count
    /// would leave the row-index class, or the offset would leave
    /// the coordinate space.
    pub fn open(mut source: S, depth: DepthLimit) -> Result<Self, (S, OpenFault<S::Error>)> {
        let mut rows: Vec<Row> = Vec::new();
        let outcome = match source.begin() {
            Ok(walk) => {
                let mut pump = Pump::new(walk);
                scan_layer(&mut pump, &mut rows, None, None, 0, depth)
                    .map(|first| (first, pump.off))
            }
            Err(fault) => {
                Err(Halt::Source(ReplayFault::Rewind { phase: ReplayPhase::Index, source: fault }))
            }
        };
        match outcome {
            Ok((first, total)) => Ok(Self {
                source,
                total,
                rows,
                top: first,
                store: <$Store>::new(),
                faults: Vec::new(),
                limit: depth,
                dirty: false,
            }),
            Err(halt) => {
                let fault = match halt {
                    Halt::Wire(fault) => OpenFault::Wire(fault),
                    Halt::Source(fault) => OpenFault::Source(fault),
                    // The open walk measures: a walk end is a
                    // document property (truncation), never a tear.
                    Halt::Torn { .. } => unreachable!("the measuring walk has no earlier anchor"),
                    Halt::IndexOverflow { at } => OpenFault::IndexOverflow { at },
                    Halt::OffsetExhausted { at } => OpenFault::OffsetExhausted { at },
                };
                Err((source, fault))
            }
        }
    }

    /// Releases the source handle. The rows are dropped; spans
    /// taken earlier remain plain numbers over the source's byte
    /// sequence.
    #[inline]
    #[must_use]
    pub fn into_source(self) -> S {
        self.source
    }

    /// The measured total source length (the open walk's end).
    #[inline]
    #[must_use]
    pub const fn source_len(&self) -> u64 {
        self.total
    }

    fn row_mut(&mut self, id: RowId) -> &mut Row {
        &mut self.rows[id.index()]
    }

    fn row(&self, id: RowId) -> &Row {
        &self.rows[id.index()]
    }

    /// Marks the row and its ancestors as edit witnesses. Monotone:
    /// the climb stops at the first already-touched ancestor.
    fn mark_dirty(&mut self, id: RowId) {
        self.dirty = true;
        let mut cur = Some(id);
        while let Some(at) = cur {
            let row = self.row_mut(at);
            if row.state & FLAG_TOUCHED != 0 {
                break;
            }
            row.state |= FLAG_TOUCHED;
            cur = row.parent;
        }
    }

    /// Container nesting depth (root records: zero).
    fn depth_of(&self, id: RowId) -> u32 {
        let mut depth = 0;
        let mut cur = self.row(id).parent;
        while let Some(at) = cur {
            depth += 1;
            cur = self.row(at).parent;
        }
        depth
    }

    // ─ navigation ─

    /// Iterates the top-layer records.
    #[inline]
    pub fn top(&self) -> Children<'_> {
        Children { rows: &self.rows, cur: self.top }
    }

    /// Iterates `handle`'s direct children (empty for leaves and
    /// undescended payloads).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[track_caller]
    pub fn children(&self, handle: Handle) -> Children<'_> {
        Children { rows: &self.rows, cur: gate(&self.rows, handle).kid }
    }

    /// The enclosing container (`None`: root level).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn parent(&self, handle: Handle) -> Option<Handle> {
        gate(&self.rows, handle).parent.map(Handle)
    }

    /// The record's field number.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[track_caller]
    pub fn field(&self, handle: Handle) -> FieldNumber {
        gate(&self.rows, handle).field
    }

    /// The record's wire kind.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn kind(&self, handle: Handle) -> RecordKind {
        gate(&self.rows, handle).kind
    }

    /// The record's observable edit state.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn status(&self, handle: Handle) -> EditStatus {
        let row = gate(&self.rows, handle);
        if row.deleted() {
            return EditStatus::Deleted;
        }
        match row.base() {
            Base::Intact => EditStatus::Intact,
            Base::Replaced => EditStatus::Replaced,
            Base::Inserted => EditStatus::Inserted,
        }
    }

    /// The whole-record source span (`None`: an authored record —
    /// no source geometry exists). Coordinates answer for the
    /// source bytes, not for any pending edit.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn span(&self, handle: Handle) -> Option<SourceSpan> {
        let row = gate(&self.rows, handle);
        row.scanned().then(|| SourceSpan::new(row.start, row.span_end()))
    }

    /// The record's source geometry: every segment in one
    /// kind-indexed answer (`None`: an authored record). Widths
    /// are the stored input facts (padded encodings reproduce
    /// byte-exactly).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[must_use]
    #[track_caller]
    pub fn source_spans(&self, handle: Handle) -> Option<RecordSpans> {
        let row = gate(&self.rows, handle);
        if !row.scanned() {
            return None;
        }
        let tag = SourceSpan::new(row.start, row.start + row.tag_w());
        Some(match row.kind {
            RecordKind::Varint => RecordSpans::Varint {
                tag,
                value: SourceSpan::new(tag.end(), tag.end() + row.payload_len),
            },
            RecordKind::I64 => RecordSpans::I64 {
                tag,
                value: SourceSpan::new(tag.end(), tag.end() + row.payload_len),
            },
            RecordKind::Len => {
                let prefix = SourceSpan::new(tag.end(), tag.end() + row.delim_w());
                RecordSpans::Len {
                    tag,
                    prefix,
                    payload: SourceSpan::new(prefix.end(), prefix.end() + row.payload_len),
                }
            }
            RecordKind::Group => {
                let interior = SourceSpan::new(tag.end(), tag.end() + row.payload_len);
                RecordSpans::Group {
                    tag,
                    interior,
                    end: SourceSpan::new(interior.end(), interior.end() + row.delim_w()),
                }
            }
            RecordKind::I32 => RecordSpans::I32 {
                tag,
                value: SourceSpan::new(tag.end(), tag.end() + row.payload_len),
            },
        })
    }

    // ─ values ─

    /// The varint record's current value (`None`: not a VARINT
    /// record): the pending replacement if one is set, the
    /// scanned value otherwise (deleted records keep answering —
    /// deletion only prunes the save). Row-resident, no source
    /// walk.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn varint_word(&self, handle: Handle) -> Option<u64> {
        let row = gate(&self.rows, handle);
        matches!(row.kind, RecordKind::Varint).then_some(row.word)
    }

    /// The fixed 32-bit record's current value bits (`None`: not
    /// an I32 record). Row-resident, no source walk.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    #[allow(
        clippy::as_conversions,
        reason = "an I32 row's word column holds four bytes' bits, so it fits u32"
    )]
    pub fn i32_bits(&self, handle: Handle) -> Option<u32> {
        let row = gate(&self.rows, handle);
        matches!(row.kind, RecordKind::I32).then_some(row.word as u32)
    }

    /// The fixed 64-bit record's current value bits (`None`: not
    /// an I64 record). Row-resident, no source walk.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn i64_bits(&self, handle: Handle) -> Option<u64> {
        let row = gate(&self.rows, handle);
        matches!(row.kind, RecordKind::I64).then_some(row.word)
    }

    // ─ descend ─

    /// Parks a resident refusal on the record and projects it.
    fn park(&mut self, id: RowId, fault: Fault) -> Descent<'_> {
        let slot = park_in(&mut self.rows, &mut self.faults, id, fault);
        Descent::Parked(&self.faults[usize_of(slot)])
    }

    /// The descend gate shared with `materialize`: `Err` is the
    /// caller's target fault; `Ok(false)` means the interior is
    /// already standing (groups always, and LENs with a resident
    /// verdict or an empty extent); `Ok(true)` means a walk is
    /// owed.
    fn descend_gate(&mut self, id: RowId) -> Result<bool, EditFault> {
        let row = *self.row(id);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        match row.kind {
            // A group's interior is standing from the walk that
            // scanned it (authored groups: from the command).
            RecordKind::Group => return Ok(false),
            RecordKind::Len => {}
            RecordKind::Varint | RecordKind::I64 | RecordKind::I32 => {
                return Err(EditFault::KindMismatch { have: row.kind });
            }
        }
        if !matches!(row.base(), Base::Intact) {
            return Err(EditFault::AuthoredPayload);
        }
        if row.opened() || row.faulted() {
            return Ok(false);
        }
        if row.payload_len == 0 {
            // An empty payload opens without a walk: there is
            // nothing to parse.
            self.row_mut(id).state |= FLAG_OPENED;
            return Ok(false);
        }
        Ok(true)
    }

    /// Opens a container's interior for editing. A group's
    /// interior is standing from the walk that scanned it, so a
    /// group descend answers walk-free, always. A LEN payload
    /// parses on the first call — an explicit commitment that
    /// these bytes are a message, never a speculation — and the
    /// verdict is resident: a wire fault or the declared depth
    /// bound parks on the record and projects unchanged on every
    /// later call, costing no further walk. One walk per fresh
    /// verdict (an empty payload opens walk-free).
    ///
    /// The parse trusts the provider's byte-identity obligation:
    /// the walk verifies only that the source still reaches the
    /// extent's end, so bytes that moved beneath unchanged
    /// coordinates are judged as the document's own — a breached
    /// obligation can park a verdict the document's bytes never
    /// spelled ([`Descent::Parked`]).
    ///
    /// # Errors
    ///
    /// [`DescendFault::Edit`] when the target gate refuses
    /// (scalars, deleted records, authored payloads);
    /// [`DescendFault::Source`], [`DescendFault::Torn`] when the
    /// supply refuses or tears (no verdict parks — nothing about
    /// the document was judged); [`DescendFault::IndexOverflow`]
    /// when the interior rows outgrow the row domain. On any
    /// `Err` the editor is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[track_caller]
    pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, DescendFault<S::Error>> {
        let id = handle.0;
        let _ = gate(&self.rows, handle);
        if !self.descend_gate(id).map_err(DescendFault::Edit)? {
            let row = self.row(id);
            if row.faulted() {
                let slot = row.value;
                return Ok(Descent::Parked(&self.faults[usize_of(slot)]));
            }
            return Ok(Descent::Opened { first: self.row(id).kid.map(Handle) });
        }
        if self.depth_of(id) >= u32::from(self.limit.as_inner()) {
            let row = self.row(id);
            let fault = Fault {
                at: row.start,
                kind: FaultKind::DepthExceeded { field: row.field, limit: self.limit },
            };
            return Ok(self.park(id, fault));
        }
        let (start, end) = {
            let row = self.row(id);
            (row.payload_at(), row.payload_at() + row.payload_len)
        };
        let base = self.depth_of(id) + 1;
        let mark = self.rows.len();
        let outcome =
            scan_extent(&mut self.source, &mut self.rows, id, start, end, base, self.limit);
        match outcome {
            Ok(first) => {
                let row = self.row_mut(id);
                row.kid = first;
                row.state |= FLAG_OPENED;
                Ok(Descent::Opened { first: first.map(Handle) })
            }
            Err(halt) => {
                self.rows.truncate(mark);
                match halt {
                    Halt::Wire(fault) => Ok(self.park(id, fault)),
                    Halt::Source(fault) => Err(DescendFault::Source(fault)),
                    Halt::Torn { at } => Err(DescendFault::Torn { at }),
                    Halt::IndexOverflow { at } => Err(DescendFault::IndexOverflow { at }),
                    Halt::OffsetExhausted { at } => Err(DescendFault::OffsetExhausted { at }),
                }
            }
        }
    }

    /// Resolves several container handles in one source-ordered
    /// walk — the batch face that makes k scattered descents cost
    /// one walk instead of k. Group handles and handles already
    /// carrying a resident verdict settle walk-free (idempotent);
    /// depth refusals park walk-free; each extent commits
    /// atomically, and a wire refusal inside one extent parks on
    /// that handle while the walk continues to the next.
    ///
    /// # Errors
    ///
    /// The refusing handle beside its [`DescendFault`]. Target
    /// gates are validated whole before any state changes; a
    /// supply refusal or tear aborts the walk, but verdicts
    /// already parked by earlier extents stand.
    ///
    /// # Panics
    ///
    /// Panics if any handle was not minted by this editor (the
    /// arena index contract).
    #[track_caller]
    pub fn materialize(
        &mut self,
        handles: &[Handle],
    ) -> Result<(), (Handle, DescendFault<S::Error>)> {
        for &handle in handles {
            let row = gate(&self.rows, handle);
            if row.deleted() {
                return Err((handle, DescendFault::Edit(EditFault::DeletedTarget)));
            }
            match row.kind {
                // A group's interior is standing: the batch
                // settles it walk-free below.
                RecordKind::Group | RecordKind::Len => {}
                RecordKind::Varint | RecordKind::I64 | RecordKind::I32 => {
                    return Err((
                        handle,
                        DescendFault::Edit(EditFault::KindMismatch { have: row.kind }),
                    ));
                }
            }
            if !matches!(row.kind, RecordKind::Group) && !matches!(row.base(), Base::Intact) {
                return Err((handle, DescendFault::Edit(EditFault::AuthoredPayload)));
            }
        }
        // Walk-free settlements first: standing groups, resident
        // verdicts, empty extents, depth refusals.
        let mut pending: Vec<(u64, u64, RowId, u32)> = Vec::new();
        for &handle in handles {
            let id = handle.0;
            let row = *self.row(id);
            if matches!(row.kind, RecordKind::Group) || row.opened() || row.faulted() {
                continue;
            }
            if row.payload_len == 0 {
                self.row_mut(id).state |= FLAG_OPENED;
                continue;
            }
            let depth = self.depth_of(id);
            if depth >= u32::from(self.limit.as_inner()) {
                let fault = Fault {
                    at: row.start,
                    kind: FaultKind::DepthExceeded { field: row.field, limit: self.limit },
                };
                let _ = self.park(id, fault);
                continue;
            }
            pending.push((row.payload_at(), row.payload_at() + row.payload_len, id, depth + 1));
        }
        if pending.is_empty() {
            return Ok(());
        }
        pending.sort_unstable_by_key(|&(start, _, _, _)| start);
        // The walk borrows the source for the whole batch, so the
        // arenas are addressed as plain fields beside it.
        let rows = &mut self.rows;
        let faults = &mut self.faults;
        let limit = self.limit;
        let walk = match self.source.begin() {
            Ok(walk) => walk,
            Err(fault) => {
                let handle = Handle(pending[0].2);
                return Err((
                    handle,
                    DescendFault::Source(ReplayFault::Rewind {
                        phase: ReplayPhase::Descend,
                        source: fault,
                    }),
                ));
            }
        };
        let mut pump = Pump::new(walk);
        for &(start, end, id, base) in &pending {
            if rows[id.index()].opened() || rows[id.index()].faulted() {
                // A duplicate request settled by an earlier
                // iteration of this same batch.
                continue;
            }
            let handle = Handle(id);
            let owed = start - pump.off;
            match pump.skip_bytes(owed) {
                Ok(advanced) if advanced == owed => {}
                Ok(_) => return Err((handle, DescendFault::Torn { at: start })),
                Err(supply) => {
                    return Err((
                        handle,
                        DescendFault::Source(ReplayFault::Read {
                            phase: ReplayPhase::Descend,
                            at: pump.off,
                            source: supply,
                        }),
                    ));
                }
            }
            pump.zone = end;
            let mark = rows.len();
            let outcome = scan_layer(&mut pump, rows, Some(id), Some(end), base, limit);
            pump.zone = u64::MAX;
            match outcome {
                Ok(first) => {
                    let row = &mut rows[id.index()];
                    row.kid = first;
                    row.state |= FLAG_OPENED;
                }
                Err(halt) => {
                    rows.truncate(mark);
                    match halt {
                        Halt::Wire(fault) => {
                            park_in(rows, faults, id, fault);
                            // The scan stopped mid-extent; realign
                            // by seeking to the extent's end for
                            // the next request.
                            pump.clear_construct();
                            let owed = end - pump.off;
                            match pump.skip_bytes(owed) {
                                Ok(advanced) if advanced == owed => {}
                                Ok(_) => return Err((handle, DescendFault::Torn { at: end })),
                                Err(supply) => {
                                    return Err((
                                        handle,
                                        DescendFault::Source(ReplayFault::Read {
                                            phase: ReplayPhase::Descend,
                                            at: pump.off,
                                            source: supply,
                                        }),
                                    ));
                                }
                            }
                        }
                        Halt::Source(fault) => return Err((handle, DescendFault::Source(fault))),
                        Halt::Torn { at } => return Err((handle, DescendFault::Torn { at })),
                        Halt::IndexOverflow { at } => {
                            return Err((handle, DescendFault::IndexOverflow { at }));
                        }
                        Halt::OffsetExhausted { at } => {
                            return Err((handle, DescendFault::OffsetExhausted { at }));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // ─ fetch ─

    /// The record's current payload bytes, appended to `out` (the
    /// buffer truncates back to its entry length on any refusal —
    /// never poisoned, a retry is lawful): the pending
    /// replacement if one is set — answered from the authored
    /// store, no walk — the scanned payload otherwise (one fetch
    /// walk; deleted and parked records keep answering). The
    /// fetch walk verifies only that the source still reaches the
    /// extent's end: bytes that moved beneath unchanged
    /// coordinates are appended as they now read (the provider's
    /// byte-identity obligation, not a fetch judgment).
    ///
    /// # Errors
    ///
    /// [`FetchFault::KindMismatch`] for scalar records (their
    /// values are row-resident) and groups (their interiors are
    /// standing records, not a byte extent),
    /// [`FetchFault::Oversize`] for an extent past the address
    /// space, [`FetchFault::Torn`] when
    /// the source ends before a measured coordinate,
    /// [`FetchFault::Source`] for the supply's own refusals. On
    /// `Err`, `out` is byte-identical to entry.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[track_caller]
    pub fn read_payload(
        &mut self,
        handle: Handle,
        out: &mut Vec<u8>,
    ) -> Result<(), FetchFault<S::Error>> {
        let row = *gate(&self.rows, handle);
        if !matches!(row.kind, RecordKind::Len) {
            return Err(FetchFault::KindMismatch { have: row.kind });
        }
        match row.base() {
            Base::Replaced | Base::Inserted => {
                out.extend_from_slice(self.store.payload_of(row.value));
                Ok(())
            }
            Base::Intact => {
                let span = SourceSpan::new(row.payload_at(), row.payload_at() + row.payload_len);
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
                let outcome =
                    fetch_extent(&mut self.source, span, |bytes| out.extend_from_slice(bytes));
                if let Err(handed) = outcome {
                    out.truncate(mark);
                    return Err(handed.fault);
                }
                Ok(())
            }
        }
    }

    /// Hands the record's current payload bytes to `sink` as
    /// borrowed views, in order — the unbounded-extent face. An
    /// authored payload is one view from the store (no walk); a
    /// scanned payload is one fetch walk, verifying only that the
    /// source still reaches the extent's end: bytes that moved
    /// beneath unchanged coordinates are handed as they now read
    /// (the provider's byte-identity obligation, not a fetch
    /// judgment).
    ///
    /// # Errors
    ///
    /// As [`Self::read_payload`] minus the address-space
    /// ceiling; the refusal rides beside the exact byte count
    /// already handed over ([`Handed`]) — the prefix carries no
    /// validity promise.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[track_caller]
    pub fn payload_sink(
        &mut self,
        handle: Handle,
        mut sink: impl FnMut(&[u8]),
    ) -> Result<(), Handed<FetchFault<S::Error>>> {
        let row = *gate(&self.rows, handle);
        if !matches!(row.kind, RecordKind::Len) {
            return Err(Handed { handed: 0, fault: FetchFault::KindMismatch { have: row.kind } });
        }
        match row.base() {
            Base::Replaced | Base::Inserted => {
                let bytes = self.store.payload_of(row.value);
                if !bytes.is_empty() {
                    sink(bytes);
                }
                Ok(())
            }
            Base::Intact => {
                let span = SourceSpan::new(row.payload_at(), row.payload_at() + row.payload_len);
                fetch_extent(&mut self.source, span, sink)
            }
        }
    }

    // ─ commands ─

    /// The shared scalar-set gate and commit.
    #[track_caller]
    fn set_scalar(&mut self, handle: Handle, kind: RecordKind, word: u64) -> Result<(), EditFault> {
        let row = gate(&self.rows, handle);
        if row.kind != kind {
            return Err(EditFault::KindMismatch { have: row.kind });
        }
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        let row = self.row_mut(handle.0);
        row.word = word;
        if matches!(row.base(), Base::Intact) {
            row.state = (row.state & !BASE_MASK) | BASE_REPLACED;
        }
        self.mark_dirty(handle.0);
        Ok(())
    }

    /// Replaces the varint record's value. The source tag bytes
    /// still ride verbatim at save; only the value re-emits,
    /// minimally.
    ///
    /// # Errors
    ///
    /// [`EditFault::KindMismatch`] unless the record is a varint,
    /// [`EditFault::DeletedTarget`] for deleted ones. On any
    /// `Err` the editor is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[track_caller]
    pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::Varint, value)
    }

    /// Replaces the fixed 32-bit record's value bits.
    ///
    /// # Errors
    ///
    /// As [`Self::set_varint`], with the fixed 32-bit kind
    /// gate.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[track_caller]
    pub fn set_i32(&mut self, handle: Handle, bits: u32) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::I32, u64::from(bits))
    }

    /// Replaces the fixed 64-bit record's value bits.
    ///
    /// # Errors
    ///
    /// As [`Self::set_varint`], with the fixed 64-bit kind
    /// gate.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[track_caller]
    pub fn set_i64(&mut self, handle: Handle, bits: u64) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::I64, bits)
    }

    /// The shared payload-set gate.
    #[track_caller]
    fn payload_set_gate(&self, handle: Handle, len: usize) -> Result<(), EditFault> {
        let row = gate(&self.rows, handle);
        if !matches!(row.kind, RecordKind::Len) {
            return Err(EditFault::KindMismatch { have: row.kind });
        }
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        if row.opened() {
            return Err(EditFault::OpenedTarget);
        }
        if len > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len });
        }
        Ok(())
    }

    /// The infallible suffix of a payload set: the value slot, the
    /// state flip, the dirty mark.
    fn payload_set_commit(&mut self, handle: Handle, slot: u32) {
        let row = self.row_mut(handle.0);
        row.value = slot;
        row.state &= !FLAG_FAULTED;
        if matches!(row.base(), Base::Intact) {
            row.state = (row.state & !BASE_MASK) | BASE_REPLACED;
        }
        self.mark_dirty(handle.0);
    }

    overhaul_machine!(@set_payload $pay $(<$plt>)?, Machine: $Machine);

    /// Deletes the record: it vanishes whole at save, subtree
    /// included — interior records and any insertions made inside
    /// them emit nothing. Commit-only: there is no restore.
    ///
    /// # Errors
    ///
    /// [`EditFault::DeletedTarget`] when the record is already
    /// deleted. On `Err` the editor is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[inline]
    #[track_caller]
    pub fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
        let row = gate(&self.rows, handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        self.row_mut(handle.0).state |= FLAG_DELETED;
        self.mark_dirty(handle.0);
        Ok(())
    }

    // ─ insertion ─

    /// Gates an insertion container.
    #[track_caller]
    fn container_gate(&self, container: Option<Handle>) -> Result<Option<RowId>, EditFault> {
        let Some(handle) = container else {
            return Ok(None);
        };
        let row = gate(&self.rows, handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        match row.kind {
            // A group's interior is standing (scanned or
            // authored): always an insertion container.
            RecordKind::Group => Ok(Some(handle.0)),
            RecordKind::Len => {
                if !matches!(row.base(), Base::Intact) {
                    return Err(EditFault::AuthoredPayload);
                }
                if row.opened() { Ok(Some(handle.0)) } else { Err(EditFault::TargetUnopened) }
            }
            RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => {
                Err(EditFault::KindMismatch { have: row.kind })
            }
        }
    }

    /// The first record of a container's chain (the top layer for
    /// `None`).
    fn first_of(&self, parent: Option<RowId>) -> Option<RowId> {
        parent.map_or(self.top, |id| self.row(id).kid)
    }

    /// The last record of a container's chain: a linear walk —
    /// commit-only rows carry no tail anchor, so a tail insertion
    /// pays O(siblings).
    fn tail_of(&self, parent: Option<RowId>) -> Option<RowId> {
        let mut cur = self.first_of(parent)?;
        while let Some(next) = self.row(cur).next {
            cur = next;
        }
        Some(cur)
    }

    /// Resolves an anchor into a proven splice point.
    #[track_caller]
    fn resolve_anchor(&self, at: InsertAt) -> Result<(Option<RowId>, Option<RowId>), EditFault> {
        match at {
            InsertAt::HeadOf(container) => Ok((self.container_gate(container)?, None)),
            InsertAt::TailOf(container) => {
                let parent = self.container_gate(container)?;
                Ok((parent, self.tail_of(parent)))
            }
            InsertAt::After(anchor) => {
                let row = gate(&self.rows, anchor);
                Ok((row.parent, Some(anchor.0)))
            }
        }
    }

    /// Mints the next row coordinate for an insertion.
    fn mint_insert(&self) -> Result<RowId, EditFault> {
        u32::try_from(self.rows.len())
            .ok()
            .filter(|&at| at <= RowId::MAX.as_inner())
            .map(mint)
            .ok_or(EditFault::IndexSpaceExhausted)
    }

    /// Splices a freshly minted authored row into its chain.
    #[allow(
        clippy::too_many_arguments,
        reason = "the arguments are one authored row's columns, spelled once at the \
                  one mint"
    )]
    fn apply_insert(
        &mut self,
        parent: Option<RowId>,
        prev: Option<RowId>,
        id: RowId,
        field: FieldNumber,
        kind: RecordKind,
        word: u64,
        value: u32,
    ) {
        let next = match prev {
            Some(prev) => {
                let anchor = self.row_mut(prev);
                anchor.next.replace(id)
            }
            None => match parent {
                Some(container) => self.row_mut(container).kid.replace(id),
                None => self.top.replace(id),
            },
        };
        self.rows.push(Row {
            start: 0,
            payload_len: 0,
            word,
            parent,
            kid: None,
            next,
            value,
            field,
            kind,
            tag_width: WordWidth::MIN,
            delim_width: None,
            state: BASE_INSERTED,
        });
        // The edit witness climbs from the container whose
        // interior changed — never from the previous sibling,
        // whose own subtree is untouched (a falsely touched
        // unopened LEN would settle as a bodiless spine and drop
        // its source extent from the save).
        match parent {
            Some(container) => self.mark_dirty(container),
            None => self.dirty = true,
        }
    }

    /// Inserts a varint record at the anchor. Anchors name gaps:
    /// the head or tail of a container's chain, or the gap right
    /// after a sibling. Authored records emit minimally at save.
    ///
    /// # Errors
    ///
    /// [`EditFault::KindMismatch`] for a scalar container,
    /// [`EditFault::DeletedTarget`] for a deleted one,
    /// [`EditFault::TargetUnopened`] for an undescended LEN,
    /// [`EditFault::AuthoredPayload`] for a replaced or authored
    /// payload, [`EditFault::IndexSpaceExhausted`] when the row
    /// domain is spent. On any `Err` the editor is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by
    /// this editor (the arena index contract).
    #[track_caller]
    pub fn insert_varint(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        value: u64,
    ) -> Result<Handle, EditFault> {
        let (parent, prev) = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        self.apply_insert(parent, prev, id, field, RecordKind::Varint, value, 0);
        Ok(Handle(id))
    }

    /// Inserts a fixed 32-bit record at the anchor.
    ///
    /// # Errors
    ///
    /// As [`Self::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by
    /// this editor (the arena index contract).
    #[track_caller]
    pub fn insert_i32(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        bits: u32,
    ) -> Result<Handle, EditFault> {
        let (parent, prev) = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        self.apply_insert(parent, prev, id, field, RecordKind::I32, u64::from(bits), 0);
        Ok(Handle(id))
    }

    /// Inserts a fixed 64-bit record at the anchor.
    ///
    /// # Errors
    ///
    /// As [`Self::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by
    /// this editor (the arena index contract).
    #[track_caller]
    pub fn insert_i64(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        bits: u64,
    ) -> Result<Handle, EditFault> {
        let (parent, prev) = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        self.apply_insert(parent, prev, id, field, RecordKind::I64, bits, 0);
        Ok(Handle(id))
    }

    overhaul_machine!(@insert_payload $pay $(<$plt>)?, Machine: $Machine);

    /// Inserts an empty group at the anchor — an insertion
    /// container from birth: later insertions may name it. Emits
    /// as a minimal start tag and a minimal end tag around
    /// whatever its interior holds at save.
    ///
    /// # Errors
    ///
    /// As [`Self::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by
    /// this editor (the arena index contract).
    #[track_caller]
    pub fn insert_group(&mut self, at: InsertAt, field: FieldNumber) -> Result<Handle, EditFault> {
        let (parent, prev) = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        self.apply_insert(parent, prev, id, field, RecordKind::Group, 0, 0);
        Ok(Handle(id))
    }

    // ─ save ─

    /// The exact byte length [`Self::save`] would produce,
    /// without producing bytes and without a source walk: the
    /// sizing pass alone. An editor with no edits answers in
    /// O(1): the save is the source.
    ///
    /// # Errors
    ///
    /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
    /// outgrows the length class — the same sizing that would
    /// refuse the save, surfaced without a walk.
    pub fn save_len(&self) -> Result<u64, SaveFault<S::Error>> {
        if !self.dirty {
            return Ok(self.total);
        }
        let view = SaveView { rows: &self.rows, top: self.top, store: &self.store };
        view.size_pass().map(|(total, _)| total)
    }

    /// Serializes into a fresh `Vec<u8>`: one booking walk
    /// compiles and prices, then one splicing walk emits —
    /// untouched extents ride verbatim, byte for byte.
    ///
    /// # Errors
    ///
    /// [`SaveFault`]; no buffer exists on `Err`.
    pub fn save(&mut self) -> Result<Vec<u8>, SaveFault<S::Error>> {
        let mut out = Vec::new();
        self.save_into(&mut out)?;
        Ok(out)
    }

    /// Serializes by appending to the caller's buffer (reserved
    /// once at the compiled total) — the reuse face for batch
    /// loops.
    ///
    /// # Errors
    ///
    /// [`SaveFault`]; the buffer is truncated back to its entry
    /// mark, so a faulted save never poisons the loop.
    pub fn save_into(&mut self, out: &mut Vec<u8>) -> Result<(), SaveFault<S::Error>> {
        // Direct field borrows: the view reads the arenas while
        // the fold walks the source beside them.
        let view = SaveView { rows: &self.rows, top: self.top, store: &self.store };
        let script = view.compile()?;
        let mark = out.len();
        if let Ok(planned) = usize::try_from(script.out_len()) {
            out.reserve_exact(planned);
        }
        match fold(&mut self.source, &script, self.total, &mut |view| {
            out.extend_from_slice(view);
        }) {
            Ok(()) => {
                debug_assert!(
                    u64::try_from(out.len() - mark) == Ok(script.out_len()),
                    "the fold emits exactly the compiled length"
                );
                Ok(())
            }
            Err(fault) => {
                out.truncate(mark);
                Err(emit_fault(fault))
            }
        }
    }

    /// Serializes by handing the save's bytes to `sink` as
    /// borrowed views, in output order — no output buffer exists
    /// on either side.
    ///
    /// Compile faults precede every handoff (`handed` is zero
    /// there); an emission fault names the exact prefix the sink
    /// received. The prefix carries no validity promise — atomic
    /// publication is the caller's transactional destination.
    ///
    /// # Errors
    ///
    /// [`Handed`] around the [`SaveFault`].
    pub fn save_sink(
        &mut self,
        mut sink: impl FnMut(&[u8]),
    ) -> Result<(), Handed<SaveFault<S::Error>>> {
        let view = SaveView { rows: &self.rows, top: self.top, store: &self.store };
        let script = match view.compile() {
            Ok(script) => script,
            Err(fault) => return Err(Handed { handed: 0, fault }),
        };
        let mut handed = 0u64;
        match fold(&mut self.source, &script, self.total, &mut |view| {
            #[allow(clippy::as_conversions, reason = "view lengths widen losslessly into u64")]
            {
                handed += view.len() as u64;
            }
            sink(view);
        }) {
            Ok(()) => Ok(()),
            Err(fault) => Err(Handed { handed, fault: emit_fault(fault) }),
        }
    }
        }

        overhaul_machine!(@save_view $Machine $(<$plt>)?, store: $Store);
    };
    (@save_view $Machine:ident $(<$plt:lifetime>)?, store: $Store:ty) => {
        impl<'a $(, $plt)?> SaveView<'a, $Store> {
    const fn row(&self, id: RowId) -> &'a Row {
        &self.rows[id.index()]
    }

    /// The authored bytes behind a payload slot.
    fn payload_of(&self, slot: u32) -> &'a [u8] {
        self.store.payload_of(slot)
    }

    /// The save verdict for one row — where the sizing and
    /// compile walks meet the same dispatch.
    fn settle(&self, row: &Row) -> Arm {
        if row.deleted() {
            return Arm::Skip { end: row.scanned().then(|| row.span_end()) };
        }
        if row.rides_verbatim() {
            return Arm::Clean { at: row.start, end: row.span_end() };
        }
        match (row.kind, row.base()) {
            (RecordKind::Group, Base::Intact) => {
                Arm::GroupSpine { tag_end: row.start + row.tag_w(), first: row.kid }
            }
            (RecordKind::Group, Base::Inserted) => {
                Arm::NewGroup { field: row.field, first: row.kid }
            }
            (RecordKind::Group, Base::Replaced) => {
                unreachable!("no command replaces a group whole")
            }
            (RecordKind::Len, Base::Intact) => Arm::Spine {
                tag_end: row.start + row.tag_w(),
                prefix_end: row.payload_at(),
                src_len: row.payload_len,
                first: row.kid,
            },
            (RecordKind::Len, Base::Replaced) => Arm::ReBody {
                tag_end: row.start + row.tag_w(),
                prefix_end: row.payload_at(),
                src_len: row.payload_len,
                slot: row.value,
                span_end: row.span_end(),
            },
            (RecordKind::Len, Base::Inserted) => {
                Arm::NewBody { head: head_word(row.field, row.kind), slot: row.value }
            }
            (kind, Base::Replaced) => Arm::ReValue {
                tag_end: row.start + row.tag_w(),
                span_end: row.span_end(),
                kind,
                word: row.word,
            },
            (kind, Base::Inserted) => {
                Arm::NewValue { head: head_word(row.field, kind), kind, word: row.word }
            }
            // An intact, touched scalar cannot exist: the touch
            // witness climbs through containers only.
            (_, Base::Intact) => Arm::Clean { at: row.start, end: row.span_end() },
        }
    }

    /// The sizing walk: postorder over the live rows, pricing
    /// every touched container's new interior (in preorder slot
    /// order, for the compile walk to consume) and the grand
    /// total. No source walk.
    ///
    /// # Errors
    ///
    /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
    /// outgrows the length class.
    #[allow(
        clippy::as_conversions,
        reason = "authored payload lengths were admitted to the LEN class, which \
                  fits u64"
    )]
    fn size_pass<E>(&self) -> Result<(u64, Vec<u64>), SaveFault<E>> {
        /// What closes the container at the pop: a LEN's priced
        /// prefix (the length class judged there) or a group's
        /// end tag (no class — width only). Met widths move from
        /// the framed row; an authored group's mint minimally.
        enum Seal {
            Prefix { slot: usize, at: u64, prefix_src_w: WordWidth, src_len: u64 },
            End { end_w: WordWidth },
        }
        struct Frame {
            next: Option<RowId>,
            outer: u64,
            head_w: WordWidth,
            seal: Seal,
        }
        let mut bodies: Vec<u64> = Vec::new();
        let mut spine: Vec<Frame> = Vec::new();
        let mut acc: u64 = 0;
        let mut cur = self.top;
        loop {
            let Some(id) = cur else {
                let Some(frame) = spine.pop() else { break };
                let body = acc;
                match frame.seal {
                    Seal::Prefix { slot, at, prefix_src_w, src_len } => {
                        if body > u64::from(PayloadLen::MAX.as_inner()) {
                            return Err(SaveFault::BodyOverCap { at });
                        }
                        bodies[slot] = body;
                        let prefix = if body == src_len {
                            u64::from(prefix_src_w.w())
                        } else {
                            u64::from(encoded_len64(body))
                        };
                        acc = frame.outer + u64::from(frame.head_w.w()) + prefix + body;
                    }
                    Seal::End { end_w } => {
                        acc =
                            frame.outer + u64::from(frame.head_w.w()) + body + u64::from(end_w.w());
                    }
                }
                cur = frame.next;
                continue;
            };
            let row = self.row(id);
            match self.settle(row) {
                Arm::Skip { .. } => {}
                Arm::Clean { at, end } => acc += end - at,
                Arm::ReValue { tag_end, kind, word, .. } => {
                    acc += (tag_end - row.start) + value_width(kind, word);
                }
                Arm::NewValue { head, kind, word } => {
                    acc += u64::from(encoded_len32(head)) + value_width(kind, word);
                }
                Arm::ReBody { tag_end, prefix_end, src_len, slot, .. } => {
                    let len = self.payload_of(slot).len() as u64;
                    let prefix = if len == src_len {
                        prefix_end - tag_end
                    } else {
                        u64::from(encoded_len64(len))
                    };
                    acc += (tag_end - row.start) + prefix + len;
                }
                Arm::NewBody { head, slot } => {
                    let len = self.payload_of(slot).len() as u64;
                    acc += u64::from(encoded_len32(head)) + u64::from(encoded_len64(len)) + len;
                }
                Arm::Spine { tag_end, prefix_end, src_len, first } => {
                    let slot = bodies.len();
                    bodies.push(0);
                    debug_assert!(
                        tag_end - row.start == row.tag_w() && prefix_end - tag_end == row.delim_w(),
                        "the settle's spine windows are the stored met widths"
                    );
                    #[allow(
                        clippy::option_if_let_else,
                        reason = "the None arm is an unsafe unreachable whose SAFETY \
                                  comment sits on the arm; a closure form would detach it"
                    )]
                    let prefix_src_w = match row.delim_width {
                        Some(w) => w,
                        // SAFETY: the settle's Spine arm admits intact
                        // scanned LEN rows only, whose scan stored the
                        // met prefix width.
                        None => unsafe { core::hint::unreachable_unchecked() },
                    };
                    spine.push(Frame {
                        next: row.next,
                        outer: acc,
                        head_w: row.tag_width,
                        seal: Seal::Prefix { slot, at: row.start, prefix_src_w, src_len },
                    });
                    acc = 0;
                    cur = first;
                    continue;
                }
                Arm::GroupSpine { tag_end, first } => {
                    debug_assert!(
                        tag_end - row.start == row.tag_w(),
                        "the settle's group window is the stored met width"
                    );
                    #[allow(
                        clippy::option_if_let_else,
                        reason = "the None arm is an unsafe unreachable whose SAFETY \
                                  comment sits on the arm; a closure form would detach it"
                    )]
                    let end_w = match row.delim_width {
                        Some(w) => w,
                        // SAFETY: the settle's GroupSpine arm admits
                        // intact scanned group rows only, whose close
                        // patched the met end-tag width.
                        None => unsafe { core::hint::unreachable_unchecked() },
                    };
                    spine.push(Frame {
                        next: row.next,
                        outer: acc,
                        head_w: row.tag_width,
                        seal: Seal::End { end_w },
                    });
                    acc = 0;
                    cur = first;
                    continue;
                }
                Arm::NewGroup { field, first } => {
                    spine.push(Frame {
                        next: row.next,
                        outer: acc,
                        head_w: WordWidth::minimal_of(head_word(field, RecordKind::Group)),
                        seal: Seal::End { end_w: WordWidth::minimal_of(end_word(field)) },
                    });
                    acc = 0;
                    cur = first;
                    continue;
                }
            }
            cur = row.next;
        }
        Ok((acc, bodies))
    }

    /// The compile walk: preorder over the live rows, booking
    /// source-order script steps in a single walk. Opened LENs
    /// ride prefix slots settled at each close, so the compiled
    /// script carries the priced total in [`Script::out_len`]. No
    /// source walk.
    ///
    /// # Errors
    ///
    /// [`SaveFault::BodyOverCap`] when a settled interior
    /// outgrows the length class.
    #[allow(
        clippy::as_conversions,
        reason = "authored payload lengths were admitted to the LEN class, which \
                  fits u64"
    )]
    fn compile<E>(&self) -> Result<Script<'a>, SaveFault<E>> {
        let mut script = Script::new();
        let mut lens: Vec<(u32, u64, u64)> = Vec::new();
        let mut open: Option<RowId> = None;
        let mut cur = self.top;
        loop {
            let Some(id) = cur else {
                let Some(container) = open else { break };
                let row = self.row(container);
                // The pop epilogue: a group closes with its end
                // tag here, an opened LEN settles its prefix slot
                // against the booked interior.
                match (row.kind, row.base()) {
                    (RecordKind::Group, Base::Intact) => script.copy_to(row.span_end()),
                    (RecordKind::Group, Base::Inserted) => {
                        script.stage_word(u64::from(end_word(row.field)));
                    }
                    _ => {
                        let Some((slot, mark, declared)) = lens.pop() else {
                            unreachable!("every opened LEN pushed its prefix slot")
                        };
                        let interior = script.out_len() - mark;
                        if script.settle_prefix(slot, interior, declared).is_err() {
                            return Err(SaveFault::BodyOverCap { at: row.start });
                        }
                    }
                }
                cur = row.next;
                open = row.parent;
                continue;
            };
            let row = self.row(id);
            match self.settle(row) {
                Arm::Skip { end } => {
                    if let Some(end) = end {
                        script.skip_to(end);
                    }
                }
                Arm::Clean { end, .. } => script.copy_to(end),
                Arm::ReValue { tag_end, span_end, kind, word } => {
                    script.copy_to(tag_end);
                    stage_value(&mut script, kind, word);
                    script.skip_to(span_end);
                }
                Arm::NewValue { head, kind, word } => {
                    script.stage_word(u64::from(head));
                    stage_value(&mut script, kind, word);
                }
                Arm::ReBody { tag_end, prefix_end, src_len, slot, span_end } => {
                    script.copy_to(tag_end);
                    let bytes = self.payload_of(slot);
                    let len = bytes.len() as u64;
                    if len == src_len {
                        script.copy_to(prefix_end);
                    } else {
                        script.skip_to(prefix_end);
                        script.stage_word(len);
                    }
                    script.borrow(bytes);
                    script.skip_to(span_end);
                }
                Arm::NewBody { head, slot } => {
                    script.stage_word(u64::from(head));
                    let bytes = self.payload_of(slot);
                    script.stage_word(bytes.len() as u64);
                    script.borrow(bytes);
                }
                Arm::Spine { tag_end, prefix_end, src_len, first } => {
                    script.copy_to(tag_end);
                    let slot = script.open_prefix(tag_end, prefix_end);
                    lens.push((slot, script.out_len(), src_len));
                    open = Some(id);
                    cur = first;
                    continue;
                }
                Arm::GroupSpine { tag_end, first } => {
                    script.copy_to(tag_end);
                    open = Some(id);
                    cur = first;
                    continue;
                }
                Arm::NewGroup { field, first } => {
                    script.stage_word(u64::from(head_word(field, RecordKind::Group)));
                    open = Some(id);
                    cur = first;
                    continue;
                }
            }
            cur = row.next;
        }
        debug_assert!(lens.is_empty(), "every opened LEN settled its prefix slot");
        Ok(script)
    }
        }
    };
    (@set_payload copy, Machine: $Machine:ident) => {
    /// Replaces the LEN record's payload, staging the bytes by
    /// copy at this command — temporaries welcome; no payload
    /// lifetime binds the install. The source tag bytes still
    /// ride verbatim at save; the length prefix rides verbatim
    /// when the new payload's length equals the declared one, and
    /// re-emits minimally otherwise.
    ///
    /// # Errors
    ///
    /// [`EditFault::KindMismatch`] unless the record is a LEN,
    /// [`EditFault::DeletedTarget`] for deleted ones,
    /// [`EditFault::OpenedTarget`] when the interior is open for
    /// editing, [`EditFault::PayloadTooLarge`] past the length
    /// class, [`EditFault::IndexSpaceExhausted`] when the slot
    /// domain is spent. On any `Err` the editor is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[track_caller]
    pub fn set_payload(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
        self.payload_set_gate(handle, payload.len())?;
        let slot = self.store.push_copied(payload)?;
        self.payload_set_commit(handle, slot);
        Ok(())
    }
    };
    (@set_payload borrow <$plt:lifetime>, Machine: $Machine:ident) => {
    /// Replaces the LEN record's payload with borrowed bytes,
    /// held until the save copies them once into the output. The
    /// source tag bytes still ride verbatim at save; the length
    /// prefix rides verbatim when the new payload's length equals
    /// the declared one, and re-emits minimally otherwise.
    ///
    /// # Errors
    ///
    /// [`EditFault::KindMismatch`] unless the record is a LEN,
    /// [`EditFault::DeletedTarget`] for deleted ones,
    /// [`EditFault::OpenedTarget`] when the interior is open for
    /// editing, [`EditFault::PayloadTooLarge`] past the length
    /// class, [`EditFault::IndexSpaceExhausted`] when the slot
    /// domain is spent. On any `Err` the editor is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[track_caller]
    pub fn set_payload(&mut self, handle: Handle, payload: &$plt [u8]) -> Result<(), EditFault> {
        self.payload_set_gate(handle, payload.len())?;
        let slot = self.store.push_borrowed(payload)?;
        self.payload_set_commit(handle, slot);
        Ok(())
    }
    };
    (@set_payload mixed <$plt:lifetime>, Machine: $Machine:ident) => {
    /// Replaces the LEN record's payload with borrowed bytes,
    /// held until the save copies them once into the output (the
    #[doc = concat!(" escape hatch for temporaries is [`", stringify!($Machine), "::set_payload_copy`]).")]
    /// The source tag bytes still ride verbatim at save; the
    /// length prefix rides verbatim when the new payload's length
    /// equals the declared one, and re-emits minimally otherwise.
    ///
    /// # Errors
    ///
    /// [`EditFault::KindMismatch`] unless the record is a LEN,
    /// [`EditFault::DeletedTarget`] for deleted ones,
    /// [`EditFault::OpenedTarget`] when the interior is open for
    /// editing, [`EditFault::PayloadTooLarge`] past the length
    /// class, [`EditFault::IndexSpaceExhausted`] when the slot
    /// domain is spent. On any `Err` the editor is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[track_caller]
    pub fn set_payload(&mut self, handle: Handle, payload: &$plt [u8]) -> Result<(), EditFault> {
        self.payload_set_gate(handle, payload.len())?;
        let slot = self.store.push_borrowed(payload)?;
        self.payload_set_commit(handle, slot);
        Ok(())
    }

    #[doc = concat!(" [`", stringify!($Machine), "::set_payload`]'s copying twin: the payload is")]
    /// staged by copy at this command — the face for temporaries;
    /// no payload lifetime binds the install.
    ///
    /// # Errors
    ///
    #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this editor (the
    /// arena index contract).
    #[track_caller]
    pub fn set_payload_copy(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
        self.payload_set_gate(handle, payload.len())?;
        let slot = self.store.push_copied(payload)?;
        self.payload_set_commit(handle, slot);
        Ok(())
    }
    };
    (@insert_payload copy, Machine: $Machine:ident) => {
    /// Inserts a LEN record at the anchor, staging the payload by
    /// copy at this command — temporaries welcome; no payload
    /// lifetime binds the install.
    ///
    /// # Errors
    ///
    #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
    /// [`EditFault::PayloadTooLarge`] past the length class.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by
    /// this editor (the arena index contract).
    #[track_caller]
    pub fn insert_payload(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        payload: &[u8],
    ) -> Result<Handle, EditFault> {
        if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len: payload.len() });
        }
        let (parent, prev) = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let slot = self.store.push_copied(payload)?;
        self.apply_insert(parent, prev, id, field, RecordKind::Len, 0, slot);
        Ok(Handle(id))
    }
    };
    (@insert_payload borrow <$plt:lifetime>, Machine: $Machine:ident) => {
    /// Inserts a LEN record with borrowed payload bytes at the
    /// anchor, held until the save copies them once into the
    /// output.
    ///
    /// # Errors
    ///
    #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
    /// [`EditFault::PayloadTooLarge`] past the length class.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by
    /// this editor (the arena index contract).
    #[track_caller]
    pub fn insert_payload(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        payload: &$plt [u8],
    ) -> Result<Handle, EditFault> {
        if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len: payload.len() });
        }
        let (parent, prev) = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let slot = self.store.push_borrowed(payload)?;
        self.apply_insert(parent, prev, id, field, RecordKind::Len, 0, slot);
        Ok(Handle(id))
    }
    };
    (@insert_payload mixed <$plt:lifetime>, Machine: $Machine:ident) => {
    /// Inserts a LEN record with borrowed payload bytes at the
    /// anchor, held until the save copies them once into the
    /// output (the escape hatch for temporaries is
    #[doc = concat!(" [`", stringify!($Machine), "::insert_payload_copy`]).")]
    ///
    /// # Errors
    ///
    #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
    /// [`EditFault::PayloadTooLarge`] past the length class.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by
    /// this editor (the arena index contract).
    #[track_caller]
    pub fn insert_payload(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        payload: &$plt [u8],
    ) -> Result<Handle, EditFault> {
        if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len: payload.len() });
        }
        let (parent, prev) = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let slot = self.store.push_borrowed(payload)?;
        self.apply_insert(parent, prev, id, field, RecordKind::Len, 0, slot);
        Ok(Handle(id))
    }

    #[doc = concat!(" [`", stringify!($Machine), "::insert_payload`]'s copying twin: the payload is")]
    /// staged by copy at this command — the face for temporaries.
    ///
    /// # Errors
    ///
    #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`].")]
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by
    /// this editor (the arena index contract).
    #[track_caller]
    pub fn insert_payload_copy(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        payload: &[u8],
    ) -> Result<Handle, EditFault> {
        if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len: payload.len() });
        }
        let (parent, prev) = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let slot = self.store.push_copied(payload)?;
        self.apply_insert(parent, prev, id, field, RecordKind::Len, 0, slot);
        Ok(Handle(id))
    }
    };
}

overhaul_machine! {
    #[doc = " The one-shot commit-only editor over a stable-replay source"]
    #[doc = " with per-install payload backing: the source handle, the"]
    #[doc = " edit-row table measured over its top layer, and the authored"]
    #[doc = " store."]
    #[doc = ""]
    #[doc = " The unsuffixed payload faces retain borrowed slices until"]
    #[doc = " the save copies them once into the output; their `_copy`"]
    #[doc = " twins stage the bytes at the command."]
    #[doc = ""]
    #[doc = " Handles are minted by this editor and panic at the arena gate"]
    #[doc = " when forged (the documented index contract); they stay valid"]
    #[doc = " for the editor's life. Rows and stored values are never"]
    #[doc = " reclaimed — re-setting a payload leaves the old bytes behind"]
    #[doc = " inert, the commit-only trade."]
    #[doc = ""]
    #[doc = " Every face that walks the source takes `&mut self` (the walk"]
    #[doc = " is the supply's), and each spends exactly the walks its"]
    #[doc = " contract names: `open` one, `descend` one (zero once resident),"]
    #[doc = " `materialize` one for the whole batch, each fetch one, each"]
    #[doc = " save one, `save_len` zero."]
    machine Overhaul<'p>,
    store: Store<'p>,
    pay: mixed,
}

overhaul_machine! {
    #[doc = " A one-shot commit-only editor over a stable-replay source,"]
    #[doc = " with borrowed payloads: [`Overhaul`]'s sibling for callers"]
    #[doc = " whose payload bytes all outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload` and `insert_payload` take `&'p [u8]` and retain"]
    #[doc = " the slice — no staging copy, no copied-byte arena at all (the"]
    #[doc = " layout pin below the forms holds the saved column), and no"]
    #[doc = " `_copy` twins. Saves copy each live payload once into the"]
    #[doc = " output; the saved bytes carry no borrow."]
    #[doc = ""]
    #[doc = " Everything else is [`Overhaul`]'s contract: tolerant"]
    #[doc = " admission, byte-exact fidelity for untouched extents, and"]
    #[doc = " commit-only editing over plain data."]
    machine BorrowOverhaul<'p>,
    store: BorrowStore<'p>,
    pay: borrow,
}

overhaul_machine! {
    #[doc = " A one-shot commit-only editor over a stable-replay source,"]
    #[doc = " with copied payloads: [`Overhaul`]'s sibling for callers"]
    #[doc = " whose payloads are transient."]
    #[doc = ""]
    #[doc = " `set_payload` and `insert_payload` stage their bytes by copy"]
    #[doc = " at the command — temporaries welcome, no payload lifetime on"]
    #[doc = " the type, and no `_copy` suffix distinction: every install"]
    #[doc = " copies."]
    #[doc = ""]
    #[doc = " Everything else is [`Overhaul`]'s contract: tolerant"]
    #[doc = " admission, byte-exact fidelity for untouched extents, and"]
    #[doc = " commit-only editing over plain data."]
    machine CopyOverhaul,
    store: CopyStore,
    pay: copy,
}

// The machine layouts, pinned exactly over the slice source so
// the store forms' deltas stay reviewable: the borrowed form
// drops the copied arena whole (one Vec — 24 bytes on 64-bit
// pointers; on 32-bit the machine's 8-alignment absorbs part of
// it and the saving is eight), and the mixed form matches the
// copy form (its slot entries are wider, its columns the same).
// Size pins, not field-semantics proofs: any layout change lands
// here for review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    let mixed = core::mem::size_of::<Overhaul<'_, crate::replay_source::SliceSource<'_>>>();
    let borrow = core::mem::size_of::<BorrowOverhaul<'_, crate::replay_source::SliceSource<'_>>>();
    let copy = core::mem::size_of::<CopyOverhaul<crate::replay_source::SliceSource<'_>>>();
    assert!(mixed == if w64 { 128 } else { 72 });
    assert!(borrow + if w64 { 24 } else { 8 } == mixed);
    assert!(copy == mixed);
};

/// The save walks' read-only view over the edit state: rows,
/// chain anchor, and the authored store — everything the sizing
/// and compile walks read, with the source handle left outside so
/// the emission walk can borrow it beside the compiled script.
/// Declared once; each store form carries its own concrete impl.
#[derive(Clone, Copy)]
struct SaveView<'a, St> {
    rows: &'a [Row],
    top: Option<RowId>,
    store: &'a St,
}

/// The save arms: one verdict per row, shared by the sizing and
/// compile walks so their dispatch cannot drift.
enum Arm {
    /// Deleted: the source extent (if any) is sought past.
    Skip { end: Option<u64> },
    /// Rides verbatim whole, subtree included.
    Clean { at: u64, end: u64 },
    /// Replaced scalar: source tag verbatim, minimal value.
    ReValue { tag_end: u64, span_end: u64, kind: RecordKind, word: u64 },
    /// Authored scalar: minimal head, minimal value.
    NewValue { head: u32, kind: RecordKind, word: u64 },
    /// Replaced payload: source tag verbatim, prefix verbatim on
    /// equal length, authored bytes.
    ReBody { tag_end: u64, prefix_end: u64, src_len: u64, slot: u32, span_end: u64 },
    /// Authored LEN: minimal head, minimal prefix, authored
    /// bytes.
    NewBody { head: u32, slot: u32 },
    /// An opened container with interior edits: tag verbatim,
    /// prefix priced against the settled body, interior chain
    /// descends.
    Spine { tag_end: u64, prefix_end: u64, src_len: u64, first: Option<RowId> },
    /// A scanned group with interior edits: start tag verbatim,
    /// interior chain descends, end tag verbatim at the pop — no
    /// prefix exists to price (the pop reads the row's own
    /// geometry).
    GroupSpine { tag_end: u64, first: Option<RowId> },
    /// An authored group: minimal start tag, interior chain,
    /// minimal end tag at the pop.
    NewGroup { field: FieldNumber, first: Option<RowId> },
}

/// The minimal head word of an authored record (a group's start
/// tag included: its kind code is the start code).
fn head_word(field: FieldNumber, kind: RecordKind) -> u32 {
    (field.as_inner() << 3) | u32::from(kind.low3().as_inner())
}

/// The minimal end-of-group word of an authored group (code 4:
/// the end-of-group punctuation).
const fn end_word(field: FieldNumber) -> u32 {
    (field.as_inner() << 3) | 4
}

/// An emitted scalar value's width.
#[allow(
    clippy::as_conversions,
    reason = "an encoded varint width (1..=10) widens losslessly into u64"
)]
const fn value_width(kind: RecordKind, word: u64) -> u64 {
    match kind {
        RecordKind::Varint => encoded_len64(word) as u64,
        RecordKind::I32 => 4,
        RecordKind::I64 => 8,
        RecordKind::Len | RecordKind::Group => unreachable!(),
    }
}

/// Stages a scalar value into the script.
fn stage_value(script: &mut Script<'_>, kind: RecordKind, word: u64) {
    match kind {
        RecordKind::Varint => script.stage_word(word),
        #[allow(
            clippy::as_conversions,
            reason = "an I32 row's word column holds four bytes' bits, so it fits u32"
        )]
        RecordKind::I32 => script.stage_bytes(&(word as u32).to_le_bytes()),
        RecordKind::I64 => script.stage_bytes(&word.to_le_bytes()),
        RecordKind::Len | RecordKind::Group => {
            unreachable!("the value arms carry scalar kinds only")
        }
    }
}

/// Maps a splicing-pump refusal onto the save alphabet.
#[cold]
fn emit_fault<E>(fault: FoldFault<E>) -> SaveFault<E> {
    match fault {
        FoldFault::Rewind(supply) => {
            SaveFault::Source(ReplayFault::Rewind { phase: ReplayPhase::Emit, source: supply })
        }
        FoldFault::Source { at, source } => {
            SaveFault::Source(ReplayFault::Read { phase: ReplayPhase::Emit, at, source })
        }
        FoldFault::Torn { at } => SaveFault::Torn { at },
    }
}

// ─── iterators ───

/// Iterates one sibling chain, in wire order.
#[derive(Clone)]
pub struct Children<'t> {
    rows: &'t [Row],
    cur: Option<RowId>,
}

impl Iterator for Children<'_> {
    type Item = Handle;

    fn next(&mut self) -> Option<Handle> {
        let id = self.cur?;
        self.cur = self.rows[id.index()].next;
        Some(Handle(id))
    }
}

impl core::iter::FusedIterator for Children<'_> {}

impl<'t> Children<'t> {
    /// Filters the chain to records of one field number.
    #[inline]
    pub fn by_field(self, field: FieldNumber) -> impl Iterator<Item = Handle> + 't {
        let rows = self.rows;
        self.filter(move |&Handle(id)| rows[id.index()].field == field)
    }
}

// ─── the walks (private) ───

/// Parks a resident refusal on a record, returning the fault
/// slot.
fn park_in(rows: &mut [Row], faults: &mut Vec<Fault>, id: RowId, fault: Fault) -> u32 {
    #[allow(
        clippy::as_conversions,
        reason = "at most one parked verdict per LEN row, and rows fit the index class"
    )]
    let slot = faults.len() as u32;
    faults.push(fault);
    let row = &mut rows[id.index()];
    row.value = slot;
    row.state |= FLAG_FAULTED;
    slot
}

/// A walk-stopping outcome, judged by the caller's phase: the
/// open walk turns `Wire` into a refusal, the descend walks park
/// it; `Torn` exists only past the measuring walk.
enum Halt<E> {
    Wire(Fault),
    Source(ReplayFault<E>),
    Torn { at: u64 },
    IndexOverflow { at: u64 },
    OffsetExhausted { at: u64 },
}

/// Books one row into the arena, linking the chain, admitted
/// against the row-index class.
#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are one row's columns, spelled once at the one mint"
)]
fn push_row<E>(
    rows: &mut Vec<Row>,
    chain: &mut Chain,
    parent: Option<RowId>,
    at: u64,
    field: FieldNumber,
    kind: RecordKind,
    tag_width: WordWidth,
    payload_len: u64,
    delim_width: Option<WordWidth>,
    word: u64,
) -> Result<(), Halt<E>> {
    let Ok(index) = u32::try_from(rows.len()) else {
        return Err(Halt::IndexOverflow { at });
    };
    if index > RowId::MAX.as_inner() {
        return Err(Halt::IndexOverflow { at });
    }
    let id = mint(index);
    rows.push(Row {
        start: at,
        payload_len,
        word,
        parent,
        kid: None,
        next: None,
        value: 0,
        field,
        kind,
        tag_width,
        delim_width,
        state: BASE_INTACT,
    });
    match chain.prev {
        Some(prev) => rows[prev.index()].next = Some(id),
        None => chain.first = Some(id),
    }
    chain.prev = Some(id);
    Ok(())
}

/// One sibling chain under construction.
struct Chain {
    first: Option<RowId>,
    prev: Option<RowId>,
}

/// A fresh walk over one measured extent: begin, seek, scan — the
/// descend face's engine. The extent's coordinates were measured
/// by the open walk, so a short walk is a tear. `base` is the
/// extent's interior depth (the LEN's own depth plus one): groups
/// met inside spend the budget from there.
fn scan_extent<S: StableReplaySource>(
    source: &mut S,
    rows: &mut Vec<Row>,
    parent: RowId,
    start: u64,
    end: u64,
    base: u32,
    limit: DepthLimit,
) -> Result<Option<RowId>, Halt<S::Error>> {
    let walk = match source.begin() {
        Ok(walk) => walk,
        Err(fault) => {
            return Err(Halt::Source(ReplayFault::Rewind {
                phase: ReplayPhase::Descend,
                source: fault,
            }));
        }
    };
    let mut pump = Pump::new(walk);
    match pump.skip_bytes(start) {
        Ok(advanced) if advanced == start => {}
        Ok(_) => return Err(Halt::Torn { at: start }),
        Err(supply) => {
            return Err(Halt::Source(ReplayFault::Read {
                phase: ReplayPhase::Descend,
                at: pump.off,
                source: supply,
            }));
        }
    }
    pump.zone = end;
    scan_layer(&mut pump, rows, Some(parent), Some(end), base, limit)
}

/// Scans one layer at the pump's position into the row arena —
/// walking group interiors transparently (their frames live on
/// the scan's own stack) — returning the outermost chain's first
/// row.
///
/// `extent` is `None` for the open walk (the root layer: the
/// walk's own end closes it, and a mid-construct end is the
/// document's truncation) and the measured payload end for the
/// descend walks (a walk end before it is a tear — the open walk
/// proved those bytes). The pump's zone must equal the extent's
/// end (the root: the sentinel) — groups declare no extent and
/// never move it. `base` is this layer's depth; each open group
/// frame adds one against `limit`.
#[allow(
    clippy::too_many_lines,
    reason = "one dispatch site per wire construct; splitting it would scatter the \
              refusal coordinates the arms share"
)]
fn scan_layer<W: ReplayWalk>(
    pump: &mut Pump<W>,
    rows: &mut Vec<Row>,
    outer_parent: Option<RowId>,
    extent: Option<u64>,
    base: u32,
    limit: DepthLimit,
) -> Result<Option<RowId>, Halt<W::Error>> {
    let phase = if extent.is_none() { ReplayPhase::Index } else { ReplayPhase::Descend };
    let supply_abort = |pump: &Pump<W>, supply: SupplyFault<W::Error>| {
        Halt::Source(ReplayFault::Read { phase, at: pump.off, source: supply })
    };
    // The walk's end mid-construct: the measuring walk judges the
    // document truncated; a descend walk judges the source torn.
    let cut_end = |pump: &Pump<W>, wire: Fault| match extent {
        None => Halt::Wire(wire),
        Some(_) => Halt::Torn { at: pump.off },
    };
    let mut chain = Chain { first: None, prev: None };
    // Open group frames: the group's row beside the chain it
    // suspended. The chain in `chain` is always the innermost.
    let mut stack: Vec<(RowId, Chain)> = Vec::new();
    let mut parent = outer_parent;
    // The extent (or the root walk) may not end around an open
    // group: its end tag never appeared.
    let unclosed = |rows: &[Row], stack: &[(RowId, Chain)], at: u64| {
        let &(gid, _) = stack.last().expect("judged only with frames open");
        Halt::Wire(Fault { at, kind: FaultKind::GroupUnclosed { open: rows[gid.index()].field } })
    };
    loop {
        if let Some(end) = extent
            && pump.off == end
        {
            if !stack.is_empty() {
                return Err(unclosed(rows, &stack, pump.off));
            }
            return Ok(chain.first);
        }
        debug_assert!(pump.off <= pump.zone);
        let at = pump.off;
        let (word, tag_width) = match pump.step_tag(Standard::Tolerant) {
            StepRead::Done { value, width } => (value, width),
            StepRead::End => {
                if extent.is_none() {
                    if !stack.is_empty() {
                        return Err(unclosed(rows, &stack, pump.off));
                    }
                    return Ok(chain.first);
                }
                // A sealed extent's walk cannot end cleanly before
                // the seal: the open walk measured bytes here.
                return Err(Halt::Torn { at: pump.off });
            }
            StepRead::SealCut => {
                return Err(Halt::Wire(Fault {
                    at: pump.off,
                    kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SealCut },
                }));
            }
            StepRead::SourceEnd => {
                return Err(cut_end(
                    pump,
                    Fault {
                        at: pump.off,
                        kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SourceEnd },
                    },
                ));
            }
            StepRead::TooWide => {
                let start = pump.construct_start();
                return Err(Halt::Wire(Fault {
                    at: start,
                    kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::TooWide },
                }));
            }
            StepRead::OutOfClass => {
                let start = pump.construct_start();
                return Err(Halt::Wire(Fault {
                    at: start,
                    kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::OutOfClass },
                }));
            }
            StepRead::NonMinimal { .. } => {
                unreachable!("the tolerant standard judges no widths")
            }
            StepRead::Exhausted => return Err(Halt::OffsetExhausted { at: pump.off }),
            StepRead::Fault(supply) => return Err(supply_abort(pump, supply)),
        };
        let low3 = Low3::from_word(word);
        let Some(field) = FieldNumber::from_word(word) else {
            return Err(Halt::Wire(Fault { at, kind: FaultKind::FieldZero { code: low3 } }));
        };
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                let after_tag = pump.off;
                let (value, width) = match pump.step_value(Standard::Tolerant) {
                    StepRead::Done { value, width } => (value, width),
                    StepRead::SealCut => {
                        return Err(Halt::Wire(Fault {
                            at: pump.off,
                            kind: FaultKind::Read {
                                stage: Stage::Value { field },
                                cause: ReadFault::SealCut,
                            },
                        }));
                    }
                    StepRead::SourceEnd => {
                        return Err(cut_end(
                            pump,
                            Fault {
                                at: pump.off,
                                kind: FaultKind::Read {
                                    stage: Stage::Value { field },
                                    cause: ReadFault::SourceEnd,
                                },
                            },
                        ));
                    }
                    StepRead::TooWide => {
                        return Err(Halt::Wire(Fault {
                            at: after_tag,
                            kind: FaultKind::Read {
                                stage: Stage::Value { field },
                                cause: ReadFault::TooWide,
                            },
                        }));
                    }
                    StepRead::OutOfClass => {
                        return Err(Halt::Wire(Fault {
                            at: after_tag,
                            kind: FaultKind::Read {
                                stage: Stage::Value { field },
                                cause: ReadFault::OutOfClass,
                            },
                        }));
                    }
                    StepRead::End | StepRead::NonMinimal { .. } => {
                        unreachable!("interior steps judge a walk end as SourceEnd; tolerant")
                    }
                    StepRead::Exhausted => return Err(Halt::OffsetExhausted { at: pump.off }),
                    StepRead::Fault(supply) => return Err(supply_abort(pump, supply)),
                };
                push_row(
                    rows,
                    &mut chain,
                    parent,
                    at,
                    field,
                    RecordKind::Varint,
                    tag_width,
                    u64::from(width.w()),
                    None,
                    value,
                )?;
            }
            TagClass::Record(kind @ (RecordKind::I64 | RecordKind::I32)) => {
                let needed: u8 = if matches!(kind, RecordKind::I64) { 8 } else { 4 };
                let after_tag = pump.off;
                if pump.zone - pump.off < u64::from(needed) {
                    return Err(Halt::Wire(Fault {
                        at: after_tag,
                        kind: FaultKind::FixedTruncated { field, needed },
                    }));
                }
                let grabbed = if matches!(kind, RecordKind::I64) {
                    match pump.grab_fixed::<8>() {
                        GrabRead::Done(value) => Some(u64::from_le_bytes(value)),
                        GrabRead::SourceEnd => None,
                        GrabRead::Exhausted => {
                            return Err(Halt::OffsetExhausted { at: pump.off });
                        }
                        GrabRead::Fault(supply) => return Err(supply_abort(pump, supply)),
                    }
                } else {
                    match pump.grab_fixed::<4>() {
                        GrabRead::Done(value) => Some(u64::from(u32::from_le_bytes(value))),
                        GrabRead::SourceEnd => None,
                        GrabRead::Exhausted => {
                            return Err(Halt::OffsetExhausted { at: pump.off });
                        }
                        GrabRead::Fault(supply) => return Err(supply_abort(pump, supply)),
                    }
                };
                let Some(word) = grabbed else {
                    return Err(cut_end(
                        pump,
                        Fault { at: after_tag, kind: FaultKind::FixedTruncated { field, needed } },
                    ));
                };
                push_row(
                    rows,
                    &mut chain,
                    parent,
                    at,
                    field,
                    kind,
                    tag_width,
                    u64::from(needed),
                    None,
                    word,
                )?;
            }
            TagClass::Record(RecordKind::Len) => {
                let after_tag = pump.off;
                let (declared, prefix_width) = match pump.step_len(Standard::Tolerant) {
                    StepRead::Done { value, width } => (value, width),
                    StepRead::SealCut => {
                        return Err(Halt::Wire(Fault {
                            at: pump.off,
                            kind: FaultKind::Read {
                                stage: Stage::LenPrefix { field },
                                cause: ReadFault::SealCut,
                            },
                        }));
                    }
                    StepRead::SourceEnd => {
                        return Err(cut_end(
                            pump,
                            Fault {
                                at: pump.off,
                                kind: FaultKind::Read {
                                    stage: Stage::LenPrefix { field },
                                    cause: ReadFault::SourceEnd,
                                },
                            },
                        ));
                    }
                    StepRead::TooWide => {
                        return Err(Halt::Wire(Fault {
                            at: after_tag,
                            kind: FaultKind::Read {
                                stage: Stage::LenPrefix { field },
                                cause: ReadFault::TooWide,
                            },
                        }));
                    }
                    StepRead::OutOfClass => {
                        return Err(Halt::Wire(Fault {
                            at: after_tag,
                            kind: FaultKind::Read {
                                stage: Stage::LenPrefix { field },
                                cause: ReadFault::OutOfClass,
                            },
                        }));
                    }
                    StepRead::End | StepRead::NonMinimal { .. } => {
                        unreachable!("interior steps judge a walk end as SourceEnd; tolerant")
                    }
                    StepRead::Exhausted => return Err(Halt::OffsetExhausted { at: pump.off }),
                    StepRead::Fault(supply) => return Err(supply_abort(pump, supply)),
                };
                let declared64 = u64::from(declared.as_inner());
                if pump.zone == u64::MAX {
                    if declared64 > (u64::MAX - 1) - pump.off {
                        return Err(Halt::Wire(Fault {
                            at,
                            kind: FaultKind::LenUnsatisfiable { field, declared },
                        }));
                    }
                } else if declared64 > pump.zone - pump.off {
                    let zone_left = pump.zone - pump.off;
                    return Err(Halt::Wire(Fault {
                        at: after_tag,
                        kind: FaultKind::LenOverrun { field, declared, zone_left },
                    }));
                }
                push_row(
                    rows,
                    &mut chain,
                    parent,
                    at,
                    field,
                    RecordKind::Len,
                    tag_width,
                    declared64,
                    Some(prefix_width),
                    0,
                )?;
                // The payload stays opaque here: skipped, never
                // lent. A short skip is the source ending inside
                // the declared extent.
                match pump.skip_bytes(declared64) {
                    Ok(advanced) if advanced == declared64 => {}
                    Ok(advanced) => {
                        return Err(cut_end(
                            pump,
                            Fault {
                                at: after_tag,
                                kind: FaultKind::LenOverrun {
                                    field,
                                    declared,
                                    zone_left: advanced,
                                },
                            },
                        ));
                    }
                    Err(supply) => return Err(supply_abort(pump, supply)),
                }
            }
            TagClass::Record(RecordKind::Group) => {
                #[allow(
                    clippy::as_conversions,
                    reason = "open frame counts are bounded by the depth class, which \
                              fits u32"
                )]
                if base + stack.len() as u32 >= u32::from(limit.as_inner()) {
                    return Err(Halt::Wire(Fault {
                        at,
                        kind: FaultKind::DepthExceeded { field, limit },
                    }));
                }
                push_row(
                    rows,
                    &mut chain,
                    parent,
                    at,
                    field,
                    RecordKind::Group,
                    tag_width,
                    0,
                    None,
                    0,
                )?;
                let gid = chain.prev.expect("push_row just linked this row");
                // Suspend the outer chain; the interior scans as
                // part of this same walk.
                stack
                    .push((gid, core::mem::replace(&mut chain, Chain { first: None, prev: None })));
                parent = Some(gid);
            }
            TagClass::GroupEnd => {
                let Some((gid, outer)) = stack.pop() else {
                    return Err(Halt::Wire(Fault {
                        at,
                        kind: FaultKind::GroupEndOrphan { found: field },
                    }));
                };
                let row = &mut rows[gid.index()];
                if row.field != field {
                    return Err(Halt::Wire(Fault {
                        at,
                        kind: FaultKind::GroupEndMismatch { open: row.field, found: field },
                    }));
                }
                row.kid = chain.first;
                row.payload_len = at - (row.start + row.tag_w());
                row.delim_width = Some(tag_width);
                parent = row.parent;
                chain = outer;
            }
            TagClass::Unassigned => {
                return Err(Halt::Wire(Fault {
                    at,
                    kind: FaultKind::Unassigned { field, code: low3 },
                }));
            }
        }
    }
}

/// One fetch walk over one measured extent: begin, seek, deliver.
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
    let mut handed = 0u64;
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

#[cfg(test)]
mod tests;
