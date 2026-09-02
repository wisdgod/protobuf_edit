//! The grouped maintain editor: handle-based edits with precise
//! undo over a stable-replay source, saved in two passes with the
//! overhaul's byte fidelity.
//!
//! This dialect speaks the six-code wire language: groups are
//! containers framed by their own start and end tags, and every
//! scan materializes them eagerly — a group carries no length
//! declaration, so there is nothing to skip past; its interior
//! parses as part of the walk that meets it, with an unbounded
//! fallible frame stack and no declared depth budget (descent
//! into LENs stays caller-stepped). Group grammar violations
//! ([`FaultKind::GroupEndOrphan`], [`FaultKind::GroupEndMismatch`],
//! [`FaultKind::GroupUnclosed`]) are wire faults like any other.
//!
//! Admission is tolerant: padded tags, length prefixes, and varint
//! values are lawful input, so every framing width the scan meets
//! is stored on the row as an input fact (a group's end-tag width
//! is patched at its close), every scanned scalar's decoded word
//! is banked at the scan, and every untouched span reproduces its
//! padding byte-exactly at save. The root layer is eager; LEN
//! payloads stay opaque until [`Maintain::descend`], whose verdict
//! is resident.
//!
//! The fidelity contract, face by face: records no live edit
//! touches ride into the output bit-exact, padding included; a
//! replaced record keeps its source tag bytes verbatim; a LEN
//! prefix rides verbatim while its body length is unchanged and is
//! re-authored minimally only when the length moved;
//! command-authored records emit minimally. Reverting a command
//! restores the fidelity reading exactly — `revert_all` makes the
//! save the source again, padding included — and costs no walk:
//! the banked words and stored widths re-speak the scanned
//! reading.
//!
//! The canonical contract, one face family: `save_canonical`,
//! `save_canonical_into`, and `save_canonical_sink` minimally emit
//! every varint construct in the materialized commitment closure.
//! The opacity boundary is explicit descent: bytes inside an
//! un-descended or faulted LEN may happen to form padded protobuf
//! words — they are payload bytes, not records, and pass unchanged
//! behind re-derived outer framing; a successful descend commits
//! them into the closure and the next canonical save normalizes
//! them.
//!
//! Every mutation is transactional: admission judgments come
//! first, every reservation is fallible, and once the store push
//! (or, for storeless commands, the last reservation) succeeds the
//! remaining suffix cannot fail — an `Err` from any command leaves
//! the editor's observable edit state unchanged. Allocation
//! refusals surface as structured errors ([`OpenFault::Resource`],
//! [`EditFault::Resource`], [`SaveFault::Resource`]); nothing in
//! this module aborts on allocator pressure.
//!
//! Two fault layers split what a walk can judge from what it never
//! re-reads (the supply stratum's contract): supply refusals
//! surface as structured faults, machine-detected tears as `Torn`.
//! A descend, materialize, or fetch walk judges only that the
//! source still reaches its extent's end, refusing a shorter
//! source as `Torn`; growth and displacement are undetectable
//! there, so under a breached byte-identity obligation a fetch
//! hands wrong bytes and a descend can park a fabricated document
//! fault — never memory-unsafe, warranty void. Only the save walks
//! anchor the measured total: the emission's end probe refuses a
//! source that grew or shrank as `Torn`.
//!
//! Coordinates: write · sequential-repeatable · offline · grouped · tolerant (type-level) · revisable.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::maintain::grouped::Maintain;
//! use protobuf_edit::replay_source::SliceSource;
//!
//! // group f1 { varint f2=3 } · varint f2=42
//! let msg = [0x0B, 0x10, 0x03, 0x0C, 0x10, 0x2A];
//! let mut editor = Maintain::open(SliceSource::new(&msg)).unwrap();
//! let tops: Vec<_> = editor.top().collect();
//!
//! // Group interiors materialize at the scan: no descend owed.
//! let inner = editor.children(tops[0]).unwrap().next().unwrap();
//! assert_eq!(editor.varint_word(inner).unwrap(), 3);
//!
//! // Group framing tags ride saves verbatim around interior
//! // edits.
//! editor.set_varint(inner, 7).unwrap();
//! assert_eq!(editor.save().unwrap(), [0x0B, 0x10, 0x07, 0x0C, 0x10, 0x2A]);
//! ```

use alloc::vec::Vec;

use crate::admission::usize_of;
#[cfg(debug_assertions)]
use crate::maintain::FLAG_HIST;
use crate::maintain::{
    At64, BorrowStore, Edit, FLAG_AUTHORED, FLAG_DEAD, FLAG_DIRTY, FLAG_FAULT, FLAG_OPENED,
    FLAG_OWN_HIST, Handle, Layer, LayerId, Mark, MixStore, NO_CHILD, RowId, Slot, SourceRun,
    SourceRunId, Store, StoreFault, Transition, ValueAt, Zone,
};
use crate::replay_pump::{GrabRead, Pump, StepRead};
use crate::replay_script::{FoldFault, Script, fold};
use crate::replay_source::{
    AuthoredAt, FaultAt, Handed, ReplayFault, ReplayPhase, ReplayWalk, SliceSource, SlotAt,
    SourceAt, SourceSpan, StableReplaySource, SupplyFault,
};
use crate::varint::{ValueWidth, WordWidth, encoded_len32, encoded_len64};
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{FaultClass, Stage, Standard};

use crate::maintain::{EditStatus, InsertAt};

use alloc::collections::TryReserveError;

#[cfg(test)]
mod tests;

crate::replay_revise::revising_replay_store!(@word_role full);
crate::replay_revise::revising_replay_store!(@len_role met);
crate::replay_revise::revising_replay_store!(@row tolerant);

// ─── the law ───

/// A varint read refusal in walk coordinates: the carry kernel's
/// refusal alphabet with the boundary folded into the cause.
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
/// The coordinate is a [`FaultAt`]: the fault sits on bytes a
/// source walk established (whole-source offsets) or on bytes a
/// caller installed (one authored slot's own zone) — the two
/// spaces share no origin, so the carrier keeps them from
/// impersonating each other. Its offset's meaning per kind: a
/// [`FaultKind::Read`] names the refused construct's first byte,
/// except that a [`ReadFault::SealCut`] names the sealed endpoint
/// and a [`ReadFault::SourceEnd`] names the zone's end; truncation
/// kinds name the zone's end; structural kinds name the judgment
/// point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: FaultAt,
    kind: FaultKind,
}

impl Fault {
    /// The coordinate, in exactly one of the two zones a maintain
    /// editor reads.
    #[inline]
    pub const fn at(self) -> FaultAt {
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
        match (self.at.source_at(), self.at.slot(), self.at.authored_at()) {
            (Some(at), _, _) => write!(f, "{} at source offset {at}", self.kind),
            (None, Some(slot), Some(at)) => {
                write!(f, "{} at offset {at} of authored slot {slot}", self.kind)
            }
            // The carrier projects exactly one zone.
            _ => unreachable!("a fault coordinate speaks exactly one zone"),
        }
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.kind)
    }
}

/// The refusal classes, sectioned by [`FaultClass`] (grammar
/// sites, then capability); [`class`](Self::class) answers the
/// section.
///
/// This machine is the tolerant instance, so no minimality
/// judgments exist in its vocabulary, and it declares no depth
/// bound, so no policy section exists either — descent into LENs
/// is caller-stepped, and group nesting rides a fallible frame
/// stack. Wire-declared quantities are quoted as their wire
/// types; a bad record never reaches the row table, so its field
/// number travels with the fault — inside the [`Stage`]
/// coordinate for varint reads (the tag stage carries none: no
/// field exists yet), on the variant elsewhere. Group codes are
/// this dialect's own language, so no group-code capability
/// refusal exists — the group grammar arms judge their pairing
/// instead.
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
    /// The extent (or the zone) ended inside a fixed-width
    /// payload.
    FixedTruncated {
        /// The record's field number.
        field: FieldNumber,
        /// The width the kind requires (4 or 8).
        needed: u8,
    },
    // ─ grammar: group pairing ─
    /// A group end tag arrived with no group open.
    GroupEndOrphan {
        /// The end tag's field number.
        found: FieldNumber,
    },
    /// A group end tag named a different field than the group it
    /// would close.
    GroupEndMismatch {
        /// The open group's field number.
        open: FieldNumber,
        /// The end tag's field number.
        found: FieldNumber,
    },
    /// The extent (or the zone) ended before an open group's end
    /// tag.
    GroupUnclosed {
        /// The open group's field number.
        open: FieldNumber,
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
    /// for.
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
                    ReadFault::SourceEnd => f.write_str("the zone ended inside ")?,
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
                write!(f, "group end tag of field {} closes nothing", found.as_inner())
            }
            Self::GroupEndMismatch { open, found } => write!(
                f,
                "group of field {} is closed by an end tag of field {}",
                open.as_inner(),
                found.as_inner()
            ),
            Self::GroupUnclosed { open } => {
                write!(f, "group of field {} never meets its end tag", open.as_inner())
            }
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
/// The revisable editor refuses an unlawful root layer whole (the
/// buffered twins' law: a document that cannot be saved back
/// faithfully is refused before any handle is minted); the source
/// rides back beside the mark.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenFault<E> {
    /// The root layer violates the wire grammar, the dialect
    /// capability, or the coordinate space's hosting judgment.
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
    /// The allocator refused the editor's working storage or the
    /// root scan; the source rides back and the open may be
    /// retried.
    Resource,
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
            Self::Resource => f.write_str("allocator refused the editor's working storage"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for OpenFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(fault) => Some(fault),
            Self::Source(fault) => Some(fault),
            Self::IndexOverflow { .. } | Self::OffsetExhausted { .. } | Self::Resource => None,
        }
    }
}

/// Why an edit command refused.
///
/// Failure classes are judged in no promised order: a command may
/// report a temporary refusal ([`Self::Resource`]) before a
/// permanent one on the same call. On any `Err` the editor's
/// observable edit state is unchanged.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EditFault {
    /// The handle's row was orphaned by a payload replacement.
    DeadHandle,
    /// The record's wire kind does not fit the command.
    KindMismatch {
        /// The record's actual kind.
        have: RecordKind,
    },
    /// The record is deleted; undelete it first.
    DeletedTarget,
    /// The record is not deleted.
    NotDeleted,
    /// Only replaced records clear back to their scanned state.
    NotClearable,
    /// Descend the container before inserting into it.
    TargetUnopened,
    /// Records inside an authored payload are browse-only.
    InsideAuthoredBody,
    /// The interior carries edits or revision-log entries; revert
    /// first.
    EditedInterior,
    /// The replacement payload exceeds the length class.
    PayloadTooLarge {
        /// The refused payload length.
        len: usize,
    },
    /// The allocator refused editor growth; the command changed
    /// nothing and may be retried.
    Resource,
    /// The editor's edit storage is full; the refusal is permanent
    /// for this editor.
    IndexSpaceExhausted,
}

impl core::fmt::Display for EditFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::DeadHandle => f.write_str("the row was orphaned by a payload replacement"),
            Self::KindMismatch { have } => {
                write!(f, "the command expects another wire kind; the record is {have:?}")
            }
            Self::DeletedTarget => f.write_str("the record is deleted; undelete it first"),
            Self::NotDeleted => f.write_str("the record is not deleted"),
            Self::NotClearable => {
                f.write_str("only replaced records clear back to their scanned state")
            }
            Self::TargetUnopened => f.write_str("descend the container before inserting into it"),
            Self::InsideAuthoredBody => {
                f.write_str("records inside an authored payload are browse-only")
            }
            Self::EditedInterior => {
                f.write_str("the interior carries edits or revision log entries; revert them first")
            }
            Self::PayloadTooLarge { len } => {
                write!(f, "payload of {len} bytes exceeds the length class")
            }
            Self::Resource => f.write_str("allocator refused editor growth"),
            Self::IndexSpaceExhausted => f.write_str("the editor's edit storage is full"),
        }
    }
}

impl core::error::Error for EditFault {}

/// Why a descend (or materialize) call gave no resident verdict.
///
/// Nothing about the *document* was judged — the target gate
/// refused, the supply refused, or the walk's length shape
/// contradicted the measured coordinates. The editor's observable
/// edit state is exactly as before the call (verdicts already
/// parked by an earlier extent of the same batch stand — each
/// extent commits atomically).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DescendFault<E> {
    /// The target gate refused (dead handle, kind, allocator);
    /// walk-free.
    Edit(EditFault),
    /// The supply refused (transport or a detected snapshot
    /// break).
    Source(ReplayFault<E>),
    /// The walk met its end before a measured coordinate — a
    /// length-shaped tear.
    Torn {
        /// The measured whole-source coordinate the walk could
        /// not honor.
        at: u64,
    },
    /// The interior rows would leave the row-index class (the
    /// verdict is not parked).
    IndexOverflow {
        /// The whole-source offset of the record that would not
        /// fit.
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
/// could not. On any `Err` the `Vec` face's buffer is
/// byte-identical to entry (the sink face reports its handed
/// prefix instead).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FetchFault<E> {
    /// The handle's row was orphaned by a payload replacement.
    DeadHandle,
    /// The record is not a LEN record, so no payload extent
    /// exists to fetch (scalar values are row-resident:
    /// `varint_word`, `i32_bits`, `i64_bits`).
    KindMismatch {
        /// The record's actual kind.
        have: RecordKind,
    },
    /// The extent does not fit the address space, so the `Vec`
    /// face cannot stage it (the sink faces have no such
    /// ceiling).
    Oversize {
        /// The extent's byte length.
        len: u64,
    },
    /// The allocator refused the `Vec` face's reservation; the
    /// call changed nothing and may be retried (the sink faces
    /// reserve nothing).
    Resource,
    /// The walk met its end before a coordinate the index walk
    /// measured — a length-shaped tear, refused.
    Torn {
        /// The measured whole-source coordinate the walk could
        /// not reach.
        at: u64,
    },
    /// The supply refused (transport or a detected snapshot
    /// break).
    Source(ReplayFault<E>),
}

impl<E: core::fmt::Display> core::fmt::Display for FetchFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeadHandle => f.write_str("the row was orphaned by a payload replacement"),
            Self::KindMismatch { have } => {
                write!(f, "the fetch expects a LEN record; the record is {have:?}")
            }
            Self::Oversize { len } => {
                write!(f, "an extent of {len} bytes cannot stage in the address space")
            }
            Self::Resource => f.write_str("allocator refused the fetch buffer"),
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
            Self::DeadHandle
            | Self::KindMismatch { .. }
            | Self::Oversize { .. }
            | Self::Resource
            | Self::Torn { .. } => None,
        }
    }
}

/// Why a save refused. The owned-product faces restore their
/// buffer on any `Err`; the sink faces report their handed prefix
/// instead ([`Handed`]).
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SaveFault<E> {
    /// A rewritten LEN body outgrew the length class.
    BodyOverCap {
        /// Whole-source offset of the overflowing LEN record's
        /// head tag.
        at: u64,
    },
    /// The allocator refused the sizing scratch, the compiled
    /// script, or the output; the save changed nothing and may be
    /// retried.
    Resource,
    /// The supply refused (transport or a detected snapshot
    /// break) during the emission walk.
    Source(ReplayFault<E>),
    /// The emission walk's length shape contradicted the measured
    /// coordinates — the source grew or shrank between walks.
    Torn {
        /// The measured coordinate the walk could not honor.
        at: u64,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for SaveFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BodyOverCap { at } => {
                write!(f, "rewritten body of the LEN at {at} exceeds the length class")
            }
            Self::Resource => f.write_str("allocator refused the save"),
            Self::Source(fault) => write!(f, "{fault}"),
            Self::Torn { at } => {
                write!(f, "the source tore against measured coordinate {at}")
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for SaveFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Source(fault) => Some(fault),
            Self::BodyOverCap { .. } | Self::Resource | Self::Torn { .. } => None,
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
pub enum Descent<'s> {
    /// The payload parsed; its first child, if any.
    Opened {
        /// First record of the interior layer.
        first: Option<Handle>,
    },
    /// The payload refused — a wire violation or the dialect
    /// capability ([`FaultKind`] carries the class) — and the
    /// verdict parked (resident).
    ///
    /// For a source-backed payload, a parked verdict is a
    /// document claim only under the provider's byte-identity
    /// obligation: the descend walk cannot see growth or
    /// displacement beneath its measured coordinates, so a
    /// breached obligation can park a fault the document's bytes
    /// never spelled.
    Parked(&'s Fault),
}

/// Source-document geometry of one backed record.
///
/// The segments partition the record's span exactly, at the
/// widths the scan actually met — padded framing reports its
/// padded extents. Coordinates answer for the walked source
/// bytes, not for any pending edit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordSpans {
    /// Tag, then the varint value.
    Varint {
        /// The tag word.
        tag: SourceSpan,
        /// The value bytes.
        value: SourceSpan,
    },
    /// Tag, then eight value bytes.
    I64 {
        /// The tag word.
        tag: SourceSpan,
        /// The value bytes.
        value: SourceSpan,
    },
    /// Tag, length prefix, payload.
    Len {
        /// The tag word.
        tag: SourceSpan,
        /// The length prefix.
        prefix: SourceSpan,
        /// The payload bytes.
        payload: SourceSpan,
    },
    /// Tag, then four value bytes.
    I32 {
        /// The tag word.
        tag: SourceSpan,
        /// The value bytes.
        value: SourceSpan,
    },
    /// Start tag, interior records, end tag.
    Group {
        /// The start tag word.
        tag: SourceSpan,
        /// The interior records.
        interior: SourceSpan,
        /// The end tag word.
        end_tag: SourceSpan,
    },
}

// ─── rows ───

impl Row {
    /// A command-authored record, born as its own ghost: the
    /// insert command logs this state as the row's past and then
    /// transitions it live, so reverting the birth shrouds it.
    const fn authored(
        field: FieldNumber,
        kind: RecordKind,
        parent: Option<RowId>,
        next: Option<RowId>,
        ghost: Edit,
    ) -> Self {
        Self {
            at: None,
            edit: ghost,
            word_or_end: ScalarWordOrGroupEnd::vacant(),
            field,
            len_or_met: PayloadLenOrValueWidth::vacant(),
            parent,
            next,
            kids: NO_CHILD,
            kind,
            flags: 0,
            tag_width: None,
            delim_width: None,
        }
    }

    /// Stored widths as whole-zone integers (zero when absent —
    /// every use sits behind a state or kind dispatch that proves
    /// presence).
    fn tag_w(&self) -> u64 {
        self.tag_width.map_or(0, |w| u64::from(w.w()))
    }

    fn delim_w(&self) -> u64 {
        self.delim_width.map_or(0, |w| u64::from(w.w()))
    }

    /// The scanned value side's byte extent, derived per kind:
    /// a varint's met value width, a fixed scalar's own width, a
    /// LEN's declared payload length. A group's extent rides the
    /// 8-byte role column instead ([`Row::span_end`]).
    fn value_extent(&self) -> u64 {
        match self.kind {
            RecordKind::Varint => u64::from(self.len_or_met.met_width(self.kind)),
            RecordKind::I32 => 4,
            RecordKind::I64 => 8,
            RecordKind::Len => self.len_or_met.payload_len(self.kind),
            // A group's end is the role column's own fact.
            RecordKind::Group => unreachable!("a group's extent rides the role column"),
        }
    }

    /// End of the whole-record span in the backing zone, from the
    /// caller's witnessed offset (the [`scanned_at`] proof): kind
    /// disjointness derives it — a scalar's from its widths and
    /// met facts, a LEN's from its declared length, a group's
    /// from the banked end in the 8-byte role column. No end
    /// column exists.
    fn span_end(&self, at: At64) -> u64 {
        if matches!(self.kind, RecordKind::Group) {
            return self.word_or_end.end(self.kind);
        }
        at.as_inner() + self.tag_w() + self.delim_w() + self.value_extent()
    }

    /// The payload extent's start in the backing zone, from the
    /// caller's witnessed offset (scanned LEN rows only).
    fn payload_at(&self, at: At64) -> u64 {
        at.as_inner() + self.tag_w() + self.delim_w()
    }

    const fn dirty(&self) -> bool {
        self.flags & FLAG_DIRTY != 0
    }

    const fn dead(&self) -> bool {
        self.flags & FLAG_DEAD != 0
    }

    const fn set_dead(&mut self) {
        self.flags |= FLAG_DEAD;
    }

    const fn authored_zone(&self) -> bool {
        self.flags & FLAG_AUTHORED != 0
    }

    const fn own_hist(&self) -> bool {
        self.flags & FLAG_OWN_HIST != 0
    }

    /// The subtree-history mark, read only by the lattice oracle
    /// (the maintenance climbs address flags through [`Mark`]).
    #[cfg(debug_assertions)]
    const fn hist(&self) -> bool {
        self.flags & FLAG_HIST != 0
    }

    const fn slot(&self) -> Slot {
        if self.flags & FLAG_OPENED != 0 {
            // SAFETY: `set_slot` stores only minted layer ids under
            // `FLAG_OPENED`.
            Slot::Opened(unsafe { LayerId::new_unchecked(self.kids) })
        } else if self.flags & FLAG_FAULT != 0 {
            Slot::Fault(self.kids)
        } else {
            Slot::Unopened
        }
    }

    const fn set_slot(&mut self, slot: Slot) {
        self.flags &= !(FLAG_OPENED | FLAG_FAULT);
        match slot {
            Slot::Unopened => self.kids = NO_CHILD,
            Slot::Opened(layer) => {
                self.flags |= FLAG_OPENED;
                self.kids = layer.as_inner();
            }
            Slot::Fault(index) => {
                self.flags |= FLAG_FAULT;
                self.kids = index;
            }
        }
    }
}

/// The zone offset of a scanned row — one whose edit sits outside
/// the command-authored families. The proof spans two fields
/// (`Row::edit` and `Row::at`) and neither type can carry it
/// alone, so this is the invariant's single witness point; callers
/// bind the offset here once and pass it onward.
///
/// # Safety
///
/// `row.edit` must lie outside the `Inserted` families (the caller
/// has just matched that arm): command-authored rows are born in
/// them and every edit transition is closed over the families, so
/// such a row was pushed by a scan, which always records its
/// offset.
const unsafe fn scanned_at(row: &Row) -> At64 {
    match row.at {
        Some(at) => at,
        // SAFETY: the function's precondition — outside the
        // Inserted families means scan-pushed, and the scan
        // records offsets.
        None => unsafe { core::hint::unreachable_unchecked() },
    }
}

/// The zone offset of a run row — the reverse index's witness
/// point, sibling to [`scanned_at`]: callers bind the offset here
/// once instead of re-testing an `Option` the run contract already
/// proves on every bisection step.
///
/// # Safety
///
/// `row` must be a row of a published source run: run rows are
/// pushed only by a source scan, which always records an offset.
const unsafe fn run_at(row: &Row) -> At64 {
    match row.at {
        Some(at) => at,
        // SAFETY: the function's precondition — run rows are
        // scan-pushed, and the scan records offsets.
        None => unsafe { core::hint::unreachable_unchecked() },
    }
}

// ─── the walks (private) ───

/// The sealed backing zone one scan reads: the walked source, or
/// one authored payload slot's own zone. The scan mints row
/// offsets and fault coordinates through it, so neither space can
/// impersonate the other.
#[derive(Clone, Copy)]
enum ScanZone {
    /// The walked source: whole-source coordinates.
    Source,
    /// One authored slot's zone: slot-relative coordinates.
    Authored {
        /// The store slot whose bytes back the scan.
        slot: SlotAt,
    },
}

impl ScanZone {
    /// Mints a row offset in this zone.
    #[allow(
        clippy::option_if_let_else,
        reason = "the None arm is an unreachable whose argument comment sits on the arm; \
                  a closure form would detach it"
    )]
    fn at(self, off: u64) -> At64 {
        match self {
            // SAFETY: the pump's per-view admission keeps every
            // walk position at most `u64::MAX − 1`.
            Self::Source => At64::from_source(unsafe { SourceAt::new_unchecked(off) }),
            Self::Authored { .. } => match u32::try_from(off).ok().and_then(AuthoredAt::new) {
                Some(at) => At64::from_authored(at),
                // The zone's end was admitted against the length
                // class at its push.
                None => unreachable!("authored zones end inside the length class"),
            },
        }
    }

    /// Mints a fault coordinate in this zone.
    #[allow(
        clippy::option_if_let_else,
        reason = "the None arm is an unreachable whose argument comment sits on the arm; \
                  a closure form would detach it"
    )]
    fn fault_at(self, off: u64) -> FaultAt {
        match self {
            // SAFETY: as [`ScanZone::at`] — the pump's per-view
            // admission bounds the offset.
            Self::Source => FaultAt::source(unsafe { SourceAt::new_unchecked(off) }),
            Self::Authored { slot } => match u32::try_from(off).ok().and_then(AuthoredAt::new) {
                Some(at) => FaultAt::authored(slot, at),
                // As [`ScanZone::at`].
                None => unreachable!("authored zones end inside the length class"),
            },
        }
    }

    /// The layer zone a scan of this backing seals (source layers
    /// take their run at the seal).
    const fn layer_zone(self, run: Option<SourceRunId>) -> Zone {
        match self {
            Self::Source => Zone::Source { run },
            Self::Authored { slot } => Zone::Authored { slot },
        }
    }
}

/// One sibling chain under construction.
struct Chain {
    first: Option<RowId>,
    prev: Option<RowId>,
}

/// A walk-stopping outcome, judged by the caller's phase: the
/// open walk turns `Wire` into a refusal, the descend walks park
/// it; `Torn` exists only past the measuring walk, and only the
/// source zone can meet the supply or coordinate arms.
enum Halt<E> {
    Wire(Fault),
    Source(ReplayFault<E>),
    Torn { at: u64 },
    IndexOverflow { at: u64 },
    OffsetExhausted { at: u64 },
    Resource,
}

#[cold]
const fn halt_resource<E>(_refused: TryReserveError) -> Halt<E> {
    Halt::Resource
}

/// Reserves and mints the next row coordinate.
fn mint_row<E>(rows: &mut Vec<Row>, at: u64) -> Result<RowId, Halt<E>> {
    rows.try_reserve(1).map_err(halt_resource)?;
    u32::try_from(rows.len()).ok().and_then(RowId::new).ok_or(Halt::IndexOverflow { at })
}

/// The arena length as a run bound: every id was minted through
/// the [`RowId`] judgment, so the length always fits.
#[allow(clippy::as_conversions, reason = "row minting judged every id, bounding the length")]
const fn arena_end(rows: &[Row]) -> u32 {
    rows.len() as u32
}

/// Books one scanned row into the arena, linking the chain.
/// Groups arrive with a vacant word role and no delimiter width —
/// their close patches the banked end and the end tag's met width.
#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are one row's columns, spelled once at the one mint"
)]
fn push_row<E>(
    rows: &mut Vec<Row>,
    chain: &mut Chain,
    parent: Option<RowId>,
    zone: ScanZone,
    at: u64,
    field: FieldNumber,
    kind: RecordKind,
    tag_width: WordWidth,
    len_or_met: PayloadLenOrValueWidth,
    delim_width: Option<WordWidth>,
    word: u64,
) -> Result<(), Halt<E>> {
    let id = mint_row(rows, at)?;
    // The reservation in `mint_row` covers this push.
    rows.push(Row {
        at: Some(zone.at(at)),
        edit: Edit::Intact,
        word_or_end: match kind {
            RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => {
                ScalarWordOrGroupEnd::scalar(kind, word)
            }
            RecordKind::Len | RecordKind::Group => ScalarWordOrGroupEnd::vacant(),
        },
        field,
        len_or_met,
        parent,
        next: None,
        kids: NO_CHILD,
        kind,
        flags: match zone {
            ScanZone::Source => 0,
            ScanZone::Authored { .. } => FLAG_AUTHORED,
        },
        tag_width: Some(tag_width),
        delim_width,
    });
    match chain.prev {
        Some(prev) => rows[prev.index()].next = Some(id),
        None => chain.first = Some(id),
    }
    chain.prev = Some(id);
    Ok(())
}

/// Scans one layer at the pump's position into the row arena —
/// walking group interiors transparently (their frames live on a
/// fallible stack, and every group publishes its own layer at the
/// open tag) — returning the outermost chain's anchors.
///
/// `extent` is `None` for the open walk (the root layer: the
/// walk's own end closes it, and a mid-construct end is the
/// document's truncation) and the measured payload end for the
/// descend walks (a walk end before it is a tear — the open walk
/// proved those bytes; over a resident authored zone the tear arm
/// is unreachable). The pump's zone must equal the extent's end
/// (the root: the sentinel) — groups declare no extent and never
/// move it. On any halt the caller discards the provisional rows
/// and layers; nothing here touches published state.
#[allow(
    clippy::too_many_lines,
    reason = "one dispatch site per wire construct; splitting it would scatter the \
              refusal coordinates the arms share"
)]
fn scan_layer<W: ReplayWalk>(
    pump: &mut Pump<W>,
    rows: &mut Vec<Row>,
    layers: &mut Vec<Layer>,
    zone: ScanZone,
    outer_parent: Option<RowId>,
    extent: Option<u64>,
) -> Result<Chain, Halt<W::Error>> {
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
        let Some(&(gid, _)) = stack.last() else { unreachable!("judged only with frames open") };
        Halt::Wire(Fault {
            at: zone.fault_at(at),
            kind: FaultKind::GroupUnclosed { open: rows[gid.index()].field },
        })
    };
    loop {
        if let Some(end) = extent
            && pump.off == end
        {
            if !stack.is_empty() {
                return Err(unclosed(rows, &stack, pump.off));
            }
            return Ok(chain);
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
                    return Ok(chain);
                }
                // A sealed extent's walk cannot end cleanly before
                // the seal: the open walk measured bytes here.
                return Err(Halt::Torn { at: pump.off });
            }
            StepRead::SealCut => {
                return Err(Halt::Wire(Fault {
                    at: zone.fault_at(pump.off),
                    kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SealCut },
                }));
            }
            StepRead::SourceEnd => {
                return Err(cut_end(
                    pump,
                    Fault {
                        at: zone.fault_at(pump.off),
                        kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::SourceEnd },
                    },
                ));
            }
            StepRead::TooWide => {
                let start = pump.construct_start();
                return Err(Halt::Wire(Fault {
                    at: zone.fault_at(start),
                    kind: FaultKind::Read { stage: Stage::Tag, cause: ReadFault::TooWide },
                }));
            }
            StepRead::OutOfClass => {
                let start = pump.construct_start();
                return Err(Halt::Wire(Fault {
                    at: zone.fault_at(start),
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
            return Err(Halt::Wire(Fault {
                at: zone.fault_at(at),
                kind: FaultKind::FieldZero { code: low3 },
            }));
        };
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                let after_tag = pump.off;
                let (value, width) = match pump.step_value(Standard::Tolerant) {
                    StepRead::Done { value, width } => (value, width),
                    StepRead::SealCut => {
                        return Err(Halt::Wire(Fault {
                            at: zone.fault_at(pump.off),
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
                                at: zone.fault_at(pump.off),
                                kind: FaultKind::Read {
                                    stage: Stage::Value { field },
                                    cause: ReadFault::SourceEnd,
                                },
                            },
                        ));
                    }
                    StepRead::TooWide => {
                        return Err(Halt::Wire(Fault {
                            at: zone.fault_at(after_tag),
                            kind: FaultKind::Read {
                                stage: Stage::Value { field },
                                cause: ReadFault::TooWide,
                            },
                        }));
                    }
                    StepRead::OutOfClass => {
                        return Err(Halt::Wire(Fault {
                            at: zone.fault_at(after_tag),
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
                    zone,
                    at,
                    field,
                    RecordKind::Varint,
                    tag_width,
                    PayloadLenOrValueWidth::met(RecordKind::Varint, width),
                    None,
                    value,
                )?;
            }
            TagClass::Record(kind @ (RecordKind::I64 | RecordKind::I32)) => {
                let needed: u8 = if matches!(kind, RecordKind::I64) { 8 } else { 4 };
                let after_tag = pump.off;
                if pump.zone - pump.off < u64::from(needed) {
                    return Err(Halt::Wire(Fault {
                        at: zone.fault_at(after_tag),
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
                        Fault {
                            at: zone.fault_at(after_tag),
                            kind: FaultKind::FixedTruncated { field, needed },
                        },
                    ));
                };
                push_row(
                    rows,
                    &mut chain,
                    parent,
                    zone,
                    at,
                    field,
                    kind,
                    tag_width,
                    PayloadLenOrValueWidth::vacant(),
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
                            at: zone.fault_at(pump.off),
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
                                at: zone.fault_at(pump.off),
                                kind: FaultKind::Read {
                                    stage: Stage::LenPrefix { field },
                                    cause: ReadFault::SourceEnd,
                                },
                            },
                        ));
                    }
                    StepRead::TooWide => {
                        return Err(Halt::Wire(Fault {
                            at: zone.fault_at(after_tag),
                            kind: FaultKind::Read {
                                stage: Stage::LenPrefix { field },
                                cause: ReadFault::TooWide,
                            },
                        }));
                    }
                    StepRead::OutOfClass => {
                        return Err(Halt::Wire(Fault {
                            at: zone.fault_at(after_tag),
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
                            at: zone.fault_at(at),
                            kind: FaultKind::LenUnsatisfiable { field, declared },
                        }));
                    }
                } else if declared64 > pump.zone - pump.off {
                    let zone_left = pump.zone - pump.off;
                    return Err(Halt::Wire(Fault {
                        at: zone.fault_at(after_tag),
                        kind: FaultKind::LenOverrun { field, declared, zone_left },
                    }));
                }
                push_row(
                    rows,
                    &mut chain,
                    parent,
                    zone,
                    at,
                    field,
                    RecordKind::Len,
                    tag_width,
                    PayloadLenOrValueWidth::len(RecordKind::Len, declared),
                    Some(prefix_width),
                    0,
                )?;
                // The payload stays opaque here: skipped, never
                // lent. A short skip is the zone ending inside the
                // declared extent.
                match pump.skip_bytes(declared64) {
                    Ok(advanced) if advanced == declared64 => {}
                    Ok(advanced) => {
                        return Err(cut_end(
                            pump,
                            Fault {
                                at: zone.fault_at(after_tag),
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
                push_row(
                    rows,
                    &mut chain,
                    parent,
                    zone,
                    at,
                    field,
                    RecordKind::Group,
                    tag_width,
                    PayloadLenOrValueWidth::vacant(),
                    None,
                    0,
                )?;
                let Some(gid) = chain.prev else { unreachable!("push_row just linked this row") };
                // Every group publishes its own layer at the open
                // tag, so insertion anchors exist the moment the
                // group is browsable; the anchors patch at the
                // close.
                layers.try_reserve(1).map_err(halt_resource)?;
                let layer = match u32::try_from(layers.len()).ok().and_then(LayerId::new) {
                    Some(layer) => layer,
                    None => return Err(Halt::IndexOverflow { at }),
                };
                layers.push(Layer::empty(zone.layer_zone(None)));
                rows[gid.index()].set_slot(Slot::Opened(layer));
                // Suspend the outer chain; the interior scans as
                // part of this same walk, its frame on a fallible
                // stack with no declared bound.
                stack.try_reserve(1).map_err(halt_resource)?;
                stack
                    .push((gid, core::mem::replace(&mut chain, Chain { first: None, prev: None })));
                parent = Some(gid);
            }
            TagClass::GroupEnd => {
                let Some((gid, outer)) = stack.pop() else {
                    return Err(Halt::Wire(Fault {
                        at: zone.fault_at(at),
                        kind: FaultKind::GroupEndOrphan { found: field },
                    }));
                };
                let open_field = rows[gid.index()].field;
                if open_field != field {
                    return Err(Halt::Wire(Fault {
                        at: zone.fault_at(at),
                        kind: FaultKind::GroupEndMismatch { open: open_field, found: field },
                    }));
                }
                // The close patches the row's banked end (one past
                // the end tag) and the end tag's met width, then
                // seals the interior chain into the group's layer.
                let group_layer = match rows[gid.index()].slot() {
                    Slot::Opened(layer) => layer,
                    // The open tag published the layer.
                    Slot::Unopened | Slot::Fault(_) => {
                        unreachable!("the scan publishes a layer with every group push")
                    }
                };
                let row = &mut rows[gid.index()];
                row.word_or_end =
                    ScalarWordOrGroupEnd::group_end(RecordKind::Group, zone.at(pump.off));
                row.delim_width = Some(tag_width);
                parent = row.parent;
                layers[group_layer.index()].first = chain.first;
                layers[group_layer.index()].last = chain.prev;
                chain = outer;
            }
            TagClass::Unassigned => {
                return Err(Halt::Wire(Fault {
                    at: zone.fault_at(at),
                    kind: FaultKind::Unassigned { field, code: low3 },
                }));
            }
        }
    }
}

/// One fetch walk over one measured source extent: begin, seek,
/// deliver.
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

// ─── the machine (shared helpers) ───

#[cold]
const fn edit_resource(_refused: TryReserveError) -> EditFault {
    EditFault::Resource
}

#[cold]
const fn edit_store_fault(fault: StoreFault) -> EditFault {
    match fault {
        StoreFault::Resource => EditFault::Resource,
        StoreFault::Exhausted => EditFault::IndexSpaceExhausted,
    }
}

#[cold]
const fn save_alloc<E>(_refused: TryReserveError) -> SaveFault<E> {
    SaveFault::Resource
}

/// Maps a resident authored parse's halt onto the walk-free door
/// alphabet: wire refusals park (the caller's business), and the
/// walk-shaped arms are unreachable over resident bytes.
#[cold]
fn authored_halt(halt: Halt<crate::replay_source::SliceFault>) -> Result<Fault, EditFault> {
    match halt {
        Halt::Wire(fault) => Ok(fault),
        Halt::Resource => Err(EditFault::Resource),
        Halt::IndexOverflow { .. } => Err(EditFault::IndexSpaceExhausted),
        // A resident zone cannot tear, refuse, or outrun the
        // coordinate space: its bytes are whole in memory and its
        // end was admitted against the length class.
        Halt::Source(_) | Halt::Torn { .. } | Halt::OffsetExhausted { .. } => {
            unreachable!("resident zones cannot tear or refuse")
        }
    }
}

/// The arena gate: forged handles (coordinates the editor never
/// minted) panic right here on the index bound.
#[track_caller]
const fn gate(rows: &[Row], handle: Handle) -> &Row {
    &rows[handle.0.index()]
}

/// Registers a resident verdict and seals the slot — spelled over
/// the fields so a mounted walk can park beside its own borrow of
/// the source.
#[cold]
fn park_in(
    rows: &mut [Row],
    faults: &mut Vec<Fault>,
    id: RowId,
    fault: Fault,
) -> Result<u32, EditFault> {
    faults.try_reserve(1).map_err(edit_resource)?;
    let index = u32::try_from(faults.len()).map_err(|_| EditFault::IndexSpaceExhausted)?;
    faults.push(fault);
    rows[id.index()].set_slot(Slot::Fault(index));
    Ok(index)
}

/// Publishes a freshly scanned interior — spelled over the fields
/// so a mounted walk can seal beside its own borrow of the
/// source: mints the source run (source scans of non-empty layers
/// only) and the layer descriptor, then seals the slot last — an
/// `Err` from either reservation leaves the container unopened,
/// and the caller discards the provisional tables.
fn seal_scan_in(
    rows: &mut [Row],
    layers: &mut Vec<Layer>,
    source_runs: &mut Vec<SourceRun>,
    id: RowId,
    first: Option<RowId>,
    last: Option<RowId>,
    zone: ScanZone,
) -> Result<(), EditFault> {
    let run = match (zone, first) {
        (ScanZone::Source, Some(run_first)) => {
            source_runs.try_reserve(1).map_err(edit_resource)?;
            let run = u32::try_from(source_runs.len())
                .ok()
                .and_then(SourceRunId::new)
                .ok_or(EditFault::IndexSpaceExhausted)?;
            source_runs.push(SourceRun { first: run_first, end: arena_end(rows) });
            Some(run)
        }
        _ => None,
    };
    // A later refusal retires the run minted above: the seal
    // publishes whole or not at all.
    let unwind_run = |source_runs: &mut Vec<SourceRun>, fault: EditFault| {
        if run.is_some() {
            source_runs.pop();
        }
        fault
    };
    if let Err(refused) = layers.try_reserve(1) {
        return Err(unwind_run(source_runs, edit_resource(refused)));
    }
    let Some(layer) = u32::try_from(layers.len()).ok().and_then(LayerId::new) else {
        return Err(unwind_run(source_runs, EditFault::IndexSpaceExhausted));
    };
    layers.push(Layer { first, last, dirty_kids: 0, history_kids: 0, zone: zone.layer_zone(run) });
    rows[id.index()].set_slot(Slot::Opened(layer));
    Ok(())
}

/// A live witness for scalar value commands: the gated row is
/// neither dead, authored-backed, shrouded, nor of another kind —
/// the carried state is everything a setter may transition from.
#[derive(Clone, Copy)]
enum LiveEdit {
    Virgin,
    Replaced,
    Inserted,
}

impl LiveEdit {
    /// The state a fresh scalar store value transitions this
    /// witness to.
    const fn set(self, value: ValueAt) -> Edit {
        match self {
            Self::Virgin | Self::Replaced => Edit::Replaced(value),
            Self::Inserted => Edit::Inserted(value),
        }
    }
}

/// A live witness for payload commands — [`LiveEdit`]'s sibling
/// over the payload-backed states.
#[derive(Clone, Copy)]
enum LivePayload {
    Virgin,
    Replaced,
    Inserted,
}

impl LivePayload {
    /// The state a fresh authored slot transitions this witness
    /// to.
    const fn set(self, slot: SlotAt) -> Edit {
        match self {
            Self::Virgin | Self::Replaced => Edit::ReplacedPayload(slot),
            Self::Inserted => Edit::InsertedPayload(slot),
        }
    }
}

/// An insertion's resolved splice point, proven before anything is
/// occupied: the parent is an open container and the predecessor
/// is a live chain member.
#[derive(Clone, Copy)]
struct InsertPlan {
    parent: Option<RowId>,
    prev: Option<RowId>,
}

// ─── the save walks (shared shapes) ───

/// An authored scalar value headed for the output, its emission
/// width priced once.
#[derive(Clone, Copy)]
enum Word {
    /// A varint word, emitted minimally.
    Varint(u64),
    /// Four little-endian bytes.
    Bits32(u32),
    /// Eight little-endian bytes.
    Bits64(u64),
}

impl Word {
    /// The value's emission width in bytes.
    const fn width(self) -> u64 {
        match self {
            Self::Varint(word) => encoded_len64(word) as u64,
            Self::Bits32(_) => 4,
            Self::Bits64(_) => 8,
        }
    }
}

/// A banked scanned scalar, resolved for canonical emission.
#[allow(
    clippy::cast_possible_truncation,
    clippy::as_conversions,
    reason = "an I32 row's banked word holds four bytes' bits, so it fits u32"
)]
const fn banked_word(kind: RecordKind, word: u64) -> Word {
    match kind {
        RecordKind::Varint => Word::Varint(word),
        RecordKind::I32 => Word::Bits32(word as u32),
        RecordKind::I64 => Word::Bits64(word),
        // The callers' kind dispatch keeps container rows out.
        RecordKind::Len | RecordKind::Group => unreachable!(),
    }
}

/// The save passes' verdict for one row, every value resolved at
/// judgment time so no pass re-derives anything. The Re arms are
/// the fidelity contract's letter: a replaced record keeps its
/// source tag bytes verbatim, and a LEN prefix rides verbatim
/// while its body length is unchanged. Windows are whole-source
/// coordinates derived from the row's stored met widths.
enum Arm {
    /// Shrouded or ghost: the source extent (if any) is sought
    /// past.
    Skip {
        /// The span end for scanned rows; `None` for ghosts,
        /// which own no source extent.
        end: Option<u64>,
    },
    /// A clean scanned subtree: copied verbatim from the source.
    Clean {
        /// The whole-span end.
        end: u64,
    },
    /// A replaced scalar: source tag verbatim, then the value.
    ReValue {
        /// End of the verbatim tag window.
        tag_end: u64,
        /// The scanned span's end, sought past.
        span_end: u64,
        /// The store value.
        value: Word,
    },
    /// An authored scalar: minimal head, then the value.
    NewValue {
        /// The minimal head word.
        head: u32,
        /// The store value.
        value: Word,
    },
    /// A replaced LEN: source tag verbatim; the prefix rides
    /// verbatim iff the authored payload keeps the source length.
    ReBody {
        /// End of the verbatim tag window.
        tag_end: u64,
        /// End of the source prefix window.
        prefix_end: u64,
        /// The source body length (the verbatim criterion).
        src_len: u64,
        /// The authored slot.
        slot: SlotAt,
        /// The scanned span's end, sought past.
        span_end: u64,
    },
    /// An authored LEN: minimal head, prefix, payload.
    NewBody {
        /// The minimal head word.
        head: u32,
        /// The authored slot.
        slot: SlotAt,
    },
    /// A source-framed LEN with an edited interior: recurse; the
    /// prefix rides verbatim iff the interior lands back on the
    /// source length.
    Spine {
        /// End of the verbatim tag window.
        tag_end: u64,
        /// End of the source prefix window.
        prefix_end: u64,
        /// The source body length (the verbatim criterion).
        src_len: u64,
        /// First record of the interior chain.
        first: Option<RowId>,
    },
    /// A scanned group with an edited interior: both framing tags
    /// ride verbatim (the close re-derives its window from the
    /// row's banked end); recurse.
    ReGroup {
        /// End of the verbatim start-tag window.
        tag_end: u64,
        /// First record of the interior chain.
        first: Option<RowId>,
    },
    /// An authored group: minimal start and end tags; recurse.
    NewGroup {
        /// The minimal start-tag word.
        head: u32,
        /// The minimal end-tag word.
        end_word: u32,
        /// First record of the interior chain.
        first: Option<RowId>,
    },
}

/// One frame of the size pass's container spine: a LEN prices a
/// body slot against its declared length, a group only restores
/// the enclosing accumulator around its priced framing tags.
enum SizeFrame {
    /// An opened LEN with an edited interior.
    Len {
        /// Where the walk resumes after the close.
        next: Option<RowId>,
        /// The enclosing accumulator, restored at close.
        outer: u64,
        /// The body's slot in the size table.
        slot: usize,
        /// The source prefix's met width (the verbatim candidate).
        prefix_w: WordWidth,
        /// The source body length (the verbatim criterion).
        src_len: u64,
        /// Whole-source tag offset, for the over-cap fault.
        at: u64,
        /// The met tag width (the tag rides verbatim).
        tag_w: WordWidth,
    },
    /// A group container (scanned or authored).
    Group {
        /// Where the walk resumes after the close.
        next: Option<RowId>,
        /// The enclosing accumulator, restored at close.
        outer: u64,
        /// Both framing tags' widths, priced at the open.
        framing: u64,
    },
}

/// The canonical walk's verdict for one row, every value resolved
/// at judgment time. Stored widths are not output widths here —
/// they remain the source-geometry proof that locates each opaque
/// payload.
enum CanonicalArm {
    /// Shrouded or ghost: contributes nothing.
    Skip,
    /// A scalar record: minimal head, the banked or stored value.
    Value {
        /// The minimal head word.
        head: u32,
        /// The value, from the row bank or the store.
        value: Word,
    },
    /// A LEN whose payload is an opaque declaration: minimal
    /// framing, the payload bytes unchanged.
    OpaqueLen {
        /// The minimal head word.
        head: u32,
        /// Where the payload bytes live.
        payload: CanonicalPayload,
    },
    /// An opened LEN: minimal framing over the re-priced
    /// interior.
    OpenLen {
        /// The minimal head word.
        head: u32,
        /// First record of the interior chain.
        first: Option<RowId>,
        /// Whole-source tag offset, for the over-cap fault.
        at: u64,
    },
    /// A group container: a minimal start tag over the re-priced
    /// interior (the close re-derives the end tag from the row).
    OpenGroup {
        /// The minimal start-tag word.
        head: u32,
        /// First record of the interior chain.
        first: Option<RowId>,
    },
}

/// Where an opaque canonical payload's bytes live.
enum CanonicalPayload {
    /// A scanned source extent, copied through the walk.
    Doc {
        /// The payload extent's start.
        at: u64,
        /// The payload extent's length.
        len: u64,
    },
    /// An authored slot, emitted from the store.
    Store(SlotAt),
}

/// Books the fidelity save's whole step program over one settled
/// tree in a single walk; `$book` maps each booking face onto the
/// per-edge fallible booking sink, keeping the walk text apart
/// from the funding faces. Opened LENs ride prefix slots: the
/// close settles each one against the interior the script booked
/// beneath it, so no sizing pass precedes the booking.
macro_rules! book_fidelity {
    ($self:ident, $script:ident, $lens:ident, $book:ident) => {{
        let mut open: Option<RowId> = None;
        let mut cur = $self.root.first;
        loop {
            let Some(id) = cur else {
                let Some(container) = open else { break };
                let row = $self.row(container);
                // A container's close books here, where its
                // interior has finished. A group: the scanned end
                // tag rides verbatim, the authored one emits
                // minimally (only live groups open as save
                // containers). An opened LEN: its prefix slot
                // settles against the booked interior.
                if matches!(row.kind, RecordKind::Group) {
                    match row.edit {
                        Edit::Intact => {
                            // SAFETY: Intact is outside the
                            // Inserted families.
                            let at = unsafe { scanned_at(row) };
                            $book!(copy_to, row.span_end(at));
                        }
                        Edit::Inserted(_) => {
                            $book!(stage_word, u64::from(group_end_word(row.field)));
                        }
                        _ => unreachable!("only live groups open as save containers"),
                    }
                } else {
                    let Some((slot, mark, declared)) = $lens.pop() else {
                        unreachable!("every opened LEN pushed its prefix slot")
                    };
                    let interior = $script.out_len() - mark;
                    if $script.settle_prefix(slot, interior, declared).is_err() {
                        // SAFETY: spines settle scanned rows alone.
                        let at = unsafe { scanned_at(row) }.as_inner();
                        return Err(SaveFault::BodyOverCap { at });
                    }
                }
                cur = row.next;
                open = row.parent;
                continue;
            };
            let row = $self.row(id);
            match $self.settle(row) {
                Arm::Skip { end } => {
                    if let Some(end) = end {
                        $book!(skip_to, end);
                    }
                }
                Arm::Clean { end } => {
                    $book!(copy_to, end);
                }
                Arm::ReValue { tag_end, span_end, value } => {
                    $book!(copy_to, tag_end);
                    $book!(value, value);
                    $book!(skip_to, span_end);
                }
                Arm::NewValue { head, value } => {
                    $book!(stage_word, u64::from(head));
                    $book!(value, value);
                }
                Arm::ReBody { tag_end, prefix_end, src_len, slot, span_end } => {
                    $book!(copy_to, tag_end);
                    let bytes = $self.store.zone_bytes(slot);
                    #[allow(
                        clippy::as_conversions,
                        reason = "authored payload lengths were admitted to the length \
                                  class, which fits u64"
                    )]
                    let len = bytes.len() as u64;
                    if len == src_len {
                        $book!(copy_to, prefix_end);
                    } else {
                        $book!(skip_to, prefix_end);
                        $book!(stage_word, len);
                    }
                    $book!(borrow, bytes);
                    $book!(skip_to, span_end);
                }
                Arm::NewBody { head, slot } => {
                    $book!(stage_word, u64::from(head));
                    let bytes = $self.store.zone_bytes(slot);
                    #[allow(
                        clippy::as_conversions,
                        reason = "authored payload lengths were admitted to the length \
                                  class, which fits u64"
                    )]
                    {
                        $book!(stage_word, bytes.len() as u64);
                    }
                    $book!(borrow, bytes);
                }
                Arm::Spine { tag_end, prefix_end, src_len, first } => {
                    $book!(copy_to, tag_end);
                    $lens.try_reserve(1).map_err(save_alloc)?;
                    let slot = $book!(open_prefix, tag_end, prefix_end);
                    $lens.push((slot, $script.out_len(), src_len));
                    open = Some(id);
                    cur = first;
                    continue;
                }
                Arm::ReGroup { tag_end, first, .. } => {
                    $book!(copy_to, tag_end);
                    open = Some(id);
                    cur = first;
                    continue;
                }
                Arm::NewGroup { head, first, .. } => {
                    $book!(stage_word, u64::from(head));
                    open = Some(id);
                    cur = first;
                    continue;
                }
            }
            cur = row.next;
        }
        // The emission walk must meet the source's end exactly at
        // the measured total for the fold's end probe; trailing
        // shrouded extents seek there (a no-op when the last step
        // already landed on it).
        $book!(skip_to, $self.total.as_inner());
        debug_assert!($lens.is_empty(), "every opened LEN settled its prefix slot");
    }};
}

/// Books the canonical save's whole step program in a single walk
/// — the fidelity walk's twin over [`CanonicalArm`], booked
/// through the same per-edge sink. Opened LENs ride minted prefix
/// slots (canonical prefixes always re-author), settled at each
/// close against the booked interior.
macro_rules! book_canonical {
    ($self:ident, $script:ident, $lens:ident, $book:ident) => {{
        let mut open: Option<RowId> = None;
        let mut cur = $self.root.first;
        loop {
            let Some(id) = cur else {
                let Some(container) = open else { break };
                let row = $self.row(container);
                // A container's close books here. A group:
                // canonical output re-emits the end tag minimally
                // whatever the scan met. An opened LEN: its minted
                // prefix slot settles against the booked interior.
                if matches!(row.kind, RecordKind::Group) {
                    $book!(stage_word, u64::from(group_end_word(row.field)));
                } else {
                    let Some((slot, mark, at)) = $lens.pop() else {
                        unreachable!("every opened LEN pushed its prefix slot")
                    };
                    let interior = $script.out_len() - mark;
                    if $script.settle_minted_prefix(slot, interior).is_err() {
                        return Err(SaveFault::BodyOverCap { at });
                    }
                }
                cur = row.next;
                open = row.parent;
                continue;
            };
            let row = $self.row(id);
            match $self.settle_canonical(row) {
                CanonicalArm::Skip => {}
                CanonicalArm::Value { head, value } => {
                    $book!(stage_word, u64::from(head));
                    $book!(value, value);
                }
                CanonicalArm::OpaqueLen { head, payload } => {
                    $book!(stage_word, u64::from(head));
                    match payload {
                        CanonicalPayload::Doc { at, len } => {
                            $book!(stage_word, len);
                            $book!(skip_to, at);
                            $book!(copy_to, at + len);
                        }
                        CanonicalPayload::Store(slot) => {
                            let bytes = $self.store.zone_bytes(slot);
                            #[allow(
                                clippy::as_conversions,
                                reason = "authored payload lengths were admitted to the \
                                          length class, which fits u64"
                            )]
                            {
                                $book!(stage_word, bytes.len() as u64);
                            }
                            $book!(borrow, bytes);
                        }
                    }
                }
                CanonicalArm::OpenLen { head, first, at } => {
                    $book!(stage_word, u64::from(head));
                    $lens.try_reserve(1).map_err(save_alloc)?;
                    let slot = $book!(open_minted_prefix);
                    $lens.push((slot, $script.out_len(), at));
                    open = Some(id);
                    cur = first;
                    continue;
                }
                CanonicalArm::OpenGroup { head, first, .. } => {
                    $book!(stage_word, u64::from(head));
                    open = Some(id);
                    cur = first;
                    continue;
                }
            }
            cur = row.next;
        }
        // Seek to the measured total for the fold's end probe.
        $book!(skip_to, $self.total.as_inner());
        debug_assert!($lens.is_empty(), "every opened LEN settled its prefix slot");
    }};
}

/// The save walks' read-only view over the edit state: rows,
/// chain anchors, layers, the store, and the measured total —
/// everything the sizing and booking walks read, with the source
/// handle left outside so the emission walk can borrow it beside
/// the compiled script. Declared once; each store form carries its
/// own concrete impl.
struct SaveView<'a, St> {
    rows: &'a [Row],
    root: &'a Layer,
    layers: &'a [Layer],
    store: &'a St,
    total: SourceAt,
}

/// One save view over a machine's fields, spelled as disjoint
/// field borrows so the source handle stays free for the fold.
macro_rules! save_view {
    ($self:ident) => {
        SaveView {
            rows: &$self.rows,
            root: &$self.root,
            layers: &$self.layers,
            store: &$self.store,
            total: $self.total,
        }
    };
}

/// Where a payload byte question is answered: the store (an
/// authored slot, or a scanned extent inside one), or the walked
/// source.
enum PayloadAnswer {
    /// Resident bytes: an extent of one authored slot's zone.
    Resident {
        /// The backing slot.
        slot: SlotAt,
        /// The extent's start in the slot's zone.
        start: u32,
        /// The extent's byte length.
        len: u32,
    },
    /// A measured source extent: one fetch walk.
    Scanned {
        /// The payload extent, whole-source.
        span: SourceSpan,
    },
}

/// Emits one maintain machine form: the struct (its store form is
/// the parameter) and the whole face set — doors, observation,
/// descend and materialize, fetch, commands, revision, and the
/// two-pass saves. The payload-command faces ride the `@payload`
/// arms below, selected per form.
macro_rules! maintain_machine {
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident $(<$plt:lifetime>)?,
        store: $Store:ty,
        pay: $pay:ident,
        door: $door:literal $(,)?
    ) => {
        $(#[$mdoc])*
        pub struct $Machine<$($plt,)? S: StableReplaySource> {
            source: S,
            /// The one-past-end coordinate the open walk
            /// established; only the save folds read it (their end
            /// probe anchors the measured total against a grown
            /// source).
            total: SourceAt,
            rows: Vec<Row>,
            store: $Store,
            /// Parked descend verdicts, both zones.
            faults: Vec<Fault>,
            log: Vec<Transition>,
            /// The top layer's descriptor: chain anchors, aggregate
            /// counts, and the root source run.
            root: Layer,
            /// Interior-layer descriptors, minted at descend (and,
            /// for authored interiors, at their resident parse).
            layers: Vec<Layer>,
            /// Bisectable row ranges, one per source scan.
            source_runs: Vec<SourceRun>,
        }

        impl<$($plt,)? S: StableReplaySource> $Machine<$($plt,)? S> {
            // ── opening ──

            /// Takes tenure of `source` and scans its top layer in
            /// one walk — LEN payloads stay opaque declarations,
            /// skipped through the supply's own seek — measuring
            /// the source's total length. An unlawful root layer
            /// refuses whole; the source rides back beside the
            /// mark. No depth argument: descent is caller-stepped
            /// and every scan is iterative.
            ///
            /// # Errors
            ///
            /// `(source, OpenFault)` — the source beside the mark —
            /// when the root layer is unlawful, the supply refuses
            /// mid-walk, the record count would leave the row-index
            /// class, the offset would leave the coordinate space,
            /// or the allocator refuses the working storage.
            pub fn open(mut source: S) -> Result<Self, (S, OpenFault<S::Error>)> {
                let mut rows: Vec<Row> = Vec::new();
                let mut layers: Vec<Layer> = Vec::new();
                let outcome = match source.begin() {
                    Ok(walk) => {
                        let mut pump = Pump::new(walk);
                        scan_layer(&mut pump, &mut rows, &mut layers, ScanZone::Source, None, None)
                            .map(|chain| (chain, pump.off))
                    }
                    Err(fault) => Err(Halt::Source(ReplayFault::Rewind {
                        phase: ReplayPhase::Index,
                        source: fault,
                    })),
                };
                match outcome {
                    Ok((chain, total)) => {
                        let mut source_runs = Vec::new();
                        let run = match chain.first {
                            Some(first) => {
                                if source_runs.try_reserve(1).is_err() {
                                    return Err((source, OpenFault::Resource));
                                }
                                source_runs.push(SourceRun { first, end: arena_end(&rows) });
                                Some(SourceRunId::MIN)
                            }
                            None => None,
                        };
                        // SAFETY: the pump's per-view admission
                        // keeps every walk position at most
                        // `u64::MAX − 1`.
                        let total = unsafe { SourceAt::new_unchecked(total) };
                        Ok(Self {
                            source,
                            total,
                            rows,
                            store: <$Store>::new(),
                            faults: Vec::new(),
                            log: Vec::new(),
                            root: Layer {
                                first: chain.first,
                                last: chain.prev,
                                dirty_kids: 0,
                                history_kids: 0,
                                zone: Zone::Source { run },
                            },
                            layers,
                            source_runs,
                        })
                    }
                    Err(halt) => {
                        let fault = match halt {
                            Halt::Wire(fault) => OpenFault::Wire(fault),
                            Halt::Source(fault) => OpenFault::Source(fault),
                            // The open walk measures: a walk end is
                            // a document property (truncation),
                            // never a tear.
                            Halt::Torn { .. } => {
                                unreachable!("the measuring walk has no earlier anchor")
                            }
                            Halt::IndexOverflow { at } => OpenFault::IndexOverflow { at },
                            Halt::OffsetExhausted { at } => OpenFault::OffsetExhausted { at },
                            Halt::Resource => OpenFault::Resource,
                        };
                        Err((source, fault))
                    }
                }
            }

            /// Releases the source handle. The rows, stores, and
            /// revision log are dropped; spans taken earlier remain
            /// plain numbers over the source's byte sequence.
            #[inline]
            #[must_use]
            pub fn into_source(self) -> S {
                self.source
            }

            /// The measured total source length (the open walk's
            /// end).
            #[inline]
            #[must_use]
            pub const fn source_len(&self) -> u64 {
                self.total.as_inner()
            }

            // ── internal row access ──

            /// A gated row by coordinate (every public entry gates
            /// first).
            fn row(&self, id: RowId) -> &Row {
                // SAFETY: `id` was gated or minted by this machine,
                // and the arena never shrinks below a live
                // coordinate.
                unsafe { self.rows.get_unchecked(id.index()) }
            }

            #[doc = concat!(" Mutable twin of [`", stringify!($Machine), "::row`].")]
            fn row_mut(&mut self, id: RowId) -> &mut Row {
                // SAFETY: as the shared accessor.
                unsafe { self.rows.get_unchecked_mut(id.index()) }
            }

            /// A layer descriptor by minted coordinate.
            fn layer(&self, layer: LayerId) -> &Layer {
                // SAFETY: `layer` was minted by this machine, and
                // the layer table never shrinks.
                unsafe { self.layers.get_unchecked(layer.index()) }
            }

            /// The first row of a slot's layer (`None` unless
            /// opened).
            fn slot_first(&self, slot: Slot) -> Option<RowId> {
                match slot {
                    Slot::Opened(layer) => self.layer(layer).first,
                    Slot::Unopened | Slot::Fault(_) => None,
                }
            }

            /// The layer that directly holds a row with this
            /// parent: the parent's opened layer, or the root
            /// descriptor for top-level rows. Live rows always sit
            /// in a materialized layer — LEN interiors publish
            /// theirs at descend, and a re-sealed container orphans
            /// its whole subtree first.
            fn holding_layer(&self, parent: Option<RowId>) -> &Layer {
                parent.map_or(&self.root, |id| match self.row(id).slot() {
                    Slot::Opened(layer) => self.layer(layer),
                    // SAFETY: live rows sit in materialized layers —
                    // dead rows are refused upstream, and a
                    // re-sealing container orphans its whole subtree
                    // before unsealing the slot.
                    Slot::Unopened | Slot::Fault(_) => unsafe {
                        debug_assert!(false, "live rows sit in materialized layers");
                        core::hint::unreachable_unchecked()
                    },
                })
            }

            #[doc = concat!(" Mutable twin of [`", stringify!($Machine), "::holding_layer`].")]
            fn holding_layer_mut(&mut self, parent: Option<RowId>) -> &mut Layer {
                match parent {
                    Some(id) => match self.row(id).slot() {
                        Slot::Opened(layer) => {
                            // SAFETY: as the shared accessor.
                            unsafe { self.layers.get_unchecked_mut(layer.index()) }
                        }
                        // SAFETY: as the shared twin — live rows sit
                        // in materialized layers.
                        Slot::Unopened | Slot::Fault(_) => unsafe {
                            debug_assert!(false, "live rows sit in materialized layers");
                            core::hint::unreachable_unchecked()
                        },
                    },
                    None => &mut self.root,
                }
            }

            /// The authored slot whose zone holds a row minted
            /// under `parent` — the owning layer names the zone.
            fn zone_slot(&self, parent: Option<RowId>) -> SlotAt {
                match self.holding_layer(parent).zone {
                    Zone::Authored { slot } => slot,
                    // Authored-zone rows sit in authored layers by
                    // construction (the seal writes the zone).
                    Zone::Source { .. } => unreachable!("authored rows sit in authored layers"),
                }
            }

            /// Gates a handle and refuses orphaned rows.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the documented index contract).
            #[track_caller]
            fn live(&self, handle: Handle) -> Result<&Row, EditFault> {
                let row = gate(&self.rows, handle);
                if row.dead() { Err(EditFault::DeadHandle) } else { Ok(row) }
            }

            // ── observation ──

            /// Revision-log length: the number of revertible steps.
            #[inline]
            #[must_use]
            pub const fn pending(&self) -> usize {
                self.log.len()
            }

            /// The record's wire kind. Walk-free and
            /// source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn kind(&self, handle: Handle) -> Result<RecordKind, EditFault> {
                Ok(self.live(handle)?.kind)
            }

            /// The record's field number. Walk-free and
            /// source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn field(&self, handle: Handle) -> Result<FieldNumber, EditFault> {
                Ok(self.live(handle)?.field)
            }

            /// The record's edit status. Walk-free and
            /// source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn status(&self, handle: Handle) -> Result<EditStatus, EditFault> {
                Ok(match self.live(handle)?.edit {
                    Edit::Intact => EditStatus::Intact,
                    Edit::Replaced(_) | Edit::ReplacedPayload(_) => EditStatus::Replaced,
                    Edit::Deleted(_) | Edit::DeletedPayload(_) => EditStatus::Deleted,
                    Edit::Inserted(_) | Edit::InsertedPayload(_) => EditStatus::Inserted,
                    Edit::InsertedDeleted(_) | Edit::InsertedDeletedPayload(_) => {
                        EditStatus::InsertedDeleted
                    }
                })
            }

            /// True when the record's subtree carries any dirt — a
            #[doc = concat!(" subtree answer [`", stringify!($Machine), "::status`] cannot give.")]
            /// Walk-free and source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn dirty(&self, handle: Handle) -> Result<bool, EditFault> {
                Ok(self.live(handle)?.dirty())
            }

            /// The record's parent container, if any. Walk-free and
            /// source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn parent(&self, handle: Handle) -> Result<Option<Handle>, EditFault> {
                Ok(self.live(handle)?.parent.map(Handle))
            }

            /// The top layer, in wire order. Shrouded records and
            /// ghosts stay in the chain — presentation filters,
            /// topology does not.
            #[inline]
            pub fn top(&self) -> Children<'_> {
                Children { rows: &self.rows, cur: self.root.first }
            }

            /// The record's materialized children, in wire order
            /// (empty until a LEN is descended). Walk-free and
            /// source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn children(&self, handle: Handle) -> Result<Children<'_>, EditFault> {
                Ok(Children { rows: &self.rows, cur: self.slot_first(self.live(handle)?.slot()) })
            }

            /// The record's ancestor chain, innermost first.
            /// Walk-free and source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn ancestors(&self, handle: Handle) -> Result<Ancestors<'_>, EditFault> {
                Ok(Ancestors { rows: &self.rows, cur: self.live(handle)?.parent })
            }

            /// The record's whole source span in whole-source
            /// coordinates (`None` for command-authored rows and
            /// rows inside authored payloads — they own no hex).
            /// Walk-free and source-infallible; coordinates answer
            /// for the source bytes, not for any pending edit.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn span(&self, handle: Handle) -> Result<Option<SourceSpan>, EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Ok(None);
                }
                Ok(row.at.map(|at| SourceSpan::new(at.as_inner(), row.span_end(at))))
            }

            /// The record's source geometry: every segment in one
            /// kind-indexed answer (`None` for command-authored
            /// rows and rows inside authored payloads). Widths are
            /// the stored input facts — padded encodings reproduce
            /// byte-exactly. Walk-free and source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[track_caller]
            pub fn source_spans(&self, handle: Handle) -> Result<Option<RecordSpans>, EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Ok(None);
                }
                let Some(src) = row.at else {
                    return Ok(None);
                };
                let at = src.as_inner();
                let value_at = at + row.tag_w();
                let tag = SourceSpan::new(at, value_at);
                let end = row.span_end(src);
                Ok(Some(match row.kind {
                    RecordKind::Varint => {
                        RecordSpans::Varint { tag, value: SourceSpan::new(value_at, end) }
                    }
                    RecordKind::I32 => {
                        RecordSpans::I32 { tag, value: SourceSpan::new(value_at, end) }
                    }
                    RecordKind::I64 => {
                        RecordSpans::I64 { tag, value: SourceSpan::new(value_at, end) }
                    }
                    RecordKind::Len => {
                        let payload_at = value_at + row.delim_w();
                        RecordSpans::Len {
                            tag,
                            prefix: SourceSpan::new(value_at, payload_at),
                            payload: SourceSpan::new(payload_at, end),
                        }
                    }
                    RecordKind::Group => RecordSpans::Group {
                        tag,
                        interior: SourceSpan::new(value_at, end - row.delim_w()),
                        end_tag: SourceSpan::new(end - row.delim_w(), end),
                    },
                }))
            }

            /// The narrowest source-backed record whose span
            /// contains `pos` — the hex view's reverse index.
            /// Walk-free: each source run's rows ascend by offset,
            /// so a bisection lands on the latest-starting
            /// candidate, and an opened LEN chains into its
            /// interior's own run.
            #[inline]
            #[must_use]
            pub fn narrowest(&self, pos: u64) -> Option<Handle> {
                let Zone::Source { run: mut run } = self.root.zone else {
                    // The root layer is the walked source by
                    // construction.
                    unreachable!("the root layer is source-backed")
                };
                let mut best: Option<RowId> = None;
                while let Some(run_id) = run {
                    // SAFETY: `run_id` was minted by this machine,
                    // and the run table never shrinks.
                    let range = unsafe { self.source_runs.get_unchecked(run_id.index()) };
                    let Some(id) = self.bisect_run(range, pos) else { break };
                    let row = self.row(id);
                    // SAFETY: `id` is a run row.
                    if pos >= row.span_end(unsafe { run_at(row) }) {
                        // Past every candidate's start: the
                        // position sits in trailing group bytes —
                        // the innermost ancestor whose extent still
                        // covers it answers. The climb lands at
                        // worst on the run's own container, which
                        // provably covers `pos` at every interior
                        // level; only the root run can exhaust the
                        // chain.
                        let answer = self.climb_to_cover(id, pos);
                        debug_assert!(
                            best.is_none() || answer.is_some(),
                            "an interior climb found no covering ancestor"
                        );
                        return answer.map(Handle);
                    }
                    best = Some(id);
                    run = match row.slot() {
                        Slot::Opened(layer) => match self.layer(layer).zone {
                            Zone::Source { run } => run,
                            Zone::Authored { .. } => None,
                        },
                        Slot::Unopened | Slot::Fault(_) => None,
                    };
                }
                best.map(Handle)
            }

            /// The innermost ancestor of `id` whose extent covers
            /// `pos` (`None` when the chain exhausts — the
            /// position lies past the layer's content at the top
            /// level).
            fn climb_to_cover(&self, mut id: RowId, pos: u64) -> Option<RowId> {
                loop {
                    id = self.row(id).parent?;
                    let row = self.row(id);
                    // SAFETY: the climb starts on a run row and
                    // stays on its ancestors.
                    let at = unsafe { run_at(row) };
                    if at.as_inner() <= pos && pos < row.span_end(at) {
                        return Some(id);
                    }
                }
            }

            /// The latest-starting row of a run whose offset is at
            /// or before `pos` (`None` when every row starts past
            /// it). Run rows were minted by one source scan in
            /// strictly ascending offset order, which is the
            /// bisection's whole warrant.
            fn bisect_run(&self, range: &SourceRun, pos: u64) -> Option<RowId> {
                let mut lo = range.first.as_inner();
                let mut hi = range.end;
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    // SAFETY: `mid` is below the run's end, an arena
                    // index the run's scan minted.
                    let row = unsafe { self.rows.get_unchecked(usize_of(mid)) };
                    // SAFETY: `mid` is inside the run.
                    if unsafe { run_at(row) }.as_inner() <= pos {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                if lo == range.first.as_inner() {
                    return None;
                }
                // SAFETY: `lo - 1` is inside the run, whose every
                // index was minted through the `RowId` judgment.
                Some(unsafe { RowId::new_unchecked(lo - 1) })
            }

            /// The varint record's current word (the pending
            /// replacement if one is set, otherwise the banked
            /// scanned value). Row-resident: walk-free and
            /// source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the varint kind.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn varint_word(&self, handle: Handle) -> Result<u64, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::Varint) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(row
                    .edit
                    .effective_value()
                    .map_or_else(|| row.word_or_end.word(row.kind), |v| self.store.varint(v)))
            }

            /// The fixed 32-bit record's current bits.
            /// Row-resident: walk-free and source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the I32 kind.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            #[allow(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "an I32 row's banked word holds four bytes' bits, so it fits u32"
            )]
            pub fn i32_bits(&self, handle: Handle) -> Result<u32, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::I32) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(row
                    .edit
                    .effective_value()
                    .map_or_else(|| row.word_or_end.word(row.kind) as u32, |v| self.store.bits32(v)))
            }

            /// The fixed 64-bit record's current bits.
            /// Row-resident: walk-free and source-infallible.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for an orphaned row,
            /// [`EditFault::KindMismatch`] off the I64 kind.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn i64_bits(&self, handle: Handle) -> Result<u64, EditFault> {
                let row = self.live(handle)?;
                if !matches!(row.kind, RecordKind::I64) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                Ok(row
                    .edit
                    .effective_value()
                    .map_or_else(|| row.word_or_end.word(row.kind), |v| self.store.bits64(v)))
            }

            // ── descending ──

            /// Registers a resident verdict and seals the slot.
            #[cold]
            fn park(&mut self, id: RowId, fault: Fault) -> Result<u32, EditFault> {
                park_in(&mut self.rows, &mut self.faults, id, fault)
            }

            /// Publishes a freshly scanned interior
            /// ([`seal_scan_in`]'s judgments over the machine).
            fn seal_scan(
                &mut self,
                id: RowId,
                first: Option<RowId>,
                last: Option<RowId>,
                zone: ScanZone,
            ) -> Result<(), EditFault> {
                seal_scan_in(
                    &mut self.rows,
                    &mut self.layers,
                    &mut self.source_runs,
                    id,
                    first,
                    last,
                    zone,
                )?;
                #[cfg(debug_assertions)]
                self.assert_lattices();
                Ok(())
            }

            /// Parses one authored extent — resident store bytes,
            /// zero source walks. `Ok(None)`: opened; `Ok(Some)`:
            /// the parked verdict's index.
            fn descend_authored(
                &mut self,
                id: RowId,
                slot: SlotAt,
                start: u64,
                end: u64,
            ) -> Result<Option<u32>, EditFault> {
                let rows_mark = self.rows.len();
                let layers_mark = self.layers.len();
                let outcome = {
                    let mut resident = SliceSource::new(self.store.zone_bytes(slot));
                    let walk = match resident.begin() {
                        Ok(walk) => walk,
                        // The slice source's begin is `Ok` by its
                        // own definition.
                        Err(_) => unreachable!("the resident zone's walk always begins"),
                    };
                    let mut pump = Pump::new(walk);
                    match pump.skip_bytes(start) {
                        Ok(advanced) if advanced == start => {}
                        // The extent was judged inside the slot's
                        // zone when its row was minted.
                        _ => unreachable!("resident zones cover their minted extents"),
                    }
                    pump.zone = end;
                    scan_layer(
                        &mut pump,
                        &mut self.rows,
                        &mut self.layers,
                        ScanZone::Authored { slot },
                        Some(id),
                        Some(end),
                    )
                };
                match outcome {
                    Ok(chain) => {
                        match self.seal_scan(id, chain.first, chain.prev, ScanZone::Authored {
                            slot,
                        }) {
                            Ok(()) => Ok(None),
                            Err(fault) => {
                                // Discard the provisional tables:
                                // the slot publishes whole or not
                                // at all, and the refusal is
                                // retryable.
                                self.rows.truncate(rows_mark);
                                self.layers.truncate(layers_mark);
                                Err(fault)
                            }
                        }
                    }
                    Err(halt) => {
                        self.rows.truncate(rows_mark);
                        self.layers.truncate(layers_mark);
                        let fault = authored_halt(halt)?;
                        self.park(id, fault).map(Some)
                    }
                }
            }

            /// Scans one fresh source extent — one walk. `Ok(None)`:
            /// opened; `Ok(Some)`: the parked verdict's index.
            fn descend_source(
                &mut self,
                id: RowId,
                start: u64,
                end: u64,
            ) -> Result<Option<u32>, DescendFault<S::Error>> {
                if start == end {
                    // An empty extent opens without a walk: there is
                    // nothing to parse.
                    return self
                        .seal_scan(id, None, None, ScanZone::Source)
                        .map(|()| None)
                        .map_err(DescendFault::Edit);
                }
                let rows_mark = self.rows.len();
                let layers_mark = self.layers.len();
                let outcome = {
                    let walk = match self.source.begin() {
                        Ok(walk) => walk,
                        Err(fault) => {
                            return Err(DescendFault::Source(ReplayFault::Rewind {
                                phase: ReplayPhase::Descend,
                                source: fault,
                            }));
                        }
                    };
                    let mut pump = Pump::new(walk);
                    match pump.skip_bytes(start) {
                        Ok(advanced) if advanced == start => {
                            pump.zone = end;
                            scan_layer(
                                &mut pump,
                                &mut self.rows,
                                &mut self.layers,
                                ScanZone::Source,
                                Some(id),
                                Some(end),
                            )
                        }
                        Ok(_) => Err(Halt::Torn { at: start }),
                        Err(supply) => Err(Halt::Source(ReplayFault::Read {
                            phase: ReplayPhase::Descend,
                            at: pump.off,
                            source: supply,
                        })),
                    }
                };
                match outcome {
                    Ok(chain) => {
                        match self.seal_scan(id, chain.first, chain.prev, ScanZone::Source) {
                            Ok(()) => Ok(None),
                            Err(fault) => {
                                // Discard the provisional tables:
                                // the slot publishes whole or not at
                                // all, and the refusal is retryable.
                                self.rows.truncate(rows_mark);
                                self.layers.truncate(layers_mark);
                                Err(DescendFault::Edit(fault))
                            }
                        }
                    }
                    Err(halt) => {
                        self.rows.truncate(rows_mark);
                        self.layers.truncate(layers_mark);
                        match halt {
                            Halt::Wire(fault) => {
                                self.park(id, fault).map(Some).map_err(DescendFault::Edit)
                            }
                            Halt::Source(fault) => Err(DescendFault::Source(fault)),
                            Halt::Torn { at } => Err(DescendFault::Torn { at }),
                            Halt::IndexOverflow { at } => Err(DescendFault::IndexOverflow { at }),
                            Halt::OffsetExhausted { at } => {
                                Err(DescendFault::OffsetExhausted { at })
                            }
                            Halt::Resource => Err(DescendFault::Edit(EditFault::Resource)),
                        }
                    }
                }
            }

            /// The descend target's backing, judged once: the
            /// effective authored slot, the enclosing authored
            /// zone's extent, or a fresh source extent.
            fn descend_backing(&self, row: &Row) -> DescendBacking {
                if let Some(slot) = row.edit.effective_slot() {
                    #[allow(
                        clippy::as_conversions,
                        reason = "authored payload lengths were admitted to the length \
                                  class, which fits u64"
                    )]
                    return DescendBacking::Authored {
                        slot,
                        start: 0,
                        end: self.store.zone_bytes(slot).len() as u64,
                    };
                }
                // Intact or Deleted(None): a scanned row with
                // geometry.
                // SAFETY: both states are outside the Inserted
                // families.
                let at = unsafe { scanned_at(row) };
                let start = row.payload_at(at);
                let end = row.span_end(at);
                if row.authored_zone() {
                    DescendBacking::Authored { slot: self.zone_slot(row.parent), start, end }
                } else {
                    DescendBacking::Source { start, end }
                }
            }

            /// Opens a LEN's interior for editing. The payload
            /// parses on the first call — an explicit commitment
            /// that these bytes are a message, never a speculation
            /// — and the verdict is resident: a wire fault or the
            /// dialect capability parks on the record and projects
            /// unchanged on every later call, costing no further
            /// walk. One walk per fresh source extent; an empty
            /// extent, a resident verdict, and every authored
            /// payload (the effective replacement, or an interior
            /// inside one) open walk-free — the store is
            /// addressable memory.
            ///
            /// A source-backed parse trusts the provider's
            /// byte-identity obligation: the walk verifies only
            /// that the source still reaches the extent's end, so
            /// bytes that moved beneath unchanged coordinates are
            /// judged as the document's own — a breached obligation
            /// can park a verdict the document's bytes never
            /// spelled ([`Descent::Parked`]).
            ///
            /// # Errors
            ///
            /// [`DescendFault::Edit`] when the gate refuses
            /// ([`EditFault::DeadHandle`], [`EditFault::KindMismatch`])
            /// or a reservation is refused
            /// ([`EditFault::Resource`] — retryable —
            /// [`EditFault::IndexSpaceExhausted`]);
            /// [`DescendFault::Source`], [`DescendFault::Torn`]
            /// when the supply refuses or tears (no verdict parks —
            /// nothing about the document was judged);
            /// [`DescendFault::IndexOverflow`],
            /// [`DescendFault::OffsetExhausted`] off the coordinate
            /// classes. On any `Err` the editor's observable edit
            /// state is unchanged.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[track_caller]
            pub fn descend(
                &mut self,
                handle: Handle,
            ) -> Result<Descent<'_>, DescendFault<S::Error>> {
                let row = *self.live(handle).map_err(DescendFault::Edit)?;
                if matches!(row.kind, RecordKind::Group) {
                    // Groups materialize at the scan: the stored
                    // outcome projects directly, walk-free.
                    return Ok(Descent::Opened {
                        first: self.slot_first(row.slot()).map(Handle),
                    });
                }
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(DescendFault::Edit(EditFault::KindMismatch { have: row.kind }));
                }
                let id = handle.0;
                match row.slot() {
                    Slot::Opened(layer) => {
                        Ok(Descent::Opened { first: self.layer(layer).first.map(Handle) })
                    }
                    Slot::Fault(index) => Ok(Descent::Parked(&self.faults[usize_of(index)])),
                    Slot::Unopened => {
                        let parked = match self.descend_backing(&row) {
                            DescendBacking::Authored { slot, start, end } => self
                                .descend_authored(id, slot, start, end)
                                .map_err(DescendFault::Edit)?,
                            DescendBacking::Source { start, end } => {
                                self.descend_source(id, start, end)?
                            }
                        };
                        Ok(match parked {
                            Some(index) => Descent::Parked(&self.faults[usize_of(index)]),
                            None => Descent::Opened {
                                first: self.slot_first(self.row(id).slot()).map(Handle),
                            },
                        })
                    }
                }
            }

            /// Resolves several unopened LEN handles in zero or one
            /// source-ordered walk — zero when no fresh source
            /// extent remains: resident verdicts and already-opened
            /// slots project, empty extents and authored payloads
            /// settle walk-free, and only the fresh source
            /// remainder mounts the walk. Extent-atomic, not
            /// call-atomic: gate refusals precede every settlement
            /// and leave the call unchanged; a mid-walk refusal
            /// preserves every earlier settlement (each extent
            /// commits atomically), and a wire refusal inside one
            /// extent parks on that handle while the walk continues
            /// to the next.
            ///
            /// # Errors
            ///
            /// The refusing handle beside its [`DescendFault`].
            /// Handles are gated whole before any state changes; a
            /// supply refusal or tear aborts the walk, but verdicts
            /// already parked by earlier extents stand.
            ///
            /// # Panics
            ///
            /// Panics if any handle was not minted by this editor
            /// (the arena index contract).
            #[track_caller]
            pub fn materialize(
                &mut self,
                handles: &[Handle],
            ) -> Result<(), (Handle, DescendFault<S::Error>)> {
                for &handle in handles {
                    let row = gate(&self.rows, handle);
                    if row.dead() {
                        return Err((handle, DescendFault::Edit(EditFault::DeadHandle)));
                    }
                    // Groups pass the gate and settle walk-free
                    // below: their layers materialized at the scan.
                    if !matches!(row.kind, RecordKind::Len | RecordKind::Group) {
                        return Err((
                            handle,
                            DescendFault::Edit(EditFault::KindMismatch { have: row.kind }),
                        ));
                    }
                }
                // Walk-free settlements first: resident verdicts,
                // opened slots, authored payloads, empty extents.
                let mut pending: Vec<(u64, u64, RowId)> = Vec::new();
                for &handle in handles {
                    let id = handle.0;
                    let row = *self.row(id);
                    if !matches!(row.slot(), Slot::Unopened) {
                        continue;
                    }
                    match self.descend_backing(&row) {
                        DescendBacking::Authored { slot, start, end } => {
                            self.descend_authored(id, slot, start, end)
                                .map_err(|fault| (handle, DescendFault::Edit(fault)))?;
                        }
                        DescendBacking::Source { start, end } if start == end => {
                            self.seal_scan(id, None, None, ScanZone::Source)
                                .map_err(|fault| (handle, DescendFault::Edit(fault)))?;
                        }
                        DescendBacking::Source { start, end } => {
                            pending
                                .try_reserve(1)
                                .map_err(|_| (handle, DescendFault::Edit(EditFault::Resource)))?;
                            pending.push((start, end, id));
                        }
                    }
                }
                if pending.is_empty() {
                    return Ok(());
                }
                pending.sort_unstable_by_key(|&(start, _, _)| start);
                // The walk borrows the source for the whole batch,
                // so the arenas are addressed as plain fields
                // beside it.
                let Self { source, rows, layers, source_runs, faults, .. } = self;
                let walk = match source.begin() {
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
                for &(start, end, id) in &pending {
                    if !matches!(rows[id.index()].slot(), Slot::Unopened) {
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
                    let rows_mark = rows.len();
                    let layers_mark = layers.len();
                    let outcome =
                        scan_layer(&mut pump, rows, layers, ScanZone::Source, Some(id), Some(end));
                    pump.zone = u64::MAX;
                    match outcome {
                        Ok(chain) => {
                            seal_scan_in(
                                rows,
                                layers,
                                source_runs,
                                id,
                                chain.first,
                                chain.prev,
                                ScanZone::Source,
                            )
                            .map_err(|fault| {
                                rows.truncate(rows_mark);
                                layers.truncate(layers_mark);
                                (handle, DescendFault::Edit(fault))
                            })?;
                        }
                        Err(halt) => {
                            rows.truncate(rows_mark);
                            layers.truncate(layers_mark);
                            match halt {
                                Halt::Wire(fault) => {
                                    park_in(rows, faults, id, fault)
                                        .map_err(|fault| (handle, DescendFault::Edit(fault)))?;
                                    // The scan stopped mid-extent;
                                    // realign by seeking to the
                                    // extent's end for the next
                                    // request.
                                    pump.clear_construct();
                                    let owed = end - pump.off;
                                    match pump.skip_bytes(owed) {
                                        Ok(advanced) if advanced == owed => {}
                                        Ok(_) => {
                                            return Err((handle, DescendFault::Torn { at: end }));
                                        }
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
                                Halt::Source(fault) => {
                                    return Err((handle, DescendFault::Source(fault)));
                                }
                                Halt::Torn { at } => {
                                    return Err((handle, DescendFault::Torn { at }));
                                }
                                Halt::IndexOverflow { at } => {
                                    return Err((handle, DescendFault::IndexOverflow { at }));
                                }
                                Halt::OffsetExhausted { at } => {
                                    return Err((handle, DescendFault::OffsetExhausted { at }));
                                }
                                Halt::Resource => {
                                    return Err((
                                        handle,
                                        DescendFault::Edit(EditFault::Resource),
                                    ));
                                }
                            }
                        }
                    }
                }
                drop(pump);
                #[cfg(debug_assertions)]
                self.assert_lattices();
                Ok(())
            }

            // ── fetch ──

            /// Judges one fetch target and locates its current
            /// payload bytes: an authored slot (the effective
            /// replacement, or the enclosing zone of a row scanned
            /// inside one) answers resident; a scanned source
            /// payload answers as a measured extent.
            fn payload_answer(&self, handle: Handle) -> Result<PayloadAnswer, FetchFault<S::Error>> {
                let row = gate(&self.rows, handle);
                if row.dead() {
                    return Err(FetchFault::DeadHandle);
                }
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(FetchFault::KindMismatch { have: row.kind });
                }
                if let Some(slot) = row.edit.effective_slot() {
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::as_conversions,
                        reason = "authored payload lengths were admitted to the length class"
                    )]
                    return Ok(PayloadAnswer::Resident {
                        slot,
                        start: 0,
                        len: self.store.zone_bytes(slot).len() as u32,
                    });
                }
                // SAFETY: Intact and Deleted(None) sit outside the
                // Inserted families.
                let at = unsafe { scanned_at(row) };
                let start = row.payload_at(at);
                let end = row.span_end(at);
                if row.authored_zone() {
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::as_conversions,
                        reason = "authored zones end inside the length class"
                    )]
                    Ok(PayloadAnswer::Resident {
                        slot: self.zone_slot(row.parent),
                        start: start as u32,
                        len: (end - start) as u32,
                    })
                } else {
                    Ok(PayloadAnswer::Scanned { span: SourceSpan::new(start, end) })
                }
            }

            /// One resident payload extent, whole.
            fn resident_bytes(&self, slot: SlotAt, start: u32, len: u32) -> &[u8] {
                let start = usize_of(start);
                &self.store.zone_bytes(slot)[start..start + usize_of(len)]
            }

            /// The record's current payload bytes, appended to
            /// `out` (the buffer truncates back to its entry length
            /// on any refusal — never poisoned, a retry is lawful):
            /// an authored payload — the pending replacement, or an
            /// interior extent of one — answers from the store with
            /// no walk; a scanned source payload is one fresh fetch
            /// walk (deleted and parked records keep answering).
            /// The fetch walk verifies only that the source still
            /// reaches the extent's end: bytes that moved beneath
            /// unchanged coordinates are appended as they now read
            /// (the provider's byte-identity obligation, not a
            /// fetch judgment).
            ///
            /// # Errors
            ///
            /// [`FetchFault::DeadHandle`] for an orphaned row,
            /// [`FetchFault::KindMismatch`] for scalar records
            /// (their values are row-resident),
            /// [`FetchFault::Oversize`] for an extent past the
            /// address space, [`FetchFault::Resource`] when the
            /// reservation is refused, [`FetchFault::Torn`] when
            /// the source ends before a measured coordinate,
            /// [`FetchFault::Source`] for the supply's own
            /// refusals. On `Err`, `out` is byte-identical to
            /// entry.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[track_caller]
            pub fn read_payload(
                &mut self,
                handle: Handle,
                out: &mut Vec<u8>,
            ) -> Result<(), FetchFault<S::Error>> {
                match self.payload_answer(handle)? {
                    PayloadAnswer::Resident { slot, start, len } => {
                        out.try_reserve(usize_of(len)).map_err(|_| FetchFault::Resource)?;
                        out.extend_from_slice(self.resident_bytes(slot, start, len));
                        Ok(())
                    }
                    PayloadAnswer::Scanned { span } => {
                        #[allow(
                            clippy::as_conversions,
                            reason = "usize::MAX widens losslessly to u64 for the ceiling \
                                      judgment"
                        )]
                        if span.len() > usize::MAX as u64 {
                            return Err(FetchFault::Oversize { len: span.len() });
                        }
                        let mark = out.len();
                        #[allow(
                            clippy::as_conversions,
                            clippy::cast_possible_truncation,
                            reason = "the extent was just judged to fit the address space"
                        )]
                        out.try_reserve(span.len() as usize).map_err(|_| FetchFault::Resource)?;
                        let outcome = fetch_extent(&mut self.source, span, |bytes| {
                            out.extend_from_slice(bytes);
                        });
                        if let Err(handed) = outcome {
                            out.truncate(mark);
                            return Err(handed.fault);
                        }
                        Ok(())
                    }
                }
            }

            /// Hands the record's current payload bytes to `sink`
            /// as borrowed views, in order — the unbounded-extent
            /// face. An authored payload is one view from the store
            /// (no walk); a scanned source payload is one fresh
            /// fetch walk, verifying only that the source still
            /// reaches the extent's end: bytes that moved beneath
            /// unchanged coordinates are handed as they now read
            /// (the provider's byte-identity obligation, not a
            /// fetch judgment).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::read_payload`] minus the")]
            /// address-space ceiling and the reservation; the
            /// refusal rides beside the exact byte count already
            /// handed over ([`Handed`]) — the prefix carries no
            /// validity promise.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[track_caller]
            pub fn payload_sink(
                &mut self,
                handle: Handle,
                mut sink: impl FnMut(&[u8]),
            ) -> Result<(), Handed<FetchFault<S::Error>>> {
                match self.payload_answer(handle).map_err(|fault| Handed { handed: 0, fault })? {
                    PayloadAnswer::Resident { slot, start, len } => {
                        let bytes = self.resident_bytes(slot, start, len);
                        if !bytes.is_empty() {
                            sink(bytes);
                        }
                        Ok(())
                    }
                    PayloadAnswer::Scanned { span } => fetch_extent(&mut self.source, span, sink),
                }
            }

            /// Hands many records' current payload bytes to `sink`,
            /// each view tagged with its request's handle — the
            /// batch face that makes k scattered reads cost at most
            /// one walk instead of k. Every handle is validated
            /// before anything is handed; authored payloads settle
            /// from the store first (walk-free, argument order),
            /// then the scanned source extents resolve in one
            /// source-ordered walk (by extent start,
            /// enclosing-first on ties) — zero walks when no
            /// scanned extent remains. Nested and overlapping
            /// extents are lawful: a byte covered by several
            /// requests is handed to each. The walk verifies only
            /// that the source still reaches each extent's end:
            /// bytes that moved beneath unchanged coordinates are
            /// handed as they now read (the provider's
            /// byte-identity obligation, not a fetch judgment).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::payload_sink`]; `handed` sums the")]
            /// bytes delivered across all requests before the
            /// refusal.
            ///
            /// # Panics
            ///
            /// Panics if any handle was not minted by this editor
            /// (the arena index contract).
            #[track_caller]
            pub fn fetch_payloads(
                &mut self,
                handles: &[Handle],
                mut sink: impl FnMut(Handle, &[u8]),
            ) -> Result<(), Handed<FetchFault<S::Error>>> {
                // Validate every handle before anything is handed.
                let mut requests: Vec<(u64, u64, Handle)> = Vec::new();
                if requests.try_reserve(handles.len()).is_err() {
                    return Err(Handed { handed: 0, fault: FetchFault::Resource });
                }
                let mut resident: Vec<(Handle, SlotAt, u32, u32)> = Vec::new();
                if resident.try_reserve(handles.len()).is_err() {
                    return Err(Handed { handed: 0, fault: FetchFault::Resource });
                }
                for &handle in handles {
                    match self
                        .payload_answer(handle)
                        .map_err(|fault| Handed { handed: 0, fault })?
                    {
                        PayloadAnswer::Resident { slot, start, len } => {
                            resident.push((handle, slot, start, len));
                        }
                        PayloadAnswer::Scanned { span } => {
                            if !span.is_empty() {
                                requests.push((span.start(), span.end(), handle));
                            }
                        }
                    }
                }
                // Authored answers settle separately, walk-free, in
                // argument order.
                let mut handed = 0u64;
                for &(handle, slot, start, len) in &resident {
                    let bytes = self.resident_bytes(slot, start, len);
                    if !bytes.is_empty() {
                        sink(handle, bytes);
                        handed += u64::from(len);
                    }
                }
                if requests.is_empty() {
                    return Ok(());
                }
                requests.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
                let walk = match self.source.begin() {
                    Ok(walk) => walk,
                    Err(fault) => {
                        return Err(Handed {
                            handed,
                            fault: FetchFault::Source(ReplayFault::Rewind {
                                phase: ReplayPhase::Fetch,
                                source: fault,
                            }),
                        });
                    }
                };
                let mut pump = Pump::new(walk);
                let fail =
                    |pump: &Pump<S::Walk<'_>>, handed: u64, supply: SupplyFault<S::Error>| Handed {
                        handed,
                        fault: FetchFault::Source(ReplayFault::Read {
                            phase: ReplayPhase::Fetch,
                            at: pump.off,
                            source: supply,
                        }),
                    };
                let mut active: Vec<(u64, Handle)> = Vec::new();
                let mut next = 0usize;
                loop {
                    if active.is_empty() {
                        let Some(&(start, _, _)) = requests.get(next) else {
                            return Ok(());
                        };
                        let owed = start - pump.off;
                        match pump.skip_bytes(owed) {
                            Ok(advanced) if advanced == owed => {}
                            Ok(_) => {
                                return Err(Handed {
                                    handed,
                                    fault: FetchFault::Torn { at: start },
                                });
                            }
                            Err(supply) => return Err(fail(&pump, handed, supply)),
                        }
                    }
                    while let Some(&(start, end, handle)) = requests.get(next) {
                        if start > pump.off {
                            break;
                        }
                        if active.try_reserve(1).is_err() {
                            return Err(Handed { handed, fault: FetchFault::Resource });
                        }
                        active.push((end, handle));
                        next += 1;
                    }
                    // The nearest boundary: the closest active end
                    // or the next request's start, whichever comes
                    // first.
                    let mut boundary = active.iter().map(|&(end, _)| end).min().unwrap_or(u64::MAX);
                    if let Some(&(start, _, _)) = requests.get(next) {
                        boundary = boundary.min(start);
                    }
                    let owed = boundary - pump.off;
                    let outcome = pump.copy_bytes(owed, |bytes| {
                        for &(_, handle) in &active {
                            sink(handle, bytes);
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
                        Ok(_) => {
                            return Err(Handed { handed, fault: FetchFault::Torn { at: boundary } });
                        }
                        Err(supply) => return Err(fail(&pump, handed, supply)),
                    }
                    active.retain(|&(end, _)| end > boundary);
                }
            }

            // ── mutation ──

            /// A live, editable witness for scalar value commands.
            #[track_caller]
            fn value_gate(&self, handle: Handle, want: RecordKind) -> Result<LiveEdit, EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                if row.kind != want {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                match row.edit {
                    Edit::Intact => Ok(LiveEdit::Virgin),
                    Edit::Replaced(_) => Ok(LiveEdit::Replaced),
                    Edit::Inserted(_) => Ok(LiveEdit::Inserted),
                    Edit::Deleted(_) | Edit::InsertedDeleted(_) => Err(EditFault::DeletedTarget),
                    // Payload-backed states sit on LEN rows alone,
                    // which the kind gate above refused.
                    Edit::ReplacedPayload(_)
                    | Edit::DeletedPayload(_)
                    | Edit::InsertedPayload(_)
                    | Edit::InsertedDeletedPayload(_) => {
                        unreachable!("the kind gate keeps payload states off scalar rows")
                    }
                }
            }

            /// A live, editable witness for payload commands —
            /// the scalar gate's sibling over the payload-backed
            /// states.
            #[track_caller]
            fn payload_gate(&self, handle: Handle) -> Result<LivePayload, EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                match row.edit {
                    Edit::Intact => Ok(LivePayload::Virgin),
                    Edit::ReplacedPayload(_) => Ok(LivePayload::Replaced),
                    Edit::InsertedPayload(_) => Ok(LivePayload::Inserted),
                    Edit::Deleted(_)
                    | Edit::DeletedPayload(_)
                    | Edit::InsertedDeletedPayload(_) => Err(EditFault::DeletedTarget),
                    // Scalar-backed value states sit on scalar rows
                    // alone, which the kind gate above refused; a
                    // scanned LEN's virgin state is `Intact`.
                    Edit::Replaced(_) | Edit::Inserted(_) | Edit::InsertedDeleted(_) => {
                        unreachable!("the kind gate keeps scalar value states off LEN rows")
                    }
                }
            }

            /// Refuses a backing flip over an interior that carries
            /// undo history: precise undo would otherwise point
            /// into rows the flip orphans. The target's own history
            /// is fine — only strict descendants block, and the
            /// layer's history count answers for them whole.
            fn interior_gate(&self, id: RowId) -> Result<(), EditFault> {
                match self.row(id).slot() {
                    Slot::Opened(layer) if self.layer(layer).history_kids > 0 => {
                        Err(EditFault::EditedInterior)
                    }
                    Slot::Opened(_) | Slot::Unopened | Slot::Fault(_) => Ok(()),
                }
            }

            /// The undo log's single append point: records the
            /// step, marks the row's own history on its first
            /// pending entry, and raises the subtree marks. Every
            /// reservation already holds.
            fn log_push(&mut self, id: RowId, from: Edit) {
                let fresh = !self.row(id).own_hist();
                self.log.push(Transition::new(id, from, fresh));
                if fresh {
                    self.row_mut(id).flags |= FLAG_OWN_HIST;
                    self.raise_mark(Mark::Hist, id);
                }
            }

            /// The undo log's single removal point: popping a row's
            /// fresh (first) entry releases its own-history mark
            /// and lowers the subtree marks — exact because reverts
            /// run strictly last-in-first-out, so no later entry
            /// for the row remains.
            fn log_pop(&mut self) -> Option<Transition> {
                let transition = self.log.pop()?;
                if transition.fresh() {
                    self.row_mut(transition.row()).flags &= !FLAG_OWN_HIST;
                    self.lower_mark(Mark::Hist, transition.row());
                }
                Some(transition)
            }

            /// Raises a subtree mark from `id` upward: each newly
            /// flagged row counts into its holding layer, and the
            /// climb stops at the first ancestor already flagged.
            /// Inlined for the already-flagged early return on the
            /// value-edit hot path.
            #[inline]
            fn raise_mark(&mut self, mark: Mark, mut id: RowId) {
                loop {
                    let row = self.row_mut(id);
                    if row.flags & mark.flag() != 0 {
                        return;
                    }
                    row.flags |= mark.flag();
                    let parent = row.parent;
                    *self.holding_layer_mut(parent).count_mut(mark) += 1;
                    match parent {
                        Some(next) => id = next,
                        None => return,
                    }
                }
            }

            /// Lowers a subtree mark from `id` upward: a row stays
            /// flagged while its own state or its opened layer's
            /// count holds the mark, and each falling flag leaves
            /// its holding layer's count. Inlined for the
            /// still-held early return on the value-edit hot path.
            #[inline]
            fn lower_mark(&mut self, mark: Mark, mut id: RowId) {
                loop {
                    let row = self.row(id);
                    if row.flags & mark.flag() == 0 {
                        return;
                    }
                    let held = match mark {
                        Mark::Dirt => row.edit.own_dirty(),
                        Mark::Hist => row.own_hist(),
                    } || match row.slot() {
                        Slot::Opened(layer) => self.layer(layer).count(mark) > 0,
                        Slot::Unopened | Slot::Fault(_) => false,
                    };
                    if held {
                        return;
                    }
                    let parent = row.parent;
                    self.row_mut(id).flags &= !mark.flag();
                    *self.holding_layer_mut(parent).count_mut(mark) -= 1;
                    match parent {
                        Some(next) => id = next,
                        None => return,
                    }
                }
            }

            /// Logs and applies one edit transition (the infallible
            /// suffix of every value command: both reservations
            /// already hold).
            fn apply_edit(&mut self, id: RowId, to: Edit) {
                let from = self.row(id).edit;
                self.log_push(id, from);
                self.write_state(id, to);
            }

            /// Applies one edit transition: sets the state,
            /// re-seals the child slot when the row's backing
            /// flips, and keeps the dirt lattice exact in both
            /// directions.
            ///
            /// Orphaned interiors are always clean; three
            /// guarantees join to prove it: the interior gate
            /// refuses a forward flip over any interior history,
            /// revert executes strictly last-in-first-out (every
            /// later descendant transition is already unwound when
            /// a flip replays backwards), and rows under an
            /// authored backing accept no edits at all.
            fn write_state(&mut self, id: RowId, to: Edit) {
                let row = self.row_mut(id);
                debug_assert!(!row.dead(), "write_state: dead rows accept no transitions");
                let from = row.edit;
                row.edit = to;
                let flip = from.effective_value() != to.effective_value()
                    || from.effective_slot() != to.effective_slot();
                let sealed = !matches!(row.slot(), Slot::Unopened);
                if flip && sealed {
                    self.orphan_interior(id);
                }
                if to.own_dirty() {
                    self.raise_mark(Mark::Dirt, id);
                } else {
                    self.lower_mark(Mark::Dirt, id);
                }
                #[cfg(debug_assertions)]
                self.assert_lattices();
            }

            /// Re-seals a flipped container: the parsed interior
            /// (clean by the transition argument above) is orphaned
            /// and the slot returns to unopened, ready to parse the
            /// new backing. The interior's layers and runs stay
            /// behind, unreachable and inert.
            fn orphan_interior(&mut self, id: RowId) {
                let first = self.slot_first(self.row(id).slot());
                self.row_mut(id).set_slot(Slot::Unopened);
                let mut cur = first;
                while let Some(orphan) = cur {
                    let row = self.row_mut(orphan);
                    debug_assert!(!row.edit.own_dirty(), "orphaned interiors are clean");
                    row.set_dead();
                    cur = preorder_next(&self.rows, &self.layers, orphan, id);
                }
            }

            /// Replaces a varint record's value. Walk-free.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`], [`EditFault::KindMismatch`],
            /// [`EditFault::DeletedTarget`],
            /// [`EditFault::InsideAuthoredBody`] off the gates;
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`]
            /// when the value cannot be stored. On any `Err` the
            /// editor's observable edit state is unchanged.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::Varint)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_varint(value).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

            /// Replaces a fixed 32-bit record's bits. Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_i32(&mut self, handle: Handle, bits: u32) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::I32)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_bits32(bits).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

            /// Replaces a fixed 64-bit record's bits. Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_i64(&mut self, handle: Handle, bits: u64) -> Result<(), EditFault> {
                let witness = self.value_gate(handle, RecordKind::I64)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let at = self.store.push_bits64(bits).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(at));
                Ok(())
            }

            maintain_machine!(@set_payload $pay $(<$plt>)?, Machine: $Machine);

            /// Shrouds a record: it stays in the topology, stops
            /// emitting, and holds its pending value for
            #[doc = concat!(" [`", stringify!($Machine), "::undelete`]. Walk-free.")]
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::DeletedTarget`] when already shrouded,
            /// [`EditFault::Resource`] when the log cannot grow. On
            /// any `Err` the editor's observable edit state is
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Intact => Edit::Deleted(None),
                    Edit::Replaced(value) => Edit::Deleted(Some(value)),
                    Edit::Inserted(value) => Edit::InsertedDeleted(value),
                    Edit::ReplacedPayload(slot) => Edit::DeletedPayload(Some(slot)),
                    Edit::InsertedPayload(slot) => Edit::InsertedDeletedPayload(slot),
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::DeletedPayload(_)
                    | Edit::InsertedDeletedPayload(_) => return Err(EditFault::DeletedTarget),
                };
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, to);
                Ok(())
            }

            /// Lifts a shroud, restoring the state deletion found.
            /// Walk-free.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::NotDeleted`] when nothing is shrouded,
            /// [`EditFault::Resource`] when the log cannot grow. On
            /// any `Err` the editor's observable edit state is
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn undelete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                let to = match row.edit {
                    Edit::Deleted(None) => Edit::Intact,
                    Edit::Deleted(Some(value)) => Edit::Replaced(value),
                    Edit::InsertedDeleted(value) => Edit::Inserted(value),
                    Edit::DeletedPayload(None) => Edit::Intact,
                    Edit::DeletedPayload(Some(slot)) => Edit::ReplacedPayload(slot),
                    Edit::InsertedDeletedPayload(slot) => Edit::InsertedPayload(slot),
                    Edit::Intact
                    | Edit::Replaced(_)
                    | Edit::Inserted(_)
                    | Edit::ReplacedPayload(_)
                    | Edit::InsertedPayload(_) => {
                        return Err(EditFault::NotDeleted);
                    }
                };
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, to);
                Ok(())
            }

            /// Clears a replacement back to the scanned state. On a
            /// LEN this is a backing flip, but it needs no interior
            /// gate: a replaced LEN's materialized interior is
            /// authored bytes, and authored rows refuse every
            /// mutation face — the interior can hold no history to
            /// protect. Walk-free.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`],
            /// [`EditFault::InsideAuthoredBody`],
            /// [`EditFault::NotClearable`] off the replaced states,
            /// [`EditFault::Resource`] when the log cannot grow. On
            /// any `Err` the editor's observable edit state is
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn clear_edit(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.edit {
                    Edit::Replaced(_) | Edit::ReplacedPayload(_) => {}
                    Edit::Intact
                    | Edit::Deleted(_)
                    | Edit::Inserted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::DeletedPayload(_)
                    | Edit::InsertedPayload(_)
                    | Edit::InsertedDeletedPayload(_) => {
                        return Err(EditFault::NotClearable);
                    }
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.apply_edit(handle.0, Edit::Intact);
                Ok(())
            }

            // ── insertion ──

            /// Gates an insertion container and yields its layer.
            #[track_caller]
            fn container_gate(&self, container: Option<Handle>) -> Result<&Layer, EditFault> {
                let Some(handle) = container else {
                    return Ok(&self.root);
                };
                let row = self.live(handle)?;
                if row.authored_zone() {
                    return Err(EditFault::InsideAuthoredBody);
                }
                match row.kind {
                    RecordKind::Len => {
                        if row.edit.effective_slot().is_some() {
                            // A replaced or authored payload: its
                            // interior is authored bytes,
                            // browse-only.
                            return Err(EditFault::InsideAuthoredBody);
                        }
                    }
                    // A group's layer materialized at the scan (or
                    // at its insertion), so the slot dispatch below
                    // always finds it open.
                    RecordKind::Group => {}
                    RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => {
                        return Err(EditFault::KindMismatch { have: row.kind });
                    }
                }
                match row.slot() {
                    Slot::Opened(layer) => Ok(self.layer(layer)),
                    Slot::Unopened | Slot::Fault(_) => Err(EditFault::TargetUnopened),
                }
            }

            /// Resolves an anchor into a proven splice point.
            #[track_caller]
            fn resolve_anchor(&self, at: InsertAt) -> Result<InsertPlan, EditFault> {
                match at {
                    InsertAt::HeadOf(container) => {
                        self.container_gate(container)?;
                        Ok(InsertPlan { parent: container.map(|h| h.0), prev: None })
                    }
                    InsertAt::TailOf(container) => {
                        let layer = self.container_gate(container)?;
                        Ok(InsertPlan { parent: container.map(|h| h.0), prev: layer.last })
                    }
                    InsertAt::After(anchor) => {
                        let row = self.live(anchor)?;
                        if row.authored_zone() {
                            return Err(EditFault::InsideAuthoredBody);
                        }
                        Ok(InsertPlan { parent: row.parent, prev: Some(anchor.0) })
                    }
                }
            }

            /// Mints the next row coordinate for an insertion.
            fn mint_insert(&self) -> Result<RowId, EditFault> {
                u32::try_from(self.rows.len())
                    .ok()
                    .and_then(RowId::new)
                    .ok_or(EditFault::IndexSpaceExhausted)
            }

            /// Splices, logs, and awakens an authored row (the
            /// infallible suffix of every insert command: every
            /// reservation holds). Chain anchors update in place:
            /// the holding layer's head when the row splices first,
            /// its tail when nothing follows.
            fn apply_insert(
                &mut self,
                plan: &InsertPlan,
                id: RowId,
                field: FieldNumber,
                kind: RecordKind,
                ghost: Edit,
                live: Edit,
            ) {
                let next = plan
                    .prev
                    .map_or_else(|| self.holding_layer(plan.parent).first, |prev| {
                        self.row(prev).next
                    });
                // The reservation in the command covers this push.
                self.rows.push(Row::authored(field, kind, plan.parent, next, ghost));
                match plan.prev {
                    Some(prev) => self.row_mut(prev).next = Some(id),
                    None => self.holding_layer_mut(plan.parent).first = Some(id),
                }
                if next.is_none() {
                    self.holding_layer_mut(plan.parent).last = Some(id);
                }
                self.log_push(id, ghost);
                self.write_state(id, live);
            }

            /// Inserts a varint record at the anchor. Walk-free;
            /// authored records emit minimally at save.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeadHandle`] for a dead anchor,
            /// [`EditFault::KindMismatch`] for a scalar container,
            /// [`EditFault::TargetUnopened`] for an undescended
            /// LEN, [`EditFault::InsideAuthoredBody`] under
            /// authored bytes,
            /// [`EditFault::Resource`]/[`EditFault::IndexSpaceExhausted`]
            /// when the row, log, or value cannot be stored. On any
            /// `Err` the editor's observable edit state is
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn insert_varint(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                value: u64,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_varint(value).map_err(edit_store_fault)?;
                self.apply_insert(
                    &plan,
                    id,
                    field,
                    RecordKind::Varint,
                    Edit::InsertedDeleted(value),
                    Edit::Inserted(value),
                );
                Ok(Handle(id))
            }

            /// Inserts a fixed 32-bit record at the anchor.
            /// Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn insert_i32(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                bits: u32,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_bits32(bits).map_err(edit_store_fault)?;
                self.apply_insert(
                    &plan,
                    id,
                    field,
                    RecordKind::I32,
                    Edit::InsertedDeleted(value),
                    Edit::Inserted(value),
                );
                Ok(Handle(id))
            }

            /// Inserts a fixed 64-bit record at the anchor.
            /// Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn insert_i64(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                bits: u64,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let value = self.store.push_bits64(bits).map_err(edit_store_fault)?;
                self.apply_insert(
                    &plan,
                    id,
                    field,
                    RecordKind::I64,
                    Edit::InsertedDeleted(value),
                    Edit::Inserted(value),
                );
                Ok(Handle(id))
            }

            maintain_machine!(@insert_payload $pay $(<$plt>)?, Machine: $Machine);

            /// Inserts an empty group container at the anchor —
            /// its layer publishes immediately, so interior
            /// insertions need no descend. Walk-free; the start
            /// and end tags emit minimally at save.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[track_caller]
            pub fn insert_group(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let layer = u32::try_from(self.layers.len())
                    .ok()
                    .and_then(LayerId::new)
                    .ok_or(EditFault::IndexSpaceExhausted)?;
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                self.layers.try_reserve(1).map_err(edit_resource)?;
                // The group sentinel: an unbacked coordinate for
                // the row whose value side is empty — no store
                // column holds an entry for it, and the kind gates
                // keep every value and payload reader off group
                // rows, so it is never dereferenced. Any admitted
                // coordinate serves; minting through `new` in const
                // position keeps the choice judged at compile time.
                const UNBACKED: ValueAt = ValueAt::new(0).unwrap();
                self.apply_insert(
                    &plan,
                    id,
                    field,
                    RecordKind::Group,
                    Edit::InsertedDeleted(UNBACKED),
                    Edit::Inserted(UNBACKED),
                );
                // The reservation above covers this push. The
                // layer's zone carries no run: command-authored
                // interiors own no hex.
                self.layers.push(Layer::empty(Zone::Source { run: None }));
                self.row_mut(id).set_slot(Slot::Opened(layer));
                #[cfg(debug_assertions)]
                self.assert_lattices();
                Ok(Handle(id))
            }

            // ── revision ──

            /// Reverts the most recent command; returns the touched
            /// row. Reverting an insertion shrouds the row
            /// (topology is monotone; the ghost stays for
            /// presentation to filter). Walk-free — the banked
            /// words and stored widths re-speak the scanned reading
            /// — with one walk-visible consequence: re-descending a
            /// re-sealed source container later costs one fresh
            /// walk (fresh rows, a fresh layer, a fresh run).
            #[inline]
            pub fn revert(&mut self) -> Option<Handle> {
                let transition = self.log_pop()?;
                self.write_state(transition.row(), transition.from);
                Some(Handle(transition.row()))
            }

            /// Reverts every pending command, newest first.
            /// Walk-free; the next save is the source verbatim.
            #[inline]
            pub fn revert_all(&mut self) {
                while self.revert().is_some() {}
            }

            /// The lattice oracle: pins the own-history marks to
            /// the log (every logged row is marked, and the
            /// marked-row count equals the fresh-entry count —
            /// reverts run last-in-first-out, so a logged row has
            /// exactly one fresh entry and the two counts coincide
            /// exactly when the marks name the logged rows), then
            /// re-derives every row's subtree marks from their
            /// local ground truths and walks every reachable
            /// layer's chain against its anchors and both counts —
            /// the local closures compose inductively from the
            /// leaves, so together they pin the global aggregates.
            /// O(rows + log), all threaded, no allocation; debug
            /// builds run it after every transition and
            /// publication.
            #[cfg(debug_assertions)]
            fn assert_lattices(&self) {
                let mut fresh = 0_usize;
                for t in &self.log {
                    debug_assert!(self.row(t.row()).own_hist(), "logged row without its own mark");
                    fresh += usize::from(t.fresh());
                }
                let marked = self.rows.iter().filter(|row| row.own_hist()).count();
                debug_assert_eq!(marked, fresh, "own-history marks drift from the log");
                for row in &self.rows {
                    let kids = |mark: Mark| match row.slot() {
                        Slot::Opened(layer) => self.layer(layer).count(mark) > 0,
                        Slot::Unopened | Slot::Fault(_) => false,
                    };
                    debug_assert_eq!(
                        row.flags & FLAG_HIST != 0,
                        row.own_hist() || kids(Mark::Hist),
                        "subtree-history mark drift"
                    );
                    debug_assert_eq!(
                        row.dirty(),
                        row.edit.own_dirty() || kids(Mark::Dirt),
                        "subtree-dirt mark drift"
                    );
                }
                self.assert_layer(&self.root, None);
                for (index, row) in self.rows.iter().enumerate() {
                    if let Slot::Opened(layer) = row.slot() {
                        let owner = u32::try_from(index).ok().and_then(RowId::new);
                        debug_assert!(owner.is_some(), "arena index outside the row domain");
                        self.assert_layer(self.layer(layer), owner);
                    }
                }
            }

            /// One layer's oracle: the chain from `first` ends on
            /// `last`, every member names `owner` as parent, and
            /// both flagged-member counts match the maintained
            /// ones.
            #[cfg(debug_assertions)]
            fn assert_layer(&self, layer: &Layer, owner: Option<RowId>) {
                let mut dirty = 0u32;
                let mut marked = 0u32;
                let mut tail = None;
                let mut cur = layer.first;
                while let Some(id) = cur {
                    let row = self.row(id);
                    debug_assert!(row.parent == owner, "chain member outside its layer");
                    if row.dirty() {
                        dirty += 1;
                    }
                    if row.hist() {
                        marked += 1;
                    }
                    tail = Some(id);
                    cur = row.next;
                }
                debug_assert!(layer.last == tail, "layer tail drift");
                debug_assert_eq!(layer.dirty_kids, dirty, "layer dirt count drift");
                debug_assert_eq!(layer.history_kids, marked, "layer history count drift");
            }

            // ── saving ──

            /// The exact byte length the saves would produce,
            /// without producing bytes and without a source walk:
            /// the sizing pass alone. An editor with no dirt
            /// answers in O(1): the save is the source.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
            /// outgrows the length class — the same sizing that
            /// would refuse the save, surfaced without a walk —
            /// [`SaveFault::Resource`] when the sizing scratch is
            /// refused.
            pub fn save_len(&self) -> Result<u64, SaveFault<S::Error>> {
                if self.root.dirty_kids == 0 {
                    return Ok(self.total.as_inner());
                }
                Ok(save_view!(self).size_pass()?.0)
            }

            /// Serializes into a fresh `Vec<u8>`: one booking walk
            /// compiles and prices, then one splicing walk emits —
            /// untouched extents ride verbatim, byte for byte,
            /// padding included.
            ///
            /// # Errors
            ///
            /// [`SaveFault`]; no buffer exists on `Err` and the
            /// editor's observable edit state is unchanged.
            ///
            /// # Panics
            ///
            /// If the fold's emission disagrees with the compiled
            /// length — a library bug caught at the seam.
            pub fn save(&mut self) -> Result<Vec<u8>, SaveFault<S::Error>> {
                let mut out = Vec::new();
                self.save_into(&mut out)?;
                Ok(out)
            }

            /// Serializes by appending to the caller's buffer
            /// (reserved once, fallibly, at the compiled total) —
            /// the reuse face for batch loops. One booking walk and
            /// one emission walk; repeated saves are lawful (the
            /// edit state is read, never consumed).
            ///
            /// # Errors
            ///
            /// [`SaveFault`]; the buffer is truncated back to its
            /// entry mark, so a faulted save never poisons the
            /// loop, and the editor's observable edit state is
            /// unchanged.
            ///
            /// # Panics
            ///
            /// If the fold's emission disagrees with the compiled
            /// length — a library bug caught at the seam.
            pub fn save_into(&mut self, out: &mut Vec<u8>) -> Result<(), SaveFault<S::Error>> {
                // Direct field borrows: the view reads the arenas
                // while the fold walks the source beside them.
                let view = save_view!(self);
                let script = view.compile()?;
                let planned =
                    usize::try_from(script.out_len()).map_err(|_| SaveFault::Resource)?;
                out.try_reserve_exact(planned).map_err(save_alloc)?;
                let mark = out.len();
                match fold(&mut self.source, &script, self.total.as_inner(), &mut |view| {
                    out.extend_from_slice(view);
                }) {
                    Ok(()) => {
                        assert!(
                            out.len() - mark == planned,
                            "maintain save: the fold emits exactly the compiled length"
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
            /// borrowed views, in output order — no output buffer
            /// exists on either side. One booking walk and one
            /// emission walk.
            ///
            /// Compile faults precede every handoff (`handed` is
            /// zero there); an emission fault names the exact
            /// prefix the sink received. The prefix carries no
            /// validity promise — atomic publication is the
            /// caller's transactional destination.
            ///
            /// # Errors
            ///
            /// [`Handed`] around the [`SaveFault`].
            pub fn save_sink(
                &mut self,
                mut sink: impl FnMut(&[u8]),
            ) -> Result<(), Handed<SaveFault<S::Error>>> {
                let view = save_view!(self);
                let script = match view.compile() {
                    Ok(script) => script,
                    Err(fault) => return Err(Handed { handed: 0, fault }),
                };
                let mut handed = 0u64;
                match fold(&mut self.source, &script, self.total.as_inner(), &mut |view| {
                    #[allow(
                        clippy::as_conversions,
                        reason = "view lengths widen losslessly into u64"
                    )]
                    {
                        handed += view.len() as u64;
                    }
                    sink(view);
                }) {
                    Ok(()) => Ok(()),
                    Err(fault) => Err(Handed { handed, fault: emit_fault(fault) }),
                }
            }

            /// The output-order span table of the save this editor
            /// would emit: every record the save walk emits —
            /// source-endorsed or authored, not shrouded, ghosts
            /// excluded — paired with its whole-record span in the
            /// output, containers enclosing their interiors. (An
            /// authored payload emits wholesale, so its record is
            /// one entry; rows scanned out of it stay interior to
            /// that entry.) The sizing pass runs first, so the
            /// table prices exactly what the save would produce,
            /// without a walk and without emitting a byte.
            ///
            /// Handles do not survive a save-and-reopen; spans do —
            /// the cross-save identity recipe in [`crate::maintain`]
            #[doc = concat!(" composes this face with [`", stringify!($Machine), "::narrowest`] on the")]
            /// reopened document.
            ///
            /// # Errors
            ///
            /// As the saves — the same sizing pass surfaces the
            /// same faults, and the table's memory reserves
            /// fallibly.
            ///
            /// # Panics
            ///
            /// If the sizing and span walks disagree — a library
            /// bug caught at the seam.
            pub fn save_spans(&self) -> Result<SaveSpans, SaveFault<S::Error>> {
                let view = save_view!(self);
                let (total, bodies) = view.size_pass()?;
                let mut entries: Vec<(Handle, SourceSpan)> = Vec::new();
                // One reservation covers the table: at most one
                // entry per arena row.
                entries.try_reserve(self.rows.len()).map_err(save_alloc)?;
                let covered = view.span_walk(&bodies, &mut entries)?;
                assert!(covered == total, "maintain spans: the span walk covers the priced save");
                Ok(SaveSpans { entries })
            }

            // ── canonical output ──

            /// Serializes under the `CanonicalMinimal` output
            /// standard into a fresh, exactly reserved `Vec<u8>`:
            /// minimally emits every varint construct in the
            /// materialized commitment closure; opaque LEN payload
            /// bytes pass unchanged. One booking walk (the rows
            /// carry the banked words and met widths) and one
            /// emission walk.
            ///
            /// The commitment closure is the row graph this editor
            /// already materialized: the root layer, plus each
            /// source LEN interior a successful descend committed.
            /// Every head tag, LEN prefix, and varint value inside
            /// it re-emits at its value's own width — padding on
            /// kept tags included — and prefix shrinkage cascades
            /// through every opened LEN ancestor. An unopened or
            /// faulted LEN payload and every effective authored
            /// payload terminate the closure and ride
            /// byte-for-byte behind re-derived framing, even when
            /// those bytes happen to parse. Values, field order,
            /// duplicates, liveness, and the fixed-width bits are
            /// untouched.
            ///
            /// The face caches nothing: the compiled script and
            /// its prefix slots are call-local, so
            #[doc = concat!(" [`pending`](", stringify!($Machine), "::pending), every status, source")]
            /// spans, the undo log, and the ordinary fidelity save
            /// read identically before and after the call. The
            /// ordinary [`save`](Self::save) family answers
            /// byte-fidelity instead; both re-ingest under
            /// `Tolerant`, and this family's output additionally
            /// closes under the dialect validator's
            /// `CanonicalMinimal` standard.
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] when the allocator refuses
            /// the script or the output reservation,
            /// [`SaveFault::BodyOverCap`] when an opened LEN's
            /// canonical body outgrows the length class,
            /// [`SaveFault::Source`] and [`SaveFault::Torn`] off
            /// the emission walk. On `Err` no buffer exists and
            /// the editor's observable edit state is unchanged.
            ///
            /// # Panics
            ///
            /// If the fold's emission disagrees with the compiled
            /// length — a library bug caught at the seam.
            pub fn save_canonical(&mut self) -> Result<Vec<u8>, SaveFault<S::Error>> {
                let mut out = Vec::new();
                self.save_canonical_into(&mut out)?;
                Ok(out)
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s emission appended to")]
            /// `out` — existing content is untouched, and the
            /// buffer grows by one exact fallible reservation. One
            /// booking walk and one emission walk.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]; the buffer is")]
            /// truncated back to its entry mark on any `Err`.
            ///
            /// # Panics
            ///
            /// If the fold's emission disagrees with the compiled
            /// length — a library bug caught at the seam.
            pub fn save_canonical_into(
                &mut self,
                out: &mut Vec<u8>,
            ) -> Result<(), SaveFault<S::Error>> {
                let view = save_view!(self);
                let script = view.canonical_compile()?;
                let planned =
                    usize::try_from(script.out_len()).map_err(|_| SaveFault::Resource)?;
                out.try_reserve_exact(planned).map_err(save_alloc)?;
                let mark = out.len();
                match fold(&mut self.source, &script, self.total.as_inner(), &mut |view| {
                    out.extend_from_slice(view);
                }) {
                    Ok(()) => {
                        assert!(
                            out.len() - mark == planned,
                            "maintain canonical save: the fold emits exactly the compiled length"
                        );
                        Ok(())
                    }
                    Err(fault) => {
                        out.truncate(mark);
                        Err(emit_fault(fault))
                    }
                }
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s bytes handed to `sink`")]
            /// as borrowed views, in output order — no output
            /// buffer. One booking walk and one emission walk;
            /// compile faults precede every handoff, and an
            /// emission fault names the exact prefix the sink
            /// received (no validity promise).
            ///
            /// # Errors
            ///
            /// [`Handed`] around the [`SaveFault`].
            pub fn save_canonical_sink(
                &mut self,
                mut sink: impl FnMut(&[u8]),
            ) -> Result<(), Handed<SaveFault<S::Error>>> {
                let view = save_view!(self);
                let script = match view.canonical_compile() {
                    Ok(script) => script,
                    Err(fault) => return Err(Handed { handed: 0, fault }),
                };
                let mut handed = 0u64;
                match fold(&mut self.source, &script, self.total.as_inner(), &mut |view| {
                    #[allow(
                        clippy::as_conversions,
                        reason = "view lengths widen losslessly into u64"
                    )]
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

        maintain_machine!(@save_view $Machine $(<$plt>)?, store: $Store);
    };
    (@save_view $Machine:ident $(<$plt:lifetime>)?, store: $Store:ty) => {
        impl<'a $(, $plt)?> SaveView<'a, $Store> {
            /// A row by minted coordinate.
            fn row(&self, id: RowId) -> &'a Row {
                // SAFETY: `id` was minted by the machine whose
                // fields this view borrows, and the arena never
                // shrinks.
                unsafe { self.rows.get_unchecked(id.index()) }
            }

            /// A layer descriptor by minted coordinate.
            fn layer(&self, layer: LayerId) -> &'a Layer {
                // SAFETY: `layer` was minted by the machine whose
                // fields this view borrows, and the layer table
                // never shrinks.
                unsafe { self.layers.get_unchecked(layer.index()) }
            }

            /// The first row of a slot's layer (`None` unless
            /// opened).
            fn slot_first(&self, slot: Slot) -> Option<RowId> {
                match slot {
                    Slot::Opened(layer) => self.layer(layer).first,
                    Slot::Unopened | Slot::Fault(_) => None,
                }
            }

            /// The save passes' verdict for one row, values
            /// resolved once — the fidelity dispatch: replaced
            /// records keep their source tag bytes verbatim, LEN
            /// prefixes ride verbatim while the body length is
            /// unchanged, and only command-authored records emit
            /// minimally.
            fn settle(&self, row: &Row) -> Arm {
                match row.edit {
                    Edit::Deleted(_) | Edit::DeletedPayload(_) => {
                        // SAFETY: the shroud families keep their
                        // scanned geometry (command-authored rows
                        // shroud into the ghost families instead).
                        let at = unsafe { scanned_at(row) };
                        Arm::Skip { end: Some(row.span_end(at)) }
                    }
                    Edit::InsertedDeleted(_) | Edit::InsertedDeletedPayload(_) => {
                        Arm::Skip { end: None }
                    }
                    Edit::Intact => {
                        // SAFETY: the Intact arm is outside the
                        // Inserted families.
                        let at = unsafe { scanned_at(row) };
                        if !row.dirty() {
                            return Arm::Clean { end: row.span_end(at) };
                        }
                        match row.kind {
                            RecordKind::Len if matches!(row.slot(), Slot::Opened(_)) => {
                                let tag_end = at.as_inner() + row.tag_w();
                                let prefix_end = tag_end + row.delim_w();
                                Arm::Spine {
                                    tag_end,
                                    prefix_end,
                                    src_len: row.span_end(at) - prefix_end,
                                    first: self.slot_first(row.slot()),
                                }
                            }
                            RecordKind::Group => Arm::ReGroup {
                                tag_end: at.as_inner() + row.tag_w(),
                                first: self.slot_first(row.slot()),
                            },
                            // A dirty Intact row is an opened
                            // container with interior edits; the
                            // scalar arm here is untouched-only in
                            // practice — it stays for totality
                            // (settle is shared by every save
                            // walk).
                            _ => Arm::Clean { end: row.span_end(at) },
                        }
                    }
                    Edit::Replaced(value) => {
                        // SAFETY: Replaced is outside the Inserted
                        // families.
                        let at = unsafe { scanned_at(row) };
                        Arm::ReValue {
                            tag_end: at.as_inner() + row.tag_w(),
                            span_end: row.span_end(at),
                            value: self.scalar_word(row.kind, value),
                        }
                    }
                    Edit::Inserted(value) => {
                        if matches!(row.kind, RecordKind::Group) {
                            return Arm::NewGroup {
                                head: head_word(row.field, row.kind),
                                end_word: group_end_word(row.field),
                                first: self.slot_first(row.slot()),
                            };
                        }
                        Arm::NewValue {
                            head: head_word(row.field, row.kind),
                            value: self.scalar_word(row.kind, value),
                        }
                    }
                    Edit::ReplacedPayload(slot) => {
                        // SAFETY: ReplacedPayload is outside the
                        // Inserted families.
                        let at = unsafe { scanned_at(row) };
                        let tag_end = at.as_inner() + row.tag_w();
                        let prefix_end = tag_end + row.delim_w();
                        Arm::ReBody {
                            tag_end,
                            prefix_end,
                            src_len: row.span_end(at) - prefix_end,
                            slot,
                            span_end: row.span_end(at),
                        }
                    }
                    Edit::InsertedPayload(slot) => {
                        Arm::NewBody { head: head_word(row.field, row.kind), slot }
                    }
                }
            }

            /// One scalar store value, resolved for emission.
            fn scalar_word(&self, kind: RecordKind, value: ValueAt) -> Word {
                match kind {
                    RecordKind::Varint => Word::Varint(self.store.varint(value)),
                    RecordKind::I32 => Word::Bits32(self.store.bits32(value)),
                    RecordKind::I64 => Word::Bits64(self.store.bits64(value)),
                    // The value gates keep scalar states off LEN
                    // rows, and inserted groups settle before this
                    // resolver.
                    RecordKind::Len | RecordKind::Group => {
                        unreachable!("scalar value states sit on scalar rows")
                    }
                }
            }

            /// The sizing walk: postorder over the live rows,
            /// pricing every dirty LEN's rewritten body bottom-up
            /// (in walk order, for the booking walk to consume)
            /// and the grand total. No source walk; the scratch
            /// reserves fallibly.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
            /// outgrows the length class, [`SaveFault::Resource`]
            /// off the scratch reservations.
            #[allow(
                clippy::as_conversions,
                reason = "authored payload lengths were admitted to the length class, \
                          which fits u64"
            )]
            fn size_pass<E>(&self) -> Result<(u64, Vec<u64>), SaveFault<E>> {
                let mut bodies: Vec<u64> = Vec::new();
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        match frame {
                            SizeFrame::Len { next, outer, slot, prefix_w, src_len, at, tag_w } => {
                                let body = acc;
                                if body > u64::from(PayloadLen::MAX.as_inner()) {
                                    return Err(SaveFault::BodyOverCap { at });
                                }
                                bodies[slot] = body;
                                // The fidelity criterion: an
                                // unchanged body length keeps the
                                // source prefix, padding included.
                                let prefix = if body == src_len {
                                    u64::from(prefix_w.w())
                                } else {
                                    u64::from(encoded_len64(body))
                                };
                                acc = outer + u64::from(tag_w.w()) + prefix + body;
                                cur = next;
                            }
                            SizeFrame::Group { next, outer, framing } => {
                                acc += outer + framing;
                                cur = next;
                            }
                        }
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle(row) {
                        Arm::Skip { .. } => {}
                        Arm::Clean { end } => {
                            // SAFETY: the Clean arm settles scanned
                            // rows alone.
                            acc += end - unsafe { scanned_at(row) }.as_inner();
                        }
                        Arm::ReValue { value, .. } => {
                            acc += row.tag_w() + value.width();
                        }
                        Arm::NewValue { head, value } => {
                            acc += u64::from(encoded_len32(head)) + value.width();
                        }
                        Arm::ReBody { src_len, slot, .. } => {
                            let len = self.store.zone_bytes(slot).len() as u64;
                            let prefix = if len == src_len {
                                row.delim_w()
                            } else {
                                u64::from(encoded_len64(len))
                            };
                            acc += row.tag_w() + prefix + len;
                        }
                        Arm::NewBody { head, slot } => {
                            let len = self.store.zone_bytes(slot).len() as u64;
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len64(len))
                                + len;
                        }
                        Arm::Spine { src_len, first, .. } => {
                            bodies.try_reserve(1).map_err(save_alloc)?;
                            spine.try_reserve(1).map_err(save_alloc)?;
                            let slot = bodies.len();
                            bodies.push(0);
                            let (Some(tag_w), Some(prefix_w)) = (row.tag_width, row.delim_width)
                            else {
                                // Spines settle scanned LENs alone,
                                // whose scan stored both met widths.
                                unreachable!("spines carry met framing widths")
                            };
                            // SAFETY: spines settle scanned rows
                            // alone.
                            let at = unsafe { scanned_at(row) }.as_inner();
                            spine.push(SizeFrame::Len {
                                next: row.next,
                                outer: acc,
                                slot,
                                prefix_w,
                                src_len,
                                at,
                                tag_w,
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                        Arm::ReGroup { first, .. } => {
                            spine.try_reserve(1).map_err(save_alloc)?;
                            spine.push(SizeFrame::Group {
                                next: row.next,
                                outer: acc,
                                framing: row.tag_w() + row.delim_w(),
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                        Arm::NewGroup { head, end_word, first } => {
                            spine.try_reserve(1).map_err(save_alloc)?;
                            spine.push(SizeFrame::Group {
                                next: row.next,
                                outer: acc,
                                framing: u64::from(encoded_len32(head))
                                    + u64::from(encoded_len32(end_word)),
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

            /// The booking walk, funded per edge: every booking
            /// face reserves its own slot (a merged booking leaves
            /// spare capacity, never a missing one). One walk —
            /// opened LENs ride prefix slots settled at each
            /// close, so the compiled script carries the priced
            /// total in [`Script::out_len`].
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] at the refusing edge (the
            /// script is discarded whole),
            /// [`SaveFault::BodyOverCap`] when a settled interior
            /// outgrows the length class.
            fn compile<E>(&self) -> Result<Script<'a>, SaveFault<E>> {
                let mut script = Script::new();
                let mut lens: Vec<(u32, u64, u64)> = Vec::new();
                macro_rules! book {
                    (copy_to, $to:expr) => {
                        script.try_copy_to($to).map_err(save_alloc)?
                    };
                    (skip_to, $to:expr) => {
                        script.try_skip_to($to).map_err(save_alloc)?
                    };
                    (stage_word, $word:expr) => {
                        script.try_stage_word($word).map_err(save_alloc)?
                    };
                    (value, $value:expr) => {
                        match $value {
                            Word::Varint(word) => script.try_stage_word(word),
                            Word::Bits32(bits) => script.try_stage_bytes(&bits.to_le_bytes()),
                            Word::Bits64(bits) => script.try_stage_bytes(&bits.to_le_bytes()),
                        }
                        .map_err(save_alloc)?
                    };
                    (borrow, $bytes:expr) => {
                        script.try_borrow($bytes).map_err(save_alloc)?
                    };
                    (open_prefix, $start:expr, $end:expr) => {
                        script.try_open_prefix($start, $end).map_err(save_alloc)?
                    };
                }
                book_fidelity!(self, script, lens, book);
                Ok(script)
            }

            /// The canonical walk's verdict for one row, every
            /// value resolved at judgment time. Stored widths are
            /// not output widths here — they remain the
            /// source-geometry proof that locates each opaque
            /// payload.
            fn settle_canonical(&self, row: &Row) -> CanonicalArm {
                let head = head_word(row.field, row.kind);
                match row.edit {
                    Edit::Deleted(_)
                    | Edit::InsertedDeleted(_)
                    | Edit::DeletedPayload(_)
                    | Edit::InsertedDeletedPayload(_) => CanonicalArm::Skip,
                    Edit::Intact => {
                        // The walk never crosses an effective
                        // authored payload, so no authored-zone row
                        // is reachable.
                        debug_assert!(
                            !row.authored_zone(),
                            "the canonical walk stays in the closure"
                        );
                        // SAFETY: the Intact arm is outside the
                        // Inserted families.
                        let at = unsafe { scanned_at(row) };
                        match row.kind {
                            RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => {
                                CanonicalArm::Value {
                                    head,
                                    value: banked_word(row.kind, row.word_or_end.word(row.kind)),
                                }
                            }
                            RecordKind::Group => CanonicalArm::OpenGroup {
                                head,
                                first: self.slot_first(row.slot()),
                            },
                            RecordKind::Len => match row.slot() {
                                Slot::Opened(layer) => CanonicalArm::OpenLen {
                                    head,
                                    first: self.layer(layer).first,
                                    at: at.as_inner(),
                                },
                                // Unopened or faulted: the payload
                                // bytes are a declaration, not
                                // records — the closure ends here
                                // even when they happen to parse.
                                Slot::Unopened | Slot::Fault(_) => CanonicalArm::OpaqueLen {
                                    head,
                                    payload: CanonicalPayload::Doc {
                                        at: row.payload_at(at),
                                        len: row.value_extent(),
                                    },
                                },
                            },
                        }
                    }
                    Edit::Inserted(_) if matches!(row.kind, RecordKind::Group) => {
                        CanonicalArm::OpenGroup { head, first: self.slot_first(row.slot()) }
                    }
                    Edit::Replaced(value) | Edit::Inserted(value) => {
                        CanonicalArm::Value { head, value: self.scalar_word(row.kind, value) }
                    }
                    // An effective authored payload terminates the
                    // closure whatever rows a browse materialized.
                    Edit::ReplacedPayload(slot) | Edit::InsertedPayload(slot) => {
                        CanonicalArm::OpaqueLen { head, payload: CanonicalPayload::Store(slot) }
                    }
                }
            }

            /// The canonical booking walk, funded per edge (the
            /// ordinary compile's funding shape over the canonical
            /// arms). One walk — opened LENs ride minted prefix
            /// slots settled at each close, so the compiled script
            /// carries the priced total in [`Script::out_len`].
            ///
            /// # Errors
            ///
            /// [`SaveFault::Resource`] at the refusing edge (the
            /// script is discarded whole),
            /// [`SaveFault::BodyOverCap`] when a settled canonical
            /// body outgrows the length class.
            fn canonical_compile<E>(&self) -> Result<Script<'a>, SaveFault<E>> {
                let mut script = Script::new();
                let mut lens: Vec<(u32, u64, u64)> = Vec::new();
                macro_rules! book {
                    (copy_to, $to:expr) => {
                        script.try_copy_to($to).map_err(save_alloc)?
                    };
                    (skip_to, $to:expr) => {
                        script.try_skip_to($to).map_err(save_alloc)?
                    };
                    (stage_word, $word:expr) => {
                        script.try_stage_word($word).map_err(save_alloc)?
                    };
                    (value, $value:expr) => {
                        match $value {
                            Word::Varint(word) => script.try_stage_word(word),
                            Word::Bits32(bits) => script.try_stage_bytes(&bits.to_le_bytes()),
                            Word::Bits64(bits) => script.try_stage_bytes(&bits.to_le_bytes()),
                        }
                        .map_err(save_alloc)?
                    };
                    (borrow, $bytes:expr) => {
                        script.try_borrow($bytes).map_err(save_alloc)?
                    };
                    (open_minted_prefix) => {
                        script.try_open_minted_prefix().map_err(save_alloc)?
                    };
                }
                book_canonical!(self, script, lens, book);
                Ok(script)
            }

            /// The span walk: the booking walk's twin, advancing an
            /// output cursor instead of steps. Container entries
            /// open with their start and take their end at
            /// climb-out, when the interior has priced itself.
            fn span_walk<E>(
                &self,
                bodies: &[u64],
                entries: &mut Vec<(Handle, SourceSpan)>,
            ) -> Result<u64, SaveFault<E>> {
                let mut out: u64 = 0;
                let mut body_cursor = 0;
                // Entry indexes of open containers, patched at
                // climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = self.root.first;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        // A group's end tag prices at the close
                        // (verbatim when scanned, minimal when
                        // authored); only then does the entry take
                        // its end.
                        if matches!(row.kind, RecordKind::Group) {
                            out += match row.edit {
                                Edit::Intact => row.delim_w(),
                                Edit::Inserted(_) => {
                                    u64::from(encoded_len32(group_end_word(row.field)))
                                }
                                _ => unreachable!("only live groups open as save containers"),
                            };
                        }
                        let Some(at) = frames.pop() else {
                            unreachable!("maintain spans: climb without an open frame")
                        };
                        entries[at].1 = SourceSpan::new(entries[at].1.start(), out);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    #[allow(
                        clippy::as_conversions,
                        reason = "authored payload lengths were admitted to the length \
                                  class, which fits u64"
                    )]
                    match self.settle(row) {
                        Arm::Skip { .. } => {}
                        Arm::Clean { end } => {
                            self.verbatim_spans(id, out, entries);
                            // SAFETY: the Clean arm settles scanned
                            // rows alone.
                            out += end - unsafe { scanned_at(row) }.as_inner();
                        }
                        Arm::ReValue { value, .. } => {
                            let len = row.tag_w() + value.width();
                            entries.push((Handle(id), SourceSpan::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewValue { head, value } => {
                            let len = u64::from(encoded_len32(head)) + value.width();
                            entries.push((Handle(id), SourceSpan::new(out, out + len)));
                            out += len;
                        }
                        Arm::ReBody { src_len, slot, .. } => {
                            let plen = self.store.zone_bytes(slot).len() as u64;
                            let prefix = if plen == src_len {
                                row.delim_w()
                            } else {
                                u64::from(encoded_len64(plen))
                            };
                            let len = row.tag_w() + prefix + plen;
                            entries.push((Handle(id), SourceSpan::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewBody { head, slot } => {
                            let plen = self.store.zone_bytes(slot).len() as u64;
                            let len = u64::from(encoded_len32(head))
                                + u64::from(encoded_len64(plen))
                                + plen;
                            entries.push((Handle(id), SourceSpan::new(out, out + len)));
                            out += len;
                        }
                        Arm::Spine { src_len, first, .. } => {
                            let body = bodies[body_cursor];
                            body_cursor += 1;
                            let prefix = if body == src_len {
                                row.delim_w()
                            } else {
                                u64::from(encoded_len64(body))
                            };
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), SourceSpan::new(out, out)));
                            out += row.tag_w() + prefix;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                        Arm::ReGroup { first, .. } => {
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), SourceSpan::new(out, out)));
                            out += row.tag_w();
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                        Arm::NewGroup { head, first, .. } => {
                            frames.try_reserve(1).map_err(save_alloc)?;
                            frames.push(entries.len());
                            entries.push((Handle(id), SourceSpan::new(out, out)));
                            out += u64::from(encoded_len32(head));
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                Ok(out)
            }

            /// Span entries for one clean scanned subtree: every
            /// live row shifts by one delta — the subtree's output
            /// position against its source position. Ghosts
            /// contribute no entry and hide their (authored,
            /// never-emitted) interiors.
            fn verbatim_spans(
                &self,
                root: RowId,
                out: u64,
                entries: &mut Vec<(Handle, SourceSpan)>,
            ) {
                // SAFETY: the callers' clean arm admits only
                // scanned rows.
                let base = unsafe { scanned_at(self.row(root)) }.as_inner();
                let mut cur = Some(root);
                while let Some(id) = cur {
                    let row = self.row(id);
                    let live = matches!(row.edit, Edit::Intact);
                    if live {
                        // SAFETY: `Intact` is outside the Inserted
                        // families.
                        let at = unsafe { scanned_at(row) };
                        entries.push((
                            Handle(id),
                            SourceSpan::new(
                                at.as_inner() - base + out,
                                row.span_end(at) - base + out,
                            ),
                        ));
                    }
                    let kid = if live { self.slot_first(row.slot()) } else { None };
                    cur = kid.map_or_else(
                        || {
                            let mut climb = id;
                            loop {
                                if climb == root {
                                    break None;
                                }
                                let done = self.row(climb);
                                if let Some(next) = done.next {
                                    break Some(next);
                                }
                                match done.parent {
                                    Some(parent) => climb = parent,
                                    None => break None,
                                }
                            }
                        },
                        Some,
                    );
                }
            }
        }
    };
    (@set_payload copy, Machine: $Machine:ident) => {
            /// Replaces a LEN record's payload wholesale, orphaning
            /// any interior rows parsed out of the old payload. The
            /// payload is copied into the editor's store at the
            /// command — temporaries welcome; no payload lifetime
            /// binds the install. The payload's interior is the
            /// caller's declaration: it lands as opaque bytes,
            /// judged only if an explicit descend later commits it
            /// as a message. Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`], plus")]
            /// [`EditFault::EditedInterior`] while the interior
            /// carries edits or history and
            /// [`EditFault::PayloadTooLarge`] beyond the length
            /// class.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
                let witness = self.payload_gate(handle)?;
                self.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                let slot = self.store.push_bytes(payload).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(slot));
                Ok(())
            }
    };
    (@set_payload borrow <$plt:lifetime>, Machine: $Machine:ident) => {
            /// Replaces a LEN record's payload with a borrowed
            /// slice, orphaning any interior rows parsed out of the
            /// old payload. The slice is retained — not copied — as
            /// a fresh immutable slot the editor reads until it
            /// drops, so its owner must outlive the editor; earlier
            /// installs keep their own slots, which is what lets a
            /// revert restore the exact prior payload. The
            /// payload's interior is the caller's declaration: it
            /// lands as opaque bytes, judged only if an explicit
            /// descend later commits it as a message. Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`], plus")]
            /// [`EditFault::EditedInterior`] while the interior
            /// carries edits or history and
            /// [`EditFault::PayloadTooLarge`] beyond the length
            /// class.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(
                &mut self,
                handle: Handle,
                payload: &$plt [u8],
            ) -> Result<(), EditFault> {
                let witness = self.payload_gate(handle)?;
                self.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                let slot = self.store.push_slot(payload).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(slot));
                Ok(())
            }
    };
    (@set_payload mixed <$plt:lifetime>, Machine: $Machine:ident) => {
            /// Replaces a LEN record's payload with a borrowed
            /// slice, orphaning any interior rows parsed out of the
            /// old payload. The slice is retained — not copied — as
            /// a fresh immutable slot the editor reads until it
            /// drops, so its owner must outlive the editor (the
            /// escape hatch for temporaries is
            #[doc = concat!(" [`", stringify!($Machine), "::set_payload_copy`]); earlier installs keep")]
            /// their own slots, whichever backing they chose, which
            /// is what lets a revert restore the exact prior
            /// payload. The payload's interior is the caller's
            /// declaration: it lands as opaque bytes, judged only
            /// if an explicit descend later commits it as a
            /// message. Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`], plus")]
            /// [`EditFault::EditedInterior`] while the interior
            /// carries edits or history and
            /// [`EditFault::PayloadTooLarge`] beyond the length
            /// class.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(
                &mut self,
                handle: Handle,
                payload: &$plt [u8],
            ) -> Result<(), EditFault> {
                let witness = self.payload_gate(handle)?;
                self.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                let slot = self.store.push_slot(payload).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(slot));
                Ok(())
            }

            #[doc = concat!(" [`", stringify!($Machine), "::set_payload`]'s copying twin: the payload")]
            /// is copied into the editor's store at the command, so
            /// a transient owner may die right after the call — no
            /// payload lifetime binds the install. Everything else
            /// is the unsuffixed face's contract: one fresh
            /// immutable slot, the old interior orphaned, the
            /// interior opaque until an explicit descend.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload_copy(
                &mut self,
                handle: Handle,
                payload: &[u8],
            ) -> Result<(), EditFault> {
                let witness = self.payload_gate(handle)?;
                self.interior_gate(handle.0)?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.log.try_reserve(1).map_err(edit_resource)?;
                let slot = self.store.push_bytes(payload).map_err(edit_store_fault)?;
                self.apply_edit(handle.0, witness.set(slot));
                Ok(())
            }
    };
    (@insert_payload copy, Machine: $Machine:ident) => {
            /// Inserts a LEN record with an authored payload at the
            /// anchor, copied into the editor's store at the
            /// command. The payload's interior is the caller's
            /// declaration: it lands as opaque bytes, judged only
            /// if an explicit descend later commits it as a
            /// message. Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
            /// [`EditFault::PayloadTooLarge`] beyond the length
            /// class.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &[u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let slot = self.store.push_bytes(payload).map_err(edit_store_fault)?;
                self.apply_insert(
                    &plan,
                    id,
                    field,
                    RecordKind::Len,
                    Edit::InsertedDeletedPayload(slot),
                    Edit::InsertedPayload(slot),
                );
                Ok(Handle(id))
            }
    };
    (@insert_payload borrow <$plt:lifetime>, Machine: $Machine:ident) => {
            /// Inserts a LEN record with a borrowed authored
            /// payload at the anchor. The slice is retained — not
            /// copied — as a fresh immutable slot the editor reads
            /// until it drops, so its owner must outlive the
            /// editor. The payload's interior is the caller's
            /// declaration: it lands as opaque bytes, judged only
            /// if an explicit descend later commits it as a
            /// message. Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
            /// [`EditFault::PayloadTooLarge`] beyond the length
            /// class.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &$plt [u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let slot = self.store.push_slot(payload).map_err(edit_store_fault)?;
                self.apply_insert(
                    &plan,
                    id,
                    field,
                    RecordKind::Len,
                    Edit::InsertedDeletedPayload(slot),
                    Edit::InsertedPayload(slot),
                );
                Ok(Handle(id))
            }
    };
    (@insert_payload mixed <$plt:lifetime>, Machine: $Machine:ident) => {
            /// Inserts a LEN record with a borrowed authored
            /// payload at the anchor. The slice is retained — not
            /// copied — as a fresh immutable slot the editor reads
            /// until it drops, so its owner must outlive the editor
            /// (the escape hatch for temporaries is
            #[doc = concat!(" [`", stringify!($Machine), "::insert_payload_copy`]). The payload's")]
            /// interior is the caller's declaration: it lands as
            /// opaque bytes, judged only if an explicit descend
            /// later commits it as a message. Walk-free.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
            /// [`EditFault::PayloadTooLarge`] beyond the length
            /// class.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &$plt [u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let slot = self.store.push_slot(payload).map_err(edit_store_fault)?;
                self.apply_insert(
                    &plan,
                    id,
                    field,
                    RecordKind::Len,
                    Edit::InsertedDeletedPayload(slot),
                    Edit::InsertedPayload(slot),
                );
                Ok(Handle(id))
            }

            #[doc = concat!(" [`", stringify!($Machine), "::insert_payload`]'s copying twin: the")]
            /// payload is copied into the editor's store at the
            /// command — the face for temporaries.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[inline]
            #[track_caller]
            pub fn insert_payload_copy(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &[u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                self.rows.try_reserve(1).map_err(edit_resource)?;
                self.log.try_reserve(1).map_err(edit_resource)?;
                let slot = self.store.push_bytes(payload).map_err(edit_store_fault)?;
                self.apply_insert(
                    &plan,
                    id,
                    field,
                    RecordKind::Len,
                    Edit::InsertedDeletedPayload(slot),
                    Edit::InsertedPayload(slot),
                );
                Ok(Handle(id))
            }
    };
}

/// The descend target's backing, judged once per call.
enum DescendBacking {
    /// Resident authored bytes: one slot's zone extent.
    Authored {
        /// The backing slot.
        slot: SlotAt,
        /// The extent's start in the slot's zone.
        start: u64,
        /// The extent's end in the slot's zone.
        end: u64,
    },
    /// A fresh measured source extent.
    Source {
        /// The extent's whole-source start.
        start: u64,
        /// The extent's whole-source end.
        end: u64,
    },
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

maintain_machine! {
    #[doc = " A maintenance editor over a stable-replay source, with"]
    #[doc = " copied payloads."]
    #[doc = ""]
    #[doc = " Handles stay valid for the editor's life unless a payload"]
    #[doc = " replacement orphans the rows parsed out of the old payload;"]
    #[doc = " orphaned handles answer with [`EditFault::DeadHandle`]. Undo"]
    #[doc = " is exact: [`Maintain::revert`] walks the log backwards and"]
    #[doc = " restores the save-observable state of the previous step —"]
    #[doc = " byte fidelity included, padding and all, with zero walks;"]
    #[doc = " orphaned handles are not revived."]
    #[doc = ""]
    #[doc = " Editor storage grows monotonically: rows and stored values"]
    #[doc = " are never reclaimed (the handle contract names them for the"]
    #[doc = " editor's life), and each descend of a re-sealed container"]
    #[doc = " mints fresh interior rows, a fresh layer descriptor, and —"]
    #[doc = " for source-backed payloads — a fresh run entry, leaving the"]
    #[doc = " orphaned ones behind inert. Each replace → revert →"]
    #[doc = " re-descend cycle therefore re-mints the whole interior (the"]
    #[doc = " source-backed re-descend costing one fresh walk); a"]
    #[doc = " long-lived editor budgets for that growth or reopens the"]
    #[doc = " document at its checkpoints."]
    #[doc = ""]
    #[doc = " Plain data over the moved-in source handle: no share"]
    #[doc = " counting, no interior mutability — the machine is"]
    #[doc = " `Send + Sync` exactly when `S` is, and a mid-edit editor"]
    #[doc = " moves, returns, and caches freely (rows address the source"]
    #[doc = " by coordinates, never pointers)."]
    #[doc = ""]
    #[doc = " The canonical-output faces (the `save_canonical` family)"]
    #[doc = " ride every payload-backing form — this one,"]
    #[doc = " [`BorrowMaintain`], and [`MixMaintain`] — without changing"]
    #[doc = " any form's lifetime or allocation profile."]
    machine Maintain,
    store: Store,
    pay: copy,
    door: "Maintain::open(SliceSource::new(&msg))",
}

maintain_machine! {
    #[doc = " A maintenance editor over a stable-replay source, with"]
    #[doc = " borrowed payloads: [`Maintain`]'s sibling for callers whose"]
    #[doc = " payload bytes outlive the machine."]
    #[doc = ""]
    #[doc = " `set_payload` and `insert_payload` take `&'p [u8]` and"]
    #[doc = " retain the slice — no staging copy — as a fresh immutable"]
    #[doc = " slot per install; earlier installs keep their slots, so a"]
    #[doc = " revert restores the exact prior payload. The price is the"]
    #[doc = " profile: every payload owner must outlive the editor, `'p`"]
    #[doc = " rides the type beside the source parameter, and the staged"]
    #[doc = " payload frames (which exist to copy chunks in) have no"]
    #[doc = " place here. Saves copy each live payload once into the"]
    #[doc = " output; `save_sink` hands the slices through; the saved"]
    #[doc = " bytes carry no borrow."]
    #[doc = ""]
    #[doc = " Everything else is [`Maintain`]'s contract: tolerant"]
    #[doc = " admission, byte fidelity for untouched records, exact undo,"]
    #[doc = " and monotonic storage — and it stays plain data over its"]
    #[doc = " source handle and payload borrows."]
    machine BorrowMaintain<'p>,
    store: BorrowStore<'p>,
    pay: borrow,
    door: "BorrowMaintain::open(SliceSource::new(&msg))",
}

maintain_machine! {
    #[doc = " A maintenance editor over a stable-replay source, with"]
    #[doc = " per-install payload backing."]
    #[doc = ""]
    #[doc = " [`Maintain`]'s sibling for callers who mix long-lived"]
    #[doc = " payload slices with transient ones on one handle arena and"]
    #[doc = " one revision log."]
    #[doc = ""]
    #[doc = " Each install selects its backing at the face. The unsuffixed"]
    #[doc = " faces (`set_payload`, `insert_payload`) take `&'p [u8]` and"]
    #[doc = " retain the slice — no staging copy, the owner must outlive"]
    #[doc = " the editor. Their `_copy` twins (`set_payload_copy`,"]
    #[doc = " `insert_payload_copy`) and the staged payload frames"]
    #[doc = " (`begin_set_payload` and kin, which exist to copy chunks in"]
    #[doc = " and so carry no `_copy` suffix) copy the bytes into the"]
    #[doc = " editor, so temporaries pass through them freely. Either way"]
    #[doc = " each install appends one immutable slot; earlier installs"]
    #[doc = " keep theirs, whichever backing they chose, so a revert"]
    #[doc = " restores the exact prior payload — and the save's byte"]
    #[doc = " fidelity, padding included, reads exactly as [`Maintain`]'s."]
    #[doc = ""]
    #[doc = " `'p` and the source handle are independent: either may"]
    #[doc = " outlive the other, provided both cover the machine's use."]
    machine MixMaintain<'p>,
    store: MixStore<'p>,
    pay: mixed,
    door: "MixMaintain::open(SliceSource::new(&msg))",
}

// The machine layouts, pinned exactly over the slice source so the
// store forms' deltas stay reviewable: the borrowed form is one
// Vec lighter (24 bytes on 64-bit pointers; on 32-bit the
// machine's 8-alignment absorbs part of it and the saving is
// eight), and the mixed form matches the copy form (the tagged
// slot table rides the copied store's own five headers). Size
// pins, not field-semantics proofs: any layout change lands here
// for review.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    let copy = core::mem::size_of::<Maintain<SliceSource<'_>>>();
    let borrow = core::mem::size_of::<BorrowMaintain<'_, SliceSource<'_>>>();
    let mixed = core::mem::size_of::<MixMaintain<'_, SliceSource<'_>>>();
    assert!(copy == if w64 { 288 } else { 160 });
    assert!(borrow + if w64 { 24 } else { 8 } == copy);
    assert!(mixed == copy);
};

// ─── the staged payload frames ───

/// The command a staged payload frame closes with.
#[derive(Clone, Copy)]
enum FrameOp {
    /// Replace an existing LEN's payload.
    Set {
        /// The gated target.
        handle: Handle,
        /// The live-edit witness the gates produced.
        witness: LivePayload,
    },
    /// Insert a fresh LEN record at a resolved splice point.
    Insert {
        /// The proven anchor.
        plan: InsertPlan,
        /// The new record's field.
        field: FieldNumber,
    },
}

/// Why a sized payload frame refused: the declaration judgments,
/// plus exactly the two failure classes the publishing close can
/// meet.
///
/// The frame faces carry their own alphabet because the
/// declaration judgments exist nowhere else — the editor's command
/// faces keep a frame-free [`EditFault`].
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FrameFault {
    /// The staged bytes would pass the frame's declaration.
    OverDeclared {
        /// The declared payload length.
        declared: u32,
        /// The staged total the refused write would reach.
        total: u64,
    },
    /// The frame finished short of its declaration; nothing was
    /// installed.
    UnderDeclared {
        /// The declared payload length.
        declared: u32,
        /// The bytes actually staged.
        staged: u32,
    },
    /// The allocator refused growth at the publishing close; the
    /// staged bytes are reclaimed with the frame and the command
    /// may be restaged.
    Resource,
    /// The editor's edit storage is full; the refusal is permanent
    /// for this editor.
    IndexSpaceExhausted,
}

impl core::fmt::Display for FrameFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::OverDeclared { declared, total } => {
                write!(f, "staged payload of {total} bytes passes its declared length {declared}")
            }
            Self::UnderDeclared { declared, staged } => write!(
                f,
                "staged payload of {staged} bytes falls short of its declared length {declared}"
            ),
            Self::Resource => f.write_str("allocator refused editor growth"),
            Self::IndexSpaceExhausted => f.write_str("the editor's edit storage is full"),
        }
    }
}

impl core::error::Error for FrameFault {}

/// Maps the publishing close's faults onto the frame alphabet.
/// Total by the close's own domain: it reserves and mints only, so
/// only the resource and coordinate classes arise there.
#[cold]
fn close_fault(fault: EditFault) -> FrameFault {
    match fault {
        EditFault::Resource => FrameFault::Resource,
        EditFault::IndexSpaceExhausted => FrameFault::IndexSpaceExhausted,
        _ => unreachable!("the publishing close reserves and mints only"),
    }
}

/// Emits the staged payload frames — the chunked copying doors —
/// for one copying-capable machine form.
macro_rules! maintain_frames {
    ($Machine:ident $(<$plt:lifetime>)?, $Frame:ident, $SizedFrame:ident) => {
        impl<$($plt,)? S: StableReplaySource> $Machine<$($plt,)? S> {
            /// Opens a staged replacement of the LEN record's
            /// payload: chunks copy into the editor's store through
            /// the returned frame, and exactly one logged
            /// transition applies at
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish) — before it, no row or log")]
            /// state changes, so a revert can never see a
            /// half-staged command. The gates judge here, so the
            /// frame itself cannot discover a refused target.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`]'s gates. On `Err` the")]
            /// editor's observable edit state is unchanged.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[track_caller]
            pub fn begin_set_payload(
                &mut self,
                handle: Handle,
            ) -> Result<$Frame<'_, $($plt,)? S>, EditFault> {
                let witness = self.payload_gate(handle)?;
                self.interior_gate(handle.0)?;
                let mark = self.store.stage_mark();
                Ok($Frame { machine: self, op: FrameOp::Set { handle, witness }, mark })
            }

            /// Opens a staged insertion of a fresh LEN record at
            /// the anchor: chunks copy into the editor's store
            /// through the returned frame, and exactly one row
            /// splices — with its one logged transition — at
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish). The anchor resolves here;")]
            /// the frame's exclusive borrow keeps it valid through
            /// the close.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor gates. On")]
            /// `Err` the editor's observable edit state is
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[track_caller]
            pub fn begin_insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
            ) -> Result<$Frame<'_, $($plt,)? S>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let mark = self.store.stage_mark();
                Ok($Frame { machine: self, op: FrameOp::Insert { plan, field }, mark })
            }

            /// Judges a length-class declaration into the store's
            /// byte column and reserves its bytes exactly once —
            /// the sized doors' shared suffix. Both judgments
            /// precede the fallible reservation, so a refusal
            /// allocates nothing.
            fn stage_declare(&mut self, len: usize) -> Result<u32, EditFault> {
                if len > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len });
                }
                self.store.stage_reserve(len).map_err(edit_store_fault)?;
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::as_conversions,
                    reason = "just judged against the length class, which is below u32::MAX"
                )]
                Ok(len as u32)
            }

            #[doc = concat!(" [`begin_set_payload`](", stringify!($Machine), "::begin_set_payload)'s")]
            /// declared-length twin: the caller states the
            /// payload's exact byte length up front, so the class
            /// judgment lands here — zero allocation on refusal —
            /// and the store's byte column reserves exactly once,
            /// fallibly. The frame is held to its word: a write
            /// past the declaration refuses
            /// [`FrameFault::OverDeclared`], a finish short of it
            /// refuses [`FrameFault::UnderDeclared`], and either
            /// fault leaves the editor's observable edit state
            /// unchanged. The undeclared door serves callers
            /// streaming an unknown total.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_set_payload`]'s gates, plus")]
            /// [`EditFault::PayloadTooLarge`] when `len` exceeds
            /// the length class — judged before anything is
            /// reserved — [`EditFault::IndexSpaceExhausted`] when
            /// the store's byte column cannot hold `len` more
            /// bytes, and [`EditFault::Resource`] when the
            /// allocator refuses the reservation. On `Err` the
            /// editor's observable edit state is unchanged.
            ///
            /// # Panics
            ///
            /// Panics if `handle` was not minted by this editor
            /// (the arena index contract).
            #[track_caller]
            pub fn begin_set_payload_sized(
                &mut self,
                handle: Handle,
                len: usize,
            ) -> Result<$SizedFrame<'_, $($plt,)? S>, EditFault> {
                let witness = self.payload_gate(handle)?;
                self.interior_gate(handle.0)?;
                let declared = self.stage_declare(len)?;
                let mark = self.store.stage_mark();
                Ok($SizedFrame {
                    inner: $Frame { machine: self, op: FrameOp::Set { handle, witness }, mark },
                    declared,
                })
            }

            #[doc = concat!(" [`begin_insert_payload`](", stringify!($Machine), "::begin_insert_payload)'s")]
            /// declared-length twin
            #[doc = concat!(" ([`", stringify!($Machine), "::begin_set_payload_sized`]'s door contract,")]
            /// at an anchor).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_insert_payload`]'s anchor gates,")]
            /// plus the sized door's judgments:
            /// [`EditFault::PayloadTooLarge`] when `len` exceeds
            /// the length class — judged before anything is
            /// reserved — [`EditFault::IndexSpaceExhausted`] when
            /// the store's byte column cannot hold `len` more
            /// bytes, and [`EditFault::Resource`] when the
            /// allocator refuses the reservation. On `Err` the
            /// editor's observable edit state is unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted
            /// by this editor (the arena index contract).
            #[track_caller]
            pub fn begin_insert_payload_sized(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                len: usize,
            ) -> Result<$SizedFrame<'_, $($plt,)? S>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let declared = self.stage_declare(len)?;
                let mark = self.store.stage_mark();
                Ok($SizedFrame {
                    inner: $Frame { machine: self, op: FrameOp::Insert { plan, field }, mark },
                    declared,
                })
            }
        }

        /// A fallible staged payload frame.
        ///
        /// Chunks copy into the editor's store as they arrive, and
        /// exactly one command — one logged transition — applies at
        #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish): before it, no row or log state")]
        /// changes, so a revert can never see a half-staged command
        /// and any refusal (allocator faults included) leaves the
        /// editor's observable edit state unchanged. Dropping the
        /// frame unfinished reclaims its staged bytes — the
        /// editor's store returns to its pre-frame byte cursor,
        /// slot table, and offset space; capacity gained while
        /// staging may be retained for reuse — and its exclusive
        /// borrow of the editor keeps every other command out while
        /// it lives.
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct $Frame<'s, $($plt,)? S: StableReplaySource> {
            machine: &'s mut $Machine<$($plt,)? S>,
            op: FrameOp,
            /// The store's byte-column tail at open: the staged
            /// extent is `mark..` for the frame's whole life, in
            /// the zone-offset domain by the column's push
            /// judgments.
            mark: u32,
        }

        impl<$($plt,)? S: StableReplaySource> Drop for $Frame<'_, $($plt,)? S> {
            /// Reclaims the staged extent: only a publishing
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish) keeps the staged bytes, so")]
            /// abandonment and every refusal path leave the store's
            /// byte cursor, slot table, and offset space exactly as
            /// the door found them (reserved capacity may be
            /// retained).
            fn drop(&mut self) {
                self.machine.store.stage_abandon(self.mark);
            }
        }

        impl<$($plt,)? S: StableReplaySource> $Frame<'_, $($plt,)? S> {
            /// Appends one chunk to the staged payload, copying it
            /// at the call — temporaries welcome; the store owns
            /// them. An empty chunk is a no-op.
            ///
            /// # Errors
            ///
            /// [`EditFault::PayloadTooLarge`] when the staged total
            /// would leave the length class,
            /// [`EditFault::Resource`] when the store cannot grow,
            /// [`EditFault::IndexSpaceExhausted`] when its
            /// coordinate space is spent. On `Err` the chunk is not
            /// staged and the frame stays usable.
            pub fn write(&mut self, chunk: &[u8]) -> Result<(), EditFault> {
                let staged = u64::from(self.machine.store.stage_mark() - self.mark);
                #[allow(
                    clippy::as_conversions,
                    reason = "chunk lengths widen losslessly to u64"
                )]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(PayloadLen::MAX.as_inner()) {
                    let len = usize::try_from(total).unwrap_or(usize::MAX);
                    return Err(EditFault::PayloadTooLarge { len });
                }
                self.machine.store.stage_chunk(chunk).map_err(edit_store_fault)?;
                Ok(())
            }

            /// Installs the staged payload: the set flips its
            /// record, the insert splices exactly one fresh row —
            /// one logged transition either way, appended now.
            /// Returns the changed record's handle (the set's own
            /// target, or the minted insertion).
            ///
            /// # Errors
            ///
            /// [`EditFault::Resource`] when the row or log
            /// reservation is refused,
            /// [`EditFault::IndexSpaceExhausted`] when a coordinate
            /// space is spent. On `Err` the editor's observable
            /// edit state is unchanged — the staged bytes are
            /// reclaimed with the frame, so the whole command may
            /// be restaged and retried.
            pub fn finish(mut self) -> Result<Handle, EditFault> {
                match self.apply() {
                    Ok(handle) => {
                        // Published: the slot now covers the staged
                        // extent, so defuse the drop reclamation.
                        core::mem::forget(self);
                        Ok(handle)
                    }
                    // Dropping the frame reclaims the staged
                    // extent.
                    Err(fault) => Err(fault),
                }
            }

            /// The publishing close: reserves, mints the slot,
            /// applies the one command.
            fn apply(&mut self) -> Result<Handle, EditFault> {
                match self.op {
                    FrameOp::Set { handle, witness } => {
                        // The gates judged at open; the frame's
                        // exclusive borrow kept the row exactly as
                        // they left it.
                        self.machine.log.try_reserve(1).map_err(edit_resource)?;
                        let slot =
                            self.machine.store.stage_finish(self.mark).map_err(edit_store_fault)?;
                        self.machine.apply_edit(handle.0, witness.set(slot));
                        Ok(handle)
                    }
                    FrameOp::Insert { plan, field } => {
                        let id = self.machine.mint_insert()?;
                        self.machine.rows.try_reserve(1).map_err(edit_resource)?;
                        self.machine.log.try_reserve(1).map_err(edit_resource)?;
                        let slot =
                            self.machine.store.stage_finish(self.mark).map_err(edit_store_fault)?;
                        self.machine.apply_insert(
                            &plan,
                            id,
                            field,
                            RecordKind::Len,
                            Edit::InsertedDeletedPayload(slot),
                            Edit::InsertedPayload(slot),
                        );
                        Ok(Handle(id))
                    }
                }
            }
        }

        /// A fallible staged payload frame held to a declared
        /// length.
        ///
        /// The declaration was judged and its bytes reserved when
        /// the door opened
        #[doc = concat!(" ([`", stringify!($Machine), "::begin_set_payload_sized`],")]
        #[doc = concat!(" [`", stringify!($Machine), "::begin_insert_payload_sized`]), so staging never")]
        /// regrows the column; a write past the declaration refuses
        /// [`FrameFault::OverDeclared`] and [`finish`](Self::finish)
        /// installs only the exact declared extent —
        /// [`FrameFault::UnderDeclared`] otherwise. The declaration
        /// judgments live on the frame faces alone, so the sized
        /// faces speak [`FrameFault`]; everything else is the
        /// undeclared frame's contract: chunks copy in as they
        /// arrive, exactly one logged transition applies at the
        /// finish, and a dropped or refused frame reclaims its
        /// staged bytes.
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct $SizedFrame<'s, $($plt,)? S: StableReplaySource> {
            inner: $Frame<'s, $($plt,)? S>,
            /// The declared payload length, in the length class.
            declared: u32,
        }

        impl<$($plt,)? S: StableReplaySource> $SizedFrame<'_, $($plt,)? S> {
            /// Appends one chunk to the staged payload, copying it
            /// at the call into the bytes the door reserved —
            /// spending the door's proof: no bound, domain, or
            /// allocator judgment re-runs here, only the
            /// declaration compare below. An empty chunk is a
            /// no-op.
            ///
            /// # Errors
            ///
            /// [`FrameFault::OverDeclared`] when the staged total
            /// would pass the declaration. On `Err` the chunk is
            /// not staged and the frame stays usable.
            pub fn write(&mut self, chunk: &[u8]) -> Result<(), FrameFault> {
                let staged = u64::from(self.inner.machine.store.stage_mark() - self.inner.mark);
                #[allow(
                    clippy::as_conversions,
                    reason = "chunk lengths widen losslessly to u64"
                )]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(self.declared) {
                    return Err(FrameFault::OverDeclared { declared: self.declared, total });
                }
                // The door judged the declaration into the length
                // class and the byte column's offset domain and
                // reserved its bytes; the gate above bounds the
                // staged total inside the declaration, so this
                // append stays inside both.
                self.inner.machine.store.stage_chunk_reserved(chunk);
                Ok(())
            }

            /// Installs the staged payload exactly as declared —
            /// the undeclared frame's
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish), behind the declaration")]
            /// judgment.
            ///
            /// # Errors
            ///
            /// [`FrameFault::UnderDeclared`] when fewer bytes than
            /// declared were staged, then the publishing close's
            /// faults: [`FrameFault::Resource`] when the row or log
            /// reservation is refused,
            /// [`FrameFault::IndexSpaceExhausted`] when a
            /// coordinate space is spent. On `Err` the editor's
            /// observable edit state is unchanged — the staged
            /// bytes are reclaimed with the frame.
            pub fn finish(self) -> Result<Handle, FrameFault> {
                let staged = self.inner.machine.store.stage_mark() - self.inner.mark;
                if staged != self.declared {
                    return Err(FrameFault::UnderDeclared { declared: self.declared, staged });
                }
                self.inner.finish().map_err(close_fault)
            }
        }
    };
}

maintain_frames!(Maintain, PayloadFrame, SizedPayloadFrame);
maintain_frames!(MixMaintain<'p>, MixPayloadFrame, MixSizedPayloadFrame);

// ─── views ───

/// The table entry a machine-minted link names.
///
/// # Safety
///
/// `index` must come from a link this machine minted for `table` —
/// row ids from arena appends and the `next`/`parent` links rows
/// store, layer ids from the pushes that seal opened slots. The
/// tables never shrink, so every minted link stays in-table for
/// the machine's whole life.
#[inline]
unsafe fn linked<T>(table: &[T], index: usize) -> &T {
    debug_assert!(index < table.len(), "links are minted in-table");
    // SAFETY: the caller's link provenance covers the index.
    unsafe { table.get_unchecked(index) }
}

/// The next row of a preorder walk bounded to `root`'s subtree:
/// down the first child, across the sibling chain, climbing on
/// exhaustion — no stack, no recursion, no allocation.
fn preorder_next(rows: &[Row], layers: &[Layer], from: RowId, root: RowId) -> Option<RowId> {
    // SAFETY: `from` is a minted row (the walk starts at one and
    // yields only minted links), and an `Opened` slot's layer id
    // was minted by the push that sealed it.
    if let Slot::Opened(layer) = unsafe { linked(rows, from.index()) }.slot()
        && let Some(kid) = unsafe { linked(layers, layer.index()) }.first
    {
        return Some(kid);
    }
    let mut cur = from;
    loop {
        if cur == root {
            return None;
        }
        // SAFETY: `cur` starts at the minted `from` and advances
        // only through rows' own `parent` links.
        let row = unsafe { linked(rows, cur.index()) };
        if let Some(next) = row.next {
            return Some(next);
        }
        cur = row.parent?;
    }
}

/// Sibling records in wire order (shrouded records and ghosts
/// included — topology is monotone, presentation filters).
#[must_use]
pub struct Children<'s> {
    rows: &'s [Row],
    cur: Option<RowId>,
}

impl<'s> Children<'s> {
    /// Narrows to records of one field, preserving wire order.
    #[inline]
    pub fn by_field(self, field: FieldNumber) -> impl Iterator<Item = Handle> + 's {
        let rows = self.rows;
        // SAFETY: the iterator yields minted links only (see
        // `next`).
        self.filter(move |handle| unsafe { linked(rows, handle.0.index()) }.field == field)
    }
}

impl Iterator for Children<'_> {
    type Item = Handle;

    #[inline]
    fn next(&mut self) -> Option<Handle> {
        let id = self.cur?;
        // SAFETY: the chain starts at a layer's minted anchor and
        // every later id is again a row's own `next` link.
        self.cur = unsafe { linked(self.rows, id.index()) }.next;
        Some(Handle(id))
    }
}

impl core::iter::FusedIterator for Children<'_> {}

/// A record's ancestor chain, innermost container first.
#[must_use]
pub struct Ancestors<'s> {
    rows: &'s [Row],
    cur: Option<RowId>,
}

impl Iterator for Ancestors<'_> {
    type Item = Handle;

    #[inline]
    fn next(&mut self) -> Option<Handle> {
        let id = self.cur?;
        // SAFETY: the chain starts at a live row's parent link and
        // every later id is again a row's own `parent` link.
        self.cur = unsafe { linked(self.rows, id.index()) }.parent;
        Some(Handle(id))
    }
}

impl core::iter::FusedIterator for Ancestors<'_> {}

/// The output-order span table of one priced save: every emitted
/// record's handle against its whole-record span in the output —
/// `save_spans`'s product.
///
/// Entries follow output order (a container precedes and encloses
/// its interior), and the farthest span end is the save's exact
/// length.
#[must_use]
#[derive(Debug)]
pub struct SaveSpans {
    entries: Vec<(Handle, SourceSpan)>,
}

impl SaveSpans {
    /// The number of emitted records in the table.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the save carries no records.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries in output order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (Handle, SourceSpan)> + '_ {
        self.entries.iter().copied()
    }
}
