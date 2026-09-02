//! The groupless fixed-scratch one-shot patch: borrowed input,
//! width-carrying rows, commit-only edits over caller-supplied
//! working memory, and byte-fidelity saves into a caller slice or
//! sink.
//!
//! This dialect speaks the four-code wire language: group codes
//! are well-formed wire outside it, refused as a capability
//! judgment ([`Refusal::GroupCode`]) distinct from grammar faults
//! — at the root that refusal stops the open, inside a payload it
//! is a resident verdict and the payload stays readable as bytes.
//!
//! Admission is tolerant: padded tags, length prefixes, and varint
//! values are lawful input, so every framing width the scan meets
//! is stored on the row as an input fact and every untouched span
//! reproduces its padding byte-exactly at save. The root layer is
//! flat and eager; LEN payloads stay opaque until
//! [`Patch::descend`], whose verdict is resident. Descent is an
//! explicit commitment: nothing here speculates a payload into a
//! message.
//!
//! Commands commit: there is no revision log and no way to restore a
//! deleted record — dropping the machine discards the plan. Every
//! mutation is transactional: every judgment — semantic gates and
//! lane capacity alike — comes before the first state change, so an
//! `Err` from any command leaves the machine's observable state
//! untouched. Working memory is the caller's slab, carved once at
//! the door under the plan's capacity contract; capacity exhaustion
//! is a deterministic [`ScratchExhausted`](EditFault::ScratchExhausted)
//! refusal naming the lane, never an abort, and the machine stays
//! usable after it. No face of this module calls the allocator.
//!
//! Within its plan, behavior is byte-identical to the heap patch
//! cell: the fidelity contract (untouched records ride bit-exact,
//! padding included; replaced records keep their source tags; a LEN
//! prefix rides verbatim while its body length is unchanged), the
//! canonical contract (`save_canonical_into`/`save_canonical_sink`
//! minimally emit every varint construct in the materialized
//! commitment closure), and every verdict and fault value match the
//! heap twin's — only the output faces change deployment: `save_into`
//! fills a caller slice, refusing [`SaveFault::OutputShort`] with
//! zero bytes written, and the sink faces hand borrowed slices out.
//!
//! Coordinates: write · buffered · offline · groupless · tolerant (type-level) · borrowed · commit-only · fixed scratch.
//!
//! # Examples
//!
//! ```
//! use core::mem::MaybeUninit;
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::fixed_patch::groupless::{Patch, Plan};
//!
//! // varint f1=150 (value padded to two bytes) · LEN f2 "hi"
//! let msg = [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x68, 0x69];
//! let plan = Plan::new(4, 2, 2, 16, 2).unwrap();
//! let mut slab = [MaybeUninit::<u8>::uninit(); 512];
//! let mut patch = Patch::open(&msg, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
//!
//! let second = patch.top().nth(1).unwrap();
//! patch.set_payload(second, b"no").unwrap();
//!
//! // The padded varint rode verbatim; the same-length payload
//! // kept its prefix. The output is the caller's own buffer.
//! let mut out = [0u8; 8];
//! let written = patch.save_into(&mut out).unwrap();
//! assert_eq!(&out[..written as usize], [0x08, 0x96, 0x81, 0x00, 0x12, 0x02, 0x6E, 0x6F]);
//! ```

use core::mem::MaybeUninit;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::fixed_patch::{
    BorrowBudget, BorrowedPayloadStore, BorrowedSlot, Budget, CopiedPayloadStore, Handle, Lane,
    PayloadAt, PayloadSlot, PayloadStore, RowId, ScratchRole, WordAt, WordStore, admit,
    parts_len_usize,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{WordWidth, emit64, encoded_len32, encoded_len64};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

pub use crate::fixed_patch::{EditStatus, InsertAt};

// ─── faults ───

/// A wire-grammar violation: where it struck and what it is.
///
/// `at` is the offset of the construct the kind names — the tag
/// word, length word, varint value, or payload start.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    /// Offset of the faulted construct.
    pub at: u32,
    /// The violation found there.
    pub kind: FaultKind,
}

/// Wire-grammar violations this dialect can meet. The set is the
/// grammar's own closed alphabet — deliberately exhaustive, so
/// downstream matches are a stable promise.
///
/// A fault judged after the head tag revealed its field number
/// carries that field; the tag's own faults carry none — no field
/// exists yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// The tag word failed to read.
    Tag {
        /// The kernel's refusal.
        fault: ReadFault,
    },
    /// The tag word names field zero, which the format never
    /// assigns.
    FieldZero,
    /// The tag word carries a code the format leaves unassigned.
    Unassigned {
        /// The field the tag names (judged before the code).
        field: FieldNumber,
        /// The unassigned code bits.
        low3: Low3,
    },
    /// A LEN length word failed to read.
    Len {
        /// The record's field number.
        field: FieldNumber,
        /// The kernel's refusal.
        fault: ReadFault,
    },
    /// A varint value failed to read.
    Value {
        /// The record's field number.
        field: FieldNumber,
        /// The kernel's refusal.
        fault: ReadFault,
    },
    /// A fixed-width value or a LEN payload runs past its extent.
    PayloadCut {
        /// The record's field number.
        field: FieldNumber,
        /// Bytes the record claims.
        need: u32,
        /// Bytes the extent still holds.
        have: u32,
    },
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let at = self.at;
        match self.kind {
            FaultKind::Tag { fault } => write!(f, "tag word at {at}: {fault}"),
            FaultKind::FieldZero => write!(f, "tag word at {at} names field zero"),
            FaultKind::Unassigned { field, low3 } => write!(
                f,
                "tag word at {at} carries unassigned code {} on field {}",
                low3.as_inner(),
                field.as_inner()
            ),
            FaultKind::Len { field, fault } => {
                write!(f, "length word of field {} at {at}: {fault}", field.as_inner())
            }
            FaultKind::Value { field, fault } => {
                write!(f, "varint value of field {} at {at}: {fault}", field.as_inner())
            }
            FaultKind::PayloadCut { field, need, have } => write!(
                f,
                "payload of field {} at {at} claims {need} bytes but the extent holds {have}",
                field.as_inner()
            ),
        }
    }
}

impl core::error::Error for Fault {}

/// Lawful wire this machine refuses: outside its language or its
/// declared bounds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// A group code: well-formed wire outside this dialect's
    /// language — the capability refusal.
    GroupCode {
        /// Offset of the tag word.
        at: u32,
        /// The field the tag names.
        field: FieldNumber,
        /// The group code bits (3 or 4).
        low3: Low3,
    },
    /// Opening this container would nest past the declared
    /// [`DepthLimit`] bound.
    DepthExceeded {
        /// Offset of the container's head tag.
        at: u32,
        /// The container's field.
        field: FieldNumber,
    },
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::GroupCode { at, field, low3 } => write!(
                f,
                "tag word at {at} carries group code {} on field {} — outside this dialect",
                low3.as_inner(),
                field.as_inner()
            ),
            Self::DepthExceeded { at, field } => write!(
                f,
                "container of field {} at {at} nests past the declared depth bound",
                field.as_inner()
            ),
        }
    }
}

impl core::error::Error for Refusal {}

/// Why a fixed patch refused to open. On any `Err` no machine is
/// published and the slab holds no live state.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenFault {
    /// The source exceeds the coordinate class (`i32::MAX` bytes).
    TooLarge {
        /// The refused source length.
        len: usize,
    },
    /// The slab is shorter than the plan's priced demand — judged
    /// as a pure length compare before anything is carved, so the
    /// refusal is deterministic for every slab address.
    SlabShort {
        /// The plan's demand, [`Plan::bytes`]' answer.
        need: u64,
        /// The bytes supplied.
        have: u64,
    },
    /// The root scan outgrew a plan capacity; the named lane's
    /// planned value is the repair.
    ScratchExhausted {
        /// The exhausted lane (the root scan occupies rows alone).
        role: ScratchRole,
    },
    /// The root layer violates the wire grammar.
    Wire(Fault),
    /// The root layer is lawful wire outside this machine's
    /// language or declared bounds.
    Refused(Refusal),
}

impl core::fmt::Display for OpenFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::TooLarge { len } => {
                write!(f, "source of {len} bytes exceeds the coordinate class")
            }
            Self::SlabShort { need, have } => {
                write!(f, "slab of {have} bytes falls short of the plan's {need}")
            }
            Self::ScratchExhausted { role } => {
                write!(f, "the plan's {role:?} capacity is spent at open")
            }
            Self::Wire(fault) => write!(f, "root layer: {fault}"),
            Self::Refused(refusal) => write!(f, "root layer: {refusal}"),
        }
    }
}

impl core::error::Error for OpenFault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(fault) => Some(fault),
            Self::Refused(refusal) => Some(refusal),
            Self::TooLarge { .. } | Self::SlabShort { .. } | Self::ScratchExhausted { .. } => None,
        }
    }
}

/// Why an edit command refused. Failure classes are judged in no
/// promised order within one call; on any `Err` the machine's
/// observable state is unchanged.
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
    /// The record's interior is open for editing; edit it in place
    /// or delete the record instead of replacing the payload
    /// wholesale.
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
    /// A plan capacity is spent; the refusal is permanent for that
    /// lane (fixed lanes never grow) and the machine stays usable.
    /// Occupancy against capacity reads off `budget()`; the repair
    /// is a bigger plan.
    ScratchExhausted {
        /// The exhausted lane.
        role: ScratchRole,
    },
}

impl core::fmt::Display for EditFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::KindMismatch { have } => {
                write!(f, "the command expects another wire kind; the record is {have}")
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
            Self::ScratchExhausted { role } => {
                write!(f, "the plan's {role:?} capacity is spent")
            }
        }
    }
}

impl core::error::Error for EditFault {}

/// Why a sized payload frame refused: the declaration judgments,
/// plus the capacity refusals the doors and the publishing close
/// can meet.
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
    /// A plan capacity is spent; the refusal is permanent for that
    /// lane and the machine stays usable.
    ScratchExhausted {
        /// The exhausted lane.
        role: ScratchRole,
    },
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
            Self::ScratchExhausted { role } => {
                write!(f, "the plan's {role:?} capacity is spent")
            }
        }
    }
}

impl core::error::Error for FrameFault {}

/// Maps the publishing close's faults onto the frame alphabet.
/// Total by the close's own domain: it mints coordinates only, so
/// only the capacity class arises there.
#[cold]
fn close_fault(fault: EditFault) -> FrameFault {
    match fault {
        EditFault::ScratchExhausted { role } => FrameFault::ScratchExhausted { role },
        _ => unreachable!("the publishing close mints coordinates only"),
    }
}

/// Why a save refused. On any `Err` the caller's buffer or sink has
/// been handed nothing.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SaveFault {
    /// A rewritten LEN body outgrew the length class.
    BodyOverCap {
        /// Source offset of the overflowing LEN record.
        at: u32,
    },
    /// The rewritten document outgrew the coordinate class.
    DocOverCap {
        /// The oversized total.
        total: u64,
    },
    /// The caller's output slice is shorter than the priced save —
    /// judged after the sizing walk, before the first byte.
    OutputShort {
        /// The priced save length.
        need: u32,
        /// The bytes supplied.
        have: usize,
    },
}

impl core::fmt::Display for SaveFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::BodyOverCap { at } => {
                write!(f, "rewritten body of the LEN at {at} exceeds the length class")
            }
            Self::DocOverCap { total } => {
                write!(f, "rewritten document of {total} bytes exceeds the coordinate class")
            }
            Self::OutputShort { need, have } => {
                write!(f, "output of {have} bytes falls short of the priced save of {need}")
            }
        }
    }
}

impl core::error::Error for SaveFault {}

// ─── verdicts and geometry ───

/// A descend verdict. Faults and refusals are resident: they park
/// on the record and project unchanged on every later call, while
/// the payload stays readable as bytes.
#[must_use = "the verdict reports whether the payload opened, faulted, or was refused"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Descent<'p> {
    /// The payload parsed; its first child, if any.
    Opened {
        /// First record of the interior layer.
        first: Option<Handle>,
    },
    /// The payload violates the wire grammar (resident).
    Faulted(&'p Fault),
    /// The payload is lawful wire outside this machine's language
    /// or declared bounds (resident).
    Refused(&'p Refusal),
}

/// Source geometry of one scanned record.
///
/// The segments partition the record's span exactly, at the widths
/// the scan actually met — padded framing included. Coordinates
/// answer for the source bytes, not for any pending edit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordSpans {
    /// Tag, then the varint value.
    Varint {
        /// The tag word.
        tag: Span,
        /// The value bytes.
        value: Span,
    },
    /// Tag, then eight value bytes.
    I64 {
        /// The tag word.
        tag: Span,
        /// The value bytes.
        value: Span,
    },
    /// Tag, length prefix, payload.
    Len {
        /// The tag word.
        tag: Span,
        /// The length prefix.
        prefix: Span,
        /// The payload bytes.
        payload: Span,
    },
    /// Tag, then four value bytes.
    I32 {
        /// The tag word.
        tag: Span,
        /// The value bytes.
        value: Span,
    },
}

// ─── rows ───

/// `Row.state` bits 0–1: the base edit state ([`Base`]).
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
/// `Row.state`: a LEN's descent parked a resident verdict;
/// `Row.value` holds its fault-table index.
const FLAG_FAULTED: u8 = 1 << 4;
/// The subtree edit witness: this record, or one beneath it, was
/// replaced, deleted, or had an insertion spliced in. Monotone —
/// commit-only offers no path that clears an edit — so ancestors
/// accumulate it on the way up and the save's verbatim arm trusts
/// its absence.
const FLAG_DIRTY: u8 = 1 << 5;

/// A row's base edit state: which side speaks for the value. The
/// deleted flag rides orthogonally so a deleted record's value side
/// stays answerable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Base {
    /// As scanned; the source bytes speak.
    Intact,
    /// The store value speaks; the source tag still rides.
    Replaced,
    /// Command-authored; the store value speaks and there is no
    /// source geometry.
    Inserted,
}

/// One record row, packed to 32 bytes. The arena is the tree:
/// parent and sibling links thread it, so every walk in this module
/// climbs instead of recursing.
///
/// Partition theorem (every span read cites it): a scanned record's
/// bytes are `tag ⊎ delim ⊎ payload`, pairwise disjoint, union the
/// whole record — the record span is one formula for all kinds
/// while the payload's position dispatches on kind. Widths are
/// stored input facts: tolerant admission accepts padding, and span
/// arithmetic must reproduce it byte-exactly.
#[derive(Clone, Copy)]
struct Row {
    field: FieldNumber,
    parent: Option<RowId>,
    next: Option<RowId>,
    /// First interior record of an opened container.
    kid: Option<RowId>,
    /// Source offset of the head tag; meaningless for authored rows
    /// (their `tag_width` is `None`).
    start: Coord,
    /// Source payload extent: a LEN's declared length, a varint
    /// value's scanned width, or 4/8 for the fixed kinds.
    /// Meaningless for authored rows.
    payload_len: Extent,
    /// The store coordinate (`Replaced`/`Inserted`), or the
    /// fault-table index under `FLAG_FAULTED`.
    value: u32,
    kind: RecordKind,
    /// The head tag's actual input width; `None` for authored rows,
    /// which have no source geometry.
    tag_width: Option<WordWidth>,
    /// The LEN length prefix's actual input width. `None` for
    /// scalars and authored rows.
    delim_width: Option<WordWidth>,
    /// Packed edit state: base bits, the deleted flag, and the LEN
    /// slot flags.
    state: u8,
}

const _: () = assert!(size_of::<Option<RowId>>() == 4);
const _: () = assert!(size_of::<Row>() == 32 && align_of::<Row>() == 4);
const _: () = assert!(size_of::<SlotFault>() == 16 && align_of::<SlotFault>() == 4);

crate::fixed_patch::carve_ladder! { ($)
    /// Carves the mixed door's working set from its slab in the
    /// ladder's order: scalar words, body words, payload slots,
    /// rows, parked faults, the save spine, and the staged byte
    /// pool last (unaligned by construction).
    carve_mixed, caps MixedCaps, lanes MixedLanes {
        words: u64,
        bodies: u64,
        slots: PayloadSlot<'_>,
        rows: Row,
        faults: SlotFault,
        spine: u32,
        @bytes staged,
    }
}

crate::fixed_patch::carve_ladder! { ($)
    /// Carves the borrowed door's working set from its slab in
    /// the ladder's order: scalar words, body words, borrowed
    /// payload slots, rows, parked faults, and the save spine.
    carve_borrowed, caps BorrowedCaps, lanes BorrowedLanes {
        words: u64,
        bodies: u64,
        slots: BorrowedSlot<'_>,
        rows: Row,
        faults: SlotFault,
        spine: u32,
    }
}

crate::fixed_patch::carve_ladder! { ($)
    /// Carves the copy door's working set from its slab in the
    /// ladder's order: scalar words, body words, rows, staged
    /// payload extents, parked faults, the save spine, and the
    /// staged byte pool last (unaligned by construction).
    carve_copy, caps CopyCaps, lanes CopyLanes {
        words: u64,
        bodies: u64,
        rows: Row,
        slots: (u32, u32),
        faults: SlotFault,
        spine: u32,
        @bytes staged,
    }
}

impl Row {
    /// A freshly scanned record.
    const fn scanned(
        field: FieldNumber,
        kind: RecordKind,
        start: Coord,
        payload_len: Extent,
        tag_width: WordWidth,
        delim_width: Option<WordWidth>,
        parent: Option<RowId>,
    ) -> Self {
        Self {
            field,
            start,
            payload_len,
            parent,
            next: None,
            kid: None,
            value: 0,
            kind,
            tag_width: Some(tag_width),
            delim_width,
            state: BASE_INTACT,
        }
    }

    /// A command-authored record.
    const fn authored(
        field: FieldNumber,
        kind: RecordKind,
        parent: Option<RowId>,
        next: Option<RowId>,
        value: u32,
    ) -> Self {
        Self {
            field,
            start: Coord::MIN,
            payload_len: Extent::from_width(0),
            parent,
            next,
            kid: None,
            value,
            kind,
            tag_width: None,
            delim_width: None,
            state: BASE_INSERTED,
        }
    }

    const fn base(&self) -> Base {
        match self.state & BASE_MASK {
            BASE_INTACT => Base::Intact,
            BASE_REPLACED => Base::Replaced,
            _ => Base::Inserted,
        }
    }

    const fn set_replaced(&mut self) {
        self.state = (self.state & !BASE_MASK) | BASE_REPLACED;
    }

    const fn deleted(&self) -> bool {
        self.state & FLAG_DELETED != 0
    }

    const fn set_deleted(&mut self) {
        self.state |= FLAG_DELETED;
    }

    const fn opened(&self) -> bool {
        self.state & FLAG_OPENED != 0
    }

    const fn set_opened(&mut self) {
        self.state |= FLAG_OPENED;
    }

    const fn faulted(&self) -> bool {
        self.state & FLAG_FAULTED != 0
    }

    const fn set_faulted(&mut self) {
        self.state |= FLAG_FAULTED;
    }

    const fn clear_faulted(&mut self) {
        self.state &= !FLAG_FAULTED;
    }

    const fn dirty(&self) -> bool {
        self.state & FLAG_DIRTY != 0
    }

    const fn set_dirty(&mut self) {
        self.state |= FLAG_DIRTY;
    }

    /// One mask test for the save walk's hot question: intact base
    /// (`BASE_INTACT` is zero), not deleted, subtree clean — the
    /// record and everything beneath it ride the source verbatim.
    const fn rides_verbatim(&self) -> bool {
        self.state & (BASE_MASK | FLAG_DELETED | FLAG_DIRTY) == BASE_INTACT
    }

    /// Stored widths as coordinate-class integers (zero when absent
    /// — every use sits behind a base or kind dispatch that proves
    /// presence).
    const fn tag_w(&self) -> u32 {
        match self.tag_width {
            Some(w) => w.w(),
            None => 0,
        }
    }

    const fn delim_w(&self) -> u32 {
        match self.delim_width {
            Some(w) => w.w(),
            None => 0,
        }
    }

    /// The scanned-geometry witness: rows minted by a scan carry
    /// their met widths; authored rows never do.
    const fn has_source(&self) -> bool {
        self.tag_width.is_some()
    }

    /// The whole-record source span end: one formula for all kinds,
    /// per the partition theorem.
    const fn span_end(&self) -> u32 {
        self.start.as_inner() + self.tag_w() + self.delim_w() + self.payload_len.as_inner()
    }

    /// The source payload's offset: past the tag, and past the
    /// length prefix for LENs.
    const fn payload_at(&self) -> u32 {
        self.start.as_inner() + self.tag_w() + self.delim_w()
    }
}

/// A resident descend verdict.
#[derive(Clone, Copy)]
enum SlotFault {
    Wire(Fault),
    Refused(Refusal),
}

/// Projects a resident verdict off the fault table.
const fn project(faults: &[SlotFault], index: u32) -> Descent<'_> {
    match &faults[usize_of(index)] {
        SlotFault::Wire(fault) => Descent::Faulted(fault),
        SlotFault::Refused(refusal) => Descent::Refused(refusal),
    }
}

// ─── the layer scan ───

/// Why a layer scan halted.
enum Halt {
    Wire(Fault),
    Refused(Refusal),
    Exhausted,
}

#[cold]
const fn halt_wire(at: u32, kind: FaultKind) -> Halt {
    Halt::Wire(Fault { at, kind })
}

/// Mints the next row coordinate: the plan's row capacity is the
/// judgment, and the minted index is in the `RowId` domain because
/// the plan judged the capacity into it at construction.
const fn mint_row(rows: &Lane<'_, Row>) -> Result<RowId, Halt> {
    let Some(at) = rows.mint() else {
        return Err(Halt::Exhausted);
    };
    // SAFETY: `at < capacity` by the mint, and the plan judged the
    // capacity into the RowId domain at construction.
    Ok(unsafe { RowId::new_unchecked(at) })
}

/// Scans one flat layer of `bytes[start..end]` into provisional
/// rows under `parent`. Widths ride onto the rows as scanned;
/// nothing is re-derived from values. On any halt the caller
/// discards the provisional tail; nothing here touches published
/// state.
fn scan_layer(
    rows: &mut Lane<'_, Row>,
    bytes: &[u8],
    start: u32,
    end: u32,
    parent: Option<RowId>,
) -> Result<Option<RowId>, Halt> {
    debug_assert!(usize_of(end) <= bytes.len());
    let extent = usize_of(end);
    let mut first: Option<RowId> = None;
    let mut last: Option<RowId> = None;
    let mut pos = start;
    while pos < end {
        // SAFETY: `extent <= bytes.len()` — the scan's own extent
        // contract, established at the door's admission.
        let (word, tag_width) = unsafe { slice::tag_word_trusted(bytes, usize_of(pos), extent) }
            .map_err(|fault| halt_wire(pos, FaultKind::Tag { fault }))?;
        let Some(field) = FieldNumber::from_word(word) else {
            return Err(halt_wire(pos, FaultKind::FieldZero));
        };
        let value_at = pos + u32::from(tag_width);
        // SAFETY: the kernel's widths land in 1..=5.
        let tag_width = unsafe { WordWidth::met_unchecked(tag_width) };
        let kind = match classify(Low3::from_word(word)) {
            TagClass::Record(kind) => kind,
            TagClass::GroupCode => {
                return Err(Halt::Refused(Refusal::GroupCode {
                    at: pos,
                    field,
                    low3: Low3::from_word(word),
                }));
            }
            TagClass::Unassigned => {
                return Err(halt_wire(
                    pos,
                    FaultKind::Unassigned { field, low3: Low3::from_word(word) },
                ));
            }
        };
        let (payload_len, delim_width, record_end) = match kind {
            RecordKind::Varint => {
                // SAFETY: the scan's extent contract, as the tag read.
                let (_, width) =
                    unsafe { slice::value64_trusted(bytes, usize_of(value_at), extent) }
                        .map_err(|fault| halt_wire(value_at, FaultKind::Value { field, fault }))?;
                (Extent::from_width(width), None, value_at + u32::from(width))
            }
            RecordKind::I32 | RecordKind::I64 => {
                let width: u8 = if matches!(kind, RecordKind::I32) { 4 } else { 8 };
                let need = u32::from(width);
                let have = end - value_at;
                if have < need {
                    return Err(halt_wire(value_at, FaultKind::PayloadCut { field, need, have }));
                }
                (Extent::from_width(width), None, value_at + need)
            }
            RecordKind::Len => {
                // SAFETY: the scan's extent contract, as the tag read.
                let (len, width) =
                    unsafe { slice::len_word_trusted(bytes, usize_of(value_at), extent) }
                        .map_err(|fault| halt_wire(value_at, FaultKind::Len { field, fault }))?;
                // SAFETY: the kernel's widths land in 1..=5.
                let width = unsafe { WordWidth::met_unchecked(width) };
                let body = value_at + width.w();
                if u64::from(body) + u64::from(len.as_inner()) > u64::from(end) {
                    return Err(halt_wire(
                        body,
                        FaultKind::PayloadCut { field, need: len.as_inner(), have: end - body },
                    ));
                }
                (Extent::from_len(len), Some(width), body + len.as_inner())
            }
        };
        let id = mint_row(rows)?;
        match last {
            Some(prev) => {
                rows.get_mut(prev.as_inner()).next = Some(id);
            }
            None => first = Some(id),
        }
        // SAFETY: `pos` walks admitted source coordinates — the door
        // admitted the length into the coordinate class.
        let start = unsafe { Coord::new_unchecked(pos) };
        rows.push_minted(Row::scanned(
            field,
            kind,
            start,
            payload_len,
            tag_width,
            delim_width,
            parent,
        ));
        last = Some(id);
        pos = record_end;
    }
    Ok(first)
}

// ─── the machine plumbing ───

/// The arena gate: forged handles (coordinates the machine never
/// minted) panic right here on the index bound.
#[track_caller]
const fn gate(rows: &[Row], handle: Handle) -> &Row {
    &rows[handle.0.index()]
}

/// The arena row a machine-minted link names.
///
/// # Safety
///
/// `index` must come from a link this machine minted: a row id from
/// an arena append or the `next`/`parent` links rows store. The
/// arena never truncates below a minted link (descends reclaim only
/// their own provisional tails, which no surviving link names), so
/// every minted link stays in-table for the machine's whole life.
#[inline]
unsafe fn linked(rows: &[Row], index: usize) -> &Row {
    debug_assert!(index < rows.len(), "links are minted in-table");
    // SAFETY: the caller's link provenance covers the index.
    unsafe { rows.get_unchecked(index) }
}

/// An insertion's resolved splice point, proven before anything is
/// occupied.
#[derive(Clone, Copy)]
struct SplicePoint {
    parent: Option<RowId>,
    prev: Option<RowId>,
}

/// A scalar value headed for the output.
#[derive(Clone, Copy)]
enum Word {
    Varint(u64),
    Bits32(u32),
    Bits64(u64),
}

impl Word {
    /// The value's canonical emitted width.
    const fn width(self) -> u32 {
        match self {
            Self::Varint(word) => encoded_len64(word),
            Self::Bits32(_) => 4,
            Self::Bits64(_) => 8,
        }
    }
}

/// The save passes' verdict for one row, every value resolved at
/// judgment time so neither pass re-derives anything.
enum Arm {
    /// Deleted: contributes nothing, subtree included.
    Skip,
    /// An untouched leaf or sealed container: the whole source span
    /// rides verbatim.
    Clean { at: u32, end: u32 },
    /// A replaced scalar: source tag verbatim, then the value.
    ReValue { tag_at: u32, tag_end: u32, value: Word },
    /// An authored scalar: minimal head, then the value.
    NewValue { head: u32, value: Word },
    /// A replaced LEN: source tag verbatim; the prefix rides
    /// verbatim iff the authored payload keeps the source length.
    ReBody { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, value: PayloadAt },
    /// An authored LEN: minimal head, prefix, payload.
    NewBody { head: u32, value: PayloadAt },
    /// A source-framed LEN with an opened interior: recurse; the
    /// prefix rides verbatim iff the interior lands back on the
    /// source length.
    Spine { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, first: Option<RowId> },
}

// ─── the save emitters ───

/// One save emitter: the emit walk drives these faces, and the
/// slice and sink twins implement them — one walk shape, two
/// custodies for the bytes.
trait Out {
    /// Publishes the pending verbatim run, if any.
    fn flush(&mut self);
    /// Copies `at..end` of the source, merging contiguous runs.
    fn verbatim(&mut self, at: u32, end: u32);
    /// Emits one minimal head word.
    fn word(&mut self, word: u32);
    /// Emits one authored scalar value.
    fn value(&mut self, value: Word);
    /// Emits one minimal varint (LEN prefixes).
    fn varint(&mut self, value: u64);
    /// Emits authored payload bytes.
    fn bytes(&mut self, bytes: &[u8]);
}

/// The forward emitter into a caller slice the sizing pass already
/// judged: a pending verbatim run rides between writes so
/// contiguous untouched records coalesce into one copy. Writes past
/// the judged length cannot happen while the sizing and emit walks
/// agree; the slice indexing is the seam assertion.
struct SliceEmit<'o, 'a> {
    out: &'o mut [u8],
    at: usize,
    src: &'a [u8],
    run: Option<(u32, u32)>,
}

impl SliceEmit<'_, '_> {
    /// Lands one produced slice at the cursor.
    fn put(&mut self, bytes: &[u8]) {
        self.out[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }
}

impl Out for SliceEmit<'_, '_> {
    fn flush(&mut self) {
        if let Some((from, to)) = self.run.take() {
            // SAFETY: scanned spans lie within the admitted source.
            let run = unsafe { self.src.get_unchecked(usize_of(from)..usize_of(to)) };
            self.put(run);
        }
    }

    fn verbatim(&mut self, at: u32, end: u32) {
        match &mut self.run {
            Some((_, to)) if *to == at => *to = end,
            _ => {
                self.flush();
                self.run = Some((at, end));
            }
        }
    }

    fn word(&mut self, word: u32) {
        self.flush();
        let width = emit64(u64::from(word), &mut self.out[self.at..]);
        self.at += usize_of(width);
    }

    fn value(&mut self, value: Word) {
        self.flush();
        match value {
            Word::Varint(word) => {
                let width = emit64(word, &mut self.out[self.at..]);
                self.at += usize_of(width);
            }
            Word::Bits32(bits) => self.put(&bits.to_le_bytes()),
            Word::Bits64(bits) => self.put(&bits.to_le_bytes()),
        }
    }

    fn varint(&mut self, value: u64) {
        self.flush();
        let width = emit64(value, &mut self.out[self.at..]);
        self.at += usize_of(width);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.flush();
        self.put(bytes);
    }
}

/// [`SliceEmit`]'s sink twin: the same walk hands borrowed slices
/// to the caller's sink — verbatim runs as windows of the source,
/// authored words through a ten-byte stack window. The written
/// count serves the seam assertion.
struct SinkEmit<'a, 's, F> {
    src: &'a [u8],
    sink: &'s mut F,
    run: Option<(u32, u32)>,
    /// Bytes handed to the sink so far.
    written: u64,
}

impl<F: FnMut(&[u8])> SinkEmit<'_, '_, F> {
    /// Hands one non-empty slice to the sink (empty handoffs are
    /// dropped: they carry no bytes to account).
    fn hand(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        {
            self.written += bytes.len() as u64;
        }
        (self.sink)(bytes);
    }

    /// Hands one minimal varint through the stack window.
    fn hand_varint(&mut self, value: u64) {
        let mut window = [0u8; 10];
        let width = emit64(value, &mut window);
        self.hand(&window[..usize_of(width)]);
    }
}

impl<F: FnMut(&[u8])> Out for SinkEmit<'_, '_, F> {
    fn flush(&mut self) {
        if let Some((from, to)) = self.run.take() {
            let src = self.src;
            // SAFETY: scanned spans lie within the admitted source.
            self.hand(unsafe { src.get_unchecked(usize_of(from)..usize_of(to)) });
        }
    }

    fn verbatim(&mut self, at: u32, end: u32) {
        match &mut self.run {
            Some((_, to)) if *to == at => *to = end,
            _ => {
                self.flush();
                self.run = Some((at, end));
            }
        }
    }

    fn word(&mut self, word: u32) {
        self.flush();
        self.hand_varint(u64::from(word));
    }

    fn value(&mut self, value: Word) {
        self.flush();
        match value {
            Word::Varint(word) => self.hand_varint(word),
            Word::Bits32(bits) => self.hand(&bits.to_le_bytes()),
            Word::Bits64(bits) => self.hand(&bits.to_le_bytes()),
        }
    }

    fn varint(&mut self, value: u64) {
        self.flush();
        self.hand_varint(value);
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.flush();
        self.hand(bytes);
    }
}

// ─── iterators ───

/// Sibling records in wire order (deleted records included —
/// topology is stable, presentation filters).
#[must_use]
pub struct Children<'p> {
    rows: &'p [Row],
    cur: Option<RowId>,
}

impl<'p> Children<'p> {
    /// Narrows to records of one field, preserving wire order.
    #[inline]
    pub fn by_field(self, field: FieldNumber) -> impl Iterator<Item = Handle> + 'p {
        let rows = self.rows;
        // SAFETY: the iterator yields minted links only (see `next`).
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
pub struct Ancestors<'p> {
    rows: &'p [Row],
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

/// The command a staged payload frame closes with.
#[derive(Clone, Copy)]
enum WriteOp {
    /// Replace an existing LEN's payload.
    Set {
        /// The gated target.
        handle: Handle,
    },
    /// Insert a fresh LEN record at a resolved splice point.
    Insert {
        /// The proven anchor.
        point: SplicePoint,
        /// The new record's field.
        field: FieldNumber,
    },
}

// ─── the canonical walk vocabulary ───

/// The canonical walk's verdict for one row: every record in the
/// materialized commitment closure re-emits with minimal framing,
/// so no whole-record verbatim arm exists — byte runs ride verbatim
/// only for fixed-width value bytes and opaque payload bytes,
/// neither of which contains an emitted varint construct.
enum CanonicalArm {
    /// Deleted: contributes nothing, subtree included.
    Skip,
    /// Minimal head, then the current word, minimally emitted.
    Varint { head: u32, word: u64 },
    /// Minimal head, then the current four value bytes.
    I32 { head: u32, value: CanonicalValue },
    /// Minimal head, then the current eight value bytes.
    I64 { head: u32, value: CanonicalValue },
    /// Minimal head, minimal prefix for the current payload byte
    /// length, then that payload byte-for-byte: unopened, faulted,
    /// or refused source LENs and every effective authored payload
    /// — the points where the commitment closure ends.
    OpaqueLen { head: u32, payload: CanonicalPayload },
    /// A source-backed LEN whose interior a successful descend
    /// committed into the closure: its body is walked and the
    /// prefix re-derives from the canonical body total; the close
    /// reads the row itself for the over-cap fault's offset.
    OpenLen { head: u32, first: Option<RowId> },
}

/// Where a canonical fixed-width value's bytes come from.
#[derive(Clone, Copy)]
enum CanonicalValue {
    /// The source value bytes at this offset, copied verbatim.
    Doc { at: u32 },
    /// The store word, through the existing bit emitter.
    Store(Word),
}

/// Where a canonical opaque payload's bytes come from.
#[derive(Clone, Copy)]
enum CanonicalPayload {
    /// The source payload extent, copied verbatim.
    Doc { at: u32, len: u32 },
    /// The authored payload store slot.
    Store(PayloadAt),
}

// ─── the capacity contracts ───

/// The count of distinct `RowId` values — the row-capacity ceiling
/// every plan judges at construction, so row minting is in-domain
/// by contract.
const ROW_DOMAIN: u32 = 0x7FFF_FFFF;

/// The spine capacity the door derives: open source-LEN frames on
/// one walk path. Each frame is a distinct row, and descend judges
/// nesting below the depth bound, so both bound it; the tighter one
/// prices.
const fn spine_cap(rows: u32, limit: DepthLimit) -> u32 {
    let bound = limit.as_inner() as u32;
    if rows < bound { rows } else { bound }
}

/// The mixed machine's capacity contract: the roles no
/// configuration implies, each judged into its coordinate class.
///
/// The door derives the rest (the save walks' body table rides the
/// row count, the container spine the depth bound) — a plan never
/// restates configuration.
///
/// Counts are cumulative demand, not live population: commit-only
/// re-sets leave replaced staged extents inert, refused descents
/// occupy rows while scanning, and abandoned frames occupy staged
/// bytes while live — `budget()`'s high-water is the number a
/// sufficient plan must cover.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plan {
    rows: u32,
    words: u32,
    payload_slots: u32,
    staged_bytes: u32,
    faults: u32,
}

impl Plan {
    /// Judges the declared capacities into their coordinate classes:
    /// rows into the row-id domain; every other count is already in
    /// its column's class by type. `None` past a class bound.
    #[inline]
    pub const fn new(
        rows: u32,
        words: u32,
        payload_slots: u32,
        staged_bytes: u32,
        faults: u32,
    ) -> Option<Self> {
        if rows > ROW_DOMAIN {
            return None;
        }
        Some(Self { rows, words, payload_slots, staged_bytes, faults })
    }

    /// The exact slab demand under `limit`, sufficient for any slab
    /// address: worst-case front alignment is priced in, and the
    /// door refuses a shorter slab with
    /// [`OpenFault::SlabShort`] as a pure length compare — a
    /// luckier alignment never shrinks the demand. The depth bound
    /// prices the derived container spine, which is why the face
    /// takes it.
    #[inline]
    #[must_use]
    pub const fn bytes(&self, limit: DepthLimit) -> u64 {
        self.caps(limit).priced()
    }

    /// The mixed door's lane capacities: the declared roles plus
    /// the derived ones (the save walks' body table rides the row
    /// count, the container spine the depth bound) — one
    /// construction, priced and carved alike.
    const fn caps(&self, limit: DepthLimit) -> MixedCaps {
        MixedCaps {
            words: self.words,
            bodies: self.rows,
            slots: self.payload_slots,
            rows: self.rows,
            faults: self.faults,
            spine: spine_cap(self.rows, limit),
            staged: self.staged_bytes,
        }
    }
}

/// The borrowed-only machine's capacity contract: [`Plan`] without
/// the staged byte pool — no `_copy` face exists to fill one.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BorrowPlan {
    rows: u32,
    words: u32,
    payload_slots: u32,
    faults: u32,
}

impl BorrowPlan {
    /// Judges the declared capacities into their coordinate classes
    /// ([`Plan::new`]'s contract, without the staged pool).
    #[inline]
    pub const fn new(rows: u32, words: u32, payload_slots: u32, faults: u32) -> Option<Self> {
        if rows > ROW_DOMAIN {
            return None;
        }
        Some(Self { rows, words, payload_slots, faults })
    }

    /// The exact slab demand under `limit` ([`Plan::bytes`]'
    /// contract).
    #[inline]
    #[must_use]
    pub const fn bytes(&self, limit: DepthLimit) -> u64 {
        self.caps(limit).priced()
    }

    /// The borrowed door's lane capacities ([`Plan::caps`]'
    /// contract, without the staged pool).
    const fn caps(&self, limit: DepthLimit) -> BorrowedCaps {
        BorrowedCaps {
            words: self.words,
            bodies: self.rows,
            slots: self.payload_slots,
            rows: self.rows,
            faults: self.faults,
            spine: spine_cap(self.rows, limit),
        }
    }
}

/// The copy-only machine's capacity contract: [`Plan`]'s roles over
/// bare-extent payload slots.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CopyPlan {
    rows: u32,
    words: u32,
    payload_slots: u32,
    staged_bytes: u32,
    faults: u32,
}

impl CopyPlan {
    /// Judges the declared capacities into their coordinate classes
    /// ([`Plan::new`]'s contract).
    #[inline]
    pub const fn new(
        rows: u32,
        words: u32,
        payload_slots: u32,
        staged_bytes: u32,
        faults: u32,
    ) -> Option<Self> {
        if rows > ROW_DOMAIN {
            return None;
        }
        Some(Self { rows, words, payload_slots, staged_bytes, faults })
    }

    /// The exact slab demand under `limit` ([`Plan::bytes`]'
    /// contract).
    #[inline]
    #[must_use]
    pub const fn bytes(&self, limit: DepthLimit) -> u64 {
        self.caps(limit).priced()
    }

    /// The copy door's lane capacities ([`Plan::caps`]' contract).
    const fn caps(&self, limit: DepthLimit) -> CopyCaps {
        CopyCaps {
            words: self.words,
            bodies: self.rows,
            rows: self.rows,
            slots: self.payload_slots,
            faults: self.faults,
            spine: spine_cap(self.rows, limit),
            staged: self.staged_bytes,
        }
    }
}

// ─── the save walks, shared across the payload backings ───

/// The payload-store faces the save walks consume — the three
/// sibling stores answer them identically over their own slot
/// shapes, so one walk serves every backing.
trait Payloads {
    /// The payload length at a minted coordinate, in the length
    /// class.
    fn len(&self, at: PayloadAt) -> u32;
    /// The payload's bytes in emission order.
    fn for_each_piece(&self, at: PayloadAt, piece: impl FnMut(&[u8]));
}

impl Payloads for PayloadStore<'_, '_> {
    fn len(&self, at: PayloadAt) -> u32 {
        Self::len(self, at)
    }

    fn for_each_piece(&self, at: PayloadAt, piece: impl FnMut(&[u8])) {
        Self::for_each_piece(self, at, piece);
    }
}

impl Payloads for BorrowedPayloadStore<'_, '_> {
    fn len(&self, at: PayloadAt) -> u32 {
        Self::len(self, at)
    }

    fn for_each_piece(&self, at: PayloadAt, piece: impl FnMut(&[u8])) {
        Self::for_each_piece(self, at, piece);
    }
}

impl Payloads for CopiedPayloadStore<'_> {
    fn len(&self, at: PayloadAt) -> u32 {
        Self::len(self, at)
    }

    fn for_each_piece(&self, at: PayloadAt, piece: impl FnMut(&[u8])) {
        Self::for_each_piece(self, at, piece);
    }
}

/// Debug re-derivation of the dirty witness from first principles:
/// the row's own edit state, or a dirty direct kid. One level
/// suffices — the save walk visits rows top down, so induction
/// covers the depth.
fn subtree_dirt(rows: &[Row], row: &Row) -> bool {
    if !matches!(row.base(), Base::Intact) || row.deleted() {
        return true;
    }
    let mut cur = row.kid;
    while let Some(id) = cur {
        // SAFETY: `kid`/`next` are minted links.
        let kid = unsafe { linked(rows, id.index()) };
        if kid.dirty() {
            return true;
        }
        cur = kid.next;
    }
    false
}

/// The save passes' verdict for one row.
fn settle(rows: &[Row], words: &WordStore<'_>, row: &Row) -> Arm {
    debug_assert_eq!(row.dirty(), subtree_dirt(rows, row), "row dirt drift");
    if row.deleted() {
        return Arm::Skip;
    }
    match row.base() {
        Base::Intact if !row.dirty() => {
            Arm::Clean { at: row.start.as_inner(), end: row.span_end() }
        }
        Base::Intact => match row.kind {
            RecordKind::Len if row.opened() => {
                let tag_end = row.start.as_inner() + row.tag_w();
                Arm::Spine {
                    tag_at: row.start.as_inner(),
                    tag_end,
                    prefix_end: tag_end + row.delim_w(),
                    src_len: row.payload_len.as_inner(),
                    first: row.kid,
                }
            }
            _ => Arm::Clean { at: row.start.as_inner(), end: row.span_end() },
        },
        Base::Replaced => {
            let tag_at = row.start.as_inner();
            let tag_end = row.start.as_inner() + row.tag_w();
            match row.kind {
                RecordKind::Varint => Arm::ReValue {
                    tag_at,
                    tag_end,
                    value: Word::Varint(words.word(WordAt::of_slot(row.value))),
                },
                RecordKind::I32 => {
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::as_conversions,
                        reason = "fixed 32-bit words are stored zero-extended"
                    )]
                    let bits = words.word(WordAt::of_slot(row.value)) as u32;
                    Arm::ReValue { tag_at, tag_end, value: Word::Bits32(bits) }
                }
                RecordKind::I64 => Arm::ReValue {
                    tag_at,
                    tag_end,
                    value: Word::Bits64(words.word(WordAt::of_slot(row.value))),
                },
                RecordKind::Len => Arm::ReBody {
                    tag_at,
                    tag_end,
                    prefix_end: tag_end + row.delim_w(),
                    src_len: row.payload_len.as_inner(),
                    value: PayloadAt::of_slot(row.value),
                },
            }
        }
        Base::Inserted => {
            let head = head_word(row.field, row.kind);
            match row.kind {
                RecordKind::Varint => Arm::NewValue {
                    head,
                    value: Word::Varint(words.word(WordAt::of_slot(row.value))),
                },
                RecordKind::I32 => {
                    #[allow(
                        clippy::cast_possible_truncation,
                        clippy::as_conversions,
                        reason = "fixed 32-bit words are stored zero-extended"
                    )]
                    let bits = words.word(WordAt::of_slot(row.value)) as u32;
                    Arm::NewValue { head, value: Word::Bits32(bits) }
                }
                RecordKind::I64 => Arm::NewValue {
                    head,
                    value: Word::Bits64(words.word(WordAt::of_slot(row.value))),
                },
                RecordKind::Len => Arm::NewBody { head, value: PayloadAt::of_slot(row.value) },
            }
        }
    }
}

/// Records the entry mark of one opened spine frame: the body slot
/// mints in walk order and the open frame's slot index stacks. Both
/// occupancies are proven by the door's derivation — one body slot
/// per opened source LEN (distinct rows, so at most the row
/// capacity) and one open frame per nesting level (descend judges
/// nesting below the depth bound) — so neither push can refuse.
fn spine_enter(bodies: &mut Lane<'_, u64>, spine: &mut Lane<'_, u32>, entry: u64) {
    let Some(slot) = bodies.push(entry) else {
        debug_assert!(false, "body slots outgrew the row capacity");
        // SAFETY: each slot belongs to a distinct opened-LEN row,
        // and the bodies lane was carved at the row capacity.
        unsafe { core::hint::unreachable_unchecked() }
    };
    if spine.push(slot).is_none() {
        debug_assert!(false, "spine frames outgrew the nesting bound");
        // SAFETY: open frames nest one per opened-LEN ancestor;
        // descend judged that nesting below the depth bound and
        // each frame is a distinct row, so the carved capacity
        // (the smaller of the two) covers every path.
        unsafe { core::hint::unreachable_unchecked() }
    }
}

/// Pops the innermost open frame's body slot at its close.
fn spine_close(spine: &mut Lane<'_, u32>) -> u32 {
    let Some(slot) = spine.pop() else {
        debug_assert!(false, "closes pair with entries");
        // SAFETY: the walk closes exactly the frames it entered.
        unsafe { core::hint::unreachable_unchecked() }
    };
    slot
}

/// The size pass over one dirty subtree: accumulates the root's
/// rewritten size, recording every opened LEN's body (in walk
/// order) for the emit walk's prefix decisions. The accumulator is
/// cumulative across the subtree; a spine frame records its entry
/// mark in its body slot and the close settles the difference, so
/// the walk needs no saved outer accumulator — the arena's parent
/// links are the spine, plus one slot index per open frame. The
/// root is a top-layer row (its parent is `None`), so the final
/// climb ends the walk; the root takes no sibling step.
fn size_subtree<P: Payloads>(
    rows: &[Row],
    words: &WordStore<'_>,
    payloads: &P,
    bodies: &mut Lane<'_, u64>,
    spine: &mut Lane<'_, u32>,
    root: RowId,
) -> Result<u64, SaveFault> {
    let mut acc: u64 = 0;
    let mut open: Option<RowId> = None;
    let mut cur = Some(root);
    loop {
        let Some(id) = cur else {
            let Some(container) = open else { break };
            // SAFETY: `open` holds minted links only.
            let row = unsafe { linked(rows, container.index()) };
            let slot = spine_close(spine);
            let entry = *bodies.get(slot);
            let grown = acc - entry;
            let body = u32::try_from(grown)
                .ok()
                .and_then(PayloadLen::new)
                .ok_or(SaveFault::BodyOverCap { at: row.start.as_inner() })?;
            let body = body.as_inner();
            *bodies.get_mut(slot) = u64::from(body);
            let prefix = if body == row.payload_len.as_inner() {
                row.delim_w()
            } else {
                encoded_len32(body)
            };
            acc += u64::from(row.tag_w()) + u64::from(prefix);
            cur = if container == root { None } else { row.next };
            open = row.parent;
            continue;
        };
        // SAFETY: the walk follows minted links from a minted root.
        let row = unsafe { linked(rows, id.index()) };
        match settle(rows, words, row) {
            Arm::Skip => {}
            Arm::Clean { at, end } => acc += u64::from(end - at),
            Arm::ReValue { tag_at, tag_end, value } => {
                acc += u64::from(tag_end - tag_at) + u64::from(value.width());
            }
            Arm::NewValue { head, value } => {
                acc += u64::from(encoded_len32(head)) + u64::from(value.width());
            }
            Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                let len = payloads.len(value);
                let prefix = if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
            }
            Arm::NewBody { head, value } => {
                let len = payloads.len(value);
                acc +=
                    u64::from(encoded_len32(head)) + u64::from(encoded_len32(len)) + u64::from(len);
            }
            Arm::Spine { first, .. } => {
                spine_enter(bodies, spine, acc);
                open = Some(id);
                cur = first;
                continue;
            }
        }
        cur = if open.is_none() { None } else { row.next };
    }
    Ok(acc)
}

/// The emit walk over one dirty subtree: the size walk's twin,
/// forward, writing into the shared emitter. Climbing out of
/// containers follows parent links — the spine is the arena itself
/// — and the root takes no sibling step.
fn emit_subtree<P: Payloads, O: Out>(
    rows: &[Row],
    words: &WordStore<'_>,
    payloads: &P,
    emit: &mut O,
    root: RowId,
    bodies: &[u64],
    body_cursor: &mut usize,
) {
    let mut open: Option<RowId> = None;
    let mut cur = Some(root);
    loop {
        let Some(id) = cur else {
            let Some(container) = open else { break };
            // SAFETY: `open` holds minted links only.
            let row = unsafe { linked(rows, container.index()) };
            cur = if container == root { None } else { row.next };
            open = row.parent;
            continue;
        };
        // SAFETY: the walk follows minted links from a minted root.
        let row = unsafe { linked(rows, id.index()) };
        match settle(rows, words, row) {
            Arm::Skip => {}
            Arm::Clean { at, end } => emit.verbatim(at, end),
            Arm::ReValue { tag_at, tag_end, value } => {
                emit.verbatim(tag_at, tag_end);
                emit.value(value);
            }
            Arm::NewValue { head, value } => {
                emit.word(head);
                emit.value(value);
            }
            Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                emit.verbatim(tag_at, tag_end);
                let len = payloads.len(value);
                if len == src_len {
                    emit.verbatim(tag_end, prefix_end);
                } else {
                    emit.varint(u64::from(len));
                }
                payloads.for_each_piece(value, |piece| emit.bytes(piece));
            }
            Arm::NewBody { head, value } => {
                emit.word(head);
                emit.varint(u64::from(payloads.len(value)));
                payloads.for_each_piece(value, |piece| emit.bytes(piece));
            }
            Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                emit.verbatim(tag_at, tag_end);
                let body = body_at(bodies, *body_cursor);
                *body_cursor += 1;
                if body == src_len {
                    emit.verbatim(tag_end, prefix_end);
                } else {
                    emit.varint(u64::from(body));
                }
                open = Some(id);
                cur = first;
                continue;
            }
        }
        cur = if id == root { None } else { row.next };
    }
}

/// A priced body read back in walk order: every slot was settled by
/// its close, which judged the value into the length class.
const fn body_at(bodies: &[u64], cursor: usize) -> u32 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::as_conversions,
        reason = "closed slots hold bodies judged into the length class"
    )]
    {
        bodies[cursor] as u32
    }
}

/// The fused sizing pass: one walk prices the whole save and keeps
/// every splice's LEN bodies, in walk order, for the emit walk to
/// consume — the priced bodies are computed exactly once per save.
fn size_pass<P: Payloads>(
    rows: &[Row],
    words: &WordStore<'_>,
    payloads: &P,
    bodies: &mut Lane<'_, u64>,
    spine: &mut Lane<'_, u32>,
    top: Option<RowId>,
) -> Result<u32, SaveFault> {
    bodies.truncate(0);
    spine.truncate(0);
    let mut total: u64 = 0;
    let mut run: Option<(u32, RowId)> = None;
    let mut cur = top;
    while let Some(id) = cur {
        // SAFETY: the top chain holds minted links only.
        let row = unsafe { linked(rows, id.index()) };
        cur = row.next;
        if row.rides_verbatim() {
            match &mut run {
                Some((_, last)) => *last = id,
                None => run = Some((row.start.as_inner(), id)),
            }
            continue;
        }
        if let Some((from, last)) = run.take() {
            // SAFETY: the run's last id is a minted link.
            total += u64::from(unsafe { linked(rows, last.index()) }.span_end() - from);
        }
        if row.deleted() {
            continue;
        }
        total += size_subtree(rows, words, payloads, bodies, spine, id)?;
    }
    if let Some((from, last)) = run.take() {
        // SAFETY: the run's last id is a minted link.
        total += u64::from(unsafe { linked(rows, last.index()) }.span_end() - from);
    }
    u32::try_from(total)
        .ok()
        .filter(|n| *n <= PayloadLen::MAX.as_inner())
        .ok_or(SaveFault::DocOverCap { total })
}

/// The emit pass over the whole top chain, consuming the sizing
/// pass's priced bodies: verbatim runs coalesce untouched records
/// into single copies, each dirty record splices through
/// [`emit_subtree`].
fn emit_pass<P: Payloads, O: Out>(
    rows: &[Row],
    words: &WordStore<'_>,
    payloads: &P,
    emit: &mut O,
    bodies: &[u64],
    top: Option<RowId>,
) {
    let mut cursor = 0usize;
    let mut run: Option<(u32, RowId)> = None;
    let mut cur = top;
    while let Some(id) = cur {
        // SAFETY: the top chain holds minted links only.
        let row = unsafe { linked(rows, id.index()) };
        cur = row.next;
        if row.rides_verbatim() {
            match &mut run {
                Some((_, last)) => *last = id,
                None => run = Some((row.start.as_inner(), id)),
            }
            continue;
        }
        if let Some((from, last)) = run.take() {
            // SAFETY: the run's last id is a minted link.
            emit.verbatim(from, unsafe { linked(rows, last.index()) }.span_end());
        }
        if row.deleted() {
            continue;
        }
        emit.flush();
        emit_subtree(rows, words, payloads, emit, id, bodies, &mut cursor);
        emit.flush();
    }
    if let Some((from, last)) = run.take() {
        // SAFETY: the run's last id is a minted link.
        emit.verbatim(from, unsafe { linked(rows, last.index()) }.span_end());
    }
    emit.flush();
}

/// The canonical walk's verdict for one row, every value resolved
/// at judgment time. Stored widths are not output widths here —
/// they remain the source-geometry proof that locates each value,
/// prefix, and payload.
fn settle_canonical(source: &[u8], words: &WordStore<'_>, row: &Row) -> CanonicalArm {
    if row.deleted() {
        return CanonicalArm::Skip;
    }
    let head = head_word(row.field, row.kind);
    match row.base() {
        Base::Intact => match row.kind {
            RecordKind::Varint => CanonicalArm::Varint {
                head,
                // SAFETY: the scan admitted this varint at this
                // offset — the row's geometry is the proof.
                word: unsafe {
                    slice::value64_unchecked(source, usize_of(row.start.as_inner() + row.tag_w()))
                },
            },
            RecordKind::I32 => {
                CanonicalArm::I32 { head, value: CanonicalValue::Doc { at: row.payload_at() } }
            }
            RecordKind::I64 => {
                CanonicalArm::I64 { head, value: CanonicalValue::Doc { at: row.payload_at() } }
            }
            RecordKind::Len => {
                if row.opened() {
                    CanonicalArm::OpenLen { head, first: row.kid }
                } else {
                    CanonicalArm::OpaqueLen {
                        head,
                        payload: CanonicalPayload::Doc {
                            at: row.payload_at(),
                            len: row.payload_len.as_inner(),
                        },
                    }
                }
            }
        },
        Base::Replaced | Base::Inserted => match row.kind {
            RecordKind::Varint => {
                CanonicalArm::Varint { head, word: words.word(WordAt::of_slot(row.value)) }
            }
            RecordKind::I32 => {
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::as_conversions,
                    reason = "fixed 32-bit words are stored zero-extended"
                )]
                let bits = words.word(WordAt::of_slot(row.value)) as u32;
                CanonicalArm::I32 { head, value: CanonicalValue::Store(Word::Bits32(bits)) }
            }
            RecordKind::I64 => CanonicalArm::I64 {
                head,
                value: CanonicalValue::Store(Word::Bits64(words.word(WordAt::of_slot(row.value)))),
            },
            RecordKind::Len => CanonicalArm::OpaqueLen {
                head,
                payload: CanonicalPayload::Store(PayloadAt::of_slot(row.value)),
            },
        },
    }
}

/// The canonical sizing walk: one complete pass over the
/// materialized commitment closure, settling every opened LEN's
/// canonical body (in walk order) for the emit walk's prefixes.
/// Every live row is visited — the walk follows visibility, not
/// dirt, so a clean machine still pays it in full. The accumulator
/// is cumulative; frames record entry marks in their body slots
/// ([`size_subtree`]'s discipline over the whole chain).
fn canonical_size_pass<P: Payloads>(
    source: &[u8],
    rows: &[Row],
    words: &WordStore<'_>,
    payloads: &P,
    bodies: &mut Lane<'_, u64>,
    spine: &mut Lane<'_, u32>,
    top: Option<RowId>,
) -> Result<u32, SaveFault> {
    bodies.truncate(0);
    spine.truncate(0);
    let mut acc: u64 = 0;
    let mut open: Option<RowId> = None;
    let mut cur = top;
    loop {
        let Some(id) = cur else {
            let Some(container) = open else { break };
            // SAFETY: `open` holds minted links only.
            let row = unsafe { linked(rows, container.index()) };
            let slot = spine_close(spine);
            let entry = *bodies.get(slot);
            let grown = acc - entry;
            let body = u32::try_from(grown)
                .ok()
                .and_then(PayloadLen::new)
                .ok_or(SaveFault::BodyOverCap { at: row.start.as_inner() })?;
            let body = body.as_inner();
            *bodies.get_mut(slot) = u64::from(body);
            acc += u64::from(encoded_len32(head_word(row.field, row.kind)))
                + u64::from(encoded_len32(body));
            cur = row.next;
            open = row.parent;
            continue;
        };
        // SAFETY: the walk follows minted links from the top chain.
        let row = unsafe { linked(rows, id.index()) };
        match settle_canonical(source, words, row) {
            CanonicalArm::Skip => {}
            CanonicalArm::Varint { head, word } => {
                acc += u64::from(encoded_len32(head)) + u64::from(encoded_len64(word));
            }
            CanonicalArm::I32 { head, .. } => acc += u64::from(encoded_len32(head)) + 4,
            CanonicalArm::I64 { head, .. } => acc += u64::from(encoded_len32(head)) + 8,
            CanonicalArm::OpaqueLen { head, payload } => {
                let len = match payload {
                    CanonicalPayload::Doc { len, .. } => len,
                    CanonicalPayload::Store(value) => payloads.len(value),
                };
                acc +=
                    u64::from(encoded_len32(head)) + u64::from(encoded_len32(len)) + u64::from(len);
            }
            CanonicalArm::OpenLen { first, .. } => {
                spine_enter(bodies, spine, acc);
                open = Some(id);
                cur = first;
                continue;
            }
        }
        cur = row.next;
    }
    u32::try_from(acc)
        .ok()
        .filter(|n| *n <= PayloadLen::MAX.as_inner())
        .ok_or(SaveFault::DocOverCap { total: acc })
}

/// The canonical emit walk: the sizing walk's twin, forward,
/// writing into the shared emitter. Climbing out of opened LENs
/// follows parent links — the spine is the arena itself. Returns
/// the count of body slots consumed, for the faces' seam assertion.
fn canonical_emit_pass<P: Payloads, O: Out>(
    source: &[u8],
    rows: &[Row],
    words: &WordStore<'_>,
    payloads: &P,
    emit: &mut O,
    bodies: &[u64],
    top: Option<RowId>,
) -> usize {
    let mut body_cursor = 0;
    let mut open: Option<RowId> = None;
    let mut cur = top;
    loop {
        let Some(id) = cur else {
            let Some(container) = open else { break };
            // SAFETY: `open` holds minted links only.
            let row = unsafe { linked(rows, container.index()) };
            cur = row.next;
            open = row.parent;
            continue;
        };
        // SAFETY: the walk follows minted links from the top chain.
        let row = unsafe { linked(rows, id.index()) };
        match settle_canonical(source, words, row) {
            CanonicalArm::Skip => {}
            CanonicalArm::Varint { head, word } => {
                emit.word(head);
                emit.varint(word);
            }
            CanonicalArm::I32 { head, value } => {
                emit.word(head);
                match value {
                    CanonicalValue::Doc { at } => emit.verbatim(at, at + 4),
                    CanonicalValue::Store(word) => emit.value(word),
                }
            }
            CanonicalArm::I64 { head, value } => {
                emit.word(head);
                match value {
                    CanonicalValue::Doc { at } => emit.verbatim(at, at + 8),
                    CanonicalValue::Store(word) => emit.value(word),
                }
            }
            CanonicalArm::OpaqueLen { head, payload } => {
                emit.word(head);
                match payload {
                    CanonicalPayload::Doc { at, len } => {
                        emit.varint(u64::from(len));
                        emit.verbatim(at, at + len);
                    }
                    CanonicalPayload::Store(value) => {
                        emit.varint(u64::from(payloads.len(value)));
                        payloads.for_each_piece(value, |piece| emit.bytes(piece));
                    }
                }
            }
            CanonicalArm::OpenLen { head, first, .. } => {
                emit.word(head);
                emit.varint(u64::from(body_at(bodies, body_cursor)));
                body_cursor += 1;
                open = Some(id);
                cur = first;
                continue;
            }
        }
        cur = row.next;
    }
    emit.flush();
    body_cursor
}

// ─── the mixed machine ───

/// A fixed-scratch one-shot editing patch over one borrowed source.
///
/// Plain data over `&'a [u8]`: no share counting, no interior
/// mutability — the machine is `Send` because there is nothing to
/// engineer around. Working memory is the caller's slab, borrowed
/// exclusively for `'s` and carved once at the door; the slab's
/// content is contractually garbage after the machine goes. Handles
/// stay valid for the machine's life; rows and stored values are
/// never reclaimed (re-setting a copied payload leaves the old
/// bytes behind inert — the commit-only trade, priced by the plan's
/// cumulative staged capacity). `'p` backs the borrowed payloads
/// (`set_payload`, `insert_payload`): each is held until a save
/// copies it into the output. The three lifetimes are independent —
/// source, payload owners, and slab may die in any order once the
/// machine is gone.
///
/// The save faces take `&mut self`: the priced body table and the
/// container spine are carved machine scratch, reused across saves.
/// Saving is repeatable and changes no observable state.
pub struct Patch<'a, 'p, 's> {
    source: &'a [u8],
    rows: Lane<'s, Row>,
    words: WordStore<'s>,
    payloads: PayloadStore<'s, 'p>,
    faults: Lane<'s, SlotFault>,
    /// Save scratch: one priced LEN body per opened spine frame,
    /// entry marks while sizing.
    bodies: Lane<'s, u64>,
    /// Save scratch: the open spine frames' body slots.
    spine: Lane<'s, u32>,
    top: Option<RowId>,
    limit: DepthLimit,
    /// The whole-document edit latch: raised by the first edit and
    /// never lowered (commit-only), so a clean save is one copy of
    /// the source, no walk.
    dirty: bool,
}

impl<'a, 'p, 's> Patch<'a, 'p, 's> {
    /// Borrows `source` and the slab, carves the plan's lanes, and
    /// scans the flat root layer eagerly — zero bytes are copied
    /// and zero allocator calls are made; LEN payloads wait for
    /// [`Patch::descend`].
    ///
    /// Judgment order: source admission, then the slab length
    /// against [`Plan::bytes`] (a pure compare — alignment is
    /// priced in), then the root scan against the carved row lane.
    /// On any `Err` no machine is published and the slab holds no
    /// live state.
    ///
    /// # Errors
    ///
    /// [`OpenFault::TooLarge`] beyond the coordinate class
    /// (`i32::MAX` bytes), [`OpenFault::SlabShort`] when the slab
    /// undercuts the plan's demand,
    /// [`OpenFault::ScratchExhausted`] when the root layer holds
    /// more records than the planned rows, [`OpenFault::Wire`] when
    /// the root layer violates the wire grammar, and
    /// [`OpenFault::Refused`] when it carries a group code.
    pub fn open(
        source: &'a [u8],
        limit: DepthLimit,
        plan: &Plan,
        slab: &'s mut [MaybeUninit<u8>],
    ) -> Result<Self, OpenFault> {
        let len = admit(source.len()).ok_or(OpenFault::TooLarge { len: source.len() })?;
        let caps = plan.caps(limit);
        let need = caps.priced();
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        let have = slab.len() as u64;
        if have < need {
            return Err(OpenFault::SlabShort { need, have });
        }
        // The carve derives from the one ladder list
        // (`carve_ladder!` above), which asserts the descending
        // alignment and binds each lane by its ladder name; the
        // judgment above priced these same capacities.
        let MixedLanes { words, bodies, slots, mut rows, faults, spine, staged } =
            carve_mixed!(slab, caps);
        let words = WordStore::new(words);
        let top = scan_layer(&mut rows, source, 0, len, None).map_err(|halt| match halt {
            Halt::Wire(fault) => OpenFault::Wire(fault),
            Halt::Refused(refusal) => OpenFault::Refused(refusal),
            Halt::Exhausted => OpenFault::ScratchExhausted { role: ScratchRole::Rows },
        })?;
        Ok(Self {
            source,
            rows,
            words,
            payloads: PayloadStore::new(staged, slots),
            faults,
            bodies,
            spine,
            top,
            limit,
            dirty: false,
        })
    }

    /// The borrowed source bytes.
    #[inline]
    #[must_use]
    pub const fn source(&self) -> &'a [u8] {
        self.source
    }

    /// Per-role high-water occupancy against capacity — the sizing
    /// loop's answer face. High-water is cumulative demand: rows a
    /// refused descent occupied while scanning and bytes an
    /// abandoned frame staged while live both count, because the
    /// plan had to hold them.
    #[inline]
    #[must_use]
    pub const fn budget(&self) -> Budget {
        Budget {
            rows: self.rows.gauge(),
            words: self.words.gauge(),
            payload_slots: self.payloads.slots_gauge(),
            staged_bytes: self.payloads.staged_gauge(),
            faults: self.faults.gauge(),
        }
    }

    /// A gated row by coordinate (every public entry gates first).
    const fn row(&self, id: RowId) -> &Row {
        self.rows.get(id.as_inner())
    }

    /// Mutable twin of [`Patch::row`].
    const fn row_mut(&mut self, id: RowId) -> &mut Row {
        self.rows.get_mut(id.as_inner())
    }

    /// Containers enclosing a row (its nesting depth).
    const fn depth_of(&self, id: RowId) -> u32 {
        let mut depth = 0;
        let mut cur = self.row(id).parent;
        while let Some(parent) = cur {
            depth += 1;
            cur = self.row(parent).parent;
        }
        depth
    }

    /// The top layer's records in wire order (deleted records
    /// included — topology is stable, presentation filters).
    #[inline]
    pub const fn top(&self) -> Children<'_> {
        Children { rows: self.rows.inited(), cur: self.top }
    }

    /// A descended LEN's records in wire order. Empty for scalars
    /// and for containers whose interior never opened.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn children(&self, handle: Handle) -> Children<'_> {
        let rows = self.rows.inited();
        Children { rows, cur: gate(rows, handle).kid }
    }

    /// The record's enclosing container, `None` at the top layer.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn parent(&self, handle: Handle) -> Option<Handle> {
        gate(self.rows.inited(), handle).parent.map(Handle)
    }

    /// The record's ancestor chain, innermost container first.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn ancestors(&self, handle: Handle) -> Ancestors<'_> {
        let rows = self.rows.inited();
        Ancestors { rows, cur: gate(rows, handle).parent }
    }

    /// The record's wire kind.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn kind(&self, handle: Handle) -> RecordKind {
        gate(self.rows.inited(), handle).kind
    }

    /// The record's field number.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn field(&self, handle: Handle) -> FieldNumber {
        gate(self.rows.inited(), handle).field
    }

    /// The record's observable edit state.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn status(&self, handle: Handle) -> EditStatus {
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return EditStatus::Deleted;
        }
        match row.base() {
            Base::Intact => EditStatus::Intact,
            Base::Replaced => EditStatus::Replaced,
            Base::Inserted => EditStatus::Inserted,
        }
    }

    /// The record's whole source span (head tag through its last
    /// byte, at the scanned widths); `None` for authored records,
    /// which have no source geometry.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn span(&self, handle: Handle) -> Option<Span> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() {
            return None;
        }
        Some(Span::new(row.start.as_inner(), row.span_end()))
    }

    /// The narrowest source-backed record whose span contains `pos`
    /// — the coordinate-resolving face (a source offset in, the
    /// owning record out). Descends exactly as far as containers
    /// have been opened: an unopened or faulted LEN answers as
    /// itself. Authored records have no source geometry and are
    /// never named; edit state is not consulted (a deleted record
    /// still owns its source bytes).
    #[must_use]
    pub fn narrowest(&self, pos: u32) -> Option<Handle> {
        let mut best: Option<RowId> = None;
        let mut chain = self.top;
        while let Some(first) = chain {
            let mut hit: Option<RowId> = None;
            let mut cursor = Some(first);
            while let Some(id) = cursor {
                let row = self.row(id);
                if row.has_source() {
                    if row.start.as_inner() > pos {
                        break;
                    }
                    if pos < row.span_end() {
                        hit = Some(id);
                    }
                }
                cursor = row.next;
            }
            let Some(id) = hit else { break };
            best = Some(id);
            chain = self.row(id).kid;
        }
        best.map(Handle)
    }

    /// The record's source geometry, split by role at the scanned
    /// widths; `None` for authored records.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn source_spans(&self, handle: Handle) -> Option<RecordSpans> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() {
            return None;
        }
        let tag = Span::new(row.start.as_inner(), row.start.as_inner() + row.tag_w());
        Some(match row.kind {
            RecordKind::Varint => {
                RecordSpans::Varint { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::I32 => {
                RecordSpans::I32 { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::I64 => {
                RecordSpans::I64 { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::Len => {
                let payload_at = row.payload_at();
                RecordSpans::Len {
                    tag,
                    prefix: Span::new(tag.end(), payload_at),
                    payload: Span::new(payload_at, row.span_end()),
                }
            }
        })
    }

    /// Designates the record for cross-machine transfer: the exact
    /// source record bytes bound to their proved field, kind, and
    /// framing geometry. The designation names the original
    /// admitted occurrence — a pending value replacement does not
    /// ride, and rows without a live source occurrence
    /// (command-authored or deleted ones) refuse.
    ///
    /// # Errors
    ///
    /// [`Fault::NotSourceBacked`](crate::source::groupless::Fault::NotSourceBacked)
    /// for authored and deleted rows.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn record_ref(
        &self,
        handle: Handle,
    ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() || row.deleted() {
            return Err(crate::source::groupless::Fault::NotSourceBacked);
        }
        let at = usize_of(row.start.as_inner());
        let end = usize_of(row.span_end());
        // SAFETY: `has_source` (judged above) is the stored-geometry
        // witness — scanned rows store their met tag width.
        let Some(tag_w) = row.tag_width else { unsafe { core::hint::unreachable_unchecked() } };
        Ok(crate::source::groupless::RecordRef::mint(
            // SAFETY: scanned spans lie within the admitted source.
            unsafe { self.source.get_unchecked(at..end) },
            row.field,
            row.kind,
            tag_w,
            row.delim_width,
            row.payload_len.as_inner(),
            false,
        ))
    }

    /// The varint record's current value (`None`: not a VARINT
    /// record): the pending replacement if one is set, the scanned
    /// value otherwise (deleted records keep answering — deletion
    /// only prunes the save).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn varint_word(&self, handle: Handle) -> Option<u64> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::Varint) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan admitted this varint at this offset —
            // the row's geometry is the proof.
            Base::Intact => unsafe {
                slice::value64_unchecked(self.source, usize_of(row.start.as_inner() + row.tag_w()))
            },
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
        })
    }

    /// The fixed 32-bit record's current value bits (`None`: not an
    /// I32 record).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn i32_bits(&self, handle: Handle) -> Option<u32> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::I32) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan judged four value bytes inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => u32::from_le(unsafe {
                self.source
                    .as_ptr()
                    .add(usize_of(row.start.as_inner() + row.tag_w()))
                    .cast::<u32>()
                    .read_unaligned()
            }),
            #[allow(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "fixed 32-bit words are stored zero-extended"
            )]
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)) as u32,
        })
    }

    /// The fixed 64-bit record's current value bits (`None`: not an
    /// I64 record).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn i64_bits(&self, handle: Handle) -> Option<u64> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::I64) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan judged eight value bytes inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => u64::from_le(unsafe {
                self.source
                    .as_ptr()
                    .add(usize_of(row.start.as_inner() + row.tag_w()))
                    .cast::<u64>()
                    .read_unaligned()
            }),
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
        })
    }

    /// Opens a LEN's interior for editing. The payload parses on
    /// the first call — an explicit commitment that these bytes are
    /// a message, never a speculation — and the verdict is
    /// resident: a wire fault or a refusal (lawful wire outside
    /// this machine's language or declared bounds) parks on the
    /// record and projects unchanged on every later call.
    ///
    /// # Errors
    ///
    /// [`EditFault::KindMismatch`] for scalar records,
    /// [`EditFault::DeletedTarget`] for deleted ones,
    /// [`EditFault::AuthoredPayload`] when the payload was replaced
    /// or command-authored (there is no source interior),
    /// [`EditFault::ScratchExhausted`] when the interior rows
    /// outgrow the planned row capacity or the verdict table is
    /// full (the verdict is not parked). On any `Err` the machine
    /// is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
        let id = handle.0;
        let row = *gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        if !matches!(row.kind, RecordKind::Len) {
            return Err(EditFault::KindMismatch { have: row.kind });
        }
        if !matches!(row.base(), Base::Intact) {
            return Err(EditFault::AuthoredPayload);
        }
        if row.opened() {
            return Ok(Descent::Opened { first: row.kid.map(Handle) });
        }
        if row.faulted() {
            return Ok(project(self.faults.inited(), row.value));
        }
        let depth = self.depth_of(id);
        if depth >= u32::from(self.limit.as_inner()) {
            return self.park(
                id,
                SlotFault::Refused(Refusal::DepthExceeded {
                    at: row.start.as_inner(),
                    field: row.field,
                }),
            );
        }
        let body_at = row.payload_at();
        let mark = self.rows.len();
        match scan_layer(
            &mut self.rows,
            self.source,
            body_at,
            body_at + row.payload_len.as_inner(),
            Some(id),
        ) {
            Ok(first) => {
                let row = self.row_mut(id);
                row.kid = first;
                row.set_opened();
                Ok(Descent::Opened { first: first.map(Handle) })
            }
            Err(halt) => {
                self.rows.truncate(mark);
                match halt {
                    Halt::Wire(fault) => self.park(id, SlotFault::Wire(fault)),
                    Halt::Refused(refusal) => self.park(id, SlotFault::Refused(refusal)),
                    Halt::Exhausted => Err(EditFault::ScratchExhausted { role: ScratchRole::Rows }),
                }
            }
        }
    }

    /// Parks a resident verdict on a LEN's record and projects it.
    fn park(&mut self, id: RowId, fault: SlotFault) -> Result<Descent<'_>, EditFault> {
        let Some(index) = self.faults.push(fault) else {
            return Err(EditFault::ScratchExhausted { role: ScratchRole::Faults });
        };
        let row = self.row_mut(id);
        row.value = index;
        row.set_faulted();
        Ok(project(self.faults.inited(), index))
    }

    /// Records an edit at `id`: the whole-document latch, the row's
    /// own witness bit, and the ancestor chain's. Monotone bits
    /// stop the walk at the first ancestor already carrying one —
    /// its own ancestors were marked when it was.
    const fn mark_dirty(&mut self, id: RowId) {
        self.dirty = true;
        let mut cur = Some(id);
        while let Some(at) = cur {
            let row = self.row_mut(at);
            if row.dirty() {
                break;
            }
            row.set_dirty();
            cur = row.parent;
        }
    }

    /// The shared scalar setter: kind and deletion gates, then the
    /// one fallible store step, then the state flip.
    #[track_caller]
    fn set_scalar(&mut self, handle: Handle, want: RecordKind, word: u64) -> Result<(), EditFault> {
        let row = *gate(self.rows.inited(), handle);
        if row.kind != want {
            return Err(EditFault::KindMismatch { have: row.kind });
        }
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        match row.base() {
            Base::Intact => {
                let at = self
                    .words
                    .push_word(word)
                    .map_err(|role| EditFault::ScratchExhausted { role })?;
                let row = self.row_mut(handle.0);
                row.value = at.raw();
                row.set_replaced();
            }
            Base::Replaced | Base::Inserted => {
                self.words.set_word(WordAt::of_slot(row.value), word);
            }
        }
        self.mark_dirty(handle.0);
        Ok(())
    }

    /// Replaces the varint record's value. The source tag bytes —
    /// padded or not — still ride verbatim at save; only the value
    /// re-emits, minimally.
    ///
    /// # Errors
    ///
    /// [`EditFault::KindMismatch`] unless the record is a varint,
    /// [`EditFault::DeletedTarget`] for deleted ones,
    /// [`EditFault::ScratchExhausted`] when the value column is
    /// full. On any `Err` the machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::Varint, value)
    }

    /// Replaces the fixed 32-bit record's value bits.
    ///
    /// # Errors
    ///
    /// As [`Patch::set_varint`], with the fixed 32-bit kind gate.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_i32(&mut self, handle: Handle, bits: u32) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::I32, u64::from(bits))
    }

    /// Replaces the fixed 64-bit record's value bits.
    ///
    /// # Errors
    ///
    /// As [`Patch::set_varint`], with the fixed 64-bit kind gate.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_i64(&mut self, handle: Handle, bits: u64) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::I64, bits)
    }

    /// The shared payload-set gates; `Ok` carries the row copy.
    #[track_caller]
    const fn payload_set_gate(&self, handle: Handle, len: usize) -> Result<Row, EditFault> {
        let row = *gate(self.rows.inited(), handle);
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
        Ok(row)
    }

    /// The infallible suffix of a payload set: the value slot, the
    /// state flip, the dirty mark.
    const fn payload_set_commit(&mut self, handle: Handle, value: u32) {
        let row = self.row_mut(handle.0);
        row.value = value;
        row.clear_faulted();
        if matches!(row.base(), Base::Intact) {
            row.set_replaced();
        }
        self.mark_dirty(handle.0);
    }

    /// Deletes the record: it vanishes whole at save, subtree
    /// included — interior records and any insertions made inside
    /// them emit nothing. Commit-only: there is no restore.
    ///
    /// # Errors
    ///
    /// [`EditFault::DeletedTarget`] when the record is already
    /// deleted. On `Err` the machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        self.row_mut(handle.0).set_deleted();
        self.mark_dirty(handle.0);
        Ok(())
    }

    /// Gates an insertion container; `Ok` carries its row.
    #[track_caller]
    const fn container_gate(&self, container: Option<Handle>) -> Result<Option<RowId>, EditFault> {
        let Some(handle) = container else {
            return Ok(None);
        };
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        match row.kind {
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
    fn resolve_anchor(&self, at: InsertAt) -> Result<SplicePoint, EditFault> {
        match at {
            InsertAt::HeadOf(container) => {
                Ok(SplicePoint { parent: self.container_gate(container)?, prev: None })
            }
            InsertAt::TailOf(container) => {
                let parent = self.container_gate(container)?;
                Ok(SplicePoint { parent, prev: self.tail_of(parent) })
            }
            InsertAt::After(anchor) => {
                let row = gate(self.rows.inited(), anchor);
                Ok(SplicePoint { parent: row.parent, prev: Some(anchor.0) })
            }
        }
    }

    /// Mints the next row coordinate for an insertion — the row
    /// lane's capacity judgment; nothing is occupied.
    const fn mint_insert(&self) -> Result<RowId, EditFault> {
        let Some(at) = self.rows.mint() else {
            return Err(EditFault::ScratchExhausted { role: ScratchRole::Rows });
        };
        // SAFETY: `at < capacity` by the mint, and the plan judged
        // the capacity into the RowId domain at construction.
        Ok(unsafe { RowId::new_unchecked(at) })
    }

    /// Splices an authored row (the infallible suffix of every
    /// insert command: every judgment holds).
    fn apply_insert(
        &mut self,
        point: &SplicePoint,
        id: RowId,
        field: FieldNumber,
        kind: RecordKind,
        value: u32,
    ) {
        let next =
            point.prev.map_or_else(|| self.first_of(point.parent), |prev| self.row(prev).next);
        self.rows.push_minted(Row::authored(field, kind, point.parent, next, value));
        match point.prev {
            Some(prev) => self.row_mut(prev).next = Some(id),
            None => match point.parent {
                Some(parent) => self.row_mut(parent).kid = Some(id),
                None => self.top = Some(id),
            },
        }
        self.mark_dirty(id);
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
    /// payload, [`EditFault::ScratchExhausted`] when the row or
    /// value lane is full. On any `Err` the machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_varint(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        value: u64,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value =
            self.words.push_word(value).map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Varint, value.raw());
        Ok(Handle(id))
    }

    /// Inserts a fixed 32-bit record at the anchor.
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_i32(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        bits: u32,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value = self
            .words
            .push_word(u64::from(bits))
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::I32, value.raw());
        Ok(Handle(id))
    }

    /// Inserts a fixed 64-bit record at the anchor.
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_i64(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        bits: u64,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value =
            self.words.push_word(bits).map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::I64, value.raw());
        Ok(Handle(id))
    }

    /// The exact byte length [`Patch::save_into`] would write,
    /// without producing bytes: the sizing walk alone. A machine
    /// with no edits answers in O(1): the save is the source.
    ///
    /// # Errors
    ///
    /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
    /// outgrows the length class, [`SaveFault::DocOverCap`] when
    /// the document outgrows the coordinate class.
    pub fn save_len(&mut self) -> Result<u32, SaveFault> {
        if !self.dirty {
            return Ok(admitted_u32(self.source.len()));
        }
        size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )
    }

    /// Serializes the machine's current state into the front of
    /// `out`, returning the written length — this face fills the
    /// caller's slice, where the heap editors' `save_into` appends
    /// to a `Vec` — the storage decides the delivery, like
    /// `io::Write`. One sizing walk prices
    /// the save and surfaces every fault first — records whose
    /// subtree carries no edit ride the source verbatim (contiguous
    /// runs coalesced into single copies, padded framing included),
    /// each dirty record becomes a splice, and a machine that never
    /// took an edit skips the walk outright: the whole source lands
    /// as one copy. Saving is repeatable: the machine is not
    /// consumed and no observable state changes.
    ///
    /// # Errors
    ///
    /// [`SaveFault::BodyOverCap`] and [`SaveFault::DocOverCap`] as
    /// the sizing faults; [`SaveFault::OutputShort`] when `out`
    /// undercuts the priced save. On any `Err` `out` is untouched —
    /// zero bytes are written.
    ///
    /// # Panics
    ///
    /// If the sizing and emit walks disagree — a library bug caught
    /// at the seam.
    pub fn save_into(&mut self, out: &mut [u8]) -> Result<u32, SaveFault> {
        if !self.dirty {
            let need = admitted_u32(self.source.len());
            if out.len() < self.source.len() {
                return Err(SaveFault::OutputShort { need, have: out.len() });
            }
            out[..self.source.len()].copy_from_slice(self.source);
            return Ok(need);
        }
        let total = size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        if out.len() < usize_of(total) {
            return Err(SaveFault::OutputShort { need: total, have: out.len() });
        }
        let mut emit = SliceEmit { out, at: 0, src: self.source, run: None };
        emit_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(emit.at == usize_of(total), "fixed patch save: the emit walk covers the price");
        Ok(total)
    }

    /// Serializes by handing the save's bytes to `sink` as borrowed
    /// slices, in output order — no output buffer: verbatim runs
    /// pass through as windows of the source, authored words ride a
    /// ten-byte stack window, and the concatenation is exactly
    /// [`Patch::save_into`]'s output.
    ///
    /// One sizing pass runs first and surfaces every fault — its
    /// priced bodies feed the emit walk directly — so nothing can
    /// refuse once the first slice is handed over.
    ///
    /// # Errors
    ///
    /// As [`Patch::save_len`]; on `Err` the sink has been handed
    /// nothing.
    ///
    /// # Panics
    ///
    /// If the sizing and emit walks disagree — a library bug caught
    /// at the seam.
    pub fn save_sink(&mut self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
        if !self.dirty {
            if !self.source.is_empty() {
                sink(self.source);
            }
            return Ok(());
        }
        let total = size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        let mut emit = SinkEmit { src: self.source, sink: &mut sink, run: None, written: 0 };
        emit_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            emit.written == u64::from(total),
            "fixed patch save: the sink walk covers the price"
        );
        Ok(())
    }

    /// Serializes under the `CanonicalMinimal` output standard into
    /// the front of `out`, returning the written length: minimally
    /// emits every varint construct in the materialized commitment
    /// closure — the root layer plus each source LEN interior a
    /// successful descend committed; opaque LEN payload bytes pass
    /// unchanged behind re-derived framing.
    ///
    /// # Errors
    ///
    /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
    /// body outgrows the length class, [`SaveFault::DocOverCap`]
    /// when the canonical document outgrows the coordinate class,
    /// [`SaveFault::OutputShort`] when `out` undercuts the priced
    /// canonical save. On any `Err` `out` is untouched.
    ///
    /// # Panics
    ///
    /// If the canonical sizing and emit walks disagree — a library
    /// bug caught at the seam.
    pub fn save_canonical_into(&mut self, out: &mut [u8]) -> Result<u32, SaveFault> {
        let total = canonical_size_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        if out.len() < usize_of(total) {
            return Err(SaveFault::OutputShort { need: total, have: out.len() });
        }
        let mut emit = SliceEmit { out, at: 0, src: self.source, run: None };
        let consumed = canonical_emit_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            consumed == usize_of(self.bodies.len()) && emit.at == usize_of(total),
            "fixed patch canonical save: sizing and emission disagree"
        );
        Ok(total)
    }

    /// [`Patch::save_canonical_into`]'s bytes handed to `sink` as
    /// borrowed slices, in output order — no output buffer: opaque
    /// payload runs and fixed-width source values pass through as
    /// windows of the source, framing words ride a ten-byte stack
    /// window.
    ///
    /// The sizing walk runs first and surfaces every fault, so
    /// nothing can refuse once the first slice is handed over.
    ///
    /// # Errors
    ///
    /// As [`Patch::save_canonical_into`], less the output judgment;
    /// on `Err` the sink has been handed nothing.
    ///
    /// # Panics
    ///
    /// If the canonical sizing and emit walks disagree — a library
    /// bug caught at the seam.
    pub fn save_canonical_sink(&mut self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
        let total = canonical_size_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        let mut emit = SinkEmit { src: self.source, sink: &mut sink, run: None, written: 0 };
        let consumed = canonical_emit_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            consumed == usize_of(self.bodies.len()) && emit.written == u64::from(total),
            "fixed patch canonical save: the sink walk covers the price"
        );
        Ok(())
    }
}

impl<'a, 'p, 's> Patch<'a, 'p, 's> {
    /// The LEN record's current payload bytes (`None`: not a LEN
    /// record, or its pending replacement is scatter-supplied —
    /// [`Patch::set_payload_parts`]'s pieces concatenate only at
    /// the save's gather, so no contiguous borrowed view exists
    /// before it): the pending replacement if one is set, the
    /// scanned payload otherwise — readable even while a resident
    /// descend verdict parks on the record.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::Len) {
            return None;
        }
        match row.base() {
            // SAFETY: the scan judged the payload extent inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => Some(unsafe {
                self.source.get_unchecked(
                    usize_of(row.payload_at())
                        ..usize_of(row.payload_at() + row.payload_len.as_inner()),
                )
            }),
            Base::Replaced | Base::Inserted => {
                self.payloads.contiguous(PayloadAt::of_slot(row.value))
            }
        }
    }

    /// Replaces the LEN record's payload wholesale. The source tag
    /// rides verbatim; the length prefix rides verbatim too when
    /// the new payload keeps the source length, and re-authors
    /// minimally only when the length moved. The payload is
    /// borrowed until a save copies it into the output —
    /// [`Patch::set_payload_copy`] stages a copy instead, for
    /// temporaries.
    ///
    /// A record whose interior is open for editing refuses: the
    /// descent was a commitment, and its records' edits would be
    /// silently discarded by a wholesale replacement. A record with
    /// a resident descend fault accepts — replacing a broken
    /// payload is the repair path, and it clears the parked
    /// verdict.
    ///
    /// # Errors
    ///
    /// [`EditFault::KindMismatch`] unless the record is a LEN,
    /// [`EditFault::DeletedTarget`] for deleted ones,
    /// [`EditFault::OpenedTarget`] when the interior is open,
    /// [`EditFault::PayloadTooLarge`] beyond the length class,
    /// [`EditFault::ScratchExhausted`] when the slot table is full.
    /// On any `Err` the machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_payload(&mut self, handle: Handle, payload: &'p [u8]) -> Result<(), EditFault> {
        let row = self.payload_set_gate(handle, payload.len())?;
        let value = match row.base() {
            Base::Intact => self
                .payloads
                .push_borrowed(payload)
                .map_err(|role| EditFault::ScratchExhausted { role })?
                .raw(),
            Base::Replaced | Base::Inserted => {
                self.payloads.set_borrowed(PayloadAt::of_slot(row.value), payload);
                row.value
            }
        };
        self.payload_set_commit(handle, value);
        Ok(())
    }

    /// [`set_payload`](Patch::set_payload)'s staging twin: copies
    /// `payload` into the staged pool at the command, for
    /// temporaries that cannot outlive it. Same gates, same save
    /// shape; the interior stays the caller's declaration.
    ///
    /// # Errors
    ///
    /// As [`Patch::set_payload`], the capacity refusal naming the
    /// slot table or the staged pool.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_payload_copy(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
        let row = self.payload_set_gate(handle, payload.len())?;
        let value = match row.base() {
            Base::Intact => self
                .payloads
                .push_copied(payload)
                .map_err(|role| EditFault::ScratchExhausted { role })?
                .raw(),
            Base::Replaced | Base::Inserted => {
                self.payloads
                    .set_copied(PayloadAt::of_slot(row.value), payload)
                    .map_err(|role| EditFault::ScratchExhausted { role })?;
                row.value
            }
        };
        self.payload_set_commit(handle, value);
        Ok(())
    }

    /// [`set_payload`](Patch::set_payload)'s scatter twin: the
    /// payload arrives as borrowed pieces that concatenate behind
    /// one prefix at the save's gather — zero staging copies, and
    /// the pieces stay re-readable (the save may run more than
    /// once). Same gates, same save shape; the length judgment
    /// reads the concatenated length. A scatter-replaced record
    /// answers [`Patch::payload_bytes`] with `None` (no contiguous
    /// view exists before the gather).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_payload`].
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_payload_parts(
        &mut self,
        handle: Handle,
        parts: &'p [&'p [u8]],
    ) -> Result<(), EditFault> {
        let row = self.payload_set_gate(handle, parts_len_usize(parts))?;
        let value = match row.base() {
            Base::Intact => self
                .payloads
                .push_parts(parts)
                .map_err(|role| EditFault::ScratchExhausted { role })?
                .raw(),
            Base::Replaced | Base::Inserted => {
                self.payloads.set_parts(PayloadAt::of_slot(row.value), parts);
                row.value
            }
        };
        self.payload_set_commit(handle, value);
        Ok(())
    }

    /// Inserts a LEN record with an authored payload at the anchor.
    /// The payload is borrowed until a save copies it into the
    /// output — [`Patch::insert_payload_copy`] stages a copy
    /// instead, for temporaries. Its interior is the caller's
    /// declaration: it lands as opaque bytes, judged only if an
    /// explicit descend later commits it as a message.
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`], plus
    /// [`EditFault::PayloadTooLarge`] beyond the length class.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_payload(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        payload: &'p [u8],
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len: payload.len() });
        }
        let value = self
            .payloads
            .push_borrowed(payload)
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Len, value.raw());
        Ok(Handle(id))
    }

    /// [`insert_payload`](Patch::insert_payload)'s staging twin:
    /// copies `payload` into the staged pool at the command, for
    /// temporaries that cannot outlive it.
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_payload`], the capacity refusal naming
    /// the slot table or the staged pool.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_payload_copy(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        payload: &[u8],
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len: payload.len() });
        }
        let value = self
            .payloads
            .push_copied(payload)
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Len, value.raw());
        Ok(Handle(id))
    }

    /// [`insert_payload`](Patch::insert_payload)'s scatter twin:
    /// the payload arrives as borrowed pieces that concatenate
    /// behind one prefix at the save's gather — zero staging
    /// copies, re-readable pieces
    /// ([`Patch::set_payload_parts`]'s contract, at an anchor).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_payload`], the length judgment reading
    /// the concatenated length.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_payload_parts(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        parts: &'p [&'p [u8]],
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let len = parts_len_usize(parts);
        if len > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len });
        }
        let value =
            self.payloads.push_parts(parts).map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Len, value.raw());
        Ok(Handle(id))
    }

    /// Opens a staged replacement of the LEN record's payload:
    /// chunks copy into the staged pool through the returned frame,
    /// and the record flips atomically at
    /// [`finish`](PayloadWrite::finish) — until then the machine is
    /// observably unchanged, and an abandoned frame reclaims its
    /// staged bytes whole (high-water keeps them). The gates judge
    /// here, so the frame itself cannot discover a refused target.
    ///
    /// # Errors
    ///
    /// As [`Patch::set_payload_copy`]'s gates. On `Err` the machine
    /// is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn begin_set_payload(
        &mut self,
        handle: Handle,
    ) -> Result<PayloadWrite<'_, 'a, 'p, 's>, EditFault> {
        self.payload_set_gate(handle, 0)?;
        let mark = self.payloads.stage_mark();
        Ok(PayloadWrite { machine: self, op: WriteOp::Set { handle }, mark })
    }

    /// Opens a staged insertion of a fresh LEN record at the
    /// anchor: chunks copy into the staged pool through the
    /// returned frame, and exactly one row splices at
    /// [`finish`](PayloadWrite::finish) — until then the machine is
    /// observably unchanged ([`Patch::begin_set_payload`]'s frame
    /// contract). The anchor resolves here; the frame's exclusive
    /// borrow keeps it valid through the close.
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_payload_copy`]'s anchor gates. On `Err`
    /// the machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[track_caller]
    pub fn begin_insert_payload(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
    ) -> Result<PayloadWrite<'_, 'a, 'p, 's>, EditFault> {
        let point = self.resolve_anchor(at)?;
        let mark = self.payloads.stage_mark();
        Ok(PayloadWrite { machine: self, op: WriteOp::Insert { point, field }, mark })
    }

    /// Judges a length-class declaration against the staged pool's
    /// remaining capacity — the sized doors' shared suffix. The
    /// callers' gates already judged `len` into the length class.
    const fn stage_declare(&self, len: usize) -> Result<u32, EditFault> {
        if !self.payloads.stage_fits(len) {
            return Err(EditFault::ScratchExhausted { role: ScratchRole::StagedBytes });
        }
        Ok(admitted_u32(len))
    }

    /// [`begin_set_payload`](Patch::begin_set_payload)'s
    /// declared-length twin: the caller states the payload's exact
    /// byte length up front, so the class and capacity judgments
    /// land here — the whole declaration is judged against the pool
    /// before the frame opens, and staging inside it never re-runs
    /// a capacity judgment. The frame is held to its word: a write
    /// past the declaration refuses [`FrameFault::OverDeclared`], a
    /// finish short of it refuses [`FrameFault::UnderDeclared`],
    /// and either fault leaves the machine unchanged.
    ///
    /// # Errors
    ///
    /// As [`Patch::begin_set_payload`]'s gates, plus
    /// [`EditFault::PayloadTooLarge`] when `len` exceeds the length
    /// class and [`EditFault::ScratchExhausted`] when the staged
    /// pool cannot hold `len` more bytes. On `Err` the machine is
    /// unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn begin_set_payload_sized(
        &mut self,
        handle: Handle,
        len: usize,
    ) -> Result<SizedPayloadWrite<'_, 'a, 'p, 's>, EditFault> {
        self.payload_set_gate(handle, len)?;
        let declared = self.stage_declare(len)?;
        let mark = self.payloads.stage_mark();
        Ok(SizedPayloadWrite {
            inner: PayloadWrite { machine: self, op: WriteOp::Set { handle }, mark },
            declared,
        })
    }

    /// [`begin_insert_payload`](Patch::begin_insert_payload)'s
    /// declared-length twin
    /// ([`Patch::begin_set_payload_sized`]'s door contract, at an
    /// anchor).
    ///
    /// # Errors
    ///
    /// As [`Patch::begin_insert_payload`]'s anchor gates, plus the
    /// sized door's judgments: [`EditFault::PayloadTooLarge`] when
    /// `len` exceeds the length class and
    /// [`EditFault::ScratchExhausted`] when the staged pool cannot
    /// hold `len` more bytes. On `Err` the machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[track_caller]
    pub fn begin_insert_payload_sized(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        len: usize,
    ) -> Result<SizedPayloadWrite<'_, 'a, 'p, 's>, EditFault> {
        let point = self.resolve_anchor(at)?;
        if len > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len });
        }
        let declared = self.stage_declare(len)?;
        let mark = self.payloads.stage_mark();
        Ok(SizedPayloadWrite {
            inner: PayloadWrite { machine: self, op: WriteOp::Insert { point, field }, mark },
            declared,
        })
    }
}

/// A staged payload frame.
///
/// Chunks copy into the staged pool as they arrive, and exactly one
/// record changes at [`finish`](PayloadWrite::finish) — before it,
/// the machine is observably unchanged. Dropping the frame
/// unfinished reclaims its staged bytes — the pool returns to its
/// pre-frame byte cursor and capacity (high-water keeps the demand)
/// — and its exclusive borrow of the machine keeps every other
/// command out while it lives.
#[must_use = "a payload frame installs nothing until finished"]
pub struct PayloadWrite<'w, 'a, 'p, 's> {
    machine: &'w mut Patch<'a, 'p, 's>,
    op: WriteOp,
    /// The staged pool's tail at open: the staged extent is
    /// `mark..` for the frame's whole life.
    mark: u32,
}

impl Drop for PayloadWrite<'_, '_, '_, '_> {
    /// Reclaims the staged extent: only a publishing
    /// [`finish`](PayloadWrite::finish) keeps the staged bytes, so
    /// abandonment and every refusal path leave the pool's byte
    /// cursor and capacity exactly as the door found them.
    fn drop(&mut self) {
        self.machine.payloads.stage_abandon(self.mark);
    }
}

impl PayloadWrite<'_, '_, '_, '_> {
    /// Appends one chunk to the staged payload, copying it at the
    /// call — temporaries welcome; the staged pool owns them. An
    /// empty chunk is a no-op.
    ///
    /// # Errors
    ///
    /// [`EditFault::PayloadTooLarge`] when the staged total would
    /// leave the length class, [`EditFault::ScratchExhausted`] when
    /// the staged pool cannot hold the chunk. On `Err` the chunk is
    /// not staged and the frame stays usable.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), EditFault> {
        let staged = u64::from(self.machine.payloads.staged_len(self.mark));
        #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
        let total = staged.saturating_add(chunk.len() as u64);
        if total > u64::from(PayloadLen::MAX.as_inner()) {
            let len = usize::try_from(total).unwrap_or(usize::MAX);
            return Err(EditFault::PayloadTooLarge { len });
        }
        self.machine
            .payloads
            .stage_chunk(chunk)
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        Ok(())
    }

    /// Installs the staged payload: the set flips its record, the
    /// insert splices exactly one fresh row — atomically, now.
    /// Returns the changed record's handle (the set's own target,
    /// or the minted insertion).
    ///
    /// # Errors
    ///
    /// [`EditFault::ScratchExhausted`] when the row or slot lane is
    /// full. On `Err` the machine is unchanged — the staged bytes
    /// are reclaimed with the frame.
    pub fn finish(mut self) -> Result<Handle, EditFault> {
        match self.apply() {
            Ok(handle) => {
                core::mem::forget(self);
                Ok(handle)
            }
            Err(fault) => Err(fault),
        }
    }

    /// The publishing close: mints or overwrites the slot and
    /// applies the one command.
    fn apply(&mut self) -> Result<Handle, EditFault> {
        match self.op {
            WriteOp::Set { handle } => {
                let row = *gate(self.machine.rows.inited(), handle);
                let value = match row.base() {
                    Base::Intact => self
                        .machine
                        .payloads
                        .stage_finish_push(self.mark)
                        .map_err(|role| EditFault::ScratchExhausted { role })?
                        .raw(),
                    Base::Replaced | Base::Inserted => {
                        self.machine
                            .payloads
                            .stage_finish_set(PayloadAt::of_slot(row.value), self.mark);
                        row.value
                    }
                };
                self.machine.payload_set_commit(handle, value);
                Ok(handle)
            }
            WriteOp::Insert { point, field } => {
                let id = self.machine.mint_insert()?;
                let value = self
                    .machine
                    .payloads
                    .stage_finish_push(self.mark)
                    .map_err(|role| EditFault::ScratchExhausted { role })?;
                self.machine.apply_insert(&point, id, field, RecordKind::Len, value.raw());
                Ok(Handle(id))
            }
        }
    }
}

/// A staged payload frame held to a declared length.
///
/// The declaration was judged whole — length class and pool
/// capacity — when the door opened
/// ([`Patch::begin_set_payload_sized`],
/// [`Patch::begin_insert_payload_sized`]), so staging never re-runs
/// a capacity judgment; a write past the declaration refuses
/// [`FrameFault::OverDeclared`] and [`finish`](Self::finish)
/// installs only the exact declared extent —
/// [`FrameFault::UnderDeclared`] otherwise. Everything else is the
/// undeclared frame's contract: chunks copy in as they arrive,
/// exactly one record changes at the finish, and a dropped or
/// refused frame reclaims its staged bytes.
#[must_use = "a payload frame installs nothing until finished"]
pub struct SizedPayloadWrite<'w, 'a, 'p, 's> {
    inner: PayloadWrite<'w, 'a, 'p, 's>,
    /// The declared payload length, in the length class.
    declared: u32,
}

impl SizedPayloadWrite<'_, '_, '_, '_> {
    /// Appends one chunk to the staged payload, copying it at the
    /// call into bytes the door judged — spending the door's proof:
    /// no capacity judgment re-runs here, only the declaration
    /// compare below. An empty chunk is a no-op.
    ///
    /// # Errors
    ///
    /// [`FrameFault::OverDeclared`] when the staged total would
    /// pass the declaration. On `Err` the chunk is not staged and
    /// the frame stays usable.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), FrameFault> {
        let staged = u64::from(self.inner.machine.payloads.staged_len(self.inner.mark));
        #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
        let total = staged.saturating_add(chunk.len() as u64);
        if total > u64::from(self.declared) {
            return Err(FrameFault::OverDeclared { declared: self.declared, total });
        }
        self.inner.machine.payloads.stage_chunk_judged(chunk);
        Ok(())
    }

    /// Installs the staged payload exactly as declared — the
    /// undeclared frame's [`finish`](PayloadWrite::finish), behind
    /// the declaration judgment.
    ///
    /// # Errors
    ///
    /// [`FrameFault::UnderDeclared`] when fewer bytes than declared
    /// were staged, [`FrameFault::ScratchExhausted`] when the row
    /// or slot lane is full. On `Err` the machine is unchanged —
    /// the staged bytes are reclaimed with the frame.
    pub fn finish(self) -> Result<Handle, FrameFault> {
        let staged = self.inner.machine.payloads.staged_len(self.inner.mark);
        if staged != self.declared {
            return Err(FrameFault::UnderDeclared { declared: self.declared, staged });
        }
        self.inner.finish().map_err(close_fault)
    }
}

// ─── the borrowed-only machine ───

/// The borrowed-only fixed patch: every authored payload is
/// borrowed until a save copies it once into the output.
///
/// [`Patch`]'s command and save faces over the borrowed supply
/// alone. No staged pool exists, so neither the `_copy` faces nor
/// the staged frames do, and [`BorrowPlan`] drops the staged-byte
/// role whole; everything else — vocabulary, doors, the fidelity
/// and canonical contracts, the capacity discipline — is the mixed
/// machine's.
pub struct BorrowPatch<'a, 'p, 's> {
    source: &'a [u8],
    rows: Lane<'s, Row>,
    words: WordStore<'s>,
    payloads: BorrowedPayloadStore<'s, 'p>,
    faults: Lane<'s, SlotFault>,
    /// Save scratch: one priced LEN body per opened spine frame,
    /// entry marks while sizing.
    bodies: Lane<'s, u64>,
    /// Save scratch: the open spine frames' body slots.
    spine: Lane<'s, u32>,
    top: Option<RowId>,
    limit: DepthLimit,
    /// The whole-document edit latch ([`Patch`]'s contract).
    dirty: bool,
}

impl<'a, 'p, 's> BorrowPatch<'a, 'p, 's> {
    /// Borrows `source` and the slab, carves the plan's lanes, and
    /// scans the flat root layer eagerly ([`Patch::open`]'s door
    /// contract over [`BorrowPlan`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::open`].
    pub fn open(
        source: &'a [u8],
        limit: DepthLimit,
        plan: &BorrowPlan,
        slab: &'s mut [MaybeUninit<u8>],
    ) -> Result<Self, OpenFault> {
        let len = admit(source.len()).ok_or(OpenFault::TooLarge { len: source.len() })?;
        let caps = plan.caps(limit);
        let need = caps.priced();
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        let have = slab.len() as u64;
        if have < need {
            return Err(OpenFault::SlabShort { need, have });
        }
        // The carve derives from the one ladder list
        // (`carve_ladder!` above), which asserts the descending
        // alignment and binds each lane by its ladder name; the
        // judgment above priced these same capacities.
        let BorrowedLanes { words, bodies, slots, mut rows, faults, spine } =
            carve_borrowed!(slab, caps);
        let words = WordStore::new(words);
        let top = scan_layer(&mut rows, source, 0, len, None).map_err(|halt| match halt {
            Halt::Wire(fault) => OpenFault::Wire(fault),
            Halt::Refused(refusal) => OpenFault::Refused(refusal),
            Halt::Exhausted => OpenFault::ScratchExhausted { role: ScratchRole::Rows },
        })?;
        Ok(Self {
            source,
            rows,
            words,
            payloads: BorrowedPayloadStore::new(slots),
            faults,
            bodies,
            spine,
            top,
            limit,
            dirty: false,
        })
    }

    /// The borrowed source bytes.
    #[inline]
    #[must_use]
    pub const fn source(&self) -> &'a [u8] {
        self.source
    }

    /// Per-role high-water occupancy against capacity
    /// ([`Patch::budget`]'s contract, without the staged pool).
    #[inline]
    #[must_use]
    pub const fn budget(&self) -> BorrowBudget {
        BorrowBudget {
            rows: self.rows.gauge(),
            words: self.words.gauge(),
            payload_slots: self.payloads.slots_gauge(),
            faults: self.faults.gauge(),
        }
    }

    /// A gated row by coordinate (every public entry gates first).
    const fn row(&self, id: RowId) -> &Row {
        self.rows.get(id.as_inner())
    }

    /// Mutable twin of [`BorrowPatch::row`].
    const fn row_mut(&mut self, id: RowId) -> &mut Row {
        self.rows.get_mut(id.as_inner())
    }

    /// Containers enclosing a row (its nesting depth).
    const fn depth_of(&self, id: RowId) -> u32 {
        let mut depth = 0;
        let mut cur = self.row(id).parent;
        while let Some(parent) = cur {
            depth += 1;
            cur = self.row(parent).parent;
        }
        depth
    }

    /// The top layer's records in wire order ([`Patch::top`]).
    #[inline]
    pub const fn top(&self) -> Children<'_> {
        Children { rows: self.rows.inited(), cur: self.top }
    }

    /// A descended LEN's records in wire order
    /// ([`Patch::children`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn children(&self, handle: Handle) -> Children<'_> {
        let rows = self.rows.inited();
        Children { rows, cur: gate(rows, handle).kid }
    }

    /// The record's enclosing container, `None` at the top layer.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn parent(&self, handle: Handle) -> Option<Handle> {
        gate(self.rows.inited(), handle).parent.map(Handle)
    }

    /// The record's ancestor chain, innermost container first.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn ancestors(&self, handle: Handle) -> Ancestors<'_> {
        let rows = self.rows.inited();
        Ancestors { rows, cur: gate(rows, handle).parent }
    }

    /// The record's wire kind.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn kind(&self, handle: Handle) -> RecordKind {
        gate(self.rows.inited(), handle).kind
    }

    /// The record's field number.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn field(&self, handle: Handle) -> FieldNumber {
        gate(self.rows.inited(), handle).field
    }

    /// The record's observable edit state.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn status(&self, handle: Handle) -> EditStatus {
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return EditStatus::Deleted;
        }
        match row.base() {
            Base::Intact => EditStatus::Intact,
            Base::Replaced => EditStatus::Replaced,
            Base::Inserted => EditStatus::Inserted,
        }
    }

    /// The record's whole source span ([`Patch::span`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn span(&self, handle: Handle) -> Option<Span> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() {
            return None;
        }
        Some(Span::new(row.start.as_inner(), row.span_end()))
    }

    /// The narrowest source-backed record whose span contains `pos`
    /// ([`Patch::narrowest`]).
    #[must_use]
    pub fn narrowest(&self, pos: u32) -> Option<Handle> {
        let mut best: Option<RowId> = None;
        let mut chain = self.top;
        while let Some(first) = chain {
            let mut hit: Option<RowId> = None;
            let mut cursor = Some(first);
            while let Some(id) = cursor {
                let row = self.row(id);
                if row.has_source() {
                    if row.start.as_inner() > pos {
                        break;
                    }
                    if pos < row.span_end() {
                        hit = Some(id);
                    }
                }
                cursor = row.next;
            }
            let Some(id) = hit else { break };
            best = Some(id);
            chain = self.row(id).kid;
        }
        best.map(Handle)
    }

    /// The record's source geometry ([`Patch::source_spans`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn source_spans(&self, handle: Handle) -> Option<RecordSpans> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() {
            return None;
        }
        let tag = Span::new(row.start.as_inner(), row.start.as_inner() + row.tag_w());
        Some(match row.kind {
            RecordKind::Varint => {
                RecordSpans::Varint { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::I32 => {
                RecordSpans::I32 { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::I64 => {
                RecordSpans::I64 { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::Len => {
                let payload_at = row.payload_at();
                RecordSpans::Len {
                    tag,
                    prefix: Span::new(tag.end(), payload_at),
                    payload: Span::new(payload_at, row.span_end()),
                }
            }
        })
    }

    /// Designates the record for cross-machine transfer
    /// ([`Patch::record_ref`]).
    ///
    /// # Errors
    ///
    /// [`Fault::NotSourceBacked`](crate::source::groupless::Fault::NotSourceBacked)
    /// for authored and deleted rows.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn record_ref(
        &self,
        handle: Handle,
    ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() || row.deleted() {
            return Err(crate::source::groupless::Fault::NotSourceBacked);
        }
        let at = usize_of(row.start.as_inner());
        let end = usize_of(row.span_end());
        // SAFETY: `has_source` (judged above) is the stored-geometry
        // witness — scanned rows store their met tag width.
        let Some(tag_w) = row.tag_width else { unsafe { core::hint::unreachable_unchecked() } };
        Ok(crate::source::groupless::RecordRef::mint(
            // SAFETY: scanned spans lie within the admitted source.
            unsafe { self.source.get_unchecked(at..end) },
            row.field,
            row.kind,
            tag_w,
            row.delim_width,
            row.payload_len.as_inner(),
            false,
        ))
    }

    /// The varint record's current value ([`Patch::varint_word`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn varint_word(&self, handle: Handle) -> Option<u64> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::Varint) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan admitted this varint at this offset —
            // the row's geometry is the proof.
            Base::Intact => unsafe {
                slice::value64_unchecked(self.source, usize_of(row.start.as_inner() + row.tag_w()))
            },
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
        })
    }

    /// The fixed 32-bit record's current value bits
    /// ([`Patch::i32_bits`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn i32_bits(&self, handle: Handle) -> Option<u32> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::I32) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan judged four value bytes inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => u32::from_le(unsafe {
                self.source
                    .as_ptr()
                    .add(usize_of(row.start.as_inner() + row.tag_w()))
                    .cast::<u32>()
                    .read_unaligned()
            }),
            #[allow(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "fixed 32-bit words are stored zero-extended"
            )]
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)) as u32,
        })
    }

    /// The fixed 64-bit record's current value bits
    /// ([`Patch::i64_bits`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn i64_bits(&self, handle: Handle) -> Option<u64> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::I64) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan judged eight value bytes inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => u64::from_le(unsafe {
                self.source
                    .as_ptr()
                    .add(usize_of(row.start.as_inner() + row.tag_w()))
                    .cast::<u64>()
                    .read_unaligned()
            }),
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
        })
    }

    /// Opens a LEN's interior for editing ([`Patch::descend`]'s
    /// contract, resident verdicts included).
    ///
    /// # Errors
    ///
    /// As [`Patch::descend`].
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
        let id = handle.0;
        let row = *gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        if !matches!(row.kind, RecordKind::Len) {
            return Err(EditFault::KindMismatch { have: row.kind });
        }
        if !matches!(row.base(), Base::Intact) {
            return Err(EditFault::AuthoredPayload);
        }
        if row.opened() {
            return Ok(Descent::Opened { first: row.kid.map(Handle) });
        }
        if row.faulted() {
            return Ok(project(self.faults.inited(), row.value));
        }
        let depth = self.depth_of(id);
        if depth >= u32::from(self.limit.as_inner()) {
            return self.park(
                id,
                SlotFault::Refused(Refusal::DepthExceeded {
                    at: row.start.as_inner(),
                    field: row.field,
                }),
            );
        }
        let body_at = row.payload_at();
        let mark = self.rows.len();
        match scan_layer(
            &mut self.rows,
            self.source,
            body_at,
            body_at + row.payload_len.as_inner(),
            Some(id),
        ) {
            Ok(first) => {
                let row = self.row_mut(id);
                row.kid = first;
                row.set_opened();
                Ok(Descent::Opened { first: first.map(Handle) })
            }
            Err(halt) => {
                self.rows.truncate(mark);
                match halt {
                    Halt::Wire(fault) => self.park(id, SlotFault::Wire(fault)),
                    Halt::Refused(refusal) => self.park(id, SlotFault::Refused(refusal)),
                    Halt::Exhausted => Err(EditFault::ScratchExhausted { role: ScratchRole::Rows }),
                }
            }
        }
    }

    /// Parks a resident verdict on a LEN's record and projects it.
    fn park(&mut self, id: RowId, fault: SlotFault) -> Result<Descent<'_>, EditFault> {
        let Some(index) = self.faults.push(fault) else {
            return Err(EditFault::ScratchExhausted { role: ScratchRole::Faults });
        };
        let row = self.row_mut(id);
        row.value = index;
        row.set_faulted();
        Ok(project(self.faults.inited(), index))
    }

    /// Records an edit at `id` ([`Patch`]'s dirty discipline).
    const fn mark_dirty(&mut self, id: RowId) {
        self.dirty = true;
        let mut cur = Some(id);
        while let Some(at) = cur {
            let row = self.row_mut(at);
            if row.dirty() {
                break;
            }
            row.set_dirty();
            cur = row.parent;
        }
    }

    /// The shared scalar setter ([`Patch`]'s judge-then-flip shape).
    #[track_caller]
    fn set_scalar(&mut self, handle: Handle, want: RecordKind, word: u64) -> Result<(), EditFault> {
        let row = *gate(self.rows.inited(), handle);
        if row.kind != want {
            return Err(EditFault::KindMismatch { have: row.kind });
        }
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        match row.base() {
            Base::Intact => {
                let at = self
                    .words
                    .push_word(word)
                    .map_err(|role| EditFault::ScratchExhausted { role })?;
                let row = self.row_mut(handle.0);
                row.value = at.raw();
                row.set_replaced();
            }
            Base::Replaced | Base::Inserted => {
                self.words.set_word(WordAt::of_slot(row.value), word);
            }
        }
        self.mark_dirty(handle.0);
        Ok(())
    }

    /// Replaces the varint record's value ([`Patch::set_varint`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_varint`].
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::Varint, value)
    }

    /// Replaces the fixed 32-bit record's value bits
    /// ([`Patch::set_i32`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_varint`], with the fixed 32-bit kind gate.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_i32(&mut self, handle: Handle, bits: u32) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::I32, u64::from(bits))
    }

    /// Replaces the fixed 64-bit record's value bits
    /// ([`Patch::set_i64`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_varint`], with the fixed 64-bit kind gate.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_i64(&mut self, handle: Handle, bits: u64) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::I64, bits)
    }

    /// The shared payload-set gates; `Ok` carries the row copy.
    #[track_caller]
    const fn payload_set_gate(&self, handle: Handle, len: usize) -> Result<Row, EditFault> {
        let row = *gate(self.rows.inited(), handle);
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
        Ok(row)
    }

    /// The infallible suffix of a payload set ([`Patch`]'s).
    const fn payload_set_commit(&mut self, handle: Handle, value: u32) {
        let row = self.row_mut(handle.0);
        row.value = value;
        row.clear_faulted();
        if matches!(row.base(), Base::Intact) {
            row.set_replaced();
        }
        self.mark_dirty(handle.0);
    }

    /// Deletes the record ([`Patch::delete`]).
    ///
    /// # Errors
    ///
    /// [`EditFault::DeletedTarget`] when the record is already
    /// deleted. On `Err` the machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        self.row_mut(handle.0).set_deleted();
        self.mark_dirty(handle.0);
        Ok(())
    }

    /// Gates an insertion container; `Ok` carries its row.
    #[track_caller]
    const fn container_gate(&self, container: Option<Handle>) -> Result<Option<RowId>, EditFault> {
        let Some(handle) = container else {
            return Ok(None);
        };
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        match row.kind {
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

    /// The last record of a container's chain ([`Patch::tail_of`]'s
    /// linear walk).
    fn tail_of(&self, parent: Option<RowId>) -> Option<RowId> {
        let mut cur = self.first_of(parent)?;
        while let Some(next) = self.row(cur).next {
            cur = next;
        }
        Some(cur)
    }

    /// Resolves an anchor into a proven splice point.
    #[track_caller]
    fn resolve_anchor(&self, at: InsertAt) -> Result<SplicePoint, EditFault> {
        match at {
            InsertAt::HeadOf(container) => {
                Ok(SplicePoint { parent: self.container_gate(container)?, prev: None })
            }
            InsertAt::TailOf(container) => {
                let parent = self.container_gate(container)?;
                Ok(SplicePoint { parent, prev: self.tail_of(parent) })
            }
            InsertAt::After(anchor) => {
                let row = gate(self.rows.inited(), anchor);
                Ok(SplicePoint { parent: row.parent, prev: Some(anchor.0) })
            }
        }
    }

    /// Mints the next row coordinate for an insertion
    /// ([`Patch::mint_insert`]).
    const fn mint_insert(&self) -> Result<RowId, EditFault> {
        let Some(at) = self.rows.mint() else {
            return Err(EditFault::ScratchExhausted { role: ScratchRole::Rows });
        };
        // SAFETY: `at < capacity` by the mint, and the plan judged
        // the capacity into the RowId domain at construction.
        Ok(unsafe { RowId::new_unchecked(at) })
    }

    /// Splices an authored row (the infallible suffix of every
    /// insert command).
    fn apply_insert(
        &mut self,
        point: &SplicePoint,
        id: RowId,
        field: FieldNumber,
        kind: RecordKind,
        value: u32,
    ) {
        let next =
            point.prev.map_or_else(|| self.first_of(point.parent), |prev| self.row(prev).next);
        self.rows.push_minted(Row::authored(field, kind, point.parent, next, value));
        match point.prev {
            Some(prev) => self.row_mut(prev).next = Some(id),
            None => match point.parent {
                Some(parent) => self.row_mut(parent).kid = Some(id),
                None => self.top = Some(id),
            },
        }
        self.mark_dirty(id);
    }

    /// Inserts a varint record at the anchor
    /// ([`Patch::insert_varint`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_varint(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        value: u64,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value =
            self.words.push_word(value).map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Varint, value.raw());
        Ok(Handle(id))
    }

    /// Inserts a fixed 32-bit record at the anchor
    /// ([`Patch::insert_i32`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_i32(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        bits: u32,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value = self
            .words
            .push_word(u64::from(bits))
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::I32, value.raw());
        Ok(Handle(id))
    }

    /// Inserts a fixed 64-bit record at the anchor
    /// ([`Patch::insert_i64`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_i64(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        bits: u64,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value =
            self.words.push_word(bits).map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::I64, value.raw());
        Ok(Handle(id))
    }

    /// The exact byte length [`BorrowPatch::save_into`] would write
    /// ([`Patch::save_len`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_len`].
    pub fn save_len(&mut self) -> Result<u32, SaveFault> {
        if !self.dirty {
            return Ok(admitted_u32(self.source.len()));
        }
        size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )
    }

    /// Serializes into the front of `out` ([`Patch::save_into`]'s
    /// contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_into`]; on any `Err`, `out` is untouched.
    ///
    /// # Panics
    ///
    /// If the sizing and emit walks disagree — a library bug caught
    /// at the seam.
    pub fn save_into(&mut self, out: &mut [u8]) -> Result<u32, SaveFault> {
        if !self.dirty {
            let need = admitted_u32(self.source.len());
            if out.len() < self.source.len() {
                return Err(SaveFault::OutputShort { need, have: out.len() });
            }
            out[..self.source.len()].copy_from_slice(self.source);
            return Ok(need);
        }
        let total = size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        if out.len() < usize_of(total) {
            return Err(SaveFault::OutputShort { need: total, have: out.len() });
        }
        let mut emit = SliceEmit { out, at: 0, src: self.source, run: None };
        emit_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(emit.at == usize_of(total), "fixed patch save: the emit walk covers the price");
        Ok(total)
    }

    /// Serializes by handing the save's bytes to `sink`
    /// ([`Patch::save_sink`]'s contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_len`]; on `Err` the sink has been handed
    /// nothing.
    ///
    /// # Panics
    ///
    /// If the sizing and emit walks disagree — a library bug caught
    /// at the seam.
    pub fn save_sink(&mut self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
        if !self.dirty {
            if !self.source.is_empty() {
                sink(self.source);
            }
            return Ok(());
        }
        let total = size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        let mut emit = SinkEmit { src: self.source, sink: &mut sink, run: None, written: 0 };
        emit_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            emit.written == u64::from(total),
            "fixed patch save: the sink walk covers the price"
        );
        Ok(())
    }

    /// Serializes under the `CanonicalMinimal` output standard into
    /// the front of `out` ([`Patch::save_canonical_into`]'s
    /// contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_canonical_into`]; on any `Err`, `out` is
    /// untouched.
    ///
    /// # Panics
    ///
    /// If the canonical sizing and emit walks disagree — a library
    /// bug caught at the seam.
    pub fn save_canonical_into(&mut self, out: &mut [u8]) -> Result<u32, SaveFault> {
        let total = canonical_size_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        if out.len() < usize_of(total) {
            return Err(SaveFault::OutputShort { need: total, have: out.len() });
        }
        let mut emit = SliceEmit { out, at: 0, src: self.source, run: None };
        let consumed = canonical_emit_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            consumed == usize_of(self.bodies.len()) && emit.at == usize_of(total),
            "fixed patch canonical save: sizing and emission disagree"
        );
        Ok(total)
    }

    /// [`BorrowPatch::save_canonical_into`]'s bytes handed to
    /// `sink` ([`Patch::save_canonical_sink`]'s contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_canonical_into`], less the output judgment;
    /// on `Err` the sink has been handed nothing.
    ///
    /// # Panics
    ///
    /// If the canonical sizing and emit walks disagree — a library
    /// bug caught at the seam.
    pub fn save_canonical_sink(&mut self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
        let total = canonical_size_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        let mut emit = SinkEmit { src: self.source, sink: &mut sink, run: None, written: 0 };
        let consumed = canonical_emit_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            consumed == usize_of(self.bodies.len()) && emit.written == u64::from(total),
            "fixed patch canonical save: the sink walk covers the price"
        );
        Ok(())
    }

    /// The LEN record's current payload bytes
    /// ([`Patch::payload_bytes`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::Len) {
            return None;
        }
        match row.base() {
            // SAFETY: the scan judged the payload extent inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => Some(unsafe {
                self.source.get_unchecked(
                    usize_of(row.payload_at())
                        ..usize_of(row.payload_at() + row.payload_len.as_inner()),
                )
            }),
            Base::Replaced | Base::Inserted => {
                self.payloads.contiguous(PayloadAt::of_slot(row.value))
            }
        }
    }

    /// Replaces the LEN record's payload wholesale
    /// ([`Patch::set_payload`]'s contract over the borrowed supply
    /// alone).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_payload`].
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_payload(&mut self, handle: Handle, payload: &'p [u8]) -> Result<(), EditFault> {
        let row = self.payload_set_gate(handle, payload.len())?;
        let value = match row.base() {
            Base::Intact => self
                .payloads
                .push_borrowed(payload)
                .map_err(|role| EditFault::ScratchExhausted { role })?
                .raw(),
            Base::Replaced | Base::Inserted => {
                self.payloads.set_borrowed(PayloadAt::of_slot(row.value), payload);
                row.value
            }
        };
        self.payload_set_commit(handle, value);
        Ok(())
    }

    /// [`set_payload`](BorrowPatch::set_payload)'s scatter twin
    /// ([`Patch::set_payload_parts`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_payload`].
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_payload_parts(
        &mut self,
        handle: Handle,
        parts: &'p [&'p [u8]],
    ) -> Result<(), EditFault> {
        let row = self.payload_set_gate(handle, parts_len_usize(parts))?;
        let value = match row.base() {
            Base::Intact => self
                .payloads
                .push_parts(parts)
                .map_err(|role| EditFault::ScratchExhausted { role })?
                .raw(),
            Base::Replaced | Base::Inserted => {
                self.payloads.set_parts(PayloadAt::of_slot(row.value), parts);
                row.value
            }
        };
        self.payload_set_commit(handle, value);
        Ok(())
    }

    /// Inserts a LEN record with an authored payload at the anchor
    /// ([`Patch::insert_payload`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_payload`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_payload(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        payload: &'p [u8],
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len: payload.len() });
        }
        let value = self
            .payloads
            .push_borrowed(payload)
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Len, value.raw());
        Ok(Handle(id))
    }

    /// [`insert_payload`](BorrowPatch::insert_payload)'s scatter
    /// twin ([`Patch::insert_payload_parts`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_payload`], the length judgment reading
    /// the concatenated length.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_payload_parts(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        parts: &'p [&'p [u8]],
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let len = parts_len_usize(parts);
        if len > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len });
        }
        let value =
            self.payloads.push_parts(parts).map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Len, value.raw());
        Ok(Handle(id))
    }
}

// ─── the copy-only machine ───

/// The copy-only fixed patch: every authored payload is staged by
/// copy at the command.
///
/// [`Patch`]'s command and save faces over the staged supply alone
/// — a payload slot is a bare extent, no slot tag exists, and no
/// payload lifetime binds the caller: `'a` backs the borrowed
/// source and `'s` the slab. Temporaries are welcome everywhere;
/// the mixed machine's borrowed default is the zero-staging path.
pub struct CopyPatch<'a, 's> {
    source: &'a [u8],
    rows: Lane<'s, Row>,
    words: WordStore<'s>,
    payloads: CopiedPayloadStore<'s>,
    faults: Lane<'s, SlotFault>,
    /// Save scratch: one priced LEN body per opened spine frame,
    /// entry marks while sizing.
    bodies: Lane<'s, u64>,
    /// Save scratch: the open spine frames' body slots.
    spine: Lane<'s, u32>,
    top: Option<RowId>,
    limit: DepthLimit,
    /// The whole-document edit latch ([`Patch`]'s contract).
    dirty: bool,
}

impl<'a, 's> CopyPatch<'a, 's> {
    /// Borrows `source` and the slab, carves the plan's lanes, and
    /// scans the flat root layer eagerly ([`Patch::open`]'s door
    /// contract over [`CopyPlan`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::open`].
    pub fn open(
        source: &'a [u8],
        limit: DepthLimit,
        plan: &CopyPlan,
        slab: &'s mut [MaybeUninit<u8>],
    ) -> Result<Self, OpenFault> {
        let len = admit(source.len()).ok_or(OpenFault::TooLarge { len: source.len() })?;
        let caps = plan.caps(limit);
        let need = caps.priced();
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        let have = slab.len() as u64;
        if have < need {
            return Err(OpenFault::SlabShort { need, have });
        }
        // The carve derives from the one ladder list
        // (`carve_ladder!` above), which asserts the descending
        // alignment and binds each lane by its ladder name; the
        // judgment above priced these same capacities.
        let CopyLanes { words, bodies, mut rows, slots, faults, spine, staged } =
            carve_copy!(slab, caps);
        let words = WordStore::new(words);
        let top = scan_layer(&mut rows, source, 0, len, None).map_err(|halt| match halt {
            Halt::Wire(fault) => OpenFault::Wire(fault),
            Halt::Refused(refusal) => OpenFault::Refused(refusal),
            Halt::Exhausted => OpenFault::ScratchExhausted { role: ScratchRole::Rows },
        })?;
        Ok(Self {
            source,
            rows,
            words,
            payloads: CopiedPayloadStore::new(staged, slots),
            faults,
            bodies,
            spine,
            top,
            limit,
            dirty: false,
        })
    }

    /// The borrowed source bytes.
    #[inline]
    #[must_use]
    pub const fn source(&self) -> &'a [u8] {
        self.source
    }

    /// Per-role high-water occupancy against capacity
    /// ([`Patch::budget`]'s contract).
    #[inline]
    #[must_use]
    pub const fn budget(&self) -> Budget {
        Budget {
            rows: self.rows.gauge(),
            words: self.words.gauge(),
            payload_slots: self.payloads.slots_gauge(),
            staged_bytes: self.payloads.staged_gauge(),
            faults: self.faults.gauge(),
        }
    }

    /// A gated row by coordinate (every public entry gates first).
    const fn row(&self, id: RowId) -> &Row {
        self.rows.get(id.as_inner())
    }

    /// Mutable twin of [`CopyPatch::row`].
    const fn row_mut(&mut self, id: RowId) -> &mut Row {
        self.rows.get_mut(id.as_inner())
    }

    /// Containers enclosing a row (its nesting depth).
    const fn depth_of(&self, id: RowId) -> u32 {
        let mut depth = 0;
        let mut cur = self.row(id).parent;
        while let Some(parent) = cur {
            depth += 1;
            cur = self.row(parent).parent;
        }
        depth
    }

    /// The top layer's records in wire order ([`Patch::top`]).
    #[inline]
    pub const fn top(&self) -> Children<'_> {
        Children { rows: self.rows.inited(), cur: self.top }
    }

    /// A descended LEN's records in wire order
    /// ([`Patch::children`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn children(&self, handle: Handle) -> Children<'_> {
        let rows = self.rows.inited();
        Children { rows, cur: gate(rows, handle).kid }
    }

    /// The record's enclosing container, `None` at the top layer.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn parent(&self, handle: Handle) -> Option<Handle> {
        gate(self.rows.inited(), handle).parent.map(Handle)
    }

    /// The record's ancestor chain, innermost container first.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn ancestors(&self, handle: Handle) -> Ancestors<'_> {
        let rows = self.rows.inited();
        Ancestors { rows, cur: gate(rows, handle).parent }
    }

    /// The record's wire kind.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn kind(&self, handle: Handle) -> RecordKind {
        gate(self.rows.inited(), handle).kind
    }

    /// The record's field number.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn field(&self, handle: Handle) -> FieldNumber {
        gate(self.rows.inited(), handle).field
    }

    /// The record's observable edit state.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn status(&self, handle: Handle) -> EditStatus {
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return EditStatus::Deleted;
        }
        match row.base() {
            Base::Intact => EditStatus::Intact,
            Base::Replaced => EditStatus::Replaced,
            Base::Inserted => EditStatus::Inserted,
        }
    }

    /// The record's whole source span ([`Patch::span`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn span(&self, handle: Handle) -> Option<Span> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() {
            return None;
        }
        Some(Span::new(row.start.as_inner(), row.span_end()))
    }

    /// The narrowest source-backed record whose span contains `pos`
    /// ([`Patch::narrowest`]).
    #[must_use]
    pub fn narrowest(&self, pos: u32) -> Option<Handle> {
        let mut best: Option<RowId> = None;
        let mut chain = self.top;
        while let Some(first) = chain {
            let mut hit: Option<RowId> = None;
            let mut cursor = Some(first);
            while let Some(id) = cursor {
                let row = self.row(id);
                if row.has_source() {
                    if row.start.as_inner() > pos {
                        break;
                    }
                    if pos < row.span_end() {
                        hit = Some(id);
                    }
                }
                cursor = row.next;
            }
            let Some(id) = hit else { break };
            best = Some(id);
            chain = self.row(id).kid;
        }
        best.map(Handle)
    }

    /// The record's source geometry ([`Patch::source_spans`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn source_spans(&self, handle: Handle) -> Option<RecordSpans> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() {
            return None;
        }
        let tag = Span::new(row.start.as_inner(), row.start.as_inner() + row.tag_w());
        Some(match row.kind {
            RecordKind::Varint => {
                RecordSpans::Varint { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::I32 => {
                RecordSpans::I32 { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::I64 => {
                RecordSpans::I64 { tag, value: Span::new(tag.end(), row.span_end()) }
            }
            RecordKind::Len => {
                let payload_at = row.payload_at();
                RecordSpans::Len {
                    tag,
                    prefix: Span::new(tag.end(), payload_at),
                    payload: Span::new(payload_at, row.span_end()),
                }
            }
        })
    }

    /// Designates the record for cross-machine transfer
    /// ([`Patch::record_ref`]).
    ///
    /// # Errors
    ///
    /// [`Fault::NotSourceBacked`](crate::source::groupless::Fault::NotSourceBacked)
    /// for authored and deleted rows.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn record_ref(
        &self,
        handle: Handle,
    ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault> {
        let row = gate(self.rows.inited(), handle);
        if !row.has_source() || row.deleted() {
            return Err(crate::source::groupless::Fault::NotSourceBacked);
        }
        let at = usize_of(row.start.as_inner());
        let end = usize_of(row.span_end());
        // SAFETY: `has_source` (judged above) is the stored-geometry
        // witness — scanned rows store their met tag width.
        let Some(tag_w) = row.tag_width else { unsafe { core::hint::unreachable_unchecked() } };
        Ok(crate::source::groupless::RecordRef::mint(
            // SAFETY: scanned spans lie within the admitted source.
            unsafe { self.source.get_unchecked(at..end) },
            row.field,
            row.kind,
            tag_w,
            row.delim_width,
            row.payload_len.as_inner(),
            false,
        ))
    }

    /// The varint record's current value ([`Patch::varint_word`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn varint_word(&self, handle: Handle) -> Option<u64> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::Varint) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan admitted this varint at this offset —
            // the row's geometry is the proof.
            Base::Intact => unsafe {
                slice::value64_unchecked(self.source, usize_of(row.start.as_inner() + row.tag_w()))
            },
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
        })
    }

    /// The fixed 32-bit record's current value bits
    /// ([`Patch::i32_bits`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn i32_bits(&self, handle: Handle) -> Option<u32> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::I32) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan judged four value bytes inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => u32::from_le(unsafe {
                self.source
                    .as_ptr()
                    .add(usize_of(row.start.as_inner() + row.tag_w()))
                    .cast::<u32>()
                    .read_unaligned()
            }),
            #[allow(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "fixed 32-bit words are stored zero-extended"
            )]
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)) as u32,
        })
    }

    /// The fixed 64-bit record's current value bits
    /// ([`Patch::i64_bits`]).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub const fn i64_bits(&self, handle: Handle) -> Option<u64> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::I64) {
            return None;
        }
        Some(match row.base() {
            // SAFETY: the scan judged eight value bytes inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => u64::from_le(unsafe {
                self.source
                    .as_ptr()
                    .add(usize_of(row.start.as_inner() + row.tag_w()))
                    .cast::<u64>()
                    .read_unaligned()
            }),
            Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
        })
    }

    /// Opens a LEN's interior for editing ([`Patch::descend`]'s
    /// contract, resident verdicts included).
    ///
    /// # Errors
    ///
    /// As [`Patch::descend`].
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
        let id = handle.0;
        let row = *gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        if !matches!(row.kind, RecordKind::Len) {
            return Err(EditFault::KindMismatch { have: row.kind });
        }
        if !matches!(row.base(), Base::Intact) {
            return Err(EditFault::AuthoredPayload);
        }
        if row.opened() {
            return Ok(Descent::Opened { first: row.kid.map(Handle) });
        }
        if row.faulted() {
            return Ok(project(self.faults.inited(), row.value));
        }
        let depth = self.depth_of(id);
        if depth >= u32::from(self.limit.as_inner()) {
            return self.park(
                id,
                SlotFault::Refused(Refusal::DepthExceeded {
                    at: row.start.as_inner(),
                    field: row.field,
                }),
            );
        }
        let body_at = row.payload_at();
        let mark = self.rows.len();
        match scan_layer(
            &mut self.rows,
            self.source,
            body_at,
            body_at + row.payload_len.as_inner(),
            Some(id),
        ) {
            Ok(first) => {
                let row = self.row_mut(id);
                row.kid = first;
                row.set_opened();
                Ok(Descent::Opened { first: first.map(Handle) })
            }
            Err(halt) => {
                self.rows.truncate(mark);
                match halt {
                    Halt::Wire(fault) => self.park(id, SlotFault::Wire(fault)),
                    Halt::Refused(refusal) => self.park(id, SlotFault::Refused(refusal)),
                    Halt::Exhausted => Err(EditFault::ScratchExhausted { role: ScratchRole::Rows }),
                }
            }
        }
    }

    /// Parks a resident verdict on a LEN's record and projects it.
    fn park(&mut self, id: RowId, fault: SlotFault) -> Result<Descent<'_>, EditFault> {
        let Some(index) = self.faults.push(fault) else {
            return Err(EditFault::ScratchExhausted { role: ScratchRole::Faults });
        };
        let row = self.row_mut(id);
        row.value = index;
        row.set_faulted();
        Ok(project(self.faults.inited(), index))
    }

    /// Records an edit at `id` ([`Patch`]'s dirty discipline).
    const fn mark_dirty(&mut self, id: RowId) {
        self.dirty = true;
        let mut cur = Some(id);
        while let Some(at) = cur {
            let row = self.row_mut(at);
            if row.dirty() {
                break;
            }
            row.set_dirty();
            cur = row.parent;
        }
    }

    /// The shared scalar setter ([`Patch`]'s judge-then-flip shape).
    #[track_caller]
    fn set_scalar(&mut self, handle: Handle, want: RecordKind, word: u64) -> Result<(), EditFault> {
        let row = *gate(self.rows.inited(), handle);
        if row.kind != want {
            return Err(EditFault::KindMismatch { have: row.kind });
        }
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        match row.base() {
            Base::Intact => {
                let at = self
                    .words
                    .push_word(word)
                    .map_err(|role| EditFault::ScratchExhausted { role })?;
                let row = self.row_mut(handle.0);
                row.value = at.raw();
                row.set_replaced();
            }
            Base::Replaced | Base::Inserted => {
                self.words.set_word(WordAt::of_slot(row.value), word);
            }
        }
        self.mark_dirty(handle.0);
        Ok(())
    }

    /// Replaces the varint record's value ([`Patch::set_varint`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_varint`].
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::Varint, value)
    }

    /// Replaces the fixed 32-bit record's value bits
    /// ([`Patch::set_i32`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_varint`], with the fixed 32-bit kind gate.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_i32(&mut self, handle: Handle, bits: u32) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::I32, u64::from(bits))
    }

    /// Replaces the fixed 64-bit record's value bits
    /// ([`Patch::set_i64`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_varint`], with the fixed 64-bit kind gate.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_i64(&mut self, handle: Handle, bits: u64) -> Result<(), EditFault> {
        self.set_scalar(handle, RecordKind::I64, bits)
    }

    /// The shared payload-set gates; `Ok` carries the row copy.
    #[track_caller]
    const fn payload_set_gate(&self, handle: Handle, len: usize) -> Result<Row, EditFault> {
        let row = *gate(self.rows.inited(), handle);
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
        Ok(row)
    }

    /// The infallible suffix of a payload set ([`Patch`]'s).
    const fn payload_set_commit(&mut self, handle: Handle, value: u32) {
        let row = self.row_mut(handle.0);
        row.value = value;
        row.clear_faulted();
        if matches!(row.base(), Base::Intact) {
            row.set_replaced();
        }
        self.mark_dirty(handle.0);
    }

    /// Deletes the record ([`Patch::delete`]).
    ///
    /// # Errors
    ///
    /// [`EditFault::DeletedTarget`] when the record is already
    /// deleted. On `Err` the machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub const fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        self.row_mut(handle.0).set_deleted();
        self.mark_dirty(handle.0);
        Ok(())
    }

    /// Gates an insertion container; `Ok` carries its row.
    #[track_caller]
    const fn container_gate(&self, container: Option<Handle>) -> Result<Option<RowId>, EditFault> {
        let Some(handle) = container else {
            return Ok(None);
        };
        let row = gate(self.rows.inited(), handle);
        if row.deleted() {
            return Err(EditFault::DeletedTarget);
        }
        match row.kind {
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

    /// The last record of a container's chain ([`Patch::tail_of`]'s
    /// linear walk).
    fn tail_of(&self, parent: Option<RowId>) -> Option<RowId> {
        let mut cur = self.first_of(parent)?;
        while let Some(next) = self.row(cur).next {
            cur = next;
        }
        Some(cur)
    }

    /// Resolves an anchor into a proven splice point.
    #[track_caller]
    fn resolve_anchor(&self, at: InsertAt) -> Result<SplicePoint, EditFault> {
        match at {
            InsertAt::HeadOf(container) => {
                Ok(SplicePoint { parent: self.container_gate(container)?, prev: None })
            }
            InsertAt::TailOf(container) => {
                let parent = self.container_gate(container)?;
                Ok(SplicePoint { parent, prev: self.tail_of(parent) })
            }
            InsertAt::After(anchor) => {
                let row = gate(self.rows.inited(), anchor);
                Ok(SplicePoint { parent: row.parent, prev: Some(anchor.0) })
            }
        }
    }

    /// Mints the next row coordinate for an insertion
    /// ([`Patch::mint_insert`]).
    const fn mint_insert(&self) -> Result<RowId, EditFault> {
        let Some(at) = self.rows.mint() else {
            return Err(EditFault::ScratchExhausted { role: ScratchRole::Rows });
        };
        // SAFETY: `at < capacity` by the mint, and the plan judged
        // the capacity into the RowId domain at construction.
        Ok(unsafe { RowId::new_unchecked(at) })
    }

    /// Splices an authored row (the infallible suffix of every
    /// insert command).
    fn apply_insert(
        &mut self,
        point: &SplicePoint,
        id: RowId,
        field: FieldNumber,
        kind: RecordKind,
        value: u32,
    ) {
        let next =
            point.prev.map_or_else(|| self.first_of(point.parent), |prev| self.row(prev).next);
        self.rows.push_minted(Row::authored(field, kind, point.parent, next, value));
        match point.prev {
            Some(prev) => self.row_mut(prev).next = Some(id),
            None => match point.parent {
                Some(parent) => self.row_mut(parent).kid = Some(id),
                None => self.top = Some(id),
            },
        }
        self.mark_dirty(id);
    }

    /// Inserts a varint record at the anchor
    /// ([`Patch::insert_varint`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_varint(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        value: u64,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value =
            self.words.push_word(value).map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Varint, value.raw());
        Ok(Handle(id))
    }

    /// Inserts a fixed 32-bit record at the anchor
    /// ([`Patch::insert_i32`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_i32(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        bits: u32,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value = self
            .words
            .push_word(u64::from(bits))
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::I32, value.raw());
        Ok(Handle(id))
    }

    /// Inserts a fixed 64-bit record at the anchor
    /// ([`Patch::insert_i64`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_varint`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_i64(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        bits: u64,
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        let value =
            self.words.push_word(bits).map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::I64, value.raw());
        Ok(Handle(id))
    }

    /// The exact byte length [`CopyPatch::save_into`] would write
    /// ([`Patch::save_len`]).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_len`].
    pub fn save_len(&mut self) -> Result<u32, SaveFault> {
        if !self.dirty {
            return Ok(admitted_u32(self.source.len()));
        }
        size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )
    }

    /// Serializes into the front of `out` ([`Patch::save_into`]'s
    /// contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_into`]; on any `Err`, `out` is untouched.
    ///
    /// # Panics
    ///
    /// If the sizing and emit walks disagree — a library bug caught
    /// at the seam.
    pub fn save_into(&mut self, out: &mut [u8]) -> Result<u32, SaveFault> {
        if !self.dirty {
            let need = admitted_u32(self.source.len());
            if out.len() < self.source.len() {
                return Err(SaveFault::OutputShort { need, have: out.len() });
            }
            out[..self.source.len()].copy_from_slice(self.source);
            return Ok(need);
        }
        let total = size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        if out.len() < usize_of(total) {
            return Err(SaveFault::OutputShort { need: total, have: out.len() });
        }
        let mut emit = SliceEmit { out, at: 0, src: self.source, run: None };
        emit_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(emit.at == usize_of(total), "fixed patch save: the emit walk covers the price");
        Ok(total)
    }

    /// Serializes by handing the save's bytes to `sink`
    /// ([`Patch::save_sink`]'s contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_len`]; on `Err` the sink has been handed
    /// nothing.
    ///
    /// # Panics
    ///
    /// If the sizing and emit walks disagree — a library bug caught
    /// at the seam.
    pub fn save_sink(&mut self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
        if !self.dirty {
            if !self.source.is_empty() {
                sink(self.source);
            }
            return Ok(());
        }
        let total = size_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        let mut emit = SinkEmit { src: self.source, sink: &mut sink, run: None, written: 0 };
        emit_pass(
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            emit.written == u64::from(total),
            "fixed patch save: the sink walk covers the price"
        );
        Ok(())
    }

    /// Serializes under the `CanonicalMinimal` output standard into
    /// the front of `out` ([`Patch::save_canonical_into`]'s
    /// contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_canonical_into`]; on any `Err`, `out` is
    /// untouched.
    ///
    /// # Panics
    ///
    /// If the canonical sizing and emit walks disagree — a library
    /// bug caught at the seam.
    pub fn save_canonical_into(&mut self, out: &mut [u8]) -> Result<u32, SaveFault> {
        let total = canonical_size_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        if out.len() < usize_of(total) {
            return Err(SaveFault::OutputShort { need: total, have: out.len() });
        }
        let mut emit = SliceEmit { out, at: 0, src: self.source, run: None };
        let consumed = canonical_emit_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            consumed == usize_of(self.bodies.len()) && emit.at == usize_of(total),
            "fixed patch canonical save: sizing and emission disagree"
        );
        Ok(total)
    }

    /// [`CopyPatch::save_canonical_into`]'s bytes handed to `sink`
    /// ([`Patch::save_canonical_sink`]'s contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::save_canonical_into`], less the output judgment;
    /// on `Err` the sink has been handed nothing.
    ///
    /// # Panics
    ///
    /// If the canonical sizing and emit walks disagree — a library
    /// bug caught at the seam.
    pub fn save_canonical_sink(&mut self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
        let total = canonical_size_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut self.bodies,
            &mut self.spine,
            self.top,
        )?;
        let mut emit = SinkEmit { src: self.source, sink: &mut sink, run: None, written: 0 };
        let consumed = canonical_emit_pass(
            self.source,
            self.rows.inited(),
            &self.words,
            &self.payloads,
            &mut emit,
            self.bodies.inited(),
            self.top,
        );
        assert!(
            consumed == usize_of(self.bodies.len()) && emit.written == u64::from(total),
            "fixed patch canonical save: the sink walk covers the price"
        );
        Ok(())
    }

    /// The LEN record's current payload bytes
    /// ([`Patch::payload_bytes`]; every staged replacement is
    /// contiguous, so a replaced record always answers).
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
        let row = gate(self.rows.inited(), handle);
        if !matches!(row.kind, RecordKind::Len) {
            return None;
        }
        match row.base() {
            // SAFETY: the scan judged the payload extent inside the
            // admitted source — the row's geometry is the proof.
            Base::Intact => Some(unsafe {
                self.source.get_unchecked(
                    usize_of(row.payload_at())
                        ..usize_of(row.payload_at() + row.payload_len.as_inner()),
                )
            }),
            Base::Replaced | Base::Inserted => {
                self.payloads.contiguous(PayloadAt::of_slot(row.value))
            }
        }
    }

    /// Replaces the LEN record's payload wholesale, staging a copy
    /// at the command ([`Patch::set_payload_copy`]'s contract — the
    /// copy-only machine's payloads never borrow).
    ///
    /// # Errors
    ///
    /// As [`Patch::set_payload_copy`].
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[inline]
    #[track_caller]
    pub fn set_payload(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
        let row = self.payload_set_gate(handle, payload.len())?;
        let value = match row.base() {
            Base::Intact => self
                .payloads
                .push_copied(payload)
                .map_err(|role| EditFault::ScratchExhausted { role })?
                .raw(),
            Base::Replaced | Base::Inserted => {
                self.payloads
                    .set_copied(PayloadAt::of_slot(row.value), payload)
                    .map_err(|role| EditFault::ScratchExhausted { role })?;
                row.value
            }
        };
        self.payload_set_commit(handle, value);
        Ok(())
    }

    /// Inserts a LEN record with an authored payload at the anchor,
    /// staging a copy at the command
    /// ([`Patch::insert_payload_copy`]'s contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::insert_payload_copy`].
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[inline]
    #[track_caller]
    pub fn insert_payload(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        payload: &[u8],
    ) -> Result<Handle, EditFault> {
        let point = self.resolve_anchor(at)?;
        let id = self.mint_insert()?;
        if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len: payload.len() });
        }
        let value = self
            .payloads
            .push_copied(payload)
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        self.apply_insert(&point, id, field, RecordKind::Len, value.raw());
        Ok(Handle(id))
    }

    /// Opens a staged replacement of the LEN record's payload
    /// ([`Patch::begin_set_payload`]'s frame contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::begin_set_payload`]. On `Err` the machine is
    /// unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn begin_set_payload(
        &mut self,
        handle: Handle,
    ) -> Result<CopyPayloadWrite<'_, 'a, 's>, EditFault> {
        self.payload_set_gate(handle, 0)?;
        let mark = self.payloads.stage_mark();
        Ok(CopyPayloadWrite { machine: self, op: WriteOp::Set { handle }, mark })
    }

    /// Opens a staged insertion of a fresh LEN record at the anchor
    /// ([`Patch::begin_insert_payload`]'s frame contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::begin_insert_payload`]. On `Err` the machine is
    /// unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[track_caller]
    pub fn begin_insert_payload(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
    ) -> Result<CopyPayloadWrite<'_, 'a, 's>, EditFault> {
        let point = self.resolve_anchor(at)?;
        let mark = self.payloads.stage_mark();
        Ok(CopyPayloadWrite { machine: self, op: WriteOp::Insert { point, field }, mark })
    }

    /// Judges a length-class declaration against the staged pool's
    /// remaining capacity ([`Patch::stage_declare`]'s contract).
    const fn stage_declare(&self, len: usize) -> Result<u32, EditFault> {
        if !self.payloads.stage_fits(len) {
            return Err(EditFault::ScratchExhausted { role: ScratchRole::StagedBytes });
        }
        Ok(admitted_u32(len))
    }

    /// [`begin_set_payload`](CopyPatch::begin_set_payload)'s
    /// declared-length twin
    /// ([`Patch::begin_set_payload_sized`]'s door contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::begin_set_payload_sized`]. On `Err` the machine
    /// is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if `handle` was not minted by this machine (the arena
    /// index contract).
    #[track_caller]
    pub fn begin_set_payload_sized(
        &mut self,
        handle: Handle,
        len: usize,
    ) -> Result<SizedCopyPayloadWrite<'_, 'a, 's>, EditFault> {
        self.payload_set_gate(handle, len)?;
        let declared = self.stage_declare(len)?;
        let mark = self.payloads.stage_mark();
        Ok(SizedCopyPayloadWrite {
            inner: CopyPayloadWrite { machine: self, op: WriteOp::Set { handle }, mark },
            declared,
        })
    }

    /// [`begin_insert_payload`](CopyPatch::begin_insert_payload)'s
    /// declared-length twin
    /// ([`Patch::begin_insert_payload_sized`]'s door contract).
    ///
    /// # Errors
    ///
    /// As [`Patch::begin_insert_payload_sized`]. On `Err` the
    /// machine is unchanged.
    ///
    /// # Panics
    ///
    /// Panics if a handle inside the anchor was not minted by this
    /// machine (the arena index contract).
    #[track_caller]
    pub fn begin_insert_payload_sized(
        &mut self,
        at: InsertAt,
        field: FieldNumber,
        len: usize,
    ) -> Result<SizedCopyPayloadWrite<'_, 'a, 's>, EditFault> {
        let point = self.resolve_anchor(at)?;
        if len > usize_of(PayloadLen::MAX.as_inner()) {
            return Err(EditFault::PayloadTooLarge { len });
        }
        let declared = self.stage_declare(len)?;
        let mark = self.payloads.stage_mark();
        Ok(SizedCopyPayloadWrite {
            inner: CopyPayloadWrite { machine: self, op: WriteOp::Insert { point, field }, mark },
            declared,
        })
    }
}

/// A staged payload frame over the copy-only machine
/// ([`PayloadWrite`]'s contract).
#[must_use = "a payload frame installs nothing until finished"]
pub struct CopyPayloadWrite<'w, 'a, 's> {
    machine: &'w mut CopyPatch<'a, 's>,
    op: WriteOp,
    /// The staged pool's tail at open: the staged extent is
    /// `mark..` for the frame's whole life.
    mark: u32,
}

impl Drop for CopyPayloadWrite<'_, '_, '_> {
    /// Reclaims the staged extent ([`PayloadWrite`]'s drop
    /// contract).
    fn drop(&mut self) {
        self.machine.payloads.stage_abandon(self.mark);
    }
}

impl CopyPayloadWrite<'_, '_, '_> {
    /// Appends one chunk to the staged payload
    /// ([`PayloadWrite::write`]'s contract).
    ///
    /// # Errors
    ///
    /// As [`PayloadWrite::write`].
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), EditFault> {
        let staged = u64::from(self.machine.payloads.staged_len(self.mark));
        #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
        let total = staged.saturating_add(chunk.len() as u64);
        if total > u64::from(PayloadLen::MAX.as_inner()) {
            let len = usize::try_from(total).unwrap_or(usize::MAX);
            return Err(EditFault::PayloadTooLarge { len });
        }
        self.machine
            .payloads
            .stage_chunk(chunk)
            .map_err(|role| EditFault::ScratchExhausted { role })?;
        Ok(())
    }

    /// Installs the staged payload ([`PayloadWrite::finish`]'s
    /// contract).
    ///
    /// # Errors
    ///
    /// As [`PayloadWrite::finish`].
    pub fn finish(mut self) -> Result<Handle, EditFault> {
        match self.apply() {
            Ok(handle) => {
                core::mem::forget(self);
                Ok(handle)
            }
            Err(fault) => Err(fault),
        }
    }

    /// The publishing close: mints or overwrites the slot and
    /// applies the one command.
    fn apply(&mut self) -> Result<Handle, EditFault> {
        match self.op {
            WriteOp::Set { handle } => {
                let row = *gate(self.machine.rows.inited(), handle);
                let value = match row.base() {
                    Base::Intact => self
                        .machine
                        .payloads
                        .stage_finish_push(self.mark)
                        .map_err(|role| EditFault::ScratchExhausted { role })?
                        .raw(),
                    Base::Replaced | Base::Inserted => {
                        self.machine
                            .payloads
                            .stage_finish_set(PayloadAt::of_slot(row.value), self.mark);
                        row.value
                    }
                };
                self.machine.payload_set_commit(handle, value);
                Ok(handle)
            }
            WriteOp::Insert { point, field } => {
                let id = self.machine.mint_insert()?;
                let value = self
                    .machine
                    .payloads
                    .stage_finish_push(self.mark)
                    .map_err(|role| EditFault::ScratchExhausted { role })?;
                self.machine.apply_insert(&point, id, field, RecordKind::Len, value.raw());
                Ok(Handle(id))
            }
        }
    }
}

/// A staged payload frame held to a declared length over the
/// copy-only machine ([`SizedPayloadWrite`]'s contract).
#[must_use = "a payload frame installs nothing until finished"]
pub struct SizedCopyPayloadWrite<'w, 'a, 's> {
    inner: CopyPayloadWrite<'w, 'a, 's>,
    /// The declared payload length, in the length class.
    declared: u32,
}

impl SizedCopyPayloadWrite<'_, '_, '_> {
    /// Appends one chunk into bytes the door judged
    /// ([`SizedPayloadWrite::write`]'s contract).
    ///
    /// # Errors
    ///
    /// As [`SizedPayloadWrite::write`].
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), FrameFault> {
        let staged = u64::from(self.inner.machine.payloads.staged_len(self.inner.mark));
        #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
        let total = staged.saturating_add(chunk.len() as u64);
        if total > u64::from(self.declared) {
            return Err(FrameFault::OverDeclared { declared: self.declared, total });
        }
        self.inner.machine.payloads.stage_chunk_judged(chunk);
        Ok(())
    }

    /// Installs the staged payload exactly as declared
    /// ([`SizedPayloadWrite::finish`]'s contract).
    ///
    /// # Errors
    ///
    /// As [`SizedPayloadWrite::finish`].
    pub fn finish(self) -> Result<Handle, FrameFault> {
        let staged = self.inner.machine.payloads.staged_len(self.inner.mark);
        if staged != self.declared {
            return Err(FrameFault::UnderDeclared { declared: self.declared, staged });
        }
        self.inner.finish().map_err(close_fault)
    }
}

#[cfg(test)]
mod tests;
