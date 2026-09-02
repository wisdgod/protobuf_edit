//! The shared maintain layer: the coordinate classes, the edit
//! algebra with its revision log, the value stores, and the layer
//! plumbing both dialect maintain editors build on.
//!
//! A maintain editor is the editing markup's stable-replay twin:
//! the same command set, revision log, tolerant admission, and
//! two-pass fidelity save, over a source that is walked from byte
//! zero as many times as asked instead of borrowed as a slice.
//! Padded tags, length prefixes, and varint values are lawful
//! input; every framing width the scan meets is stored on the row
//! as an input fact, every scanned scalar's decoded word is banked
//! at the scan, and untouched records ride saves byte-exactly —
//! padding included — while authored words emit minimal. Reverting
//! every command restores the source reading exactly, with zero
//! walks: the banked words and stored widths re-speak the scanned
//! reading.
//!
//! Tenure moves in: `open` takes the source by value, walks it
//! once, and a refusal hands it back beside the fault —
//! transactional custody; `into_source` releases it. No source
//! byte is resident: payload bytes cross the fetch and save faces
//! only, so machine growth is O(materialized rows) + O(authored
//! values and payloads) + O(command history), never O(source
//! length).
//!
//! Allocation policy: every growth edge in this scenario is
//! fallible. The stores, the row and layer arenas, the revision
//! log, the save's script and output all reserve through
//! `try_reserve`, and a refusal surfaces as a structured `Err`
//! (the dialects' `OpenFault`/`EditFault`/`SaveFault`) — never an
//! abort: a maintain editor carries revisable interactive state
//! across turns, the fallible side of the crate root's partition
//! rule. One command's infallible suffix is funded by reservations
//! covering the sum of its obligations; the save compile books per
//! edge — every booking face behind its own reservation, so a
//! refusal surfaces at its edge with nothing retained.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other. Descending a LEN is the Commit pole of
//! the per-LEN interpretation axis: an explicit commitment that
//! the payload parses as records — a write machine never
//! speculates.
//!
//! Output acceptance: `save`/`save_into`/`save_sink` guarantee
//! `Tolerant` — authored words are minimal and untouched bytes
//! ride verbatim, so that output closes under `CanonicalMinimal`
//! exactly when the source carried no padding.
//! `save_canonical`/`save_canonical_into`/`save_canonical_sink`
//! guarantee `CanonicalMinimal`: every varint construct in the
//! materialized commitment closure re-emits minimally;
//! non-materialized (unopened/faulted) and authored LEN interiors
//! are opaque declarations.
//!
//! Coordinates: write · sequential-repeatable · offline · tolerant (type-level) · revisable.
//!
//! # Choosing a face
//!
//! - Opening: `Maintain::open` takes the source and scans its top
//!   layer in one walk — LEN payloads stay opaque declarations,
//!   skipped through the supply's own seek, and a refusal returns
//!   the source beside the mark. No depth argument: descent is
//!   caller-stepped and every scan is iterative. The commit-only
//!   replay editor is `overhaul`; the buffered revisable twin over
//!   a borrowed slice is `markup`.
//! - Commands: `set_varint`/`set_i32`/`set_i64`/`set_payload`
//!   replace values; `insert_varint`/`insert_i32`/`insert_i64`/
//!   `insert_payload` (the grouped maintain adds `insert_group`)
//!   author records; `delete` shrouds and `undelete` restores
//!   exactly; `clear_edit` clears a replacement back to the
//!   scanned state — its padded spelling included. All walk-free.
//! - Revision — the axis the one-shot replay editor lacks: every
//!   command logs one step; `revert` pops the last, `revert_all`
//!   empties the log, `pending` counts it. All walk-free; the one
//!   walk-visible consequence is that re-descending a re-sealed
//!   source container costs one fresh walk.
//! - Descending: `descend` commits one LEN interior — one walk
//!   for a fresh source extent, zero once the verdict is resident,
//!   zero for authored payloads (the store is addressable memory);
//!   `materialize` resolves a whole batch of handles in zero or
//!   one source-ordered walk (zero when no fresh source extent
//!   remains), each extent committing atomically.
//! - Fetching: `read_payload` appends one record's current
//!   payload bytes to a caller buffer; `payload_sink` hands them
//!   as borrowed views; `fetch_payloads` answers many handles in
//!   one source-ordered walk, each view tagged with its handle.
//!   Authored payloads answer from the store, walk-free; each
//!   single-handle fetch of a scanned payload is one fresh walk.
//! - Saving: `save` emits a fresh `Vec<u8>`; `save_into` appends
//!   the same bytes to a buffer the caller keeps; `save_sink`
//!   hands the same bytes to a caller sink slice by slice (the
//!   handed prefix is reported beside any fault); `save_len`
//!   prices any of them without a walk, and `save_spans` maps
//!   every emitted record to its output span — the cross-save
//!   identity supply. Each byte-producing save is one walk.
//! - Canonical output: the `save_canonical` family emits the same
//!   records under `CanonicalMinimal` in one walk. It walks the
//!   whole materialized commitment closure — no verbatim fast
//!   path — worth it exactly when a consumer requires minimal
//!   framing from a possibly padded source.
//! - Payload backing, by type: `Maintain` copies payloads at the
//!   command — temporaries welcome, no payload lifetime on the
//!   type. Its sibling `BorrowMaintain<'p, S>` retains borrowed
//!   slices instead — no staging copy, and every payload owner
//!   outlives the machine — and `MixMaintain<'p, S>` selects the
//!   backing per install; the recipes below work the borrowed and
//!   mixed profiles.
//! - Hex-view supply: `span`/`source_spans` give record geometry
//!   at the widths the scan actually met (whole-source `u64`
//!   coordinates), and `narrowest` answers "which record covers
//!   this byte" — both walk-free.
//!
//! Both dialect maintain editors ship the same faces; the crate
//! root's feature guide picks the dialect.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "maintain-groupless")] {
//! use protobuf_edit::maintain::groupless::Maintain;
//! use protobuf_edit::replay_source::SliceSource;
//!
//! // varint f1=150, its value padded to three bytes: tolerant
//! // admission carries the spelling as a stored width fact.
//! let msg = [0x08, 0x96, 0x81, 0x00];
//! let mut editor = Maintain::open(SliceSource::new(&msg)).unwrap();
//! let record = editor.top().next().unwrap();
//! assert_eq!(editor.varint_word(record).unwrap(), 150);
//!
//! // Untouched records ride saves verbatim, padding included.
//! assert_eq!(editor.save().unwrap(), msg);
//!
//! // A replacement re-authors the value minimally — the source
//! // tag still rides verbatim.
//! editor.set_varint(record, 7).unwrap();
//! assert_eq!(editor.save().unwrap(), [0x08, 0x07]);
//!
//! // Revision restores byte fidelity exactly.
//! editor.revert();
//! assert_eq!(editor.save().unwrap(), msg);
//! # }
//! ```
//!
//! # Recipes
//!
//! The undo bracket — a hand-rolled transaction over the revision
//! log: mark `pending` before a compound edit, and on failure pop
//! back to the mark:
//!
//! ```
//! # #[cfg(feature = "maintain-groupless")] {
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::maintain::groupless::Maintain;
//! use protobuf_edit::maintain::InsertAt;
//! use protobuf_edit::replay_source::SliceSource;
//!
//! let msg = [0x08, 0x2A];
//! let mut editor = Maintain::open(SliceSource::new(&msg)).unwrap();
//! let record = editor.top().next().unwrap();
//! editor.set_varint(record, 7).unwrap(); // the committed prefix
//!
//! let mark = editor.pending();
//! let f2 = FieldNumber::new(2).unwrap();
//! editor.insert_varint(InsertAt::TailOf(None), f2, 1).unwrap();
//! editor.insert_varint(InsertAt::TailOf(None), f2, 2).unwrap();
//! // The compound edit is abandoned: unwind to the mark, exactly.
//! while editor.pending() > mark {
//!     editor.revert();
//! }
//! assert_eq!(editor.save().unwrap(), [0x08, 0x07]);
//! # }
//! ```
//!
//! The borrowed-payload profile: a template that outlives both the
//! source handle and the editor installs without a staging copy:
//!
//! ```
//! # #[cfg(feature = "maintain-groupless")] {
//! use protobuf_edit::maintain::groupless::BorrowMaintain;
//! use protobuf_edit::replay_source::SliceSource;
//!
//! let template = vec![0x08, 0x2A];
//! // LEN f2 "a", its prefix padded to two bytes.
//! let source = [0x12, 0x81, 0x00, 0x61];
//! let mut editor = BorrowMaintain::open(SliceSource::new(&source)).unwrap();
//! let record = editor.top().next().unwrap();
//! editor.set_payload(record, &template).unwrap();
//! // The replacement re-authors the prefix; the source tag rides.
//! assert_eq!(editor.save().unwrap(), [0x12, 0x02, 0x08, 0x2A]);
//! editor.revert_all();
//! assert_eq!(editor.save().unwrap(), source);
//! # }
//! ```
#![cfg_attr(
    feature = "maintain-groupless",
    doc = "
A borrowed payload must outlive the editor — the type refuses
an owner that dies while the machine can still read the slot
(the copy-only `Maintain` is the escape hatch for temporaries):

```compile_fail,E0597
use protobuf_edit::maintain::groupless::BorrowMaintain;
use protobuf_edit::replay_source::SliceSource;

let source = [0x12, 0x01, 0x61];
let mut editor = BorrowMaintain::open(SliceSource::new(&source)).unwrap();
let record = editor.top().next().unwrap();
{
    let transient = vec![0x08, 0x07];
    editor.set_payload(record, &transient).unwrap();
} // the owner dies here; the editor still holds the borrow
editor.save().unwrap();
```"
)]
#![cfg_attr(
    feature = "maintain-groupless",
    doc = "
And a retained owner may not be mutated while the machine can
still read the slot — the install borrows it for the machine's
remaining life:

```compile_fail,E0502
use protobuf_edit::maintain::groupless::BorrowMaintain;
use protobuf_edit::replay_source::SliceSource;

let source = [0x12, 0x01, 0x61];
let mut payload = vec![0x08, 0x07];
let mut editor = BorrowMaintain::open(SliceSource::new(&source)).unwrap();
let record = editor.top().next().unwrap();
editor.set_payload(record, &payload).unwrap();
payload.clear(); // the editor still holds the borrow
editor.save().unwrap();
```"
)]
//!
//! The mixed-backing profile: `MixMaintain` selects the backing
//! per install — the unsuffixed faces retain like the borrowed
//! sibling, the `_copy` twins and staged frames copy like the base
//! machine — so a long-lived template and a dying temporary
//! interleave on one revision log:
//!
//! ```
//! # #[cfg(feature = "maintain-groupless")] {
//! use protobuf_edit::maintain::groupless::MixMaintain;
//! use protobuf_edit::replay_source::SliceSource;
//!
//! let template = vec![0x08, 0x2A];
//! let source = [0x12, 0x01, 0x61];
//! let mut editor = MixMaintain::open(SliceSource::new(&source)).unwrap();
//! let record = editor.top().next().unwrap();
//! editor.set_payload(record, &template).unwrap();
//! {
//!     let transient = vec![0x08, 0x07];
//!     editor.set_payload_copy(record, &transient).unwrap();
//! } // the temporary's owner dies; the copied slot keeps its bytes
//! assert_eq!(editor.save().unwrap(), [0x12, 0x02, 0x08, 0x07]);
//! editor.revert();
//! assert_eq!(editor.save().unwrap(), [0x12, 0x02, 0x08, 0x2A]);
//! # }
//! ```

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::admission::usize_of;
use crate::replay_source::{AuthoredAt, SlotAt, SourceAt};

#[cfg(feature = "maintain-grouped")]
pub mod grouped;
#[cfg(feature = "maintain-groupless")]
pub mod groupless;

crate::replay_revise::revising_replay_store!(@coords);
crate::replay_revise::revising_replay_store!(@algebra);
crate::replay_revise::revising_replay_store!(@store copied);
crate::replay_revise::revising_replay_store!(@store borrow);
crate::replay_revise::revising_replay_store!(@store mixed);

/// A maintain editor's name for one record row.
///
/// Minted by the editor that owns the row; forging one (an
/// out-of-range coordinate) panics at the arena gate, which is the
/// documented index contract.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct Handle(pub(crate) RowId);

/// A record's observable edit state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EditStatus {
    /// As scanned.
    Intact,
    /// Value replaced.
    Replaced,
    /// Shrouded (restorable by `undelete`).
    Deleted,
    /// Command-authored and live.
    Inserted,
    /// Command-authored and shrouded — a ghost the UI filters.
    InsertedDeleted,
}

/// Where an insertion splices. Anchors name gaps, not neighboring
/// records: each variant picks exactly one gap of one sibling
/// chain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InsertAt {
    /// First child of the container (`None`: the top layer).
    HeadOf(Option<Handle>),
    /// Last child of the container (`None`: the top layer).
    TailOf(Option<Handle>),
    /// Immediately after this sibling.
    After(Handle),
}

crate::_macro::define_valid_range_type! {
    /// A layer-table coordinate: minted by layer publication,
    /// judgment-free downstream. The excluded top value keeps
    /// `Option` free.
    pub(crate) struct LayerId(u32 as u32 in 0..=4_294_967_294) with new, new_unchecked;

    /// A source-run coordinate: minted once per source scan,
    /// judgment-free downstream. The excluded top value keeps
    /// `Option` free.
    pub(crate) struct SourceRunId(u32 as u32 in 0..=4_294_967_294) with min, new;
}

impl LayerId {
    /// The layer-table index this coordinate names.
    #[inline]
    pub(crate) const fn index(self) -> usize {
        usize_of(self.as_inner())
    }
}

impl SourceRunId {
    /// The run-table index this coordinate names.
    #[inline]
    pub(crate) const fn index(self) -> usize {
        usize_of(self.as_inner())
    }
}

/// The sealed backing zone a layer's rows were scanned out of —
/// the walked source, or one authored payload slot's own zone.
///
/// The zone rides the layer because a row's own offset column is
/// zone-relative: the owning layer names which zone it indexes, so
/// a descend or fetch inside an authored interior finds its slot
/// in O(1) instead of climbing, and no coordinate impersonates the
/// other space.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Zone {
    /// The walked source; `run` is the reverse index's bisectable
    /// row range (`None` for empty layers and for group layers,
    /// whose rows ride their scan's own run).
    Source {
        /// The run of source-backed rows this layer's scan minted.
        run: Option<SourceRunId>,
    },
    /// One authored payload slot's own sealed zone: rows carry
    /// slot-relative offsets and own no hex.
    Authored {
        /// The store slot whose bytes back this layer.
        slot: SlotAt,
    },
}

/// One materialized layer: both sibling-chain anchors, the counts
/// of direct members whose subtree holds dirt and pending history,
/// and the sealed zone its rows were scanned out of.
///
/// A layer whose container's slot re-seals is simply never reached
/// again; its entry stays behind, inert.
pub(crate) struct Layer {
    /// The chain head.
    pub(crate) first: Option<RowId>,
    /// The chain tail — the tail-append anchor.
    pub(crate) last: Option<RowId>,
    /// Direct members whose subtree carries dirt.
    pub(crate) dirty_kids: u32,
    /// Direct members whose subtree holds pending history.
    pub(crate) history_kids: u32,
    /// The backing zone the layer's rows index.
    pub(crate) zone: Zone,
}

const _: () = assert!(core::mem::size_of::<Layer>() == 24);

impl Layer {
    /// A freshly published empty layer over `zone` — the grouped
    /// scan's group-layer mint (groups publish their layer at the
    /// open tag and patch its anchors at the close).
    #[cfg(feature = "maintain-grouped")]
    pub(crate) const fn empty(zone: Zone) -> Self {
        Self { first: None, last: None, dirty_kids: 0, history_kids: 0, zone }
    }

    /// The flagged-member count one mark maintains.
    pub(crate) const fn count(&self, mark: Mark) -> u32 {
        match mark {
            Mark::Dirt => self.dirty_kids,
            Mark::Hist => self.history_kids,
        }
    }

    /// Mutable twin of [`Layer::count`].
    pub(crate) const fn count_mut(&mut self, mark: Mark) -> &mut u32 {
        match mark {
            Mark::Dirt => &mut self.dirty_kids,
            Mark::Hist => &mut self.history_kids,
        }
    }
}

/// One source scan's arena range: ids `first..end` were minted by
/// a single scan over walked source bytes, so their offsets ascend
/// and the reverse index bisects them. Immutable once pushed.
pub(crate) struct SourceRun {
    /// The first row the scan minted.
    pub(crate) first: RowId,
    /// One past the last arena index the scan minted; may sit one
    /// past `RowId`'s domain top.
    pub(crate) end: u32,
}

const _: () = assert!(core::mem::size_of::<SourceRun>() == 8);

/// A container row's child-slot state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Slot {
    /// Never parsed (every scalar; a LEN before its first
    /// descend).
    Unopened,
    /// Parsed: the layer descriptor (present even for an empty
    /// interior, so insertion always finds its anchors).
    Opened(LayerId),
    /// Parse halted: the resident verdict's index in the fault
    /// table.
    Fault(u32),
}

/// `Row.kids` when no child is linked (outside [`RowId`]'s domain,
/// so the packed slot decodes it as `None`).
pub(crate) const NO_CHILD: u32 = u32::MAX;

/// `Row.flags`: the subtree carries dirt.
pub(crate) const FLAG_DIRTY: u8 = 1;
/// `Row.flags`: orphaned by a payload replacement.
pub(crate) const FLAG_DEAD: u8 = 1 << 1;
/// `Row.flags`: scanned out of an authored payload (browse-only).
pub(crate) const FLAG_AUTHORED: u8 = 1 << 2;
/// `Row.flags`: the child slot holds a parsed layer.
pub(crate) const FLAG_OPENED: u8 = 1 << 3;
/// `Row.flags`: the child slot holds a resident fault index.
pub(crate) const FLAG_FAULT: u8 = 1 << 4;
/// `Row.flags`: the row itself has pending undo entries.
pub(crate) const FLAG_OWN_HIST: u8 = 1 << 5;
/// `Row.flags`: the subtree holds pending undo entries (the row's
/// own or a descendant's).
pub(crate) const FLAG_HIST: u8 = 1 << 6;

/// A subtree aggregate the maintain editor maintains. Both marks
/// share one shape: a flag per row, a flagged-direct-member count
/// per layer, and the same rising/falling climb with early stop.
#[derive(Clone, Copy)]
pub(crate) enum Mark {
    /// Pending observable change — the save's pruning judgment.
    Dirt,
    /// Pending undo entries — the backing flip's interior gate.
    Hist,
}

impl Mark {
    /// The row flag this mark rides.
    pub(crate) const fn flag(self) -> u8 {
        match self {
            Self::Dirt => FLAG_DIRTY,
            Self::Hist => FLAG_HIST,
        }
    }
}
