//! One-shot commit-only editing over a stable-replay source under
//! canonical-minimal admission (write · replay · offline ·
//! canonical type-level) — the dialect-orthogonal shared layer.
//!
//! A refit editor is the overhaul's canonical twin: the same
//! index-walk open, handle-addressed commands, on-demand LEN
//! commitments, and one splicing save walk — with every varint
//! construct the walks meet judged minimal at admission. A padded
//! tag, length prefix, varint value — in the grouped dialect, a
//! padded group end tag — is lawful tolerant wire refused by this
//! machine's standard: at the root the open refuses whole (the
//! source rides back beside the mark), inside a payload the
//! refusal parks as a resident verdict like any wire fault.
//! Admission proved every scanned framing word minimal and
//! authored words emit minimal, so untouched extents riding the
//! save verbatim *is* canonical emission: saved documents
//! re-ingest under this same door, with the one caller-declared
//! exception — an authored payload's interior passes through
//! unchanged.
//!
//! Because met and minimal coincide under this door, the rows
//! store no framing-width facts: every window derives from the
//! record's own field, kind, and extent. Coordinates are
//! whole-source `u64` spans
//! ([`SourceSpan`](crate::replay_source::SourceSpan)); row
//! indices stay `u32` (handles). The memory role: the source
//! handle, machine-lived; rows and authored stores, machine-lived
//! and never reclaimed (re-setting a payload leaves the old bytes
//! behind inert — the commit-only trade); zero resident source
//! bytes.
//!
//! Allocation policy: rows, stores, and the walks' stacks grow
//! through the standard infallible `Vec` paths (panic or abort on
//! allocator refusal) — every holding is the in-flight product of
//! one job, so an abort's loss ends with that job.
//!
//! The byte-identity obligation and its two fault layers are the
//! supply stratum's ([`crate::replay_source`]): supply refusals
//! surface as structured faults, machine-detected tears as `Torn`
//! — and the faces split on what their walks can detect. A
//! descend or fetch walk judges only that the source still
//! reaches its extent's end, refusing a shorter source as `Torn`;
//! growth and displacement are undetectable there, so under a
//! breached obligation a fetch hands wrong bytes and a descend
//! can park a fabricated document fault — never memory-unsafe,
//! warranty void. Only the save walks anchor the measured total:
//! the emission's end probe refuses a source that grew or shrank
//! as `Torn`.
//!
//! Coordinates: write · sequential-repeatable · offline · canonical (type-level) · commit-only.
//!
//! # Choosing a face
//!
//! One entry per dialect: `Refit::open` — the source and a depth
//! bound — walks once and yields the editor, refusing an unlawful
//! or padded root layer (acceptance is type-level minimality, not
//! fault tolerance). `descend` commits one LEN interior (one
//! walk, verdict resident); `materialize` resolves k unopened
//! handles in one source-ordered walk. Commands (`set_varint`,
//! `set_payload`, `delete`, `insert_*`) touch no source byte.
//! Fetching: `read_payload` appends one record's current payload
//! bytes to a caller buffer, `payload_sink` hands them as
//! borrowed views, and `fetch_payloads` answers many handles in
//! one source-ordered walk, each view tagged with its handle.
//! Saves: `save` / `save_into` (owned product, restored on any
//! refusal), `save_sink` (borrowed views, the handed prefix
//! reported beside a fault, no validity promise — atomic
//! publication is the caller's transactional destination),
//! `save_len` (the sizing alone, no source walk), and
//! `save_spans` (the output-order span table, no source walk).
//! `narrowest` answers "which record covers this byte" walk-free.
//!
//! Payload backing, by type: `Refit` selects per install — the
//! unsuffixed faces (`set_payload`, `insert_payload`) and the
//! scatter `_parts` faces retain borrowed slices, their `_copy`
//! twins and the staged payload frames (`begin_set_payload` and
//! kin) copy the bytes in. Its sibling `BorrowRefit<'p, S>`
//! retains borrowed slices only — one column lighter, no frames —
//! and `CopyRefit<S>` copies every install, no payload lifetime
//! on the type.
//!
//! Elsewhere: the same canonical one-shot editing over resident
//! bytes → `amend` (borrowed) or `intake` (owned); the tolerant
//! replay one-shot → `overhaul`; canonical revision across turns
//! over this same supply → `commission` (each behind its
//! feature).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "refit-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::refit::groupless::Refit;
//! use protobuf_edit::replay_source::SliceSource;
//!
//! // varint f1=150, minimally spelled: the canonical door admits.
//! let msg = [0x08, 0x96, 0x01];
//! let mut editor = Refit::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
//!     .map_err(|(_, fault)| fault)
//!     .unwrap();
//! let record = editor.top().next().unwrap();
//! assert_eq!(editor.varint_word(record), Some(150));
//!
//! // Untouched records ride saves verbatim — already minimal.
//! assert_eq!(editor.save().unwrap(), msg);
//!
//! // A replacement re-authors the value minimally.
//! editor.set_varint(record, 7).unwrap();
//! assert_eq!(editor.save().unwrap(), [0x08, 0x07]);
//! # }
//! ```
//!
//! A padded source refuses at the door — the same bytes the
//! tolerant replay editor (`overhaul`) accepts — and the refusal
//! projects its typed site and met width:
//!
//! ```
//! # #[cfg(feature = "refit-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::refit::groupless::{FaultKind, OpenFault, Refit};
//! use protobuf_edit::replay_source::{NonMinimalSite, SliceSource};
//!
//! // varint f1=150, its value padded to three bytes.
//! let padded = [0x08, 0x96, 0x81, 0x00];
//! let Err((_, OpenFault::Wire(fault))) =
//!     Refit::open(SliceSource::new(&padded), DepthLimit::REFERENCE)
//! else {
//!     panic!("padding refuses at the canonical door");
//! };
//! let FaultKind::NonMinimal(refusal) = fault.kind() else {
//!     panic!("the refusal names the padded construct");
//! };
//! assert_eq!(fault.at(), 1);
//! assert!(matches!(refusal.site(), NonMinimalSite::Value));
//! assert_eq!(refusal.width(), 3);
//! # }
//! ```
//!
//! The scatter profile: the mixed form installs a payload as
//! borrowed pieces, and the save concatenates them in place:
//!
//! ```
//! # #[cfg(feature = "refit-groupless")] {
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::refit::groupless::Refit;
//! use protobuf_edit::replay_source::SliceSource;
//!
//! // LEN f2 "hi".
//! let msg = [0x12, 0x02, 0x68, 0x69];
//! let mut editor = Refit::open(SliceSource::new(&msg), DepthLimit::REFERENCE)
//!     .map_err(|(_, fault)| fault)
//!     .unwrap();
//! let record = editor.top().next().unwrap();
//! let parts: [&[u8]; 3] = [b"scat", b"", b"tered"];
//! editor.set_payload_parts(record, &parts).unwrap();
//! assert_eq!(
//!     editor.save().unwrap(),
//!     [0x12, 0x09, b's', b'c', b'a', b't', b't', b'e', b'r', b'e', b'd'],
//! );
//! # }
//! ```

use crate::replay_source::ReplayFault;

pub use crate::Stage;

crate::_macro::define_valid_range_type! {
    /// An index into one editor's row table (the inner word of a
    /// [`Handle`]).
    ///
    /// Row indices stay `u32` while span coordinates are `u64`: a
    /// scanned row spends at least one source byte, but the table
    /// itself must stay addressable — a source whose record count
    /// would leave this class refuses with `IndexOverflow`. The
    /// top niche keeps `Option` of it free (chain links carry no
    /// sentinel).
    #[must_use]
    pub(crate) struct RowId(u32 as u32 in 0..=0x7FFF_FFFE) with max, new_unchecked;
}

impl RowId {
    /// The row-table index this id names.
    #[inline]
    pub(crate) const fn index(self) -> usize {
        crate::admission::usize_of(self.as_inner())
    }
}

/// Mints the id of a walk-produced row index (in class by the
/// `IndexOverflow` admission at every push).
pub(crate) const fn mint(index: u32) -> RowId {
    debug_assert!(index <= RowId::MAX.as_inner());
    // SAFETY: every row push is admitted against the id class
    // before it lands, so walk-produced indices are in class.
    unsafe { RowId::new_unchecked(index) }
}

/// An editor's name for one record row.
///
/// Minted by the editor that owns the row; forging one (an
/// out-of-range coordinate) panics at the arena gate, which is
/// the documented index contract. Handles stay valid for the
/// editor's life — commit-only editing never orphans a row.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct Handle(pub(crate) RowId);

/// A record's observable edit state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EditStatus {
    /// As scanned; the source bytes ride verbatim.
    Intact,
    /// Value replaced; the source tag still rides verbatim.
    Replaced,
    /// Deleted: the record vanishes whole at save.
    Deleted,
    /// Command-authored; emitted minimally.
    Inserted,
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

/// Why a save refused. The owned-product faces restore their
/// buffer on any `Err`; the sink face reports its handed prefix
/// instead ([`Handed`](crate::replay_source::Handed)).
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SaveFault<E> {
    /// A rewritten LEN body outgrew the length class.
    BodyOverCap {
        /// Source offset of the overflowing LEN record's head
        /// tag.
        at: u64,
    },
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
            Self::BodyOverCap { .. } | Self::Torn { .. } => None,
        }
    }
}

#[cfg(feature = "refit-grouped")]
pub mod grouped;
#[cfg(feature = "refit-groupless")]
pub mod groupless;
