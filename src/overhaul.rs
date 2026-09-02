//! One-shot commit-only editing over a stable-replay source
//! (write · replay · offline · tolerant type-level) — the
//! dialect-orthogonal shared layer.
//!
//! One index walk scans the top layer into an edit-row table —
//! LEN payloads stay opaque declarations until a `descend` or
//! `materialize` walk commits to their interiors — commands
//! mutate rows and authored stores only, and one save walk
//! compiles the rows into an edit script and splices the source
//! through it: untouched extents ride pass 2 verbatim, byte for
//! byte, padded framing included. Repeated saves are lawful; each
//! is one more walk.
//!
//! Coordinates are whole-source `u64` spans
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
//! Coordinates: write · sequential-repeatable · offline · tolerant (type-level) · commit-only.
//!
//! # Choosing a face
//!
//! One entry per dialect: `Overhaul::open` — the source and a
//! depth bound — walks once and yields the editor, refusing an
//! unlawful root layer (this is the buffered one-shot editors'
//! law: acceptance is type-level tolerance of padded framing, not
//! fault tolerance). `descend` commits one LEN interior (one
//! walk, verdict resident); `materialize` resolves k unopened
//! handles in one source-ordered walk. Commands (`set_varint`,
//! `set_payload`, `delete`, `insert_*`) touch no source byte.
//! Saves: `save` / `save_into` (owned product, restored on any
//! refusal), `save_sink` (borrowed views, the handed prefix
//! reported beside a fault, no validity promise — atomic
//! publication is the caller's transactional destination), and
//! `save_len` (the sizing alone, no source walk).
//!
//! Payload backing, by type: `Overhaul` selects per install — the
//! unsuffixed faces (`set_payload`, `insert_payload`) retain
//! borrowed slices, their `_copy` twins stage the bytes at the
//! command. Its sibling `BorrowOverhaul<'p, S>` retains borrowed
//! slices only — one column lighter — and `CopyOverhaul<S>`
//! copies every install, no payload lifetime on the type.
//!
//! Elsewhere: the same one-shot editing over resident bytes →
//! `patch` (borrowed) or `adopt` (owned); path-programmed
//! rewriting over this same supply → `replay_rewrite`; per-record
//! verdicts → `replay_splice` (each behind its feature); the same
//! job under canonical-minimal admission → `refit`.

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

#[cfg(feature = "overhaul-grouped")]
pub mod grouped;
#[cfg(feature = "overhaul-groupless")]
pub mod groupless;
