//! Standing schema-less inspection over a stable-replay source
//! (read · sequential-repeatable · offline), per wire dialect —
//! the dialect-orthogonal shared layer.
//!
//! One index walk builds the buffered inspectors' preorder row
//! product — topology, byte geometry, decoded scalar words, and
//! at most one resident wire fault — while retaining zero source
//! bytes: opaque payloads are skipped, never lent, and the walk
//! decodes every scalar to step anyway, so the rows store the
//! words and the scalar queries stay infallible. Payload bytes
//! are answered by later walks through the fetch faces; no face
//! returns `&[u8]` into a source that is not resident.
//!
//! Coordinates are whole-source `u64` spans
//! ([`SourceSpan`](crate::replay_source::SourceSpan)); row
//! indices stay `u32` ([`NodeId`]). The memory role: the source
//! handle, machine-lived; rows, product-lived; zero resident
//! source bytes.
//!
//! Allocation policy: rows and the walk's stacks grow through the
//! standard infallible `Vec` paths (panic or abort on allocator
//! refusal) — every holding is the in-flight product of one job,
//! so an abort's loss ends with that job. Wire violations are
//! never resource errors: they stay in the product as its fault.
//!
//! The byte-identity obligation and its two fault layers are the
//! supply stratum's ([`crate::replay_source`]): supply refusals
//! surface as structured faults with custody, and a fetch walk
//! judges exactly one length fact — that the source still reaches
//! the extent's end — refusing a source too short for a measured
//! coordinate as `Torn`. Growth or displacement before the extent
//! and the equal-length content tear inside it are undetectable
//! at this cost profile: under a breached obligation a fetch
//! hands wrong bytes — never a fault, never memory-unsafe — and
//! the warranty is void.
//!
//! Coordinates: read · sequential-repeatable · offline · Standard (value-level).
//!
//! # Choosing a face
//!
//! One entry chain per dialect: `Survey::open` — the source, a
//! depth bound, an advisor — walks once and yields the product;
//! `Survey::open_standard` also takes the acceptance
//! [`Standard`](crate::Standard) and picks a monomorphized engine
//! once at entry (`open` is exactly its tolerant instance). Wire
//! violations live *in* the product (`fault`, `is_complete`);
//! supply refusals return the source beside the fault.
//!
//! The advisor argument is the schema dial, exactly the buffered
//! inspectors': [`NoAdvice`] spells zero knowledge (every LEN
//! payload speculates); implement [`Advisor`] to pin the sites
//! you know. A speculative fault discards the speculatively built
//! rows and skips to the payload's end — the source is never
//! re-read for an unwind.
//!
//! Query faces by question: structure (`top`, `children`,
//! `descendants`, `by_field`), values (`varint_word`, `i32_bits`,
//! `i64_bits` — row-resident, infallible), geometry (`span`,
//! `source_spans`, `narrowest`). Byte questions are fetch faces,
//! each a fresh walk: `read_payload` (into a caller `Vec`,
//! refusing extents past the address space), `payload_sink`
//! (borrowed views, the handed prefix reported on a fault), and
//! `fetch_payloads` (many handles, one source-ordered walk — the
//! face that makes k scattered reads cost one walk instead of k).
//!
//! Elsewhere: the same standing queries over resident bytes →
//! `retain` (owned) or `inspect` (borrowed); over a document that
//! arrives in pieces → `collect`; one pass without an index →
//! `scan` (each behind its feature).

use crate::replay_source::ReplayFault;
use crate::wire::FieldNumber;

pub use crate::Stage;

crate::_macro::define_valid_range_type! {
    /// An index into one survey product's row table.
    ///
    /// Row indices stay `u32` while span coordinates are `u64`: a
    /// row spends at least one source byte, but the table itself
    /// must stay addressable — a source whose record count would
    /// leave this class refuses mid-walk with
    /// [`OpenFault::IndexOverflow`], custody intact. The top niche
    /// keeps `Option` of it free (parent links carry no sentinel).
    ///
    /// Handles are slice-like: out-of-range use panics; a stale
    /// handle from another product that happens to be in range
    /// reads that product's answer — memory-safe, semantically the
    /// caller's fault.
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

/// Mints the id of a walk-produced row index (in class by the
/// [`OpenFault::IndexOverflow`] admission at every push).
pub(crate) const fn mint(index: u32) -> NodeId {
    debug_assert!(index <= NodeId::MAX.as_inner());
    // SAFETY: every row push is admitted against the id class
    // before it lands, so walk-produced indices are in class.
    unsafe { NodeId::new_unchecked(index) }
}

/// An open refusal that is not a document property: the walk
/// stopped for a reason no later reader of the same bytes would
/// meet, so nothing resides in a product — the source rides back
/// beside this mark.
///
/// Wire violations are the opposite: they reside in the product
/// (`fault`), and the indexed prefix stays queryable beside them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenFault<E> {
    /// The supply refused (transport or a detected snapshot
    /// break) during the index walk.
    Source(ReplayFault<E>),
    /// The record count would leave the row-index class
    /// ([`NodeId`]).
    IndexOverflow {
        /// The source offset of the record that would not fit.
        at: u64,
    },
    /// The accumulated source offset would leave the addressable
    /// coordinate space (`u64::MAX − 1` bytes).
    OffsetExhausted {
        /// The offset the refused view would have crossed.
        at: u64,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for OpenFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
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
            Self::Source(fault) => Some(fault),
            Self::IndexOverflow { .. } | Self::OffsetExhausted { .. } => None,
        }
    }
}

/// A fetch refusal: the walk that was to answer a byte question
/// could not, and the product is exactly as before the call
/// (fresh-output faces hand nothing; the sink faces report their
/// handed prefix).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FetchFault<E> {
    /// The supply refused (transport or a detected snapshot
    /// break).
    Source(ReplayFault<E>),
    /// The walk met its end before a coordinate the index walk
    /// measured — a length-shaped tear, refused.
    Torn {
        /// The measured coordinate the walk could not reach.
        at: u64,
    },
    /// The extent does not fit the address space, so the `Vec`
    /// face cannot stage it (the sink face has no such ceiling).
    Oversize {
        /// The extent's byte length.
        len: u64,
    },
    /// The extent runs past the indexed prefix (a clipped row at
    /// the resident fault's boundary): the index walk never
    /// proved those bytes, so no fetch reads them.
    Incomplete {
        /// End of the indexed prefix.
        at: u64,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for FetchFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Source(fault) => write!(f, "{fault}"),
            Self::Torn { at } => {
                write!(f, "the source ended before the measured coordinate {at}")
            }
            Self::Oversize { len } => {
                write!(f, "an extent of {len} bytes cannot stage in the address space")
            }
            Self::Incomplete { at } => {
                write!(f, "the extent runs past the indexed prefix ending at {at}")
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for FetchFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Source(fault) => Some(fault),
            Self::Torn { .. } | Self::Oversize { .. } | Self::Incomplete { .. } => None,
        }
    }
}

/// The caller's per-LEN interpretation pole, supplied from schema
/// knowledge.
///
/// Not a performance hint: [`Commit`](Self::Commit) and
/// [`Opaque`](Self::Opaque) are caller contracts, and supplying
/// them changes fault ownership, never how any byte is judged.
#[must_use = "the advice decides how the LEN payload is interpreted"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Advice {
    /// Try-parse: a message attempt where any internal fault
    /// silently concludes "bytes" — the machine takes the risk, so
    /// no fault leaks. The pole for zero schema knowledge. The
    /// unwind discards the speculatively built rows and skips to
    /// the payload's end; the source is never re-read.
    Speculate,
    /// Committed message. Inside a committed chain from the root
    /// the promise is absolute and faults inside are real; under a
    /// speculating ancestor it is conditional — the ancestor may
    /// itself be bytes — and faults unwind that ancestor instead.
    Commit,
    /// Committed opaque bytes: the payload is never parsed — at
    /// this presence it is never even read (the walk skips it), so
    /// no fault can exist inside it.
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

/// Partial-schema supply, consulted at every LEN record head
/// (empty payloads included: an empty `Message` still declares
/// one nesting level and counts against the caller's depth
/// bound).
///
/// The walk does not promise call count or order: sites inside
/// speculation are consulted and may later unwind, and unwinding
/// does not undo advisor state. Implementations must answer as a
/// pure function of `(ancestry, field)`.
pub trait Advisor {
    /// The caller's knowledge about the LEN payload at
    /// `ancestry` / `field`.
    fn advise(&mut self, ancestry: Ancestry<'_>, field: FieldNumber) -> Advice;
}

/// Zero schema, spelled explicitly at call sites: every LEN
/// payload speculates.
#[derive(Clone, Copy, Default, Debug)]
pub struct NoAdvice;

impl Advisor for NoAdvice {
    #[inline]
    fn advise(&mut self, _ancestry: Ancestry<'_>, _field: FieldNumber) -> Advice {
        Advice::Speculate
    }
}

#[cfg(feature = "survey-grouped")]
pub mod grouped;
#[cfg(feature = "survey-groupless")]
pub mod groupless;
