//! The stable-replay supply stratum: the sequential-repeatable
//! source contract, its walk and coordinate vocabularies, and the
//! slice-backed reference source.
//!
//! A stable-replay source can be walked from byte zero as many
//! times as asked, each successful walk yielding one identical
//! finite byte sequence. That is the whole contract — no span is
//! addressable, no byte is retained by any machine, and chunk
//! partitioning carries no meaning (it may differ between walks;
//! only the concatenated sequence is promised). The replay
//! scenario cells (`survey`, `replay_rewrite`, `replay_splice`,
//! `overhaul`) are generic over [`StableReplaySource`]; callers
//! implement it once per storage kind and select machines by
//! feature exactly as for the buffered and stream cells.
//!
//! Replay coordinates are typed at this stratum: `SourceAt`
//! carries one whole-source offset (`u64::MAX` excluded — a byte
//! there would put the source's length past the countable space,
//! which the machines refuse at the walk), `SlotAt` and
//! `AuthoredAt` carry a store's authored payload slot and its
//! zone-relative offset, and the public [`FaultAt`] keeps those
//! two coordinate spaces from impersonating each other in the
//! fault vocabularies that embed it. The canonical replay cells
//! additionally share one refusal carrier (`NonMinimal`, behind
//! their features): the opaque site–width coupling their fault
//! vocabularies embed as the policy-classed refusal.
//!
//! Two fault layers split what a machine can judge from what it
//! never re-reads:
//!
//! - **Supply faults** ([`SupplyFault`]) are the provider's own
//!   refusals: transport errors, and [`Changed`] where the
//!   provider can detect that its snapshot no longer holds. The
//!   machines wrap them with the operation phase
//!   ([`ReplayFault`]) and return custody.
//! - **Length-shaped tears the machine's own reads can see** are
//!   detected and refused by the machines (their `Torn` faults):
//!   a walk meeting its end before a coordinate an earlier walk
//!   measured, or running past the measured total length. The
//!   equal-length content tear inside an extent a later walk only
//!   copies or skips is *not detectable at this cost profile*:
//!   byte identity across walks is therefore a documented trait
//!   obligation — violating it voids the machines' output
//!   warranties but never memory safety (every read is
//!   bounds-judged against the currently lent view; measured
//!   facts are spent as counts to request, never as indices into
//!   later views).
//!
//! The trait is safe: a lying provider is a semantic breach, not
//! a memory precondition.
//!
//! [`Changed`]: SupplyFault::Changed

/// A supply-side refusal: the source's own story, not the
/// machine's.
///
/// `E` is the provider's transport error type
/// ([`StableReplaySource::Error`]); machines are monomorphized
/// over the source, so the provider's story rides through their
/// fault enums at full fidelity and zero cost.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SupplyFault<E> {
    /// The provider failed to move bytes (I/O refusal, lease
    /// loss, …).
    Transport(E),
    /// The provider detected that its snapshot no longer holds:
    /// a later walk would not (or did not) yield the established
    /// byte sequence. Machines never retry past it — restarting
    /// against a new version would join judgments from one
    /// document to bytes from another.
    Changed,
}

impl<E: core::fmt::Display> core::fmt::Display for SupplyFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "source transport refusal: {error}"),
            Self::Changed => f.write_str("the source's snapshot no longer holds"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for SupplyFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Changed => None,
        }
    }
}

/// A non-empty lent view of the walk's next bytes.
///
/// Non-emptiness is judged at construction ([`Chunk::new`] is the
/// one mint), so a consumer loop has no empty-chunk livelock
/// branch: end-of-walk is `None` from [`ReplayWalk::fill`], never
/// an empty view.
#[must_use]
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Chunk<'a>(&'a [u8]);

impl<'a> Chunk<'a> {
    /// Wraps a non-empty view; `None` for an empty slice — the
    /// provider spells end-of-walk as [`ReplayWalk::fill`]'s own
    /// `None` instead.
    #[inline]
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.is_empty() { None } else { Some(Self(bytes)) }
    }

    /// The lent bytes (at least one).
    #[inline]
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.0
    }

    /// The lent length (at least one).
    #[allow(
        clippy::len_without_is_empty,
        reason = "non-emptiness is the type's construction judgment — an is_empty here \
                  would be a constant false"
    )]
    #[inline]
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.len()
    }
}

/// One walk over a stable-replay source, from byte zero to a
/// finite end.
///
/// The walk owns the transport buffer and lends views of it
/// ([`fill`]); the machine allocates nothing to move bytes. A
/// lent view is valid until the next mutable walk operation and
/// is never retained. Positions advance only through [`consume`]
/// and [`skip`].
///
/// Contract, per operation:
///
/// - [`fill`] lends the walk's next unconsumed bytes as a
///   non-empty view, or judges the finite end (`None`). Repeated
///   fills without an intervening consume lend the same bytes
///   (more may be appended). `None` is stable: once the end is
///   judged, later fills judge it again.
/// - [`consume`] releases the first `n` bytes of the last lent
///   view; `n` at most that view's length.
/// - [`skip`] advances up to `n` bytes without lending them and
///   reports the advanced count: exactly `n` while the walk has
///   that many left, the shorter remainder when the end arrives
///   first — never past the end. A short skip is how a machine
///   sees a document end inside an extent it never reads;
///   leaving it unreported would hide truncation behind exactly
///   the sources that seek best. Required and undefaulted: a
///   source that can seek answers in its own cost class, and a
///   rewind-only source spells its linear cost visibly by
///   delegating to [`discard_skip`] — a defaulted
///   read-and-discard body would smuggle linear skips behind
///   seeking sources' backs.
///
/// [`fill`]: Self::fill
/// [`consume`]: Self::consume
/// [`skip`]: Self::skip
pub trait ReplayWalk {
    /// The provider's transport error
    /// ([`StableReplaySource::Error`]).
    type Error;

    /// Lends the next unconsumed bytes (`None`: the walk's finite
    /// end).
    ///
    /// # Errors
    ///
    /// The provider's own refusal; [`SupplyFault::Changed`] when
    /// it can prove its snapshot broke.
    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<Self::Error>>;

    /// Releases the first `n` bytes of the last lent view.
    ///
    /// `n` must be at most the last lent view's length; more is a
    /// caller bug the provider may panic on.
    fn consume(&mut self, n: usize);

    /// Advances up to `n` bytes without lending them; reports the
    /// count actually advanced (see the trait doc's skip clause).
    ///
    /// # Errors
    ///
    /// As [`fill`](Self::fill).
    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<Self::Error>>;
}

/// A sequential-repeatable byte source: every successful
/// [`begin`] starts a walk at byte zero, and every walk yields
/// one identical finite byte sequence while the source value is
/// held.
///
/// The byte-identity clause is a trait obligation, not a machine
/// judgment (the module doc's second fault layer): the value
/// denotes an established snapshot or lease — an immutable
/// object, a filesystem snapshot, a lock whose contract really
/// prevents or detects mutation. Merely opening a mutable path
/// and comparing metadata is not enough; a provider that cannot
/// prevent mutation but can detect it surfaces
/// [`SupplyFault::Changed`] before exposing any byte that differs
/// from the established sequence.
///
/// [`begin`]: Self::begin
pub trait StableReplaySource {
    /// The provider's transport error. Rides through the
    /// machines' fault enums at full fidelity
    /// ([`SupplyFault::Transport`]).
    type Error;

    /// One walk's form; its borrow scope is exactly the walk.
    type Walk<'s>: ReplayWalk<Error = Self::Error>
    where
        Self: 's;

    /// Starts a walk at byte zero. Machines call it at the start
    /// of every pass — a fresh walk's position is never assumed.
    ///
    /// # Errors
    ///
    /// The provider's refusal to open (or re-open) the walk.
    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<Self::Error>>;
}

/// Skips by filling and discarding — the rewind-only provider's
/// visible linear skip, called from its own
/// [`ReplayWalk::skip`] so the cost is written at the impl site.
///
/// Advances up to `n` bytes and reports the count actually
/// advanced (shorter exactly when the walk's end arrives first —
/// the skip clause of the [`ReplayWalk`] contract).
///
/// # Errors
///
/// The walk's own fill refusal, at the position it occurred.
pub fn discard_skip<W: ReplayWalk + ?Sized>(
    walk: &mut W,
    n: u64,
) -> Result<u64, SupplyFault<W::Error>> {
    let mut left = n;
    while left > 0 {
        let Some(view) = walk.fill()? else {
            return Ok(n - left);
        };
        // A lent view is at most usize long, so the min fits both
        // domains losslessly.
        #[allow(
            clippy::as_conversions,
            reason = "the min of a u64 and a usize-length view fits usize on the \
                      crate's 32/64-bit targets"
        )]
        let take = left.min(view.len() as u64) as usize;
        walk.consume(take);
        #[allow(clippy::as_conversions, reason = "usize widens losslessly into u64")]
        {
            left -= take as u64;
        }
    }
    Ok(n)
}

/// The transport error of a source that cannot fail: the slice is
/// resident, so no fill or skip has a refusal to report.
///
/// An empty enum — the machines' `Transport` arms over it are
/// uninhabited and compile away.
#[allow(
    clippy::empty_enums,
    reason = "the uninhabited transport error is the type-level \"cannot fail\" fact; \
              the never type is not yet stable vocabulary here"
)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SliceFault {}

#[allow(
    clippy::uninhabited_references,
    reason = "the impl exists so the fault wrappers over the slice source are Display; \
              no receiver can ever exist, and the empty match spells exactly that"
)]
impl core::fmt::Display for SliceFault {
    #[inline]
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {}
    }
}

impl core::error::Error for SliceFault {}

/// The slice-backed reference source: a borrowed buffer worn as a
/// stable-replay source.
///
/// The shipped impl — the differential and judge vehicle (the
/// buffered twins read the same slice directly), and the honest
/// migration path for a caller whose "file" turned out to fit in
/// memory. Byte identity holds by construction: the borrow is
/// immutable for the source's life. Skips are pointer bumps; each
/// fill lends the whole remainder in one view.
///
/// # Examples
///
/// ```
/// use protobuf_edit::replay_source::{ReplayWalk, SliceSource, StableReplaySource};
///
/// let mut source = SliceSource::new(&[0x08, 0x96, 0x01]);
/// let mut walk = source.begin().unwrap();
/// let view = walk.fill().unwrap().unwrap();
/// assert_eq!(view.bytes(), [0x08, 0x96, 0x01]);
/// walk.consume(1);
/// assert_eq!(walk.skip(1).unwrap(), 1);
/// let rest = walk.fill().unwrap().unwrap();
/// assert_eq!(rest.bytes(), [0x01]);
/// walk.consume(1);
/// assert!(walk.fill().unwrap().is_none());
/// ```
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct SliceSource<'a> {
    bytes: &'a [u8],
}

impl<'a> SliceSource<'a> {
    /// Wears the borrowed buffer as a source.
    #[inline]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// The worn buffer.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// One walk over a [`SliceSource`]: the remainder view and a
/// cursor.
#[must_use]
#[derive(Debug)]
pub struct SliceWalk<'a> {
    rest: &'a [u8],
}

impl StableReplaySource for SliceSource<'_> {
    type Error = SliceFault;

    type Walk<'s>
        = SliceWalk<'s>
    where
        Self: 's;

    #[inline]
    fn begin(&mut self) -> Result<Self::Walk<'_>, SupplyFault<SliceFault>> {
        Ok(SliceWalk { rest: self.bytes })
    }
}

impl ReplayWalk for SliceWalk<'_> {
    type Error = SliceFault;

    #[inline]
    fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<SliceFault>> {
        Ok(Chunk::new(self.rest))
    }

    #[inline]
    fn consume(&mut self, n: usize) {
        self.rest = &self.rest[n..];
    }

    #[inline]
    #[allow(
        clippy::as_conversions,
        reason = "the min of a u64 and a usize-length remainder fits usize on the \
                  crate's 32/64-bit targets"
    )]
    fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<SliceFault>> {
        let take = n.min(self.rest.len() as u64) as usize;
        self.rest = &self.rest[take..];
        Ok(take as u64)
    }
}

/// The operation a machine was serving when its source refused —
/// the repair coordinate a caller routes on (retry the open,
/// re-fetch, discard the emitted prefix, …).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReplayPhase {
    /// Building a standing index (an open's first walk).
    Index,
    /// Measuring and judging for a later emission walk.
    Measure,
    /// Delivering records for the caller's verdicts.
    Decide,
    /// Materializing a container's interior.
    Descend,
    /// Reading designated payload bytes back.
    Fetch,
    /// Emitting the output.
    Emit,
}

impl core::fmt::Display for ReplayPhase {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Index => "index",
            Self::Measure => "measure",
            Self::Decide => "decide",
            Self::Descend => "descend",
            Self::Fetch => "fetch",
            Self::Emit => "emit",
        })
    }
}

/// A supply fault wrapped with the machine operation it refused —
/// the shape every replay cell's fault enum embeds beside its
/// wire, admission, and coordinate variants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReplayFault<E> {
    /// Starting a walk refused ([`StableReplaySource::begin`]).
    Rewind {
        /// The operation the walk was for.
        phase: ReplayPhase,
        /// The provider's refusal.
        source: SupplyFault<E>,
    },
    /// Reading or skipping refused mid-walk.
    Read {
        /// The operation the walk was for.
        phase: ReplayPhase,
        /// The first unread source offset.
        at: u64,
        /// The provider's refusal.
        source: SupplyFault<E>,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for ReplayFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rewind { phase, source } => {
                write!(f, "the {phase} walk failed to start: {source}")
            }
            Self::Read { phase, at, source } => {
                write!(f, "the {phase} walk failed at source offset {at}: {source}")
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ReplayFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Rewind { source, .. } | Self::Read { source, .. } => Some(source),
        }
    }
}

/// A sink-face refusal beside the exact prefix already handed
/// over.
///
/// A fallible source makes "every fault precedes the first
/// handoff" impossible for an ordinary sink, so the replay sink
/// faces name what the sink received instead of promising it
/// received nothing. The prefix carries no validity promise;
/// atomic publication is the caller's transactional destination.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Handed<F> {
    /// Bytes handed to the sink before the refusal.
    pub handed: u64,
    /// The refusal itself.
    pub fault: F,
}

impl<F: core::fmt::Display> core::fmt::Display for Handed<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} after {} bytes were handed over", self.fault, self.handed)
    }
}

impl<F: core::error::Error + 'static> core::error::Error for Handed<F> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.fault)
    }
}

/// A byte range in whole-source coordinates, half-open — the
/// replay cells' span vocabulary.
///
/// The stream coordinate space (`u64`) is what a walk position
/// inhabits, so replay products speak it everywhere the buffered
/// twins speak `u32`; the ordered-interval invariant
/// (`start <= end`) is the type's, judged at the one mint.
///
/// # Examples
///
/// ```
/// use protobuf_edit::replay_source::SourceSpan;
///
/// let span = SourceSpan::new(3, 8);
/// assert_eq!((span.start(), span.end(), span.len()), (3, 8, 5));
/// ```
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourceSpan {
    start: u64,
    end: u64,
}

impl SourceSpan {
    /// Builds the range.
    ///
    /// # Panics
    ///
    /// If `start > end` — an inverted range is a caller bug,
    /// judged here so the ordered-interval invariant holds in
    /// every build.
    #[inline]
    #[track_caller]
    pub const fn new(start: u64, end: u64) -> Self {
        assert!(start <= end, "SourceSpan::new: inverted range");
        Self { start, end }
    }

    /// Inclusive start.
    #[inline]
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Exclusive end.
    #[inline]
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Byte length.
    #[inline]
    #[must_use]
    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    /// True when the range is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// One committed container crossed on the way to a fault, in
/// whole-source coordinates.
///
/// The replay writers' trail element, present exactly when a
/// writer cell that mints it is: the buffered writers' crossing
/// vocabulary speaks their `u32` coordinate class and cannot
/// carry a walk position.
#[cfg(any(
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless"
))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourceCrossing {
    field: crate::wire::FieldNumber,
    at: u64,
}

#[cfg(any(
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless"
))]
impl SourceCrossing {
    /// Crate-internal mint: the walks record the containers they
    /// commit.
    pub(crate) const fn new(field: crate::wire::FieldNumber, at: u64) -> Self {
        Self { field, at }
    }

    /// The committed container's field number.
    #[inline]
    pub const fn field(self) -> crate::wire::FieldNumber {
        self.field
    }

    /// The container's head tag offset (whole-source).
    #[inline]
    #[must_use]
    pub const fn at(self) -> u64 {
        self.at
    }
}

crate::_macro::define_valid_range_type! {
    /// A whole-source byte coordinate: the offset of one byte a
    /// walk established, in the space every walk counts (`u64`
    /// excluding `u64::MAX`).
    ///
    /// The exclusion carries the space's meaning: a byte at
    /// coordinate `u64::MAX` would make the source at least 2^64
    /// bytes long — a length past what the walks count — so such
    /// documents are refusal domain, judged at the machines' walks
    /// (their offset-exhaustion and unsatisfiable-length
    /// verdicts), never a representable coordinate. The freed top
    /// value funds the niche (`Option<SourceAt>` is 8 bytes) and
    /// stays reserved for the pump's root-zone sentinel.
    #[must_use]
    pub(crate) struct SourceAt(u64 as u64 in 0..=18_446_744_073_709_551_614)
        with max, new_unchecked;

    /// A store-slot coordinate: names one authored payload in a
    /// machine's own store (`u32` excluding `u32::MAX`).
    ///
    /// Minted by the store's pushes and spent judgment-free for
    /// the machine's life — the slot table never shrinks. The
    /// excluded top value keeps `Option` free.
    #[must_use]
    pub(crate) struct SlotAt(u32 as u32 in 0..=4_294_967_294) with new;

    /// A byte offset into one authored payload's zone (`u32`
    /// excluding `u32::MAX`).
    ///
    /// Each authored slot is its own sealed zone: rows and
    /// verdicts minted from its bytes speak offsets relative to
    /// it, never whole-source coordinates. A zone's end is
    /// admitted against this domain when the payload enters the
    /// store, so a held offset addresses (or ends flush with)
    /// admitted bytes. The excluded top value keeps `Option`
    /// free.
    #[must_use]
    pub(crate) struct AuthoredAt(u32 as u32 in 0..=4_294_967_294) with new;
}

/// One fault coordinate in exactly one of the two spaces a replay
/// cell reads: the private typed interior of [`FaultAt`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ZonedAt {
    /// Bytes a source walk established, in whole-source
    /// coordinates.
    Source(SourceAt),
    /// Bytes a caller installed, at an offset relative to the
    /// owning slot's zone.
    Authored { slot: SlotAt, at: AuthoredAt },
}

/// Where a fault sits: one coordinate in exactly one of the two
/// spaces a replay cell reads.
///
/// The spaces — the source's whole-walk space and one authored
/// payload slot's own zone — share no origin, so a bare integer
/// could silently impersonate a source offset. The carrier is
/// therefore opaque: the typed interior stays private,
/// construction is the machines' own, and consumers route on
/// [`zone`] and read the raw projections, whose domains are
/// documented per face. The fault vocabularies of the cells that
/// scan authored payloads embed it as their coordinate.
///
/// [`zone`]: Self::zone
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FaultAt {
    at: ZonedAt,
}

/// The coordinate space a [`FaultAt`] speaks — the routing
/// discriminant its projections are read under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultZone {
    /// Whole-source coordinates: the fault sits on bytes a source
    /// walk established.
    Source,
    /// One authored payload slot's zone: the fault sits on bytes
    /// a caller installed, at an offset relative to that slot.
    Authored,
}

impl FaultAt {
    /// Crate-internal mint: a fault on walk-established bytes.
    pub(crate) const fn source(at: SourceAt) -> Self {
        Self { at: ZonedAt::Source(at) }
    }

    /// Crate-internal mint: a fault inside one authored slot's
    /// zone.
    pub(crate) const fn authored(slot: SlotAt, at: AuthoredAt) -> Self {
        Self { at: ZonedAt::Authored { slot, at } }
    }

    /// The coordinate space the fault speaks.
    #[inline]
    #[must_use]
    pub const fn zone(self) -> FaultZone {
        match self.at {
            ZonedAt::Source(_) => FaultZone::Source,
            ZonedAt::Authored { .. } => FaultZone::Authored,
        }
    }

    /// The whole-source byte offset — `Some` exactly for
    /// [`FaultZone::Source`]. Domain `0..=u64::MAX − 1`: a
    /// coordinate never reaches `u64::MAX`, because a byte there
    /// would put the source's length past the countable space and
    /// the machines refuse such documents at the walk.
    #[inline]
    #[must_use]
    pub const fn source_at(self) -> Option<u64> {
        match self.at {
            ZonedAt::Source(at) => Some(at.as_inner()),
            ZonedAt::Authored { .. } => None,
        }
    }

    /// The authored payload slot, as the machine's store names it
    /// — `Some` exactly for [`FaultZone::Authored`]. Domain
    /// `0..=u32::MAX − 1`: a store coordinate minted by the
    /// store's own pushes.
    #[inline]
    #[must_use]
    pub const fn slot(self) -> Option<u32> {
        match self.at {
            ZonedAt::Source(_) => None,
            ZonedAt::Authored { slot, .. } => Some(slot.as_inner()),
        }
    }

    /// The byte offset inside the authored slot's zone — `Some`
    /// exactly for [`FaultZone::Authored`]. Domain
    /// `0..=u32::MAX − 1`, relative to the slot and never a
    /// source offset; the zone's end was admitted against the
    /// domain when the payload entered the store.
    #[inline]
    #[must_use]
    pub const fn authored_at(self) -> Option<u32> {
        match self.at {
            ZonedAt::Source(_) => None,
            ZonedAt::Authored { at, .. } => Some(at.as_inner()),
        }
    }
}

/// The private typed interior of [`NonMinimal`]: each site
/// coupled to its own width window, so an impossible pairing (a
/// framing site carrying a value-window width) is
/// unconstructible.
#[cfg(any(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PaddedSite {
    /// A head or group-end tag word (five-byte window).
    Tag {
        /// The met framing width.
        width: crate::varint::WordWidth,
    },
    /// A LEN length prefix (five-byte window).
    LenPrefix {
        /// The record's field number.
        field: crate::wire::FieldNumber,
        /// The met framing width.
        width: crate::varint::WordWidth,
    },
    /// A varint record's value (ten-byte window).
    Value {
        /// The record's field number.
        field: crate::wire::FieldNumber,
        /// The met value width.
        width: crate::varint::ValueWidth,
    },
}

/// One canonical-admission refusal: a varint construct spelled
/// wider than its value's minimal encoding.
///
/// Such a construct is lawful tolerant wire, refused by the
/// canonical replay editors' type-level standard (`refit`,
/// `commission`), whose fault vocabularies embed this carrier as
/// their policy-classed refusal.
///
/// The interior is a typed sum coupling each site to its own
/// width window — framing sites to the five-byte window, the
/// value site to the ten-byte window — so an impossible pairing
/// (a tag carrying a value-window width) is unconstructible, and
/// the carrier is opaque so that coupling never becomes public
/// surface: construction is the machines' own, consumers route
/// on [`site`] and read the raw projections, whose domains are
/// documented per face.
///
/// [`site`]: Self::site
#[cfg(any(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NonMinimal {
    padded: PaddedSite,
}

/// The construct a [`NonMinimal`] refusal sits on — the routing
/// discriminant its projections are read under.
#[cfg(any(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NonMinimalSite {
    /// A head tag word — in the grouped dialects, a group end tag
    /// refuses through this same site at its own offset.
    Tag,
    /// A LEN length prefix.
    LenPrefix,
    /// A varint record's value.
    Value,
}

#[cfg(any(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
impl NonMinimal {
    /// Crate-internal mint: a padded head or group-end tag.
    pub(crate) const fn tag(width: crate::varint::WordWidth) -> Self {
        Self { padded: PaddedSite::Tag { width } }
    }

    /// Crate-internal mint: a padded LEN length prefix.
    pub(crate) const fn len_prefix(
        field: crate::wire::FieldNumber,
        width: crate::varint::WordWidth,
    ) -> Self {
        Self { padded: PaddedSite::LenPrefix { field, width } }
    }

    /// Crate-internal mint: a padded varint value.
    pub(crate) const fn value(
        field: crate::wire::FieldNumber,
        width: crate::varint::ValueWidth,
    ) -> Self {
        Self { padded: PaddedSite::Value { field, width } }
    }

    /// The construct the padded word was serving.
    #[inline]
    pub const fn site(self) -> NonMinimalSite {
        match self.padded {
            PaddedSite::Tag { .. } => NonMinimalSite::Tag,
            PaddedSite::LenPrefix { .. } => NonMinimalSite::LenPrefix,
            PaddedSite::Value { .. } => NonMinimalSite::Value,
        }
    }

    /// The met width, raw — the padded spelling's byte count.
    /// Domain per site: a minimal spelling is never refused, so
    /// [`Tag`] and [`LenPrefix`] carry `2..=5` (the five-byte
    /// framing window) and [`Value`] carries `2..=10` (the
    /// ten-byte value window).
    ///
    /// [`Tag`]: NonMinimalSite::Tag
    /// [`LenPrefix`]: NonMinimalSite::LenPrefix
    /// [`Value`]: NonMinimalSite::Value
    #[inline]
    #[must_use]
    pub const fn width(self) -> u8 {
        match self.padded {
            PaddedSite::Tag { width } | PaddedSite::LenPrefix { width, .. } => width.as_inner(),
            PaddedSite::Value { width, .. } => width.as_inner(),
        }
    }

    /// The record's field number, where the site carries one —
    /// `Some` exactly off the tag site (a refused head tag has
    /// not yet revealed a lawful field; a refused group end tag's
    /// pairing is the enclosing scan's business).
    #[inline]
    #[must_use]
    pub const fn field(self) -> Option<crate::wire::FieldNumber> {
        match self.padded {
            PaddedSite::Tag { .. } => None,
            PaddedSite::LenPrefix { field, .. } | PaddedSite::Value { field, .. } => Some(field),
        }
    }
}

#[cfg(any(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
impl core::fmt::Display for NonMinimal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.padded {
            PaddedSite::Tag { width } => {
                write!(
                    f,
                    "a tag spans {} bytes; its minimal spelling is narrower",
                    width.as_inner()
                )
            }
            PaddedSite::LenPrefix { field, width } => write!(
                f,
                "the length prefix of field {} spans {} bytes; its minimal spelling is narrower",
                field.as_inner(),
                width.as_inner()
            ),
            PaddedSite::Value { field, width } => write!(
                f,
                "the varint value of field {} spans {} bytes; its minimal spelling is narrower",
                field.as_inner(),
                width.as_inner()
            ),
        }
    }
}

#[cfg(any(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
impl core::error::Error for NonMinimal {}

// The carrier is one tagged byte pair beside the optional field:
// the interior coupling costs no eighth byte over the buffered
// twins' `{at-free} field + width` spelling.
#[cfg(any(
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
const _: () = assert!(core::mem::size_of::<NonMinimal>() == 8);

// The macro takes literals — tied here so they cannot drift from
// their meaning: the coordinate space's top is exactly
// `u64::MAX - 1` (a byte at `u64::MAX` is refusal domain), and
// the two store classes exclude exactly their `u32::MAX`.
const _: () = assert!(SourceAt::MAX.as_inner() == u64::MAX - 1);
const _: () = assert!(SlotAt::new(u32::MAX - 1).is_some() && SlotAt::new(u32::MAX).is_none());
const _: () =
    assert!(AuthoredAt::new(u32::MAX - 1).is_some() && AuthoredAt::new(u32::MAX).is_none());

// The niches pay for themselves: `Option` of each coordinate is
// free, and the fault carrier is one tagged 8-byte payload.
const _: () = assert!(core::mem::size_of::<Option<SourceAt>>() == 8);
const _: () = assert!(core::mem::size_of::<Option<SlotAt>>() == 4);
const _: () = assert!(core::mem::size_of::<Option<AuthoredAt>>() == 4);
const _: () = assert!(core::mem::size_of::<FaultAt>() == 16);

// The carrier's projection contract, compile-proven: each zone
// projects its own coordinates and refuses the other's.
const _: () = {
    // SAFETY: 17 lies within the admitted range.
    let source = FaultAt::source(unsafe { SourceAt::new_unchecked(17) });
    assert!(matches!(source.zone(), FaultZone::Source));
    assert!(matches!(source.source_at(), Some(17)));
    assert!(source.slot().is_none() && source.authored_at().is_none());

    let (Some(slot), Some(at)) = (SlotAt::new(3), AuthoredAt::new(9)) else {
        panic!("both lie within the admitted ranges");
    };
    let authored = FaultAt::authored(slot, at);
    assert!(matches!(authored.zone(), FaultZone::Authored));
    assert!(authored.source_at().is_none());
    assert!(matches!((authored.slot(), authored.authored_at()), (Some(3), Some(9))));
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_chunk_mint_is_the_non_emptiness_judgment() {
        assert!(Chunk::new(&[]).is_none());
        let chunk = Chunk::new(&[7]).unwrap();
        assert_eq!((chunk.len(), chunk.bytes()), (1, &[7u8][..]));
    }

    #[test]
    #[allow(
        clippy::while_let_loop,
        reason = "the loop shape ends the lent view's borrow before the consume — the \
                  trait's own discipline, kept explicit"
    )]
    fn slice_walks_yield_identical_bytes_under_any_consumption() {
        let bytes = [1u8, 2, 3, 4, 5];
        let mut source = SliceSource::new(&bytes);
        // Walk one: byte-at-a-time consumption.
        let mut one = alloc::vec::Vec::new();
        let mut walk = source.begin().unwrap();
        loop {
            // The lent view's borrow ends before the consume — the
            // trait's own discipline.
            let Some(byte) = walk.fill().unwrap().map(|view| view.bytes()[0]) else {
                break;
            };
            one.push(byte);
            walk.consume(1);
        }
        // Walk two: whole-view consumption.
        let mut two = alloc::vec::Vec::new();
        let mut walk = source.begin().unwrap();
        loop {
            let taken = match walk.fill().unwrap() {
                Some(view) => {
                    two.extend_from_slice(view.bytes());
                    view.len()
                }
                None => break,
            };
            walk.consume(taken);
        }
        assert_eq!(one, bytes);
        assert_eq!(two, bytes);
    }

    #[test]
    fn skips_report_the_advanced_count_and_stop_at_the_end() {
        let bytes = [1u8, 2, 3];
        let mut source = SliceSource::new(&bytes);
        let mut walk = source.begin().unwrap();
        assert_eq!(walk.skip(2).unwrap(), 2);
        // The end arrives first: the shorter count reports it.
        assert_eq!(walk.skip(5).unwrap(), 1);
        assert!(walk.fill().unwrap().is_none());
        // The end is stable.
        assert_eq!(walk.skip(1).unwrap(), 0);
    }

    #[test]
    fn discard_skip_is_the_visible_linear_skip() {
        // A rewind-only walk shape: fill/consume only, skip
        // delegating to the helper.
        struct Linear<'a>(SliceWalk<'a>);
        impl ReplayWalk for Linear<'_> {
            type Error = SliceFault;

            fn fill(&mut self) -> Result<Option<Chunk<'_>>, SupplyFault<SliceFault>> {
                self.0.fill()
            }

            fn consume(&mut self, n: usize) {
                self.0.consume(n);
            }

            fn skip(&mut self, n: u64) -> Result<u64, SupplyFault<SliceFault>> {
                discard_skip(self, n)
            }
        }

        let bytes = [1u8, 2, 3, 4];
        let mut source = SliceSource::new(&bytes);
        let mut walk = Linear(source.begin().unwrap());
        assert_eq!(walk.skip(3).unwrap(), 3);
        assert_eq!(walk.fill().unwrap().unwrap().bytes(), [4]);
        walk.consume(1);
        // Past the end: the shorter count, exactly as the direct
        // skip reports it.
        assert_eq!(walk.skip(9).unwrap(), 0);
    }

    #[test]
    fn source_spans_hold_the_ordered_interval_invariant() {
        let span = SourceSpan::new(u64::from(u32::MAX) + 7, u64::from(u32::MAX) + 9);
        assert_eq!(span.len(), 2);
        assert!(!span.is_empty());
        assert!(SourceSpan::new(3, 3).is_empty());
    }

    #[test]
    #[should_panic(expected = "SourceSpan::new: inverted range")]
    fn an_inverted_span_is_judged_at_the_mint() {
        let _ = SourceSpan::new(4, 3);
    }
}
