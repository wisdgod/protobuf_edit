//! The shared fixed-scratch patch layer: the caller-memory lanes,
//! the authored-value stores over them, the command vocabulary,
//! and the coordinate types both dialect machines build on.
//!
//! A fixed patch is the borrowed one-shot patch over caller-supplied
//! working memory: it borrows its source (`&'a [u8]`, zero copy at
//! open), its authored payloads (`&'p [u8]`, zero copy until save),
//! and every byte of its working memory (`&'s mut
//! [MaybeUninit<u8>]`, one slab carved once at the door). It
//! performs no allocator call anywhere: open, commands, and saves
//! run entirely in the slab, the source, and the caller's output
//! buffer or sink.
//!
//! The capacity contract has three faces:
//!
//! - A per-machine `Plan` declares the roles no configuration
//!   implies — row, scalar-word, payload-slot, and resident-fault
//!   counts, staged payload bytes. Capacities the door can derive
//!   (the save walks' body table and container spine ride the row
//!   count and the depth bound) are derived, never declared.
//! - `Plan::bytes` prices the slab exactly, worst-case slab
//!   alignment included: the door carves a slab of `bytes()` at any
//!   address and refuses a shorter one with `SlabShort` before
//!   touching anything else.
//! - `budget()` answers per-role high-water occupancy against
//!   capacity. Sizing is mechanical: prototype with a generous
//!   plan, run the representative job, read `budget()`, ship the
//!   tight plan. High-water is cumulative demand — abandoned staged
//!   frames and refused descents count the bytes and rows they
//!   occupied while live, because the slab had to hold them.
//!
//! Exhaustion is a deterministic refusal, never an abort: every
//! door and command judges its whole demand against capacity before
//! its first state change, so an `Err` leaves the machine's
//! observable state unchanged and still usable (high-water marks
//! may grow — capacity accounting sits outside the fingerprint
//! promise). The refusal names the exhausted lane
//! ([`ScratchRole`]); the repair is a bigger plan. A refusal is
//! permanent for the exhausted capacity: fixed lanes never grow.
//!
//! Within its plan, a fixed patch behaves byte-identically to the
//! heap patch cell (feature `patch-*`): same verdicts, same handle
//! order, same saved bytes, same fault values. The faces that
//! allocate their product there (`save`, `save_canonical`,
//! `save_spans`) do not exist here; `save_into` writes a caller
//! slice and the sink faces hand borrowed slices out, so the output
//! role stays caller memory too.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other.
//!
//! Coordinates: write · buffered · offline · tolerant (type-level) · borrowed · commit-only · fixed scratch.

use core::mem::MaybeUninit;

use crate::admission::usize_of;

#[cfg(feature = "fixed-patch-grouped")]
pub mod grouped;
#[cfg(feature = "fixed-patch-groupless")]
pub mod groupless;

crate::_macro::define_valid_range_type! {
    /// A row-arena coordinate, judgment-free downstream of its mint.
    ///
    /// Every mint is judged against the plan's row capacity, and the
    /// plan judged that capacity into this domain at construction —
    /// so a minted index is always in class. The excluded top value
    /// keeps `Option<RowId>` word-free.
    pub(crate) struct RowId(u32 as u32 in 0..=0x7FFF_FFFE) with new_unchecked;
}

impl RowId {
    /// The arena index this coordinate names.
    #[inline]
    pub(crate) const fn index(self) -> usize {
        usize_of(self.as_inner())
    }
}

/// Admits a source length into the coordinate class
/// ([`crate::admission`]): the length-class judgment this machine
/// folds into its own fault vocabulary.
#[inline]
pub(crate) const fn admit(len: usize) -> Option<u32> {
    if len > crate::admission::MAX {
        return None;
    }
    Some(crate::admission::admitted_u32(len))
}

/// The concatenated length of a scatter payload, for the command
/// gates' judgment. Saturating: the gates refuse anything past the
/// LEN class, so a saturated sum is already over the cap.
pub(crate) fn parts_len_usize(parts: &[&[u8]]) -> usize {
    parts.iter().fold(0usize, |total, part| total.saturating_add(part.len()))
}

// ─── the shared command vocabulary ───

mod command {
    use super::Handle;

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

    /// Where an insertion splices. Anchors name gaps, not
    /// neighboring records: each variant picks exactly one gap of
    /// one sibling chain.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum InsertAt {
        /// First child of the container (`None`: the top layer).
        HeadOf(Option<Handle>),
        /// Last child of the container (`None`: the top layer).
        TailOf(Option<Handle>),
        /// Immediately after this sibling.
        After(Handle),
    }
}

pub use command::{EditStatus, InsertAt};

/// A fixed patch's name for one record row.
///
/// Minted by the machine that owns the row; forging one (an
/// out-of-range coordinate) panics at the arena gate, which is the
/// documented index contract. Handles stay valid for the machine's
/// life — commit-only editing never orphans a row.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(transparent)]
pub struct Handle(pub(crate) RowId);

/// The working-memory lane a capacity refusal names — exactly the
/// roles a plan declares. The repair is a bigger value for that
/// role; per-role occupancy against capacity reads off `budget()`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScratchRole {
    /// The row arena (scanned and authored records).
    Rows,
    /// The authored scalar-word column.
    Words,
    /// The authored payload slot table.
    PayloadSlots,
    /// The staged (copied) payload byte pool.
    StagedBytes,
    /// The resident descend-verdict table.
    Faults,
}

/// One lane's occupancy reading: the high-water demand so far
/// against the planned capacity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gauge {
    /// High-water occupancy: the largest the lane has been, counting
    /// provisional occupancy that a refusal or an abandoned frame
    /// later reclaimed — the demand a sufficient plan must cover.
    pub used: u32,
    /// The planned capacity.
    pub capacity: u32,
}

/// Per-role high-water occupancy of a mixed or copy-only machine —
/// the sizing loop's answer face, mirroring its plan field for
/// field.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Budget {
    /// The row arena.
    pub rows: Gauge,
    /// The authored scalar-word column.
    pub words: Gauge,
    /// The authored payload slot table.
    pub payload_slots: Gauge,
    /// The staged payload byte pool.
    pub staged_bytes: Gauge,
    /// The resident-fault table.
    pub faults: Gauge,
}

/// Per-role high-water occupancy of a borrowed-only machine, whose
/// plan carries no staged byte pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BorrowBudget {
    /// The row arena.
    pub rows: Gauge,
    /// The authored scalar-word column.
    pub words: Gauge,
    /// The authored payload slot table.
    pub payload_slots: Gauge,
    /// The resident-fault table.
    pub faults: Gauge,
}

// ─── the lanes ───

/// One typed working-memory lane carved out of the caller's slab:
/// a capacity-fixed arena of `Copy` elements with an initialized
/// prefix.
///
/// Invariant: slots `[0, len)` are initialized, `[len, capacity)`
/// are uninitialized and writable, and `len <= capacity`. Every
/// stored coordinate a consumer holds is below the `len` current
/// when it was minted; truncation is lawful exactly where the owner
/// proves no held coordinate crosses the mark (the row arena's
/// provisional descend tail, the staged frame's bytes). Elements
/// are `Copy`, so truncation drops nothing.
pub(crate) struct Lane<'s, T: Copy> {
    slots: &'s mut [MaybeUninit<T>],
    len: u32,
    /// High-water `len`, never lowered by truncation.
    peak: u32,
}

impl<'s, T: Copy> Lane<'s, T> {
    /// Wraps a carved extent as an empty lane.
    pub(crate) const fn new(slots: &'s mut [MaybeUninit<T>]) -> Self {
        Self { slots, len: 0, peak: 0 }
    }

    /// Carves this lane off the door's slab: `count` slots split
    /// off the carver's front in ladder order.
    pub(crate) fn carve<const HEAD_ALIGN: usize>(
        carver: &mut crate::fixed::Carver<'s, HEAD_ALIGN>,
        count: u32,
    ) -> Self {
        let count = usize_of(count);
        assert!(count.checked_mul(size_of::<T>()).is_some(), "the plan priced this lane");
        Self::new(carver.split(count))
    }

    /// The planned capacity.
    #[inline]
    pub(crate) const fn capacity(&self) -> u32 {
        // Lossless: the carve sized this extent from a u32 count.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "see above")]
        {
            self.slots.len() as u32
        }
    }

    /// The initialized-prefix length.
    #[inline]
    pub(crate) const fn len(&self) -> u32 {
        self.len
    }

    /// This lane's gauge, for `budget()`.
    #[inline]
    pub(crate) const fn gauge(&self) -> Gauge {
        Gauge { used: self.peak, capacity: self.capacity() }
    }

    /// The next coordinate if capacity holds it — the judgment
    /// every occupancy runs first. Nothing is occupied.
    #[inline]
    pub(crate) const fn mint(&self) -> Option<u32> {
        if self.len < self.capacity() { Some(self.len) } else { None }
    }

    /// Occupies the minted slot. The caller judged capacity through
    /// [`mint`](Self::mint) on this same lane state.
    #[inline]
    pub(crate) const fn push_minted(&mut self, value: T) {
        debug_assert!(self.len < self.capacity(), "push follows a mint judgment");
        self.slots[usize_of(self.len)].write(value);
        self.len += 1;
        if self.len > self.peak {
            self.peak = self.len;
        }
    }

    /// Judges and occupies in one step; `None` when the lane is
    /// full — judged before anything is occupied.
    #[inline]
    pub(crate) fn push(&mut self, value: T) -> Option<u32> {
        let at = self.mint()?;
        self.push_minted(value);
        Some(at)
    }

    /// The initialized prefix as a slice — the read faces' view.
    #[inline]
    pub(crate) const fn inited(&self) -> &[T] {
        // SAFETY: the lane invariant — `[0, len)` is initialized,
        // `len <= capacity` — and `MaybeUninit<T>` has `T`'s layout.
        unsafe { core::slice::from_raw_parts(self.slots.as_ptr().cast::<T>(), usize_of(self.len)) }
    }

    /// An initialized element by minted coordinate, judgment-free.
    ///
    /// The caller's coordinate provenance is the proof: `at` was
    /// minted by a push on this lane and the owner never truncated
    /// across it.
    #[inline]
    pub(crate) const fn get(&self, at: u32) -> &T {
        debug_assert!(at < self.len, "coordinates are minted below len");
        // SAFETY: `at < len` by the caller's mint provenance, and
        // `[0, len)` is initialized.
        unsafe { self.slots.as_ptr().add(usize_of(at)).cast::<T>().as_ref_unchecked() }
    }

    /// Mutable twin of [`get`](Self::get), same contract.
    #[inline]
    pub(crate) const fn get_mut(&mut self, at: u32) -> &mut T {
        debug_assert!(at < self.len, "coordinates are minted below len");
        // SAFETY: as `get` — mint provenance and the initialized
        // prefix.
        unsafe { self.slots.as_mut_ptr().add(usize_of(at)).cast::<T>().as_mut_unchecked() }
    }

    /// Truncates to an earlier mark, reclaiming the tail's
    /// occupancy (high-water keeps it). Sound exactly where the
    /// owner proves no held coordinate crosses the mark; elements
    /// are `Copy`, so nothing owes a drop.
    #[inline]
    pub(crate) const fn truncate(&mut self, mark: u32) {
        debug_assert!(mark <= self.len, "truncation marks are earlier lengths");
        self.len = mark;
    }

    /// Pops the last initialized element — the stack face the save
    /// walks' open-frame slots ride. `None` on an empty lane.
    #[inline]
    pub(crate) const fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: `len` was the initialized-prefix length, so the
        // slot at the decremented index is initialized.
        Some(unsafe { self.slots[usize_of(self.len)].assume_init() })
    }
}

/// The byte-pool lane: [`Lane`]'s shape over raw bytes, with the
/// staged-extent faces the copied payload column needs. The same
/// initialized-prefix invariant, with byte extents in place of
/// typed slots.
pub(crate) struct ByteLane<'s> {
    bytes: &'s mut [MaybeUninit<u8>],
    len: u32,
    /// High-water `len`, never lowered by truncation.
    peak: u32,
}

impl<'s> ByteLane<'s> {
    /// Wraps a carved extent as an empty pool.
    pub(crate) const fn new(bytes: &'s mut [MaybeUninit<u8>]) -> Self {
        Self { bytes, len: 0, peak: 0 }
    }

    /// Carves the byte pool off the door's slab — listed last in
    /// every ladder, so no alignment question exists.
    pub(crate) fn carve<const HEAD_ALIGN: usize>(
        carver: &mut crate::fixed::Carver<'s, HEAD_ALIGN>,
        count: u32,
    ) -> Self {
        Self::new(carver.split(usize_of(count)))
    }

    /// The planned capacity.
    #[inline]
    pub(crate) const fn capacity(&self) -> u32 {
        // Lossless: the carve sized this extent from a u32 count.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "see above")]
        {
            self.bytes.len() as u32
        }
    }

    /// This lane's gauge, for `budget()`.
    #[inline]
    pub(crate) const fn gauge(&self) -> Gauge {
        Gauge { used: self.peak, capacity: self.capacity() }
    }

    /// The pool's tail — a staged frame's start mark and every
    /// extent mint's offset.
    #[inline]
    pub(crate) const fn mark(&self) -> u32 {
        self.len
    }

    /// True when `more` further bytes fit — the judgment every
    /// staging append runs first. Wrap-free: both sides live in
    /// u32-derived domains and compare in u64.
    #[inline]
    pub(crate) const fn fits(&self, more: usize) -> bool {
        // Lossless: usize widens into u64 on the crate's targets.
        #[allow(clippy::as_conversions, reason = "see above")]
        {
            self.len as u64 + more as u64 <= self.capacity() as u64
        }
    }

    /// Appends bytes the caller already judged with
    /// [`fits`](Self::fits) on this same pool state.
    #[inline]
    pub(crate) const fn extend_judged(&mut self, chunk: &[u8]) {
        debug_assert!(self.fits(chunk.len()), "extend follows a fits judgment");
        // SAFETY: `fits` proved `len + chunk.len() <= capacity`, so
        // the copy lands inside the extent past the initialized
        // prefix; `MaybeUninit<u8>` accepts raw byte writes; the
        // regions cannot overlap (the pool is exclusively borrowed
        // machine memory, the chunk a foreign shared borrow).
        unsafe {
            core::ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                self.bytes.as_mut_ptr().cast::<u8>().add(usize_of(self.len)),
                chunk.len(),
            );
        }
        // In class: `fits` bounded the sum by a u32 capacity.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "see above")]
        {
            self.len += chunk.len() as u32;
        }
        if self.len > self.peak {
            self.peak = self.len;
        }
    }

    /// Judges and appends in one step; `None` when the pool cannot
    /// hold the chunk — judged before anything is occupied.
    #[inline]
    pub(crate) const fn extend(&mut self, chunk: &[u8]) -> Option<()> {
        if !self.fits(chunk.len()) {
            return None;
        }
        self.extend_judged(chunk);
        Some(())
    }

    /// Truncates to an earlier mark, reclaiming a staged frame's
    /// bytes (high-water keeps them). Sound because no published
    /// extent crosses the mark — the owner's staged-frame
    /// discipline.
    #[inline]
    pub(crate) const fn truncate(&mut self, mark: u32) {
        debug_assert!(mark <= self.len, "truncation marks are earlier lengths");
        self.len = mark;
    }

    /// An initialized extent, judgment-free.
    ///
    /// The caller's extent provenance is the proof: `start..start +
    /// len` was staged by appends on this pool and never truncated
    /// across.
    #[inline]
    pub(crate) const fn extent(&self, start: u32, len: u32) -> &[u8] {
        debug_assert!(start as u64 + len as u64 <= self.len as u64, "extents are staged in-pool");
        // SAFETY: the extent lies inside the initialized prefix by
        // the caller's provenance, and `MaybeUninit<u8>` has `u8`'s
        // layout.
        unsafe {
            core::slice::from_raw_parts(
                self.bytes.as_ptr().cast::<u8>().add(usize_of(start)),
                usize_of(len),
            )
        }
    }
}

// ─── the carve ladder ───

/// Emits one door's carve ladder from a single ordered lane list:
/// a module-level descending-alignment assert (a plain const item,
/// so check builds evaluate it with the compiling target's
/// alignments — the venue the 32-bit layout gate runs), the
/// ladder's derived head alignment, the door's capacity struct
/// with its exact slab pricing, the door's lanes struct, and an
/// expression macro `name!(slab, caps)` carving the listed lanes
/// off the slab and returning them as the lanes struct, all in
/// exactly the listed order. The assert, the head alignment, the
/// capacities, their pricing, the lanes and the carve share the
/// one list, so the judged order, the priced set, the carved order
/// and the bound names cannot drift apart — a door binds its lanes
/// by field name, so a transposition of same-typed lanes is
/// unspellable. The optional `@bytes` tail carves the unaligned
/// byte pool last; the leading `($)` hands the dollar token to the
/// emitted macro's own matchers.
macro_rules! carve_ladder {
    (
        ($d:tt)
        $(#[$doc:meta])*
        $carve:ident, caps $Caps:ident, lanes $Lanes:ident {
            $($name:ident: $ty:ty,)+
            $(@bytes $bname:ident,)?
        }
    ) => {
        const _: () = assert!(
            $crate::fixed::descending(&[$(align_of::<$ty>()),+]),
            "the carve ladder must descend in alignment"
        );

        /// One door's per-lane capacities, named as the lanes are.
        struct $Caps {
            $($name: u32,)+
            $($bname: u32,)?
        }

        impl $Caps {
            /// The ladder's head alignment: its maximum lane
            /// alignment, derived from the one lane list — the
            /// carve aligns the slab head to exactly this value
            /// and the pricing charges its worst-case pad.
            const HEAD_ALIGN: usize = $crate::fixed::head_align(&[$(align_of::<$ty>()),+]);

            /// The exact slab demand of these capacities: the
            /// head's worst-case padding plus each listed lane's
            /// exact byte size in list order — zero interior
            /// padding by the descending-alignment carve order.
            #[allow(
                clippy::as_conversions,
                reason = "u32 capacities and usize alignments and sizes widen losslessly to u64"
            )]
            const fn priced(&self) -> u64 {
                (Self::HEAD_ALIGN - 1) as u64
                    $(+ self.$name as u64 * size_of::<$ty>() as u64)+
                    $(+ self.$bname as u64)?
            }
        }

        /// One door's carved lanes, named as the ladder lists them.
        /// Each field holds its ladder entry's lane (the carve
        /// pins the element type); the per-field generics keep
        /// every lane's borrows independent, so consuming one lane
        /// never extends another's.
        #[allow(non_camel_case_types, reason = "each lane's parameter is its ladder name")]
        struct $Lanes<$($name,)+ $($bname)?> {
            $($name: $name,)+
            $($bname: $bname,)?
        }

        $(#[$doc])*
        macro_rules! $carve {
            ($d slab:expr, $d caps:expr) => {{
                let mut carver = $crate::fixed::Carver::<{ $Caps::HEAD_ALIGN }>::new($d slab);
                let caps: $Caps = $d caps;
                $Lanes {
                    $($name: $crate::fixed_patch::Lane::<$ty>::carve(&mut carver, caps.$name),)+
                    $($bname: $crate::fixed_patch::ByteLane::carve(&mut carver, caps.$bname),)?
                }
            }};
        }
    };
}
pub(crate) use carve_ladder;

// ─── the coordinate types the stores mint ───

/// A word-column coordinate: minted by [`WordStore::push_word`],
/// read and overwritten judgment-free for the machine's life (the
/// column never shrinks). Full `u32` domain — the machine never
/// stores an `Option` of a value coordinate, so no niche is bought.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub(crate) struct WordAt(u32);

impl WordAt {
    /// Rebuilds the coordinate from a row's value slot, which is
    /// only ever written from [`Self::raw`].
    #[inline]
    pub(crate) const fn of_slot(raw: u32) -> Self {
        Self(raw)
    }

    /// The inner index, for the row's value slot.
    #[inline]
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

/// A payload-slot coordinate: minted by the payload pushes, read
/// and overwritten judgment-free for the machine's life (the slot
/// table never shrinks). Full `u32` domain, as [`WordAt`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub(crate) struct PayloadAt(u32);

impl PayloadAt {
    /// Rebuilds the coordinate from a row's value slot, which is
    /// only ever written from [`Self::raw`].
    #[inline]
    pub(crate) const fn of_slot(raw: u32) -> Self {
        Self(raw)
    }

    /// The inner index, for the row's value slot.
    #[inline]
    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

/// One live payload: the caller's borrowed slice (whole or
/// scattered), held until the save copies it once, or an extent of
/// the staged pool.
#[derive(Clone, Copy)]
pub(crate) enum PayloadSlot<'p> {
    /// The caller's slice, borrowed for `'p`.
    Borrowed(&'p [u8]),
    /// The caller's pieces, borrowed for `'p`: they concatenate at
    /// the save's gather — no contiguous view exists before it.
    BorrowedParts(&'p [&'p [u8]]),
    /// Offset and length into the staged pool.
    Copied { start: u32, len: u32 },
}

/// One live borrowed payload: the caller's slice (whole or
/// scattered), held until the save copies it once — the
/// borrowed-only sibling's slot.
#[derive(Clone, Copy)]
pub(crate) enum BorrowedSlot<'p> {
    /// The caller's slice, borrowed for `'p`.
    Borrowed(&'p [u8]),
    /// The caller's pieces, borrowed for `'p`: they concatenate at
    /// the save's gather — no contiguous view exists before it.
    BorrowedParts(&'p [&'p [u8]]),
}

// ─── the stores ───

/// Authored scalar words, one dense `u64` column for every scalar
/// kind (the row's kind says how the word reads back), over a
/// plan-sized lane.
///
/// Coordinates are minted by [`Self::push_word`] and never
/// invalidated: the column never truncates, so a read is
/// judgment-free for the coordinate's whole life.
pub(crate) struct WordStore<'s> {
    /// Scalar words: varint values, or fixed bits zero-extended.
    words: Lane<'s, u64>,
}

impl<'s> WordStore<'s> {
    /// The store over its carved lane.
    pub(crate) const fn new(words: Lane<'s, u64>) -> Self {
        Self { words }
    }

    /// The column's gauge, for `budget()`.
    #[inline]
    pub(crate) const fn gauge(&self) -> Gauge {
        self.words.gauge()
    }

    /// Registers a scalar word; refuses when the column's capacity
    /// is spent — judged before anything is occupied.
    pub(crate) fn push_word(&mut self, word: u64) -> Result<WordAt, ScratchRole> {
        self.words.push(word).map(WordAt).ok_or(ScratchRole::Words)
    }

    /// Overwrites a minted word in place — the re-set path, which
    /// cannot fail.
    #[inline]
    pub(crate) const fn set_word(&mut self, at: WordAt, word: u64) {
        *self.words.get_mut(at.0) = word;
    }

    /// The scalar word at a minted coordinate.
    #[inline]
    pub(crate) const fn word(&self, at: WordAt) -> u64 {
        *self.words.get(at.0)
    }
}

/// Authored payloads for the mixed machine: one slot per live
/// payload, plus the byte pool backing the `_copy` faces. A
/// borrowed payload occupies its slot only — the caller's bytes are
/// copied once, at save, straight into the output; a copied payload
/// stages its bytes in the pool at the command.
///
/// Coordinates are minted by the pushes and never invalidated: the
/// slot table never truncates, so a read is judgment-free for the
/// coordinate's whole life. Re-sets overwrite the slot in place; a
/// replaced staged extent stays behind inert — the commit-only
/// trade, paid in pool bytes rather than bookkeeping (the plan's
/// staged capacity is cumulative, not live).
///
/// Invariant: every slot's length sits in the length class — the
/// command faces judge `PayloadTooLarge` before any push, and every
/// staging append judges pool capacity first.
pub(crate) struct PayloadStore<'s, 'p> {
    /// Staged `_copy` bytes, end to end.
    copied: ByteLane<'s>,
    /// The live payload per minted coordinate.
    slots: Lane<'s, PayloadSlot<'p>>,
}

impl<'s, 'p> PayloadStore<'s, 'p> {
    /// The store over its carved lanes.
    pub(crate) const fn new(copied: ByteLane<'s>, slots: Lane<'s, PayloadSlot<'p>>) -> Self {
        Self { copied, slots }
    }

    /// The slot table's gauge, for `budget()`.
    #[inline]
    pub(crate) const fn slots_gauge(&self) -> Gauge {
        self.slots.gauge()
    }

    /// The staged pool's gauge, for `budget()`.
    #[inline]
    pub(crate) const fn staged_gauge(&self) -> Gauge {
        self.copied.gauge()
    }

    /// Registers a borrowed payload; refuses when the slot table's
    /// capacity is spent — judged before anything is occupied.
    pub(crate) fn push_borrowed(&mut self, payload: &'p [u8]) -> Result<PayloadAt, ScratchRole> {
        self.slots
            .push(PayloadSlot::Borrowed(payload))
            .map(PayloadAt)
            .ok_or(ScratchRole::PayloadSlots)
    }

    /// Registers a borrowed scatter payload; refuses when the slot
    /// table's capacity is spent — judged before anything is
    /// occupied. The concatenated length was judged against the LEN
    /// class by the command face.
    pub(crate) fn push_parts(&mut self, parts: &'p [&'p [u8]]) -> Result<PayloadAt, ScratchRole> {
        self.slots
            .push(PayloadSlot::BorrowedParts(parts))
            .map(PayloadAt)
            .ok_or(ScratchRole::PayloadSlots)
    }

    /// Stages a copied payload; refuses when the slot table or the
    /// staged pool is spent — both judged before anything is
    /// occupied, slot space first (the mint order).
    pub(crate) fn push_copied(&mut self, payload: &[u8]) -> Result<PayloadAt, ScratchRole> {
        let Some(at) = self.slots.mint() else {
            return Err(ScratchRole::PayloadSlots);
        };
        let slot = self.stage(payload)?;
        self.slots.push_minted(slot);
        Ok(PayloadAt(at))
    }

    /// Overwrites a minted slot with a borrowed payload — the
    /// re-set path, which cannot fail. A replaced staged extent
    /// stays behind inert.
    #[inline]
    pub(crate) const fn set_borrowed(&mut self, at: PayloadAt, payload: &'p [u8]) {
        *self.slots.get_mut(at.0) = PayloadSlot::Borrowed(payload);
    }

    /// Overwrites a minted slot with a borrowed scatter payload —
    /// the re-set path, which cannot fail ([`Self::set_borrowed`]).
    #[inline]
    pub(crate) const fn set_parts(&mut self, at: PayloadAt, parts: &'p [&'p [u8]]) {
        *self.slots.get_mut(at.0) = PayloadSlot::BorrowedParts(parts);
    }

    /// Overwrites a minted slot with a staged copy; refuses when
    /// the staged pool cannot hold the bytes — judged before
    /// anything is occupied.
    pub(crate) fn set_copied(&mut self, at: PayloadAt, payload: &[u8]) -> Result<(), ScratchRole> {
        let slot = self.stage(payload)?;
        *self.slots.get_mut(at.0) = slot;
        Ok(())
    }

    /// Appends the bytes to the staged pool and shapes their slot;
    /// refuses when the pool cannot hold them — judged before
    /// anything is occupied.
    const fn stage(&mut self, payload: &[u8]) -> Result<PayloadSlot<'p>, ScratchRole> {
        let start = self.copied.mark();
        if self.copied.extend(payload).is_none() {
            return Err(ScratchRole::StagedBytes);
        }
        // In class: the pool's capacity bounds the length in u32.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "see above")]
        let len = payload.len() as u32;
        Ok(PayloadSlot::Copied { start, len })
    }

    /// The slot at a minted coordinate.
    #[inline]
    const fn slot(&self, at: PayloadAt) -> PayloadSlot<'p> {
        *self.slots.get(at.0)
    }

    /// The length of the payload at a minted coordinate, in the
    /// length class (the store invariant).
    #[inline]
    pub(crate) fn len(&self, at: PayloadAt) -> u32 {
        match self.slot(at) {
            PayloadSlot::Borrowed(bytes) => crate::admission::admitted_u32(bytes.len()),
            PayloadSlot::BorrowedParts(parts) => {
                // In class by the command face's concatenated-length
                // judgment, restated through the admission witness.
                crate::admission::admitted_u32(parts.iter().map(|part| part.len()).sum())
            }
            PayloadSlot::Copied { len, .. } => len,
        }
    }

    /// The payload at a minted coordinate as one contiguous slice —
    /// `None` for a scatter slot, whose pieces concatenate only at
    /// the save's gather.
    #[inline]
    pub(crate) const fn contiguous(&self, at: PayloadAt) -> Option<&[u8]> {
        match self.slot(at) {
            PayloadSlot::Borrowed(bytes) => Some(bytes),
            PayloadSlot::BorrowedParts(_) => None,
            PayloadSlot::Copied { start, len } => Some(self.copied.extent(start, len)),
        }
    }

    /// Hands the payload's bytes to `piece` in emission order: one
    /// call for a contiguous backing, one per piece for a scatter —
    /// the save's gather point.
    #[inline]
    pub(crate) fn for_each_piece(&self, at: PayloadAt, mut piece: impl FnMut(&[u8])) {
        match self.slot(at) {
            PayloadSlot::Borrowed(bytes) => piece(bytes),
            PayloadSlot::BorrowedParts(parts) => {
                for part in parts {
                    piece(part);
                }
            }
            PayloadSlot::Copied { start, len } => piece(self.copied.extent(start, len)),
        }
    }

    // ── the staged frame (chunks into the staged pool) ──

    /// The staged pool's tail, marking a staged frame's start.
    #[inline]
    pub(crate) const fn stage_mark(&self) -> u32 {
        self.copied.mark()
    }

    /// True when `more` further staged bytes fit — the sized doors'
    /// whole-declaration judgment.
    #[inline]
    pub(crate) const fn stage_fits(&self, more: usize) -> bool {
        self.copied.fits(more)
    }

    /// Appends one staged chunk to the pool; refuses when the pool
    /// cannot hold it — judged before anything is occupied. Nothing
    /// references the staged extent until a finish mints (or
    /// overwrites) its slot, so the frame reclaims it with
    /// [`stage_abandon`](Self::stage_abandon) on every path that
    /// does not publish.
    pub(crate) const fn stage_chunk(&mut self, chunk: &[u8]) -> Result<(), ScratchRole> {
        match self.copied.extend(chunk) {
            Some(()) => Ok(()),
            None => Err(ScratchRole::StagedBytes),
        }
    }

    /// Appends one staged chunk into bytes a sized door judged.
    /// The door judged the whole declaration against the pool's
    /// capacity and the frame's declaration gate bounds every
    /// staged total inside it — so no capacity judgment re-runs
    /// here.
    pub(crate) const fn stage_chunk_judged(&mut self, chunk: &[u8]) {
        self.copied.extend_judged(chunk);
    }

    /// Truncates the pool to a staged frame's entry mark,
    /// reclaiming an abandoned or refused frame's staged bytes —
    /// capacity included (high-water keeps them). Sound because no
    /// slot extent crosses the mark: every extent below it was
    /// staged before the frame opened, the staged extent's own slot
    /// is minted only by the publishing finish, and the frame's
    /// exclusive machine borrow keeps every other staging out.
    pub(crate) const fn stage_abandon(&mut self, mark: u32) {
        self.copied.truncate(mark);
    }

    /// The staged extent's length since `mark`, in the length class
    /// (the frame judges every chunk against it).
    #[inline]
    pub(crate) const fn staged_len(&self, mark: u32) -> u32 {
        self.copied.mark() - mark
    }

    /// Mints a slot over the staged extent; refuses when the slot
    /// table's capacity is spent.
    pub(crate) fn stage_finish_push(&mut self, mark: u32) -> Result<PayloadAt, ScratchRole> {
        let len = self.staged_len(mark);
        self.slots
            .push(PayloadSlot::Copied { start: mark, len })
            .map(PayloadAt)
            .ok_or(ScratchRole::PayloadSlots)
    }

    /// Overwrites a minted slot with the staged extent — the re-set
    /// path, which cannot fail.
    #[inline]
    pub(crate) const fn stage_finish_set(&mut self, at: PayloadAt, mark: u32) {
        let len = self.staged_len(mark);
        *self.slots.get_mut(at.0) = PayloadSlot::Copied { start: mark, len };
    }
}

/// Authored payloads for the borrowed-only sibling: one slot per
/// live payload and nothing else — no staged pool exists, so
/// neither the `_copy` faces nor the staged frames do, and the plan
/// drops the staged-byte role whole.
///
/// Coordinates are minted by the pushes and never invalidated: the
/// slot table never truncates, so a read is judgment-free for the
/// coordinate's whole life. Re-sets overwrite the slot in place.
///
/// Invariant: every slot's length sits in the length class — the
/// command faces judge `PayloadTooLarge` before any push.
pub(crate) struct BorrowedPayloadStore<'s, 'p> {
    /// The live payload per minted coordinate.
    slots: Lane<'s, BorrowedSlot<'p>>,
}

impl<'s, 'p> BorrowedPayloadStore<'s, 'p> {
    /// The store over its carved lane.
    pub(crate) const fn new(slots: Lane<'s, BorrowedSlot<'p>>) -> Self {
        Self { slots }
    }

    /// The slot table's gauge, for `budget()`.
    #[inline]
    pub(crate) const fn slots_gauge(&self) -> Gauge {
        self.slots.gauge()
    }

    /// Registers a borrowed payload; refuses when the slot table's
    /// capacity is spent — judged before anything is occupied.
    pub(crate) fn push_borrowed(&mut self, payload: &'p [u8]) -> Result<PayloadAt, ScratchRole> {
        self.slots
            .push(BorrowedSlot::Borrowed(payload))
            .map(PayloadAt)
            .ok_or(ScratchRole::PayloadSlots)
    }

    /// Registers a borrowed scatter payload; refuses when the slot
    /// table's capacity is spent — judged before anything is
    /// occupied. The concatenated length was judged against the LEN
    /// class by the command face.
    pub(crate) fn push_parts(&mut self, parts: &'p [&'p [u8]]) -> Result<PayloadAt, ScratchRole> {
        self.slots
            .push(BorrowedSlot::BorrowedParts(parts))
            .map(PayloadAt)
            .ok_or(ScratchRole::PayloadSlots)
    }

    /// Overwrites a minted slot with a borrowed payload — the
    /// re-set path, which cannot fail.
    #[inline]
    pub(crate) const fn set_borrowed(&mut self, at: PayloadAt, payload: &'p [u8]) {
        *self.slots.get_mut(at.0) = BorrowedSlot::Borrowed(payload);
    }

    /// Overwrites a minted slot with a borrowed scatter payload —
    /// the re-set path, which cannot fail.
    #[inline]
    pub(crate) const fn set_parts(&mut self, at: PayloadAt, parts: &'p [&'p [u8]]) {
        *self.slots.get_mut(at.0) = BorrowedSlot::BorrowedParts(parts);
    }

    /// The slot at a minted coordinate.
    #[inline]
    const fn slot(&self, at: PayloadAt) -> BorrowedSlot<'p> {
        *self.slots.get(at.0)
    }

    /// The length of the payload at a minted coordinate, in the
    /// length class (the store invariant).
    #[inline]
    pub(crate) fn len(&self, at: PayloadAt) -> u32 {
        match self.slot(at) {
            BorrowedSlot::Borrowed(bytes) => crate::admission::admitted_u32(bytes.len()),
            BorrowedSlot::BorrowedParts(parts) => {
                // In class by the command face's concatenated-length
                // judgment, restated through the admission witness.
                crate::admission::admitted_u32(parts.iter().map(|part| part.len()).sum())
            }
        }
    }

    /// The payload at a minted coordinate as one contiguous slice —
    /// `None` for a scatter slot, whose pieces concatenate only at
    /// the save's gather.
    #[inline]
    pub(crate) const fn contiguous(&self, at: PayloadAt) -> Option<&[u8]> {
        match self.slot(at) {
            BorrowedSlot::Borrowed(bytes) => Some(bytes),
            BorrowedSlot::BorrowedParts(_) => None,
        }
    }

    /// Hands the payload's bytes to `piece` in emission order: one
    /// call for a whole slice, one per piece for a scatter — the
    /// save's gather point.
    #[inline]
    pub(crate) fn for_each_piece(&self, at: PayloadAt, mut piece: impl FnMut(&[u8])) {
        match self.slot(at) {
            BorrowedSlot::Borrowed(bytes) => piece(bytes),
            BorrowedSlot::BorrowedParts(parts) => {
                for part in parts {
                    piece(part);
                }
            }
        }
    }
}

/// Authored payloads for the copy-only sibling: every payload
/// stages its bytes in the pool at the command, so a slot is a bare
/// extent — no borrow variants, no slot tag, and no payload
/// lifetime binds the caller.
///
/// Coordinates are minted by the pushes and never invalidated: the
/// slot table never truncates, so a read is judgment-free for the
/// coordinate's whole life. Re-sets overwrite the slot in place; a
/// replaced staged extent stays behind inert — the commit-only
/// trade, paid in pool bytes rather than bookkeeping.
///
/// Invariant: every slot's length sits in the length class — the
/// command faces judge `PayloadTooLarge` before any push, and every
/// staging append judges pool capacity first.
pub(crate) struct CopiedPayloadStore<'s> {
    /// Staged bytes, end to end.
    copied: ByteLane<'s>,
    /// The live extent (offset, length) per minted coordinate.
    slots: Lane<'s, (u32, u32)>,
}

impl<'s> CopiedPayloadStore<'s> {
    /// The store over its carved lanes.
    pub(crate) const fn new(copied: ByteLane<'s>, slots: Lane<'s, (u32, u32)>) -> Self {
        Self { copied, slots }
    }

    /// The slot table's gauge, for `budget()`.
    #[inline]
    pub(crate) const fn slots_gauge(&self) -> Gauge {
        self.slots.gauge()
    }

    /// The staged pool's gauge, for `budget()`.
    #[inline]
    pub(crate) const fn staged_gauge(&self) -> Gauge {
        self.copied.gauge()
    }

    /// Stages a copied payload; refuses when the slot table or the
    /// staged pool is spent — both judged before anything is
    /// occupied, slot space first (the mint order).
    pub(crate) fn push_copied(&mut self, payload: &[u8]) -> Result<PayloadAt, ScratchRole> {
        let Some(at) = self.slots.mint() else {
            return Err(ScratchRole::PayloadSlots);
        };
        let slot = self.stage(payload)?;
        self.slots.push_minted(slot);
        Ok(PayloadAt(at))
    }

    /// Overwrites a minted slot with a staged copy; refuses when
    /// the staged pool cannot hold the bytes — judged before
    /// anything is occupied.
    pub(crate) fn set_copied(&mut self, at: PayloadAt, payload: &[u8]) -> Result<(), ScratchRole> {
        let slot = self.stage(payload)?;
        *self.slots.get_mut(at.0) = slot;
        Ok(())
    }

    /// Appends the bytes to the staged pool and shapes their slot;
    /// refuses when the pool cannot hold them — judged before
    /// anything is occupied.
    const fn stage(&mut self, payload: &[u8]) -> Result<(u32, u32), ScratchRole> {
        let start = self.copied.mark();
        if self.copied.extend(payload).is_none() {
            return Err(ScratchRole::StagedBytes);
        }
        // In class: the pool's capacity bounds the length in u32.
        #[allow(clippy::as_conversions, clippy::cast_possible_truncation, reason = "see above")]
        let len = payload.len() as u32;
        Ok((start, len))
    }

    /// The extent at a minted coordinate.
    #[inline]
    const fn slot(&self, at: PayloadAt) -> (u32, u32) {
        *self.slots.get(at.0)
    }

    /// The length of the payload at a minted coordinate, in the
    /// length class (the store invariant).
    #[inline]
    pub(crate) const fn len(&self, at: PayloadAt) -> u32 {
        self.slot(at).1
    }

    /// The payload at a minted coordinate as one contiguous slice —
    /// every staged extent is contiguous, so the answer never
    /// refuses; the `Option` is the shared read shape.
    #[inline]
    pub(crate) const fn contiguous(&self, at: PayloadAt) -> Option<&[u8]> {
        let (start, len) = self.slot(at);
        Some(self.copied.extent(start, len))
    }

    /// Hands the payload's bytes to `piece` in emission order: one
    /// call — staged extents are contiguous.
    #[inline]
    pub(crate) fn for_each_piece(&self, at: PayloadAt, mut piece: impl FnMut(&[u8])) {
        let (start, len) = self.slot(at);
        piece(self.copied.extent(start, len));
    }

    // ── the staged frame (chunks into the staged pool) ──

    /// The staged pool's tail, marking a staged frame's start.
    #[inline]
    pub(crate) const fn stage_mark(&self) -> u32 {
        self.copied.mark()
    }

    /// True when `more` further staged bytes fit — the sized doors'
    /// whole-declaration judgment.
    #[inline]
    pub(crate) const fn stage_fits(&self, more: usize) -> bool {
        self.copied.fits(more)
    }

    /// Appends one staged chunk to the pool; refuses when the pool
    /// cannot hold it — judged before anything is occupied. Nothing
    /// references the staged extent until a finish mints (or
    /// overwrites) its slot, so the frame reclaims it with
    /// [`stage_abandon`](Self::stage_abandon) on every path that
    /// does not publish.
    pub(crate) const fn stage_chunk(&mut self, chunk: &[u8]) -> Result<(), ScratchRole> {
        match self.copied.extend(chunk) {
            Some(()) => Ok(()),
            None => Err(ScratchRole::StagedBytes),
        }
    }

    /// Appends one staged chunk into bytes a sized door judged
    /// ([`PayloadStore::stage_chunk_judged`]'s contract).
    pub(crate) const fn stage_chunk_judged(&mut self, chunk: &[u8]) {
        self.copied.extend_judged(chunk);
    }

    /// Truncates the pool to a staged frame's entry mark,
    /// reclaiming an abandoned or refused frame's staged bytes —
    /// capacity included (high-water keeps them). Sound as
    /// [`PayloadStore::stage_abandon`]: no slot extent crosses the
    /// mark.
    pub(crate) const fn stage_abandon(&mut self, mark: u32) {
        self.copied.truncate(mark);
    }

    /// The staged extent's length since `mark`, in the length class
    /// (the frame judges every chunk against it).
    #[inline]
    pub(crate) const fn staged_len(&self, mark: u32) -> u32 {
        self.copied.mark() - mark
    }

    /// Mints a slot over the staged extent; refuses when the slot
    /// table's capacity is spent.
    pub(crate) fn stage_finish_push(&mut self, mark: u32) -> Result<PayloadAt, ScratchRole> {
        let len = self.staged_len(mark);
        self.slots.push((mark, len)).map(PayloadAt).ok_or(ScratchRole::PayloadSlots)
    }

    /// Overwrites a minted slot with the staged extent — the re-set
    /// path, which cannot fail.
    #[inline]
    pub(crate) const fn stage_finish_set(&mut self, at: PayloadAt, mark: u32) {
        let len = self.staged_len(mark);
        *self.slots.get_mut(at.0) = (mark, len);
    }
}

// The slot layouts the plans price: two borrowed pointer variants
// leave no niche for the staged extent's tag, so the mixed slot
// pays one tag word beyond the two-variant layout; the
// borrowed-only slot keeps that shape, and the copy-only slot is a
// bare eight-byte extent. Sizes and alignments are pinned per
// pointer width: the 32-bit layout gate is a check build, and only
// compile-time assertions reach it. The u64 word columns top every
// ladder here, so each door's derived head alignment — and the
// plans' seven-byte pad — is target law.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(size_of::<PayloadSlot<'_>>() == if w64 { 24 } else { 12 });
    assert!(align_of::<PayloadSlot<'_>>() == if w64 { 8 } else { 4 });
    assert!(size_of::<BorrowedSlot<'_>>() == if w64 { 24 } else { 12 });
    assert!(align_of::<BorrowedSlot<'_>>() == if w64 { 8 } else { 4 });
    assert!(size_of::<(u32, u32)>() == 8 && align_of::<(u32, u32)>() == 4);
    assert!(align_of::<u64>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The carve theorem in one walk: a deliberately misaligned
    /// slab head still yields aligned, disjoint, exactly-sized
    /// lanes in descending alignment order.
    #[test]
    fn carve_aligns_and_partitions() {
        let mut slab = [MaybeUninit::<u8>::uninit(); 256];
        let misaligned = &mut slab[1..];
        let mut carver = crate::fixed::Carver::<8>::new(misaligned);
        let words: Lane<'_, u64> = Lane::carve(&mut carver, 3);
        let pairs: Lane<'_, (u32, u32)> = Lane::carve(&mut carver, 5);
        let bytes = ByteLane::carve(&mut carver, 7);
        assert_eq!((words.capacity(), pairs.capacity(), bytes.capacity()), (3, 5, 7));
        assert_eq!(words.slots.as_ptr().addr() % 8, 0);
        assert_eq!(pairs.slots.as_ptr().addr() % 4, 0);
        // Adjacent lanes: no interior padding under descending
        // alignment order.
        assert_eq!(words.slots.as_ptr().addr() + 3 * size_of::<u64>(), pairs.slots.as_ptr().addr(),);
    }

    /// Occupancy judgments and the high-water gauge: pushes judge
    /// capacity, truncation reclaims occupancy but not the peak.
    #[test]
    fn lanes_judge_and_gauge() {
        let mut slab = [MaybeUninit::<u8>::uninit(); 64];
        let mut carver = crate::fixed::Carver::<8>::new(&mut slab[..]);
        let mut lane: Lane<'_, u64> = Lane::carve(&mut carver, 2);
        assert_eq!(lane.push(7), Some(0));
        assert_eq!(lane.push(8), Some(1));
        assert_eq!(lane.push(9), None);
        assert_eq!(lane.inited(), &[7, 8]);
        lane.truncate(1);
        assert_eq!(lane.inited(), &[7]);
        assert_eq!(lane.gauge(), Gauge { used: 2, capacity: 2 });

        let mut pool = ByteLane::carve(&mut carver, 4);
        assert_eq!(pool.extend(b"abc"), Some(()));
        assert_eq!(pool.extend(b"de"), None);
        assert_eq!(pool.extent(0, 3), b"abc");
        pool.truncate(0);
        assert_eq!(pool.extend(b"xyzw"), Some(()));
        assert_eq!(pool.gauge(), Gauge { used: 4, capacity: 4 });
    }

    /// A zero-capacity carve is lawful: every lane is empty, every
    /// push refuses, and no byte of slab is consumed past the pad.
    #[test]
    fn zero_capacity_lanes_hold() {
        let mut slab = [MaybeUninit::<u8>::uninit(); 8];
        let mut carver = crate::fixed::Carver::<8>::new(&mut slab[..]);
        let mut lane: Lane<'_, u64> = Lane::carve(&mut carver, 0);
        let mut pool = ByteLane::carve(&mut carver, 0);
        assert_eq!(lane.push(1), None);
        assert_eq!(pool.extend(b"a"), None);
        assert_eq!(pool.extend(b""), Some(()));
        assert_eq!(lane.gauge(), Gauge { used: 0, capacity: 0 });
    }
}
