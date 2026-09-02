//! Fixed-scratch schema-less inspection, per wire dialect.
//!
//! The cells here run the inspector's job ([`crate::inspect`]) —
//! one eager parse over [`Admitted`](crate::inspect::Admitted)
//! bytes into a preorder row table, every later query a table
//! lookup over borrowed bytes, wire violations product rather than
//! error — with every byte of working memory carved from one
//! caller-supplied slab. No phase of the job allocates: the row
//! arena, the open-container frame stack, and the advisor's path
//! mirror are all carved at the door, so these cells run where no
//! allocator exists at all.
//!
//! Within an adequate plan the product is byte- and value-identical
//! to the heap twin's: same rows, same preorder ids (the twin
//! reuses [`NodeId`](crate::inspect::NodeId) — the two parses are
//! one algorithm over one input, so ids agree handle for handle),
//! same spans, same fault values, same indexed prefix. What moves
//! is the memory plane.
//!
//! Capacities come from two sources, never a third:
//!
//! - **Declared in the plan.** The row arena is the one lane no
//!   configuration bounds — how many records a document holds is a
//!   fact about the caller's documents. The per-dialect `Plan`
//!   carries exactly that one count, judged into the row-id domain
//!   at construction. The demand is the parse's **peak** occupancy:
//!   rows a later unwind evaporates still occupied the arena while
//!   the speculation ran, so a plan sized to the final row count
//!   may refuse where `budget()`'s high-water succeeds.
//! - **Derived from configuration.** The frame stack and the path
//!   mirror are bounded by `min(rows, limit)`: every open container
//!   owns a distinct live row (its row is pushed before its frame
//!   opens, and an unwind truncates frames to the absorber whose
//!   row survives), and the caller's
//!   [`DepthLimit`](crate::DepthLimit) gates every open — so the
//!   door derives both stacks and the caller never restates them.
//!
//! `Plan::bytes` prices the slab exactly, worst-case head padding
//! included, one figure across 32- and 64-bit targets (every lane
//! element is pointer-free). The door refuses a shorter slab with
//! [`OpenFault::SlabShort`] as a pure length compare before
//! anything is read.
//!
//! Exhaustion is a deterministic refusal, never a wrong answer: a
//! row push can fail *inside a speculation*, and absorbing it there
//! would make the message-versus-bytes verdict depend on the plan
//! size — a lying product. So every row-lane refusal aborts the
//! parse as [`OpenFault::RowsExhausted`]: no product is published,
//! every lane borrow is dropped, the slab is reusable with contents
//! unspecified, and advisor effects stand (the host promises no
//! call count or order). Both refusals are
//! [`FaultClass::Policy`](crate::FaultClass): lawful input refused
//! under a declared capacity, accepted under a larger one — the
//! repair is a bigger plan. The sizing loop is mechanical:
//! prototype with a generous plan, parse, read
//! `budget().rows.used`, ship the tight plan.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other. The caller-facing input vocabulary —
//! `Admitted`, `Advisor`, `Advice`, `Ancestry`, `NoAdvice`, and the
//! ids — is the host's own, reused from [`crate::inspect`].
//!
//! Coordinates: read · buffered · offline · Standard (value-level) · borrowed · fixed scratch.
//!
//! # Choosing a face
//!
//! Per dialect: `Plan::new` declares the row capacity,
//! `Plan::bytes` prices the slab, `Tree::parse` runs one parse
//! under tolerant acceptance, `Tree::parse_standard` under a
//! declared [`crate::Standard`], and `Tree::budget` reports
//! per-lane high-water for sizing. The heap twin lives in
//! [`crate::inspect`] — same job, same queries, working memory on
//! the global allocator.
//!
//! # Examples
//!
//! One plan, one stack slab, the host's whole query surface:
//!
//! ```
//! # #[cfg(feature = "fixed-inspect-groupless")] {
//! use core::mem::MaybeUninit;
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::fixed_inspect::groupless::{Plan, Tree};
//! use protobuf_edit::inspect::{Admitted, NoAdvice};
//!
//! // varint f1=150 · LEN f2 "hi"
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let input = Admitted::new(&msg).unwrap();
//! let plan = Plan::new(4).unwrap();
//! let mut slab = [MaybeUninit::<u8>::uninit(); 256];
//! assert!(plan.bytes(DepthLimit::REFERENCE) <= slab.len() as u64);
//!
//! let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice, &plan, &mut slab).unwrap();
//! assert!(tree.is_complete());
//! let hits: Vec<_> = tree.top().collect();
//! assert_eq!(tree.varint_word(hits[0]), Some(150));
//! assert_eq!(tree.payload_bytes(hits[1]), [0x68, 0x69]);
//!
//! // The sizing loop: high-water tightens the plan ("hi" itself
//! // parses, so the speculation kept its row — three in all).
//! assert_eq!(tree.budget().rows.used, 3);
//! # }
//! ```

use core::mem::MaybeUninit;

use crate::admission::usize_of;

#[cfg(feature = "fixed-inspect-grouped")]
pub mod grouped;
#[cfg(feature = "fixed-inspect-groupless")]
pub mod groupless;

crate::_macro::define_valid_range_type! {
    /// A frame-stack coordinate: the innermost absorbing frame's
    /// index, stored in the machine's absorber register and each
    /// frame's save slot. The stack is bounded by
    /// [`DepthLimit`](crate::DepthLimit) (≤ 10,000), so the u16
    /// domain holds every index and the excluded top keeps
    /// `Option<FrameAt>` at two bytes.
    pub(crate) struct FrameAt(u16 as u16 in 0..=0xFFFE) with new_unchecked;
}

impl FrameAt {
    /// Mints a frame-stack index.
    #[inline]
    pub(crate) const fn of(index: usize) -> Self {
        debug_assert!(index <= 0xFFFE);
        #[allow(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "stack indices sit below DepthLimit's 10,000 cap — inside the u16 class"
        )]
        // SAFETY: every push is gated by the caller's DepthLimit
        // (≤ 10,000), so stack indices sit deep inside the class.
        unsafe {
            Self::new_unchecked(index as u16)
        }
    }

    /// The stack index this coordinate names.
    #[inline]
    pub(crate) const fn index(self) -> usize {
        #[allow(clippy::as_conversions, reason = "u16 widens losslessly into usize")]
        {
            self.as_inner() as usize
        }
    }
}

/// A door refusal: the plan (or the slab priced for it) does not
/// cover this parse.
///
/// Both variants are policy-class refusals —
/// lawful input refused under a declared capacity and accepted
/// under a larger one — and both are deterministic in
/// (plan, configuration, input); the repair is declaring more.
/// Wire violations never surface here: they stay in the product as
/// its fault, exactly as in the heap twin.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenFault {
    /// The slab is shorter than the plan's priced demand — judged
    /// as a pure length compare before anything is read, so the
    /// refusal is deterministic for every slab address and leaves
    /// the slab untouched.
    SlabShort {
        /// The plan's demand, `Plan::bytes`' answer.
        need: u64,
        /// The bytes supplied.
        have: u64,
    },
    /// The parse needed more rows than the plan declared — the row
    /// arena is the plan's one declared lane, so the refusal names
    /// it by the variant. No product is published, every lane
    /// borrow is dropped, and the slab is reusable with contents
    /// unspecified; advisor effects stand (the host promises no
    /// call count or order). The demand covers the speculation
    /// peak: rows a later unwind evaporates occupied the arena
    /// while live, so the repair is a `rows` at least the
    /// high-water a generous plan's `budget()` reads.
    RowsExhausted,
}

impl core::fmt::Display for OpenFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::SlabShort { need, have } => {
                write!(f, "slab of {have} bytes falls short of the plan's {need}")
            }
            Self::RowsExhausted => f.write_str("the plan's row capacity is spent"),
        }
    }
}

impl core::error::Error for OpenFault {}

/// One lane's occupancy reading: the high-water demand so far
/// against the planned or derived capacity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Gauge {
    /// High-water occupancy: the largest the lane has been,
    /// counting speculative occupancy that a later unwind
    /// reclaimed — the demand a sufficient plan must cover.
    pub used: u32,
    /// The planned (rows) or derived (frames, path) capacity.
    pub capacity: u32,
}

/// Per-lane high-water occupancy of one parse — the sizing loop's
/// answer face, riding the product.
///
/// Only `rows` is plan-declared; the derived lanes report their
/// high-water as information (`used <= capacity` always — the
/// door's derivation is a sufficiency bound, so a derived lane
/// never refuses).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Budget {
    /// The row arena — what a tight plan must cover (peak demand).
    pub rows: Gauge,
    /// The open-container frame stack, derived: how deep the
    /// document actually ran.
    pub frames: Gauge,
    /// The advisor's path mirror, derived.
    pub path: Gauge,
}

// ─── the lanes ───

/// The row arena's lane: a capacity-fixed store of `Copy` elements
/// with an initialized prefix and a high-water mark.
///
/// Invariant: slots `[0, len)` are initialized, `[len, capacity)`
/// are uninitialized and writable, and `len <= capacity`. Every
/// stored coordinate a consumer holds is below the `len` current
/// when it was minted; truncation is lawful exactly where the
/// owner proves no held coordinate crosses the mark (the dispose
/// order discharges it: the doomed frames leave the machine before
/// the row mark moves). Elements are `Copy`, so truncation drops
/// nothing.
pub(crate) struct StoreLane<'s, T: Copy> {
    slots: &'s mut [MaybeUninit<T>],
    len: u32,
    /// High-water `len`, never lowered by truncation.
    peak: u32,
}

impl<'s, T: Copy> StoreLane<'s, T> {
    /// Carves this lane off the door's slab: `count` slots split
    /// off the carver's front in ladder order.
    pub(crate) fn carve<const HEAD_ALIGN: usize>(
        carver: &mut crate::fixed::Carver<'s, HEAD_ALIGN>,
        count: u32,
    ) -> Self {
        let count = usize_of(count);
        assert!(count.checked_mul(size_of::<T>()).is_some(), "the plan priced this lane");
        Self { slots: carver.split(count), len: 0, peak: 0 }
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

    /// Judges and occupies in one step; `None` when the lane is
    /// full — judged before anything is occupied.
    #[inline]
    pub(crate) const fn push(&mut self, value: T) -> Option<u32> {
        if self.len >= self.capacity() {
            return None;
        }
        let at = self.len;
        self.slots[usize_of(at)].write(value);
        self.len += 1;
        if self.len > self.peak {
            self.peak = self.len;
        }
        Some(at)
    }

    /// The initialized prefix as a slice — the read faces' view.
    #[inline]
    pub(crate) const fn inited(&self) -> &[T] {
        // SAFETY: the lane invariant — `[0, len)` is initialized,
        // `len <= capacity` — and `MaybeUninit<T>` has `T`'s layout.
        unsafe { core::slice::from_raw_parts(self.slots.as_ptr().cast::<T>(), usize_of(self.len)) }
    }

    /// A mutable initialized element by minted coordinate,
    /// judgment-free.
    ///
    /// The caller's coordinate provenance is the proof: `at` was
    /// minted by a push on this lane and the owner never truncated
    /// across it.
    #[inline]
    pub(crate) const fn get_mut(&mut self, at: u32) -> &mut T {
        debug_assert!(at < self.len, "coordinates are minted below len");
        // SAFETY: `at < len` by the caller's mint provenance, and
        // `[0, len)` is initialized.
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
}

/// A derived stack's lane: a fixed-capacity stack over
/// `MaybeUninit` slots whose capacity is a proven bound, so pushes
/// are unjudged under the door's derivation.
///
/// The invariant every face preserves: slots `[0, len)` are
/// initialized, slots `[len, capacity)` are uninitialized and
/// writable, and the lane never reallocates. Element types carry
/// no drop glue (asserted at the carve), so truncation is a length
/// store.
pub(crate) struct WalkLane<'s, T> {
    slots: &'s mut [MaybeUninit<T>],
    len: usize,
}

impl<'s, T> WalkLane<'s, T> {
    /// Carves this lane off the door's slab: `count` slots split
    /// off the carver's front in ladder order.
    ///
    /// The element law is `!needs_drop` (const-asserted here): a
    /// popped slot's `assume_init_read` is a plain move, and
    /// truncation is a length store, exactly because no element
    /// owes a drop.
    pub(crate) fn carve<const HEAD_ALIGN: usize>(
        carver: &mut crate::fixed::Carver<'s, HEAD_ALIGN>,
        count: u32,
    ) -> Self {
        const {
            assert!(!core::mem::needs_drop::<T>(), "lane elements carry no drop glue");
        }
        Self { slots: carver.split(usize_of(count)), len: 0 }
    }

    /// Entries currently held.
    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// The carved capacity.
    #[inline]
    pub(crate) const fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Unjudged push: the lane's capacity is a proven bound.
    ///
    /// # Safety
    ///
    /// `len < capacity` must hold — the caller cites the demand
    /// derivation that sizes the lane for every push it can make.
    #[inline]
    pub(crate) unsafe fn push_unchecked(&mut self, value: T) {
        debug_assert!(self.len < self.slots.len(), "a derived lane bound was undersized");
        // SAFETY: `len < capacity` by the caller's cited bound.
        unsafe { self.slots.get_unchecked_mut(self.len) }.write(value);
        self.len += 1;
    }

    /// The initialized prefix.
    #[inline]
    pub(crate) const fn as_slice(&self) -> &[T] {
        // SAFETY: the lane invariant — `[0, len)` is initialized.
        unsafe { core::slice::from_raw_parts(self.slots.as_ptr().cast::<T>(), self.len) }
    }

    /// The last entry, `None` when empty (the parent-row peek).
    #[inline]
    pub(crate) fn last(&self) -> Option<&T> {
        if self.len == 0 {
            return None;
        }
        // SAFETY: `len - 1` is inside the initialized prefix.
        Some(unsafe { self.slots.get_unchecked(self.len - 1).assume_init_ref() })
    }

    /// Pops the last entry, `None` when empty.
    #[inline]
    pub(crate) fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        // SAFETY: the popped slot was inside the initialized
        // prefix; decrementing `len` first returns it to the
        // uninitialized region, and no-drop elements make the
        // bitwise read a move.
        Some(unsafe { self.slots.get_unchecked(self.len).assume_init_read() })
    }

    /// Drops the tail: `new_len` entries stay initialized. No-drop
    /// element types make this a length store.
    #[inline]
    pub(crate) fn truncate(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.len, "truncation grows nothing");
        self.len = new_len;
    }
}

// ─── the carve ladder ───

/// The ladder's flavor dispatch: binds each lane entry's keyword to
/// its lane constructor, so the emitted carve macro spells the
/// wrapper choice from the one lane list.
macro_rules! lane_of {
    (store $ty:ty, $carver:expr, $cap:expr) => {
        $crate::fixed_inspect::StoreLane::<$ty>::carve($carver, $cap)
    };
    (walk $ty:ty, $carver:expr, $cap:expr) => {
        $crate::fixed_inspect::WalkLane::<$ty>::carve($carver, $cap)
    };
}
pub(crate) use lane_of;

/// Emits one door's carve ladder from a single ordered lane list:
/// a module-level descending-alignment assert (a plain const item,
/// so check builds evaluate it with the compiling target's
/// alignments — the venue the 32-bit layout gate runs), the
/// ladder's derived head alignment, the door's capacity struct
/// with its exact slab pricing, the door's lanes struct, and an
/// expression macro `name!(slab, &caps)` carving the listed lanes
/// off the slab and returning them as the lanes struct, all in
/// exactly the listed order. The assert, the head alignment, the
/// capacities, their pricing, the lanes and the carve share the
/// one list, so the judged order, the priced set, the carved order
/// and the bound names cannot drift apart — a door binds its lanes
/// by field name, so a transposition of same-typed lanes is
/// unspellable. Each entry's flavor keyword (`store`/`walk`) picks
/// the lane wrapper; the leading `($)` hands the dollar token to
/// the emitted macro's own matchers.
macro_rules! carve_ladder {
    (
        ($d:tt)
        $(#[$doc:meta])*
        $carve:ident, caps $Caps:ident, lanes $Lanes:ident {
            $($flavor:ident $name:ident: $ty:ty,)+
        }
    ) => {
        const _: () = assert!(
            $crate::fixed::descending(&[$(align_of::<$ty>()),+]),
            "the carve ladder must descend in alignment"
        );

        /// One door's per-lane capacities, named as the lanes are.
        struct $Caps {
            $($name: u32,)+
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
            }
        }

        /// One door's carved lanes, named as the ladder lists them.
        /// Each field holds its ladder entry's lane (the carve
        /// pins the element type); the per-field generics keep
        /// every lane's borrows independent, so consuming one lane
        /// never extends another's.
        #[allow(non_camel_case_types, reason = "each lane's parameter is its ladder name")]
        struct $Lanes<$($name),+> {
            $($name: $name,)+
        }

        $(#[$doc])*
        macro_rules! $carve {
            ($d slab:expr, $d caps:expr) => {{
                let mut carver = $crate::fixed::Carver::<{ $Caps::HEAD_ALIGN }>::new($d slab);
                let caps: &$Caps = $d caps;
                $Lanes {
                    $($name: $crate::fixed_inspect::lane_of!($flavor $ty, &mut carver, caps.$name),)+
                }
            }};
        }
    };
}
pub(crate) use carve_ladder;

#[cfg(test)]
mod tests {
    use super::*;

    /// The two lane flavors uphold their invariants over one
    /// carved slab: judged store pushes with a high-water gauge,
    /// unjudged walk pushes with stack faces, truncation a length
    /// store on both.
    #[test]
    fn lanes_uphold_their_invariants_over_one_slab() {
        let mut slab = [MaybeUninit::<u8>::uninit(); 128];
        let mut carver = crate::fixed::Carver::<4>::new(&mut slab[..]);
        let mut rows: StoreLane<'_, u32> = StoreLane::carve(&mut carver, 2);
        let mut stack: WalkLane<'_, u16> = WalkLane::carve(&mut carver, 3);

        assert_eq!(rows.push(7), Some(0));
        assert_eq!(rows.push(8), Some(1));
        assert_eq!(rows.push(9), None);
        assert_eq!(rows.inited(), &[7, 8]);
        *rows.get_mut(0) = 5;
        rows.truncate(1);
        assert_eq!(rows.inited(), &[5]);
        assert_eq!(rows.gauge(), Gauge { used: 2, capacity: 2 });

        // SAFETY: three pushes against a carved capacity of three.
        unsafe {
            stack.push_unchecked(1);
            stack.push_unchecked(2);
            stack.push_unchecked(3);
        }
        assert_eq!(stack.as_slice(), &[1, 2, 3]);
        assert_eq!(stack.last(), Some(&3));
        assert_eq!(stack.pop(), Some(3));
        stack.truncate(1);
        assert_eq!((stack.len(), stack.capacity()), (1, 3));
    }

    /// A zero-capacity carve is lawful: the store lane refuses
    /// every push and no byte of slab is consumed past the pad.
    #[test]
    fn zero_capacity_lanes_hold() {
        let mut slab = [MaybeUninit::<u8>::uninit(); 4];
        let mut carver = crate::fixed::Carver::<4>::new(&mut slab[..]);
        let mut rows: StoreLane<'_, u32> = StoreLane::carve(&mut carver, 0);
        let stack: WalkLane<'_, u16> = WalkLane::carve(&mut carver, 0);
        assert_eq!(rows.push(1), None);
        assert_eq!(rows.gauge(), Gauge { used: 0, capacity: 0 });
        assert_eq!(stack.capacity(), 0);
    }
}
