//! Fixed-scratch in-place editing, per wire dialect.
//!
//! The cells here run the in-place editor's rule jobs
//! ([`crate::inplace`]) with every byte of working memory carved
//! from one caller-supplied slab — zero allocator traffic end to
//! end.
//!
//! The job is the host cell's own: a compiled [`RuleSet`] (this
//! family reuses the in-place authoring layer —
//! [`crate::inplace::Rule`], [`Action`], [`RuleSet`] — verbatim),
//! one judge walk over the
//! caller's `&mut` buffer, equal-width writes landed past the
//! fault barrier, and `Err` with the buffer byte-identical to
//! entry. Within an adequate plan the outcome is byte-identical to
//! the host twin's: same verdicts, same stats, same written bytes.
//! What moves is the memory plane. The host walk grows its matcher
//! tables, layer stack, and write list on the global allocator;
//! here the door carves all of them out of one
//! `&mut [MaybeUninit<u8>]` slab, and no phase of the job
//! allocates — the working set is fixed at the door, so these
//! cells run where no allocator exists at all.
//!
//! Capacities come from two sources, never a third:
//!
//! - **Derived from configuration.** The matcher tables, the layer
//!   stack, and (grouped) the open-group and pending-pair lanes
//!   are bounded by the rule set's own shape and the caller's
//!   [`DepthLimit`]; the door derives those bounds itself, and the
//!   caller never restates them. Each dialect's `Plan::bytes`
//!   answers the whole slab demand — exact, and independent of the
//!   slab's address (worst-case alignment padding is priced in),
//!   so the door's judgment is a pure function of plan and
//!   configuration.
//! - **Declared in the plan.** The write list is the one lane no
//!   configuration bounds — it holds one entry per matched record
//!   (a grouped pair renumber holds two), and how many records a
//!   job's rules match is a fact about the caller's documents. The
//!   per-dialect `Plan` carries exactly that one count.
//!
//! Exhaustion is a deterministic, transactional refusal, never an
//! abort: a slab shorter than the derived demand refuses at the
//! door before anything is read, and a write list outgrowing the
//! plan refuses at the judged site during the walk — in both cases
//! before the fault barrier, so the buffer is byte-identical to
//! entry, and re-running with a larger plan (or slab) accepts the
//! same job. The sizing loop is a face, not folklore: each
//! dialect's `apply_budget` reports per-lane high-water occupancy
//! against capacity, so a caller prototypes with a generous plan,
//! reads the budget, and ships the tight one.
//!
//! The slab's contents are contractually garbage outside the job:
//! the machine writes before it reads, and a refusal may leave
//! partial writes behind. Nothing is retained between calls — the
//! scratch tenure is one `apply`, which is why the faces take the
//! slab per call and no machine type exists here.
//!
//! Coordinates: write · buffered · static · Standard (value-level) · in-place · commit-only · fixed scratch.
//!
//! # Choosing a face
//!
//! Per dialect: `Plan::new` declares the write capacity,
//! `Plan::bytes` prices the slab, `apply` runs one job under
//! tolerant acceptance, `apply_standard` under a declared
//! [`crate::Standard`], and `apply_budget` additionally reports
//! the per-lane budget for sizing. The heap twin lives in
//! [`crate::inplace`] — same jobs, same faults, working memory on
//! the global allocator.
//!
//! # Examples
//!
//! One compiled set, one plan, one slab — the reusable trio of a
//! fleet job (the working memory never grows, so one sized slab
//! serves every buffer):
//!
//! ```
//! # #[cfg(feature = "fixed-inplace-groupless")] {
//! use core::mem::MaybeUninit;
//! use protobuf_edit::fixed_inplace::groupless::{Plan, apply};
//! use protobuf_edit::inplace::{Action, Rule, RuleSet};
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let rules = [Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(0) }];
//! let set = RuleSet::over(&rules).unwrap();
//! let plan = Plan::new(1).unwrap();
//! let mut slab = [MaybeUninit::<u8>::uninit(); 256];
//! assert!(plan.bytes(&set, DepthLimit::REFERENCE) <= slab.len());
//!
//! let mut fleet = [[0x08, 0x05], [0x08, 0x7F]];
//! for buf in &mut fleet {
//!     apply(buf, &set, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
//! }
//! assert_eq!(fleet, [[0x08, 0x00], [0x08, 0x00]]);
//! # }
//! ```

use core::mem::MaybeUninit;

use crate::DepthLimit;
use crate::inplace::{Action, RuleSet};
use crate::path::Segment;
use crate::wire::FieldNumber;

/// The job receipt: what each action class landed — the host
/// cell's receipt vocabulary, shared by both fixed dialects.
///
/// The exposure face for silently-inapplicable rules (a pattern
/// that never matched, an interior rule under a wholly overwritten
/// record) — zero counts are the operator's signal.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stats {
    pub(crate) replaced: u32,
    pub(crate) renumbered: u32,
    pub(crate) tombstoned: u32,
    pub(crate) substituted: u32,
}

impl Stats {
    /// Values replaced in place ([`Action::SetVarint`],
    /// [`Action::SetI32`], [`Action::SetI64`],
    /// [`Action::SetPayload`] landings).
    #[inline]
    #[must_use]
    pub const fn replaced(self) -> u32 {
        self.replaced
    }

    /// Records renumbered (a grouped pair counts once).
    #[inline]
    #[must_use]
    pub const fn renumbered(self) -> u32 {
        self.renumbered
    }

    /// Records tombstoned (a whole group counts once).
    #[inline]
    #[must_use]
    pub const fn tombstoned(self) -> u32 {
        self.tombstoned
    }

    /// Whole records substituted ([`Action::ReplaceRecord`]
    /// landings).
    #[inline]
    #[must_use]
    pub const fn substituted(self) -> u32 {
        self.substituted
    }
}

/// One lane's budget row: high-water occupancy against carved
/// capacity, in entries.
///
/// Derived lanes never reach `used > capacity` (the door's
/// derivation is a sufficiency bound); the plan-declared write
/// lane refuses at the boundary instead.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Gauge {
    /// The lane's high-water entry count across the job.
    pub used: usize,
    /// The lane's carved capacity in entries.
    pub capacity: usize,
}

impl Gauge {
    /// Folds one occupancy observation into the high-water mark.
    #[inline]
    pub(crate) const fn observe(&mut self, len: usize) {
        if len > self.used {
            self.used = len;
        }
    }
}

// ─── the slab lanes, pricing, and the carve ladder ───

/// A typed lane carved from the slab: a fixed-capacity stack over
/// `MaybeUninit` slots.
///
/// The arena invariant every face preserves: slots `[0, len)` are
/// initialized, slots `[len, capacity)` are uninitialized and
/// writable, every delivered index is below `len`, and the lane
/// never reallocates. Element types carry no drop glue (asserted
/// at the carve), so truncation is a length store.
pub(crate) struct Lane<'s, T> {
    slots: &'s mut [MaybeUninit<T>],
    len: usize,
}

impl<'s, T> Lane<'s, T> {
    /// Carves this lane off the door's slab: `cap` slots split off
    /// the carver's front in ladder order.
    ///
    /// The element law is `!needs_drop` (const-asserted here): a
    /// popped slot's `assume_init_read` is a plain move, and
    /// truncation and clearing are length stores, exactly because
    /// no element owes a drop.
    pub(crate) fn carve<const HEAD_ALIGN: usize>(
        carver: &mut crate::fixed::Carver<'s, HEAD_ALIGN>,
        cap: usize,
    ) -> Self {
        const {
            assert!(!core::mem::needs_drop::<T>(), "lane elements carry no drop glue");
        }
        Self { slots: carver.split(cap), len: 0 }
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

    /// Judged push: `false` when the lane is full, with the lane
    /// unchanged — the write-list refusal edge.
    #[inline]
    #[must_use]
    pub(crate) fn push(&mut self, value: T) -> bool {
        if self.len == self.slots.len() {
            return false;
        }
        self.slots[self.len].write(value);
        self.len += 1;
        true
    }

    /// Unjudged push for lanes whose capacity is a proven bound.
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
        // SAFETY: the arena invariant — `[0, len)` is initialized.
        unsafe { core::slice::from_raw_parts(self.slots.as_ptr().cast::<T>(), self.len) }
    }

    /// The initialized prefix, mutable (the staged sort's face).
    #[inline]
    pub(crate) const fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: the arena invariant — `[0, len)` is initialized,
        // and the exclusive borrow rides through.
        unsafe { core::slice::from_raw_parts_mut(self.slots.as_mut_ptr().cast::<T>(), self.len) }
    }

    /// Drops the tail: `new_len` entries stay initialized. No-drop
    /// element types make this a length store.
    #[inline]
    pub(crate) fn truncate(&mut self, new_len: usize) {
        debug_assert!(new_len <= self.len, "truncation grows nothing");
        self.len = new_len;
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

    /// The last entry, `None` when empty (the grouped walk's
    /// pending-pair peek).
    #[cfg(any(test, feature = "fixed-inplace-grouped"))]
    #[inline]
    pub(crate) fn last(&self) -> Option<&T> {
        if self.len == 0 {
            return None;
        }
        // SAFETY: `len - 1` is inside the initialized prefix.
        Some(unsafe { self.slots.get_unchecked(self.len - 1).assume_init_ref() })
    }

    /// The last entry, mutable, without the emptiness judgment.
    ///
    /// # Safety
    ///
    /// The lane must be non-empty — the walks' root-layer
    /// invariant (the root is pushed at entry and the only pop
    /// sits behind the walk's own return).
    #[inline]
    pub(crate) unsafe fn last_mut_unchecked(&mut self) -> &mut T {
        debug_assert!(self.len > 0, "the root-layer invariant broke");
        // SAFETY: non-empty by the caller's invariant; `len - 1`
        // is inside the initialized prefix.
        unsafe { self.slots.get_unchecked_mut(self.len - 1).assume_init_mut() }
    }

    /// Empties the lane (a per-probe transient's reset).
    #[inline]
    pub(crate) const fn clear(&mut self) {
        self.len = 0;
    }

    /// A fresh empty lane over the uninitialized tail — the
    /// grouped replacement probe's pairing stack, provably inside
    /// the free region (the walk's layer invariant leaves at least
    /// the probe's own budget free).
    #[cfg(feature = "fixed-inplace-grouped")]
    #[inline]
    pub(crate) const fn tail(&mut self) -> Lane<'_, T> {
        let (_, free) = self.slots.split_at_mut(self.len);
        Lane { slots: free, len: 0 }
    }
}

/// The slab price accumulator: the carve's arithmetic twin.
///
/// The price is head padding (worst case over every slab address:
/// the carve aligns the head once to the ladder's own maximum lane
/// alignment) plus each lane's exact byte size, accumulated in the
/// carve's own order — so a slab of exactly this many bytes always
/// carves, one byte fewer always refuses, at any address.
/// Saturating: a demand no real slab can satisfy (pathological
/// rule sets under the depth cap) prices as `usize::MAX` and
/// refuses deterministically at the door.
#[derive(Clone, Copy)]
pub(crate) struct Demand {
    total: usize,
}

impl Demand {
    /// Prices the head padding of a ladder whose head aligns at
    /// `head_align`.
    pub(crate) const fn new(head_align: usize) -> Self {
        Self { total: head_align - 1 }
    }

    /// Prices one lane of `cap` slots of `T`.
    pub(crate) const fn lane<T>(&mut self, cap: usize) {
        self.total = self.total.saturating_add(cap.saturating_mul(size_of::<T>()));
    }

    /// The whole slab demand in bytes.
    pub(crate) const fn bytes(self) -> usize {
        self.total
    }
}

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
/// unspellable. The leading `($)` hands the dollar token to the
/// emitted macro's own matchers.
macro_rules! carve_ladder {
    (
        ($d:tt)
        $(#[$doc:meta])*
        $carve:ident, caps $Caps:ident, lanes $Lanes:ident {
            $($name:ident: $ty:ty,)+
        }
    ) => {
        const _: () = assert!(
            $crate::fixed::descending(&[$(align_of::<$ty>()),+]),
            "the carve ladder must descend in alignment"
        );

        /// One door's per-lane capacities, named as the lanes are.
        struct $Caps {
            $($name: usize,)+
        }

        impl $Caps {
            /// The ladder's head alignment: its maximum lane
            /// alignment, derived from the one lane list — the
            /// carve aligns the slab head to exactly this value
            /// and the pricing charges its worst-case pad.
            const HEAD_ALIGN: usize = $crate::fixed::head_align(&[$(align_of::<$ty>()),+]);

            /// The slab price of these capacities, accumulated in
            /// the ladder's own order
            /// ([`crate::fixed_inplace::Demand`]'s contract).
            const fn priced(&self) -> usize {
                let mut demand = $crate::fixed_inplace::Demand::new(Self::HEAD_ALIGN);
                $(demand.lane::<$ty>(self.$name);)+
                demand.bytes()
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
                    $($name: $crate::fixed_inplace::Lane::<$ty>::carve(&mut carver, caps.$name),)+
                }
            }};
        }
    };
}
pub(crate) use carve_ladder;

// ─── the compiled matcher over carved lanes ───

/// A live NFA state: rule index, segment index — both minted under
/// the rule-set admission (≤ 65,535 each).
pub(crate) type State = (u16, u16);

/// One layer's start marks into the matcher's three flat tables.
#[derive(Clone, Copy)]
pub(crate) struct Marks {
    targets: usize,
    stages: usize,
    wilds: usize,
}

/// What a record's field number means to the live rules, folded
/// for a writer: two actions on one record are indeterminate, so
/// the double target is quoted, not enumerated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Hits {
    /// No rule targets it.
    None,
    /// Exactly one rule targets it.
    One(u16),
    /// Two rules target it: the determinism fault, both quoted.
    Conflict(u16, u16),
}

/// The matcher's carved lanes, split off the slab by the door and
/// bound into the [`Matcher`] for the walk.
pub(crate) struct MatcherLanes<'r, 's> {
    /// Terminal entries of action rules, all layers concatenated.
    pub(crate) targets: Lane<'s, (FieldNumber, u16)>,
    /// Non-terminal `Field` entries, all layers concatenated.
    pub(crate) stages: Lane<'s, (FieldNumber, State)>,
    /// Wildcard self-loops, all layers concatenated, deduplicated
    /// per layer (overlapping chains inside a wildcard run land
    /// once — the demand derivation's per-layer bound).
    pub(crate) wilds: Lane<'s, (&'r [FieldNumber], State)>,
    /// Child states staged by the last route probe.
    pub(crate) staged: Lane<'s, State>,
    /// Suspended ancestor marks, innermost last.
    pub(crate) levels: Lane<'s, Marks>,
}

/// The path NFA over carved lanes — the walks' matcher, sharing
/// the heap matcher's layer discipline: layer entry flattens the
/// live states' ε-chains into three flat tables; the tables stack
/// (a descent appends, an ascent truncates); target entries carry
/// non-decreasing rule ids with equal ids adjacent (the verdict
/// fold's invariant). Dialect-orthogonal: it consumes field
/// numbers and container entry/exit, never wire kinds.
pub(crate) struct Matcher<'r, 's> {
    set: RuleSet<'r>,
    lanes: MatcherLanes<'r, 's>,
    /// The current layer's start marks.
    layer: Marks,
}

impl<'r, 's> Matcher<'r, 's> {
    /// Compiles the root layer: every rule live at its head.
    pub(crate) fn new(set: RuleSet<'r>, lanes: MatcherLanes<'r, 's>) -> Self {
        let mut matcher = Self { set, lanes, layer: Marks { targets: 0, stages: 0, wilds: 0 } };
        for id in 0..set.rules().len() {
            // Lossless: the authoring door admitted the count to
            // u16.
            #[allow(clippy::as_conversions, reason = "over admitted the count to u16")]
            matcher.flatten((id as u16, 0));
        }
        matcher
    }

    /// Flattens one live state's ε-chain into the layer tables:
    /// every wildcard on the run self-loops (landed once per layer
    /// — the dedup scan below), and the chain's first `Field` lands
    /// as a target (terminal) or a stage (interior).
    fn flatten(&mut self, (rule, seg): State) {
        let rules = self.set.rules();
        debug_assert!(usize::from(rule) < rules.len(), "states are minted below the count");
        // SAFETY: every flattened state was minted below the
        // admitted rule count (the root loop above and the staged
        // states, which the stage/wild entries carry from the same
        // mints).
        let steps = unsafe { rules.get_unchecked(usize::from(rule)) }.path;
        let mut i = usize::from(seg);
        loop {
            // SAFETY: `i` starts at a minted in-bounds segment
            // index and the loop returns at its chain's first
            // `Field`, which exists — admission pinned every path's
            // terminal segment to a `Field` — so `i` never passes
            // the end.
            match unsafe { *steps.get_unchecked(i) } {
                Segment::Field(field) => {
                    if i + 1 == steps.len() {
                        // SAFETY: per layer, each staged state
                        // lands at most one terminal entry, and the
                        // demand derivation sizes the lane at the
                        // per-layer static count of
                        // terminal-chaining states times the depth
                        // factor (`derive_caps`).
                        unsafe { self.lanes.targets.push_unchecked((field, rule)) };
                    } else {
                        // Lossless: admission capped path lengths.
                        #[allow(
                            clippy::as_conversions,
                            reason = "admission capped path lengths to u16"
                        )]
                        // SAFETY: as the targets push — the demand
                        // derivation's stage-chaining static count.
                        unsafe {
                            self.lanes.stages.push_unchecked((field, (rule, i as u16 + 1)));
                        }
                    }
                    return;
                }
                Segment::AnyDepth { descend } => {
                    // Lossless: admission capped path lengths.
                    #[allow(
                        clippy::as_conversions,
                        reason = "admission capped path lengths to u16"
                    )]
                    let state = (rule, i as u16);
                    // Chains from distinct staged states overlap
                    // only inside a wildcard run; landing each
                    // wildcard state once keeps the layer at the
                    // derivation's per-layer wildcard count (the
                    // staged dedup already collapses duplicate
                    // deliveries, so the fold is unchanged).
                    let layer = &self.lanes.wilds.as_slice()[self.layer.wilds..];
                    if !layer.iter().any(|&(_, seen)| seen == state) {
                        // SAFETY: the dedup above holds this layer
                        // at the derivation's per-layer wildcard
                        // count times the depth factor.
                        unsafe { self.lanes.wilds.push_unchecked((descend, state)) };
                    }
                    i += 1;
                }
            }
        }
    }

    /// Judges `field` as a leaf under the write fold: the target
    /// verdict from the terminal table alone. Staging is untouched
    /// — leaves never descend.
    #[inline]
    pub(crate) fn probe_target(&self, field: FieldNumber) -> Hits {
        let mut found: Option<u16> = None;
        // SAFETY: `layer.targets` is a snapshot of the lane's `len`
        // taken at layer entry (zero at construction), and the lane
        // never shrinks below a live snapshot — pushes only grow
        // it, and `exit` truncates to the innermost snapshot before
        // restoring the parent's — so the range start is in bounds.
        for &(f, rule) in
            unsafe { self.lanes.targets.as_slice().get_unchecked(self.layer.targets..) }
        {
            if f == field {
                match found {
                    None => found = Some(rule),
                    // Two states of one rule can share a terminal
                    // (converging wildcard runs): not a conflict.
                    Some(first) if first != rule => return Hits::Conflict(first, rule),
                    Some(_) => {}
                }
            }
        }
        found.map_or(Hits::None, Hits::One)
    }

    /// Judges `field` as a container head under the write fold:
    /// the target verdict, and whether any rule continues into it
    /// (the staged child states, committed by
    /// [`commit_descent`](Self::commit_descent), are non-empty).
    pub(crate) fn probe(&mut self, field: FieldNumber) -> (Hits, bool) {
        let hits = self.probe_target(field);
        if let Hits::Conflict(..) = hits {
            return (hits, false);
        }
        (hits, self.probe_routes(field))
    }

    /// Stages the child states of every rule continuing into
    /// `field`; `true` when anything staged. A following
    /// [`commit_descent`](Self::commit_descent) compiles the
    /// staged layer.
    pub(crate) fn probe_routes(&mut self, field: FieldNumber) -> bool {
        self.lanes.staged.clear();
        // SAFETY: both marks are layer-entry snapshots of their
        // lanes' lengths; see `probe_target`.
        for &(f, state) in
            unsafe { self.lanes.stages.as_slice().get_unchecked(self.layer.stages..) }
        {
            if f == field {
                // SAFETY: per probe, staged pushes are bounded by
                // this layer's stage and wildcard entries, and the
                // demand derivation sizes the staged lane at the
                // per-layer static sum of both.
                unsafe { self.lanes.staged.push_unchecked(state) };
            }
        }
        // SAFETY: as above.
        for &(descend, state) in
            unsafe { self.lanes.wilds.as_slice().get_unchecked(self.layer.wilds..) }
        {
            let mut j = 0;
            while j < descend.len() {
                if descend[j] == field {
                    // SAFETY: as the stages push above.
                    unsafe { self.lanes.staged.push_unchecked(state) };
                    break;
                }
                j += 1;
            }
        }
        self.lanes.staged.len() != 0
    }

    /// Enters the container the immediately preceding route probe
    /// judged: the staged states, deduplicated, compile into the
    /// child layer's tables.
    pub(crate) fn commit_descent(&mut self) {
        // Converging states arrive as duplicates; collapsing them
        // here bounds every layer by the reachable state set.
        let staged = self.lanes.staged.as_mut_slice();
        staged.sort_unstable();
        let mut unique = 0;
        for i in 0..staged.len() {
            if i == 0 || staged[i] != staged[i - 1] {
                staged[unique] = staged[i];
                unique += 1;
            }
        }
        self.lanes.staged.truncate(unique);
        // SAFETY: suspended marks are bounded by the dialect's
        // committed-container count — the door sizes this lane at
        // that bound (each dialect's capacity derivation).
        unsafe { self.lanes.levels.push_unchecked(self.layer) };
        self.layer = Marks {
            targets: self.lanes.targets.len(),
            stages: self.lanes.stages.len(),
            wilds: self.lanes.wilds.len(),
        };
        let mut i = 0;
        while i < self.lanes.staged.len() {
            let state = self.lanes.staged.as_slice()[i];
            self.flatten(state);
            i += 1;
        }
    }

    /// Leaves a container: truncates the child layer's table
    /// entries and restores the parent's marks.
    pub(crate) fn exit(&mut self) {
        self.lanes.targets.truncate(self.layer.targets);
        self.lanes.stages.truncate(self.layer.stages);
        self.lanes.wilds.truncate(self.layer.wilds);
        debug_assert!(self.lanes.levels.len() > 0, "descents and exits pair");
        // The walkers exit only containers they entered, and the
        // wire layer verifies group pairing before delivering an
        // exit — the pop cannot miss.
        if let Some(marks) = self.lanes.levels.pop() {
            self.layer = marks;
        }
    }

    /// Current per-lane occupancy, for the budget fold: targets,
    /// stages, wilds, staged, levels.
    #[inline]
    pub(crate) const fn occupancy(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.lanes.targets.len(),
            self.lanes.stages.len(),
            self.lanes.wilds.len(),
            self.lanes.staged.len(),
            self.lanes.levels.len(),
        )
    }
}

// ─── the demand derivation (capacity proof sources) ───

/// Per-layer static counts read off the rule set's own shape — the
/// matcher lanes' capacity proof, derived by the door and never
/// restated by the caller.
///
/// The classification is static per state: a state either chains
/// to the terminal (its wildcard run ends at the terminal segment)
/// or to an interior `Field`, and only stageable states — the
/// root, a post-`Field` position, or a wildcard's own position —
/// can ever be live. Per layer, each live state lands exactly one
/// target-or-stage entry and its chain's wildcards land once each
/// (the flatten dedup), so:
///
/// - `targets`: states whose chain ends at the terminal, summed
///   over rules — per-layer target-entry bound;
/// - `stages`: states whose chain ends at an interior `Field` —
///   per-layer stage-entry bound;
/// - `wilds`: wildcard positions, summed — per-layer wildcard
///   bound under the dedup;
/// - `staged`: `stages + wilds` — one probe stages at most every
///   stage and wildcard entry of its layer.
///
/// The depth factor multiplying the per-layer bounds is
/// [`depth_factor`]'s.
pub(crate) struct PathStats {
    /// Per-layer terminal-entry bound.
    pub(crate) targets: usize,
    /// Per-layer stage-entry bound.
    pub(crate) stages: usize,
    /// Per-layer wildcard-entry bound.
    pub(crate) wilds: usize,
    /// Whether any wildcard exists (the depth factor's switch).
    pub(crate) any_wild: bool,
    /// The longest path's segment count.
    pub(crate) longest: usize,
    /// Whether any rule renumbers (the grouped pending lane's
    /// switch).
    pub(crate) any_renumber: bool,
}

/// Scans the admitted rule set once (door-time, allocation-free)
/// into [`PathStats`].
pub(crate) fn path_stats(set: &RuleSet<'_>) -> PathStats {
    let mut stats = PathStats {
        targets: 0,
        stages: 0,
        wilds: 0,
        any_wild: false,
        longest: 0,
        any_renumber: false,
    };
    for rule in set.rules() {
        let steps = rule.path;
        if steps.len() > stats.longest {
            stats.longest = steps.len();
        }
        if matches!(rule.action, Action::Renumber(_)) {
            stats.any_renumber = true;
        }
        // `run` counts the wildcards immediately before the next
        // `Field`: those states plus (when no run precedes it) the
        // post-`Field` state are exactly the stageable states whose
        // chains end at that `Field`.
        let mut run = 0usize;
        let terminal = steps.len() - 1;
        for (k, step) in steps.iter().enumerate() {
            match *step {
                Segment::AnyDepth { .. } => {
                    run += 1;
                    stats.wilds += 1;
                    stats.any_wild = true;
                }
                Segment::Field(_) => {
                    let enders = run + usize::from(run == 0);
                    if k == terminal {
                        stats.targets += enders;
                    } else {
                        stats.stages += enders;
                    }
                    run = 0;
                }
            }
        }
    }
    stats
}

/// The committed-layer bound: without wildcards live states
/// advance one segment per descent, so no layer past the longest
/// path can hold a state; with any wildcard only the caller's
/// [`DepthLimit`] bounds descent. Root included.
pub(crate) fn depth_factor(stats: &PathStats, limit: DepthLimit) -> usize {
    let limit = usize::from(limit.as_inner());
    1 + if stats.any_wild { limit } else { limit.min(stats.longest.saturating_sub(1)) }
}

#[cfg(feature = "fixed-inplace-grouped")]
pub mod grouped;
#[cfg(feature = "fixed-inplace-groupless")]
pub mod groupless;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inplace::Rule;

    fn f(n: u32) -> FieldNumber {
        FieldNumber::new(n).unwrap()
    }

    #[test]
    fn lanes_uphold_the_arena_invariant_over_a_stack_slab() {
        let mut slab = [MaybeUninit::<u8>::uninit(); 256];
        let mut carver = crate::fixed::Carver::<4>::new(&mut slab);
        let mut lane: Lane<'_, (FieldNumber, u16)> = Lane::carve(&mut carver, 4);
        assert_eq!((lane.len(), lane.capacity()), (0, 4));
        assert!(lane.push((f(1), 10)));
        assert!(lane.push((f(2), 20)));
        assert_eq!(lane.as_slice(), &[(f(1), 10), (f(2), 20)]);
        assert_eq!(lane.last(), Some(&(f(2), 20)));
        lane.truncate(1);
        assert_eq!(lane.as_slice(), &[(f(1), 10)]);
        assert_eq!(lane.pop(), Some((f(1), 10)));
        assert_eq!(lane.pop(), None);
        // The judged push refuses exactly at capacity.
        for i in 0..4 {
            assert!(lane.push((f(9), i)));
        }
        assert!(!lane.push((f(9), 4)));
        assert_eq!(lane.len(), 4);
    }

    #[test]
    fn the_carve_consumes_at_most_the_priced_demand_at_any_address() {
        // Three lane types across the alignment ladder, carved at
        // every slab offset: consumption never exceeds the price,
        // and the price is met exactly at offset-aligned worst
        // cases.
        let mut demand = Demand::new(8);
        demand.lane::<u64>(3);
        demand.lane::<u32>(5);
        demand.lane::<u16>(7);
        let need = demand.bytes();
        assert_eq!(need, 7 + 24 + 20 + 14);
        let mut backing = [MaybeUninit::<u8>::uninit(); 128];
        for offset in 0..8 {
            let slab = &mut backing[offset..offset + need];
            let mut carver = crate::fixed::Carver::<8>::new(slab);
            let a: Lane<'_, u64> = Lane::carve(&mut carver, 3);
            let b: Lane<'_, u32> = Lane::carve(&mut carver, 5);
            let c: Lane<'_, u16> = Lane::carve(&mut carver, 7);
            assert_eq!((a.capacity(), b.capacity(), c.capacity()), (3, 5, 7));
        }
    }

    #[test]
    fn path_stats_count_the_per_layer_statics() {
        let (one, two, three, seven) = (f(1), f(2), f(3), f(7));
        let route = [one, two];
        // A plain target, a staged hop, and a wildcard run of two
        // (incomparable sets — admission refuses comparable pairs)
        // before the terminal.
        let other = [one, three];
        let paths: [&[Segment<'_>]; 3] = [
            &[Segment::Field(seven)],
            &[Segment::Field(one), Segment::Field(seven)],
            &[
                Segment::AnyDepth { descend: &route },
                Segment::AnyDepth { descend: &other },
                Segment::Field(seven),
            ],
        ];
        let rules: [Rule<'_>; 3] = [
            Rule { path: paths[0], action: Action::SetVarint(0) },
            Rule { path: paths[1], action: Action::SetI32(0) },
            Rule { path: paths[2], action: Action::SetI64(0) },
        ];
        let set = RuleSet::over(&rules).unwrap();
        let stats = path_stats(&set);
        // Rule 0: one terminal-chaining state. Rule 1: one stage
        // ender at f1, one terminal ender. Rule 2: the run of two
        // wildcards chains to the terminal.
        assert_eq!(stats.targets, 1 + 1 + 2);
        assert_eq!(stats.stages, 1);
        assert_eq!(stats.wilds, 2);
        assert!(stats.any_wild);
        assert_eq!(stats.longest, 3);
        assert!(!stats.any_renumber);
        // The depth factor: wildcards hand the bound to the caller.
        assert_eq!(depth_factor(&stats, DepthLimit::new(100).unwrap()), 101);
        // Without wildcards the longest path bounds descent.
        let flat = RuleSet::over(&rules[..2]).unwrap();
        let flat_stats = path_stats(&flat);
        assert!(!flat_stats.any_wild);
        assert_eq!(depth_factor(&flat_stats, DepthLimit::new(100).unwrap()), 2);
    }

    #[test]
    fn the_matcher_over_lanes_walks_wildcards_and_quotes_conflicts() {
        let (one, two, seven) = (f(1), f(2), f(7));
        let route = [one];
        let paths: [&[Segment<'_>]; 2] = [
            &[Segment::Field(seven)],
            &[Segment::AnyDepth { descend: &route }, Segment::Field(seven)],
        ];
        let rules: [Rule<'_>; 2] = [
            Rule { path: paths[0], action: Action::SetVarint(0) },
            Rule { path: paths[1], action: Action::SetVarint(1) },
        ];
        let set = RuleSet::over(&rules).unwrap();
        let stats = path_stats(&set);
        let depth = depth_factor(&stats, DepthLimit::new(10).unwrap());
        let mut slab = [MaybeUninit::<u8>::uninit(); 4096];
        let mut carver = crate::fixed::Carver::<8>::new(&mut slab);
        // Descending alignment: the wilds and marks lanes are
        // pointer-aligned, the flat tables word-aligned, the staged
        // lane half-word-aligned.
        let lanes = MatcherLanes {
            wilds: Lane::carve(&mut carver, stats.wilds * depth),
            levels: Lane::carve(&mut carver, depth - 1),
            targets: Lane::carve(&mut carver, stats.targets * depth),
            stages: Lane::carve(&mut carver, stats.stages * depth),
            staged: Lane::carve(&mut carver, stats.stages + stats.wilds),
        };
        let mut m = Matcher::new(set, lanes);
        // Both rules target f7 at the root: the write fold quotes
        // the double target.
        assert_eq!(m.probe_target(seven), Hits::Conflict(0, 1));
        // f1 routes (the wildcard's alphabet), f2 does not.
        assert_eq!(m.probe(one), (Hits::None, true));
        assert_eq!(m.probe(two), (Hits::None, false));
        // Below one crossing only the wildcard rule survives.
        assert!(m.probe_routes(one));
        m.commit_descent();
        assert_eq!(m.probe_target(seven), Hits::One(1));
        m.exit();
        assert_eq!(m.probe_target(seven), Hits::Conflict(0, 1));
    }
}
