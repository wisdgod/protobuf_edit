//! The groupless fixed-scratch in-place editor: group codes are
//! outside the language, working memory carved from the caller's
//! slab.
//!
//! The job is `crate::inplace::groupless`'s exactly — one
//! read-only judge walk proves every write against met geometry
//! (group codes surface as the traversal's capability refusal),
//! `Err` returns with the buffer byte-identical to entry, and the
//! write loop past the barrier is infallible, allocation-free, and
//! panic-free. Within an adequate plan the two twins are
//! byte-identical in buffer outcome, receipt, and fault. The
//! difference is the memory plane: the layer stack, the matcher
//! tables, and the write list live in the caller's slab, so no
//! phase of the job touches an allocator.
//!
//! The door judges the slab against [`Plan::bytes`] before reading
//! anything ([`FaultKind::SlabShort`]); the walk refuses a write
//! list outgrowing the plan at the judged record
//! ([`FaultKind::WriteListFull`]). Both refusals precede the first
//! buffer write, are deterministic in (plan, configuration, job),
//! and repair by declaring more — the Policy class's shape.
//!
//! Coordinates: write · buffered · static · groupless · Standard (value-level) · in-place · commit-only · fixed scratch.
//!
//! # Examples
//!
//! ```
//! use core::mem::MaybeUninit;
//! use protobuf_edit::fixed_inplace::groupless::{Plan, apply};
//! use protobuf_edit::inplace::{Action, Rule, RuleSet};
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // varint f1=150 · LEN f2 "hi": replace both values in place,
//! // scratch carved from a stack array.
//! let mut msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let f1 = FieldNumber::new(1).unwrap();
//! let f2 = FieldNumber::new(2).unwrap();
//! let rules = [
//!     Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(200) },
//!     Rule { path: &[Segment::Field(f2)], action: Action::SetPayload(b"no") },
//! ];
//! let set = RuleSet::over(&rules).unwrap();
//!
//! let plan = Plan::new(2).unwrap();
//! let mut slab = [MaybeUninit::<u8>::uninit(); 512];
//! assert!(plan.bytes(&set, DepthLimit::REFERENCE) <= slab.len());
//!
//! let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
//! assert_eq!(msg, [0x08, 0xC8, 0x01, 0x12, 0x02, b'n', b'o']);
//! assert_eq!(stats.replaced(), 2);
//! ```

use core::mem::MaybeUninit;

use super::{Gauge, Hits, Lane, Marks, Matcher, MatcherLanes, State, Stats, depth_factor, path_stats};
use crate::admission::usize_of;
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::inplace::{Action, RuleSet, Write, action, commit, filler_need, width_fits};
use crate::varint::{ValueWidth, WordWidth, encoded_len32, encoded_len64};
use crate::wire::FieldNumber;
use crate::wire::groupless::{RecordKind, head_word};
use crate::{DepthLimit, FaultClass, Standard};

/// The one caller-declared capacity: the write list's entry count.
/// Everything else the job needs is derived from the rule set and
/// the [`DepthLimit`] by the door.
///
/// One entry serves one planned write: every landing action plans
/// exactly one. Zero is lawful (a judge-only job over rules that
/// match nothing).
///
/// # Examples
///
/// ```
/// use protobuf_edit::fixed_inplace::groupless::Plan;
///
/// assert!(Plan::new(16).is_some());
/// assert_eq!(Plan::new(1 << 31), None); // past the coordinate class
/// ```
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Plan {
    writes: u32,
}

impl Plan {
    /// Declares the write capacity, judged into the coordinate
    /// class (`0..=i32::MAX` — planned writes land at distinct
    /// byte extents, so no admitted document can need more).
    #[inline]
    pub const fn new(writes: u32) -> Option<Self> {
        if writes > i32::MAX.cast_unsigned() {
            return None;
        }
        Some(Self { writes })
    }

    /// The declared write capacity.
    #[inline]
    #[must_use]
    pub const fn writes(&self) -> u32 {
        self.writes
    }

    /// The exact slab demand of a job under this plan, `rules`,
    /// and `limit` — sufficient for any slab address (worst-case
    /// head padding is priced in), and exact at the refusal
    /// boundary: a slab of this many bytes carves, one byte fewer
    /// refuses [`FaultKind::SlabShort`]. Saturates at `usize::MAX`
    /// for demands no slab can satisfy.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::fixed_inplace::groupless::Plan;
    /// use protobuf_edit::inplace::{Action, Rule, RuleSet};
    /// use protobuf_edit::path::Segment;
    /// use protobuf_edit::{DepthLimit, FieldNumber};
    ///
    /// let f1 = FieldNumber::new(1).unwrap();
    /// let rules = [Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(0) }];
    /// let set = RuleSet::over(&rules).unwrap();
    ///
    /// // A bigger plan prices a bigger slab, deterministically.
    /// let small = Plan::new(1).unwrap().bytes(&set, DepthLimit::REFERENCE);
    /// let large = Plan::new(64).unwrap().bytes(&set, DepthLimit::REFERENCE);
    /// assert!(small < large);
    /// ```
    #[inline]
    #[must_use]
    pub fn bytes(&self, rules: &RuleSet<'_>, limit: DepthLimit) -> usize {
        Caps::derive(rules, limit, self).priced()
    }
}

impl Caps {
    /// Derives every capacity from (plan, rules, limit) — a pure
    /// function; saturating arithmetic keeps pathological shapes
    /// refusable instead of wrapping. The plan declares the write
    /// count; the rest are configuration-derived bounds (the
    /// demand derivation in [`crate::fixed_inplace`]).
    fn derive(rules: &RuleSet<'_>, limit: DepthLimit, plan: &Plan) -> Self {
        let stats = path_stats(rules);
        let depth = depth_factor(&stats, limit);
        Self {
            writes: usize_of(plan.writes),
            layers: depth,
            levels: depth - 1,
            targets: stats.targets.saturating_mul(depth),
            stages: stats.stages.saturating_mul(depth),
            wilds: stats.wilds.saturating_mul(depth),
            staged: stats.stages.saturating_add(stats.wilds),
        }
    }
}

/// The per-lane budget of one metered job ([`apply_budget`]):
/// high-water occupancy against carved capacity.
///
/// The sizing loop's mechanical face: derived lanes report how
/// much of their proven bound a representative job really used,
/// and the write row reports the count a tight [`Plan`] must
/// declare.
#[must_use]
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Budget {
    writes: Gauge,
    layers: Gauge,
    levels: Gauge,
    targets: Gauge,
    stages: Gauge,
    wilds: Gauge,
    staged: Gauge,
}

impl Budget {
    /// The write list: entries a tight plan must declare.
    #[inline]
    #[must_use]
    pub const fn writes(&self) -> Gauge {
        self.writes
    }

    /// The layer stack (committed LEN descents, root included).
    #[inline]
    #[must_use]
    pub const fn layers(&self) -> Gauge {
        self.layers
    }

    /// The matcher's suspended layer marks.
    #[inline]
    #[must_use]
    pub const fn levels(&self) -> Gauge {
        self.levels
    }

    /// The matcher's terminal table.
    #[inline]
    #[must_use]
    pub const fn targets(&self) -> Gauge {
        self.targets
    }

    /// The matcher's interior-hop table.
    #[inline]
    #[must_use]
    pub const fn stages(&self) -> Gauge {
        self.stages
    }

    /// The matcher's wildcard table.
    #[inline]
    #[must_use]
    pub const fn wilds(&self) -> Gauge {
        self.wilds
    }

    /// The route probe's staging strip.
    #[inline]
    #[must_use]
    pub const fn staged(&self) -> Gauge {
        self.staged
    }

    /// Installs the carved capacities.
    const fn capacities(&mut self, caps: &Caps) {
        self.writes.capacity = caps.writes;
        self.layers.capacity = caps.layers;
        self.levels.capacity = caps.levels;
        self.targets.capacity = caps.targets;
        self.stages.capacity = caps.stages;
        self.wilds.capacity = caps.wilds;
        self.staged.capacity = caps.staged;
    }

    /// Folds the matcher's current occupancy into the high-water
    /// rows.
    const fn observe_matcher(&mut self, matcher: &Matcher<'_, '_>) {
        let (targets, stages, wilds, staged, levels) = matcher.occupancy();
        self.targets.observe(targets);
        self.stages.observe(stages);
        self.wilds.observe(wilds);
        self.staged.observe(staged);
        self.levels.observe(levels);
    }
}

/// A job refusal: where, and which contract broke.
///
/// Every fault precedes the first write — on `Err` the buffer is
/// byte-identical to entry, unconditionally.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u32,
    kind: FaultKind,
}

impl Fault {
    /// Whole-buffer byte coordinate of the construct the kind
    /// names (for the width refusals: the record head; for
    /// [`FaultKind::SlabShort`], zero — the refusal precedes the
    /// walk).
    #[inline]
    #[must_use]
    pub const fn at(self) -> u32 {
        self.at
    }

    /// The broken contract.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> FaultKind {
        self.kind
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.at)
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.kind)
    }
}

/// The groupless fixed in-place editor's refusal classes: the host
/// twin's document vocabulary plus the two scratch refusals.
///
/// The width refusals share one need/have vocabulary: `need` is
/// the width or extent the rule's operand requires, `have` the
/// met slot's. Under `Tolerant` the varint-word refusals
/// ([`ValueWidth`], [`TagWidth`]) fire only for `need > have`
/// (a narrower word pads to fit); under `CanonicalMinimal` they
/// fire for `need != have` — one arm, two regimes, picked by the
/// job's declared [`Standard`]. The extent refusals
/// ([`PayloadLength`], [`ReplacementLength`]) fire for
/// `need != have` under both standards: bytes have no padded
/// spelling. The scratch refusals ([`SlabShort`],
/// [`WriteListFull`]) are [`FaultClass::Policy`]: lawful jobs
/// refused under one declared capacity, accepted under a larger
/// one.
///
/// [`ValueWidth`]: Self::ValueWidth
/// [`TagWidth`]: Self::TagWidth
/// [`PayloadLength`]: Self::PayloadLength
/// [`ReplacementLength`]: Self::ReplacementLength
/// [`SlabShort`]: Self::SlabShort
/// [`WriteListFull`]: Self::WriteListFull
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// The slab cannot host the job's carve: judged at the door,
    /// before anything — buffer, rules, slab — is read.
    /// [`FaultClass::Policy`]: the plan and configuration price
    /// the demand deterministically, and a slab of
    /// [`Plan::bytes`] accepts the same job.
    SlabShort {
        /// The exact demand ([`Plan::bytes`]).
        need: usize,
        /// The offered slab's length.
        have: usize,
    },
    /// The write list is full: the walk staged one write past the
    /// plan's declared capacity, at the judged record — before the
    /// fault barrier, so the buffer is untouched.
    /// [`FaultClass::Policy`]: a bigger [`Plan`] accepts the same
    /// job.
    WriteListFull {
        /// Entries the job needs at the refusal (one past the
        /// declared capacity).
        need: u32,
        /// The plan's declared capacity.
        have: u32,
    },
    /// The input exceeds the admission cap (`i32::MAX` bytes).
    Oversize,
    /// A committed descent (or the top layer) hit unlawful wire —
    /// the groupless traversal vocabulary, unrewrapped (group
    /// codes arrive as its capability refusal; canonical jobs
    /// surface non-minimal widths here, scan-parity).
    Wire(WireBreach),
    /// Two rules target one record.
    Conflict {
        /// The first targeting rule.
        first: u32,
        /// The second targeting rule.
        second: u32,
    },
    /// The rule's action does not fit the record's wire kind.
    KindMismatch {
        /// The offending rule's index.
        rule: u32,
    },
    /// `SetVarint`: the value's minimal encoding vs the met value
    /// slot.
    ValueWidth {
        /// The offending rule's index.
        rule: u32,
        /// The value's own minimal width.
        need: u32,
        /// The met slot width.
        have: u32,
    },
    /// `Renumber`: the new tag word's minimal encoding vs the met
    /// tag slot.
    TagWidth {
        /// The offending rule's index.
        rule: u32,
        /// The new tag word's minimal width.
        need: u32,
        /// The met tag width.
        have: u32,
    },
    /// `SetPayload`: the supplied byte count vs the payload
    /// extent.
    PayloadLength {
        /// The offending rule's index.
        rule: u32,
        /// The supplied byte count.
        need: u32,
        /// The met payload extent.
        have: u32,
    },
    /// `Tombstone`: the record extent cannot host the declared
    /// filler field (`need` is the filler's tag width plus one —
    /// fields 1..=15 fit every record).
    FillerUnfit {
        /// The offending rule's index.
        rule: u32,
        /// The filler's minimal extent.
        need: u32,
        /// The record extent.
        have: u32,
    },
    /// `ReplaceRecord`: the candidate's byte count vs the record
    /// extent.
    ReplacementLength {
        /// The offending rule's index.
        rule: u32,
        /// The candidate's byte count.
        need: u32,
        /// The record extent.
        have: u32,
    },
    /// `ReplaceRecord`: the candidate refused to parse under the
    /// job's dialect and standard.
    ReplacementWire {
        /// The offending rule's index.
        rule: u32,
        /// The refusal's candidate-relative byte coordinate (the
        /// enclosing [`Fault::at`] names the source record head).
        at: u32,
        /// The candidate's own wire refusal.
        breach: WireBreach,
    },
    /// `ReplaceRecord`: the candidate parses but does not spell
    /// exactly one record over its whole extent.
    ReplacementShape {
        /// The offending rule's index.
        rule: u32,
    },
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::SlabShort { need, have } => {
                write!(f, "the slab offers {have} bytes against a {need}-byte demand")
            }
            Self::WriteListFull { need, have } => {
                write!(f, "the job needs {need} planned writes against a plan of {have}")
            }
            Self::Oversize => f.write_str("the input exceeds the admission cap"),
            Self::Wire(breach) => write!(f, "{breach}"),
            Self::Conflict { first, second } => {
                write!(f, "rules {first} and {second} target one record")
            }
            Self::KindMismatch { rule } => {
                write!(f, "rule {rule}'s action does not fit the record's wire kind")
            }
            Self::ValueWidth { rule, need, have } => {
                write!(f, "rule {rule}'s value needs {need} bytes against a {have}-byte slot")
            }
            Self::TagWidth { rule, need, have } => {
                write!(f, "rule {rule}'s tag word needs {need} bytes against a {have}-byte slot")
            }
            Self::PayloadLength { rule, need, have } => {
                write!(f, "rule {rule} supplies {need} payload bytes against a {have}-byte extent")
            }
            Self::FillerUnfit { rule, need, have } => {
                write!(
                    f,
                    "rule {rule}'s filler field needs {need} bytes against a {have}-byte record"
                )
            }
            Self::ReplacementLength { rule, need, have } => {
                write!(f, "rule {rule}'s replacement is {need} bytes against a {have}-byte record")
            }
            Self::ReplacementWire { rule, at, breach } => {
                write!(f, "rule {rule}'s replacement refuses at its byte {at}: {breach}")
            }
            Self::ReplacementShape { rule } => {
                write!(f, "rule {rule}'s replacement does not spell exactly one record")
            }
        }
    }
}

impl core::error::Error for FaultKind {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(breach) | Self::ReplacementWire { breach, .. } => Some(breach),
            _ => None,
        }
    }
}

/// The wire breach, summarized by who acts on it: an in-place
/// consumer rejects the document either way — byte-precise
/// diagnosis over the same bytes is the inspector's job.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireBreach {
    /// A varint (tag, length, or value) refused: too wide, out of
    /// class, or cut by the input end.
    Varint,
    /// The tag word is unlawful (field zero or an unassigned code).
    Tag,
    /// A fixed-width or LEN payload exceeds the remaining input.
    Truncated,
    /// A committed descent would nest past the caller's declared
    /// [`DepthLimit`] budget.
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// canonical job faces' declared standard (the tolerant faces
    /// never judge widths).
    NonMinimal,
    /// A group code appeared — outside this dialect's language
    /// (the grouped dialect handles such documents).
    GroupCode,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget; [`NonMinimal`] is the
    /// canonical faces' standard).
    ///
    /// [`Depth`]: Self::Depth
    /// [`NonMinimal`]: Self::NonMinimal
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Varint | Self::Tag | Self::Truncated => FaultClass::Grammar,
            Self::Depth | Self::NonMinimal => FaultClass::Policy,
            Self::GroupCode => FaultClass::Capability,
        }
    }
}

impl core::fmt::Display for WireBreach {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Varint => "a varint refused (too wide, out of class, or cut short)",
            Self::Tag => "an unlawful tag word",
            Self::Truncated => "a payload past the input end",
            Self::Depth => "nesting past the declared depth budget",
            Self::NonMinimal => "a varint word wider than its minimal encoding",
            Self::GroupCode => "a group code outside this dialect",
        })
    }
}

impl core::error::Error for WireBreach {}

#[cold]
const fn breach(kind: crate::cursor::groupless::FaultKind) -> WireBreach {
    use crate::cursor::groupless::FaultKind as T;
    match kind {
        T::Read { .. } => WireBreach::Varint,
        T::FieldZero { .. } | T::Unassigned { .. } => WireBreach::Tag,
        T::GroupCode { .. } => WireBreach::GroupCode,
        T::FixedTruncated { .. } | T::LenOverrun { .. } => WireBreach::Truncated,
        T::NonMinimalTag | T::NonMinimalLen { .. } | T::NonMinimalValue { .. } => {
            WireBreach::NonMinimal
        }
    }
}

// The fault vocabulary is plain copyable data (no trail
// allocation: rule indices, byte coordinates, and the two scratch
// need/have pairs name everything), pinned per pointer width.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<FaultKind>() == if w64 { 24 } else { 16 });
    assert!(core::mem::size_of::<Fault>() == if w64 { 32 } else { 20 });
};

// ─── the judge walk (phase one) ───

/// One committed LEN layer on the carved stack.
///
/// The depth accounting is layer-local: `remaining` is the limit
/// minus this layer's nesting depth — equivalently, the stack
/// height below the pushed layer (asserted at every push) — each
/// committed descent hands its child one less, and a spent budget
/// refuses the child before anything is pushed, so the stack never
/// outgrows the depth factor the lane was carved at.
struct Layer<'i> {
    cursor: Cursor<'i>,
    /// Absolute base of this layer's window.
    base: u32,
    /// LEN crossings still allowed below this layer.
    remaining: u16,
}

const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<Layer<'_>>() == if w64 { 40 } else { 24 });
    assert!(core::mem::align_of::<Layer<'_>>() == if w64 { 8 } else { 4 });
};

// The shared members' sizes and alignments pinned per pointer
// width (the dialect types above carry their own pins) — the
// values the ladder's descending judgment and the demand
// arithmetic ride on every width.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(size_of::<Write<'_>>() == if w64 { 24 } else { 16 } && align_of::<Write<'_>>() == 8);
    assert!(size_of::<(&[FieldNumber], State)>() == if w64 { 24 } else { 12 });
    assert!(align_of::<(&[FieldNumber], State)>() == if w64 { 8 } else { 4 });
    assert!(size_of::<Marks>() == if w64 { 24 } else { 12 });
    assert!(align_of::<Marks>() == if w64 { 8 } else { 4 });
    assert!(size_of::<(FieldNumber, u16)>() == 8 && align_of::<(FieldNumber, u16)>() == 4);
    assert!(size_of::<(FieldNumber, State)>() == 8 && align_of::<(FieldNumber, State)>() == 4);
    assert!(size_of::<State>() == 4 && align_of::<State>() == 2);
};

crate::fixed_inplace::carve_ladder! { ($)
    /// Carves the dialect's whole working set from the door's
    /// slab: one head alignment, then every lane split front to
    /// back in the ladder's alignment-descending order — padding
    /// only at the head, so the priced demand covers any slab
    /// address. Capacities come from the door's derived `Caps`
    /// field of the same name.
    carve, caps Caps, lanes Lanes {
        writes: Write<'_>,
        layers: Layer<'_>,
        wilds: (&[FieldNumber], State),
        levels: Marks,
        targets: (FieldNumber, u16),
        stages: (FieldNumber, State),
        staged: State,
    }
}

/// The write-list refusal, shaped cold: `at` names the record
/// whose planned write did not fit.
#[cold]
const fn writes_full(at: u32, capacity: usize) -> Fault {
    // Lossless: the plan admitted the capacity to the coordinate
    // class, so one past it stays in u32.
    #[allow(clippy::as_conversions, reason = "plan capacities live in the coordinate class")]
    let have = capacity as u32;
    Fault { at, kind: FaultKind::WriteListFull { need: have + 1, have } }
}

/// The whole-record replacement judgment: exact extent, then a
/// re-parse as exactly one record under the job's standard —
/// through this dialect's own cursor, so LEN payloads inside the
/// candidate stay opaque exactly as in source parsing (and the
/// groupless record grammar nests nothing in-band, so no depth
/// budget is spent).
fn judge_replacement<const MINIMAL: bool>(
    rule: u16,
    bytes: &[u8],
    head: u32,
    have: u32,
) -> Result<(), Fault> {
    let rule = u32::from(rule);
    // Lossless: the authoring door judged the candidate into the
    // LEN class.
    #[allow(clippy::as_conversions, reason = "authoring admitted the candidate to the LEN class")]
    let need = bytes.len() as u32;
    if need != have {
        return Err(Fault { at: head, kind: FaultKind::ReplacementLength { rule, need, have } });
    }
    // In class by the equality just judged: the extent came off
    // the cursor, so `within`'s contract holds.
    let mut probe = Cursor::within(bytes);
    match probe.step::<MINIMAL>() {
        Some(Ok(_)) if probe.pos() == have => Ok(()),
        Some(Ok(_)) => Err(Fault { at: head, kind: FaultKind::ReplacementShape { rule } }),
        Some(Err(fault)) => Err(Fault {
            at: head,
            kind: FaultKind::ReplacementWire { rule, at: fault.at(), breach: breach(fault.kind()) },
        }),
        // Records are at least two bytes and the extent equality
        // held, so the candidate is nonempty: its first step
        // delivers or refuses.
        None => unreachable!("a nonempty window steps"),
    }
}

/// Phase one: the read-only judge walk. Every fault the job can
/// raise surfaces here; `Ok` leaves the complete write list in the
/// carved lane, every entry proven against the current bytes.
#[allow(
    clippy::too_many_lines,
    reason = "one loop, one record fold — the dialect's whole judgment in one place, \
              the walk-skeleton convention of the static write machines"
)]
fn walk<'r, 'i, const MINIMAL: bool, const METERED: bool>(
    input: &'i [u8],
    set: &RuleSet<'r>,
    limit: DepthLimit,
    writes: &mut Lane<'_, Write<'r>>,
    layers: &mut Lane<'_, Layer<'i>>,
    matcher: &mut Matcher<'r, '_>,
    budget: &mut Budget,
) -> Result<Stats, Fault> {
    let mut stats = Stats::default();
    let Ok(root) = Cursor::over(input) else {
        return Err(Fault { at: 0, kind: FaultKind::Oversize });
    };
    // The layer invariant's base case (`Layer`): the root owns the
    // whole limit at stack height zero.
    let remaining = limit.as_inner();
    debug_assert!(
        usize::from(limit.as_inner() - remaining) == layers.len(),
        "the layer invariant holds at the root"
    );
    // SAFETY: the layer lane's capacity is the depth factor, at
    // least one — the root's own slot.
    unsafe { layers.push_unchecked(Layer { cursor: root, base: 0, remaining }) };
    if METERED {
        budget.layers.observe(layers.len());
    }

    loop {
        // SAFETY: the root layer is pushed above and the only pop
        // sits behind the `len == 1` return below, so the lane is
        // never empty here.
        let layer = unsafe { layers.last_mut_unchecked() };
        let base = layer.base;
        let head = base + layer.cursor.pos();
        let Some(item) = layer.cursor.step::<MINIMAL>() else {
            // Layer exhausted cleanly.
            if layers.len() == 1 {
                return Ok(stats);
            }
            layers.pop();
            matcher.exit();
            continue;
        };
        let entry = match item {
            Ok(entry) => entry,
            Err(fault) => {
                return Err(Fault {
                    at: base + fault.at(),
                    kind: FaultKind::Wire(breach(fault.kind())),
                });
            }
        };
        let end = base + layer.cursor.pos();
        let field = entry.field();

        match entry.kind() {
            EntryKind::Varint(_) | EntryKind::I32(_) | EntryKind::I64(_) => {
                let rule = match matcher.probe_target(field) {
                    Hits::None => continue,
                    Hits::One(rule) => rule,
                    Hits::Conflict(first, second) => {
                        return Err(conflict(head, first, second));
                    }
                };
                let tag_w = u32::from(layer.cursor.tag_width());
                let value_at = head + tag_w;
                match (action(set, rule), entry.kind()) {
                    (Action::SetVarint(value), EntryKind::Varint(_)) => {
                        let have = end - value_at;
                        let need = encoded_len64(value);
                        if !width_fits::<MINIMAL>(need, have) {
                            return Err(Fault {
                                at: head,
                                kind: FaultKind::ValueWidth { rule: u32::from(rule), need, have },
                            });
                        }
                        // SAFETY: the slot width is the walk's value
                        // window — geometry subtraction over the
                        // cursor's met value read, 1..=10.
                        #[allow(
                            clippy::as_conversions,
                            reason = "cursor-delivered value widths are 1..=10"
                        )]
                        let width = unsafe { ValueWidth::met_unchecked(have as u8) };
                        if !writes.push(Write::Varint { at: value_at, width, value }) {
                            return Err(writes_full(head, writes.capacity()));
                        }
                        stats.replaced += 1;
                    }
                    (Action::SetI32(bits), EntryKind::I32(_)) => {
                        if !writes.push(Write::Fixed32 { at: value_at, bits }) {
                            return Err(writes_full(head, writes.capacity()));
                        }
                        stats.replaced += 1;
                    }
                    (Action::SetI64(bits), EntryKind::I64(_)) => {
                        if !writes.push(Write::Fixed64 { at: value_at, bits }) {
                            return Err(writes_full(head, writes.capacity()));
                        }
                        stats.replaced += 1;
                    }
                    (Action::Renumber(new_field), kind) => {
                        let kind = match kind {
                            EntryKind::Varint(_) => RecordKind::Varint,
                            EntryKind::I32(_) => RecordKind::I32,
                            EntryKind::I64(_) => RecordKind::I64,
                            // The enclosing arm admits exactly the
                            // three scalar kinds.
                            EntryKind::Len(_) => unreachable!("scalar-arm renumber"),
                        };
                        let word = head_word(new_field, kind);
                        let need = encoded_len32(word);
                        if !width_fits::<MINIMAL>(need, tag_w) {
                            return Err(Fault {
                                at: head,
                                kind: FaultKind::TagWidth {
                                    rule: u32::from(rule),
                                    need,
                                    have: tag_w,
                                },
                            });
                        }
                        // SAFETY: the slot width is the walk's
                        // framing window — the cursor's met tag
                        // read, 1..=5.
                        let width = unsafe { WordWidth::met_unchecked(layer.cursor.tag_width()) };
                        if !writes.push(Write::Tag { at: head, width, word }) {
                            return Err(writes_full(head, writes.capacity()));
                        }
                        stats.renumbered += 1;
                    }
                    (Action::ReplaceRecord(bytes), _) => {
                        judge_replacement::<MINIMAL>(rule, bytes, head, end - head)?;
                        if !writes.push(Write::Payload { at: head, bytes }) {
                            return Err(writes_full(head, writes.capacity()));
                        }
                        stats.substituted += 1;
                    }
                    (Action::Tombstone { field: filler }, _) => {
                        let need = filler_need(filler);
                        let have = end - head;
                        if have < need {
                            return Err(Fault {
                                at: head,
                                kind: FaultKind::FillerUnfit { rule: u32::from(rule), need, have },
                            });
                        }
                        if !writes.push(Write::Filler { at: head, width: have, field: filler }) {
                            return Err(writes_full(head, writes.capacity()));
                        }
                        stats.tombstoned += 1;
                    }
                    (
                        Action::SetVarint(_)
                        | Action::SetI32(_)
                        | Action::SetI64(_)
                        | Action::SetPayload(_),
                        _,
                    ) => {
                        return Err(Fault {
                            at: head,
                            kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                        });
                    }
                }
            }
            EntryKind::Len(payload) => {
                // The payload was delivered by the cursor from
                // admitted input.
                #[allow(
                    clippy::as_conversions,
                    reason = "cursor-delivered payload lies in the LEN class"
                )]
                let payload_start = end - payload.len() as u32;
                let (hits, routed) = matcher.probe(field);
                if METERED {
                    budget.observe_matcher(matcher);
                }
                let mut walk_in = false;
                match hits {
                    Hits::Conflict(first, second) => {
                        return Err(conflict(head, first, second));
                    }
                    Hits::None => walk_in = routed,
                    Hits::One(rule) => match action(set, rule) {
                        // A wholly overwritten record's interior
                        // is not walked: rules inside it do not
                        // fire, silently (the ownership law —
                        // Stats is the operator's signal).
                        Action::SetPayload(bytes) => {
                            // Lossless: both lengths were admitted
                            // to the LEN class (cursor, authoring).
                            #[allow(
                                clippy::as_conversions,
                                reason = "both lengths lie in the LEN class"
                            )]
                            let (need, have) = (bytes.len() as u32, payload.len() as u32);
                            if need != have {
                                return Err(Fault {
                                    at: head,
                                    kind: FaultKind::PayloadLength {
                                        rule: u32::from(rule),
                                        need,
                                        have,
                                    },
                                });
                            }
                            if !writes.push(Write::Payload { at: payload_start, bytes }) {
                                return Err(writes_full(head, writes.capacity()));
                            }
                            stats.replaced += 1;
                        }
                        Action::Renumber(new_field) => {
                            let tag_w = u32::from(layer.cursor.tag_width());
                            let word = head_word(new_field, RecordKind::Len);
                            let need = encoded_len32(word);
                            if !width_fits::<MINIMAL>(need, tag_w) {
                                return Err(Fault {
                                    at: head,
                                    kind: FaultKind::TagWidth {
                                        rule: u32::from(rule),
                                        need,
                                        have: tag_w,
                                    },
                                });
                            }
                            // SAFETY: the slot width is the walk's
                            // framing window — the cursor's met tag
                            // read, 1..=5.
                            let width =
                                unsafe { WordWidth::met_unchecked(layer.cursor.tag_width()) };
                            if !writes.push(Write::Tag { at: head, width, word }) {
                                return Err(writes_full(head, writes.capacity()));
                            }
                            stats.renumbered += 1;
                            // A renumber touches the tag alone —
                            // the interior stays live (tag and
                            // interior extents are disjoint).
                            walk_in = routed;
                        }
                        Action::ReplaceRecord(bytes) => {
                            judge_replacement::<MINIMAL>(rule, bytes, head, end - head)?;
                            if !writes.push(Write::Payload { at: head, bytes }) {
                                return Err(writes_full(head, writes.capacity()));
                            }
                            stats.substituted += 1;
                        }
                        Action::Tombstone { field: filler } => {
                            let need = filler_need(filler);
                            let have = end - head;
                            if have < need {
                                return Err(Fault {
                                    at: head,
                                    kind: FaultKind::FillerUnfit {
                                        rule: u32::from(rule),
                                        need,
                                        have,
                                    },
                                });
                            }
                            if !writes.push(Write::Filler { at: head, width: have, field: filler })
                            {
                                return Err(writes_full(head, writes.capacity()));
                            }
                            stats.tombstoned += 1;
                        }
                        Action::SetVarint(_) | Action::SetI32(_) | Action::SetI64(_) => {
                            return Err(Fault {
                                at: head,
                                kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                            });
                        }
                    },
                }
                if walk_in {
                    let remaining = layer.remaining;
                    if remaining == 0 {
                        return Err(Fault { at: head, kind: FaultKind::Wire(WireBreach::Depth) });
                    }
                    matcher.commit_descent();
                    // The layer invariant's induction step
                    // (`Layer`): one less than the parent's budget,
                    // at one more stack height.
                    let remaining = remaining - 1;
                    debug_assert!(
                        usize::from(limit.as_inner() - remaining) == layers.len(),
                        "the layer invariant holds below the root"
                    );
                    // SAFETY: LEN descents decrement `remaining`
                    // from the limit, so the stack never exceeds
                    // the depth factor the lane was carved at.
                    unsafe {
                        layers.push_unchecked(Layer {
                            cursor: Cursor::within(payload),
                            base: payload_start,
                            remaining,
                        });
                    }
                    if METERED {
                        budget.layers.observe(layers.len());
                        budget.observe_matcher(matcher);
                    }
                }
            }
        }
    }
}

#[cold]
fn conflict(at: u32, first: u16, second: u16) -> Fault {
    Fault { at, kind: FaultKind::Conflict { first: u32::from(first), second: u32::from(second) } }
}

// ─── the doors ───

/// One job: the door judges the slab and carves the lanes, the
/// judge walk proves every write, then the infallible loop lands
/// them in the caller's buffer.
fn run<'r, const MINIMAL: bool, const METERED: bool>(
    buf: &mut [u8],
    rules: &RuleSet<'r>,
    limit: DepthLimit,
    plan: &Plan,
    slab: &mut [MaybeUninit<u8>],
    budget: &mut Budget,
) -> Result<Stats, Fault> {
    let caps = Caps::derive(rules, limit, plan);
    let need = caps.priced();
    if slab.len() < need {
        return Err(Fault { at: 0, kind: FaultKind::SlabShort { need, have: slab.len() } });
    }
    if METERED {
        budget.capacities(&caps);
    }
    // The carve derives from the one ladder list (`carve_ladder!`
    // above), which asserts the descending alignment and binds
    // each lane by its ladder name.
    let Lanes { mut writes, mut layers, wilds, levels, targets, stages, staged } =
        carve!(slab, &caps);
    let mut matcher = Matcher::new(*rules, MatcherLanes { targets, stages, wilds, staged, levels });
    if METERED {
        budget.observe_matcher(&matcher);
    }
    let outcome =
        walk::<MINIMAL, METERED>(buf, rules, limit, &mut writes, &mut layers, &mut matcher, budget);
    if METERED {
        // The write list never truncates, so its final length is
        // its high-water — folded here so refusals report it too.
        budget.writes.observe(writes.len());
    }
    let stats = outcome?;
    // SAFETY inheritance: the walk above judged every entry
    // against cursor-delivered geometry over these same admitted
    // bytes — the host walk's own proof, transcribed — so the
    // shared write loop's contract holds (in-bounds extents,
    // pairwise disjointness, no aliasing through the safe doors).
    commit::<MINIMAL>(buf, writes.as_slice());
    Ok(stats)
}

/// Applies `rules` to `buf` in place under tolerant acceptance,
/// with working memory carved from `slab` and the job receipt on
/// `Ok`.
///
/// The buffer is the product: on `Ok` it differs exactly at the
/// planned write extents and re-ingests under `Tolerant`; on
/// `Err` it is byte-identical to entry — every fault (the scratch
/// refusals included) precedes the first write. Within an
/// adequate plan the outcome is byte-identical to
/// `crate::inplace::groupless::apply`'s over the same job.
///
/// # Errors
///
/// [`Fault`] when the slab is shorter than [`Plan::bytes`], the
/// write list outgrows the plan, the input refuses admission, a
/// committed descent (or the top layer) hits unlawful wire (group
/// codes included — the capability refusal), two rules target one
/// record, an action does not fit its record's kind, width, or
/// extent, a replacement candidate refuses, or the depth budget
/// runs out. `buf` is untouched on `Err`.
///
/// # Examples
///
/// ```
/// use core::mem::MaybeUninit;
/// use protobuf_edit::fixed_inplace::groupless::{Plan, apply};
/// use protobuf_edit::inplace::{Action, Rule, RuleSet};
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::{DepthLimit, FieldNumber};
///
/// // Tombstone field 2: the record's extent is refilled with a
/// // zeroed field-9 filler record — the wire keeps its shape, and
/// // schema readers skip the unknown field.
/// let f2 = FieldNumber::new(2).unwrap();
/// let f9 = FieldNumber::new(9).unwrap();
/// let rules = [Rule {
///     path: &[Segment::Field(f2)],
///     action: Action::Tombstone { field: f9 },
/// }];
/// let set = RuleSet::over(&rules).unwrap();
///
/// // varint f1=150 · LEN f2 "hi"
/// let mut msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
/// let plan = Plan::new(1).unwrap();
/// let mut slab = [MaybeUninit::<u8>::uninit(); 256];
/// let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
/// assert_eq!(msg, [0x08, 0x96, 0x01, 0x48, 0x80, 0x80, 0x00]);
/// assert_eq!(stats.tombstoned(), 1);
/// ```
#[inline]
pub fn apply(
    buf: &mut [u8],
    rules: &RuleSet<'_>,
    limit: DepthLimit,
    plan: &Plan,
    slab: &mut [MaybeUninit<u8>],
) -> Result<Stats, Fault> {
    run::<false, false>(buf, rules, limit, plan, slab, &mut Budget::default())
}

/// [`apply`] under a declared acceptance [`Standard`].
///
/// The standard picks a monomorphized walk instance once at this
/// entry, so a tolerant job pays no width comparison and a
/// canonical one refuses every non-minimal varint width in the
/// wire it walks ([`WireBreach::NonMinimal`], scan-parity) *and*
/// authors none: every written word is exactly minimal at exactly
/// its slot's width, so a canonical document stays canonical
/// through any command sequence.
///
/// # Errors
///
/// As [`apply`], plus the width refusals the declared standard
/// adds. `buf` is untouched on `Err`.
///
/// # Examples
///
/// ```
/// use core::mem::MaybeUninit;
/// use protobuf_edit::fixed_inplace::groupless::{FaultKind, Plan, apply_standard};
/// use protobuf_edit::inplace::{Action, Rule, RuleSet};
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::{DepthLimit, FieldNumber, Standard};
///
/// let f1 = FieldNumber::new(1).unwrap();
/// let rules =
///     [Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(7) }];
/// let set = RuleSet::over(&rules).unwrap();
/// let plan = Plan::new(1).unwrap();
/// let mut slab = [MaybeUninit::<u8>::uninit(); 256];
///
/// // The met slot is two bytes; 7 encodes in one. The canonical
/// // job refuses the width instead of padding it.
/// let mut msg = [0x08, 0x96, 0x01];
/// let fault = apply_standard(
///     &mut msg,
///     &set,
///     Standard::CanonicalMinimal,
///     DepthLimit::REFERENCE,
///     &plan,
///     &mut slab,
/// )
/// .unwrap_err();
/// assert_eq!(fault.at(), 0);
/// assert!(matches!(
///     fault.kind(),
///     FaultKind::ValueWidth { rule: 0, need: 1, have: 2 }
/// ));
/// assert_eq!(msg, [0x08, 0x96, 0x01]); // untouched on Err
///
/// // The tolerant instance pads the same value to the slot.
/// apply_standard(&mut msg, &set, Standard::Tolerant, DepthLimit::REFERENCE, &plan, &mut slab)
///     .unwrap();
/// assert_eq!(msg, [0x08, 0x87, 0x00]);
/// ```
#[inline]
pub fn apply_standard(
    buf: &mut [u8],
    rules: &RuleSet<'_>,
    standard: Standard,
    limit: DepthLimit,
    plan: &Plan,
    slab: &mut [MaybeUninit<u8>],
) -> Result<Stats, Fault> {
    let mut budget = Budget::default();
    match standard {
        Standard::Tolerant => run::<false, false>(buf, rules, limit, plan, slab, &mut budget),
        Standard::CanonicalMinimal => {
            run::<true, false>(buf, rules, limit, plan, slab, &mut budget)
        }
    }
}

/// [`apply_standard`] with the per-lane budget beside the verdict
/// — the sizing loop's face.
///
/// The budget rides both arms: a refused job still reports the
/// high-water it reached (the write row in particular carries the
/// count at the refusal), so exhaustion diagnosis and plan sizing
/// read one face. Metering is this instance's own cost — the plain
/// faces compile without it.
///
/// # Errors
///
/// As [`apply_standard`]. `buf` is untouched on `Err`.
///
/// # Examples
///
/// ```
/// use core::mem::MaybeUninit;
/// use protobuf_edit::fixed_inplace::groupless::{Plan, apply_budget};
/// use protobuf_edit::inplace::{Action, Rule, RuleSet};
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::{DepthLimit, FieldNumber, Standard};
///
/// // Size a plan by prototyping with a generous one.
/// let f1 = FieldNumber::new(1).unwrap();
/// let rules = [Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(0) }];
/// let set = RuleSet::over(&rules).unwrap();
/// let generous = Plan::new(64).unwrap();
/// let mut slab = [MaybeUninit::<u8>::uninit(); 2048];
///
/// let mut msg = [0x08, 0x05, 0x08, 0x06]; // two f1 records
/// let (result, budget) = apply_budget(
///     &mut msg,
///     &set,
///     Standard::Tolerant,
///     DepthLimit::REFERENCE,
///     &generous,
///     &mut slab,
/// );
/// result.unwrap();
/// // The representative job needed two writes: the tight plan.
/// assert_eq!(budget.writes().used, 2);
/// assert_eq!(budget.writes().capacity, 64);
/// assert!(Plan::new(2).is_some());
/// ```
pub fn apply_budget(
    buf: &mut [u8],
    rules: &RuleSet<'_>,
    standard: Standard,
    limit: DepthLimit,
    plan: &Plan,
    slab: &mut [MaybeUninit<u8>],
) -> (Result<Stats, Fault>, Budget) {
    let mut budget = Budget::default();
    let result = match standard {
        Standard::Tolerant => run::<false, true>(buf, rules, limit, plan, slab, &mut budget),
        Standard::CanonicalMinimal => run::<true, true>(buf, rules, limit, plan, slab, &mut budget),
    };
    (result, budget)
}

#[cfg(test)]
mod tests;
