//! The grouped fixed-scratch in-place editor: all six codes, group
//! tags paired in the walk, working memory carved from the
//! caller's slab.
//!
//! The job is `crate::inplace::grouped`'s exactly: groups carry
//! no length prefix, so a group's extent — start tag through its
//! verified end tag — is a walked fact; renumbering a group
//! rewrites both framing tags as one atomic pair (each judged at
//! its own met width before either write is listed); tombstone and
//! whole-record replacement own the whole verified group extent;
//! groups and committed LEN crossings spend one depth account.
//! Within an adequate plan the two twins are byte-identical in
//! buffer outcome, receipt, and fault.
//!
//! The memory plane is the carved one: the walk steps the wire
//! directly over a caller-scratch pairing stack (this dialect's
//! stepping is hand-rolled here — the heap cursor keeps its open
//! stack on the allocator), and the layer stack, matcher tables,
//! pending renumber pairs, and write list are slab lanes beside
//! it. A whole-record replacement candidate re-parses over the
//! pairing lane's free tail, which the walk's depth accounting
//! proves large enough for the candidate's own budget.
//!
//! The door judges the slab against [`Plan::bytes`] before reading
//! anything ([`FaultKind::SlabShort`]); the walk refuses a write
//! list outgrowing the plan at the judged record
//! ([`FaultKind::WriteListFull`]). Both refusals precede the first
//! buffer write and repair by declaring more — the Policy class's
//! shape.
//!
//! Coordinates: write · buffered · static · grouped · Standard (value-level) · in-place · commit-only · fixed scratch.
//!
//! # Examples
//!
//! ```
//! use core::mem::MaybeUninit;
//! use protobuf_edit::fixed_inplace::grouped::{Plan, apply};
//! use protobuf_edit::inplace::{Action, Rule, RuleSet};
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Renumber the field-1 group to field 2: start and end tags
//! // rewrite as one pair, the interior rides untouched.
//! let f1 = FieldNumber::new(1).unwrap();
//! let rules = [Rule {
//!     path: &[Segment::Field(f1)],
//!     action: Action::Renumber(FieldNumber::new(2).unwrap()),
//! }];
//! let set = RuleSet::over(&rules).unwrap();
//!
//! // group f1 { varint f2=150 } · varint f3=7
//! let mut msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x07];
//! let plan = Plan::new(2).unwrap(); // a pair plans two writes
//! let mut slab = [MaybeUninit::<u8>::uninit(); 8192];
//! let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
//! assert_eq!(msg, [0x13, 0x10, 0x96, 0x01, 0x14, 0x18, 0x07]);
//! assert_eq!(stats.renumbered(), 1);
//! ```

use core::mem::MaybeUninit;

use super::{Gauge, Hits, Lane, Marks, Matcher, MatcherLanes, State, Stats, depth_factor, path_stats};
use crate::admission::{self, admitted_u32, usize_of};
use crate::inplace::{Action, RuleSet, Write, action, commit, filler_need, width_fits};
use crate::varint::{ValueWidth, WordWidth, encoded_len32, encoded_len64, slice};
use crate::wire::FieldNumber;
use crate::wire::grouped::{RecordKind, TagClass, classify, group_end_word, head_word};
use crate::wire::Low3;
use crate::{DepthLimit, FaultClass, Standard};

/// The one caller-declared capacity: the write list's entry count.
/// Everything else the job needs is derived from the rule set and
/// the [`DepthLimit`] by the door.
///
/// One entry serves one planned write — every landing action plans
/// one, except a group renumber, whose atomic pair plans two.
/// Zero is lawful (a judge-only job over rules that match
/// nothing).
///
/// # Examples
///
/// ```
/// use protobuf_edit::fixed_inplace::grouped::Plan;
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
    /// use protobuf_edit::fixed_inplace::grouped::Plan;
    /// use protobuf_edit::inplace::{Action, Rule, RuleSet};
    /// use protobuf_edit::path::Segment;
    /// use protobuf_edit::{DepthLimit, FieldNumber};
    ///
    /// let f1 = FieldNumber::new(1).unwrap();
    /// let rules = [Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(0) }];
    /// let set = RuleSet::over(&rules).unwrap();
    ///
    /// // A deeper budget prices a bigger slab, deterministically.
    /// let shallow = Plan::new(1).unwrap().bytes(&set, DepthLimit::MIN);
    /// let deep = Plan::new(1).unwrap().bytes(&set, DepthLimit::REFERENCE);
    /// assert!(shallow < deep);
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
    /// demand derivation in [`crate::fixed_inplace`], plus this
    /// dialect's group lanes): suspended matcher marks (`levels`)
    /// and open-group pairing entries (`opens`) are depth-bounded
    /// — every walked container and every open group spends one
    /// depth account — and pending renumber pairs ride the
    /// open-group bound, zero when no rule renumbers.
    fn derive(rules: &RuleSet<'_>, limit: DepthLimit, plan: &Plan) -> Self {
        let stats = path_stats(rules);
        let depth = depth_factor(&stats, limit);
        let bound = usize::from(limit.as_inner());
        Self {
            writes: usize_of(plan.writes),
            layers: depth,
            levels: bound,
            targets: stats.targets.saturating_mul(depth),
            stages: stats.stages.saturating_mul(depth),
            wilds: stats.wilds.saturating_mul(depth),
            staged: stats.stages.saturating_add(stats.wilds),
            opens: bound,
            pending: if stats.any_renumber { bound } else { 0 },
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
    opens: Gauge,
    pending: Gauge,
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

    /// The matcher's suspended layer marks (every walked
    /// container — group or LEN — commits one).
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

    /// The walk's open-group pairing stack (a replacement
    /// candidate's transient probe rides the free tail and is
    /// bounded by its own budget, so it is not a sizing datum).
    #[inline]
    #[must_use]
    pub const fn opens(&self) -> Gauge {
        self.opens
    }

    /// The pending renumber pairs.
    #[inline]
    #[must_use]
    pub const fn pending(&self) -> Gauge {
        self.pending
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
        self.opens.capacity = caps.opens;
        self.pending.capacity = caps.pending;
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
    /// names. For the width refusals: the record head — except
    /// [`FaultKind::TagWidth`] on a group's end tag, which names
    /// that tag's own site (the pair's two judgments carry their
    /// own coordinates). For [`FaultKind::SlabShort`]: zero — the
    /// refusal precedes the walk.
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

/// The grouped fixed in-place editor's refusal classes: the host
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
    /// The walk (or a committed descent) hit unlawful wire — the
    /// grouped traversal vocabulary, unrewrapped (canonical jobs
    /// surface non-minimal widths here, scan-parity).
    Wire(WireBreach),
    /// Two rules target one record.
    Conflict {
        /// The first targeting rule.
        first: u32,
        /// The second targeting rule.
        second: u32,
    },
    /// The rule's action does not fit the record's wire kind
    /// (`SetPayload` on a group lands here: groups have no single
    /// opaque payload extent).
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
    /// `Renumber`: a new tag word's minimal encoding vs its met
    /// tag slot — a group's start and end tags are judged
    /// independently, each at its own coordinate.
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
    /// job's dialect and standard at the target's remaining depth
    /// budget.
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
    /// Group framing broke (orphaned, mismatched, or unclosed).
    Grouping,
    /// Container nesting (groups and committed LEN crossings spend
    /// one account) exceeded the caller's declared [`DepthLimit`]
    /// budget.
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// canonical job faces' declared standard (the tolerant faces
    /// never judge widths).
    NonMinimal,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget; [`NonMinimal`] is the
    /// canonical faces' standard); this dialect has no capability
    /// member (its language is the format's whole code alphabet).
    ///
    /// [`Depth`]: Self::Depth
    /// [`NonMinimal`]: Self::NonMinimal
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Varint | Self::Tag | Self::Truncated | Self::Grouping => FaultClass::Grammar,
            Self::Depth | Self::NonMinimal => FaultClass::Policy,
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
            Self::Grouping => "broken group framing",
            Self::Depth => "nesting past the declared depth budget",
            Self::NonMinimal => "a varint word wider than its minimal encoding",
        })
    }
}

impl core::error::Error for WireBreach {}

// The fault vocabulary is plain copyable data (no trail
// allocation: rule indices, byte coordinates, and the two scratch
// need/have pairs name everything), pinned per pointer width.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<FaultKind>() == if w64 { 24 } else { 16 });
    assert!(core::mem::size_of::<Fault>() == if w64 { 32 } else { 20 });
};

// ─── the hand-rolled grouped stepping (phase one's wire layer) ───

/// One delivered record: the field and the decoded observation.
struct Entry<'a> {
    field: FieldNumber,
    kind: EntryKind<'a>,
}

/// The observation a delivered record carries — the grouped
/// dialect's complete delivery set. The walk consumes kinds and
/// geometry alone, so scalar deliveries carry no decoded value
/// (the stepper still judges their widths and bounds).
enum EntryKind<'a> {
    /// A varint record (value judged and skipped).
    Varint,
    /// An I64 record (eight payload bytes judged and skipped).
    I64,
    /// A LEN record's borrowed payload — opaque here; descent is
    /// the walk's own decision.
    Len(&'a [u8]),
    /// A group opened (the entry names its field).
    GroupEnter,
    /// The innermost open group closed (the entry names its
    /// field).
    GroupExit,
    /// An I32 record (four payload bytes judged and skipped).
    I32,
}

/// The grouped wire stepper over one window, pairing groups on a
/// caller-scratch lane instead of a heap stack — otherwise the
/// heap cursor's walk verbatim: judgment per record, in order, is
/// the tag word, minimality (canonical instances), field zero, the
/// code class, then the code's own payload discipline. Faults are
/// delivered pre-collapsed into this cell's [`WireBreach`]
/// vocabulary at their local byte coordinate; the walk aborts on
/// the first one, so no fused state exists.
struct StepCursor<'a> {
    /// The walked window.
    data: &'a [u8],
    /// The next unread byte (equally: the last delivered record's
    /// end).
    at: usize,
    /// Byte width of the most recently delivered record's head
    /// tag.
    tag_w: u8,
}

impl<'a> StepCursor<'a> {
    /// Stands a walk at a window's head. The window is either the
    /// admitted input or a cursor-delivered payload — both inside
    /// the LEN class, so every coordinate fits `u32`.
    const fn over(data: &'a [u8]) -> Self {
        Self { data, at: 0, tag_w: 0 }
    }

    /// Byte offset just past the most recently delivered record.
    #[inline]
    const fn pos(&self) -> u32 {
        admitted_u32(self.at)
    }

    /// Byte width of the most recently delivered record's head
    /// tag.
    #[inline]
    const fn tag_width(&self) -> u8 {
        self.tag_w
    }

    /// One walk step, one instance per acceptance standard.
    ///
    /// `opens` is the pairing stack and `floor` this window's
    /// region start within it: enters push, exits pop and verify,
    /// the window end owes emptiness back to the floor, and a
    /// region reaching `limit` entries refuses the next enter as
    /// [`WireBreach::Depth`] before delivering it. The lane's
    /// capacity covers every push: the walk's layer invariant
    /// (`Layer`) bounds the lane's occupancy — every ancestor's
    /// region plus the current layer's — at the limit the lane was
    /// carved at, and holds the free tail at or above every
    /// replacement probe's budget, so a probe's window is covered
    /// too.
    #[allow(
        clippy::too_many_lines,
        reason = "one record fold — the dialect's whole wire judgment in one place, \
                  the heap cursor's own skeleton"
    )]
    fn step<const MINIMAL: bool>(
        &mut self,
        opens: &mut Lane<'_, (FieldNumber, u32)>,
        floor: usize,
        limit: u16,
    ) -> Option<Result<Entry<'a>, (u32, WireBreach)>> {
        let data = self.data;
        let end = data.len();
        let head = self.at;
        // Equality is the clean end. The hint keeps the delivery
        // tail on the fallthrough path — one jump per record.
        if core::hint::unlikely(head >= end) {
            if opens.len() > floor {
                // A group still open when the window ends — the
                // pairing lane's region owes emptiness.
                return Some(Err((admitted_u32(head), WireBreach::Grouping)));
            }
            return None;
        }
        let (word, tag_w) = match slice::tag_word(data, head, end) {
            Ok(read) => read,
            Err(_) => return Some(Err((admitted_u32(head), WireBreach::Varint))),
        };
        if MINIMAL && u32::from(tag_w) != encoded_len32(word) {
            return Some(Err((admitted_u32(head), WireBreach::NonMinimal)));
        }
        let Some(field) = FieldNumber::from_word(word) else {
            return Some(Err((admitted_u32(head), WireBreach::Tag)));
        };
        let low3 = Low3::from_word(word);
        let value_at = head + usize::from(tag_w);
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                let (value, width) = match slice::value64(data, value_at, end) {
                    Ok(read) => read,
                    Err(_) => return Some(Err((admitted_u32(value_at), WireBreach::Varint))),
                };
                if MINIMAL && u32::from(width) != encoded_len64(value) {
                    return Some(Err((admitted_u32(value_at), WireBreach::NonMinimal)));
                }
                self.at = value_at + usize::from(width);
                self.tag_w = tag_w;
                Some(Ok(Entry { field, kind: EntryKind::Varint }))
            }
            TagClass::Record(RecordKind::I64) => {
                if end - value_at < 8 {
                    return Some(Err((admitted_u32(value_at), WireBreach::Truncated)));
                }
                self.at = value_at + 8;
                self.tag_w = tag_w;
                Some(Ok(Entry { field, kind: EntryKind::I64 }))
            }
            TagClass::Record(RecordKind::I32) => {
                if end - value_at < 4 {
                    return Some(Err((admitted_u32(value_at), WireBreach::Truncated)));
                }
                self.at = value_at + 4;
                self.tag_w = tag_w;
                Some(Ok(Entry { field, kind: EntryKind::I32 }))
            }
            TagClass::Record(RecordKind::Len) => {
                let (len, width) = match slice::len_word(data, value_at, end) {
                    Ok(read) => read,
                    Err(_) => return Some(Err((admitted_u32(value_at), WireBreach::Varint))),
                };
                if MINIMAL && u32::from(width) != encoded_len32(len.as_inner()) {
                    return Some(Err((admitted_u32(value_at), WireBreach::NonMinimal)));
                }
                let payload_at = value_at + usize::from(width);
                let need = usize_of(len.as_inner());
                if end - payload_at < need {
                    return Some(Err((admitted_u32(payload_at), WireBreach::Truncated)));
                }
                // SAFETY: `need` bytes past `payload_at` were just
                // proven in bounds.
                let payload = unsafe { data.get_unchecked(payload_at..payload_at + need) };
                self.at = payload_at + need;
                self.tag_w = tag_w;
                Some(Ok(Entry { field, kind: EntryKind::Len(payload) }))
            }
            TagClass::Record(RecordKind::Group) => {
                if opens.len() - floor >= usize::from(limit) {
                    return Some(Err((admitted_u32(head), WireBreach::Depth)));
                }
                // SAFETY: in bounds by the layer invariant
                // (`Layer`). At the root, `floor` is zero and the
                // guard above refused the limit-th entry; below
                // the root, `floor + remaining` sits under the
                // limit and the walk's enter judgments keep this
                // region within `remaining`, so even the one
                // delivered-then-refused enter stays at or below
                // the lane's carve. A probe's window is the free
                // tail, which the same invariant holds at or above
                // the probe's budget.
                unsafe { opens.push_unchecked((field, admitted_u32(head))) };
                self.at = value_at;
                self.tag_w = tag_w;
                Some(Ok(Entry { field, kind: EntryKind::GroupEnter }))
            }
            TagClass::GroupEnd => {
                if opens.len() == floor {
                    // An end tag with no group open in this window.
                    return Some(Err((admitted_u32(head), WireBreach::Grouping)));
                }
                // The region is non-empty: the pop delivers.
                let Some((open, _)) = opens.pop() else {
                    unreachable!("the region emptiness was just judged")
                };
                if open != field {
                    return Some(Err((admitted_u32(head), WireBreach::Grouping)));
                }
                self.at = value_at;
                self.tag_w = tag_w;
                Some(Ok(Entry { field, kind: EntryKind::GroupExit }))
            }
            TagClass::Unassigned => Some(Err((admitted_u32(head), WireBreach::Tag))),
        }
    }
}

// ─── the judge walk (phase one) ───

/// One committed LEN layer on the carved stack.
///
/// The depth-accounting invariant, asserted at every layer push:
/// `floor + remaining <= limit` (the job's [`DepthLimit`]), with
/// equality exactly at the root — a committed LEN descent hands
/// its child `floor + group_depth` and `remaining - group_depth -
/// 1`, so the sum drops by one per level. Within a layer the
/// walk's enter judgments hold `group_depth` (plus the suppressed
/// count while an owned group is crossed) at or below
/// `remaining`. Together these bound the pairing lane's occupancy
/// — every ancestor's region plus this layer's — at `limit`, the
/// lane's own carve, even across the one transient push a
/// delivered-then-refused enter makes below the root; and they
/// leave the lane's free tail holding at least `remaining -
/// group_depth` entries, every replacement probe's whole budget.
struct Layer<'i> {
    cursor: StepCursor<'i>,
    /// Absolute base of this layer's window.
    base: u32,
    /// This layer's region start in the pairing lane.
    floor: u32,
    /// Depth budget left inside this layer (containers: groups
    /// and committed LEN crossings spend one account).
    remaining: u16,
    /// Open walked groups inside this layer.
    group_depth: u16,
}

const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(core::mem::size_of::<Layer<'_>>() == if w64 { 48 } else { 28 });
    assert!(core::mem::align_of::<Layer<'_>>() == if w64 { 8 } else { 4 });
};

/// A group renumber staged at its enter: both tags are judged
/// before either write is listed. The start judgment settles at
/// the enter and its write is held here; the end judgment settles
/// at the verified exit, and only then do the pair's two entries
/// land — the pair is atomic at the record.
struct PendingPair {
    /// The judged start write's destination.
    start_at: u32,
    /// The judged start write's word.
    start_word: u32,
    /// The keyed position's layer count (groups nest properly, so
    /// the pending lane's tail is always the innermost open
    /// renumber).
    layer: u32,
    /// The renumber's target field (the end word derives from it
    /// at the exit).
    field: FieldNumber,
    /// The keyed position's in-layer depth.
    depth: u16,
    /// The owning rule.
    rule: u16,
    /// The judged start write's met width (the cursor's tag
    /// window).
    start_width: WordWidth,
}

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
    assert!(size_of::<(FieldNumber, u32)>() == 8 && align_of::<(FieldNumber, u32)>() == 4);
    assert!(size_of::<PendingPair>() == 24 && align_of::<PendingPair>() == 4);
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
        opens: (FieldNumber, u32),
        pending: PendingPair,
        staged: State,
    }
}

/// A group wholly owned by its rule (`Tombstone`,
/// `ReplaceRecord`): interior events are skipped while the walk
/// verifies pairing, and the write is judged at the verified exit,
/// where the whole extent is first known.
enum Owned<'r> {
    /// The extent refills with filler records at the exit.
    Tombstone {
        /// The owning rule.
        rule: u16,
        /// The group's start-tag offset.
        head: u32,
        /// The filler field.
        field: FieldNumber,
    },
    /// The extent is replaced whole at the exit.
    Replace {
        /// The owning rule.
        rule: u16,
        /// The group's start-tag offset.
        head: u32,
        /// The replacement candidate.
        bytes: &'r [u8],
        /// The record's remaining in-band nesting budget, captured
        /// at its enter — the candidate re-parses under it.
        budget: u16,
    },
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
/// re-parse as exactly one complete record — a balanced group
/// included — under the job's standard and the target's remaining
/// depth budget. LEN payloads inside the candidate stay opaque
/// exactly as in source parsing; in-band group nesting charges
/// `budget` through the probe's own step bound, so a substituted
/// record cannot smuggle nesting past the declared limit. The
/// probe's pairing stack is the walk lane's free tail, which the
/// walk's layer invariant (`Layer`) holds at least `budget`
/// entries wide.
fn judge_replacement<const MINIMAL: bool>(
    rule: u16,
    bytes: &[u8],
    head: u32,
    have: u32,
    budget: u16,
    opens: &mut Lane<'_, (FieldNumber, u32)>,
) -> Result<(), Fault> {
    let rule = u32::from(rule);
    // Lossless: the authoring door judged the candidate into the
    // LEN class.
    #[allow(clippy::as_conversions, reason = "authoring admitted the candidate to the LEN class")]
    let need = bytes.len() as u32;
    if need != have {
        return Err(Fault { at: head, kind: FaultKind::ReplacementLength { rule, need, have } });
    }
    debug_assert!(bytes.len() <= admission::MAX, "the LEN class bounds the candidate");
    let mut probe_opens = opens.tail();
    let mut probe = StepCursor::over(bytes);
    loop {
        match probe.step::<MINIMAL>(&mut probe_opens, 0, budget) {
            Some(Ok(_)) => {
                if probe_opens.len() == 0 {
                    return if probe.pos() == have {
                        Ok(())
                    } else {
                        Err(Fault { at: head, kind: FaultKind::ReplacementShape { rule } })
                    };
                }
            }
            Some(Err((at, breach))) => {
                return Err(Fault {
                    at: head,
                    kind: FaultKind::ReplacementWire { rule, at, breach },
                });
            }
            // The extent equality held, so the candidate is
            // nonempty, and the stepper faults an unclosed group at
            // the window end itself: every path delivers or refuses
            // before exhaustion.
            None => unreachable!("a nonempty window steps or faults"),
        }
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
#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are this dialect's carved lanes, split by the door and \
              consumed here once — a bundling struct would exist for one call"
)]
fn walk<'r, 'i, const MINIMAL: bool, const METERED: bool>(
    input: &'i [u8],
    set: &RuleSet<'r>,
    limit: DepthLimit,
    writes: &mut Lane<'_, Write<'r>>,
    layers: &mut Lane<'_, Layer<'i>>,
    opens: &mut Lane<'_, (FieldNumber, u32)>,
    pending: &mut Lane<'_, PendingPair>,
    matcher: &mut Matcher<'r, '_>,
    budget: &mut Budget,
) -> Result<Stats, Fault> {
    let mut stats = Stats::default();
    if input.len() > admission::MAX {
        return Err(Fault { at: 0, kind: FaultKind::Oversize });
    }
    // The layer invariant's base case (`Layer`): the root owns the
    // whole limit at floor zero.
    let (floor, remaining) = (0u32, limit.as_inner());
    debug_assert!(
        floor + u32::from(remaining) <= u32::from(limit.as_inner()),
        "the layer invariant holds at the root"
    );
    // SAFETY: the layer lane's capacity is the depth factor, at
    // least one — the root's own slot.
    unsafe {
        layers.push_unchecked(Layer {
            cursor: StepCursor::over(input),
            base: 0,
            floor,
            remaining,
            group_depth: 0,
        });
    }
    if METERED {
        budget.layers.observe(layers.len());
    }
    // Depth inside the group currently being wholly overwritten
    // (0 = none). While suppressing, interior events are skipped
    // for matching only: the extent refills as one write, so no
    // rule fires inside — but every group enter still spends the
    // one depth account (admission never depends on which rules
    // the job carries), and the walk verifies every pairing.
    let mut suppress: u32 = 0;
    let mut owned: Option<Owned<'r>> = None;

    loop {
        let layer_count = layers.len();
        // SAFETY: the root layer is pushed above and the only pop
        // sits behind the `len == 1` return below, so the lane is
        // never empty here.
        let layer = unsafe { layers.last_mut_unchecked() };
        let base = layer.base;
        let head = base + layer.cursor.pos();
        let Some(item) =
            layer.cursor.step::<MINIMAL>(opens, usize_of(layer.floor), limit.as_inner())
        else {
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
            Err((at, breach)) => {
                return Err(Fault { at: base + at, kind: FaultKind::Wire(breach) });
            }
        };
        if METERED {
            budget.opens.observe(opens.len());
        }
        let end = base + layer.cursor.pos();

        if suppress > 0 {
            match entry.kind {
                EntryKind::GroupEnter => {
                    // Suppressed enters spend the same positional
                    // account as walked ones: the opens above are
                    // the layer's walked groups plus the owned
                    // extent's own unclosed enters.
                    if u32::from(layer.group_depth) + suppress == u32::from(layer.remaining) {
                        return Err(Fault { at: head, kind: FaultKind::Wire(WireBreach::Depth) });
                    }
                    suppress += 1;
                }
                EntryKind::GroupExit => {
                    suppress -= 1;
                    if suppress == 0 {
                        // The owned group's extent is now known:
                        // its exit judgment runs here, against the
                        // start-to-end span.
                        match owned.take() {
                            Some(Owned::Tombstone { rule, head, field }) => {
                                let need = filler_need(field);
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
                                if !writes.push(Write::Filler { at: head, width: have, field }) {
                                    return Err(writes_full(head, writes.capacity()));
                                }
                                stats.tombstoned += 1;
                            }
                            Some(Owned::Replace { rule, head, bytes, budget: probe_budget }) => {
                                judge_replacement::<MINIMAL>(
                                    rule,
                                    bytes,
                                    head,
                                    end - head,
                                    probe_budget,
                                    opens,
                                )?;
                                if !writes.push(Write::Payload { at: head, bytes }) {
                                    return Err(writes_full(head, writes.capacity()));
                                }
                                stats.substituted += 1;
                            }
                            // Suppression starts only where an
                            // owner is staged.
                            None => unreachable!("suppression carries its owner"),
                        }
                    }
                }
                EntryKind::Varint | EntryKind::I64 | EntryKind::Len(_) | EntryKind::I32 => {}
            }
            continue;
        }

        let field = entry.field;
        match entry.kind {
            EntryKind::GroupExit => {
                // An end tag is punctuation, not a record: no rule
                // judgment of its own — but a pending renumber
                // keyed at this group completes here, where the
                // end tag's met width (an independent fact) is
                // first known.
                matcher.exit();
                #[allow(
                    clippy::as_conversions,
                    reason = "layer counts stay inside the depth domain"
                )]
                let key = (layer_count as u32, layer.group_depth);
                if pending.last().map(|pair| (pair.layer, pair.depth)) == Some(key) {
                    // The peek above is `Some`: the pop delivers.
                    let Some(pair) = pending.pop() else { unreachable!("the peek above is Some") };
                    let have = u32::from(layer.cursor.tag_width());
                    let word = group_end_word(pair.field);
                    let need = encoded_len32(word);
                    if !width_fits::<MINIMAL>(need, have) {
                        return Err(Fault {
                            at: head,
                            kind: FaultKind::TagWidth { rule: u32::from(pair.rule), need, have },
                        });
                    }
                    if !writes.push(Write::Tag {
                        at: pair.start_at,
                        width: pair.start_width,
                        word: pair.start_word,
                    }) {
                        return Err(writes_full(pair.start_at, writes.capacity()));
                    }
                    // SAFETY: the slot width is the walk's framing
                    // window — the cursor's met end-tag read,
                    // 1..=5.
                    let width = unsafe { WordWidth::met_unchecked(layer.cursor.tag_width()) };
                    if !writes.push(Write::Tag { at: head, width, word }) {
                        return Err(writes_full(pair.start_at, writes.capacity()));
                    }
                    stats.renumbered += 1;
                }
                layer.group_depth -= 1;
            }
            EntryKind::GroupEnter => {
                let (hits, _routed) = matcher.probe(field);
                if METERED {
                    budget.observe_matcher(matcher);
                }
                match hits {
                    Hits::Conflict(first, second) => {
                        return Err(conflict(head, first, second));
                    }
                    Hits::One(rule) => match action(set, rule) {
                        Action::Renumber(new_field) => {
                            // A renumbered group still crosses by
                            // syntax: same budget, same matcher
                            // scope as an untargeted one — only
                            // its two framing tags rewrite.
                            if layer.group_depth == layer.remaining {
                                return Err(Fault {
                                    at: head,
                                    kind: FaultKind::Wire(WireBreach::Depth),
                                });
                            }
                            let have = u32::from(layer.cursor.tag_width());
                            let word = head_word(new_field, RecordKind::Group);
                            let need = encoded_len32(word);
                            if !width_fits::<MINIMAL>(need, have) {
                                return Err(Fault {
                                    at: head,
                                    kind: FaultKind::TagWidth { rule: u32::from(rule), need, have },
                                });
                            }
                            matcher.commit_descent();
                            layer.group_depth += 1;
                            #[allow(
                                clippy::as_conversions,
                                reason = "layer counts stay inside the depth domain"
                            )]
                            // SAFETY: one pending pair per open
                            // renumbered group, and open groups
                            // spend depth accounts — the lane was
                            // carved at the limit; the start width
                            // is the walk's framing window (the
                            // cursor's met tag read, 1..=5).
                            unsafe {
                                pending.push_unchecked(PendingPair {
                                    start_at: head,
                                    start_word: word,
                                    layer: layer_count as u32,
                                    field: new_field,
                                    depth: layer.group_depth,
                                    rule,
                                    start_width: WordWidth::met_unchecked(layer.cursor.tag_width()),
                                });
                            }
                            if METERED {
                                budget.pending.observe(pending.len());
                                budget.observe_matcher(matcher);
                            }
                        }
                        Action::Tombstone { field: filler } => {
                            // The owned group still crosses by
                            // syntax: its enter spends the account.
                            if layer.group_depth == layer.remaining {
                                return Err(Fault {
                                    at: head,
                                    kind: FaultKind::Wire(WireBreach::Depth),
                                });
                            }
                            suppress = 1;
                            owned = Some(Owned::Tombstone { rule, head, field: filler });
                        }
                        Action::ReplaceRecord(bytes) => {
                            // The owned group still crosses by
                            // syntax: its enter spends the account.
                            if layer.group_depth == layer.remaining {
                                return Err(Fault {
                                    at: head,
                                    kind: FaultKind::Wire(WireBreach::Depth),
                                });
                            }
                            suppress = 1;
                            owned = Some(Owned::Replace {
                                rule,
                                head,
                                bytes,
                                budget: layer.remaining - layer.group_depth,
                            });
                        }
                        Action::SetVarint(_)
                        | Action::SetI32(_)
                        | Action::SetI64(_)
                        | Action::SetPayload(_) => {
                            return Err(Fault {
                                at: head,
                                kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                            });
                        }
                    },
                    Hits::None => {
                        // Groups cross by syntax (the body is
                        // force-walked either way); the matcher
                        // scopes the body so its fields match at
                        // group level. The walker owns the whole
                        // container budget, and every depth
                        // refusal — the walker's or the stepper's
                        // own — spells the one public verdict.
                        if layer.group_depth == layer.remaining {
                            return Err(Fault {
                                at: head,
                                kind: FaultKind::Wire(WireBreach::Depth),
                            });
                        }
                        matcher.commit_descent();
                        layer.group_depth += 1;
                        if METERED {
                            budget.observe_matcher(matcher);
                        }
                    }
                }
            }
            EntryKind::Varint | EntryKind::I32 | EntryKind::I64 => {
                let rule = match matcher.probe_target(field) {
                    Hits::None => continue,
                    Hits::One(rule) => rule,
                    Hits::Conflict(first, second) => {
                        return Err(conflict(head, first, second));
                    }
                };
                let tag_w = u32::from(layer.cursor.tag_width());
                let value_at = head + tag_w;
                match (action(set, rule), entry.kind) {
                    (Action::SetVarint(value), EntryKind::Varint) => {
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
                    (Action::SetI32(bits), EntryKind::I32) => {
                        if !writes.push(Write::Fixed32 { at: value_at, bits }) {
                            return Err(writes_full(head, writes.capacity()));
                        }
                        stats.replaced += 1;
                    }
                    (Action::SetI64(bits), EntryKind::I64) => {
                        if !writes.push(Write::Fixed64 { at: value_at, bits }) {
                            return Err(writes_full(head, writes.capacity()));
                        }
                        stats.replaced += 1;
                    }
                    (Action::Renumber(new_field), kind) => {
                        let kind = match kind {
                            EntryKind::Varint => RecordKind::Varint,
                            EntryKind::I32 => RecordKind::I32,
                            EntryKind::I64 => RecordKind::I64,
                            // The enclosing arm admits exactly the
                            // three scalar kinds.
                            EntryKind::Len(_) | EntryKind::GroupEnter | EntryKind::GroupExit => {
                                unreachable!("scalar-arm renumber")
                            }
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
                        judge_replacement::<MINIMAL>(
                            rule,
                            bytes,
                            head,
                            end - head,
                            layer.remaining - layer.group_depth,
                            opens,
                        )?;
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
                // The payload was delivered by the stepper from
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
                            // the interior stays live.
                            walk_in = routed;
                        }
                        Action::ReplaceRecord(bytes) => {
                            judge_replacement::<MINIMAL>(
                                rule,
                                bytes,
                                head,
                                end - head,
                                layer.remaining - layer.group_depth,
                                opens,
                            )?;
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
                    let (group_depth, remaining) = (layer.group_depth, layer.remaining);
                    if group_depth == remaining {
                        return Err(Fault { at: head, kind: FaultKind::Wire(WireBreach::Depth) });
                    }
                    matcher.commit_descent();
                    // The layer invariant's induction step
                    // (`Layer`): the child's floor is the parent's
                    // plus its walked groups, its budget what the
                    // crossing leaves, so the sum drops by one.
                    let (floor, remaining) =
                        (admitted_u32(opens.len()), remaining - group_depth - 1);
                    debug_assert!(
                        floor + u32::from(remaining) < u32::from(limit.as_inner()),
                        "the layer invariant holds below the root"
                    );
                    // SAFETY: LEN descents shrink the child's
                    // remaining budget below the parent's, so the
                    // stack never exceeds the depth factor the
                    // lane was carved at.
                    unsafe {
                        layers.push_unchecked(Layer {
                            cursor: StepCursor::over(payload),
                            base: payload_start,
                            floor,
                            remaining,
                            group_depth: 0,
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
    let Lanes {
        mut writes,
        mut layers,
        wilds,
        levels,
        targets,
        stages,
        mut opens,
        mut pending,
        staged,
    } = carve!(slab, &caps);
    let mut matcher = Matcher::new(*rules, MatcherLanes { targets, stages, wilds, staged, levels });
    if METERED {
        budget.observe_matcher(&matcher);
    }
    let outcome = walk::<MINIMAL, METERED>(
        buf,
        rules,
        limit,
        &mut writes,
        &mut layers,
        &mut opens,
        &mut pending,
        &mut matcher,
        budget,
    );
    if METERED {
        // The write list never truncates, so its final length is
        // its high-water — folded here so refusals report it too.
        budget.writes.observe(writes.len());
    }
    let stats = outcome?;
    // SAFETY inheritance: the walk above judged every entry
    // against stepper-delivered geometry over these same admitted
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
/// `crate::inplace::grouped::apply`'s over the same job.
///
/// # Errors
///
/// [`Fault`] when the slab is shorter than [`Plan::bytes`], the
/// write list outgrows the plan, the input refuses admission, the
/// walk (or a committed descent) hits unlawful wire — broken group
/// framing included — two rules target one record, an action does
/// not fit its record's kind, width, or extent, a replacement
/// candidate refuses, or the depth budget runs out. `buf` is
/// untouched on `Err`.
///
/// # Examples
///
/// ```
/// use core::mem::MaybeUninit;
/// use protobuf_edit::fixed_inplace::grouped::{Plan, apply};
/// use protobuf_edit::inplace::{Action, Rule, RuleSet};
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::{DepthLimit, FieldNumber};
///
/// // Tombstone the whole field-1 group: the extent — start tag
/// // through end tag — refills with one zeroed field-9 filler.
/// let f1 = FieldNumber::new(1).unwrap();
/// let f9 = FieldNumber::new(9).unwrap();
/// let rules = [Rule {
///     path: &[Segment::Field(f1)],
///     action: Action::Tombstone { field: f9 },
/// }];
/// let set = RuleSet::over(&rules).unwrap();
///
/// // group f1 { varint f2=150 } · varint f3=7
/// let mut msg = [0x0B, 0x10, 0x96, 0x01, 0x0C, 0x18, 0x07];
/// let plan = Plan::new(1).unwrap();
/// let mut slab = [MaybeUninit::<u8>::uninit(); 8192];
/// let stats = apply(&mut msg, &set, DepthLimit::REFERENCE, &plan, &mut slab).unwrap();
/// assert_eq!(msg, [0x48, 0x80, 0x80, 0x80, 0x00, 0x18, 0x07]);
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
/// wire it walks — group framing tags included, scan-parity —
/// ([`WireBreach::NonMinimal`]) *and* authors none: every written
/// word is exactly minimal at exactly its slot's width, so a
/// canonical document stays canonical through any command
/// sequence.
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
/// use protobuf_edit::fixed_inplace::grouped::{Plan, apply_standard};
/// use protobuf_edit::inplace::{Action, Rule, RuleSet};
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::{DepthLimit, FieldNumber, Standard};
///
/// // A group under a padded start tag: tolerant input the
/// // canonical job refuses at admission, width-first.
/// let f1 = FieldNumber::new(1).unwrap();
/// let rules = [Rule {
///     path: &[Segment::Field(f1)],
///     action: Action::Renumber(FieldNumber::new(2).unwrap()),
/// }];
/// let set = RuleSet::over(&rules).unwrap();
/// let plan = Plan::new(2).unwrap();
/// let mut slab = [MaybeUninit::<u8>::uninit(); 8192];
///
/// let mut padded = [0x8B, 0x00, 0x0C];
/// let fault = apply_standard(
///     &mut padded,
///     &set,
///     Standard::CanonicalMinimal,
///     DepthLimit::REFERENCE,
///     &plan,
///     &mut slab,
/// )
/// .unwrap_err();
/// assert_eq!(fault.at(), 0);
/// assert_eq!(padded, [0x8B, 0x00, 0x0C]); // untouched on Err
///
/// // The tolerant instance renumbers the pair at its met widths:
/// // the padded start stays two bytes wide, the end stays one.
/// apply_standard(
///     &mut padded,
///     &set,
///     Standard::Tolerant,
///     DepthLimit::REFERENCE,
///     &plan,
///     &mut slab,
/// )
/// .unwrap();
/// assert_eq!(padded, [0x93, 0x00, 0x14]);
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
/// use protobuf_edit::fixed_inplace::grouped::{Plan, apply_budget};
/// use protobuf_edit::inplace::{Action, Rule, RuleSet};
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::{DepthLimit, FieldNumber, Standard};
///
/// // A pair renumber plans two writes: the budget names the
/// // count a tight plan must declare.
/// let f1 = FieldNumber::new(1).unwrap();
/// let rules = [Rule {
///     path: &[Segment::Field(f1)],
///     action: Action::Renumber(FieldNumber::new(2).unwrap()),
/// }];
/// let set = RuleSet::over(&rules).unwrap();
/// let generous = Plan::new(64).unwrap();
/// let mut slab = [MaybeUninit::<u8>::uninit(); 8192];
///
/// let mut msg = [0x0B, 0x10, 0x96, 0x01, 0x0C];
/// let (result, budget) = apply_budget(
///     &mut msg,
///     &set,
///     Standard::Tolerant,
///     DepthLimit::REFERENCE,
///     &generous,
///     &mut slab,
/// );
/// result.unwrap();
/// assert_eq!(budget.writes().used, 2);
/// assert_eq!(budget.opens().used, 1);
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
