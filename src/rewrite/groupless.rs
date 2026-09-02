//! The groupless rewriter: group codes are outside the language.
//!
//! Without groups the machine sheds whole subsystems: no
//! suppression machinery (nothing to delete pairwise), no group
//! budget (every container is a LEN crossing), and the wire
//! vocabulary is the groupless traversal's — group codes surface
//! as its `GroupCode` capability refusal, inherited for free
//! through the `Wire` wrapper. All-LEN framing makes the slot
//! table denser (every recursion level claims a slot); the machine
//! shape is unchanged.
//!
//! The depth bound stays: the rewriter is the recursing consumer
//! (`AnyDepth` makes commitment depth a document property), unlike
//! the bare traversal cursor whose LEN recursion is the caller's
//! own choice.
//!
//! Coordinates: write · buffered · static · groupless · Standard (value-level) · borrowed · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::rewrite::groupless::rewrite;
//! use protobuf_edit::rewrite::{Action, Rule, RuleSet, Value};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Replace field 1 at any depth along the field-3 route (the
//! // wildcard also matches zero crossings).
//! let route = [FieldNumber::new(3).unwrap()];
//! let rules = [Rule {
//!     path: &[
//!         Segment::AnyDepth { descend: &route },
//!         Segment::Field(FieldNumber::new(1).unwrap()),
//!     ],
//!     action: Action::Replace(Value::Varint(9)),
//! }];
//! let set = RuleSet::over(&rules).unwrap();
//!
//! // LEN f3 { varint f1=1 } · varint f1=42
//! let msg = [0x1A, 0x02, 0x08, 0x01, 0x08, 0x2A];
//! let (out, stats) = rewrite(&msg, &set, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(out, [0x1A, 0x02, 0x08, 0x09, 0x08, 0x09]);
//! assert_eq!((stats.replaced(), stats.descended()), (2, 1));
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::Infallible;

use super::{
    Action, Gap, InsertRule, InsertStats, Plan, Sets, SlotTable, SlotValue, TailFlag, Value,
    action, parts_total,
};
use crate::admission::usize_of;
use crate::path::{Crossing, Hits, Lane, Matcher, ix_u32};
use crate::{DepthLimit, FaultClass, Standard};
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::varint::{emit64, encoded_len32, encoded_len64, write64_at};
use crate::wire::PayloadLen;
use crate::wire::groupless::{RecordKind, head_word};

/// A job refusal: where, the promise chain crossed to reach it,
/// and which contract broke.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u32,
    trail: Box<[Crossing]>,
    kind: FaultKind,
}

impl Fault {
    /// Whole-input byte coordinate.
    #[inline]
    #[must_use]
    pub const fn at(&self) -> u32 {
        self.at
    }

    /// Committed containers crossed to reach the fault (outermost
    /// first; empty at top level).
    #[inline]
    #[must_use]
    pub fn trail(&self) -> &[Crossing] {
        &self.trail
    }

    /// The broken contract.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> FaultKind {
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

/// The groupless rewriter's refusal classes.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// A committed descent (or the top level) hit unlawful wire —
    /// the groupless traversal vocabulary, unrewrapped (group
    /// codes arrive as its capability refusal).
    Wire(WireBreach),
    /// Two rules target one record.
    Conflict {
        /// The first targeting rule.
        first: u32,
        /// The second targeting rule.
        second: u32,
    },
    /// A replacement's wire kind differs from the record's.
    KindMismatch {
        /// The offending rule's index.
        rule: u32,
    },
    /// A rewritten interior outgrew the LEN class.
    Growth {
        /// The interior's computed length.
        len: u64,
    },
    /// The rewritten root outgrew the admission cap.
    Output {
        /// The root's computed length.
        len: u64,
    },
    /// The input itself exceeds the admission cap.
    Oversize,
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Wire(breach) => write!(f, "{breach}"),
            Self::Conflict { first, second } => {
                write!(f, "rules {first} and {second} target one record")
            }
            Self::KindMismatch { rule } => {
                write!(f, "rule {rule}'s replacement kind differs from the record's")
            }
            Self::Growth { len } => {
                write!(f, "a rewritten interior of {len} bytes outgrew the LEN class")
            }
            Self::Output { len } => {
                write!(f, "the rewritten root of {len} bytes outgrew the admission cap")
            }
            Self::Oversize => f.write_str("the input exceeds the admission cap"),
        }
    }
}

impl core::error::Error for FaultKind {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(breach) => Some(breach),
            Self::Conflict { .. }
            | Self::KindMismatch { .. }
            | Self::Growth { .. }
            | Self::Output { .. }
            | Self::Oversize => None,
        }
    }
}

/// The wire breach, summarized by who acts on it: a rewrite
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

// The 64-bit layout is pinned exactly; narrower pointer widths
// are bounded by the same ceiling.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Fault>() == 40);
#[cfg(not(target_pointer_width = "64"))]
const _: () = assert!(core::mem::size_of::<Fault>() <= 40);

// ─── the walk skeleton (private) ───

/// The emit-pass answer to a LEN descent question.
enum Down {
    /// Walk in (pass one always; pass two on a dirty slot).
    Walk,
    /// The subtree is byte-identical: the walker copies the whole
    /// record verbatim and does not descend.
    Skip,
}

/// One pass's consumer. `verbatim` spans are absolute and
/// contiguous-mergeable; `ascend` reports an over-class interior
/// as `Err(len)` for the walker to coordinate.
///
/// `Refusal` is the pass's fault channel: the measuring pass
/// carries the document [`Fault`] out; the emit pass sits past
/// the fault barrier, so its channel is uninhabited and every
/// walker fault site is dead in its instantiation.
trait Sink {
    type Refusal;
    fn refuse(&self, fault: Fault) -> Self::Refusal;
    fn verbatim(&mut self, from: u32, to: u32);
    fn delete(&mut self);
    fn replace(&mut self, tag_from: u32, tag_to: u32, value: Value<'_>);
    /// The whole record re-emits minimally: `head` is its minimal
    /// head word, `value` its own payload words (a LEN payload
    /// passes verbatim behind a minimal prefix).
    fn normalize(&mut self, head: u32, value: Value<'_>);
    /// One inserted record emits: mechanically `normalize`'s
    /// emission (crate-authored minimal head, canonical value) —
    /// the same accounting, the same dirtying — split as its own
    /// event so gap sites read as what they are.
    fn insert(&mut self, head: u32, value: Value<'_>) {
        self.normalize(head, value);
    }
    fn descend(&mut self, head: u32, tag_end: u32, payload_start: u32, payload_end: u32) -> Down;
    fn ascend(
        &mut self,
        head: u32,
        tag_end: u32,
        payload_start: u32,
        payload_end: u32,
    ) -> Result<(), u64>;
}

/// One committed LEN layer on the explicit stack. Generic over
/// the door's tail payload: the insert-free door's layers store no
/// flag at all, the insert door's store the pending bool.
struct Layer<'i, T> {
    cursor: Cursor<'i>,
    /// Absolute base of this layer's payload.
    base: u32,
    /// The crossing that opened this layer (`None` at the root).
    crossing: Option<Crossing>,
    /// Record geometry of the opening LEN (meaningless at root).
    head: u32,
    tag_end: u32,
    payload_start: u32,
    payload_end: u32,
    /// LEN crossings still allowed below this layer.
    remaining: u16,
    /// `TailOf` rules hit the opening record: fire at this layer's
    /// exhaustion, into its interior. Door-keyed payload: the unit
    /// form for insert-free sets — no byte, and the exit test folds
    /// with the constant unlaned form — the pending flag for the
    /// insert door.
    tails: T,
}

// The insert-free door's layer entries drop the tail flag (its
// byte rode padding in this dialect); the insert door pays the
// flag inside the same padded footprint. Size pins: 64-bit layouts
// exact, narrower pointer widths bounded by the same ceiling.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Layer<'_, ()>>() == 64);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Layer<'_, bool>>() == 64);
#[cfg(not(target_pointer_width = "64"))]
const _: () = assert!(core::mem::size_of::<Layer<'_, ()>>() <= 64);
#[cfg(not(target_pointer_width = "64"))]
const _: () = assert!(core::mem::size_of::<Layer<'_, bool>>() <= 64);

/// One inserted record fires: the head word is authored minimal
/// from the rule's own field and the value's wire kind.
fn fire_gap<S: Sink>(sink: &mut S, stats: &mut InsertStats, insert: &InsertRule<'_>) {
    stats.inserted += 1;
    let kind = match insert.value {
        Value::Varint(_) => RecordKind::Varint,
        Value::I32(_) => RecordKind::I32,
        Value::I64(_) => RecordKind::I64,
        Value::Len(_) | Value::LenParts(_) => RecordKind::Len,
    };
    sink.insert(head_word(insert.field, kind), insert.value);
}

/// Fires every insert rule of `lane`'s kind hitting `field` in the
/// matcher's current layer, in rule-index order. Cold and
/// outlined: gap traffic must not ride the insert-free hot path's
/// code layout (for the insert-free door the call sites fold away
/// with the rest of the gap machinery).
#[cold]
#[inline(never)]
fn fire_lane<'r, R: Sets<'r>, S: Sink>(
    matcher: &Matcher<'r, R>,
    set: &R,
    field: crate::wire::FieldNumber,
    lane: Lane,
    sink: &mut S,
    stats: &mut InsertStats,
) {
    matcher.visit_gaps(field, lane, |id| match action(set, id) {
        Action::Insert(insert) => fire_gap(sink, stats, insert),
        // Gap lanes are minted from insert actions alone
        // (`InsertRuleSet`'s `Paths::lane`).
        _ => unreachable!("gap lanes quote insert rules"),
    });
}

/// The promise chain: one crossing per committed LEN layer.
/// Allocates, but only on the fault path — every caller is a
/// refusal.
fn trail<T>(layers: &[Layer<'_, T>]) -> Box<[Crossing]> {
    layers.iter().filter_map(|l| l.crossing).collect()
}

/// Runs one pass. Every fault funnels through the sink's refusal
/// channel: the measuring pass carries [`Fault`] out; the emit
/// pass replays the identical judgment sequence over the same
/// bytes, so its fault sites are dead by construction and its
/// channel is uninhabited (shared here because the skeleton is
/// shared). One instance per acceptance standard and per set
/// door: the walk rides the traversal cursor's engine split (the
/// tolerant faces pay no minimality test, both passes of a
/// canonical job judge identically), and the insert-free door's
/// instantiation folds every gap gate away behind its constant
/// unlaned form.
fn walk<'r, R: Sets<'r>, S: Sink, const MINIMAL: bool>(
    input: &[u8],
    set: &R,
    limit: DepthLimit,
    sink: &mut S,
) -> Result<InsertStats, S::Refusal> {
    let mut matcher = Matcher::new(*set);
    // Hoisted once: the per-record gate must cost a register test,
    // not a matcher field load — and for the insert-free door the
    // constant unlaned form folds it (and every site behind it)
    // out of the instantiation entirely.
    let gapped = R::LANED && matcher.gapped();
    let mut stats = InsertStats::default();
    let Ok(root) = Cursor::over(input) else {
        return Err(sink.refuse(Fault { at: 0, trail: Box::new([]), kind: FaultKind::Oversize }));
    };
    let mut layers: Vec<Layer<'_, R::Tails>> = Vec::new();
    layers.push(Layer {
        cursor: root,
        base: 0,
        crossing: None,
        head: 0,
        tag_end: 0,
        payload_start: 0,
        payload_end: 0,
        remaining: limit.as_inner(),
        tails: R::Tails::set(false),
    });
    // Root head gaps: empty-anchor rules never enter the NFA, so
    // they fire at the root interior's own events — its head is the
    // walk's start.
    set.root_inserts(Gap::HeadOf, |insert| fire_gap(sink, &mut stats, insert));

    loop {
        // SAFETY: the root layer is pushed above and the only pop
        // sits behind the `len == 1` return below, so the stack is
        // never empty here.
        let layer = unsafe { layers.last_mut().unwrap_unchecked() };
        let base = layer.base;
        let head = base + layer.cursor.pos();
        let Some(item) = layer.cursor.step::<MINIMAL>() else {
            // Layer exhausted cleanly.
            if layers.len() == 1 {
                // The root interior's tail — before nothing: the
                // document simply ends.
                set.root_inserts(Gap::TailOf, |insert| fire_gap(sink, &mut stats, insert));
                return Ok(stats);
            }
            // SAFETY: length checked above — at least two layers.
            let done = unsafe { layers.pop().unwrap_unchecked() };
            matcher.exit();
            // SAFETY: every non-root layer is pushed with its
            // crossing.
            let done_field = unsafe { done.crossing.unwrap_unchecked() }.field();
            // Tail gaps fire inside the exhausted interior — the
            // matcher just restored the parent layer, where the
            // opening record's entries live, and the sink's ascent
            // has not yet settled the interior, so the emission
            // lands (and accounts) inside it. The insert-free
            // door's constant folds the whole exit gate away.
            if R::LANED && core::hint::unlikely(done.tails.pending()) {
                fire_lane(&matcher, set, done_field, Lane::Tail, sink, &mut stats);
            }
            if let Err(len) =
                sink.ascend(done.head, done.tag_end, done.payload_start, done.payload_end)
            {
                return Err(sink.refuse(Fault {
                    at: done.head,
                    trail: trail(&layers),
                    kind: FaultKind::Growth { len },
                }));
            }
            continue;
        };
        let entry = match item {
            Ok(entry) => entry,
            Err(fault) => {
                return Err(sink.refuse(Fault {
                    at: base + fault.at(),
                    trail: trail(&layers),
                    kind: FaultKind::Wire(breach(fault.kind())),
                }));
            }
        };
        let end = base + layer.cursor.pos();
        let field = entry.field();

        match entry.kind() {
            EntryKind::Varint(_) | EntryKind::I32(_) | EntryKind::I64(_) => {
                let hits = matcher.probe_target(field);
                if let Hits::Conflict(first, second) = hits {
                    return Err(sink.refuse(conflict(head, &layers, first, second)));
                }
                // One flag test keeps the gap question off the
                // insert-free fallthrough path. HeadOf/TailOf
                // commit containerhood: a scalar occurrence of a
                // gap anchor is the caller's schema error, quoting
                // the lowest-indexed anchoring rule.
                if core::hint::unlikely(gapped)
                    && let Some(rule) = matcher.first_interior_gap(field)
                {
                    return Err(sink.refuse(Fault {
                        at: head,
                        trail: trail(&layers),
                        kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                    }));
                }
                match hits {
                    Hits::One(rule) => match action(set, rule) {
                        Action::Delete => {
                            stats.deleted += 1;
                            sink.delete();
                        }
                        Action::Replace(value) => {
                            let matches = matches!(
                                (entry.kind(), value),
                                (EntryKind::Varint(_), Value::Varint(_))
                                    | (EntryKind::I32(_), Value::I32(_))
                                    | (EntryKind::I64(_), Value::I64(_))
                            );
                            if !matches {
                                return Err(sink.refuse(Fault {
                                    at: head,
                                    trail: trail(&layers),
                                    kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                                }));
                            }
                            stats.replaced += 1;
                            let tag_end = head + u32::from(layer.cursor.tag_width());
                            sink.replace(head, tag_end, value);
                        }
                        Action::Normalize => {
                            stats.normalized += 1;
                            let (kind, value) = match entry.kind() {
                                EntryKind::Varint(word) => {
                                    (RecordKind::Varint, Value::Varint(word))
                                }
                                EntryKind::I32(bits) => (RecordKind::I32, Value::I32(bits)),
                                EntryKind::I64(bits) => (RecordKind::I64, Value::I64(bits)),
                                // The enclosing arm admits exactly
                                // the three scalar kinds.
                                EntryKind::Len(_) => unreachable!("scalar-arm normalize"),
                            };
                            sink.normalize(head_word(field, kind), value);
                        }
                        // Insert entries never enter the Hits fold
                        // (they ride the gap lanes).
                        Action::Insert(_) => unreachable!("targets quote action rules"),
                    },
                    Hits::None => sink.verbatim(head, end),
                    Hits::Conflict(..) => unreachable!("conflicts returned above"),
                }
            }
            EntryKind::Len(payload) => {
                // The payload was delivered by the cursor from admitted input.
                #[allow(
                    clippy::as_conversions,
                    reason = "cursor-delivered payload lies in the LEN class"
                )]
                let payload_start = end - payload.len() as u32;
                let (hits, routed) = matcher.probe(field);
                if let Hits::Conflict(first, second) = hits {
                    return Err(sink.refuse(conflict(head, &layers, first, second)));
                }
                match hits {
                    // An action owns the record; interior gaps on
                    // it die with the unwalked interior (the
                    // ownership law), silently.
                    Hits::One(rule) => match action(set, rule) {
                        Action::Delete => {
                            stats.deleted += 1;
                            sink.delete();
                        }
                        Action::Replace(value @ (Value::Len(_) | Value::LenParts(_))) => {
                            stats.replaced += 1;
                            let tag_end = head + u32::from(layer.cursor.tag_width());
                            sink.replace(head, tag_end, value);
                        }
                        Action::Replace(_) => {
                            return Err(sink.refuse(Fault {
                                at: head,
                                trail: trail(&layers),
                                kind: FaultKind::KindMismatch { rule: u32::from(rule) },
                            }));
                        }
                        Action::Normalize => {
                            stats.normalized += 1;
                            sink.normalize(head_word(field, RecordKind::Len), Value::Len(payload));
                        }
                        // Insert entries never enter the Hits fold.
                        Action::Insert(_) => unreachable!("targets quote action rules"),
                    },
                    Hits::None => {
                        // Interior gaps commit the descent exactly
                        // as a crossing path does: the anchor's
                        // interior must be walked to have head and
                        // tail events at all — one flag test keeps
                        // the question off insert-free jobs.
                        let interior =
                            core::hint::unlikely(gapped) && !matcher.probe_gaps(field).is_empty();
                        if interior || routed {
                            let remaining = layer.remaining;
                            if remaining == 0 {
                                return Err(sink.refuse(Fault {
                                    at: head,
                                    trail: trail(&layers),
                                    kind: FaultKind::Wire(WireBreach::Depth),
                                }));
                            }
                            let tag_end = head + u32::from(layer.cursor.tag_width());
                            match sink.descend(head, tag_end, payload_start, end) {
                                Down::Skip => sink.verbatim(head, end),
                                Down::Walk => {
                                    stats.descended += 1;
                                    // Gap sides scanned before the
                                    // matcher enters the child
                                    // layer (the entries live in
                                    // this one); head gaps fire at
                                    // descent commit, after the
                                    // container's head emission
                                    // (the sink's descend just
                                    // emitted it).
                                    let mut tails = R::Tails::set(false);
                                    if core::hint::unlikely(interior) {
                                        let gaps = matcher.probe_gaps(field);
                                        tails = R::Tails::set(gaps.tail());
                                        if gaps.head() {
                                            fire_lane(
                                                &matcher,
                                                set,
                                                field,
                                                Lane::Head,
                                                sink,
                                                &mut stats,
                                            );
                                        }
                                    }
                                    matcher.commit_descent();
                                    layers.push(Layer {
                                        cursor: Cursor::within(payload),
                                        base: payload_start,
                                        crossing: Some(Crossing::new(field, head)),
                                        head,
                                        tag_end,
                                        payload_start,
                                        payload_end: end,
                                        remaining: remaining - 1,
                                        tails,
                                    });
                                }
                            }
                        } else {
                            sink.verbatim(head, end);
                        }
                    }
                    Hits::Conflict(..) => unreachable!("conflicts returned above"),
                }
            }
        }
    }
}

#[cold]
fn conflict<T>(at: u32, layers: &[Layer<'_, T>], first: u16, second: u16) -> Fault {
    Fault {
        at,
        trail: trail(layers),
        kind: FaultKind::Conflict { first: u32::from(first), second: u32::from(second) },
    }
}

// ─── pass one: measure ───

/// One measuring layer: the running interior total, the slot it
/// fills at ascent, and whether any interior byte changed.
struct Frame {
    total: u64,
    /// The pre-order slot claimed at descent. The claimed count at
    /// that moment is `slot + 1`, so descendant accounting needs no
    /// second field. Zero at the root, which never fills a slot.
    slot: u32,
    dirty: bool,
}

struct Measure {
    /// Layer accumulators, root first — never empty: the root frame
    /// lives from construction to `root_total`.
    frames: Vec<Frame>,
    slots: SlotTable,
}

impl Measure {
    fn new() -> Self {
        Self {
            frames: alloc::vec![Frame { total: 0, slot: 0, dirty: false }],
            slots: SlotTable::new(),
        }
    }

    fn root_total(&self) -> u64 {
        debug_assert!(self.frames.len() == 1, "all layers ascended");
        // SAFETY: the root frame is pushed at construction and only
        // `ascend` pops — paired with a `descend` push by the walk —
        // so index zero is always occupied.
        unsafe { self.frames.get_unchecked(0) }.total
    }

    /// The current layer's accumulator.
    fn top(&mut self) -> &mut Frame {
        debug_assert!(!self.frames.is_empty(), "the root frame is never popped");
        // SAFETY: the root frame is pushed at construction and only
        // `ascend` pops — paired with a `descend` push by the walk.
        unsafe { self.frames.last_mut().unwrap_unchecked() }
    }
}

impl Sink for Measure {
    type Refusal = Fault;

    fn refuse(&self, fault: Fault) -> Fault {
        fault
    }

    fn verbatim(&mut self, from: u32, to: u32) {
        self.top().total += u64::from(to - from);
    }

    fn delete(&mut self) {
        self.top().dirty = true;
    }

    fn replace(&mut self, tag_from: u32, tag_to: u32, value: Value<'_>) {
        let frame = self.top();
        frame.total += u64::from(tag_to - tag_from) + value.size();
        frame.dirty = true;
    }

    fn normalize(&mut self, head: u32, value: Value<'_>) {
        let frame = self.top();
        frame.total += u64::from(encoded_len32(head)) + value.size();
        frame.dirty = true;
    }

    fn descend(&mut self, _head: u32, _tag_end: u32, _ps: u32, _pe: u32) -> Down {
        // Lossless: one slot per descended LEN, and descended
        // records have distinct heads in an input under 2^31.
        #[allow(
            clippy::as_conversions,
            reason = "slot counts stay under 2^30 (two source bytes per descended LEN)"
        )]
        let slot = self.slots.claim() as u32;
        self.frames.push(Frame { total: 0, slot, dirty: false });
        Down::Walk
    }

    fn ascend(
        &mut self,
        head: u32,
        tag_end: u32,
        payload_start: u32,
        payload_end: u32,
    ) -> Result<(), u64> {
        debug_assert!(self.frames.len() >= 2, "descend/ascend pairing");
        // SAFETY: paired with the `descend` push — the walk ascends
        // only layers it descended into, above the permanent root.
        let child = unsafe { self.frames.pop().unwrap_unchecked() };
        if child.total > u64::from(PayloadLen::MAX.as_inner()) {
            return Err(child.total);
        }
        let old_len = u64::from(payload_end - payload_start);
        if child.dirty {
            // In class: judged two lines up.
            #[allow(
                clippy::as_conversions,
                reason = "pass-one total was judged against the LEN class"
            )]
            self.slots.fill(usize_of(child.slot), true, child.total as u32);
            let prefix = if child.total == old_len {
                u64::from(payload_start - tag_end)
            } else {
                #[allow(
                    clippy::as_conversions,
                    reason = "pass-one total was judged against the LEN class"
                )]
                u64::from(encoded_len32(child.total as u32))
            };
            let parent = self.top();
            parent.total += u64::from(tag_end - head) + prefix + child.total;
            parent.dirty = true;
        } else {
            debug_assert!(child.total == old_len, "a clean subtree is byte-identical");
            // Lossless: claims are bounded by the record count.
            let descendants = ix_u32(self.slots.claimed() - (usize_of(child.slot) + 1));
            self.slots.fill(usize_of(child.slot), false, descendants);
            self.top().total += u64::from(payload_end - head);
        }
        Ok(())
    }
}

// ─── pass two: emit ───

struct Emit<'i, 'o> {
    input: &'i [u8],
    out: &'o mut Vec<u8>,
    /// The caller's published length at entry: everything past it
    /// is this job's reserved, unpublished spare capacity.
    base: usize,
    /// Bytes written into the spare region so far.
    written: usize,
    /// The reserved emission size (the plan's in-class total).
    total: usize,
    /// Pending verbatim run, absolute half-open.
    run: Option<(u32, u32)>,
    slots: SlotTable,
    cursor: usize,
    /// Logical bytes emitted (runs included before flushing).
    logical: u64,
    /// Per-dirty-layer ledger: (logical at entry, expected
    /// interior).
    ledger: Vec<(u64, u32)>,
}

impl<'i, 'o> Emit<'i, 'o> {
    /// Opens the emit pass over a sealed plan's ledger and size:
    /// one exact reservation, and the caller's length stays
    /// unpublished until [`finish`](Self::finish).
    fn new(input: &'i [u8], out: &'o mut Vec<u8>, slots: SlotTable, total: u32) -> Self {
        let total = usize_of(total);
        out.reserve_exact(total);
        let base = out.len();
        Self {
            input,
            out,
            base,
            written: 0,
            total,
            run: None,
            slots,
            cursor: 0,
            logical: 0,
            ledger: Vec::new(),
        }
    }

    /// Appends `bytes` to the unpublished region.
    fn push(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() <= self.total - self.written, "emission stays in the plan");
        // SAFETY: `new` reserved `total` spare bytes past `base`,
        // and the measuring pass accounted this emission into
        // `total` (each sink event emits exactly the bytes the
        // measuring sink counted for it), so the copy lands inside
        // the reservation; `out`'s exclusive borrow keeps source
        // and destination disjoint.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.out.as_mut_ptr().add(self.base + self.written),
                bytes.len(),
            );
        }
        self.written += bytes.len();
    }

    /// Appends `value` as exactly `width` varint bytes. Contract:
    /// `width` is the value's own encoded width — the accounting
    /// already computed it.
    fn push_varint(&mut self, value: u64, width: u32) {
        debug_assert!(usize_of(width) <= self.total - self.written, "emission stays in the plan");
        // SAFETY: as in `push` — the measuring pass accounted
        // exactly `width` bytes for this site, and `width` is the
        // value's own encoded length by the caller's contract.
        unsafe {
            write64_at(self.out.as_mut_ptr().add(self.base + self.written), value, width);
        }
        self.written += usize_of(width);
    }

    fn flush(&mut self) {
        if let Some((from, to)) = self.run.take() {
            // SAFETY: runs are record extents the cursor delivered,
            // merged only when contiguous: from <= to <= input len.
            let src = unsafe { self.input.get_unchecked(usize_of(from)..usize_of(to)) };
            self.push(src);
        }
    }

    /// The canonical payload emission `replace` and `normalize`
    /// share: value words minimal, LEN payloads verbatim behind a
    /// minimal prefix.
    fn emit_value(&mut self, value: Value<'_>) {
        match value {
            Value::Varint(word) => self.push_varint(word, encoded_len64(word)),
            Value::I32(bits) => self.push(&bits.to_le_bytes()),
            Value::I64(bits) => self.push(&bits.to_le_bytes()),
            Value::Len(bytes) => {
                // In the LEN class — by `RuleSet::over` for a
                // replacement, by input admission for a normalized
                // record's own payload — where the 32- and 64-bit
                // encoded widths coincide.
                #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
                let word = bytes.len() as u64;
                self.push_varint(word, encoded_len64(word));
                self.push(bytes);
            }
            Value::LenParts(parts) => {
                // The scatter gather: one minimal prefix over the
                // concatenated length (in the LEN class by
                // `RuleSet::over`), then the pieces in order —
                // zero staging copies.
                let word = parts_total(parts);
                self.push_varint(word, encoded_len64(word));
                for part in parts {
                    self.push(part);
                }
            }
        }
    }

    /// The three assertions are deliberate library-invariant pins
    /// (slot consumption, ledger closure, measured total), judged
    /// once per job — and publication sits behind them: the
    /// caller's new length appears only after every pin passes.
    fn finish(mut self) {
        self.flush();
        assert!(self.cursor == self.slots.claimed(), "every slot consumed exactly once");
        assert!(self.ledger.is_empty(), "every dirty layer closed");
        assert!(self.written == self.total, "pass two emitted the measured total");
        // SAFETY: `new` reserved `total` bytes past `base`; `push`
        // and `push_varint` initialized every byte below
        // `base + written`, advancing `written` by exactly the
        // bytes they wrote — the published prefix is initialized
        // and inside the reservation.
        unsafe { self.out.set_len(self.base + self.written) };
    }
}

impl Sink for Emit<'_, '_> {
    type Refusal = Infallible;

    #[inline]
    fn refuse(&self, _fault: Fault) -> Infallible {
        // SAFETY: the emit pass replays the measuring pass — the
        // same walk skeleton over the same bytes, rules, and limit,
        // with matcher state restored exactly across the subtrees
        // it skips — so every judgment repeats, and a job the
        // measuring pass accepted reaches no fault site here.
        unsafe { core::hint::unreachable_unchecked() }
    }

    fn verbatim(&mut self, from: u32, to: u32) {
        self.logical += u64::from(to - from);
        match &mut self.run {
            Some((_, tail)) if *tail == from => *tail = to,
            Some(_) => {
                self.flush();
                self.run = Some((from, to));
            }
            None => self.run = Some((from, to)),
        }
    }

    fn delete(&mut self) {}

    fn replace(&mut self, tag_from: u32, tag_to: u32, value: Value<'_>) {
        self.verbatim(tag_from, tag_to);
        self.flush();
        self.logical += value.size();
        self.emit_value(value);
    }

    fn normalize(&mut self, head: u32, value: Value<'_>) {
        self.flush();
        let head_width = encoded_len32(head);
        self.logical += u64::from(head_width) + value.size();
        self.push_varint(u64::from(head), head_width);
        self.emit_value(value);
    }

    fn descend(&mut self, head: u32, tag_end: u32, payload_start: u32, payload_end: u32) -> Down {
        match self.slots.read(self.cursor) {
            SlotValue::Clean { descendants } => {
                self.cursor += 1 + usize_of(descendants);
                Down::Skip
            }
            SlotValue::Dirty { new_len } => {
                self.cursor += 1;
                let old_len = payload_end - payload_start;
                if new_len == old_len {
                    // Value unchanged: the whole frame (tag and
                    // prefix) is untouched bytes.
                    self.verbatim(head, payload_start);
                } else {
                    self.verbatim(head, tag_end);
                    self.flush();
                    let width = encoded_len32(new_len);
                    self.logical += u64::from(width);
                    self.push_varint(u64::from(new_len), width);
                }
                self.ledger.push((self.logical, new_len));
                Down::Walk
            }
        }
    }

    fn ascend(&mut self, _head: u32, _tag_end: u32, _ps: u32, _pe: u32) -> Result<(), u64> {
        debug_assert!(!self.ledger.is_empty(), "dirty layers are ledgered");
        // SAFETY: `descend` pushes a ledger entry for every layer it
        // walks into, and ascents pair with descents.
        let (mark, expected) = unsafe { self.ledger.pop().unwrap_unchecked() };
        assert!(
            self.logical - mark == u64::from(expected),
            "a dirty interior emitted exactly its slot length"
        );
        Ok(())
    }
}

// ─── pass two, the sink twin ───

/// [`Emit`]'s sink twin: the same replay, handing borrowed slices
/// to the caller's sink instead of writing a buffer. Verbatim runs
/// coalesce and pass through as windows of the input; authored
/// words ride a ten-byte stack window. The invariant pins are the
/// buffered twin's, with the written count standing in for the
/// reservation.
struct SinkEmit<'i, 's, F> {
    input: &'i [u8],
    sink: &'s mut F,
    /// Pending verbatim run, absolute half-open.
    run: Option<(u32, u32)>,
    slots: SlotTable,
    cursor: usize,
    /// Bytes handed to the sink so far.
    written: u64,
    /// The plan's in-class total (the finish pin).
    total: u64,
    /// Logical bytes emitted (runs included before flushing).
    logical: u64,
    /// Per-dirty-layer ledger: (logical at entry, expected
    /// interior).
    ledger: Vec<(u64, u32)>,
}

impl<F: FnMut(&[u8])> SinkEmit<'_, '_, F> {
    /// Hands one non-empty slice to the sink (empty handoffs are
    /// dropped: they carry no bytes to account).
    fn hand(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        {
            self.written += bytes.len() as u64;
        }
        (self.sink)(bytes);
    }

    /// Hands `value` as exactly `width` minimal varint bytes
    /// through the stack window. Contract: `width` is the value's
    /// own encoded width — the accounting already computed it.
    fn hand_varint(&mut self, value: u64, width: u32) {
        let mut window = [0u8; 10];
        let emitted = emit64(value, &mut window);
        debug_assert!(emitted == width, "the accounted width is the value's own");
        self.hand(&window[..usize_of(width)]);
    }

    fn flush(&mut self) {
        if let Some((from, to)) = self.run.take() {
            let input = self.input;
            // SAFETY: runs are record extents the cursor delivered,
            // merged only when contiguous: from <= to <= input len.
            self.hand(unsafe { input.get_unchecked(usize_of(from)..usize_of(to)) });
        }
    }

    /// The canonical payload emission, as the buffered twin's.
    fn emit_value(&mut self, value: Value<'_>) {
        match value {
            Value::Varint(word) => self.hand_varint(word, encoded_len64(word)),
            Value::I32(bits) => self.hand(&bits.to_le_bytes()),
            Value::I64(bits) => self.hand(&bits.to_le_bytes()),
            Value::Len(bytes) => {
                // In the LEN class — by `RuleSet::over` for a
                // replacement, by input admission for a normalized
                // record's own payload.
                #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
                let word = bytes.len() as u64;
                self.hand_varint(word, encoded_len64(word));
                self.hand(bytes);
            }
            Value::LenParts(parts) => {
                // The scatter gather ([`Emit::emit_value`]): the
                // pieces hand over in order, uncopied.
                let word = parts_total(parts);
                self.hand_varint(word, encoded_len64(word));
                for part in parts {
                    self.hand(part);
                }
            }
        }
    }

    /// The buffered twin's invariant pins, judged once per job:
    /// slot consumption, ledger closure, the measured total.
    fn finish(mut self) {
        self.flush();
        assert!(self.cursor == self.slots.claimed(), "every slot consumed exactly once");
        assert!(self.ledger.is_empty(), "every dirty layer closed");
        assert!(self.written == self.total, "pass two handed the sink the measured total");
    }
}

impl<F: FnMut(&[u8])> Sink for SinkEmit<'_, '_, F> {
    type Refusal = Infallible;

    #[inline]
    fn refuse(&self, _fault: Fault) -> Infallible {
        // SAFETY: as the buffered twin — the emit pass replays the
        // measuring pass over the same bytes, rules, and limit, so
        // a job the measuring pass accepted reaches no fault site
        // here.
        unsafe { core::hint::unreachable_unchecked() }
    }

    fn verbatim(&mut self, from: u32, to: u32) {
        self.logical += u64::from(to - from);
        match &mut self.run {
            Some((_, tail)) if *tail == from => *tail = to,
            Some(_) => {
                self.flush();
                self.run = Some((from, to));
            }
            None => self.run = Some((from, to)),
        }
    }

    fn delete(&mut self) {}

    fn replace(&mut self, tag_from: u32, tag_to: u32, value: Value<'_>) {
        self.verbatim(tag_from, tag_to);
        self.flush();
        self.logical += value.size();
        self.emit_value(value);
    }

    fn normalize(&mut self, head: u32, value: Value<'_>) {
        self.flush();
        let head_width = encoded_len32(head);
        self.logical += u64::from(head_width) + value.size();
        self.hand_varint(u64::from(head), head_width);
        self.emit_value(value);
    }

    fn descend(&mut self, head: u32, tag_end: u32, payload_start: u32, payload_end: u32) -> Down {
        match self.slots.read(self.cursor) {
            SlotValue::Clean { descendants } => {
                self.cursor += 1 + usize_of(descendants);
                Down::Skip
            }
            SlotValue::Dirty { new_len } => {
                self.cursor += 1;
                let old_len = payload_end - payload_start;
                if new_len == old_len {
                    // Value unchanged: the whole frame (tag and
                    // prefix) is untouched bytes.
                    self.verbatim(head, payload_start);
                } else {
                    self.verbatim(head, tag_end);
                    self.flush();
                    let width = encoded_len32(new_len);
                    self.logical += u64::from(width);
                    self.hand_varint(u64::from(new_len), width);
                }
                self.ledger.push((self.logical, new_len));
                Down::Walk
            }
        }
    }

    fn ascend(&mut self, _head: u32, _tag_end: u32, _ps: u32, _pe: u32) -> Result<(), u64> {
        debug_assert!(!self.ledger.is_empty(), "dirty layers are ledgered");
        // SAFETY: `descend` pushes a ledger entry for every layer it
        // walks into, and ascents pair with descents.
        let (mark, expected) = unsafe { self.ledger.pop().unwrap_unchecked() };
        assert!(
            self.logical - mark == u64::from(expected),
            "a dirty interior emitted exactly its slot length"
        );
        Ok(())
    }
}

// ─── the public faces ───

/// Rewrites `input` under `rules` into fresh bytes (one exact
/// allocation), with the job receipt.
///
/// # Errors
///
/// [`Fault`] when the input refuses admission, a committed descent
/// (or the top level) hits unlawful wire (group codes included —
/// the capability refusal), two rules target one record, a
/// replacement's kind mismatches, the depth budget runs out, or a
/// rewritten interior or the root outgrows the LEN class. No bytes
/// are produced on `Err`.
///
/// # Examples
///
/// ```
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::rewrite::groupless::{FaultKind, WireBreach, rewrite};
/// use protobuf_edit::rewrite::{Action, Rule, RuleSet};
/// use protobuf_edit::{DepthLimit, FieldNumber};
///
/// let rules = [Rule {
///     path: &[Segment::Field(FieldNumber::new(1).unwrap())],
///     action: Action::Delete,
/// }];
/// let set = RuleSet::over(&rules).unwrap();
///
/// // An empty group of field 1: outside this dialect's language.
/// let fault = rewrite(&[0x0B, 0x0C], &set, DepthLimit::REFERENCE).unwrap_err();
/// assert_eq!(fault.at(), 0);
/// assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::GroupCode)));
/// ```
///
/// # Panics
///
/// If the crate's own two passes disagree on what they measured
/// and what they emitted — a library bug caught at the seam
/// (the fresh buffer this wrapper allocates cannot reach the
/// capacity extreme the `_into` face documents).
#[inline]
pub fn rewrite<'r, R: Sets<'r>>(
    input: &[u8],
    rules: &R,
    limit: DepthLimit,
) -> Result<(Vec<u8>, R::Stats), Fault> {
    let mut out = Vec::new();
    let stats = rewrite_into(input, rules, limit, &mut out)?;
    Ok((out, stats))
}

/// Rewrites `input` under `rules`, appending to `out` — the reuse
/// face.
///
/// Existing content is untouched, all faults precede the
/// reservation, and the new length is published once — after the
/// emit pass's invariant pins.
///
/// # Errors
///
/// As [`rewrite`]; `out` is untouched on `Err`.
///
/// # Panics
///
/// If the crate's own two passes disagree on what they measured
/// and what they emitted — a library bug caught at the seam —
/// or if appending the output to `out` would overflow the
/// vector's capacity bounds (an extreme the caller can reach on
/// 32-bit targets with a near-full buffer).
#[inline]
pub fn rewrite_into<'r, R: Sets<'r>>(
    input: &[u8],
    rules: &R,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<R::Stats, Fault> {
    run_into::<R, false>(input, rules, limit, out)
}

/// One buffered job, one instance per acceptance standard: the
/// measuring pass walks and judges, the emit pass replays the same
/// instance over the sealed plan.
fn run_into<'r, R: Sets<'r>, const MINIMAL: bool>(
    input: &[u8],
    rules: &R,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<R::Stats, Fault> {
    let mut measure = Measure::new();
    let stats = walk::<R, _, MINIMAL>(input, rules, limit, &mut measure)?;
    let total = measure.root_total();
    let Some(plan) = Plan::new(input, *rules, limit, stats, measure.slots, total) else {
        return Err(Fault { at: 0, trail: Box::new([]), kind: FaultKind::Output { len: total } });
    };
    Ok(R::receipt(replay::<R, MINIMAL>(plan, out)))
}

/// Rewrites `input` under `rules`, handing the output to `sink`
/// as borrowed slices in output order.
///
/// No output buffer exists: verbatim runs pass through as windows
/// of `input`, authored words ride a ten-byte stack window, and
/// the concatenation is exactly [`rewrite`]'s output.
///
/// # Errors
///
/// As [`rewrite`]. Every fault surfaces in the measuring pass,
/// ahead of the first handoff — on `Err` the sink has received
/// nothing, so the transactional contract survives the streaming
/// shape.
///
/// # Panics
///
/// If the crate's own two passes disagree on what they measured
/// and what they handed over — a library bug caught at the seam.
pub fn rewrite_sink<'r, R: Sets<'r>>(
    input: &[u8],
    rules: &R,
    limit: DepthLimit,
    mut sink: impl FnMut(&[u8]),
) -> Result<R::Stats, Fault> {
    run_sink::<R, false>(input, rules, limit, &mut sink)
}

/// [`run_into`]'s sink twin.
fn run_sink<'r, R: Sets<'r>, const MINIMAL: bool>(
    input: &[u8],
    rules: &R,
    limit: DepthLimit,
    sink: &mut impl FnMut(&[u8]),
) -> Result<R::Stats, Fault> {
    let mut measure = Measure::new();
    let stats = walk::<R, _, MINIMAL>(input, rules, limit, &mut measure)?;
    let total = measure.root_total();
    let Some(plan) = Plan::new(input, *rules, limit, stats, measure.slots, total) else {
        return Err(Fault { at: 0, trail: Box::new([]), kind: FaultKind::Output { len: total } });
    };
    Ok(R::receipt(replay_sink::<R, MINIMAL>(plan, sink)))
}

/// [`rewrite`] under a declared acceptance [`Standard`].
///
/// The standard picks a monomorphized walk instance once at this
/// entry — both passes run it — so a tolerant job pays no width
/// comparison and a canonical one refuses every non-minimal
/// varint width in the input it walks (opaque interiors stay the
/// caller's declaration, exactly as for the tolerant faces) as
/// [`WireBreach::NonMinimal`], at the construct's first byte.
///
/// # Errors
///
/// As [`rewrite`], plus the width refusals the declared standard
/// adds. No bytes are produced on `Err`.
///
/// # Examples
///
/// ```
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::rewrite::groupless::{FaultKind, WireBreach, rewrite_standard};
/// use protobuf_edit::rewrite::{Action, Rule, RuleSet};
/// use protobuf_edit::{DepthLimit, FieldNumber, Standard};
///
/// let rules = [Rule {
///     path: &[Segment::Field(FieldNumber::new(2).unwrap())],
///     action: Action::Delete,
/// }];
/// let set = RuleSet::over(&rules).unwrap();
///
/// // varint f1=150 padded: refused under the canonical standard,
/// // rewritten under the tolerant one.
/// let msg = [0x08, 0x96, 0x81, 0x00, 0x10, 0x2A];
/// let fault = rewrite_standard(&msg, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
///     .unwrap_err();
/// assert_eq!(fault.at(), 1);
/// assert!(matches!(fault.kind(), FaultKind::Wire(WireBreach::NonMinimal)));
///
/// let (out, stats) =
///     rewrite_standard(&msg, &set, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(out, [0x08, 0x96, 0x81, 0x00]);
/// assert_eq!(stats.deleted(), 1);
/// ```
///
/// # Panics
///
/// As [`rewrite`].
#[inline]
pub fn rewrite_standard<'r, R: Sets<'r>>(
    input: &[u8],
    rules: &R,
    standard: Standard,
    limit: DepthLimit,
) -> Result<(Vec<u8>, R::Stats), Fault> {
    let mut out = Vec::new();
    let stats = rewrite_into_standard(input, rules, standard, limit, &mut out)?;
    Ok((out, stats))
}

/// [`rewrite_into`] under a declared acceptance [`Standard`]
/// ([`rewrite_standard`]'s reuse face).
///
/// # Errors
///
/// As [`rewrite_standard`]; `out` is untouched on `Err`.
///
/// # Panics
///
/// As [`rewrite_into`].
#[inline]
pub fn rewrite_into_standard<'r, R: Sets<'r>>(
    input: &[u8],
    rules: &R,
    standard: Standard,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<R::Stats, Fault> {
    match standard {
        Standard::Tolerant => run_into::<R, false>(input, rules, limit, out),
        Standard::CanonicalMinimal => run_into::<R, true>(input, rules, limit, out),
    }
}

/// [`rewrite_sink`] under a declared acceptance [`Standard`]
/// ([`rewrite_standard`]'s streaming face).
///
/// # Errors
///
/// As [`rewrite_standard`]. Every fault surfaces in the measuring
/// pass, ahead of the first handoff — on `Err` the sink has
/// received nothing.
///
/// # Panics
///
/// As [`rewrite_sink`].
#[inline]
pub fn rewrite_sink_standard<'r, R: Sets<'r>>(
    input: &[u8],
    rules: &R,
    standard: Standard,
    limit: DepthLimit,
    mut sink: impl FnMut(&[u8]),
) -> Result<R::Stats, Fault> {
    match standard {
        Standard::Tolerant => run_sink::<R, false>(input, rules, limit, &mut sink),
        Standard::CanonicalMinimal => run_sink::<R, true>(input, rules, limit, &mut sink),
    }
}

/// The emit pass over a sealed plan: the walk's input, rules, and
/// limit come from the plan itself ([`Plan`]'s replay identity),
/// so the slot reads replay exactly the walk that claimed them —
/// the acceptance instance included.
fn replay<'r, R: Sets<'r>, const MINIMAL: bool>(
    plan: Plan<'_, R>,
    out: &mut Vec<u8>,
) -> InsertStats {
    let Plan { input, rules, limit, stats, slots, total } = plan;
    let mut emit = Emit::new(input, out, slots, total);
    // The emit pass is past the fault barrier: its refusal channel
    // is uninhabited, so the pattern is irrefutable.
    let Ok(repeated) = walk::<R, _, MINIMAL>(input, &rules, limit, &mut emit);
    debug_assert!(
        // The emit pass skips clean subtrees, so its descend count
        // lawfully undershoots; every judgment tally must repeat.
        (repeated.deleted(), repeated.replaced(), repeated.normalized(), repeated.inserted())
            == (stats.deleted(), stats.replaced(), stats.normalized(), stats.inserted()),
        "the emit pass repeats the measuring pass's judgments"
    );
    emit.finish();
    stats
}

/// [`replay`]'s sink twin, over the same sealed plan identity.
fn replay_sink<'r, R: Sets<'r>, const MINIMAL: bool>(
    plan: Plan<'_, R>,
    sink: &mut impl FnMut(&[u8]),
) -> InsertStats {
    let Plan { input, rules, limit, stats, slots, total } = plan;
    let mut emit = SinkEmit {
        input,
        sink,
        run: None,
        slots,
        cursor: 0,
        written: 0,
        total: u64::from(total),
        logical: 0,
        ledger: Vec::new(),
    };
    // The emit pass is past the fault barrier: its refusal channel
    // is uninhabited, so the pattern is irrefutable.
    let Ok(repeated) = walk::<R, _, MINIMAL>(input, &rules, limit, &mut emit);
    debug_assert!(
        // The emit pass skips clean subtrees, so its descend count
        // lawfully undershoots; every judgment tally must repeat.
        (repeated.deleted(), repeated.replaced(), repeated.normalized(), repeated.inserted())
            == (stats.deleted(), stats.replaced(), stats.normalized(), stats.inserted()),
        "the emit pass repeats the measuring pass's judgments"
    );
    emit.finish();
    stats
}

// The transfer engine: the third plan door's jobs, emitted only
// under the transfer capability.
#[cfg(feature = "transfer-rewrite-groupless")]
pub mod transfer;

#[cfg(feature = "transfer-rewrite-groupless")]
pub use transfer::{
    TransferFault, TransferFaultKind, rewrite_transfers, rewrite_transfers_into,
    rewrite_transfers_into_standard, rewrite_transfers_sink, rewrite_transfers_sink_standard,
    rewrite_transfers_standard,
};

#[cfg(test)]
mod tests;
