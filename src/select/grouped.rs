//! The grouped selector: groups walk by syntax.
//!
//! Group bodies are force-walked (crossing one costs a depth
//! account like a committed LEN), the matcher scopes each body so
//! its fields match at group level, and the cursor verifies every
//! pairing. A group's extent does not exist at its open tag —
//! finding the end *is* walking the body — so a selected group
//! delivers once, at its verified close, after its interior's own
//! matches. Delivery order is split: LEN
//! selections are pre-order (payload in hand at the head), group
//! selections are post-order (extent in hand at the close);
//! scalar selections are their own record. Everything else about
//! delivery — fan-out, ascending path order, convergence collapse
//! — is the shared contract ([`crate::select`]).
//!
//! Coordinates: read · buffered · static · grouped · tolerant (type-level) · canonical (type-level) · borrowed.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::select::grouped::{MatchKind, Matches};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Select the field-2 group and field 3 inside it.
//! let f2 = FieldNumber::new(2).unwrap();
//! let f3 = FieldNumber::new(3).unwrap();
//! let paths: [&[Segment<'_>]; 2] =
//!     [&[Segment::Field(f2)], &[Segment::Field(f2), Segment::Field(f3)]];
//! let program = Program::over(&paths).unwrap();
//!
//! // varint f1=150 · group f2 { varint f3=1 }
//! let msg = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
//! let hits: Vec<_> = Matches::over(&msg, &program, DepthLimit::REFERENCE)
//!     .unwrap()
//!     .collect::<Result<_, _>>()
//!     .unwrap();
//! // The interior match lands first; the group's own match lands
//! // at its verified close, carrying the interior bytes.
//! assert_eq!(hits.len(), 2);
//! assert_eq!((hits[0].path().index(), hits[0].kind()), (1, MatchKind::Varint(1)));
//! assert_eq!((hits[1].path().index(), hits[1].kind()), (0, MatchKind::Group(&[0x18, 0x01])));
//! assert_eq!((hits[1].span().start(), hits[1].span().end()), (3, 7));
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{Oversize, walk_span};
use crate::admission::usize_of;
use crate::path::{Crossing, Matcher, PathId, Program};
use crate::cursor::GroupDepth;
use crate::cursor::grouped::{Cursor, EntryKind};
use crate::wire::FieldNumber;
use crate::{DepthLimit, FaultClass, Span};

/// One delivered selection: which path hit, and the record it hit.
///
/// The span covers the whole record (a group's span runs from its
/// open tag through its close tag) in whole-input coordinates; the
/// kind carries the decoded observation, borrowing the input where
/// the record does.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Match<'i> {
    path: PathId,
    field: FieldNumber,
    span: Span,
    kind: MatchKind<'i>,
}

impl<'i> Match<'i> {
    /// The path that selected this record.
    #[inline]
    pub const fn path(self) -> PathId {
        self.path
    }

    /// The record's field number.
    #[inline]
    pub const fn field(self) -> FieldNumber {
        self.field
    }

    /// The whole record's extent, in whole-input coordinates.
    #[inline]
    pub const fn span(self) -> Span {
        self.span
    }

    /// The decoded observation.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> MatchKind<'i> {
        self.kind
    }
}

/// The observation a delivered match carries — this dialect's
/// complete delivery set, closed by design: exhaustive matching is
/// part of the selector's promise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MatchKind<'i> {
    /// A varint record's decoded word.
    Varint(u64),
    /// An I64 record's eight little-endian payload bytes, as bits.
    I64(u64),
    /// A LEN record's borrowed payload.
    Len(&'i [u8]),
    /// A selected group's interior bytes (open-tag end to
    /// close-tag start), delivered at the verified close.
    Group(&'i [u8]),
    /// An I32 record's four little-endian payload bytes, as bits.
    I32(u32),
}

/// A job refusal: where, the promise chain crossed to reach it,
/// and which wire contract broke.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u32,
    trail: Box<[Crossing]>,
    breach: WireBreach,
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
    pub const fn breach(&self) -> WireBreach {
        self.breach
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.breach, self.at)
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.breach)
    }
}

/// The wire breach, summarized by who acts on it: a selection
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
    /// canonical face's declared standard (the tolerant face never
    /// judges widths).
    NonMinimal,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget; [`NonMinimal`] is the
    /// canonical face's standard); this dialect has no capability
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

#[cold]
const fn breach(kind: crate::cursor::grouped::FaultKind) -> WireBreach {
    use crate::cursor::grouped::FaultKind as T;
    match kind {
        T::Read { .. } => WireBreach::Varint,
        T::FieldZero { .. } | T::Unassigned { .. } => WireBreach::Tag,
        T::FixedTruncated { .. } | T::LenOverrun { .. } => WireBreach::Truncated,
        T::GroupEndMismatch { .. } | T::GroupEndOrphan { .. } | T::GroupUnclosed { .. } => {
            WireBreach::Grouping
        }
        T::DepthExceeded { .. } => WireBreach::Depth,
        T::NonMinimalTag | T::NonMinimalLen { .. } | T::NonMinimalValue { .. } => {
            WireBreach::NonMinimal
        }
    }
}

const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Match<'_>>() == 40
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Match<'_>>() <= 40
    });
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Fault>() == 24
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Fault>() <= 24
    });
};

/// One committed LEN layer on the explicit stack.
struct Layer<'i> {
    cursor: Cursor<'i>,
    /// Absolute base of this layer's payload.
    base: u32,
    /// The crossing that opened this layer (`None` at the root).
    crossing: Option<Crossing>,
    /// Depth budget left inside this layer (container crossings).
    remaining: u16,
    /// Open groups inside this layer (they consume budget too).
    group_depth: u16,
}

/// One open group frame: where it opened, where its interior
/// starts, and its slice of the pending-group id arena.
struct OpenGroup {
    /// The open tag's head (the group span's start).
    head: u32,
    /// The open tag's end (the interior's start).
    body: u32,
    /// Start of this group's ids in the pending-group arena.
    ids_at: usize,
}

/// The promise chain: one crossing per committed LEN layer.
/// Allocates, but only on the fault path — every caller is a
/// refusal.
fn trail(layers: &[Layer<'_>]) -> Box<[Crossing]> {
    layers.iter().filter_map(|l| l.crossing).collect()
}

/// The selection walk over one buffered message: a fused iterator
/// of matches.
///
/// The walk pulls one record at a time from the innermost
/// committed layer, fans its deliveries out (ascending path
/// order), and descends where the program routes; a selected
/// group's ids wait in a per-group scratch until its verified
/// close. Dropping the iterator is the early stop; the first
/// `Err` fuses it.
#[must_use = "a selection delivers nothing until iterated"]
pub struct Matches<'i, 'r> {
    /// The whole input — group interiors slice from it by
    /// absolute coordinates.
    input: &'i [u8],
    /// Committed layers, root first; emptied by fusing.
    layers: Vec<Layer<'i>>,
    matcher: Matcher<'r, Program<'r>>,
    limit: DepthLimit,
    /// The current record's deliveries, ascending path order.
    pending: Vec<Match<'i>>,
    /// Drain position into `pending`.
    next_hit: usize,
    /// A refusal deferred behind pending deliveries: a depth
    /// breach on a LEN that is also selected delivers the
    /// selection first, then fuses.
    stalled: Option<Fault>,
    /// Open group frames, innermost last (groups nest properly
    /// within and across layers — each layer's cursor verifies its
    /// own pairing, so the stack is LIFO across the whole walk).
    groups: Vec<OpenGroup>,
    /// Path ids selected for still-open groups (arena; each frame
    /// marks its start) — paid only when groups are targeted.
    group_ids: Vec<u16>,
}

impl<'i, 'r> Matches<'i, 'r> {
    /// Admits `input` and stands the selection at its head.
    ///
    /// # Errors
    ///
    /// [`Oversize`] when `input` exceeds the `i32::MAX` input cap
    /// — the admission that keeps every walk coordinate inside `u32`.
    pub fn over(
        input: &'i [u8],
        program: &Program<'r>,
        limit: DepthLimit,
    ) -> Result<Self, Oversize> {
        let Ok(root) = Cursor::over(input, GroupDepth::from(limit)) else {
            return Err(Oversize);
        };
        let layers = alloc::vec![Layer {
            cursor: root,
            base: 0,
            crossing: None,
            remaining: limit.as_inner(),
            group_depth: 0,
        }];
        Ok(Self {
            input,
            layers,
            matcher: Matcher::new(*program),
            limit,
            pending: Vec::new(),
            next_hit: 0,
            stalled: None,
            groups: Vec::new(),
            group_ids: Vec::new(),
        })
    }

    /// Shapes a refusal with the promise chain crossed so far.
    #[cold]
    fn fault_at(&self, at: u32, breach: WireBreach) -> Fault {
        Fault { at, trail: trail(&self.layers), breach }
    }

    /// Fans one record's deliveries into the pending scratch —
    /// every targeting path, ascending, one match each (matches
    /// are copied whole, so no delivery aliases the matcher
    /// across mutations).
    fn fan_out(&mut self, field: FieldNumber, span: Span, kind: MatchKind<'i>) {
        let pending = &mut self.pending;
        self.matcher.visit_targets(field, |id| {
            pending.push(Match { path: PathId::mint(id), field, span, kind });
        });
    }

    /// One delivery step, one instance per acceptance standard:
    /// the walk rides the traversal cursor's own engine split, so
    /// the tolerant selection pays no minimality test and the
    /// canonical twin inherits the cursor's judgment order and
    /// coordinates (group framing tags included).
    fn step<const MINIMAL: bool>(&mut self) -> Option<Result<Match<'i>, Fault>> {
        loop {
            // Drain the current record's fan-out first: deliveries
            // precede the descent the record may also have opened
            // (pre-order), and precede any stalled refusal.
            if let Some(&hit) = self.pending.get(self.next_hit) {
                self.next_hit += 1;
                return Some(Ok(hit));
            }
            if let Some(fault) = self.stalled.take() {
                self.layers.clear();
                return Some(Err(fault));
            }
            let layer = self.layers.last_mut()?;
            let base = layer.base;
            let head = base + layer.cursor.pos();
            let Some(item) = layer.cursor.step::<MINIMAL>() else {
                // Layer exhausted cleanly.
                if self.layers.len() == 1 {
                    return None;
                }
                self.layers.pop();
                self.matcher.exit();
                continue;
            };
            let end = base + layer.cursor.pos();
            let entry = match item {
                Ok(entry) => entry,
                Err(fault) => {
                    let fault = self.fault_at(base + fault.at(), breach(fault.kind()));
                    self.layers.clear();
                    return Some(Err(fault));
                }
            };
            let field = entry.field();
            self.pending.clear();
            self.next_hit = 0;
            match entry.kind() {
                EntryKind::GroupExit => {
                    // The cursor verified the pairing; the matcher
                    // scope closes with it.
                    self.matcher.exit();
                    layer.group_depth -= 1;
                    debug_assert!(!self.groups.is_empty(), "enters and exits pair");
                    // SAFETY: frames push at every delivered enter
                    // and pop at every delivered exit, and the
                    // cursor refuses orphan and mismatched end tags
                    // — a delivered exit always has its open frame.
                    let open = unsafe { self.groups.pop().unwrap_unchecked() };
                    if self.group_ids.len() > open.ids_at {
                        // Post-order single delivery: the extent
                        // exists only now, at the verified close.
                        let span = walk_span(open.head, end);
                        // SAFETY: `body` and `head` are cursor
                        // positions mapped into whole-input
                        // coordinates — monotone along the walk
                        // (body at the open tag's end, head at the
                        // close tag's head) and bounded by the
                        // layer window's end, which lies inside
                        // `input`.
                        let interior = unsafe {
                            self.input.get_unchecked(usize_of(open.body)..usize_of(head))
                        };
                        let pending = &mut self.pending;
                        for id in self.group_ids.drain(open.ids_at..) {
                            pending.push(Match {
                                path: PathId::mint(id),
                                field,
                                span,
                                kind: MatchKind::Group(interior),
                            });
                        }
                    }
                }
                EntryKind::GroupEnter => {
                    // Groups and committed LEN crossings spend one
                    // budget account.
                    if layer.group_depth == layer.remaining {
                        let fault = self.fault_at(head, WireBreach::Depth);
                        self.layers.clear();
                        return Some(Err(fault));
                    }
                    // A selected group delivers at its verified
                    // close — stash the ids until then.
                    let ids = &mut self.group_ids;
                    let ids_at = ids.len();
                    self.matcher.visit_targets(field, |id| ids.push(id));
                    self.groups.push(OpenGroup { head, body: end, ids_at });
                    // Groups cross by syntax: stage whatever routes
                    // through the field and commit even an empty
                    // layer, keeping matcher and cursor scopes
                    // paired.
                    self.matcher.probe_routes(field);
                    self.matcher.commit_descent();
                    layer.group_depth += 1;
                }
                EntryKind::Varint(word) => {
                    self.fan_out(field, walk_span(head, end), MatchKind::Varint(word));
                }
                EntryKind::I64(bits) => {
                    self.fan_out(field, walk_span(head, end), MatchKind::I64(bits));
                }
                EntryKind::I32(bits) => {
                    self.fan_out(field, walk_span(head, end), MatchKind::I32(bits));
                }
                EntryKind::Len(payload) => {
                    let (remaining, group_depth) = (layer.remaining, layer.group_depth);
                    let span = walk_span(head, end);
                    // Pre-order: the payload delivery lands ahead of
                    // whatever the descent below yields.
                    self.fan_out(field, span, MatchKind::Len(payload));
                    if self.matcher.probe_routes(field) {
                        if group_depth == remaining {
                            self.stalled = Some(self.fault_at(head, WireBreach::Depth));
                        } else {
                            // The payload was delivered by the cursor
                            // from admitted input.
                            #[allow(
                                clippy::as_conversions,
                                reason = "cursor-delivered payload lies in the LEN class"
                            )]
                            let payload_start = end - payload.len() as u32;
                            self.matcher.commit_descent();
                            self.layers.push(Layer {
                                cursor: Cursor::within(payload, GroupDepth::from(self.limit)),
                                base: payload_start,
                                crossing: Some(Crossing::new(field, head)),
                                remaining: remaining - group_depth - 1,
                                group_depth: 0,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Delivered matches ride `Ok`; the walk's first refusal rides
/// `Err` and fuses the iterator — every later call is `None`, as
/// after a clean end.
impl<'i> Iterator for Matches<'i, '_> {
    type Item = Result<Match<'i>, Fault>;

    fn next(&mut self) -> Option<Self::Item> {
        self.step::<false>()
    }
}

impl core::iter::FusedIterator for Matches<'_, '_> {}

/// [`Matches`]'s canonical-minimal twin.
///
/// The same selection walk over the canonical traversal engine: a
/// padded tag (group framing included), length prefix, or value
/// anywhere the walk reads — committed layers included — is the
/// [`WireBreach::NonMinimal`] refusal at the construct's first
/// byte. Matches, order, spans, and every other judgment are
/// [`Matches`]'s exactly.
///
/// A separate concrete type, not a stored standard: the engine
/// instance is picked by the type once, so the tolerant iterator
/// carries no acceptance field and no per-record branch.
///
/// # Examples
///
/// ```
/// use protobuf_edit::path::{Program, Segment};
/// use protobuf_edit::select::grouped::{CanonicalMatches, MatchKind, WireBreach};
/// use protobuf_edit::{DepthLimit, FieldNumber};
///
/// let field1 = FieldNumber::new(1).unwrap();
/// let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(field1)]];
/// let program = Program::over(&paths).unwrap();
///
/// // Minimal wire selects; the same value padded refuses.
/// let clean = [0x08, 0x96, 0x01];
/// let hits: Vec<_> = CanonicalMatches::over(&clean, &program, DepthLimit::REFERENCE)
///     .unwrap()
///     .collect::<Result<_, _>>()
///     .unwrap();
/// assert_eq!(hits[0].kind(), MatchKind::Varint(150));
///
/// let padded = [0x08, 0x96, 0x81, 0x00];
/// let fault = CanonicalMatches::over(&padded, &program, DepthLimit::REFERENCE)
///     .unwrap()
///     .next()
///     .unwrap()
///     .unwrap_err();
/// assert_eq!((fault.at(), fault.breach()), (1, WireBreach::NonMinimal));
/// ```
#[must_use = "a selection delivers nothing until iterated"]
pub struct CanonicalMatches<'i, 'r> {
    walk: Matches<'i, 'r>,
}

impl<'i, 'r> CanonicalMatches<'i, 'r> {
    /// Admits `input` and stands the selection at its head
    /// ([`Matches::over`]).
    ///
    /// # Errors
    ///
    /// [`Oversize`] when `input` exceeds the `i32::MAX` input cap
    /// — the admission that keeps every walk coordinate inside `u32`.
    #[inline]
    pub fn over(
        input: &'i [u8],
        program: &Program<'r>,
        limit: DepthLimit,
    ) -> Result<Self, Oversize> {
        Ok(Self { walk: Matches::over(input, program, limit)? })
    }
}

/// Delivered matches ride `Ok`; the walk's first refusal rides
/// `Err` and fuses the iterator — every later call is `None`, as
/// after a clean end.
impl<'i> Iterator for CanonicalMatches<'i, '_> {
    type Item = Result<Match<'i>, Fault>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk.step::<true>()
    }
}

impl core::iter::FusedIterator for CanonicalMatches<'_, '_> {}

#[cfg(test)]
mod tests;
