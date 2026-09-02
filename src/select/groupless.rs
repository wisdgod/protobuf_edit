//! The groupless selector: group codes are outside the language.
//!
//! Without groups the machine sheds the pending-group scratch and
//! the in-layer group account: every container is a LEN crossing,
//! and the wire vocabulary is the groupless traversal's — group
//! codes surface as its `GroupCode` capability refusal, inherited
//! for free through the `Wire` mapping. Delivery is pre-order
//! throughout: a selected LEN hands over its payload, then its
//! interior's matches follow.
//!
//! The depth bound stays: the selector is the recursing consumer
//! (`AnyDepth` makes commitment depth a document property), unlike
//! the bare traversal cursor whose LEN recursion is the caller's
//! own choice.
//!
//! Coordinates: read · buffered · static · groupless · tolerant (type-level) · canonical (type-level) · borrowed.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::select::groupless::{MatchKind, Matches};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Select field 1 at any depth along the field-3 route (the
//! // wildcard also matches zero crossings).
//! let route = [FieldNumber::new(3).unwrap()];
//! let paths: [&[Segment<'_>]; 1] =
//!     [&[Segment::AnyDepth { descend: &route }, Segment::Field(FieldNumber::new(1).unwrap())]];
//! let program = Program::over(&paths).unwrap();
//!
//! // LEN f3 { varint f1=1 } · varint f1=42
//! let msg = [0x1A, 0x02, 0x08, 0x01, 0x08, 0x2A];
//! let hits: Vec<_> = Matches::over(&msg, &program, DepthLimit::REFERENCE)
//!     .unwrap()
//!     .collect::<Result<_, _>>()
//!     .unwrap();
//! assert_eq!(hits.len(), 2);
//! assert_eq!(hits[0].kind(), MatchKind::Varint(1));
//! assert_eq!((hits[1].span().start(), hits[1].kind()), (4, MatchKind::Varint(42)));
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{Oversize, walk_span};
use crate::path::{Crossing, Matcher, PathId, Program};
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::wire::FieldNumber;
use crate::{DepthLimit, FaultClass, Span};

/// One delivered selection: which path hit, and the record it hit.
///
/// The span covers the whole record (tag through payload) in
/// whole-input coordinates; the kind carries the decoded
/// observation, borrowing the input where the record does.
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
    /// A committed descent would nest past the caller's declared
    /// [`DepthLimit`] budget.
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// canonical face's declared standard (the tolerant face never
    /// judges widths).
    NonMinimal,
    /// A group code appeared — outside this dialect's language
    /// (the grouped dialect handles such documents).
    GroupCode,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget; [`NonMinimal`] is the
    /// canonical face's standard).
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
    /// LEN crossings still allowed below this layer.
    remaining: u16,
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
/// order), and descends where the program routes. Dropping the
/// iterator is the early stop; the first `Err` fuses it.
#[must_use = "a selection delivers nothing until iterated"]
pub struct Matches<'i, 'r> {
    /// Committed layers, root first; emptied by fusing.
    layers: Vec<Layer<'i>>,
    matcher: Matcher<'r, Program<'r>>,
    /// The current record's deliveries, ascending path order.
    pending: Vec<Match<'i>>,
    /// Drain position into `pending`.
    next_hit: usize,
    /// A refusal deferred behind pending deliveries: a depth
    /// breach on a LEN that is also selected delivers the
    /// selection first, then fuses.
    stalled: Option<Fault>,
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
        let Ok(root) = Cursor::over(input) else {
            return Err(Oversize);
        };
        let layers = alloc::vec![Layer {
            cursor: root,
            base: 0,
            crossing: None,
            remaining: limit.as_inner(),
        }];
        Ok(Self {
            layers,
            matcher: Matcher::new(*program),
            pending: Vec::new(),
            next_hit: 0,
            stalled: None,
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
    /// coordinates.
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
            let remaining = layer.remaining;
            let entry = match item {
                Ok(entry) => entry,
                Err(fault) => {
                    let fault = self.fault_at(base + fault.at(), breach(fault.kind()));
                    self.layers.clear();
                    return Some(Err(fault));
                }
            };
            let field = entry.field();
            let span = walk_span(head, end);
            self.pending.clear();
            self.next_hit = 0;
            match entry.kind() {
                EntryKind::Varint(word) => self.fan_out(field, span, MatchKind::Varint(word)),
                EntryKind::I64(bits) => self.fan_out(field, span, MatchKind::I64(bits)),
                EntryKind::I32(bits) => self.fan_out(field, span, MatchKind::I32(bits)),
                EntryKind::Len(payload) => {
                    // Pre-order: the payload delivery lands ahead of
                    // whatever the descent below yields.
                    self.fan_out(field, span, MatchKind::Len(payload));
                    if self.matcher.probe_routes(field) {
                        if remaining == 0 {
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
                                cursor: Cursor::within(payload),
                                base: payload_start,
                                crossing: Some(Crossing::new(field, head)),
                                remaining: remaining - 1,
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
/// padded tag, length prefix, or value anywhere the walk reads —
/// committed layers included — is the [`WireBreach::NonMinimal`]
/// refusal at the construct's first byte. Matches, order, spans,
/// and every other judgment are [`Matches`]'s exactly.
///
/// A separate concrete type, not a stored standard: the engine
/// instance is picked by the type once, so the tolerant iterator
/// carries no acceptance field and no per-record branch.
///
/// # Examples
///
/// ```
/// use protobuf_edit::path::{Program, Segment};
/// use protobuf_edit::select::groupless::{CanonicalMatches, MatchKind, WireBreach};
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
