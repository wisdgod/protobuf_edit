//! The groupless cursor engine: the four-code walk behind the
//! `traverse` faces, driven directly by the groupless select and
//! rewrite walks.
//!
//! No cross-record state: the walk keeps no stack, allocates
//! nothing, and refuses group codes as a capability judgment. LEN
//! payloads deliver opaque, and acceptance is the step instance
//! (`step::<MINIMAL>`) — the public iterator twins pin one
//! instance each, so neither stores a standard nor branches on
//! one.

use super::Oversize;
use crate::Stage;
use crate::admission::{self, admitted_u32, usize_of};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{encoded_len32, encoded_len64};
use crate::wire::groupless::{RecordKind, TagClass, classify};
#[cfg(feature = "traverse-groupless")]
use crate::FaultClass;
use crate::wire::{FieldNumber, Low3, PayloadLen};

/// One delivered record: the field and the decoded observation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry<'a> {
    field: FieldNumber,
    kind: EntryKind<'a>,
}

impl<'a> Entry<'a> {
    /// The record's field number.
    #[inline]
    pub const fn field(self) -> FieldNumber {
        self.field
    }

    /// The decoded observation.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> EntryKind<'a> {
        self.kind
    }
}

/// The observation a delivered record carries — this dialect's
/// complete delivery set, closed by design: exhaustive matching is
/// part of the cursor's promise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind<'a> {
    /// A varint record's decoded word.
    Varint(u64),
    /// An I64 record's eight little-endian payload bytes, as bits.
    I64(u64),
    /// A LEN record's borrowed payload — opaque here; descent is
    /// the consumer's own cursor over the slice.
    Len(&'a [u8]),
    /// An I32 record's four little-endian payload bytes, as bits.
    I32(u32),
}

/// A walk refusal: where, and which clause broke. The first fault
/// fuses the cursor.
///
/// `at` meanings per kind: [`FaultKind::Read`] names the refused
/// construct's first byte; `FieldZero`, `GroupCode`, and
/// `Unassigned` name the head tag; `FixedTruncated` and
/// `LenOverrun` name the payload start.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u32,
    kind: FaultKind,
}

impl Fault {
    /// Byte offset of the refused construct, in the walked slice's
    /// coordinates.
    #[inline]
    #[must_use]
    pub const fn at(self) -> u32 {
        self.at
    }

    /// The broken clause.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> FaultKind {
        self.kind
    }
}

/// The groupless walk's refusal classes, sectioned by
/// [`FaultClass`] (grammar, then capability); [`class`](Self::class)
/// answers the section.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    // ─ grammar ─
    /// A varint construct refused at one of the record's stages.
    Read {
        /// The construct the read was serving.
        stage: Stage,
        /// The kernel's refusal.
        cause: ReadFault,
    },
    /// The tag word names field zero — unassigned by the format,
    /// judged ahead of the code class.
    FieldZero {
        /// The whole tag word.
        word: u32,
    },
    /// The tag word carries a code the format leaves unassigned.
    Unassigned {
        /// The field the tag names.
        field: FieldNumber,
        /// The unassigned code bits.
        code: Low3,
    },
    /// A fixed-width payload runs past the input end.
    FixedTruncated {
        /// The record's field.
        field: FieldNumber,
    },
    /// A LEN payload claims more bytes than the input holds.
    LenOverrun {
        /// The record's field.
        field: FieldNumber,
        /// The declared payload length.
        len: PayloadLen,
    },
    // ─ policy: the canonical twin's standard ─
    /// A tag wider than minimal ([`CanonicalCursor`] only).
    NonMinimalTag,
    /// A length prefix wider than minimal ([`CanonicalCursor`]
    /// only).
    NonMinimalLen {
        /// The record's field.
        field: FieldNumber,
    },
    /// A value varint wider than minimal ([`CanonicalCursor`]
    /// only).
    NonMinimalValue {
        /// The record's field.
        field: FieldNumber,
    },
    // ─ capability: the dialect boundary ─
    /// The tag word carries a group code: well-formed wire outside
    /// this dialect's language — the capability refusal, distinct
    /// from [`FaultKind::Unassigned`].
    GroupCode {
        /// The field the tag names.
        field: FieldNumber,
        /// The group code bits (3 or 4).
        code: Low3,
    },
}

impl FaultKind {
    /// The refusal's [`FaultClass`] — which repair the fault asks
    /// for. Policy membership names its configuration datum (the
    /// `NonMinimal*` family is [`CanonicalCursor`]'s declared
    /// standard); the walk still takes no nesting bound (it never
    /// descends a LEN on its own). A traverse face: the
    /// select/rewrite walks fold kinds into their own vocabularies
    /// instead.
    #[cfg(feature = "traverse-groupless")]
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Read { .. }
            | Self::FieldZero { .. }
            | Self::Unassigned { .. }
            | Self::FixedTruncated { .. }
            | Self::LenOverrun { .. } => FaultClass::Grammar,
            Self::NonMinimalTag | Self::NonMinimalLen { .. } | Self::NonMinimalValue { .. } => {
                FaultClass::Policy
            }
            Self::GroupCode { .. } => FaultClass::Capability,
        }
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let at = self.at;
        match self.kind {
            FaultKind::Read { stage: Stage::Tag, cause } => {
                write!(f, "tag word at {at}: {cause}")
            }
            FaultKind::Read { stage: Stage::LenPrefix { field }, cause } => {
                write!(f, "length word of field {} at {at}: {cause}", field.as_inner())
            }
            FaultKind::Read { stage: Stage::Value { field }, cause } => {
                write!(f, "varint value of field {} at {at}: {cause}", field.as_inner())
            }
            FaultKind::FieldZero { word } => {
                write!(f, "tag word {word:#x} at {at} names field zero")
            }
            FaultKind::Unassigned { field, code } => write!(
                f,
                "tag word at {at} names field {} with unassigned code {}",
                field.as_inner(),
                code.as_inner()
            ),
            FaultKind::GroupCode { field, code } => write!(
                f,
                "tag word at {at} names field {} with group code {} outside this dialect",
                field.as_inner(),
                code.as_inner()
            ),
            FaultKind::FixedTruncated { field } => write!(
                f,
                "fixed-width payload of field {} at {at} runs past the input end",
                field.as_inner()
            ),
            FaultKind::LenOverrun { field, len } => write!(
                f,
                "LEN payload of field {} at {at} claims {} bytes past the input end",
                field.as_inner(),
                len.as_inner()
            ),
            FaultKind::NonMinimalTag => {
                write!(f, "tag at {at} is wider than its minimal encoding")
            }
            FaultKind::NonMinimalLen { field } => write!(
                f,
                "length prefix of field {} at {at} is wider than its minimal encoding",
                field.as_inner()
            ),
            FaultKind::NonMinimalValue { field } => write!(
                f,
                "varint value of field {} at {at} is wider than its minimal encoding",
                field.as_inner()
            ),
        }
    }
}

impl core::error::Error for Fault {}

const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Entry<'_>>() == 32
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Entry<'_>>() <= 32
    });
    assert!(core::mem::size_of::<Fault>() == 16);
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Cursor<'_>>() == 32
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Cursor<'_>>() <= 32
    });
};

// The canonical twin is the same walk state exactly: no acceptance
// field exists to grow it.
#[cfg(feature = "traverse-groupless")]
const _: () =
    assert!(core::mem::size_of::<CanonicalCursor<'_>>() == core::mem::size_of::<Cursor<'_>>());

/// The groupless walk over one buffered message.
///
/// Judgment per record, in order: the tag word, field zero, the
/// code class, then the code's own payload discipline. Positions
/// only advance past records the walk delivered, so [`pos`]
/// differences measure whole records.
///
/// The cursor is plain state over the borrowed window, so it is
/// `Copy`: a snapshot is a free lookahead — iterate the copy,
/// resume from the original.
///
/// [`pos`]: Self::pos
#[derive(Clone, Copy)]
#[must_use = "a cursor delivers nothing until iterated"]
pub struct Cursor<'a> {
    /// The walked window. The first fault empties it — fusing
    /// rides the exhausted-window guard, no flag.
    data: &'a [u8],
    /// The next unread byte (equally: the last delivered record's
    /// end). A fault freezes it at the refused head — past the
    /// emptied window's end.
    at: usize,
    /// Head geometry of the last delivered record: tag width in
    /// the low byte, LEN prefix width in the high byte — one field
    /// so a delivery commits both in one store.
    geo: u16,
}

impl<'a> Cursor<'a> {
    /// Admits `data` and stands the walk at its head.
    ///
    /// # Errors
    ///
    /// [`Oversize`] when `data` exceeds the `i32::MAX` input cap
    /// — the admission that keeps every walk coordinate inside `u32`.
    #[inline]
    pub const fn over(data: &'a [u8]) -> Result<Self, Oversize> {
        if data.len() > admission::MAX {
            return Err(Oversize);
        }
        Ok(Self { data, at: 0, geo: 0 })
    }

    /// Builds a cursor over a crate-delivered payload without
    /// repeating admission: a LEN payload is inside the LEN class
    /// by construction, so [`over`](Self::over)'s refusal cannot
    /// arise.
    ///
    /// # Panics
    ///
    /// Panics if `payload` exceeds the LEN class — reachable only
    /// with a slice that never came out of a cursor.
    #[inline]
    #[track_caller]
    pub const fn within(payload: &'a [u8]) -> Self {
        assert!(payload.len() <= admission::MAX, "Cursor::within: payload exceeds the LEN class");
        Self { data: payload, at: 0, geo: 0 }
    }

    /// Byte offset just past the most recently delivered record —
    /// differences measure whole records. Per arm: scalar entries
    /// end past the value, `Len` past the payload. Starts at zero
    /// and, once the walk faults, freezes at the refused record's
    /// head. Query it between deliveries with `while let` around
    /// [`Iterator::next`] — a `for` loop borrows the cursor
    /// exclusively.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "traverse-groupless")] {
    /// use protobuf_edit::traverse::groupless::Cursor;
    ///
    /// // Whole-record spans from `pos` differences.
    /// let msg = [0x08, 0x96, 0x01, 0x12, 0x03, b'a', b'b', b'c'];
    /// let mut cursor = Cursor::over(&msg).unwrap();
    /// let mut spans = Vec::new();
    /// let mut start = cursor.pos();
    /// while let Some(entry) = cursor.next() {
    ///     entry.unwrap();
    ///     spans.push(start..cursor.pos());
    ///     start = cursor.pos();
    /// }
    /// assert_eq!(spans, [0..3, 3..8]);
    /// # }
    /// ```
    #[inline]
    #[must_use]
    pub const fn pos(&self) -> u32 {
        admitted_u32(self.at)
    }

    /// Byte width of the most recently delivered record's head tag
    /// — already parsed by the walk, exposed so re-emitters need
    /// not re-read the head. Zero until the first delivery;
    /// unchanged by faults.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "traverse-groupless")] {
    /// use protobuf_edit::traverse::groupless::Cursor;
    ///
    /// // Field 2, LEN, three payload bytes: one-byte tag, one-byte
    /// // length prefix.
    /// let msg = [0x12, 0x03, b'a', b'b', b'c'];
    /// let mut cursor = Cursor::over(&msg).unwrap();
    /// cursor.next().unwrap().unwrap();
    /// assert_eq!((cursor.tag_width(), cursor.prefix_width()), (1, 1));
    /// # }
    /// ```
    #[cfg(any(
        feature = "rewrite-groupless",
        feature = "inplace-groupless",
        feature = "fixed-inplace-groupless",
        feature = "convert-grouped",
        feature = "splice-groupless",
        feature = "traverse-groupless"
    ))]
    #[inline]
    #[must_use]
    pub const fn tag_width(&self) -> u8 {
        self.geo.to_le_bytes()[0]
    }

    /// Byte width of the most recently delivered record's LEN
    /// length prefix. Zero until the first delivery, and zero when
    /// that record carried no prefix (scalar entries). A traverse
    /// face: the walks read record geometry from `pos` differences
    /// instead.
    #[cfg(feature = "traverse-groupless")]
    #[inline]
    #[must_use]
    pub const fn prefix_width(&self) -> u8 {
        self.geo.to_le_bytes()[1]
    }

    /// Fuses the walk and shapes the fault — the cold tail of every
    /// refusing arm. Fusing empties the window; `at` is not
    /// advanced: `pos` stays at the refused record's head.
    #[cold]
    const fn fault(&mut self, at: usize, kind: FaultKind) -> Option<Result<Entry<'a>, Fault>> {
        self.data = &[];
        Some(Err(Fault { at: admitted_u32(at), kind }))
    }

    /// One walk step, one instance per acceptance standard: the
    /// tolerant instance folds every minimality test away, so the
    /// tolerant cursor pays nothing for the canonical twin. The
    /// minimality gate sits between a word's read and its
    /// classification — the stream scanner's judgment order, which
    /// the cross-machine differentials pin (a padded group tag is
    /// `NonMinimalTag`, never `GroupCode`). Crate-visible: the
    /// selector and rewriter walks instantiate their own acceptance
    /// engines through it.
    #[inline]
    pub(crate) fn step<const MINIMAL: bool>(&mut self) -> Option<Result<Entry<'a>, Fault>> {
        let data = self.data;
        let end = data.len();
        let head = self.at;
        // Equality is the clean end; strict excess is the fused
        // state (the frozen head over the emptied window). The hint
        // keeps the delivery tail, not the walk end, on the
        // fallthrough path — one jump per record.
        if core::hint::unlikely(head >= end) {
            return None;
        }
        let (word, tag_w) = match slice::tag_word(data, head, end) {
            Ok(read) => read,
            Err(cause) => return self.fault(head, FaultKind::Read { stage: Stage::Tag, cause }),
        };
        if MINIMAL && u32::from(tag_w) != encoded_len32(word) {
            return self.fault(head, FaultKind::NonMinimalTag);
        }
        let Some(field) = FieldNumber::from_word(word) else {
            return self.fault(head, FaultKind::FieldZero { word });
        };
        let low3 = Low3::from_word(word);
        let value_at = head + usize::from(tag_w);
        // Each arm commits its own advance and geometry and builds
        // the delivery in place: funneling the observation through
        // one join point would materialize the `EntryKind` at every
        // arm end and rebuild the `Entry` after the join — spilled
        // instructions the per-arm form provably avoids.
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                let (value, width) = match slice::value64(data, value_at, end) {
                    Ok(read) => read,
                    Err(cause) => {
                        return self.fault(
                            value_at,
                            FaultKind::Read { stage: Stage::Value { field }, cause },
                        );
                    }
                };
                if MINIMAL && u32::from(width) != encoded_len64(value) {
                    return self.fault(value_at, FaultKind::NonMinimalValue { field });
                }
                self.at = value_at + usize::from(width);
                self.geo = u16::from(tag_w);
                Some(Ok(Entry { field, kind: EntryKind::Varint(value) }))
            }
            TagClass::Record(RecordKind::I64) => {
                if end - value_at < 8 {
                    return self.fault(value_at, FaultKind::FixedTruncated { field });
                }
                // SAFETY: eight bytes past `value_at` were just
                // proven in bounds; u8 bytes are always initialized
                // and `read_unaligned` carries no alignment
                // obligation.
                let raw = unsafe { data.as_ptr().add(value_at).cast::<u64>().read_unaligned() };
                self.at = value_at + 8;
                self.geo = u16::from(tag_w);
                Some(Ok(Entry { field, kind: EntryKind::I64(u64::from_le(raw)) }))
            }
            TagClass::Record(RecordKind::I32) => {
                if end - value_at < 4 {
                    return self.fault(value_at, FaultKind::FixedTruncated { field });
                }
                // SAFETY: four bytes past `value_at` were just
                // proven in bounds; u8 bytes are always initialized
                // and `read_unaligned` carries no alignment
                // obligation.
                let raw = unsafe { data.as_ptr().add(value_at).cast::<u32>().read_unaligned() };
                self.at = value_at + 4;
                self.geo = u16::from(tag_w);
                Some(Ok(Entry { field, kind: EntryKind::I32(u32::from_le(raw)) }))
            }
            TagClass::Record(RecordKind::Len) => {
                let (len, width) = match slice::len_word(data, value_at, end) {
                    Ok(read) => read,
                    Err(cause) => {
                        return self.fault(
                            value_at,
                            FaultKind::Read { stage: Stage::LenPrefix { field }, cause },
                        );
                    }
                };
                if MINIMAL && u32::from(width) != encoded_len32(len.as_inner()) {
                    return self.fault(value_at, FaultKind::NonMinimalLen { field });
                }
                let payload_at = value_at + usize::from(width);
                let need = usize_of(len.as_inner());
                if end - payload_at < need {
                    return self.fault(payload_at, FaultKind::LenOverrun { field, len });
                }
                // SAFETY: `need` bytes past `payload_at` were just
                // proven in bounds.
                let payload = unsafe { data.get_unchecked(payload_at..payload_at + need) };
                self.at = payload_at + need;
                self.geo = (u16::from(width) << 8) | u16::from(tag_w);
                Some(Ok(Entry { field, kind: EntryKind::Len(payload) }))
            }
            TagClass::GroupCode => self.fault(head, FaultKind::GroupCode { field, code: low3 }),
            TagClass::Unassigned => self.fault(head, FaultKind::Unassigned { field, code: low3 }),
        }
    }
}

/// Delivered records ride `Ok`; the walk's first refusal rides
/// `Err` and fuses the cursor — every later call is `None`, as
/// after a clean end.
impl<'a> Iterator for Cursor<'a> {
    type Item = Result<Entry<'a>, Fault>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.step::<false>()
    }
}

impl core::iter::FusedIterator for Cursor<'_> {}

/// [`Cursor`]'s canonical-minimal twin.
///
/// The same walk, judging every varint word's width against its
/// minimal encoding — a padded tag, length prefix, or value is
/// the matching `NonMinimal*` refusal at the construct's first
/// byte, exactly where the stream scanner's canonical validator
/// judges it.
///
/// A separate concrete type, not a stored standard: the engine
/// instance is picked by the type once, so the tolerant cursor
/// carries no acceptance field and no per-record branch. Same
/// entries, same geometry faces, same fusing discipline.
///
/// # Examples
///
/// ```
/// use protobuf_edit::traverse::groupless::{CanonicalCursor, EntryKind, FaultKind};
///
/// // Minimal wire delivers; 150 padded to three bytes refuses.
/// let clean = [0x08, 0x96, 0x01];
/// let entries: Vec<_> =
///     CanonicalCursor::over(&clean).unwrap().collect::<Result<_, _>>().unwrap();
/// assert_eq!(entries[0].kind(), EntryKind::Varint(150));
///
/// let padded = [0x08, 0x96, 0x81, 0x00];
/// let fault = CanonicalCursor::over(&padded).unwrap().next().unwrap().unwrap_err();
/// assert_eq!(fault.at(), 1);
/// assert!(matches!(fault.kind(), FaultKind::NonMinimalValue { .. }));
/// ```
#[cfg(feature = "traverse-groupless")]
#[derive(Clone, Copy)]
#[must_use = "a cursor delivers nothing until iterated"]
pub struct CanonicalCursor<'a> {
    walk: Cursor<'a>,
}

#[cfg(feature = "traverse-groupless")]
impl<'a> CanonicalCursor<'a> {
    /// Admits `data` and stands the walk at its head
    /// ([`Cursor::over`]).
    ///
    /// # Errors
    ///
    /// [`Oversize`] when `data` exceeds the `i32::MAX` input cap
    /// — the admission that keeps every walk coordinate inside `u32`.
    #[inline]
    pub const fn over(data: &'a [u8]) -> Result<Self, Oversize> {
        match Cursor::over(data) {
            Ok(walk) => Ok(Self { walk }),
            Err(refusal) => Err(refusal),
        }
    }

    /// Builds a cursor over a crate-delivered payload without
    /// repeating admission ([`Cursor::within`]).
    ///
    /// # Panics
    ///
    /// Panics if `payload` exceeds the LEN class — reachable only
    /// with a slice that never came out of a cursor.
    #[inline]
    #[track_caller]
    pub const fn within(payload: &'a [u8]) -> Self {
        Self { walk: Cursor::within(payload) }
    }

    /// Byte offset just past the most recently delivered record
    /// ([`Cursor::pos`]).
    #[inline]
    #[must_use]
    pub const fn pos(&self) -> u32 {
        self.walk.pos()
    }

    /// Byte width of the most recently delivered record's head tag
    /// ([`Cursor::tag_width`]).
    #[inline]
    #[must_use]
    pub const fn tag_width(&self) -> u8 {
        self.walk.tag_width()
    }

    /// Byte width of the most recently delivered record's LEN
    /// length prefix ([`Cursor::prefix_width`]).
    #[inline]
    #[must_use]
    pub const fn prefix_width(&self) -> u8 {
        self.walk.prefix_width()
    }
}

/// Delivered records ride `Ok`; the walk's first refusal rides
/// `Err` and fuses the cursor — every later call is `None`, as
/// after a clean end.
#[cfg(feature = "traverse-groupless")]
impl<'a> Iterator for CanonicalCursor<'a> {
    type Item = Result<Entry<'a>, Fault>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.walk.step::<true>()
    }
}

#[cfg(feature = "traverse-groupless")]
impl core::iter::FusedIterator for CanonicalCursor<'_> {}

#[cfg(test)]
mod tests;
