//! The grouped cursor engine: the six-code walk behind the
//! `traverse` faces, driven directly by the grouped select and
//! rewrite walks.
//!
//! Group tags pair in the walk (the open stack verifies each
//! pairing, bounded by [`GroupDepth`]), LEN payloads deliver
//! opaque, and acceptance is the step instance: `step::<false>`
//! walks width-tolerant, `step::<true>` refuses every non-minimal
//! varint width — the public iterator twins pin one instance each,
//! so neither stores a standard nor branches on one.

use alloc::vec::Vec;

use super::{GroupDepth, Oversize};
use crate::Stage;
use crate::admission::{self, admitted_u32, usize_of};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{encoded_len32, encoded_len64};
use crate::wire::grouped::{RecordKind, TagClass, classify};
#[cfg(feature = "traverse-grouped")]
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
    /// A group opened: entries that follow belong to it until its
    /// matching exit.
    GroupEnter,
    /// The innermost open group closed (the entry names its field).
    GroupExit,
    /// An I32 record's four little-endian payload bytes, as bits.
    I32(u32),
}

/// A walk refusal: where, and which clause broke. The first fault
/// fuses the cursor.
///
/// `at` meanings per kind: [`FaultKind::Read`] names the refused
/// construct's first byte; `FieldZero`, `Unassigned`, and the group
/// family name the head tag; `FixedTruncated` and `LenOverrun` name
/// the payload start; `GroupUnclosed` names the input end.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "traverse-grouped")] {
/// use protobuf_edit::traverse::GroupDepth;
/// use protobuf_edit::traverse::grouped::{Cursor, FaultKind};
///
/// // A group that never closes: the enter delivers, then the
/// // input end faults and fuses the cursor.
/// let mut cursor = Cursor::over(&[0x0B], GroupDepth::REFERENCE).unwrap();
/// assert!(cursor.next().unwrap().is_ok()); // GroupEnter delivers
/// let fault = cursor.next().unwrap().unwrap_err();
/// assert_eq!(fault.at(), 1); // the input end
/// assert!(matches!(
///     fault.kind(),
///     FaultKind::GroupUnclosed { open, opened_at: 0 } if open.as_inner() == 1,
/// ));
/// assert_eq!(cursor.next(), None); // fused
/// # }
/// ```
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

/// The grouped walk's refusal classes, sectioned by
/// [`FaultClass`] (grammar, then policy); [`class`](Self::class)
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
    /// An end tag names a field other than the innermost open
    /// group's.
    GroupEndMismatch {
        /// The open group's field.
        open: FieldNumber,
        /// Where that group opened.
        opened_at: u32,
        /// The field the end tag names.
        found: FieldNumber,
    },
    /// An end tag with no group open.
    GroupEndOrphan {
        /// The field the end tag names.
        found: FieldNumber,
    },
    /// A group still open when the input ends — the innermost, the
    /// one whose end tag was owed next.
    GroupUnclosed {
        /// The open group's field.
        open: FieldNumber,
        /// Where it opened.
        opened_at: u32,
    },
    // ─ policy: the cursor's bound and the canonical twin's
    //   standard ─
    /// A group open would nest past the cursor's declared
    /// [`GroupDepth`] bound.
    DepthExceeded {
        /// The field that would open.
        field: FieldNumber,
        /// The configured bound.
        limit: GroupDepth,
    },
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
}

impl FaultKind {
    /// The refusal's [`FaultClass`] — which repair the fault asks
    /// for. Policy membership names its configuration datum (the
    /// [`GroupDepth`] bound; the `NonMinimal*` family is
    /// [`CanonicalCursor`]'s declared standard); this dialect has
    /// no capability member (its language is the format's whole
    /// code alphabet). A traverse face: the select/rewrite walks
    /// fold kinds into their own vocabularies instead.
    #[cfg(feature = "traverse-grouped")]
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Read { .. }
            | Self::FieldZero { .. }
            | Self::Unassigned { .. }
            | Self::FixedTruncated { .. }
            | Self::LenOverrun { .. }
            | Self::GroupEndMismatch { .. }
            | Self::GroupEndOrphan { .. }
            | Self::GroupUnclosed { .. } => FaultClass::Grammar,
            Self::DepthExceeded { .. }
            | Self::NonMinimalTag
            | Self::NonMinimalLen { .. }
            | Self::NonMinimalValue { .. } => FaultClass::Policy,
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
            FaultKind::GroupEndMismatch { open, opened_at, found } => write!(
                f,
                "end tag at {at} names field {} while group field {} (opened at {opened_at}) \
                 is open",
                found.as_inner(),
                open.as_inner()
            ),
            FaultKind::GroupEndOrphan { found } => {
                write!(f, "end tag at {at} names field {} with no group open", found.as_inner())
            }
            FaultKind::GroupUnclosed { open, opened_at } => {
                write!(f, "group field {} opened at {opened_at} never closes", open.as_inner())
            }
            FaultKind::DepthExceeded { field, limit } => write!(
                f,
                "group field {} at {at} would nest past depth {}",
                field.as_inner(),
                limit.as_inner()
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
    assert!(core::mem::size_of::<Fault>() == 20);
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Cursor<'_>>() == 56
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Cursor<'_>>() <= 56
    });
};

// The canonical twin is the same walk state exactly: no acceptance
// field exists to grow it.
#[cfg(feature = "traverse-grouped")]
const _: () =
    assert!(core::mem::size_of::<CanonicalCursor<'_>>() == core::mem::size_of::<Cursor<'_>>());

/// The grouped walk over one buffered message.
///
/// Judgment per record, in order: the tag word, field zero, the
/// code class, then the code's own payload discipline. Positions
/// only advance past records the walk delivered, so [`pos`]
/// differences measure whole records.
///
/// The cursor is `Clone` for lookahead — iterate the clone,
/// resume from the original. The snapshot duplicates the open
/// stack, so its cost is the current group depth (the groupless
/// twin is stackless and `Copy`).
///
/// [`pos`]: Self::pos
#[derive(Clone)]
#[must_use = "a cursor delivers nothing until iterated"]
pub struct Cursor<'a> {
    /// The walked window. The first fault empties it — fusing
    /// rides the exhausted-window guard, no flag.
    data: &'a [u8],
    /// Open groups: field and open-tag offset, innermost last.
    /// Lazily allocated — group-free walks never touch the heap —
    /// and bounded by `limit` (80 KB at the domain cap).
    opens: Vec<(FieldNumber, u32)>,
    /// The next unread byte (equally: the last delivered record's
    /// end). A fault freezes it at the refused head — past the
    /// emptied window's end.
    at: usize,
    limit: GroupDepth,
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
    pub const fn over(data: &'a [u8], limit: GroupDepth) -> Result<Self, Oversize> {
        if data.len() > admission::MAX {
            return Err(Oversize);
        }
        Ok(Self { data, opens: Vec::new(), at: 0, limit, geo: 0 })
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
    ///
    /// A descending consumer's face: the converter flattens groups
    /// instead of stacking payload walks, so it never compiles it.
    #[cfg(any(
        feature = "select-grouped",
        feature = "rewrite-grouped",
        feature = "inplace-grouped",
        feature = "splice-grouped",
        feature = "traverse-grouped"
    ))]
    #[inline]
    #[track_caller]
    pub const fn within(payload: &'a [u8], limit: GroupDepth) -> Self {
        assert!(payload.len() <= admission::MAX, "Cursor::within: payload exceeds the LEN class");
        Self { data: payload, opens: Vec::new(), at: 0, limit, geo: 0 }
    }

    /// Byte offset just past the most recently delivered record —
    /// differences measure whole records. Per arm: scalar entries
    /// end past the value, `Len` past the payload, group entries
    /// past the tag. Starts at zero and, once the walk faults,
    /// freezes at the refused record's head. Query it between
    /// deliveries with `while let` around [`Iterator::next`] — a
    /// `for` loop borrows the cursor exclusively.
    #[inline]
    #[must_use]
    pub const fn pos(&self) -> u32 {
        admitted_u32(self.at)
    }

    /// Byte width of the most recently delivered record's head tag
    /// — already parsed by the walk, exposed so re-emitters need
    /// not re-read the head. Zero until the first delivery;
    /// unchanged by faults.
    #[cfg(any(
        feature = "rewrite-grouped",
        feature = "inplace-grouped",
        feature = "splice-grouped",
        feature = "traverse-grouped"
    ))]
    #[inline]
    #[must_use]
    pub const fn tag_width(&self) -> u8 {
        self.geo.to_le_bytes()[0]
    }

    /// Byte width of the most recently delivered record's LEN
    /// length prefix. Zero until the first delivery, and zero when
    /// that record carried no prefix (scalar and group entries).
    /// A traverse face: the walks read record geometry from `pos`
    /// differences instead.
    #[cfg(feature = "traverse-grouped")]
    #[inline]
    #[must_use]
    pub const fn prefix_width(&self) -> u8 {
        self.geo.to_le_bytes()[1]
    }

    /// Fuses the walk and shapes the fault — the cold tail of every
    /// refusing arm. Fusing empties the window and the open stack
    /// (so no second `GroupUnclosed` fires); `at` is not advanced:
    /// `pos` stays at the refused record's head.
    #[cold]
    fn fault(&mut self, at: usize, kind: FaultKind) -> Option<Result<Entry<'a>, Fault>> {
        self.data = &[];
        self.opens.clear();
        Some(Err(Fault { at: admitted_u32(at), kind }))
    }

    /// One walk step, one instance per acceptance standard: the
    /// tolerant instance folds every minimality test away, so the
    /// tolerant cursor pays nothing for the canonical twin. The
    /// minimality gate sits between a word's read and its
    /// classification — the stream scanner's judgment order, which
    /// the cross-machine differentials pin (a padded end tag is
    /// `NonMinimalTag`, never a pairing judgment). Crate-visible:
    /// the selector and rewriter walks instantiate their own
    /// acceptance engines through it.
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
            let unclosed = self.opens.last().copied();
            return unclosed.and_then(|(open, opened_at)| {
                self.fault(head, FaultKind::GroupUnclosed { open, opened_at })
            });
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
            TagClass::Record(RecordKind::Group) => {
                if self.opens.len() >= usize::from(self.limit.as_inner()) {
                    return self.fault(head, FaultKind::DepthExceeded { field, limit: self.limit });
                }
                self.opens.push((field, admitted_u32(head)));
                self.at = value_at;
                self.geo = u16::from(tag_w);
                Some(Ok(Entry { field, kind: EntryKind::GroupEnter }))
            }
            TagClass::GroupEnd => match self.opens.pop() {
                Some((open, _)) if open == field => {
                    self.at = value_at;
                    self.geo = u16::from(tag_w);
                    Some(Ok(Entry { field, kind: EntryKind::GroupExit }))
                }
                Some((open, opened_at)) => {
                    self.fault(head, FaultKind::GroupEndMismatch { open, opened_at, found: field })
                }
                None => self.fault(head, FaultKind::GroupEndOrphan { found: field }),
            },
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
/// minimal encoding — a padded tag (group framing included),
/// length prefix, or value is the matching `NonMinimal*` refusal
/// at the construct's first byte, exactly where the stream
/// scanner's canonical validator judges it.
///
/// A separate concrete type, not a stored standard: the engine
/// instance is picked by the type once, so the tolerant cursor
/// carries no acceptance field and no per-record branch. Same
/// entries, same geometry faces, same pairing and fusing
/// discipline.
///
/// # Examples
///
/// ```
/// use protobuf_edit::traverse::GroupDepth;
/// use protobuf_edit::traverse::grouped::{CanonicalCursor, EntryKind, FaultKind};
///
/// // A minimal group pair delivers; a padded end tag refuses as
/// // width, ahead of any pairing judgment.
/// let clean = [0x0B, 0x10, 0x96, 0x01, 0x0C];
/// let entries: Vec<_> = CanonicalCursor::over(&clean, GroupDepth::REFERENCE)
///     .unwrap()
///     .collect::<Result<_, _>>()
///     .unwrap();
/// assert_eq!(entries.len(), 3);
///
/// let padded_end = [0x0B, 0x8C, 0x80, 0x00];
/// let mut cursor = CanonicalCursor::over(&padded_end, GroupDepth::REFERENCE).unwrap();
/// assert!(cursor.next().unwrap().is_ok()); // GroupEnter delivers
/// let fault = cursor.next().unwrap().unwrap_err();
/// assert_eq!(fault.at(), 1);
/// assert!(matches!(fault.kind(), FaultKind::NonMinimalTag));
/// ```
#[cfg(feature = "traverse-grouped")]
#[derive(Clone)]
#[must_use = "a cursor delivers nothing until iterated"]
pub struct CanonicalCursor<'a> {
    walk: Cursor<'a>,
}

#[cfg(feature = "traverse-grouped")]
impl<'a> CanonicalCursor<'a> {
    /// Admits `data` and stands the walk at its head
    /// ([`Cursor::over`]).
    ///
    /// # Errors
    ///
    /// [`Oversize`] when `data` exceeds the `i32::MAX` input cap
    /// — the admission that keeps every walk coordinate inside `u32`.
    #[inline]
    pub const fn over(data: &'a [u8], limit: GroupDepth) -> Result<Self, Oversize> {
        // The tolerant constructor's admission, restated: matching
        // its `Result` out here would ask const evaluation to drop
        // the stack-carrying cursor on the refusal arm.
        if data.len() > admission::MAX {
            return Err(Oversize);
        }
        Ok(Self { walk: Cursor { data, opens: Vec::new(), at: 0, limit, geo: 0 } })
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
    pub const fn within(payload: &'a [u8], limit: GroupDepth) -> Self {
        Self { walk: Cursor::within(payload, limit) }
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
#[cfg(feature = "traverse-grouped")]
impl<'a> Iterator for CanonicalCursor<'a> {
    type Item = Result<Entry<'a>, Fault>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.walk.step::<true>()
    }
}

#[cfg(feature = "traverse-grouped")]
impl core::iter::FusedIterator for CanonicalCursor<'_> {}

#[cfg(test)]
mod tests;
