//! The groupless source-designation carrier: one complete record
//! of the four-code wire language, detached from its machine as
//! exact bytes plus the proved framing facts.
//!
//! Minting is the hosts' business — the inspectors' and editors'
//! `record_ref` faces bind the byte range, field, kind, and met
//! widths of a live source-backed row; no public constructor
//! exists. Projections answer from those stored facts without
//! re-reading a framing word; [`RecordRef::try_canonical`] is the
//! one judgment, walking the record's framing words once against
//! the canonical-minimal standard (the LEN interior is opaque and
//! never participates). A groupless record widens to the grouped
//! dialect without judgment — every groupless record is lawful
//! grouped wire.

use crate::Stage;
use crate::admission::usize_of;
use crate::varint::slice;
use crate::varint::{WordWidth, encoded_len32, encoded_len64};
use crate::wire::FieldNumber;
use crate::wire::groupless::RecordKind;

/// Why a designation was refused: the minting judgments and the
/// canonical-standard judgment, one closed alphabet.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// The row's record extent runs past the parsed prefix; a
    /// designation names complete records only.
    IncompleteRecord {
        /// Offset where the parse stopped, in the host's source
        /// coordinates.
        at: u32,
    },
    /// The row is not a live original source occurrence: authored,
    /// copied, imported, shrouded, suppressed, or orphaned rows do
    /// not designate.
    NotSourceBacked,
    /// `payload` was asked of a non-LEN record.
    KindMismatch {
        /// The record's actual kind.
        have: RecordKind,
    },
    /// A framing word or varint value is wider than its value's own
    /// encoding — the record is tolerant wire, not canonical.
    StandardMismatch {
        /// Offset of the padded construct, relative to the record's
        /// first byte.
        at: u32,
        /// The construct the padded word was serving.
        stage: Stage,
    },
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::IncompleteRecord { at } => {
                write!(f, "record runs past the parsed prefix ending at {at}")
            }
            Self::NotSourceBacked => f.write_str("row is not a live original source occurrence"),
            Self::KindMismatch { have } => {
                write!(f, "payload asked of a non-LEN record; the record is {have}")
            }
            Self::StandardMismatch { at, .. } => {
                write!(f, "padded framing word at record offset {at}")
            }
        }
    }
}

impl core::error::Error for Fault {}

/// The record's framing partition at the widths the host actually
/// met: `tag ⊎ delim ⊎ payload`, in wire order, union the whole
/// byte range. Private — the partition is minted proof, never
/// caller input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Geometry {
    /// The head tag's met width.
    tag_w: WordWidth,
    /// The LEN length prefix's met width; `None` for scalars.
    delim_w: Option<WordWidth>,
    /// The payload extent: a LEN's declared length, a varint
    /// value's width, or 4/8 for the fixed kinds.
    payload_len: u32,
}

/// One complete groupless record, designated: exact source bytes
/// plus the proved field, kind, and framing geometry.
///
/// The bytes are the whole record — head tag through its last byte
/// — borrowed from the minting host's backing at `'s`. The
/// designation names the original admitted occurrence: minting from
/// an edited handle still binds the source reading, and rows
/// without one (authored, copied, imported, shrouded) refuse to
/// mint.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "inspect-groupless")] {
/// use protobuf_edit::DepthLimit;
/// use protobuf_edit::inspect::{Admitted, NoAdvice};
/// use protobuf_edit::inspect::groupless::Tree;
/// use protobuf_edit::wire::groupless::RecordKind;
///
/// // varint f1=150, value padded to two bytes: the designation
/// // carries the met spelling.
/// let msg = [0x08, 0x96, 0x81, 0x00];
/// let input = Admitted::new(&msg).unwrap();
/// let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
/// let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
/// assert_eq!(record.as_bytes(), msg);
/// assert_eq!(record.kind(), RecordKind::Varint);
/// assert_eq!(record.field().as_inner(), 1);
/// # }
/// ```
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecordRef<'s> {
    bytes: &'s [u8],
    field: FieldNumber,
    kind: RecordKind,
    geometry: Geometry,
    /// Whether the minting host already proved every framing word
    /// minimal (canonical admission); `try_canonical` spends it.
    canonical: bool,
}

impl<'s> RecordRef<'s> {
    // Minted by the read and edit machines, and by the grouped
    // module's dialect narrowing. A lone construct cut compiles it
    // unread: the precise gate is a feature conjunction (construct
    // with the grouped module present), which the monotone-gate
    // law forbids — the armed expectation below carries that cut.
    #[cfg(any(
        feature = "inspect-groupless",
        feature = "fixed-inspect-groupless",
        feature = "retain-groupless",
        feature = "patch-groupless",
        feature = "fixed-patch-groupless",
        feature = "adopt-groupless",
        feature = "amend-groupless",
        feature = "intake-groupless",
        feature = "markup-groupless",
        feature = "draft-groupless",
        feature = "review-groupless",
        feature = "session-groupless",
        feature = "stream-adopt-groupless",
        feature = "stream-draft-groupless",
        feature = "stream-intake-groupless",
        feature = "collect-groupless",
        feature = "construct-groupless"
    ))]
    #[cfg_attr(
        all(
            not(any(
                feature = "inspect-groupless",
                feature = "fixed-inspect-groupless",
                feature = "retain-groupless",
                feature = "patch-groupless",
                feature = "fixed-patch-groupless",
                feature = "adopt-groupless",
                feature = "amend-groupless",
                feature = "intake-groupless",
                feature = "markup-groupless",
                feature = "draft-groupless",
                feature = "review-groupless",
                feature = "session-groupless",
                feature = "stream-adopt-groupless",
                feature = "stream-draft-groupless",
                feature = "stream-intake-groupless",
                feature = "collect-groupless"
            )),
            not(any(
                feature = "inspect-grouped",
                feature = "fixed-inspect-grouped",
                feature = "retain-grouped",
                feature = "patch-grouped",
                feature = "fixed-patch-grouped",
                feature = "adopt-grouped",
                feature = "amend-grouped",
                feature = "intake-grouped",
                feature = "markup-grouped",
                feature = "draft-grouped",
                feature = "review-grouped",
                feature = "session-grouped",
                feature = "stream-adopt-grouped",
                feature = "stream-draft-grouped",
                feature = "stream-intake-grouped",
                feature = "collect-grouped",
                feature = "construct-grouped"
            ))
        ),
        expect(
            dead_code,
            reason = "a lone construct cut has no reader: the mint's readers are this \
                      dialect's hosts and the grouped module's narrowing converter, \
                      whose gate mirrors the mint's own — in any cut that compiles the \
                      mint, the converter reads it exactly when a grouped feature is \
                      on"
        )
    )]
    /// Crate-internal mint: the host binds the exact record slice
    /// and its proved partition. `bytes` must be the complete
    /// record, `tag_w ⊎ delim_w ⊎ payload_len` must partition it,
    /// and `canonical` must hold only under a canonical-admission
    /// proof.
    pub(crate) fn mint(
        bytes: &'s [u8],
        field: FieldNumber,
        kind: RecordKind,
        tag_w: WordWidth,
        delim_w: Option<WordWidth>,
        payload_len: u32,
        canonical: bool,
    ) -> Self {
        debug_assert!(
            tag_w.w() + delim_w.map_or(0, WordWidth::w) + payload_len
                == crate::admission::admitted_u32(bytes.len()),
            "a designation's partition covers its record exactly"
        );
        Self { bytes, field, kind, geometry: Geometry { tag_w, delim_w, payload_len }, canonical }
    }

    /// The exact record bytes: met tag spelling, framing words at
    /// their met widths, the whole payload.
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'s [u8] {
        self.bytes
    }

    /// The record's field number.
    #[inline]
    pub const fn field(&self) -> FieldNumber {
        self.field
    }

    /// The record's wire kind.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.kind
    }

    /// The LEN interior as a detached payload view.
    ///
    /// # Errors
    ///
    /// [`Fault::KindMismatch`] unless the record is a LEN.
    #[inline]
    pub fn payload(&self) -> Result<super::PayloadRef<'s>, Fault> {
        if !matches!(self.kind, RecordKind::Len) {
            return Err(Fault::KindMismatch { have: self.kind });
        }
        let at = usize_of(self.geometry.tag_w.w() + self.geometry.delim_w.map_or(0, WordWidth::w));
        // The mint invariant: the partition covers the record slice
        // exactly, so the payload subspan is in bounds.
        Ok(super::PayloadRef::new(&self.bytes[at..at + usize_of(self.geometry.payload_len)]))
    }

    /// Judges the record against the canonical-minimal standard and
    /// mints the proof-carrying form. A record minted by a
    /// canonical-admission host carries the proof already and
    /// re-judges nothing; otherwise the record's framing words —
    /// head tag, then the varint value or LEN length prefix — are
    /// walked once, and the first padded word refuses. The LEN
    /// interior is opaque: padded words inside it are payload
    /// bytes, not framing, and never block the proof.
    ///
    /// # Errors
    ///
    /// [`Fault::StandardMismatch`] at the first non-minimal framing
    /// word or varint value.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "inspect-groupless")] {
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::inspect::{Admitted, NoAdvice};
    /// use protobuf_edit::inspect::groupless::Tree;
    /// use protobuf_edit::source::groupless::Fault;
    /// use protobuf_edit::Stage;
    ///
    /// // varint f1=150 minimal · varint f2, value padded.
    /// let msg = [0x08, 0x96, 0x01, 0x10, 0x81, 0x00];
    /// let input = Admitted::new(&msg).unwrap();
    /// let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    /// let tops: Vec<_> = tree.top().collect();
    ///
    /// let minimal = tree.record_ref(tops[0]).unwrap();
    /// assert!(minimal.try_canonical().is_ok());
    ///
    /// let padded = tree.record_ref(tops[1]).unwrap();
    /// assert!(matches!(
    ///     padded.try_canonical(),
    ///     Err(Fault::StandardMismatch { at: 1, stage: Stage::Value { .. } })
    /// ));
    /// # }
    /// ```
    pub fn try_canonical(self) -> Result<CanonicalRecordRef<'s>, Fault> {
        if self.canonical {
            return Ok(CanonicalRecordRef(self));
        }
        let tag_w = self.geometry.tag_w.w();
        if tag_w > encoded_len32(crate::wire::groupless::head_word(self.field, self.kind)) {
            return Err(Fault::StandardMismatch { at: 0, stage: Stage::Tag });
        }
        match self.kind {
            RecordKind::Varint => {
                // The mint invariant: the value bytes are a complete
                // in-class varint, so the bounded read cannot refuse.
                let Ok((value, width)) =
                    slice::value64(self.bytes, usize_of(tag_w), self.bytes.len())
                else {
                    unreachable!("minted records are structurally complete")
                };
                if u32::from(width) > encoded_len64(value) {
                    return Err(Fault::StandardMismatch {
                        at: tag_w,
                        stage: Stage::Value { field: self.field },
                    });
                }
            }
            RecordKind::Len => {
                if self.geometry.delim_w.map_or(0, WordWidth::w)
                    > encoded_len32(self.geometry.payload_len)
                {
                    return Err(Fault::StandardMismatch {
                        at: tag_w,
                        stage: Stage::LenPrefix { field: self.field },
                    });
                }
            }
            RecordKind::I32 | RecordKind::I64 => {}
        }
        Ok(CanonicalRecordRef(Self { canonical: true, ..self }))
    }

    /// Widens the designation into the grouped dialect, judgment
    /// free: every groupless record is lawful grouped wire, and no
    /// group structure exists to measure (the relative group depth
    /// is zero).
    // The destination module's own union: the widening exists
    // exactly where the grouped module does.
    #[cfg(any(
        feature = "inspect-grouped",
        feature = "fixed-inspect-grouped",
        feature = "retain-grouped",
        feature = "patch-grouped",
        feature = "fixed-patch-grouped",
        feature = "adopt-grouped",
        feature = "amend-grouped",
        feature = "intake-grouped",
        feature = "markup-grouped",
        feature = "draft-grouped",
        feature = "review-grouped",
        feature = "session-grouped",
        feature = "stream-adopt-grouped",
        feature = "stream-draft-grouped",
        feature = "stream-intake-grouped",
        feature = "collect-grouped",
        feature = "construct-grouped"
    ))]
    pub fn widen(self) -> super::grouped::RecordRef<'s> {
        let kind = match self.kind {
            RecordKind::Varint => crate::wire::grouped::RecordKind::Varint,
            RecordKind::I64 => crate::wire::grouped::RecordKind::I64,
            RecordKind::Len => crate::wire::grouped::RecordKind::Len,
            RecordKind::I32 => crate::wire::grouped::RecordKind::I32,
        };
        super::grouped::RecordRef::mint(
            self.bytes,
            self.field,
            kind,
            self.geometry.tag_w,
            self.geometry.delim_w,
            self.geometry.payload_len,
            0,
            self.canonical,
        )
    }
}

/// A [`RecordRef`] whose every framing word is proven minimal —
/// the admission proof a canonical host's whole-record import
/// spends instead of re-judging.
///
/// Minted by [`RecordRef::try_canonical`] alone (canonical-
/// admission hosts mint records that carry the proof, so their
/// `try_canonical` never walks). The LEN interior stays the
/// source's opaque declaration: the proof covers framing words
/// only, which is exactly what a canonical destination re-emits.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CanonicalRecordRef<'s>(RecordRef<'s>);

impl<'s> CanonicalRecordRef<'s> {
    /// The tolerant view of the same designation.
    #[inline]
    pub const fn record_ref(self) -> RecordRef<'s> {
        self.0
    }

    /// The exact record bytes ([`RecordRef::as_bytes`]).
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &'s [u8] {
        self.0.as_bytes()
    }

    /// The record's field number.
    #[inline]
    pub const fn field(&self) -> FieldNumber {
        self.0.field()
    }

    /// The record's wire kind.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> RecordKind {
        self.0.kind()
    }

    /// The LEN interior as a detached payload view.
    ///
    /// # Errors
    ///
    /// [`Fault::KindMismatch`] unless the record is a LEN.
    #[inline]
    pub fn payload(&self) -> Result<super::PayloadRef<'s>, Fault> {
        self.0.payload()
    }
}

#[cfg(test)]
mod tests;
