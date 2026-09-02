//! The grouped source-designation carrier: one complete record of
//! the six-code wire language, detached from its machine as exact
//! bytes plus the proved framing facts.
//!
//! A group travels with its whole structural closure and matching
//! end tag.
//!
//! Minting is the hosts' business — the inspectors' and editors'
//! `record_ref` faces bind the byte range, field, kind, met widths,
//! and relative group depth of a live source-backed row; no public
//! constructor exists. Projections answer from those stored facts;
//! [`RecordRef::try_canonical`] is the one judgment, walking the
//! record's framing words once against the canonical-minimal
//! standard. The opacity boundary is the dialect's own: a LEN
//! interior is an opaque declaration and never participates, while
//! a group interior is structural wire and always does. A grouped
//! record narrows to the groupless dialect only under the
//! common-kind proof — its outer kind is not a group.

use crate::Stage;
use crate::admission::usize_of;
use crate::varint::slice;
use crate::varint::{WordWidth, encoded_len32, encoded_len64};
use crate::wire::grouped::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3};

/// Why a designation was refused: the minting judgments, the
/// canonical-standard judgment, and the dialect narrowing, one
/// closed alphabet.
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
    /// `payload` was asked of a non-LEN record (a group's interior
    /// is structural wire, not a payload).
    KindMismatch {
        /// The record's actual kind.
        have: RecordKind,
    },
    /// The record cannot narrow to the groupless dialect: its outer
    /// kind is a group.
    DialectMismatch {
        /// The record's actual kind.
        have: RecordKind,
    },
    /// A framing word or varint value is wider than its value's own
    /// encoding — the record is tolerant wire, not canonical.
    StandardMismatch {
        /// Offset of the padded construct, relative to the record's
        /// first byte (group end tags judge as tag words).
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
            Self::DialectMismatch { have } => {
                write!(f, "a {have} record does not narrow to the groupless dialect")
            }
            Self::StandardMismatch { at, .. } => {
                write!(f, "padded framing word at record offset {at}")
            }
        }
    }
}

impl core::error::Error for Fault {}

/// The record's framing partition at the widths the host actually
/// met. For scalars and LENs the order is `tag ⊎ delim ⊎ payload`;
/// for a group it is `tag ⊎ interior(payload) ⊎ end tag(delim)` —
/// the delimiter is the matching end tag, trailing. Private — the
/// partition is minted proof, never caller input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Geometry {
    /// The head tag's met width.
    tag_w: WordWidth,
    /// The second framing word's met width: a LEN's length prefix
    /// or a group's end tag; `None` for scalars.
    delim_w: Option<WordWidth>,
    /// The payload extent: a LEN's declared length, a group's
    /// interior length, a varint value's width, or 4/8 for the
    /// fixed kinds.
    payload_len: u32,
}

/// One complete grouped record, designated: exact source bytes
/// plus the proved field, kind, framing geometry, and relative
/// group depth.
///
/// The bytes are the whole record — head tag through its last byte,
/// a group's matching end tag included — borrowed from the minting
/// host's backing at `'s`. The designation names the original
/// admitted occurrence: minting from an edited handle still binds
/// the source reading, and rows without one (authored, copied,
/// imported, shrouded) refuse to mint.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "inspect-grouped")] {
/// use protobuf_edit::DepthLimit;
/// use protobuf_edit::inspect::{Admitted, NoAdvice};
/// use protobuf_edit::inspect::grouped::Tree;
/// use protobuf_edit::wire::grouped::RecordKind;
///
/// // Group f1 { varint f2=5 }: the designation is the closure,
/// // end tag included, one level of group structure.
/// let msg = [0x0B, 0x10, 0x05, 0x0C];
/// let input = Admitted::new(&msg).unwrap();
/// let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
/// let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
/// assert_eq!(record.as_bytes(), msg);
/// assert_eq!(record.kind(), RecordKind::Group);
/// assert_eq!(record.group_depth(), 1);
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
    /// of the closure minimal (canonical admission);
    /// `try_canonical` spends it.
    canonical: bool,
    /// The record's own structural group nesting: zero for scalars
    /// and LENs, one plus the deepest nested group for a group (LEN
    /// interiors are opaque and contribute nothing). A `u32` fact:
    /// unbounded-depth hosts mint closures past the sixteen-bit
    /// edge, while the source cap bounds nesting well inside this
    /// width.
    group_depth: u32,
}

impl<'s> RecordRef<'s> {
    // Minted by the read and edit machines, and by the groupless
    // module's dialect widening. A lone construct cut compiles it
    // unread: the precise gate is a feature conjunction (construct
    // with the groupless module present), which the monotone-gate
    // law forbids — the armed expectation below carries that cut.
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
    #[cfg_attr(
        all(
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
                feature = "collect-grouped"
            )),
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
                feature = "collect-groupless",
                feature = "construct-groupless"
            ))
        ),
        expect(
            dead_code,
            reason = "a lone construct cut has no reader: the mint's readers are this \
                      dialect's hosts and the groupless module's widening converter, \
                      whose gate mirrors the mint's own — in any cut that compiles the \
                      mint, the converter reads it exactly when a groupless feature is \
                      on"
        )
    )]
    /// Crate-internal mint: the host binds the exact record slice
    /// and its proved partition. `bytes` must be the complete
    /// record (a group's closure with its end tag),
    /// `tag_w ⊎ delim_w ⊎ payload_len` must partition it,
    /// `group_depth` must be the closure's measured structural
    /// nesting, and `canonical` must hold only under a
    /// canonical-admission proof.
    #[allow(
        clippy::too_many_arguments,
        reason = "the mint binds every stored fact once; a parameter struct would respell the type"
    )]
    pub(crate) fn mint(
        bytes: &'s [u8],
        field: FieldNumber,
        kind: RecordKind,
        tag_w: WordWidth,
        delim_w: Option<WordWidth>,
        payload_len: u32,
        group_depth: u32,
        canonical: bool,
    ) -> Self {
        debug_assert!(
            tag_w.w() + delim_w.map_or(0, WordWidth::w) + payload_len
                == crate::admission::admitted_u32(bytes.len()),
            "a designation's partition covers its record exactly"
        );
        debug_assert!(
            matches!(kind, RecordKind::Group) == (group_depth > 0),
            "group depth counts group closures alone"
        );
        Self {
            bytes,
            field,
            kind,
            geometry: Geometry { tag_w, delim_w, payload_len },
            canonical,
            group_depth,
        }
    }

    /// The exact record bytes: met tag spelling, framing words at
    /// their met widths, the whole payload or group closure.
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

    /// The record's own structural group nesting: zero for scalars
    /// and LENs, one plus the deepest nested group for a group. LEN
    /// interiors are opaque declarations and contribute nothing,
    /// whatever bytes they hold. Derived from the original source
    /// occurrence alone: authored, copied, and imported structure
    /// under the closure does not ride.
    #[inline]
    #[must_use]
    pub const fn group_depth(&self) -> u32 {
        self.group_depth
    }

    /// The LEN interior as a detached payload view. A group has no
    /// payload: its interior is structural wire, carried whole by
    /// [`RecordRef::as_bytes`].
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
    /// re-judges nothing; otherwise the record's framing words are
    /// walked once and the first padded word refuses. The opacity
    /// boundary is the dialect's own: a LEN interior never
    /// participates, while a group's whole structural closure —
    /// every interior tag, varint value, LEN prefix, and end tag —
    /// must prove minimal.
    ///
    /// # Errors
    ///
    /// [`Fault::StandardMismatch`] at the first non-minimal framing
    /// word or varint value (group end tags judge as tag words).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(feature = "inspect-grouped")] {
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::inspect::{Admitted, NoAdvice};
    /// use protobuf_edit::inspect::grouped::Tree;
    /// use protobuf_edit::source::grouped::Fault;
    ///
    /// // Group f1 { varint f2, value padded }: the closure is
    /// // structural, so the interior padding refuses the proof.
    /// let msg = [0x0B, 0x10, 0x81, 0x00, 0x0C];
    /// let input = Admitted::new(&msg).unwrap();
    /// let tree = Tree::parse(input, DepthLimit::REFERENCE, &mut NoAdvice);
    /// let record = tree.record_ref(tree.top().next().unwrap()).unwrap();
    /// assert!(matches!(
    ///     record.try_canonical(),
    ///     Err(Fault::StandardMismatch { at: 2, .. })
    /// ));
    /// # }
    /// ```
    pub fn try_canonical(self) -> Result<CanonicalRecordRef<'s>, Fault> {
        if self.canonical {
            return Ok(CanonicalRecordRef(self));
        }
        let tag_w = self.geometry.tag_w.w();
        if tag_w > encoded_len32(crate::wire::grouped::head_word(self.field, self.kind)) {
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
            RecordKind::Group => self.canonical_closure(tag_w)?,
            RecordKind::I32 | RecordKind::I64 => {}
        }
        Ok(CanonicalRecordRef(Self { canonical: true, ..self }))
    }

    /// The group-closure leg of the canonical judgment: walks the
    /// interior structurally from past the head tag through the
    /// matching end tag, judging every framing word and varint
    /// value; LEN interiors are skipped whole. Reads cannot refuse
    /// — the mint invariant proves the closure structurally
    /// complete.
    fn canonical_closure(&self, mut pos: u32) -> Result<(), Fault> {
        let extent = self.bytes.len();
        let mut depth = 1u32;
        while depth > 0 {
            let Ok((word, width)) = slice::tag_word(self.bytes, usize_of(pos), extent) else {
                unreachable!("minted group closures are structurally complete")
            };
            if u32::from(width) > encoded_len32(word) {
                return Err(Fault::StandardMismatch { at: pos, stage: Stage::Tag });
            }
            let Some(field) = FieldNumber::from_word(word) else {
                unreachable!("minted group closures carry no zero fields")
            };
            let value_at = pos + u32::from(width);
            match classify(Low3::from_word(word)) {
                TagClass::Record(kind) => match kind {
                    RecordKind::Varint => {
                        let Ok((value, w)) = slice::value64(self.bytes, usize_of(value_at), extent)
                        else {
                            unreachable!("minted group closures are structurally complete")
                        };
                        if u32::from(w) > encoded_len64(value) {
                            return Err(Fault::StandardMismatch {
                                at: value_at,
                                stage: Stage::Value { field },
                            });
                        }
                        pos = value_at + u32::from(w);
                    }
                    RecordKind::I32 => pos = value_at + 4,
                    RecordKind::I64 => pos = value_at + 8,
                    RecordKind::Len => {
                        let Ok((len, w)) = slice::len_word(self.bytes, usize_of(value_at), extent)
                        else {
                            unreachable!("minted group closures are structurally complete")
                        };
                        if u32::from(w) > encoded_len32(len.as_inner()) {
                            return Err(Fault::StandardMismatch {
                                at: value_at,
                                stage: Stage::LenPrefix { field },
                            });
                        }
                        pos = value_at + u32::from(w) + len.as_inner();
                    }
                    RecordKind::Group => {
                        depth += 1;
                        pos = value_at;
                    }
                },
                TagClass::GroupEnd => {
                    depth -= 1;
                    pos = value_at;
                }
                TagClass::Unassigned => {
                    unreachable!("minted group closures carry assigned codes only")
                }
            }
        }
        Ok(())
    }

    /// Narrows the designation into the groupless dialect under the
    /// common-kind proof: the outer kind must not be a group. The
    /// LEN interior stays opaque and does not participate in the
    /// judgment, whatever bytes it holds.
    ///
    /// # Errors
    ///
    /// [`Fault::DialectMismatch`] when the record is a group.
    // The destination module's own union: the narrowing exists
    // exactly where the groupless module does.
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
    pub fn try_groupless(self) -> Result<super::groupless::RecordRef<'s>, Fault> {
        let kind = match self.kind {
            RecordKind::Varint => crate::wire::groupless::RecordKind::Varint,
            RecordKind::I64 => crate::wire::groupless::RecordKind::I64,
            RecordKind::Len => crate::wire::groupless::RecordKind::Len,
            RecordKind::I32 => crate::wire::groupless::RecordKind::I32,
            RecordKind::Group => return Err(Fault::DialectMismatch { have: self.kind }),
        };
        Ok(super::groupless::RecordRef::mint(
            self.bytes,
            self.field,
            kind,
            self.geometry.tag_w,
            self.geometry.delim_w,
            self.geometry.payload_len,
            self.canonical,
        ))
    }
}

/// A [`RecordRef`] whose every framing word — the whole group
/// closure included — is proven minimal: the admission proof a
/// canonical host's whole-record import spends instead of
/// re-judging.
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

    /// The record's own structural group nesting
    /// ([`RecordRef::group_depth`]).
    #[inline]
    #[must_use]
    pub const fn group_depth(&self) -> u32 {
        self.0.group_depth()
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
