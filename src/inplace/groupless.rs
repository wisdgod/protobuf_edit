//! The groupless in-place editor: group codes are outside the
//! language.
//!
//! Without groups every record stands alone or nests through LEN
//! framing only, so the judge walk keeps one explicit layer stack
//! over the traversal cursor and nothing else: group codes surface
//! as the traversal's `GroupCode` capability refusal, inherited
//! through the [`WireBreach`] wrapper, and the grouped twin owns
//! such documents.
//!
//! The machine shape is the shared layer's ([`crate::inplace`]):
//! one read-only judge walk proves every write against met
//! geometry, `Err` returns with the buffer byte-identical to
//! entry, and the write loop past the barrier is infallible,
//! allocation-free, and panic-free.
//!
//! The depth bound is the committed-descent budget: a rule path
//! crossing a LEN commits its payload to be a message, and
//! nesting past the caller's [`DepthLimit`] refuses as
//! [`WireBreach::Depth`].
//!
//! Coordinates: write · buffered · static · groupless · Standard (value-level) · in-place · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::inplace::groupless::apply;
//! use protobuf_edit::inplace::{Action, Rule, RuleSet};
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Replace field 1 at any depth along the field-3 route (the
//! // wildcard also matches zero crossings). The slot is two bytes
//! // wide, so the one-byte value 9 lands continuation-padded —
//! // equal width is the machine's law.
//! let route = [FieldNumber::new(3).unwrap()];
//! let rules = [Rule {
//!     path: &[
//!         Segment::AnyDepth { descend: &route },
//!         Segment::Field(FieldNumber::new(1).unwrap()),
//!     ],
//!     action: Action::SetVarint(9),
//! }];
//! let set = RuleSet::over(&rules).unwrap();
//!
//! // LEN f3 { varint f1=150 } · varint f1=150
//! let mut msg = [0x1A, 0x03, 0x08, 0x96, 0x01, 0x08, 0x96, 0x01];
//! let stats = apply(&mut msg, &set, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(msg, [0x1A, 0x03, 0x08, 0x89, 0x00, 0x08, 0x89, 0x00]);
//! assert_eq!(stats.replaced(), 2);
//! ```

use alloc::vec::Vec;

use super::{Action, RuleSet, Stats, Write, action, filler_need, width_fits};
use crate::path::{Hits, Matcher};
use crate::cursor::groupless::{Cursor, EntryKind};
use crate::varint::{ValueWidth, WordWidth, encoded_len32, encoded_len64};
use crate::wire::groupless::{RecordKind, head_word};
use crate::{DepthLimit, FaultClass, Standard};

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
    /// names (for the width refusals: the record head).
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

/// The groupless in-place editor's refusal classes.
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
/// spelling.
///
/// [`ValueWidth`]: Self::ValueWidth
/// [`TagWidth`]: Self::TagWidth
/// [`PayloadLength`]: Self::PayloadLength
/// [`ReplacementLength`]: Self::ReplacementLength
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
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
// allocation: rule indices and byte coordinates name everything).
const _: () = {
    assert!(core::mem::size_of::<FaultKind>() == 16);
    assert!(core::mem::size_of::<Fault>() == 20);
};

// ─── the judge walk (phase one) ───

/// One committed LEN layer on the explicit stack.
struct Layer<'i> {
    cursor: Cursor<'i>,
    /// Absolute base of this layer's window.
    base: u32,
    /// LEN crossings still allowed below this layer.
    remaining: u16,
}

const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Layer<'_>>() == 40
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Layer<'_>>() <= 40
    });
};

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
/// raise surfaces here; `Ok` carries the complete write list,
/// every entry proven against the current bytes.
#[allow(
    clippy::too_many_lines,
    reason = "one loop, one record fold — the dialect's whole judgment in one place, \
              the walk-skeleton convention of the static write machines"
)]
fn walk<'r, const MINIMAL: bool>(
    input: &[u8],
    set: &RuleSet<'r>,
    limit: DepthLimit,
) -> Result<(Vec<Write<'r>>, Stats), Fault> {
    let mut matcher = Matcher::new(*set);
    let mut writes: Vec<Write<'r>> = Vec::new();
    let mut stats = Stats::default();
    let Ok(root) = Cursor::over(input) else {
        return Err(Fault { at: 0, kind: FaultKind::Oversize });
    };
    let mut layers: Vec<Layer<'_>> = Vec::new();
    layers.push(Layer { cursor: root, base: 0, remaining: limit.as_inner() });

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
                return Ok((writes, stats));
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
                        #[allow(
                            clippy::as_conversions,
                            reason = "cursor-delivered value widths are 1..=10"
                        )]
                        writes.push(Write::Varint {
                            at: value_at,
                            // SAFETY: the slot width is the walk's
                            // value window — geometry subtraction
                            // over the cursor's met value read,
                            // 1..=10.
                            width: unsafe { ValueWidth::met_unchecked(have as u8) },
                            value,
                        });
                        stats.replaced += 1;
                    }
                    (Action::SetI32(bits), EntryKind::I32(_)) => {
                        writes.push(Write::Fixed32 { at: value_at, bits });
                        stats.replaced += 1;
                    }
                    (Action::SetI64(bits), EntryKind::I64(_)) => {
                        writes.push(Write::Fixed64 { at: value_at, bits });
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
                        writes.push(Write::Tag {
                            at: head,
                            // SAFETY: the slot width is the walk's
                            // framing window — the cursor's met tag
                            // read, 1..=5.
                            width: unsafe { WordWidth::met_unchecked(layer.cursor.tag_width()) },
                            word,
                        });
                        stats.renumbered += 1;
                    }
                    (Action::ReplaceRecord(bytes), _) => {
                        judge_replacement::<MINIMAL>(rule, bytes, head, end - head)?;
                        writes.push(Write::Payload { at: head, bytes });
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
                        writes.push(Write::Filler { at: head, width: have, field: filler });
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
                            writes.push(Write::Payload { at: payload_start, bytes });
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
                            writes.push(Write::Tag {
                                at: head,
                                // SAFETY: the slot width is the
                                // walk's framing window — the
                                // cursor's met tag read, 1..=5.
                                width: unsafe {
                                    WordWidth::met_unchecked(layer.cursor.tag_width())
                                },
                                word,
                            });
                            stats.renumbered += 1;
                            // A renumber touches the tag alone —
                            // the interior stays live (tag and
                            // interior extents are disjoint).
                            walk_in = routed;
                        }
                        Action::ReplaceRecord(bytes) => {
                            judge_replacement::<MINIMAL>(rule, bytes, head, end - head)?;
                            writes.push(Write::Payload { at: head, bytes });
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
                            writes.push(Write::Filler { at: head, width: have, field: filler });
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
                    layers.push(Layer {
                        cursor: Cursor::within(payload),
                        base: payload_start,
                        remaining: remaining - 1,
                    });
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

/// One job, one instance per acceptance standard: the judge walk
/// proves every write, then the infallible loop lands them.
fn run<'r, const MINIMAL: bool>(
    buf: &mut [u8],
    rules: &RuleSet<'r>,
    limit: DepthLimit,
) -> Result<Stats, Fault> {
    let (writes, stats) = walk::<MINIMAL>(buf, rules, limit)?;
    super::commit::<MINIMAL>(buf, &writes);
    Ok(stats)
}

/// Applies `rules` to `buf` in place under tolerant acceptance,
/// with the job receipt.
///
/// The buffer is the product: on `Ok` it differs exactly at the
/// planned write extents and re-ingests under `Tolerant`; on
/// `Err` it is byte-identical to entry — every fault precedes the
/// first write. Authored varint words may land continuation-padded
/// to their slots (declare `CanonicalMinimal` through
/// [`apply_standard`] and no padding is ever authored).
///
/// # Errors
///
/// [`Fault`] when the input refuses admission, a committed descent
/// (or the top level) hits unlawful wire (group codes included —
/// the capability refusal), two rules target one record, an action
/// does not fit its record's kind, width, or extent, a replacement
/// candidate refuses, or the depth budget runs out. `buf` is
/// untouched on `Err`.
///
/// # Examples
///
/// ```
/// use protobuf_edit::inplace::groupless::apply;
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
/// let stats = apply(&mut msg, &set, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(msg, [0x08, 0x96, 0x01, 0x48, 0x80, 0x80, 0x00]);
/// assert_eq!(stats.tombstoned(), 1);
/// ```
#[inline]
pub fn apply(buf: &mut [u8], rules: &RuleSet<'_>, limit: DepthLimit) -> Result<Stats, Fault> {
    run::<false>(buf, rules, limit)
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
/// use protobuf_edit::inplace::groupless::{FaultKind, apply_standard};
/// use protobuf_edit::inplace::{Action, Rule, RuleSet};
/// use protobuf_edit::path::Segment;
/// use protobuf_edit::{DepthLimit, FieldNumber, Standard};
///
/// let f1 = FieldNumber::new(1).unwrap();
/// let rules =
///     [Rule { path: &[Segment::Field(f1)], action: Action::SetVarint(7) }];
/// let set = RuleSet::over(&rules).unwrap();
///
/// // The met slot is two bytes; 7 encodes in one. The canonical
/// // job refuses the width instead of padding it.
/// let mut msg = [0x08, 0x96, 0x01];
/// let fault =
///     apply_standard(&mut msg, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
///         .unwrap_err();
/// assert_eq!(fault.at(), 0);
/// assert!(matches!(
///     fault.kind(),
///     FaultKind::ValueWidth { rule: 0, need: 1, have: 2 }
/// ));
/// assert_eq!(msg, [0x08, 0x96, 0x01]); // untouched on Err
///
/// // The tolerant instance pads the same value to the slot.
/// apply_standard(&mut msg, &set, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(msg, [0x08, 0x87, 0x00]);
/// ```
#[inline]
pub fn apply_standard(
    buf: &mut [u8],
    rules: &RuleSet<'_>,
    standard: Standard,
    limit: DepthLimit,
) -> Result<Stats, Fault> {
    match standard {
        Standard::Tolerant => run::<false>(buf, rules, limit),
        Standard::CanonicalMinimal => run::<true>(buf, rules, limit),
    }
}

#[cfg(test)]
mod tests;
