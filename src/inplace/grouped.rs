//! The grouped in-place editor: all six codes, group tags paired
//! in the walk.
//!
//! Groups carry no length prefix, so a group's extent — start tag
//! through its verified end tag — is a walked fact, not a read
//! one. The judge walk verifies every pairing as it goes
//! (mismatched, orphaned, and unclosed ends are wire faults), and
//! the group-specific action semantics fall out of the extent law:
//!
//! - [`Action::Renumber`] on a group rewrites the start and end
//!   tags as one atomic pair. Each tag's met width is an
//!   independent fact — tolerant input may pad one and not the
//!   other — so both judgments settle before either write is
//!   listed: the start is judged at the enter, the end at its
//!   verified exit, and the pair's two entries land together. The
//!   interior stays live under the walk.
//! - [`Action::Tombstone`] and [`Action::ReplaceRecord`] own the
//!   whole group extent, judged at the verified exit where the
//!   extent is known. Rules inside fire nowhere, silently (the
//!   ownership law), but the interior is not exempt from wire law:
//!   its pairing is verified and its group enters spend the one
//!   depth account below — and the extent refills as one write.
//! - [`Action::SetPayload`] on a group is a kind mismatch: groups
//!   have no single opaque payload extent (the LEN-only law).
//!   Scalar and LEN records judge inside groups exactly as at top
//!   level — geometry is per-record.
//!
//! Groups and committed LEN crossings spend one depth account: a
//! group enter or LEN descent past the caller's [`DepthLimit`]
//! refuses as [`WireBreach::Depth`]. A whole-record replacement
//! candidate re-parses under the target's remaining budget, so a
//! substituted group cannot smuggle nesting past the declared
//! bound.
//!
//! The machine shape is the shared layer's ([`crate::inplace`]):
//! every fault precedes the first write, and the write loop past
//! the barrier is infallible, allocation-free, and panic-free.
//!
//! Coordinates: write · buffered · static · grouped · Standard (value-level) · in-place · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::inplace::grouped::apply;
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
//! let stats = apply(&mut msg, &set, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(msg, [0x13, 0x10, 0x96, 0x01, 0x14, 0x18, 0x07]);
//! assert_eq!(stats.renumbered(), 1);
//! ```

use alloc::vec::Vec;

use super::{Action, RuleSet, Stats, Write, action, filler_need, width_fits};
use crate::path::{Hits, Matcher};
use crate::cursor::GroupDepth;
use crate::cursor::grouped::{Cursor, EntryKind};
use crate::varint::{ValueWidth, WordWidth, encoded_len32, encoded_len64};
use crate::wire::FieldNumber;
use crate::wire::grouped::{RecordKind, group_end_word, head_word};
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
    /// names. For the width refusals: the record head — except
    /// [`FaultKind::TagWidth`] on a group's end tag, which names
    /// that tag's own site (the pair's two judgments carry their
    /// own coordinates).
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

/// The grouped in-place editor's refusal classes.
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
    /// Depth budget left inside this layer (containers: groups
    /// and committed LEN crossings spend one account).
    remaining: u16,
    /// Open groups inside this layer.
    group_depth: u16,
}

const _: () = {
    assert!(if cfg!(target_pointer_width = "64") {
        core::mem::size_of::<Layer<'_>>() == 64
    } else {
        // Narrower pointers are bounded by the same ceiling.
        core::mem::size_of::<Layer<'_>>() <= 64
    });
};

/// A group renumber staged at its enter: both tags are judged
/// before either write is listed. The start judgment settles at
/// the enter and its write is held here; the end judgment settles
/// at the verified exit, and only then do the pair's two entries
/// land — the pair is atomic at the record.
struct PendingPair {
    /// The keyed position: walk-layer count and in-layer depth
    /// (groups nest properly, so the pending stack's tail is
    /// always the innermost open renumber).
    layer: usize,
    depth: u16,
    rule: u16,
    /// The judged start write, held back until the end passes.
    start_at: u32,
    /// The start tag's met width (the cursor's tag window).
    start_width: WordWidth,
    start_word: u32,
    /// The renumber's target field (the end word derives from it
    /// at the exit).
    field: FieldNumber,
}

/// A group wholly owned by its rule (`Tombstone`,
/// `ReplaceRecord`): interior events are skipped while the cursor
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

/// The whole-record replacement judgment: exact extent, then a
/// re-parse as exactly one complete record — a balanced group
/// included — under the job's standard and the target's remaining
/// depth budget. LEN payloads inside the candidate stay opaque
/// exactly as in source parsing; in-band group nesting charges
/// `budget`, so a substituted record cannot smuggle nesting past
/// the declared bound.
fn judge_replacement<const MINIMAL: bool>(
    rule: u16,
    bytes: &[u8],
    head: u32,
    have: u32,
    budget: u16,
    limit: GroupDepth,
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
    // the cursor, so `within`'s contract holds. The cursor's own
    // bound is the job's limit; the walk-position budget below is
    // the tighter judgment.
    let mut probe = Cursor::within(bytes, limit);
    let mut depth: u16 = 0;
    loop {
        let at = probe.pos();
        match probe.step::<MINIMAL>() {
            Some(Ok(entry)) => {
                match entry.kind() {
                    EntryKind::GroupEnter => {
                        if depth == budget {
                            return Err(Fault {
                                at: head,
                                kind: FaultKind::ReplacementWire {
                                    rule,
                                    at,
                                    breach: WireBreach::Depth,
                                },
                            });
                        }
                        depth += 1;
                    }
                    EntryKind::GroupExit => depth -= 1,
                    EntryKind::Varint(_)
                    | EntryKind::I64(_)
                    | EntryKind::Len(_)
                    | EntryKind::I32(_) => {}
                }
                if depth == 0 {
                    return if probe.pos() == have {
                        Ok(())
                    } else {
                        Err(Fault { at: head, kind: FaultKind::ReplacementShape { rule } })
                    };
                }
            }
            Some(Err(fault)) => {
                return Err(Fault {
                    at: head,
                    kind: FaultKind::ReplacementWire {
                        rule,
                        at: fault.at(),
                        breach: breach(fault.kind()),
                    },
                });
            }
            // The extent equality held, so the candidate is
            // nonempty, and the cursor faults an unclosed group at
            // the window end itself: every path delivers or
            // refuses before exhaustion.
            None => unreachable!("a nonempty window steps or faults"),
        }
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
    let Ok(root) = Cursor::over(input, GroupDepth::from(limit)) else {
        return Err(Fault { at: 0, kind: FaultKind::Oversize });
    };
    let mut layers: Vec<Layer<'_>> = Vec::new();
    layers.push(Layer { cursor: root, base: 0, remaining: limit.as_inner(), group_depth: 0 });
    // Depth inside the group currently being wholly overwritten
    // (0 = none). While suppressing, interior events are skipped
    // for matching only: the extent refills as one write, so no
    // rule fires inside — but every group enter still spends the
    // one depth account (admission never depends on which rules
    // the job carries), and the cursor verifies every pairing.
    let mut suppress: u32 = 0;
    let mut owned: Option<Owned<'r>> = None;
    // Group renumbers staged at their enters, completed at the
    // matching exits.
    let mut pending: Vec<PendingPair> = Vec::new();

    loop {
        let layer_count = layers.len();
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

        if suppress > 0 {
            match entry.kind() {
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
                                writes.push(Write::Filler { at: head, width: have, field });
                                stats.tombstoned += 1;
                            }
                            Some(Owned::Replace { rule, head, bytes, budget }) => {
                                judge_replacement::<MINIMAL>(
                                    rule,
                                    bytes,
                                    head,
                                    end - head,
                                    budget,
                                    GroupDepth::from(limit),
                                )?;
                                writes.push(Write::Payload { at: head, bytes });
                                stats.substituted += 1;
                            }
                            // Suppression starts only where an
                            // owner is staged.
                            None => unreachable!("suppression carries its owner"),
                        }
                    }
                }
                EntryKind::Varint(_)
                | EntryKind::I64(_)
                | EntryKind::Len(_)
                | EntryKind::I32(_) => {}
            }
            continue;
        }

        let field = entry.field();
        match entry.kind() {
            EntryKind::GroupExit => {
                // An end tag is punctuation, not a record: no rule
                // judgment of its own — but a pending renumber
                // keyed at this group completes here, where the
                // end tag's met width (an independent fact) is
                // first known.
                matcher.exit();
                if pending.last().map(|pair| (pair.layer, pair.depth))
                    == Some((layer_count, layer.group_depth))
                {
                    // SAFETY: the peek above is `Some`.
                    let pair = unsafe { pending.pop().unwrap_unchecked() };
                    let have = u32::from(layer.cursor.tag_width());
                    let word = group_end_word(pair.field);
                    let need = encoded_len32(word);
                    if !width_fits::<MINIMAL>(need, have) {
                        return Err(Fault {
                            at: head,
                            kind: FaultKind::TagWidth { rule: u32::from(pair.rule), need, have },
                        });
                    }
                    writes.push(Write::Tag {
                        at: pair.start_at,
                        width: pair.start_width,
                        word: pair.start_word,
                    });
                    writes.push(Write::Tag {
                        at: head,
                        // SAFETY: the slot width is the walk's
                        // framing window — the cursor's met end-tag
                        // read, 1..=5.
                        width: unsafe { WordWidth::met_unchecked(layer.cursor.tag_width()) },
                        word,
                    });
                    stats.renumbered += 1;
                }
                layer.group_depth -= 1;
            }
            EntryKind::GroupEnter => {
                let (hits, _routed) = matcher.probe(field);
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
                            pending.push(PendingPair {
                                layer: layer_count,
                                depth: layer.group_depth,
                                rule,
                                start_at: head,
                                // SAFETY: the slot width is the
                                // walk's framing window — the
                                // cursor's met tag read, 1..=5.
                                start_width: unsafe {
                                    WordWidth::met_unchecked(layer.cursor.tag_width())
                                },
                                start_word: word,
                                field: new_field,
                            });
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
                        // refusal — the walker's or the cursor's
                        // own — spells the one public verdict.
                        if layer.group_depth == layer.remaining {
                            return Err(Fault {
                                at: head,
                                kind: FaultKind::Wire(WireBreach::Depth),
                            });
                        }
                        matcher.commit_descent();
                        layer.group_depth += 1;
                    }
                }
            }
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
                        judge_replacement::<MINIMAL>(
                            rule,
                            bytes,
                            head,
                            end - head,
                            layer.remaining - layer.group_depth,
                            GroupDepth::from(limit),
                        )?;
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
                                GroupDepth::from(limit),
                            )?;
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
                    let (group_depth, remaining) = (layer.group_depth, layer.remaining);
                    if group_depth == remaining {
                        return Err(Fault { at: head, kind: FaultKind::Wire(WireBreach::Depth) });
                    }
                    matcher.commit_descent();
                    layers.push(Layer {
                        cursor: Cursor::within(payload, GroupDepth::from(limit)),
                        base: payload_start,
                        remaining: remaining - group_depth - 1,
                        group_depth: 0,
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
/// [`Fault`] when the input refuses admission, the walk (or a
/// committed descent) hits unlawful wire — broken group framing
/// included — two rules target one record, an action does not fit
/// its record's kind, width, or extent, a replacement candidate
/// refuses, or the depth budget runs out. `buf` is untouched on
/// `Err`.
///
/// # Examples
///
/// ```
/// use protobuf_edit::inplace::grouped::apply;
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
/// let stats = apply(&mut msg, &set, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(msg, [0x48, 0x80, 0x80, 0x80, 0x00, 0x18, 0x07]);
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
/// use protobuf_edit::inplace::grouped::{FaultKind, apply_standard};
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
///
/// let mut padded = [0x8B, 0x00, 0x0C];
/// let fault =
///     apply_standard(&mut padded, &set, Standard::CanonicalMinimal, DepthLimit::REFERENCE)
///         .unwrap_err();
/// assert_eq!(fault.at(), 0);
/// assert_eq!(padded, [0x8B, 0x00, 0x0C]); // untouched on Err
///
/// // The tolerant instance renumbers the pair at its met widths:
/// // the padded start stays two bytes wide, the end stays one.
/// apply_standard(&mut padded, &set, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
/// assert_eq!(padded, [0x93, 0x00, 0x14]);
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
