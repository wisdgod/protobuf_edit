//! The groupless replay rewriter: group codes are outside the
//! language.
//!
//! Pass one drives the supply walk once, in whole-source
//! coordinates: it judges wire law, folds the matcher's verdicts,
//! and compiles the edit script — kept extents as coalesced copy
//! spans, dropped ones as seeks, authored words into the staging
//! arena, and one prefix slot per committed container, settled at
//! its close from the interior lengths the walk accumulated (the
//! layer stack is the settle ledger). Unrouted LEN payloads are
//! never read: pass one seeks past them through the supply's own
//! skip, so an edit under a shallow rule set costs far less than
//! the source's length in read bytes.
//!
//! Pass two folds the script against a fresh walk and parses
//! nothing; its whole fault alphabet is the supply's refusals and
//! the length-shaped tear ([`JobFault::Torn`]). Wire faults are
//! unspellable there: every judgment already ran.
//!
//! Without groups the machine sheds the pairing and suppression
//! machinery, and group codes surface as this dialect's
//! capability refusal ([`WireBreach::GroupCode`]).
//!
//! Coordinates: write · sequential-repeatable · static · groupless · Standard (value-level) · commit-only.
//!
//! # Publication custody
//!
//! - [`rewrite`]: a fresh buffer — absent on `Err`, so no partial
//!   product exists.
//! - [`rewrite_into`]: appends to the caller's buffer, truncated
//!   back to its entry mark on any refusal — the reuse face for
//!   batch loops.
//! - [`rewrite_sink`]: borrowed views handed forward as they
//!   emit; a refusal reports the exact handed prefix
//!   ([`Handed`]) — a fallible source makes "every fault precedes
//!   the first handoff" impossible, so no zero-handoff promise
//!   exists (pass-one faults do precede every handoff; pass-two
//!   faults need not).
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::path::Segment;
//! use protobuf_edit::replay_rewrite::groupless::rewrite;
//! use protobuf_edit::replay_rewrite::{Action, Rule, RuleSet, Value};
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Replace field 1 at any depth along the field-3 route.
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
//! let mut source = SliceSource::new(&msg);
//! let (out, stats) = rewrite(&mut source, &set, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(out, [0x1A, 0x02, 0x08, 0x09, 0x08, 0x09]);
//! assert_eq!((stats.replaced(), stats.descended()), (2, 1));
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::replay_script::{FoldFault, Script, fold};
use super::{Action, RuleSet, Stats, Value};
use crate::path::{Hits, Matcher};
use crate::replay_pump::{Pump, StepRead};
use crate::replay_source::{
    Handed, ReplayFault, ReplayPhase, ReplayWalk, SourceCrossing, StableReplaySource, SupplyFault,
};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3};
use crate::{DepthLimit, FaultClass, Standard};

/// A document refusal: where, the promise chain crossed to reach
/// it, and which contract broke — the measuring walk's judgment,
/// in whole-source coordinates.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u64,
    trail: Box<[SourceCrossing]>,
    kind: FaultKind,
}

impl Fault {
    /// Whole-source byte coordinate.
    #[inline]
    #[must_use]
    pub const fn at(&self) -> u64 {
        self.at
    }

    /// Committed containers crossed to reach the fault (outermost
    /// first; empty at top level).
    #[inline]
    #[must_use]
    pub fn trail(&self) -> &[SourceCrossing] {
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

/// The groupless replay rewriter's document refusal classes.
///
/// The buffered rewriter's `Output` and `Oversize` classes are
/// unspellable here: replay coordinates are the stream's `u64`
/// space, so neither the source nor the root output has an
/// admission cap to outgrow.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// A committed extent (or the top level) hit unlawful wire —
    /// the groupless vocabulary, summarized (group codes arrive
    /// as its capability refusal).
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
        /// The interior's settled length.
        len: u64,
    },
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
        }
    }
}

impl core::error::Error for FaultKind {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(breach) => Some(breach),
            Self::Conflict { .. } | Self::KindMismatch { .. } | Self::Growth { .. } => None,
        }
    }
}

/// The wire breach, summarized by who acts on it: a rewrite
/// consumer rejects the document either way — byte-precise
/// diagnosis over the same bytes is the inspector's job
/// (`survey`, behind its feature).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireBreach {
    /// A varint (tag, length, or value) refused: too wide, out of
    /// class, or cut by an extent or the source's end.
    Varint,
    /// The tag word is unlawful (field zero or an unassigned
    /// code).
    Tag,
    /// A fixed-width or LEN extent exceeds its enclosing extent
    /// or the source's actual end.
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
            Self::Truncated => "an extent past its enclosing bound or the source end",
            Self::Depth => "nesting past the declared depth budget",
            Self::NonMinimal => "a varint word wider than its minimal encoding",
            Self::GroupCode => "a group code outside this dialect",
        })
    }
}

impl core::error::Error for WireBreach {}

// The 64-bit layout is pinned exactly; narrower pointer widths
// are bounded by the same ceiling.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Fault>() == 40);
#[cfg(not(target_pointer_width = "64"))]
const _: () = assert!(core::mem::size_of::<Fault>() <= 40);

/// A job refusal: the document's own fault, the supply's refusal
/// with the operation it interrupted, or the two walk-integrity
/// marks no reader of a stable source would meet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum JobFault<E> {
    /// The measuring walk judged the document itself unlawful —
    /// the same verdict every re-run over the same bytes reaches.
    Document(Fault),
    /// The supply refused (transport or a detected snapshot
    /// break), during either walk.
    Source(ReplayFault<E>),
    /// The emission walk's length shape contradicted the measured
    /// coordinates — the source grew or shrank between walks.
    Torn {
        /// The measured coordinate the walk could not honor.
        at: u64,
    },
    /// The accumulated offset would leave the addressable
    /// coordinate space (`u64::MAX − 1`).
    OffsetExhausted {
        /// The offset the refused advance started at.
        at: u64,
    },
}

impl<E: core::fmt::Display> core::fmt::Display for JobFault<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Document(fault) => write!(f, "{fault}"),
            Self::Source(fault) => write!(f, "{fault}"),
            Self::Torn { at } => {
                write!(f, "the source tore against measured coordinate {at}")
            }
            Self::OffsetExhausted { at } => {
                write!(f, "the source outgrew the coordinate space at offset {at}")
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for JobFault<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Document(fault) => Some(fault),
            Self::Source(fault) => Some(fault),
            Self::Torn { .. } | Self::OffsetExhausted { .. } => None,
        }
    }
}

// ─── pass one: the measuring walk (private) ───

/// One committed container on the walk stack: its prefix slot,
/// the settle inputs, and the restore state for the zone
/// register.
struct Frame {
    /// The container's prefix slot in the script.
    slot: u32,
    /// The container's field (the trail element).
    field: FieldNumber,
    /// The container record's head offset.
    at: u64,
    /// The interior's start — the coordinate an overrunning
    /// extent is refused at, mirroring the buffered twin.
    interior: u64,
    /// The declared interior length (the settle's verbatim test).
    declared: u64,
    /// The script's output length at open (the settle's interior
    /// subtrahend).
    mark: u64,
    /// The enclosing extent's end, restored on close.
    prev_zone: u64,
}

/// The measuring machine: the pump, the matcher, and the script
/// under compilation. Every refusal is terminal — the rule
/// language commits its paths, so no speculation machinery
/// exists.
struct Machine<'r, W: ReplayWalk> {
    pump: Pump<W>,
    matcher: Matcher<'r, RuleSet<'r>>,
    set: RuleSet<'r>,
    script: Script<'r>,
    stack: Vec<Frame>,
    limit: DepthLimit,
    stats: Stats,
}

impl<'r, W: ReplayWalk> Machine<'r, W> {
    /// The promise chain: one crossing per committed container.
    /// Allocates, but only on the fault path — every caller is a
    /// refusal.
    fn trail(&self) -> Box<[SourceCrossing]> {
        self.stack.iter().map(|f| SourceCrossing::new(f.field, f.at)).collect()
    }

    /// Fault disposition sink: the fault value takes shape here,
    /// off the walk's hot dispatch.
    #[cold]
    fn refuse(&self, at: u64, kind: FaultKind) -> JobFault<W::Error> {
        JobFault::Document(Fault { at, trail: self.trail(), kind })
    }

    /// Wraps a mid-walk supply refusal with the measure phase and
    /// the first unread offset.
    #[cold]
    const fn supply_abort(&self, supply: SupplyFault<W::Error>) -> JobFault<W::Error> {
        JobFault::Source(ReplayFault::Read {
            phase: ReplayPhase::Measure,
            at: self.pump.off,
            source: supply,
        })
    }

    /// A document verdict raised inside an open frame only stands
    /// when every open extent is honest: the buffered twin refuses
    /// an overrunning LEN at its open — before judging one
    /// interior byte — so the source is probed to the outermost
    /// committed extent's end, and a short source preempts the
    /// verdict with that record's own overrun (refused at its
    /// interior's start, at the top level).
    #[cold]
    fn arbitrate(&mut self, fault: JobFault<W::Error>) -> JobFault<W::Error> {
        if !matches!(fault, JobFault::Document(_)) {
            return fault;
        }
        let Some(frame) = self.stack.first() else {
            return fault;
        };
        // A refused construct may still sit in the carry; its
        // bytes are booked into the offset already.
        self.pump.clear_construct();
        let owed = (frame.interior + frame.declared) - self.pump.off;
        match self.pump.skip_bytes(owed) {
            Ok(advanced) if advanced == owed => fault,
            Ok(_) => JobFault::Document(Fault {
                at: frame.interior,
                trail: Box::default(),
                kind: FaultKind::Wire(WireBreach::Truncated),
            }),
            Err(supply) => self.supply_abort(supply),
        }
    }

    /// Advances `n` bytes through the supply's own seek; a short
    /// advance is the source ending inside a measured extent —
    /// truncation, terminal, anchored at the extent's start.
    fn skip_extent(&mut self, n: u64) -> Result<(), JobFault<W::Error>> {
        let anchor = self.pump.off;
        match self.pump.skip_bytes(n) {
            Ok(advanced) if advanced == n => Ok(()),
            Ok(_) => Err(self.refuse(anchor, FaultKind::Wire(WireBreach::Truncated))),
            Err(supply) => Err(self.supply_abort(supply)),
        }
    }

    /// Closes the frame the extent end popped: the settle writes
    /// the container's prefix slot from the interior the script
    /// accumulated since the open.
    fn close_frame(&mut self) -> Result<(), JobFault<W::Error>> {
        // The root zone is the coordinate space's sentinel, so a
        // met endpoint always has a frame to close.
        let Some(frame) = self.stack.pop() else {
            unreachable!("the root zone is the coordinate space's sentinel")
        };
        self.matcher.exit();
        let interior = self.script.out_len() - frame.mark;
        if let Err(len) = self.script.settle_prefix(frame.slot, interior, frame.declared) {
            return Err(self.refuse(frame.at, FaultKind::Growth { len }));
        }
        self.pump.zone = frame.prev_zone;
        Ok(())
    }

    /// Runs the measuring walk to the source's end; the script,
    /// the measured total, and the receipt come back together.
    fn run<const MINIMAL: bool>(mut self) -> Result<(Script<'r>, u64, Stats), JobFault<W::Error>> {
        match self.walk::<MINIMAL>() {
            Ok(total) => Ok((self.script, total, self.stats)),
            Err(fault) => Err(self.arbitrate(fault)),
        }
    }

    /// The measuring loop, returning the source's total length at
    /// a clean end; [`Machine::run`] arbitrates its refusals
    /// against the source's actual end.
    fn walk<const MINIMAL: bool>(&mut self) -> Result<u64, JobFault<W::Error>> {
        let std = const { if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant } };
        loop {
            debug_assert!(self.pump.off <= self.pump.zone);
            if self.pump.off == self.pump.zone {
                self.close_frame()?;
                continue;
            }
            let at = self.pump.off;
            let word = match self.pump.step_tag(std) {
                StepRead::Done { value, .. } => value,
                StepRead::End => {
                    // Clean only at the root: an open extent owes
                    // bytes the source no longer has.
                    if self.stack.is_empty() {
                        return Ok(self.pump.off);
                    }
                    return Err(self.refuse(self.pump.off, FaultKind::Wire(WireBreach::Truncated)));
                }
                StepRead::SealCut
                | StepRead::SourceEnd
                | StepRead::TooWide
                | StepRead::OutOfClass => {
                    return Err(self
                        .refuse(self.pump.construct_start(), FaultKind::Wire(WireBreach::Varint)));
                }
                StepRead::NonMinimal { width } => {
                    let start = self.pump.off - u64::from(width.w());
                    return Err(self.refuse(start, FaultKind::Wire(WireBreach::NonMinimal)));
                }
                StepRead::Exhausted => {
                    return Err(JobFault::OffsetExhausted { at: self.pump.off });
                }
                StepRead::Fault(supply) => return Err(self.supply_abort(supply)),
            };
            let low3 = Low3::from_word(word);
            let Some(field) = FieldNumber::from_word(word) else {
                return Err(self.refuse(at, FaultKind::Wire(WireBreach::Tag)));
            };
            match classify(low3) {
                TagClass::Record(RecordKind::Varint) => {
                    self.varint_record::<MINIMAL>(at, field)?;
                }
                TagClass::Record(kind @ (RecordKind::I64 | RecordKind::I32)) => {
                    self.fixed_record(at, field, kind)?;
                }
                TagClass::Record(RecordKind::Len) => self.len_record::<MINIMAL>(at, field)?,
                TagClass::GroupCode => {
                    return Err(self.refuse(at, FaultKind::Wire(WireBreach::GroupCode)));
                }
                TagClass::Unassigned => {
                    return Err(self.refuse(at, FaultKind::Wire(WireBreach::Tag)));
                }
            }
        }
    }

    /// VARINT: the value steps (wire law needs its width either
    /// way), then the write fold's verdict compiles the record.
    fn varint_record<const MINIMAL: bool>(
        &mut self,
        at: u64,
        field: FieldNumber,
    ) -> Result<(), JobFault<W::Error>> {
        let std = const { if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant } };
        let after_tag = self.pump.off;
        let (value, width) = match self.pump.step_value(std) {
            StepRead::Done { value, width } => (value, width),
            StepRead::SealCut | StepRead::SourceEnd | StepRead::TooWide | StepRead::OutOfClass => {
                return Err(self.refuse(after_tag, FaultKind::Wire(WireBreach::Varint)));
            }
            StepRead::NonMinimal { .. } => {
                return Err(self.refuse(after_tag, FaultKind::Wire(WireBreach::NonMinimal)));
            }
            StepRead::End => unreachable!("interior steps judge a walk end as SourceEnd"),
            StepRead::Exhausted => {
                return Err(JobFault::OffsetExhausted { at: self.pump.off });
            }
            StepRead::Fault(supply) => return Err(self.supply_abort(supply)),
        };
        let end = after_tag + u64::from(width.w());
        match self.matcher.probe_target(field) {
            Hits::Conflict(first, second) => Err(self.refuse(
                at,
                FaultKind::Conflict { first: u32::from(first), second: u32::from(second) },
            )),
            Hits::One(rule) => match self.set.action(rule) {
                Action::Delete => {
                    self.stats.deleted += 1;
                    self.script.skip_to(end);
                    Ok(())
                }
                Action::Replace(Value::Varint(word)) => {
                    self.stats.replaced += 1;
                    self.script.copy_to(after_tag);
                    self.script.skip_to(end);
                    self.script.stage_word(word);
                    Ok(())
                }
                Action::Replace(_) => {
                    Err(self.refuse(at, FaultKind::KindMismatch { rule: u32::from(rule) }))
                }
                Action::Normalize => {
                    self.stats.normalized += 1;
                    self.script.skip_to(end);
                    self.script.stage_word(u64::from(head_word(field, RecordKind::Varint)));
                    self.script.stage_word(value);
                    Ok(())
                }
            },
            Hits::None => {
                self.script.copy_to(end);
                Ok(())
            }
        }
    }

    /// I32/I64: the payload is never read — the walk seeks past
    /// it, and a kept or normalized payload rides verbatim in
    /// pass two.
    fn fixed_record(
        &mut self,
        at: u64,
        field: FieldNumber,
        kind: RecordKind,
    ) -> Result<(), JobFault<W::Error>> {
        let needed: u64 = if matches!(kind, RecordKind::I64) { 8 } else { 4 };
        let after_tag = self.pump.off;
        if self.pump.zone - self.pump.off < needed {
            return Err(self.refuse(after_tag, FaultKind::Wire(WireBreach::Truncated)));
        }
        self.skip_extent(needed)?;
        let end = self.pump.off;
        match self.matcher.probe_target(field) {
            Hits::Conflict(first, second) => Err(self.refuse(
                at,
                FaultKind::Conflict { first: u32::from(first), second: u32::from(second) },
            )),
            Hits::One(rule) => match self.set.action(rule) {
                Action::Delete => {
                    self.stats.deleted += 1;
                    self.script.skip_to(end);
                    Ok(())
                }
                Action::Replace(Value::I32(bits)) if matches!(kind, RecordKind::I32) => {
                    self.stats.replaced += 1;
                    self.script.copy_to(after_tag);
                    self.script.skip_to(end);
                    self.script.stage_bytes(&bits.to_le_bytes());
                    Ok(())
                }
                Action::Replace(Value::I64(bits)) if matches!(kind, RecordKind::I64) => {
                    self.stats.replaced += 1;
                    self.script.copy_to(after_tag);
                    self.script.skip_to(end);
                    self.script.stage_bytes(&bits.to_le_bytes());
                    Ok(())
                }
                Action::Replace(_) => {
                    Err(self.refuse(at, FaultKind::KindMismatch { rule: u32::from(rule) }))
                }
                Action::Normalize => {
                    self.stats.normalized += 1;
                    self.script.skip_to(after_tag);
                    self.script.stage_word(u64::from(head_word(field, kind)));
                    self.script.copy_to(end);
                    Ok(())
                }
            },
            Hits::None => {
                self.script.copy_to(end);
                Ok(())
            }
        }
    }

    /// LEN: the prefix steps and the extent is admitted against
    /// the enclosing bound; the write fold then either owns the
    /// record (action), commits the descent (a crossing path), or
    /// rides it verbatim — the payload read only when a rule
    /// walks it.
    fn len_record<const MINIMAL: bool>(
        &mut self,
        at: u64,
        field: FieldNumber,
    ) -> Result<(), JobFault<W::Error>> {
        let std = const { if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant } };
        let after_tag = self.pump.off;
        let declared = match self.pump.step_len(std) {
            StepRead::Done { value, .. } => value,
            StepRead::SealCut | StepRead::SourceEnd | StepRead::TooWide | StepRead::OutOfClass => {
                return Err(self.refuse(after_tag, FaultKind::Wire(WireBreach::Varint)));
            }
            StepRead::NonMinimal { .. } => {
                return Err(self.refuse(after_tag, FaultKind::Wire(WireBreach::NonMinimal)));
            }
            StepRead::End => unreachable!("interior steps judge a walk end as SourceEnd"),
            StepRead::Exhausted => {
                return Err(JobFault::OffsetExhausted { at: self.pump.off });
            }
            StepRead::Fault(supply) => return Err(self.supply_abort(supply)),
        };
        let payload_start = self.pump.off;
        let declared64 = u64::from(declared.as_inner());
        // The extent judgment: inside a seal the declared extent
        // must fit it; at the unbounded root the coordinate space
        // itself is the ceiling.
        if self.pump.zone == u64::MAX {
            if declared64 > (u64::MAX - 1) - payload_start {
                return Err(self.refuse(after_tag, FaultKind::Wire(WireBreach::Truncated)));
            }
        } else if declared64 > self.pump.zone - payload_start {
            return Err(self.refuse(after_tag, FaultKind::Wire(WireBreach::Truncated)));
        }
        let payload_end = payload_start + declared64;
        let (hits, routed) = self.matcher.probe(field);
        match hits {
            Hits::Conflict(first, second) => Err(self.refuse(
                at,
                FaultKind::Conflict { first: u32::from(first), second: u32::from(second) },
            )),
            Hits::One(rule) => match self.set.action(rule) {
                Action::Delete => {
                    self.stats.deleted += 1;
                    self.skip_extent(declared64)?;
                    self.script.skip_to(payload_end);
                    Ok(())
                }
                Action::Replace(Value::Len(bytes)) => {
                    self.stats.replaced += 1;
                    self.skip_extent(declared64)?;
                    self.script.copy_to(after_tag);
                    self.script.skip_to(payload_end);
                    #[allow(
                        clippy::as_conversions,
                        reason = "the payload was admitted to the LEN class at authoring, \
                                  which fits u64"
                    )]
                    self.script.stage_word(bytes.len() as u64);
                    self.script.borrow(bytes);
                    Ok(())
                }
                Action::Replace(_) => {
                    Err(self.refuse(at, FaultKind::KindMismatch { rule: u32::from(rule) }))
                }
                Action::Normalize => {
                    self.stats.normalized += 1;
                    self.skip_extent(declared64)?;
                    self.script.skip_to(payload_start);
                    self.script.stage_word(u64::from(head_word(field, RecordKind::Len)));
                    self.script.stage_word(declared64);
                    self.script.copy_to(payload_end);
                    Ok(())
                }
            },
            Hits::None if routed => {
                if self.stack.len() >= usize::from(self.limit.as_inner()) {
                    return Err(self.refuse(at, FaultKind::Wire(WireBreach::Depth)));
                }
                self.stats.descended += 1;
                self.script.copy_to(after_tag);
                let slot = self.script.open_prefix(after_tag, payload_start);
                self.matcher.commit_descent();
                self.stack.push(Frame {
                    slot,
                    field,
                    at,
                    interior: payload_start,
                    declared: declared64,
                    mark: self.script.out_len(),
                    prev_zone: self.pump.zone,
                });
                self.pump.zone = payload_end;
                Ok(())
            }
            Hits::None => {
                self.skip_extent(declared64)?;
                self.script.copy_to(payload_end);
                Ok(())
            }
        }
    }
}

/// Runs pass one over a fresh walk.
fn measure<'r, S: StableReplaySource>(
    source: &mut S,
    set: &RuleSet<'r>,
    limit: DepthLimit,
    standard: Standard,
) -> Result<(Script<'r>, u64, Stats), JobFault<S::Error>> {
    let walk = match source.begin() {
        Ok(walk) => walk,
        Err(fault) => {
            return Err(JobFault::Source(ReplayFault::Rewind {
                phase: ReplayPhase::Measure,
                source: fault,
            }));
        }
    };
    let machine = Machine {
        pump: Pump::new(walk),
        matcher: Matcher::new(*set),
        set: *set,
        script: Script::new(),
        stack: Vec::new(),
        limit,
        stats: Stats::default(),
    };
    match standard {
        Standard::Tolerant => machine.run::<false>(),
        Standard::CanonicalMinimal => machine.run::<true>(),
    }
}

/// Maps a splicing-pump refusal into the job vocabulary at the
/// emit phase.
#[cold]
fn emit_fault<E>(fold: FoldFault<E>) -> JobFault<E> {
    match fold {
        FoldFault::Rewind(source) => {
            JobFault::Source(ReplayFault::Rewind { phase: ReplayPhase::Emit, source })
        }
        FoldFault::Source { at, source } => {
            JobFault::Source(ReplayFault::Read { phase: ReplayPhase::Emit, at, source })
        }
        FoldFault::Torn { at } => JobFault::Torn { at },
    }
}

/// Rewrites the source into a fresh buffer — the tolerant
/// instance of [`rewrite_standard`].
///
/// # Errors
///
/// [`JobFault`]; no buffer exists on `Err`.
#[inline]
pub fn rewrite<S: StableReplaySource>(
    source: &mut S,
    set: &RuleSet<'_>,
    limit: DepthLimit,
) -> Result<(Vec<u8>, Stats), JobFault<S::Error>> {
    rewrite_standard(source, set, limit, Standard::Tolerant)
}

/// Rewrites the source into a fresh buffer under the declared
/// acceptance standard: two walks — one measuring, one splicing —
/// and the buffer reserved once at the measured total.
///
/// # Errors
///
/// [`JobFault`]; no buffer exists on `Err`.
pub fn rewrite_standard<S: StableReplaySource>(
    source: &mut S,
    set: &RuleSet<'_>,
    limit: DepthLimit,
    standard: Standard,
) -> Result<(Vec<u8>, Stats), JobFault<S::Error>> {
    let mut out = Vec::new();
    let stats = rewrite_into_standard(source, set, limit, standard, &mut out)?;
    Ok((out, stats))
}

/// Rewrites the source, appending to the caller's buffer — the
/// tolerant instance of [`rewrite_into_standard`].
///
/// # Errors
///
/// [`JobFault`]; the buffer is truncated back to its entry mark.
#[inline]
pub fn rewrite_into<S: StableReplaySource>(
    source: &mut S,
    set: &RuleSet<'_>,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<Stats, JobFault<S::Error>> {
    rewrite_into_standard(source, set, limit, Standard::Tolerant, out)
}

/// Rewrites the source under the declared acceptance standard,
/// appending to the caller's buffer (reserved once at the
/// measured total) — the reuse face for batch loops.
///
/// # Errors
///
/// [`JobFault`]; the buffer is truncated back to its entry mark,
/// so a faulted source skips without poisoning the loop.
pub fn rewrite_into_standard<S: StableReplaySource>(
    source: &mut S,
    set: &RuleSet<'_>,
    limit: DepthLimit,
    standard: Standard,
    out: &mut Vec<u8>,
) -> Result<Stats, JobFault<S::Error>> {
    let (script, total, stats) = measure(source, set, limit, standard)?;
    let mark = out.len();
    if let Ok(planned) = usize::try_from(script.out_len()) {
        out.reserve_exact(planned);
    }
    match fold(source, &script, total, &mut |view| out.extend_from_slice(view)) {
        Ok(()) => {
            debug_assert!(
                u64::try_from(out.len() - mark) == Ok(script.out_len()),
                "the fold emits exactly the compiled length"
            );
            Ok(stats)
        }
        Err(fault) => {
            out.truncate(mark);
            Err(emit_fault(fault))
        }
    }
}

/// Rewrites the source into a caller sink — the tolerant instance
/// of [`rewrite_sink_standard`].
///
/// # Errors
///
/// [`Handed`] around the [`JobFault`], naming the exact prefix
/// already handed over.
#[inline]
pub fn rewrite_sink<S: StableReplaySource>(
    source: &mut S,
    set: &RuleSet<'_>,
    limit: DepthLimit,
    sink: impl FnMut(&[u8]),
) -> Result<Stats, Handed<JobFault<S::Error>>> {
    rewrite_sink_standard(source, set, limit, Standard::Tolerant, sink)
}

/// Rewrites the source under the declared acceptance standard,
/// handing output views to a caller sink as they emit — no
/// document buffer exists on either side.
///
/// Pass-one faults precede every handoff (`handed` is zero
/// there); a pass-two fault names the exact prefix the sink
/// received. The prefix carries no validity promise — atomic
/// publication is the caller's transactional destination.
///
/// # Errors
///
/// [`Handed`] around the [`JobFault`].
pub fn rewrite_sink_standard<S: StableReplaySource>(
    source: &mut S,
    set: &RuleSet<'_>,
    limit: DepthLimit,
    standard: Standard,
    mut sink: impl FnMut(&[u8]),
) -> Result<Stats, Handed<JobFault<S::Error>>> {
    let (script, total, stats) = match measure(source, set, limit, standard) {
        Ok(parts) => parts,
        Err(fault) => return Err(Handed { handed: 0, fault }),
    };
    let mut handed = 0u64;
    match fold(source, &script, total, &mut |view| {
        #[allow(clippy::as_conversions, reason = "view lengths widen losslessly into u64")]
        {
            handed += view.len() as u64;
        }
        sink(view);
    }) {
        Ok(()) => Ok(stats),
        Err(fault) => Err(Handed { handed, fault: emit_fault(fault) }),
    }
}

#[cfg(test)]
mod tests;
