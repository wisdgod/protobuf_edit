//! The groupless replay splicer: group codes are outside the
//! language.
//!
//! Pass one drives the supply walk once, in whole-source
//! coordinates: it judges wire law, fires one ask per record, and
//! compiles the edit script — kept extents as coalesced copy
//! spans, dropped ones as seeks, answer copies into the staging
//! arena, and one prefix slot per committed container, settled at
//! its close from the interior lengths the walk accumulated (the
//! frame stack is the settle ledger). Opaque payloads are never
//! read: pass one seeks past them through the supply's own skip,
//! so a shallow edit costs far less than the source's length in
//! read bytes.
//!
//! Pass two folds the script against a fresh walk and parses
//! nothing; its whole fault alphabet is the supply's refusals and
//! the length-shaped tear ([`JobFault::Torn`]). Wire faults are
//! unspellable there, and the rule is absent from the emitter —
//! every judgment and every ask already ran.
//!
//! Without groups the machine sheds the pairing and suppression
//! machinery, and group codes surface as this dialect's
//! capability refusal ([`WireBreach::GroupCode`]).
//!
//! Coordinates: write · sequential-repeatable · online · groupless · Standard (value-level) · commit-only.
//!
//! # Publication custody
//!
//! - [`splice`]: a fresh buffer — absent on `Err`, so no partial
//!   product exists.
//! - [`splice_into`]: appends to the caller's buffer, truncated
//!   back to its entry mark on any refusal — the reuse face for
//!   batch loops.
//! - [`splice_sink`]: borrowed views handed forward as they emit;
//!   a refusal reports the exact handed prefix ([`Handed`]) — a
//!   fallible source makes "every fault precedes the first
//!   handoff" impossible, so no zero-handoff promise exists
//!   (pass-one faults do precede every handoff; pass-two faults
//!   need not).
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::replay_splice::Scalar;
//! use protobuf_edit::replay_splice::groupless::{Rule, splice};
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! // Rewrite every top-level field 1 varint to 9.
//! struct Nine;
//! impl Rule for Nine {
//!     fn on_varint(&mut self, _at: u64, field: FieldNumber, _value: u64) -> Scalar<'_, u64> {
//!         if field.as_inner() == 1 { Scalar::Rewrite(9) } else { Scalar::Keep }
//!     }
//! }
//!
//! // varint f1=42 · varint f2=5
//! let msg = [0x08, 0x2A, 0x10, 0x05];
//! let mut source = SliceSource::new(&msg);
//! let out = splice(&mut source, &mut Nine, Standard::Tolerant, DepthLimit::REFERENCE)
//!     .unwrap();
//! assert_eq!(out, [0x08, 0x09, 0x10, 0x05]);
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{Close, Head, Scalar};
use crate::replay_pump::{GrabRead, Pump, StepRead};
use crate::replay_script::{FoldFault, Script, fold};
use crate::replay_source::{
    Handed, ReplayFault, ReplayPhase, ReplayWalk, SourceCrossing, StableReplaySource, SupplyFault,
};
use crate::wire::groupless::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, FaultClass, Standard};

/// The consumer's per-record asks, one method per wire kind — an
/// ill-typed verdict is unspellable, so no mismatch fault class
/// exists.
///
/// Every method defaults to the identity: opaque heads, `Pass`
/// closes, `Keep` scalars — a rule implements only the kinds it
/// edits. `at` is the record head's whole-source byte offset (the
/// close ask repeats its head's). Answer slices are borrowed only
/// for the ask: the machine stages them by copy before returning.
pub trait Rule {
    /// A varint record completed, value in hand.
    fn on_varint(&mut self, at: u64, field: FieldNumber, value: u64) -> Scalar<'_, u64> {
        let _ = (at, field, value);
        Scalar::Keep
    }

    /// An I32 record completed (little-endian bits).
    fn on_i32(&mut self, at: u64, field: FieldNumber, bits: u32) -> Scalar<'_, u32> {
        let _ = (at, field, bits);
        Scalar::Keep
    }

    /// An I64 record completed (little-endian bits).
    fn on_i64(&mut self, at: u64, field: FieldNumber, bits: u64) -> Scalar<'_, u64> {
        let _ = (at, field, bits);
        Scalar::Keep
    }

    /// A LEN record's head — phase one, the irrevocable
    /// interpretation declaration. No payload rides the ask; an
    /// undescended record's output verdict comes at
    /// [`Rule::on_close`].
    fn on_len(&mut self, at: u64, field: FieldNumber, len: PayloadLen) -> Head<'_> {
        let _ = (at, field, len);
        Head::Opaque
    }

    /// One payload view of a [`Head::Observe`] record, in source
    /// order; `at` is the view's first byte. Notification only —
    /// no verdict rides back.
    fn on_fragment(&mut self, at: u64, view: &[u8]) {
        let _ = (at, view);
    }

    /// An undescended LEN record's close — phase two, the one
    /// output-settling verdict for a [`Head::Opaque`] or
    /// [`Head::Observe`] declaration. Committed records never
    /// reach it: their prefixes settle mechanically.
    fn on_close(&mut self, at: u64, field: FieldNumber) -> Close<'_> {
        let _ = (at, field);
        Close::Pass
    }
}

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

/// The groupless replay splicer's document refusal classes.
///
/// The buffered splicer's `Output` and `Oversize` classes are
/// unspellable here: replay coordinates are the stream's `u64`
/// space, so neither the source nor the root output has an
/// admission cap to outgrow. An ill-typed verdict is unspellable
/// too — each ask method's verdict vocabulary is its own — so no
/// mismatch class exists.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// A committed extent (or the top level) hit unlawful wire —
    /// the groupless vocabulary, summarized (group codes arrive
    /// as its capability refusal).
    Wire(WireBreach),
    /// A [`Close::Replace`] answer or a committed container's
    /// settled interior outgrew the LEN class its prefix must
    /// encode. Insert and tail bytes carry no prefix and land in
    /// the root's unbounded space, so only their enclosing
    /// containers judge them (through the settled interior).
    Growth {
        /// The refused length.
        len: u64,
    },
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Wire(breach) => write!(f, "{breach}"),
            Self::Growth { len } => {
                write!(f, "an interior of {len} bytes outgrew the LEN class")
            }
        }
    }
}

impl core::error::Error for FaultKind {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(breach) => Some(breach),
            Self::Growth { .. } => None,
        }
    }
}

/// The wire breach, summarized by who acts on it: a splice
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
    /// A [`Head::Commit`] declaration past the caller's declared
    /// [`DepthLimit`] budget — only entering costs; any other
    /// declaration or verdict at the wall is lawful.
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// declared [`Standard::CanonicalMinimal`]'s judgment (a
    /// tolerant job never judges widths).
    NonMinimal,
    /// A group code appeared — outside this dialect's language
    /// (the grouped dialect handles such documents).
    GroupCode,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget; [`NonMinimal`] is the
    /// declared [`Standard`]).
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
            Self::Depth => "a commit past the declared depth budget",
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
/// the settle inputs, the stashed tail, and the restore state for
/// the zone register.
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
    /// The commit's tail, stashed by copy at the ask; it lands
    /// after the last interior record.
    tail: Option<(usize, usize)>,
}

/// The measuring machine: the pump, the consumer's rule, and the
/// script under compilation. Every refusal is terminal — asks are
/// output-settling by type, so no speculation machinery exists.
struct Machine<'j, R, W: ReplayWalk> {
    pump: Pump<W>,
    rule: &'j mut R,
    script: Script<'static>,
    stack: Vec<Frame>,
    limit: DepthLimit,
}

impl<R: Rule, W: ReplayWalk> Machine<'_, R, W> {
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

    /// Walks `n` bytes forward, handing each supply view to the
    /// rule's fragment hook with its absolute offset; a short walk
    /// is truncation, anchored at the extent's start.
    fn observe_extent(&mut self, n: u64) -> Result<(), JobFault<W::Error>> {
        let anchor = self.pump.off;
        let mut cursor = anchor;
        let rule = &mut *self.rule;
        match self.pump.copy_bytes(n, |view| {
            rule.on_fragment(cursor, view);
            #[allow(clippy::as_conversions, reason = "view lengths widen losslessly into u64")]
            {
                cursor += view.len() as u64;
            }
        }) {
            Ok(advanced) if advanced == n => Ok(()),
            Ok(_) => Err(self.refuse(anchor, FaultKind::Wire(WireBreach::Truncated))),
            Err(supply) => Err(self.supply_abort(supply)),
        }
    }

    /// Closes the frame the extent end popped: the stashed tail
    /// lands, then the settle writes the container's prefix slot
    /// from the interior the script accumulated since the open.
    fn close_frame(&mut self) -> Result<(), JobFault<W::Error>> {
        // The root zone is the coordinate space's sentinel, so a
        // met endpoint always has a frame to close.
        let Some(frame) = self.stack.pop() else {
            unreachable!("the root zone is the coordinate space's sentinel")
        };
        if let Some((start, end)) = frame.tail {
            self.script.emit_stashed(start, end);
        }
        let interior = self.script.out_len() - frame.mark;
        if let Err(len) = self.script.settle_prefix(frame.slot, interior, frame.declared) {
            return Err(self.refuse(frame.at, FaultKind::Growth { len }));
        }
        self.pump.zone = frame.prev_zone;
        Ok(())
    }

    /// Runs the measuring walk to the source's end; the script
    /// and the measured total come back together.
    fn run<const MINIMAL: bool>(mut self) -> Result<(Script<'static>, u64), JobFault<W::Error>> {
        match self.walk::<MINIMAL>() {
            Ok(total) => Ok((self.script, total)),
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

    /// VARINT: the value steps (the ask hands it), then the
    /// verdict compiles the record.
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
        match self.rule.on_varint(at, field, value) {
            Scalar::Keep => self.script.copy_to(end),
            Scalar::Rewrite(word) => {
                self.script.copy_to(after_tag);
                self.script.skip_to(end);
                self.script.stage_word(word);
            }
            Scalar::Drop => self.script.skip_to(end),
            Scalar::Insert(bytes) => {
                self.script.copy_to(at);
                self.script.stage_bytes(bytes);
                self.script.copy_to(end);
            }
        }
        Ok(())
    }

    /// I32/I64: the payload's bits collect for the ask, then the
    /// verdict compiles the record — a kept payload still rides
    /// verbatim in pass two (the collection is transient).
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
        let end = after_tag + needed;
        if matches!(kind, RecordKind::I64) {
            let bytes = self.grab::<8>(after_tag)?;
            let verdict = self.rule.on_i64(at, field, u64::from_le_bytes(bytes));
            Self::fixed_verdict(
                &mut self.script,
                at,
                after_tag,
                end,
                verdict.map(u64::to_le_bytes),
            );
        } else {
            let bytes = self.grab::<4>(after_tag)?;
            let verdict = self.rule.on_i32(at, field, u32::from_le_bytes(bytes));
            Self::fixed_verdict(
                &mut self.script,
                at,
                after_tag,
                end,
                verdict.map(u32::to_le_bytes),
            );
        }
        Ok(())
    }

    /// Collects one fixed payload; the drivers admitted the width
    /// against the zone, so a cut is the source's own end.
    fn grab<const NEED: usize>(&mut self, anchor: u64) -> Result<[u8; NEED], JobFault<W::Error>> {
        match self.pump.grab_fixed::<NEED>() {
            GrabRead::Done(value) => Ok(value),
            GrabRead::SourceEnd => Err(self.refuse(anchor, FaultKind::Wire(WireBreach::Truncated))),
            GrabRead::Exhausted => Err(JobFault::OffsetExhausted { at: self.pump.off }),
            GrabRead::Fault(supply) => Err(self.supply_abort(supply)),
        }
    }

    /// Folds a fixed record's verdict, its rewrite already in
    /// little-endian bytes. Associated, not a method: the verdict
    /// borrows the machine's rule, so the script comes in alone.
    fn fixed_verdict<const NEED: usize>(
        script: &mut Script<'static>,
        at: u64,
        after_tag: u64,
        end: u64,
        verdict: Scalar<'_, [u8; NEED]>,
    ) {
        match verdict {
            Scalar::Keep => script.copy_to(end),
            Scalar::Rewrite(bytes) => {
                script.copy_to(after_tag);
                script.skip_to(end);
                script.stage_bytes(&bytes);
            }
            Scalar::Drop => script.skip_to(end),
            Scalar::Insert(bytes) => {
                script.copy_to(at);
                script.stage_bytes(bytes);
                script.copy_to(end);
            }
        }
    }

    /// LEN: the prefix steps and the extent is admitted against
    /// the enclosing bound; the head declaration then either
    /// commits the descent, observes the payload view by view, or
    /// seeks past it opaque — the two undescended forms take
    /// their close verdict once the extent is walked.
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
        match self.rule.on_len(at, field, declared) {
            Head::Commit { tail } => {
                // The ask fired; only the entering declaration
                // spends the budget.
                if self.stack.len() >= usize::from(self.limit.as_inner()) {
                    return Err(self.refuse(at, FaultKind::Wire(WireBreach::Depth)));
                }
                let tail = tail.map(|bytes| self.script.stash(bytes));
                self.script.copy_to(after_tag);
                let slot = self.script.open_prefix(after_tag, payload_start);
                self.stack.push(Frame {
                    slot,
                    field,
                    at,
                    interior: payload_start,
                    declared: declared64,
                    mark: self.script.out_len(),
                    prev_zone: self.pump.zone,
                    tail,
                });
                self.pump.zone = payload_end;
                Ok(())
            }
            Head::Opaque => {
                self.skip_extent(declared64)?;
                self.close_record(at, after_tag, payload_end, field)
            }
            Head::Observe => {
                self.observe_extent(declared64)?;
                self.close_record(at, after_tag, payload_end, field)
            }
        }
    }

    /// An undescended record's close verdict — the extent is
    /// walked, the script cursor still stands before the record,
    /// so every answer stays spellable.
    fn close_record(
        &mut self,
        at: u64,
        after_tag: u64,
        payload_end: u64,
        field: FieldNumber,
    ) -> Result<(), JobFault<W::Error>> {
        match self.rule.on_close(at, field) {
            Close::Pass => self.script.copy_to(payload_end),
            Close::Replace(bytes) => {
                #[allow(clippy::as_conversions, reason = "usize widens losslessly into u64")]
                let len = bytes.len() as u64;
                if len > u64::from(PayloadLen::MAX.as_inner()) {
                    return Err(self.refuse(at, FaultKind::Growth { len }));
                }
                self.script.copy_to(after_tag);
                self.script.skip_to(payload_end);
                self.script.stage_word(len);
                self.script.stage_bytes(bytes);
            }
            Close::Drop => self.script.skip_to(payload_end),
            Close::Insert(bytes) => {
                self.script.copy_to(at);
                self.script.stage_bytes(bytes);
                self.script.copy_to(payload_end);
            }
        }
        Ok(())
    }
}

/// Runs pass one over a fresh walk.
fn measure<S: StableReplaySource, R: Rule>(
    source: &mut S,
    rule: &mut R,
    limit: DepthLimit,
    standard: Standard,
) -> Result<(Script<'static>, u64), JobFault<S::Error>> {
    let walk = match source.begin() {
        Ok(walk) => walk,
        Err(fault) => {
            return Err(JobFault::Source(ReplayFault::Rewind {
                phase: ReplayPhase::Measure,
                source: fault,
            }));
        }
    };
    let machine =
        Machine { pump: Pump::new(walk), rule, script: Script::new(), stack: Vec::new(), limit };
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

/// Splices the source under the rule into a fresh buffer.
///
/// Two walks — one asking, one splicing — and the buffer reserved
/// once at the measured total. The rule's state is spent for the
/// asks already fired whichever way the job ends.
///
/// # Errors
///
/// [`JobFault`]; no buffer exists on `Err`.
pub fn splice<S: StableReplaySource, R: Rule>(
    source: &mut S,
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
) -> Result<Vec<u8>, JobFault<S::Error>> {
    let mut out = Vec::new();
    splice_into(source, rule, standard, limit, &mut out)?;
    Ok(out)
}

/// Splices the source under the rule, appending to the caller's
/// buffer (reserved once at the measured total) — the reuse face
/// for batch loops.
///
/// # Errors
///
/// [`JobFault`]; the buffer is truncated back to its entry mark,
/// so a faulted source skips without poisoning the loop.
pub fn splice_into<S: StableReplaySource, R: Rule>(
    source: &mut S,
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<(), JobFault<S::Error>> {
    let (script, total) = measure(source, rule, limit, standard)?;
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
            Ok(())
        }
        Err(fault) => {
            out.truncate(mark);
            Err(emit_fault(fault))
        }
    }
}

/// Splices the source under the rule, handing output views to a
/// caller sink as they emit — no document buffer exists on either
/// side.
///
/// Pass-one faults precede every handoff (`handed` is zero
/// there); a pass-two fault names the exact prefix the sink
/// received. The prefix carries no validity promise — atomic
/// publication is the caller's transactional destination.
///
/// # Errors
///
/// [`Handed`] around the [`JobFault`].
pub fn splice_sink<S: StableReplaySource, R: Rule>(
    source: &mut S,
    rule: &mut R,
    standard: Standard,
    limit: DepthLimit,
    mut sink: impl FnMut(&[u8]),
) -> Result<(), Handed<JobFault<S::Error>>> {
    let (script, total) = match measure(source, rule, limit, standard) {
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
        Ok(()) => Ok(()),
        Err(fault) => Err(Handed { handed, fault: emit_fault(fault) }),
    }
}

#[cfg(test)]
mod tests;
