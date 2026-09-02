//! The groupless-output replay converter: a grouped supply walked,
//! every group re-framed as a LEN record.
//!
//! The walk is the grouped language's — groups arrive as in-band
//! open/end tags — and the re-framing is total: group punctuation
//! identifies every source group by syntax, so no policy exists to
//! declare. Each group becomes a LEN record of the same field:
//! minimal tag, minimal length prefix over the converted body, the
//! body's records in order (nested groups convert bottom-up — the
//! interior settles before the enclosing prefix is knowable).
//! Everything that is not group framing rides byte-verbatim:
//! scalar records, LEN records whole, and LEN payloads stay opaque
//! — pass one seeks past them through the supply's own skip, and
//! a group hidden inside one is the payload author's domain (this
//! machine never guesses messageness).
//!
//! Every face is two walks: pass one measures, judges, and
//! compiles the source-anchored script — every group's minted
//! prefix opened at its open tag and settled at its verified end
//! tag — and pass two folds the script against a fresh walk,
//! parsing nothing. The Vec faces reserve exactly once at the
//! script's compiled out-length before the fold. Pass two's whole
//! fault alphabet is the supply's refusals and the length-shaped
//! tear ([`JobFault::Torn`]); wire faults are unspellable there.
//!
//! Output closure: the output always re-ingests under the
//! groupless dialect's `Tolerant` standard, and it closes under
//! the groupless *language* exactly — no group code survives at
//! any depth the grouped walk reaches (group bodies are in-band;
//! LEN payloads are not walked and ride as the opaque declarations
//! they already were). It closes under `CanonicalMinimal` exactly
//! when every padded source word either was group framing or sat
//! inside some group's body: converted framing is authored
//! minimal, every other word rides verbatim — and a converted
//! group's body becomes a LEN payload, an opaque declaration the
//! canonical judge does not enter. Only a padded word outside
//! every group stays visible and breaks closure. A job run under
//! the `CanonicalMinimal` input standard admits no padded word
//! anywhere it walks, so its output closes canonically by
//! construction.
//!
//! The depth bound is spent as the walk's group-nesting bound:
//! conversion never commits a LEN descent, so group nesting is the
//! only recursion the input can spend.
//!
//! Coordinates: write · sequential-repeatable · static · grouped (input) · groupless (output) · Standard (value-level) · commit-only.
//!
//! # Publication custody
//!
//! - [`convert`]: a fresh buffer — absent on `Err`, so no partial
//!   product exists.
//! - [`convert_into`]: appends to the caller's buffer, truncated
//!   back to its entry mark on any refusal — the reuse face for
//!   batch loops.
//! - [`convert_sink`]: borrowed views handed forward as they emit;
//!   a refusal reports the exact handed prefix
//!   ([`Handed`]) — pass-one faults precede every handoff,
//!   pass-two faults need not, and the prefix carries no validity
//!   promise.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::replay_convert::groupless::convert;
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::{DepthLimit, Standard};
//!
//! // varint f1=150 · group f2 { varint f3=1 }
//! let msg = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
//! let mut source = SliceSource::new(&msg);
//! let (out, stats) =
//!     convert(&mut source, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
//! // varint f1=150 · LEN f2 [ varint f3=1 ]
//! assert_eq!(out, [0x08, 0x96, 0x01, 0x12, 0x02, 0x18, 0x01]);
//! assert_eq!(stats.converted(), 1);
//!
//! // Group-free input is the identity: conversion has nothing to
//! // re-frame, and everything else rides verbatim.
//! let flat = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut source = SliceSource::new(&flat);
//! let (out, stats) =
//!     convert(&mut source, Standard::Tolerant, DepthLimit::REFERENCE).unwrap();
//! assert_eq!(out, flat);
//! assert_eq!(stats.converted(), 0);
//! ```

use alloc::vec::Vec;

use crate::replay_pump::{Pump, StepRead};
use crate::replay_script::{FoldFault, Script, fold};
use crate::replay_source::{
    Handed, ReplayFault, ReplayPhase, ReplayWalk, StableReplaySource, SupplyFault,
};
use crate::wire::grouped::{RecordKind, TagClass, classify};
use crate::wire::groupless::{RecordKind as OutKind, head_word};
use crate::wire::{FieldNumber, Low3};
use crate::{DepthLimit, FaultClass, Standard};

/// The job receipt.
///
/// A zero count is the identity signal: nothing was re-framed, and
/// the output is byte-identical to the source's walk.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stats {
    converted: u32,
}

impl Stats {
    /// Groups re-framed as LEN records (nested groups count one
    /// each).
    #[inline]
    #[must_use]
    pub const fn converted(self) -> u32 {
        self.converted
    }
}

/// A document refusal: where, and which contract broke — the
/// measuring walk's judgment, in whole-source coordinates.
///
/// No promise chain exists to quote: this machine never commits a
/// LEN descent (payloads ride opaque), so every coordinate is the
/// document's own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u64,
    kind: FaultKind,
}

impl Fault {
    /// Whole-source byte coordinate.
    #[inline]
    #[must_use]
    pub const fn at(self) -> u64 {
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

/// The groupless-output replay converter's document refusal
/// classes.
///
/// The buffered converter's `Output` and `Oversize` classes are
/// unspellable here: replay coordinates are the stream's `u64`
/// space, so neither the source nor the root output has an
/// admission cap to outgrow.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// The walk hit unlawful wire — the grouped language's
    /// vocabulary, summarized (group pairing breaches included).
    Wire(WireBreach),
    /// A converted group body outgrew the LEN class: the source
    /// group carried no length prefix, and the one this conversion
    /// must author has no lawful spelling. `at` names the group's
    /// open tag.
    Growth {
        /// The body's settled length.
        len: u64,
    },
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Wire(breach) => write!(f, "{breach}"),
            Self::Growth { len } => {
                write!(f, "a converted group body of {len} bytes outgrew the LEN class")
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

/// The wire breach, summarized by who acts on it: a conversion
/// consumer rejects the document either way — byte-precise
/// diagnosis over the same bytes is the inspector's job
/// (`survey`, behind its feature).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireBreach {
    /// A varint (tag, length, or value) refused: too wide, out of
    /// class, or cut by the source's end.
    Varint,
    /// The tag word is unlawful (field zero or an unassigned
    /// code).
    Tag,
    /// A fixed-width or LEN extent exceeds the source's actual
    /// end, or a LEN declares past the coordinate space.
    Truncated,
    /// Group framing broke (orphaned, mismatched, or unclosed).
    Grouping,
    /// Group nesting past the declared [`DepthLimit`] budget.
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// declared [`Standard::CanonicalMinimal`]'s judgment (a
    /// tolerant job never judges widths).
    NonMinimal,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum ([`Depth`]
    /// is the [`DepthLimit`] budget; [`NonMinimal`] is the
    /// declared [`Standard`]); the grouped input language is the
    /// format's whole code alphabet, so no capability member
    /// exists.
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
            Self::Truncated => "an extent past the source end",
            Self::Grouping => "broken group framing",
            Self::Depth => "group nesting past the declared depth budget",
            Self::NonMinimal => "a varint word wider than its minimal encoding",
        })
    }
}

impl core::error::Error for WireBreach {}

// The 64-bit layout is pinned exactly; narrower pointer widths
// are bounded by the same ceiling.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<Fault>() == 24);
#[cfg(not(target_pointer_width = "64"))]
const _: () = assert!(core::mem::size_of::<Fault>() <= 24);

/// A job refusal: the document's own fault, the supply's refusal
/// with the operation it interrupted, or the two walk-integrity
/// marks no reader of a stable source would meet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

/// Fault disposition sink: the fault value takes shape here, off
/// the walks' hot dispatch. No promise chain exists to quote —
/// this direction never commits a LEN descent.
#[cold]
const fn refuse<E>(at: u64, kind: FaultKind) -> JobFault<E> {
    JobFault::Document(Fault { at, kind })
}

/// One open group on the walk stack: its minted prefix slot, the
/// pairing and coordinate facts, and the script mark its interior
/// settles from.
struct Frame {
    /// The group's minted prefix slot in the script.
    slot: u32,
    /// The group's field (the end-tag pairing judgment).
    field: FieldNumber,
    /// The group record's open-tag offset (the Growth fault
    /// coordinate).
    at: u64,
    /// The script's output length at the body's start (the
    /// settle's interior subtrahend).
    mark: u64,
}

/// The measuring machine: the pump and the script under
/// compilation. Groups declare no extent, so the pump's zone stays
/// the unbounded root for the whole walk and no committed-extent
/// arbitration exists — every document verdict stands as raised.
struct Machine<W: ReplayWalk> {
    pump: Pump<W>,
    script: Script<'static>,
    stack: Vec<Frame>,
    limit: DepthLimit,
    stats: Stats,
}

impl<W: ReplayWalk> Machine<W> {
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

    /// Advances `n` bytes through the supply's own seek; a short
    /// advance is the source ending inside a measured extent —
    /// truncation, terminal, anchored at the extent's start.
    fn skip_extent(&mut self, n: u64) -> Result<(), JobFault<W::Error>> {
        let anchor = self.pump.off;
        match self.pump.skip_bytes(n) {
            Ok(advanced) if advanced == n => Ok(()),
            Ok(_) => Err(refuse(anchor, FaultKind::Wire(WireBreach::Truncated))),
            Err(supply) => Err(self.supply_abort(supply)),
        }
    }

    /// One frame per open group: group nesting is the only
    /// recursion this direction can spend.
    fn at_depth_limit(&self) -> bool {
        self.stack.len() >= usize::from(self.limit.as_inner())
    }

    /// A group's end tag settled its pairing: the frame pops, the
    /// interior the script accumulated since the open settles the
    /// minted prefix, and the end tag's bytes are dropped.
    fn settle_group(&mut self, at: u64, end: u64) -> Result<(), JobFault<W::Error>> {
        // The caller verified the pairing against the innermost
        // frame before settling.
        let Some(frame) = self.stack.pop() else { unreachable!("the caller verified the pairing") };
        self.script.copy_to(at);
        let interior = self.script.out_len() - frame.mark;
        if let Err(len) = self.script.settle_minted_prefix(frame.slot, interior) {
            return Err(refuse(frame.at, FaultKind::Growth { len }));
        }
        self.script.skip_to(end);
        Ok(())
    }

    /// Runs the measuring walk to the source's end; the script,
    /// the measured total, and the receipt come back together.
    fn run<const MINIMAL: bool>(
        mut self,
    ) -> Result<(Script<'static>, u64, Stats), JobFault<W::Error>> {
        let total = self.walk::<MINIMAL>()?;
        Ok((self.script, total, self.stats))
    }

    /// The measuring loop, returning the source's total length at
    /// a clean end. Groups declare no extent, so no post-fault
    /// source probe exists: a document verdict stands as raised.
    fn walk<const MINIMAL: bool>(&mut self) -> Result<u64, JobFault<W::Error>> {
        let std = const { if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant } };
        loop {
            let at = self.pump.off;
            let word = match self.pump.step_tag(std) {
                StepRead::Done { value, .. } => value,
                StepRead::End => {
                    // Clean only at the root: an open group's end
                    // tag never arrived.
                    if self.stack.is_empty() {
                        return Ok(self.pump.off);
                    }
                    return Err(refuse(self.pump.off, FaultKind::Wire(WireBreach::Grouping)));
                }
                StepRead::SealCut
                | StepRead::SourceEnd
                | StepRead::TooWide
                | StepRead::OutOfClass => {
                    return Err(refuse(
                        self.pump.construct_start(),
                        FaultKind::Wire(WireBreach::Varint),
                    ));
                }
                StepRead::NonMinimal { width } => {
                    let start = self.pump.off - u64::from(width.w());
                    return Err(refuse(start, FaultKind::Wire(WireBreach::NonMinimal)));
                }
                StepRead::Exhausted => {
                    return Err(JobFault::OffsetExhausted { at: self.pump.off });
                }
                StepRead::Fault(supply) => return Err(self.supply_abort(supply)),
            };
            let low3 = Low3::from_word(word);
            let Some(field) = FieldNumber::from_word(word) else {
                return Err(refuse(at, FaultKind::Wire(WireBreach::Tag)));
            };
            match classify(low3) {
                TagClass::Record(RecordKind::Varint) => self.varint_record::<MINIMAL>()?,
                TagClass::Record(RecordKind::I64) => self.fixed_record(8)?,
                TagClass::Record(RecordKind::I32) => self.fixed_record(4)?,
                TagClass::Record(RecordKind::Len) => self.len_record::<MINIMAL>()?,
                TagClass::Record(RecordKind::Group) => self.group_open(at, field)?,
                TagClass::GroupEnd => {
                    match self.stack.last() {
                        Some(frame) if frame.field == field => {}
                        // Orphaned, or paired against the wrong
                        // open field.
                        _ => return Err(refuse(at, FaultKind::Wire(WireBreach::Grouping))),
                    }
                    self.settle_group(at, self.pump.off)?;
                }
                TagClass::Unassigned => {
                    return Err(refuse(at, FaultKind::Wire(WireBreach::Tag)));
                }
            }
        }
    }

    /// VARINT: the value steps (wire law needs its width), and the
    /// whole record extends the verbatim run.
    fn varint_record<const MINIMAL: bool>(&mut self) -> Result<(), JobFault<W::Error>> {
        let std = const { if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant } };
        let after_tag = self.pump.off;
        let width = match self.pump.step_value(std) {
            StepRead::Done { width, .. } => width,
            StepRead::SealCut | StepRead::SourceEnd | StepRead::TooWide | StepRead::OutOfClass => {
                return Err(refuse(after_tag, FaultKind::Wire(WireBreach::Varint)));
            }
            StepRead::NonMinimal { .. } => {
                return Err(refuse(after_tag, FaultKind::Wire(WireBreach::NonMinimal)));
            }
            StepRead::End => unreachable!("interior steps judge a walk end as SourceEnd"),
            StepRead::Exhausted => {
                return Err(JobFault::OffsetExhausted { at: self.pump.off });
            }
            StepRead::Fault(supply) => return Err(self.supply_abort(supply)),
        };
        self.script.copy_to(after_tag + u64::from(width.w()));
        Ok(())
    }

    /// I32/I64: the payload is never read — the walk seeks past
    /// it, and the record rides verbatim.
    fn fixed_record(&mut self, needed: u64) -> Result<(), JobFault<W::Error>> {
        self.skip_extent(needed)?;
        self.script.copy_to(self.pump.off);
        Ok(())
    }

    /// LEN: the prefix steps, the extent is admitted against the
    /// coordinate space, and the whole record rides verbatim —
    /// the payload is never read, and conversion never descends
    /// one.
    fn len_record<const MINIMAL: bool>(&mut self) -> Result<(), JobFault<W::Error>> {
        let std = const { if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant } };
        let after_tag = self.pump.off;
        let declared = match self.pump.step_len(std) {
            StepRead::Done { value, .. } => value,
            StepRead::SealCut | StepRead::SourceEnd | StepRead::TooWide | StepRead::OutOfClass => {
                return Err(refuse(after_tag, FaultKind::Wire(WireBreach::Varint)));
            }
            StepRead::NonMinimal { .. } => {
                return Err(refuse(after_tag, FaultKind::Wire(WireBreach::NonMinimal)));
            }
            StepRead::End => unreachable!("interior steps judge a walk end as SourceEnd"),
            StepRead::Exhausted => {
                return Err(JobFault::OffsetExhausted { at: self.pump.off });
            }
            StepRead::Fault(supply) => return Err(self.supply_abort(supply)),
        };
        let payload_start = self.pump.off;
        let declared64 = u64::from(declared.as_inner());
        // The extent judgment: no seal exists in this direction
        // (opaque payloads are never entered), so the coordinate
        // space itself is the ceiling.
        if declared64 > (u64::MAX - 1) - payload_start {
            return Err(refuse(after_tag, FaultKind::Wire(WireBreach::Truncated)));
        }
        self.skip_extent(declared64)?;
        self.script.copy_to(payload_start + declared64);
        Ok(())
    }

    /// A group's open tag: the source framing drops, the minimal
    /// LEN tag of the same field is authored, and the minted
    /// prefix opens — its width unknowable until the matching end
    /// tag settles the interior.
    fn group_open(&mut self, at: u64, field: FieldNumber) -> Result<(), JobFault<W::Error>> {
        if self.at_depth_limit() {
            return Err(refuse(at, FaultKind::Wire(WireBreach::Depth)));
        }
        self.stats.converted += 1;
        self.script.copy_to(at);
        self.script.skip_to(self.pump.off);
        self.script.stage_word(u64::from(head_word(field, OutKind::Len)));
        let slot = self.script.open_minted_prefix();
        self.stack.push(Frame { slot, field, at, mark: self.script.out_len() });
        Ok(())
    }
}

// ─── the job fronts ───

/// Runs pass one over a fresh walk.
fn measure<S: StableReplaySource>(
    source: &mut S,
    standard: Standard,
    limit: DepthLimit,
) -> Result<(Script<'static>, u64, Stats), JobFault<S::Error>> {
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

/// Converts the source into a fresh buffer, with the job receipt.
///
/// # Errors
///
/// [`JobFault`]; no buffer exists on `Err`.
pub fn convert<S: StableReplaySource>(
    source: &mut S,
    standard: Standard,
    limit: DepthLimit,
) -> Result<(Vec<u8>, Stats), JobFault<S::Error>> {
    let mut out = Vec::new();
    let stats = convert_into(source, standard, limit, &mut out)?;
    Ok((out, stats))
}

/// Converts the source, appending to the caller's buffer — the
/// reuse face for batch loops.
///
/// # Errors
///
/// [`JobFault`]; the buffer is truncated back to its entry mark,
/// so a faulted source skips without poisoning the loop.
pub fn convert_into<S: StableReplaySource>(
    source: &mut S,
    standard: Standard,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<Stats, JobFault<S::Error>> {
    let (script, total, stats) = measure(source, standard, limit)?;
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

/// Converts the source, handing output views to a caller sink as
/// they emit — no document buffer exists on either side.
///
/// Two walks: pass one measures and compiles, pass two folds the
/// script against a fresh walk and parses nothing. Pass-one faults
/// precede every handoff (`handed` is zero there); a pass-two
/// fault names the exact prefix the sink received. The prefix
/// carries no validity promise — atomic publication is the
/// caller's transactional destination.
///
/// # Errors
///
/// [`Handed`] around the [`JobFault`].
pub fn convert_sink<S: StableReplaySource>(
    source: &mut S,
    standard: Standard,
    limit: DepthLimit,
    mut sink: impl FnMut(&[u8]),
) -> Result<Stats, Handed<JobFault<S::Error>>> {
    let (script, total, stats) = match measure(source, standard, limit) {
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
