//! The grouped-output replay converter: a groupless supply
//! walked, designated LEN records re-framed as groups.
//!
//! Designation is a compiled [`Program`]: re-framing a LEN as a
//! group commits its payload to be a message — the group framing
//! exposes the interior to every grouped consumer — and this
//! library never guesses messageness, so the caller must say
//! which fields carry messages. The law is three-way. A
//! **designated** occurrence converts: minimal open tag, the
//! payload's records walked and emitted (a parse fault inside is
//! a real fault with the crossing trail; nested designations
//! convert within), minimal end tag — the length prefix vanishes,
//! because groups carry none. A **routed-but-untargeted** LEN a
//! designating path crosses is committed and descended exactly as
//! `replay_rewrite`'s crossings: it stays LEN, its interior is
//! walked, and its length prefix re-settles when conversions
//! inside change its extent. Only an **unrouted** LEN rides
//! opaque — pass one seeks past it through the supply's own skip.
//! A designated occurrence that is not a LEN record is the
//! caller's schema error, faulted loudly and quoted by
//! designating-path index.
//!
//! Every face is two walks: pass one measures, judges, and
//! compiles the source-anchored script — every crossed prefix
//! opened over its source span and settled at its extent's close
//! — and pass two folds the script against a fresh walk, parsing
//! nothing. The Vec faces reserve exactly once at the script's
//! compiled out-length before the fold. Pass two's whole fault
//! alphabet is the supply's refusals and the length-shaped tear
//! ([`JobFault::Torn`]); wire faults are unspellable there.
//!
//! Output closure: the output always re-ingests under the grouped
//! dialect's `Tolerant` standard (groupless-lawful records are
//! grouped-lawful — the four-code language is a sub-language —
//! and authored framing pairs by construction). It closes under
//! `CanonicalMinimal` exactly when every padded source word was a
//! converted occurrence's dropped framing (its tag or its length
//! prefix) or a resized crossed prefix: authored framing and
//! re-settled prefixes are minimal, every other word rides
//! verbatim. A job run under the `CanonicalMinimal` input
//! standard admits no padded word, so its output closes
//! canonically by construction. An *empty* program converts
//! nothing and the output is byte-identical — but if identity is
//! the whole job, no machine is needed: unchanged
//! groupless-lawful bytes are already grouped-lawful (see the
//! [`crate::replay_convert`] module doc).
//!
//! Coordinates: write · sequential-repeatable · static · groupless (input) · grouped (output) · Standard (value-level) · commit-only.
//!
//! # Publication custody
//!
//! - [`convert`]: a fresh buffer — absent on `Err`, so no partial
//!   product exists.
//! - [`convert_into`]: appends to the caller's buffer, truncated
//!   back to its entry mark on any refusal — the reuse face for
//!   batch loops.
//! - [`convert_sink`]: borrowed views handed forward as they
//!   emit; a refusal reports the exact handed prefix
//!   ([`Handed`]) — pass-one faults precede every handoff,
//!   pass-two faults need not, and the prefix carries no validity
//!   promise.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::replay_convert::grouped::convert;
//! use protobuf_edit::replay_source::SliceSource;
//! use protobuf_edit::{DepthLimit, FieldNumber, Standard};
//!
//! // varint f1=150 · LEN f2 [ varint f3=1 ]
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x18, 0x01];
//! let paths: [&[Segment<'_>]; 1] =
//!     [&[Segment::Field(FieldNumber::new(2).unwrap())]];
//! let program = Program::over(&paths).unwrap();
//! let mut source = SliceSource::new(&msg);
//! let (out, stats) =
//!     convert(&mut source, program, Standard::Tolerant, DepthLimit::REFERENCE)
//!         .unwrap();
//! // varint f1=150 · group f2 { varint f3=1 }
//! assert_eq!(out, [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14]);
//! assert_eq!(stats.converted(), 1);
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::path::{Matcher, Program};
use crate::replay_pump::{Pump, StepRead};
use crate::replay_script::{FoldFault, Script, fold};
use crate::replay_source::{
    Handed, ReplayFault, ReplayPhase, ReplayWalk, SourceCrossing, StableReplaySource, SupplyFault,
};
use crate::wire::grouped::{RecordKind as OutKind, group_end_word, head_word};
use crate::wire::groupless::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3};
use crate::{DepthLimit, FaultClass, Standard};

/// The job receipt.
///
/// A zero `converted` count is the silently-inapplicable-policy
/// signal: no designated occurrence existed, and the output is
/// byte-identical to the source's walk.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Stats {
    converted: u32,
    descended: u32,
}

impl Stats {
    /// LEN records re-framed as groups (nested conversions count
    /// one each).
    #[inline]
    #[must_use]
    pub const fn converted(self) -> u32 {
        self.converted
    }

    /// Undesignated LEN payloads descended into (committed as
    /// messages by crossing paths).
    #[inline]
    #[must_use]
    pub const fn descended(self) -> u32 {
        self.descended
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
    /// first; empty at top level) — converted containers included:
    /// re-framing is a commitment.
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

/// The grouped-output replay converter's document refusal classes.
///
/// The buffered converter's `Output` and `Oversize` classes are
/// unspellable here: replay coordinates are the stream's `u64`
/// space, so neither the source nor the root output has an
/// admission cap to outgrow.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    /// A committed descent (or the top level) hit unlawful wire —
    /// the groupless vocabulary, summarized (group codes arrive as
    /// its capability refusal).
    Wire(WireBreach),
    /// A designated occurrence is not a LEN record: the program
    /// committed the field to carry messages, and the document
    /// disagrees — the caller's schema error, quoted by path.
    KindMismatch {
        /// The designating path's index.
        path: u32,
    },
    /// A routed-but-untargeted LEN's re-settled interior outgrew
    /// the LEN class its prefix must encode (its designated
    /// descendants re-framed into wider spellings).
    Growth {
        /// The interior's settled length.
        len: u64,
    },
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Wire(breach) => write!(f, "{breach}"),
            Self::KindMismatch { path } => {
                write!(f, "path {path} designates a record whose kind is not LEN")
            }
            Self::Growth { len } => {
                write!(f, "a resized interior of {len} bytes outgrew the LEN class")
            }
        }
    }
}

impl core::error::Error for FaultKind {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(breach) => Some(breach),
            Self::KindMismatch { .. } | Self::Growth { .. } => None,
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
    /// class, or cut by an extent or the source's end.
    Varint,
    /// The tag word is unlawful (field zero or an unassigned
    /// code).
    Tag,
    /// A fixed-width or LEN extent exceeds its enclosing extent
    /// or the source's actual end.
    Truncated,
    /// A committed descent would nest past the caller's declared
    /// [`DepthLimit`] budget (conversions are commitments too).
    Depth,
    /// A varint word wider than its minimal encoding — the
    /// declared [`Standard::CanonicalMinimal`]'s judgment (a
    /// tolerant job never judges widths).
    NonMinimal,
    /// A group code appeared — outside the input dialect's
    /// language (an already-grouped document needs no converter).
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
            Self::Depth => "nesting past the declared depth budget",
            Self::NonMinimal => "a varint word wider than its minimal encoding",
            Self::GroupCode => "a group code outside the input dialect",
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

/// What one committed layer is: a designated LEN re-framing as a
/// group (authored framing, no prefix — groups carry none), or a
/// routed-but-untargeted LEN crossed exactly as rewrite's (its
/// prefix slot re-settles at the close).
enum FrameKind {
    /// A designated LEN: the minimal end tag lands at the close.
    Convert,
    /// A crossed LEN: the prefix slot and the settle inputs.
    Cross {
        /// The container's prefix slot in the script.
        slot: u32,
        /// The script's output length at open (the settle's
        /// interior subtrahend).
        mark: u64,
    },
}

/// One committed LEN layer on the walk stack.
struct Frame {
    /// The container's field (the trail element).
    field: FieldNumber,
    /// The container record's head offset.
    at: u64,
    /// The interior's start — the coordinate an overrunning
    /// extent is refused at, mirroring the buffered twin.
    interior: u64,
    /// The declared interior length (the settle's verbatim test
    /// and the arbitration probe's bound).
    declared: u64,
    /// The enclosing extent's end, restored on close.
    prev_zone: u64,
    kind: FrameKind,
}

/// The measuring machine: the pump, the compiled program's
/// matcher, and the script under compilation. Every refusal is
/// terminal — designation is static, so no speculation machinery
/// exists.
struct Machine<'r, W: ReplayWalk> {
    pump: Pump<W>,
    matcher: Matcher<'r, Program<'r>>,
    script: Script<'static>,
    stack: Vec<Frame>,
    limit: DepthLimit,
    stats: Stats,
}

impl<'r, W: ReplayWalk> Machine<'r, W> {
    /// The promise chain: one crossing per committed layer —
    /// converted containers included (re-framing is a commitment).
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

    /// A document verdict raised inside an open layer only stands
    /// when every committed extent is honest: the buffered twin
    /// refuses an overrunning LEN at its open — before judging one
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

    /// Closes the layer the extent end popped: a converted layer
    /// lands its minimal end tag, a crossed one settles its prefix
    /// slot from the interior the script accumulated since the
    /// open.
    fn close_frame(&mut self) -> Result<(), JobFault<W::Error>> {
        // The root zone is the coordinate space's sentinel, so a
        // met endpoint always has a frame to close.
        let Some(frame) = self.stack.pop() else {
            unreachable!("the root zone is the coordinate space's sentinel")
        };
        self.matcher.exit();
        match frame.kind {
            FrameKind::Convert => {
                self.script.stage_word(u64::from(group_end_word(frame.field)));
            }
            FrameKind::Cross { slot, mark } => {
                let interior = self.script.out_len() - mark;
                if let Err(len) = self.script.settle_prefix(slot, interior, frame.declared) {
                    return Err(self.refuse(frame.at, FaultKind::Growth { len }));
                }
            }
        }
        self.pump.zone = frame.prev_zone;
        Ok(())
    }

    /// Runs the measuring walk to the source's end; the script,
    /// the measured total, and the receipt come back together.
    fn run<const MINIMAL: bool>(
        mut self,
    ) -> Result<(Script<'static>, u64, Stats), JobFault<W::Error>> {
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
                TagClass::Record(RecordKind::I64) => self.fixed_record(at, field, 8)?,
                TagClass::Record(RecordKind::I32) => self.fixed_record(at, field, 4)?,
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

    /// VARINT: the value steps (wire law needs its width), then a
    /// designation on the field is the caller's schema error —
    /// everything undesignated rides verbatim.
    fn varint_record<const MINIMAL: bool>(
        &mut self,
        at: u64,
        field: FieldNumber,
    ) -> Result<(), JobFault<W::Error>> {
        let std = const { if MINIMAL { Standard::CanonicalMinimal } else { Standard::Tolerant } };
        let after_tag = self.pump.off;
        let width = match self.pump.step_value(std) {
            StepRead::Done { width, .. } => width,
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
        if let Some(path) = self.matcher.first_target(field) {
            return Err(self.refuse(at, FaultKind::KindMismatch { path: u32::from(path) }));
        }
        self.script.copy_to(after_tag + u64::from(width.w()));
        Ok(())
    }

    /// I32/I64: the payload is never read — the walk seeks past
    /// it — and a designation on the field is the caller's schema
    /// error.
    fn fixed_record(
        &mut self,
        at: u64,
        field: FieldNumber,
        needed: u64,
    ) -> Result<(), JobFault<W::Error>> {
        let after_tag = self.pump.off;
        if self.pump.zone - self.pump.off < needed {
            return Err(self.refuse(after_tag, FaultKind::Wire(WireBreach::Truncated)));
        }
        self.skip_extent(needed)?;
        if let Some(path) = self.matcher.first_target(field) {
            return Err(self.refuse(at, FaultKind::KindMismatch { path: u32::from(path) }));
        }
        self.script.copy_to(self.pump.off);
        Ok(())
    }

    /// LEN: the prefix steps and the extent is admitted against
    /// the enclosing bound; the three-way law then converts a
    /// designated occurrence, commits a routed one as a crossing,
    /// or rides it verbatim — the payload read only when a path
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
        let designated = self.matcher.first_target(field).is_some();
        let routed = self.matcher.probe_routes(field);
        if !designated && !routed {
            self.skip_extent(declared64)?;
            self.script.copy_to(payload_end);
            return Ok(());
        }
        if self.stack.len() >= usize::from(self.limit.as_inner()) {
            return Err(self.refuse(at, FaultKind::Wire(WireBreach::Depth)));
        }
        let kind = if designated {
            self.stats.converted += 1;
            self.script.copy_to(at);
            self.script.skip_to(payload_start);
            self.script.stage_word(u64::from(head_word(field, OutKind::Group)));
            FrameKind::Convert
        } else {
            self.stats.descended += 1;
            self.script.copy_to(after_tag);
            let slot = self.script.open_prefix(after_tag, payload_start);
            FrameKind::Cross { slot, mark: self.script.out_len() }
        };
        self.matcher.commit_descent();
        self.stack.push(Frame {
            field,
            at,
            interior: payload_start,
            declared: declared64,
            prev_zone: self.pump.zone,
            kind,
        });
        self.pump.zone = payload_end;
        Ok(())
    }
}

// ─── the job fronts ───

/// Runs pass one over a fresh walk.
fn measure<S: StableReplaySource>(
    source: &mut S,
    program: Program<'_>,
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
        matcher: Matcher::new(program),
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
/// The program passes by value: it is one borrowed slice-of-slices
/// wide, exactly a `&[u8]` parameter's posture.
///
/// # Errors
///
/// [`JobFault`]; no buffer exists on `Err`.
pub fn convert<S: StableReplaySource>(
    source: &mut S,
    program: Program<'_>,
    standard: Standard,
    limit: DepthLimit,
) -> Result<(Vec<u8>, Stats), JobFault<S::Error>> {
    let mut out = Vec::new();
    let stats = convert_into(source, program, standard, limit, &mut out)?;
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
    program: Program<'_>,
    standard: Standard,
    limit: DepthLimit,
    out: &mut Vec<u8>,
) -> Result<Stats, JobFault<S::Error>> {
    let (script, total, stats) = measure(source, program, standard, limit)?;
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
    program: Program<'_>,
    standard: Standard,
    limit: DepthLimit,
    mut sink: impl FnMut(&[u8]),
) -> Result<Stats, Handed<JobFault<S::Error>>> {
    let (script, total, stats) = match measure(source, program, standard, limit) {
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
