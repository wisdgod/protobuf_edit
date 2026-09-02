//! The grouped scanner: groups walk structurally.
//!
//! The mixed stack interleaves descended-LEN frames and open-group
//! frames; the innermost sealed endpoint rides the cursor register
//! and frames keep only shadowed predecessors, so pops are O(1) and
//! the endpoint check is `off == zone`. Group ends never pop LEN
//! frames and the endpoint cascade never pops group frames — the
//! two pop paths are disjoint by frame kind.
//!
//! Coordinates: read · stream · online · grouped · Standard (value-level).
//!
//! # Examples
//!
//! ```
//! use core::ops::ControlFlow;
//! use protobuf_edit::scan::{Flow, Standard};
//! use protobuf_edit::scan::grouped::{Parser, Sink};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! struct Sum(u64);
//! impl Sink for Sum {
//!     fn on_varint(&mut self, _field: FieldNumber, value: u64) -> ControlFlow<()> {
//!         self.0 += value;
//!         ControlFlow::Continue(())
//!     }
//! }
//!
//! // varint f1=150 · group f2 { varint f3=1 }
//! let msg = [0x08, 0x96, 0x01, 0x13, 0x18, 0x01, 0x14];
//! let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
//! let mut sum = Sum(0);
//! assert_eq!(parser.feed(&msg[..4], &mut sum).unwrap(), Flow::More);
//! assert_eq!(parser.feed(&msg[4..], &mut sum).unwrap(), Flow::More);
//! parser.finish().unwrap();
//! assert_eq!(sum.0, 151);
//! ```

use alloc::vec::Vec;
use core::num::NonZeroU32;
use core::ops::ControlFlow;

use super::{Flow, LenDisposition, Mode, ReadFault, Stage, Standard};
use crate::admission::usize_of;
use crate::pump::{FixedKind, Pump, Verdict, standard_of};
use crate::{DepthLimit, FaultClass};
use crate::wire::grouped::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3, PayloadLen};

/// The event consumer; every `Break` is an orderly early stop
/// (terminal).
///
/// All defaults continue, and the default disposition is
/// `OpaqueSkip` — a sink that overrides nothing is exactly the
/// wire-level validator's consumer face.
///
/// The enter/exit pairs are the ancestry supply: a sink that
/// wants the current path pushes the field on the `Commit` it
/// answers (or on `on_group_enter`) and pops on the matching exit
/// — its own stack, paid only when wanted (skipped subtrees never
/// enter, so the path holds committed containers exactly).
pub trait Sink {
    /// One question per LEN head: field, declared length, payload
    /// start offset. Answering `Commit` is the enter notification.
    #[inline]
    fn on_len(
        &mut self,
        field: FieldNumber,
        len: PayloadLen,
        at: u64,
    ) -> ControlFlow<(), LenDisposition> {
        let _ = (field, len, at);
        ControlFlow::Continue(LenDisposition::OpaqueSkip)
    }

    /// A descended LEN reached its endpoint (`at` = payload end).
    #[inline]
    fn on_len_exit(&mut self, field: FieldNumber, at: u64) -> ControlFlow<()> {
        let _ = (field, at);
        ControlFlow::Continue(())
    }

    /// A group opened (`at` = content start).
    #[inline]
    fn on_group_enter(&mut self, field: FieldNumber, at: u64) -> ControlFlow<()> {
        let _ = (field, at);
        ControlFlow::Continue(())
    }

    /// A group closed (`at` = content end = end-tag start).
    #[inline]
    fn on_group_exit(&mut self, field: FieldNumber, at: u64) -> ControlFlow<()> {
        let _ = (field, at);
        ControlFlow::Continue(())
    }

    /// A varint record completed: the wire word by value (schema
    /// semantics belong to the caller via the `scalar` matrix).
    #[inline]
    fn on_varint(&mut self, field: FieldNumber, value: u64) -> ControlFlow<()> {
        let _ = (field, value);
        ControlFlow::Continue(())
    }

    /// An I32 record completed: four little-endian bits.
    #[inline]
    fn on_i32(&mut self, field: FieldNumber, bits: u32) -> ControlFlow<()> {
        let _ = (field, bits);
        ControlFlow::Continue(())
    }

    /// An I64 record completed: eight little-endian bits.
    #[inline]
    fn on_i64(&mut self, field: FieldNumber, bits: u64) -> ControlFlow<()> {
        let _ = (field, bits);
        ControlFlow::Continue(())
    }

    /// One fragment of an `OpaqueBytes`-disposed payload, borrowing
    /// the current chunk (copy to retain). Fragments arrive without
    /// interleaved events and sum to the announced length; a
    /// zero-length payload delivers no fragment (the sink already
    /// knows the length from `on_len`).
    #[inline]
    fn on_segment(&mut self, bytes: &[u8]) -> ControlFlow<()> {
        let _ = bytes;
        ControlFlow::Continue(())
    }
}

/// The all-default sink: descend nothing, watch nothing — the pure
/// wire-level validator's consumer face.
impl Sink for () {}

/// One law violation, terminal: where, and which law.
///
/// `at`'s meaning per kind: a [`FaultKind::Read`] names the
/// refused construct's first byte, except that a
/// [`ReadFault::SealCut`] and
/// [`GroupUnclosedAtLenEnd`](FaultKind::GroupUnclosedAtLenEnd)
/// name the sealed endpoint and a [`ReadFault::StreamEnd`] names
/// the stream end; structural faults name the judgment point; an
/// [`OffsetExhausted`](FaultKind::OffsetExhausted) names the
/// current offset (the refused chunk would begin there);
/// `FixedTruncated`, `PayloadTruncated`,
/// [`UnclosedLen`](FaultKind::UnclosedLen), and
/// [`GroupUnclosed`](FaultKind::GroupUnclosed) name the stream
/// end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u64,
    kind: FaultKind,
}

// The error arm's layout budget: the kind stays at 12 bytes and
// the carrier within 24 (u64-alignment padding differs by target,
// so the carrier is a ceiling, not an equality).
const _: () = assert!(core::mem::size_of::<FaultKind>() == 12);
const _: () = assert!(core::mem::size_of::<Fault>() <= 24);

impl Fault {
    /// The coordinate (absolute stream offset).
    #[inline]
    #[must_use]
    pub const fn at(self) -> u64 {
        self.at
    }

    /// The violated law.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> FaultKind {
        self.kind
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at input offset {}", self.kind, self.at)
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.kind)
    }
}

/// The scanner's refusal classes (the dialect tables' precedent:
/// overlapping variants per dialect, unshared), sectioned by
/// [`FaultClass`] (grammar sites, then policy);
/// [`class`](Self::class) answers the section.
///
/// A fault judged after the head tag revealed its field number
/// carries that field — inside the [`Stage`] coordinate for varint
/// reads (the tag stage carries none: no field exists yet), on the
/// variant elsewhere. The one exception is [`PayloadTruncated`]:
/// an undelivered opaque payload counts down without its field
/// (the resume mode keeps only the owed count), so the fault
/// quotes what the machine still owes.
///
/// [`PayloadTruncated`]: Self::PayloadTruncated
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    // ─ grammar: varint sites ─
    /// A varint construct refused at one of the record's stages
    /// (tag: five-byte window, u32 word class; length prefix:
    /// five-byte window, 2^31 − 1 length class; value: ten-byte
    /// window, u64 class).
    Read {
        /// The construct the read was serving.
        stage: Stage,
        /// The refusal, in stream coordinates.
        cause: ReadFault,
    },
    /// A tag decoded to field number zero.
    FieldZero,
    /// A tag carried a code unassigned by the format (6 or 7).
    Unassigned {
        /// The field the tag names (judged before the code).
        field: FieldNumber,
        /// The unassigned code.
        code: Low3,
    },
    /// A declared length punctures the enclosing seal.
    LenOverrun {
        /// The record's field number.
        field: FieldNumber,
        /// The declared payload length.
        len: PayloadLen,
    },
    // ─ grammar: payload sites ─
    /// A fixed payload does not fit the enclosing extent.
    FixedOverrun {
        /// The record's field number.
        field: FieldNumber,
    },
    /// The stream ended inside a fixed payload.
    FixedTruncated {
        /// The record's field number.
        field: FieldNumber,
    },
    /// The stream ended inside a counted payload.
    PayloadTruncated {
        /// Bytes still owed (a counting mode always owes).
        remaining: NonZeroU32,
    },
    /// The stream ended with a descended LEN still open.
    UnclosedLen {
        /// The innermost open LEN's field.
        field: FieldNumber,
    },
    // ─ grammar: group framing ─
    /// An end-of-group tag with no open group.
    GroupEndOrphan {
        /// The end tag's field.
        end: FieldNumber,
    },
    /// An end-of-group tag whose field differs from the innermost
    /// open group's.
    GroupEndMismatch {
        /// The end tag's field.
        end: FieldNumber,
        /// The innermost open group's field.
        open: FieldNumber,
    },
    /// An end-of-group tag arriving while the innermost frame is a
    /// LEN whose endpoint has not been reached: closing would
    /// pierce the seal.
    GroupEndAcrossLen {
        /// The end tag's field.
        end: FieldNumber,
        /// The innermost (unfinished) LEN's field.
        open_len: FieldNumber,
    },
    /// A LEN endpoint arrived while a group inside it is open.
    GroupUnclosedAtLenEnd {
        /// The open group's field.
        group: FieldNumber,
    },
    /// The stream ended with a group still open.
    GroupUnclosed {
        /// The innermost open group's field.
        field: FieldNumber,
    },
    // ─ policy: the declared standard and bound ─
    /// A tag wider than minimal (CanonicalMinimal only).
    NonMinimalTag,
    /// A length prefix wider than minimal (CanonicalMinimal only).
    NonMinimalLen {
        /// The record's field number.
        field: FieldNumber,
    },
    /// A value varint wider than minimal (CanonicalMinimal only).
    NonMinimalValue {
        /// The record's field number.
        field: FieldNumber,
    },
    /// Opening this container would exceed the caller's declared
    /// [`DepthLimit`] bound.
    DepthExceeded {
        /// The container's field number.
        field: FieldNumber,
    },
    // ─ capability: the coordinate space ─
    /// The accumulated stream offset would leave the addressable
    /// coordinate space: the machine admits streams of at most
    /// `u64::MAX − 1` bytes, and the offered chunk runs past that
    /// top. Judged whole at feed admission, before any byte of the
    /// chunk is read, and terminal like every fault — a stream
    /// this long has no lawful coordinate to continue at.
    OffsetExhausted,
    /// A declared length the coordinate space cannot host: outside
    /// any LEN seal (at the root — or, in the grouped dialect,
    /// inside an open group, which never moves the seal), the
    /// payload's end would land on (or past) the reserved sentinel
    /// coordinate. Read after the tag and the length prefix; the
    /// same bytes are lawful at a lower cursor — the refusal
    /// depends on the accumulated position, like the feed gate's
    /// exhaustion, so it repairs by capability rather than by
    /// editing the bytes.
    LenUnsatisfiable {
        /// The record's field number.
        field: FieldNumber,
        /// The declared payload length.
        len: PayloadLen,
    },
}

impl FaultKind {
    /// The minimality refusal at a varint stage (the pump's
    /// [`Verdict::NonMinimal`], placed into this vocabulary).
    pub(crate) const fn padded(stage: Stage) -> Self {
        match stage {
            Stage::Tag => Self::NonMinimalTag,
            Stage::LenPrefix { field } => Self::NonMinimalLen { field },
            Stage::Value { field } => Self::NonMinimalValue { field },
        }
    }

    /// The refusal's [`FaultClass`] — which repair the fault asks
    /// for. Policy membership names its configuration datum on the
    /// variant (the [`Standard`] for the `NonMinimal*` family, the
    /// [`DepthLimit`] bound for `DepthExceeded`); the capability
    /// members are the coordinate-space refusals
    /// ([`OffsetExhausted`](Self::OffsetExhausted) at the feed
    /// gate, [`LenUnsatisfiable`](Self::LenUnsatisfiable) at a LEN
    /// head outside any seal) — the dialect's language is the format's
    /// whole code alphabet, so no tag code is a capability matter
    /// here.
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Read { .. }
            | Self::FieldZero
            | Self::Unassigned { .. }
            | Self::LenOverrun { .. }
            | Self::FixedOverrun { .. }
            | Self::FixedTruncated { .. }
            | Self::PayloadTruncated { .. }
            | Self::UnclosedLen { .. }
            | Self::GroupEndOrphan { .. }
            | Self::GroupEndMismatch { .. }
            | Self::GroupEndAcrossLen { .. }
            | Self::GroupUnclosedAtLenEnd { .. }
            | Self::GroupUnclosed { .. } => FaultClass::Grammar,
            Self::NonMinimalTag
            | Self::NonMinimalLen { .. }
            | Self::NonMinimalValue { .. }
            | Self::DepthExceeded { .. } => FaultClass::Policy,
            Self::OffsetExhausted | Self::LenUnsatisfiable { .. } => FaultClass::Capability,
        }
    }
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Read { stage, cause } => {
                match cause {
                    ReadFault::SealCut => f.write_str("the sealed extent ends inside ")?,
                    ReadFault::StreamEnd => f.write_str("the stream ended inside ")?,
                    ReadFault::TooWide | ReadFault::OutOfClass => {}
                }
                let (window, class) = match stage {
                    Stage::Tag => {
                        f.write_str("a tag")?;
                        ("five", "u32 class")
                    }
                    Stage::LenPrefix { field } => {
                        write!(f, "the length prefix of field {}", field.as_inner())?;
                        ("five", "length class")
                    }
                    Stage::Value { field } => {
                        write!(f, "the varint value of field {}", field.as_inner())?;
                        ("ten", "u64 class")
                    }
                };
                match cause {
                    ReadFault::SealCut | ReadFault::StreamEnd => Ok(()),
                    ReadFault::TooWide => write!(f, " ran past the {window}-byte window"),
                    ReadFault::OutOfClass => write!(f, " exceeds the {class}"),
                }
            }
            Self::FieldZero => f.write_str("a tag names field zero"),
            Self::Unassigned { field, code } => {
                write!(f, "field {} carries unassigned code {}", field.as_inner(), code.as_inner())
            }
            Self::LenOverrun { field, len } => write!(
                f,
                "field {} declares {} payload bytes beyond its seal",
                field.as_inner(),
                len.as_inner()
            ),
            Self::LenUnsatisfiable { field, len } => write!(
                f,
                "field {} declares {} payload bytes the coordinate space cannot host",
                field.as_inner(),
                len.as_inner()
            ),
            Self::FixedOverrun { field } => {
                write!(f, "the fixed payload of field {} does not fit its extent", field.as_inner())
            }
            Self::FixedTruncated { field } => {
                write!(f, "the stream ended inside the fixed payload of field {}", field.as_inner())
            }
            Self::PayloadTruncated { remaining } => {
                write!(f, "the stream ended {remaining} bytes short of a length-prefixed payload")
            }
            Self::UnclosedLen { field } => {
                write!(f, "the stream ended inside the descended LEN of field {}", field.as_inner())
            }
            Self::GroupEndOrphan { end } => {
                write!(f, "an end-of-group tag for field {} with no open group", end.as_inner())
            }
            Self::GroupEndMismatch { end, open } => write!(
                f,
                "an end-of-group tag for field {} while group field {} is open",
                end.as_inner(),
                open.as_inner()
            ),
            Self::GroupEndAcrossLen { end, open_len } => write!(
                f,
                "an end-of-group tag for field {} inside the unfinished LEN of field {}",
                end.as_inner(),
                open_len.as_inner()
            ),
            Self::GroupUnclosedAtLenEnd { group } => {
                write!(f, "a LEN endpoint arrived while group field {} is open", group.as_inner())
            }
            Self::GroupUnclosed { field } => {
                write!(f, "the stream ended with group field {} open", field.as_inner())
            }
            Self::NonMinimalTag => f.write_str("a tag is wider than its minimal encoding"),
            Self::NonMinimalLen { field } => write!(
                f,
                "the length prefix of field {} is wider than its minimal encoding",
                field.as_inner()
            ),
            Self::NonMinimalValue { field } => write!(
                f,
                "the varint value of field {} is wider than its minimal encoding",
                field.as_inner()
            ),
            Self::DepthExceeded { field } => write!(
                f,
                "opening the container of field {} would exceed the bound",
                field.as_inner()
            ),
            Self::OffsetExhausted => {
                f.write_str("the stream ran past the addressable 2^64 - 1 bytes")
            }
        }
    }
}

impl core::error::Error for FaultKind {}

/// One open container. LEN frames keep the *shadowed* predecessor
/// endpoint (the live one rides the cursor); both kinds keep their
/// field for exit events and end-tag matching.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Extent {
    Len { prev_zone: u64, field: FieldNumber },
    Group { field: FieldNumber },
}

const _: () = assert!(core::mem::size_of::<Extent>() == 16);

/// The one-pass scanning machine (validator and extractor alike:
/// the sink is the judgment seat for what to watch; the machine
/// owns wire law and the standard).
///
/// Terminal states are final: after a fault or an early stop,
/// another `feed`/`finish` call panics (a caller bug, named); a
/// clean end goes through `finish(self)`, which consumes the
/// machine.
#[must_use]
pub struct Parser {
    pump: Pump,
    mode: Mode,
    stack: Vec<Extent>,
    depth: DepthLimit,
}

impl Parser {
    /// All configuration is explicit: the acceptance standard and
    /// the nesting bound have no defaults.
    #[inline]
    pub const fn new(standard: Standard, depth: DepthLimit) -> Self {
        Self { pump: Pump::new(standard), mode: Mode::Head, stack: Vec::new(), depth }
    }

    /// Absolute consumed offset (progress observation — skips emit
    /// no events, this is where progress is read).
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.pump.off
    }

    /// Feeds one chunk. Events flow to `sink` as constructs
    /// complete; `Flow::More` means the chunk is exhausted and the
    /// machine carries the residue.
    ///
    /// # Errors
    ///
    /// The first law violation under the declared standard ends the
    /// stream: the fault carries its absolute coordinate
    /// ([`Fault::at`]) and the violated law ([`Fault::kind`]). A
    /// chunk that would run the stream past its addressable
    /// coordinate space (`u64::MAX − 1` bytes) is refused whole at
    /// admission as [`FaultKind::OffsetExhausted`], before any of
    /// its bytes are read.
    ///
    /// # Panics
    ///
    /// After a previous fault or early stop, and after a feed whose
    /// sink callback unwound (the machine latches terminal across
    /// callbacks, so a caught panic cannot resume a half-stepped
    /// stream). The stream is over — feeding again is a caller
    /// bug.
    #[track_caller]
    pub fn feed<S: Sink>(&mut self, chunk: &[u8], sink: &mut S) -> Result<Flow, Fault> {
        assert!(!self.pump.terminal, "stream already terminal");
        // Coordinate admission ([`Pump::admits`]): the gate keeps
        // `off` strictly below the root sentinel through every
        // consuming path of this feed. Judged in this prologue so
        // the drive loop's codegen owes the gate nothing.
        if core::hint::unlikely(!self.pump.admits(chunk)) {
            return Err(self.fault(self.pump.off, FaultKind::OffsetExhausted));
        }
        // Poison across the sink callbacks: latch terminal before
        // driving, so a callback that unwinds leaves the machine
        // terminal (every later feed hits the entry assert) rather
        // than resumable mid-construct — a resumed `FixedTail`
        // could re-enter collection against a popped zone and reach
        // the unreachable `Collect::Cut`. A normal return restores
        // the latch to the drive's own verdict (fault terminal,
        // otherwise live). The declared standard picks the drive
        // instance once: the per-record minimality test is a const
        // inside the engine.
        self.pump.terminal = true;
        let flow = match self.pump.standard {
            Standard::Tolerant => self.drive::<S, false>(chunk, sink),
            Standard::CanonicalMinimal => self.drive::<S, true>(chunk, sink),
        };
        // Only `More` leaves the machine live for the next chunk; a
        // fault or an orderly stop is terminal (and a panic skips
        // this line, leaving the armed latch).
        self.pump.terminal = !matches!(flow, Ok(Flow::More));
        flow
    }

    /// The feed's drive engine, behind the admission prologue, one
    /// instance per acceptance standard.
    #[inline(never)]
    fn drive<S: Sink, const MINIMAL: bool>(
        &mut self,
        chunk: &[u8],
        sink: &mut S,
    ) -> Result<Flow, Fault> {
        // The engine's const standard and the pump's declared one
        // are the same fact in two representations; the six call
        // sites keep them aligned, and this seam pins that.
        debug_assert!(standard_of(MINIMAL) == self.pump.standard);
        let mut chunk = chunk;
        loop {
            // Cascade: resolve every endpoint at the cursor before
            // any construct starts (the carry contract, machined).
            match self.cascade(sink) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(flow) => return flow,
            }
            if chunk.is_empty() {
                return Ok(Flow::More);
            }
            let flow = match self.mode {
                Mode::Head => self.head::<_, MINIMAL>(&mut chunk, sink),
                Mode::VarintValue { field } => {
                    self.varint_value::<_, MINIMAL>(&mut chunk, field, sink)
                }
                Mode::LenWord { field } => self.len_word::<_, MINIMAL>(&mut chunk, field, sink),
                Mode::FixedTail { field, kind } => self.fixed_tail(&mut chunk, field, kind, sink),
                Mode::Forward { remaining } => self.forward(&mut chunk, remaining, sink),
                Mode::Swallow { remaining } => self.swallow(&mut chunk, remaining),
            };
            match flow {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(flow) => return flow,
            }
        }
    }

    /// Declares EOF and consumes the machine: the final verdict.
    ///
    /// No cascade runs here — every endpoint not under a suspended
    /// word was resolved inside `feed`, and an endpoint a word
    /// straddles is the truncation the mode match below reports.
    /// The sink receives nothing at EOF.
    ///
    /// # Errors
    ///
    /// EOF inside a construct or a counted payload is the matching
    /// truncation fault; a still-open container is the matching
    /// unclosed fault — every one at the final offset. A non-`Head`
    /// mode is truncation whether or not any byte of the pending
    /// word arrived: verdict and coordinate agree either way.
    ///
    /// # Panics
    ///
    /// After a previous fault or early stop, and after a feed whose
    /// sink callback unwound.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::scan::{ReadFault, Stage, Standard};
    /// use protobuf_edit::scan::grouped::{FaultKind, Parser};
    ///
    /// // A varint tag arrived; its value never did.
    /// let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
    /// parser.feed(&[0x08], &mut ()).unwrap();
    /// let fault = parser.finish().unwrap_err();
    /// assert!(matches!(
    ///     fault.kind(),
    ///     FaultKind::Read { stage: Stage::Value { field }, cause: ReadFault::StreamEnd }
    ///         if field.as_inner() == 1
    /// ));
    /// assert_eq!(fault.at(), 1);
    /// ```
    #[track_caller]
    pub fn finish(self) -> Result<(), Fault> {
        assert!(!self.pump.terminal, "stream already terminal");
        debug_assert!(
            self.pump.off != self.pump.zone
                || !(matches!(self.mode, Mode::Head) && self.pump.carry.is_empty()),
            "feed resolves every endpoint it does not leave under a suspended word"
        );
        let at = self.pump.off;
        match self.mode {
            Mode::Head => {
                if !self.pump.carry.is_empty() {
                    let kind = FaultKind::Read { stage: Stage::Tag, cause: ReadFault::StreamEnd };
                    return Err(Fault { at, kind });
                }
            }
            Mode::VarintValue { field } => {
                let kind =
                    FaultKind::Read { stage: Stage::Value { field }, cause: ReadFault::StreamEnd };
                return Err(Fault { at, kind });
            }
            Mode::LenWord { field } => {
                let kind = FaultKind::Read {
                    stage: Stage::LenPrefix { field },
                    cause: ReadFault::StreamEnd,
                };
                return Err(Fault { at, kind });
            }
            Mode::FixedTail { field, .. } => {
                return Err(Fault { at, kind: FaultKind::FixedTruncated { field } });
            }
            Mode::Forward { remaining } | Mode::Swallow { remaining } => {
                return Err(Fault { at, kind: FaultKind::PayloadTruncated { remaining } });
            }
        }
        match self.stack.last() {
            Some(&Extent::Len { field, .. }) => {
                Err(Fault { at, kind: FaultKind::UnclosedLen { field } })
            }
            Some(&Extent::Group { field }) => {
                Err(Fault { at, kind: FaultKind::GroupUnclosed { field } })
            }
            None => Ok(()),
        }
    }

    // ─ the drive arms (each returns Break to end the feed) ─

    fn cascade<S: Sink>(&mut self, sink: &mut S) -> ControlFlow<Result<Flow, Fault>> {
        while self.pump.off == self.pump.zone {
            // A seal endpoint pops only between constructs. A
            // word suspended across the seal — a tag prefix in
            // the carry, a value or length word pending — means
            // the document truncates mid-record: fall through to
            // the mode arm, whose kernel reports `Cut` at the
            // sealed cursor. The counting modes cannot arrive
            // here mid-flight: their spans were admitted against
            // the zone at the head.
            if !(matches!(self.mode, Mode::Head) && self.pump.carry.is_empty()) {
                debug_assert!(matches!(
                    self.mode,
                    Mode::Head | Mode::VarintValue { .. } | Mode::LenWord { .. }
                ));
                break;
            }
            match self.stack.last().copied() {
                Some(Extent::Len { prev_zone, field }) => {
                    self.stack.pop();
                    self.pump.zone = prev_zone;
                    if self.event(sink.on_len_exit(field, self.pump.off)).is_break() {
                        return ControlFlow::Break(Ok(Flow::Stopped));
                    }
                }
                Some(Extent::Group { field }) => {
                    return ControlFlow::Break(Err(self
                        .fault(self.pump.off, FaultKind::GroupUnclosedAtLenEnd { group: field })));
                }
                // SAFETY: an empty stack leaves the root zone,
                // `u64::MAX`, and the feed admission gate keeps
                // `off < u64::MAX` through every consuming path
                // ([`Pump::admits`]) — the cursor can never equal
                // the root sentinel.
                None => unsafe { core::hint::unreachable_unchecked() },
            }
        }
        ControlFlow::Continue(())
    }

    fn head<S: Sink, const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        // The construct's first byte, read before stepping: the
        // carry holds exactly the resumed prefix here, so the
        // coordinate equals the completed tag's start (the group
        // punctuation and the structural refusals below spend it).
        let start = self.pump.construct_start();
        let word = match self.pump.step_tag(chunk, standard_of(MINIMAL)) {
            Verdict::Done(word) => word,
            Verdict::More => return ControlFlow::Break(Ok(Flow::More)),
            Verdict::Cut => return self.halt_read(Stage::Tag, ReadFault::SealCut),
            Verdict::TooWide => return self.halt_read(Stage::Tag, ReadFault::TooWide),
            Verdict::OutOfClass => return self.halt_read(Stage::Tag, ReadFault::OutOfClass),
            Verdict::NonMinimal => return self.halt_padded(Stage::Tag),
        };
        let low3 = Low3::from_word(word);
        let Some(field) = FieldNumber::from_word(word) else {
            return self.halt(start, FaultKind::FieldZero);
        };
        match classify(low3) {
            // Record classes hand off to their word handlers:
            // the whole record completes when the chunk allows,
            // and the handlers write a suspension mode only when
            // it does not — the mode is resumption state, not a
            // per-record itinerary.
            TagClass::Record(RecordKind::Varint) => {
                self.varint_value::<_, MINIMAL>(chunk, field, sink)
            }
            TagClass::Record(kind @ (RecordKind::I32 | RecordKind::I64)) => {
                let fixed =
                    if matches!(kind, RecordKind::I64) { FixedKind::I64 } else { FixedKind::I32 };
                // Admit the width against the zone here, so the
                // kernel's Cut is unreachable in collection.
                if self.pump.zone - self.pump.off < u64::from(fixed.need()) {
                    return self.halt(self.pump.off, FaultKind::FixedOverrun { field });
                }
                self.fixed_tail(chunk, field, fixed, sink)
            }
            TagClass::Record(RecordKind::Len) => self.len_word::<_, MINIMAL>(chunk, field, sink),
            TagClass::Record(RecordKind::Group) => {
                if self.stack.len() >= usize::from(self.depth.as_inner()) {
                    return self.halt(start, FaultKind::DepthExceeded { field });
                }
                self.stack.push(Extent::Group { field });
                if self.event(sink.on_group_enter(field, self.pump.off)).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                ControlFlow::Continue(())
            }
            TagClass::GroupEnd => self.group_end(field, start, sink),
            TagClass::Unassigned => self.halt(start, FaultKind::Unassigned { field, code: low3 }),
        }
    }

    fn group_end<S: Sink>(
        &mut self,
        end: FieldNumber,
        at: u64,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        match self.stack.last().copied() {
            None => self.halt(at, FaultKind::GroupEndOrphan { end }),
            Some(Extent::Len { field, .. }) => {
                self.halt(at, FaultKind::GroupEndAcrossLen { end, open_len: field })
            }
            Some(Extent::Group { field }) if field != end => {
                self.halt(at, FaultKind::GroupEndMismatch { end, open: field })
            }
            Some(Extent::Group { field }) => {
                self.stack.pop();
                if self.event(sink.on_group_exit(field, at)).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                ControlFlow::Continue(())
            }
        }
    }

    #[inline(always)]
    fn varint_value<S: Sink, const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        match self.pump.step_value(chunk, standard_of(MINIMAL)) {
            Verdict::Done(value) => {
                self.mode = Mode::Head;
                if self.event(sink.on_varint(field, value)).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                ControlFlow::Continue(())
            }
            Verdict::More => {
                self.mode = Mode::VarintValue { field };
                ControlFlow::Break(Ok(Flow::More))
            }
            Verdict::Cut => self.halt_read(Stage::Value { field }, ReadFault::SealCut),
            Verdict::TooWide => self.halt_read(Stage::Value { field }, ReadFault::TooWide),
            Verdict::OutOfClass => self.halt_read(Stage::Value { field }, ReadFault::OutOfClass),
            Verdict::NonMinimal => self.halt_padded(Stage::Value { field }),
        }
    }

    #[inline(always)]
    fn len_word<S: Sink, const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        let len = match self.pump.step_len(chunk, standard_of(MINIMAL)) {
            Verdict::Done(len) => len,
            Verdict::More => {
                self.mode = Mode::LenWord { field };
                return ControlFlow::Break(Ok(Flow::More));
            }
            Verdict::Cut => return self.halt_read(Stage::LenPrefix { field }, ReadFault::SealCut),
            Verdict::TooWide => {
                return self.halt_read(Stage::LenPrefix { field }, ReadFault::TooWide);
            }
            Verdict::OutOfClass => {
                return self.halt_read(Stage::LenPrefix { field }, ReadFault::OutOfClass);
            }
            Verdict::NonMinimal => {
                return self.halt_padded(Stage::LenPrefix { field });
            }
        };
        // LEN admission: the one widening seam (u64 + u32). The
        // refusals split by what has to change. Inside a finite
        // zone, an end past it (or a sum past u64 entirely)
        // contradicts the enclosing declaration wherever the
        // document sits — grammar. At the root the same bytes are
        // lawful at a lower cursor; the end merely needs the
        // reserved sentinel coordinate (or beyond), which this
        // machine's space cannot host — capability, like the feed
        // gate's exhaustion.
        let end = match self.pump.off.checked_add(u64::from(len.as_inner())) {
            Some(end) if end <= self.pump.zone && end != u64::MAX => end,
            _ if self.pump.zone != u64::MAX => {
                return self.halt(self.pump.off, FaultKind::LenOverrun { field, len });
            }
            _ => return self.halt(self.pump.off, FaultKind::LenUnsatisfiable { field, len }),
        };
        match self.ask(sink.on_len(field, len, self.pump.off)) {
            ControlFlow::Break(flow) => return ControlFlow::Break(flow),
            ControlFlow::Continue(LenDisposition::Commit) => {
                if self.stack.len() >= usize::from(self.depth.as_inner()) {
                    return self.halt(self.pump.off, FaultKind::DepthExceeded { field });
                }
                self.stack.push(Extent::Len { prev_zone: self.pump.zone, field });
                self.pump.zone = end;
                self.mode = Mode::Head;
            }
            // The zero judgment is the counting modes' own
            // construction: a zero-length payload completes at its
            // head — no counting state, no fragment (the sink knows
            // the length from `on_len`).
            ControlFlow::Continue(LenDisposition::OpaqueBytes) => {
                self.mode = NonZeroU32::new(len.as_inner())
                    .map_or(Mode::Head, |remaining| Mode::Forward { remaining });
            }
            ControlFlow::Continue(LenDisposition::OpaqueSkip) => {
                self.mode = NonZeroU32::new(len.as_inner())
                    .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
            }
        }
        ControlFlow::Continue(())
    }

    #[inline(always)]
    fn fixed_tail<S: Sink>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        kind: FixedKind,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        let flow = match kind {
            FixedKind::I32 => {
                let Some(bytes) = self.pump.grab_fixed::<4>(chunk) else {
                    self.mode = Mode::FixedTail { field, kind };
                    return ControlFlow::Break(Ok(Flow::More));
                };
                sink.on_i32(field, u32::from_le_bytes(bytes))
            }
            FixedKind::I64 => {
                let Some(bytes) = self.pump.grab_fixed::<8>(chunk) else {
                    self.mode = Mode::FixedTail { field, kind };
                    return ControlFlow::Break(Ok(Flow::More));
                };
                sink.on_i64(field, u64::from_le_bytes(bytes))
            }
        };
        self.mode = Mode::Head;
        if self.event(flow).is_break() {
            return ControlFlow::Break(Ok(Flow::Stopped));
        }
        ControlFlow::Continue(())
    }

    fn forward<S: Sink>(
        &mut self,
        chunk: &mut &[u8],
        remaining: NonZeroU32,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        // The take stays in the length class: chunk lengths beyond
        // it clamp to the class top, and `min` then picks the owed
        // count, which fits by construction.
        let take = remaining.get().min(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        let (head, rest) = chunk.split_at(usize_of(take));
        self.pump.off += u64::from(take);
        *chunk = rest;
        self.mode = NonZeroU32::new(remaining.get() - take)
            .map_or(Mode::Head, |remaining| Mode::Forward { remaining });
        if self.event(sink.on_segment(head)).is_break() {
            return ControlFlow::Break(Ok(Flow::Stopped));
        }
        ControlFlow::Continue(())
    }

    fn swallow(
        &mut self,
        chunk: &mut &[u8],
        remaining: NonZeroU32,
    ) -> ControlFlow<Result<Flow, Fault>> {
        let take = remaining.get().min(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        self.pump.off += u64::from(take);
        *chunk = &chunk[usize_of(take)..];
        self.mode = NonZeroU32::new(remaining.get() - take)
            .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
        ControlFlow::Continue(())
    }

    // ─ terminal helpers ─

    #[cold]
    const fn fault(&mut self, at: u64, kind: FaultKind) -> Fault {
        self.pump.terminal = true;
        Fault { at, kind }
    }

    #[cold]
    const fn halt(&mut self, at: u64, kind: FaultKind) -> ControlFlow<Result<Flow, Fault>> {
        ControlFlow::Break(Err(self.fault(at, kind)))
    }

    /// A varint read refusal: builds the fault and its coordinate
    /// here, keeping both off the drive arms' hot paths (the seal
    /// cut names the sealed endpoint; the window and class refusals
    /// name the construct's first byte, still held by the carry).
    #[cold]
    const fn halt_read(
        &mut self,
        stage: Stage,
        cause: ReadFault,
    ) -> ControlFlow<Result<Flow, Fault>> {
        let at = match cause {
            ReadFault::SealCut => self.pump.zone,
            ReadFault::StreamEnd | ReadFault::TooWide | ReadFault::OutOfClass => {
                self.pump.construct_start()
            }
        };
        self.halt(at, FaultKind::Read { stage, cause })
    }

    /// A minimality refusal at a varint stage (CanonicalMinimal
    /// only), built off the hot paths like [`Self::halt_read`]; the
    /// pump's carry still holds the construct, so its first byte
    /// needs no companion datum.
    #[cold]
    const fn halt_padded(&mut self, stage: Stage) -> ControlFlow<Result<Flow, Fault>> {
        self.halt(self.pump.construct_start(), FaultKind::padded(stage))
    }

    /// An event's control flow: Break marks the machine terminal.
    const fn event(&mut self, flow: ControlFlow<()>) -> ControlFlow<()> {
        if flow.is_break() {
            self.pump.terminal = true;
        }
        flow
    }

    /// A disposition question's control flow.
    const fn ask(
        &mut self,
        flow: ControlFlow<(), LenDisposition>,
    ) -> ControlFlow<Result<Flow, Fault>, LenDisposition> {
        match flow {
            ControlFlow::Continue(disposition) => ControlFlow::Continue(disposition),
            ControlFlow::Break(()) => {
                self.pump.terminal = true;
                ControlFlow::Break(Ok(Flow::Stopped))
            }
        }
    }
}

/// A wire-level validator: the parser narrowed to its verdict —
/// no sink (the unit sink descends nothing, which *is* wire-level
/// validation), no `Flow` (a unit sink cannot stop early).
///
/// # Examples
///
/// ```
/// use protobuf_edit::DepthLimit;
/// use protobuf_edit::scan::Standard;
/// use protobuf_edit::scan::grouped::{FaultKind, Validator};
///
/// // An end-group tag with no group open.
/// let mut validator = Validator::new(Standard::Tolerant, DepthLimit::REFERENCE);
/// let fault = validator.feed(&[0x0C]).unwrap_err();
/// assert_eq!(fault.at(), 0);
/// assert!(matches!(fault.kind(), FaultKind::GroupEndOrphan { .. }));
/// ```
#[must_use]
pub struct Validator {
    inner: Parser,
}

impl Validator {
    /// The standard is the `X` in the verdict "legal under X".
    #[inline]
    pub const fn new(standard: Standard, depth: DepthLimit) -> Self {
        Self { inner: Parser::new(standard, depth) }
    }

    /// Absolute consumed offset.
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.inner.offset()
    }

    /// Feeds one chunk.
    ///
    /// # Errors
    ///
    /// The first law violation, as [`Parser::feed`] reports it.
    ///
    /// # Panics
    ///
    /// After a previous fault (the stream is over).
    #[inline]
    #[track_caller]
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), Fault> {
        match self.inner.feed(chunk, &mut ()) {
            Ok(Flow::More) => Ok(()),
            // SAFETY: `impl Sink for ()` overrides nothing, and
            // every default answer continues — a unit sink cannot
            // stop the stream.
            Ok(Flow::Stopped) => unsafe { core::hint::unreachable_unchecked() },
            Err(fault) => Err(fault),
        }
    }

    /// Declares EOF: the verdict.
    ///
    /// # Errors
    ///
    /// The EOF verdict, as [`Parser::finish`] reports it.
    ///
    /// # Panics
    ///
    /// After a previous fault.
    #[inline]
    #[track_caller]
    pub fn finish(self) -> Result<(), Fault> {
        self.inner.finish()
    }
}

#[cfg(test)]
mod tests;
