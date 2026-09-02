//! The groupless transcoder: group codes are outside the language.
//!
//! Without groups the free layer collapses to the root (a non-root
//! ask position
//! always has an entered LEN ancestor — passed payloads stream
//! uncommitted, dropped and replaced ones are swallowed, redirects
//! hand bytes away, none of them ask inside), suppression
//! machinery disappears with the group verbs, and group codes
//! surface as this module's capability refusal,
//! [`WireBreach::GroupCode`]. Everything else — the pump, the mode
//! set, the action vocabularies, the redirect protocol — is shared
//! unchanged.
//!
//! Coordinates: write · stream · online · groupless · Standard (value-level) · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::transcode::Standard;
//! use protobuf_edit::transcode::FreeScalar;
//! use protobuf_edit::transcode::groupless::{Rule, Transcoder};
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Rewrite field 1's value; at the root the width is free, so
//! // the record may grow.
//! struct Bump;
//! impl Rule for Bump {
//!     fn on_varint(
//!         &mut self,
//!         _at: u64,
//!         field: FieldNumber,
//!         value: u64,
//!         _width: u8,
//!     ) -> FreeScalar<'_, u64> {
//!         if field.as_inner() == 1 { FreeScalar::Rewrite(value + 1) } else { FreeScalar::Keep }
//!     }
//! }
//!
//! let mut out = Vec::new();
//! let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
//! t.feed(&[0x08, 0x7F], &mut Bump, &mut |b: &[u8]| out.extend_from_slice(b)).unwrap();
//! t.finish(&mut Bump, &mut |b: &[u8]| out.extend_from_slice(b)).unwrap();
//! // 127 + 1 re-encodes minimally at two bytes.
//! assert_eq!(out, [0x08, 0x80, 0x01]);
//! ```

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::ops::ControlFlow;

use super::{FreeLen, FreeScalar, LenVerb, LockedLen, LockedScalar, Mode, Settled};
use crate::admission::usize_of;
use crate::pump::{FixedKind, Pump, StagedHead, Verdict, standard_of};
use crate::varint::{emit64_minimal, emit64_padded, encoded_len64};
use crate::{DepthLimit, FaultClass, Standard};
use crate::wire::groupless::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3, PayloadLen};

/// The rule program (groupless): one ask per record at its
/// decision point, free and locked faces separated. All defaults
/// keep/pass — `impl Rule for ()` is the bit-identical transcoder.
///
/// Answers must not depend on input chunking; `at` arguments are
/// absolute input offsets of the record head.
pub trait Rule {
    /// A free-layer varint completed (value and source width).
    fn on_varint(
        &mut self,
        at: u64,
        field: FieldNumber,
        value: u64,
        width: u8,
    ) -> FreeScalar<'_, u64> {
        let _ = (at, field, value, width);
        FreeScalar::Keep
    }

    /// A free-layer I32 completed (little-endian bits).
    fn on_i32(&mut self, at: u64, field: FieldNumber, bits: u32) -> FreeScalar<'_, u32> {
        let _ = (at, field, bits);
        FreeScalar::Keep
    }

    /// A free-layer I64 completed.
    fn on_i64(&mut self, at: u64, field: FieldNumber, bits: u64) -> FreeScalar<'_, u64> {
        let _ = (at, field, bits);
        FreeScalar::Keep
    }

    /// A free-layer LEN head completed.
    fn on_len(&mut self, at: u64, field: FieldNumber, len: PayloadLen) -> FreeLen<'_> {
        let _ = (at, field, len);
        FreeLen::Pass
    }

    /// A locked-layer varint completed (equal-length rewrites
    /// only).
    fn on_varint_locked(
        &mut self,
        at: u64,
        field: FieldNumber,
        value: u64,
        width: u8,
    ) -> LockedScalar<u64> {
        let _ = (at, field, value, width);
        LockedScalar::Keep
    }

    /// A locked-layer I32 completed.
    fn on_i32_locked(&mut self, at: u64, field: FieldNumber, bits: u32) -> LockedScalar<u32> {
        let _ = (at, field, bits);
        LockedScalar::Keep
    }

    /// A locked-layer I64 completed.
    fn on_i64_locked(&mut self, at: u64, field: FieldNumber, bits: u64) -> LockedScalar<u64> {
        let _ = (at, field, bits);
        LockedScalar::Keep
    }

    /// A locked-layer LEN head completed.
    fn on_len_locked(&mut self, at: u64, field: FieldNumber, len: PayloadLen) -> LockedLen<'_> {
        let _ = (at, field, len);
        LockedLen::Pass
    }

    /// The active chunk source: answers the pieces of an
    /// [`FreeScalar::InsertSource`], [`FreeLen::InsertSource`], or
    /// [`FreeLen::ReplaceSource`] verdict — called repeatedly,
    /// each answer emitting directly, until the declared account
    /// is exactly consumed; nothing is retained past it. An empty
    /// answer before the account settles is the short-source
    /// breach; a chunk running past the account is the overrun
    /// breach, refused whole (it never reaches the output).
    fn on_source(&mut self) -> &[u8] {
        &[]
    }

    /// A redirected payload fragment arrived; returned bytes emit
    /// in place immediately.
    fn on_fragment<'s>(&'s mut self, fragment: &[u8]) -> &'s [u8] {
        let _ = fragment;
        &[]
    }

    /// The redirected payload is complete: called repeatedly until
    /// it returns empty.
    fn on_flush(&mut self) -> &[u8] {
        &[]
    }

    /// A committed (entered) LEN reached its endpoint.
    fn on_len_exit(&mut self, field: FieldNumber, at: u64) {
        let _ = (field, at);
    }

    /// The stream tail (root layer): called repeatedly until it
    /// returns empty.
    fn on_end(&mut self) -> &[u8] {
        &[]
    }
}

/// The all-default rule: the bit-identical transcoder.
impl Rule for () {}

/// A job refusal: read-side wire law or a rule's length-algebra
/// breach.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// The input broke wire law at `at` (stream coordinates); group
    /// codes arrive as the capability breach.
    Wire {
        /// Absolute input offset.
        at: u64,
        /// The breach, summarized.
        breach: WireBreach,
    },
    /// A rule broke the length algebra it was typed into.
    Rule(RuleFault),
}

// The error carrier's layout budget (u64-alignment padding differs
// by target, so the carrier is a ceiling, not an equality).
const _: () = assert!(core::mem::size_of::<Fault>() <= 24);

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Wire { at, breach } => write!(f, "{breach} at input offset {at}"),
            Self::Rule(fault) => fault.fmt(f),
        }
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire { breach, .. } => Some(breach),
            Self::Rule(fault) => Some(fault),
        }
    }
}

/// The wire breach, summarized by who acts on it.
///
/// The transcode consumer rejects the input either way —
/// byte-precise diagnosis is the scan validator's or the
/// inspector's job. The repair-action classes are
/// [`crate::FaultClass`]'s judgment, answered by
/// [`class`](Self::class).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireBreach {
    /// A varint (tag, length, or value) refused: too wide, out of
    /// class, or cut by a sealed LEN extent.
    Varint,
    /// The tag word is unlawful (field zero or an unassigned code).
    Tag,
    /// A fixed-width or LEN payload exceeds the remaining input,
    /// or the stream ended inside a record: stream EOF cutting any
    /// construct — a varint included — summarizes here, never
    /// under [`Varint`](Self::Varint).
    Truncated,
    /// Container nesting exceeded the configured [`DepthLimit`].
    Depth,
    /// A non-minimal encoding under the strict [`Standard`].
    Minimality,
    /// A group code appeared — outside this dialect's language
    /// (the grouped dialect handles such inputs).
    GroupCode,
    /// The coordinate space (`u64::MAX − 1` bytes) cannot host the
    /// stream. Two producers: a chunk refused whole at feed
    /// admission (`at` is the refused chunk's start, nothing was
    /// read), and a LEN head outside any
    /// seal whose declared payload would end on or past the
    /// reserved sentinel coordinate (`at` is the payload
    /// start; the head was read, the payload cannot follow). Both
    /// depend on the accumulated position, not the bytes.
    OffsetExhausted,
}

impl WireBreach {
    /// The breach's [`FaultClass`] — which repair it asks for.
    /// Policy membership names its configuration datum
    /// ([`Depth`](Self::Depth) is the [`DepthLimit`] bound,
    /// [`Minimality`](Self::Minimality) the declared [`Standard`]).
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Varint | Self::Tag | Self::Truncated => FaultClass::Grammar,
            Self::Depth | Self::Minimality => FaultClass::Policy,
            Self::GroupCode | Self::OffsetExhausted => FaultClass::Capability,
        }
    }
}

impl core::fmt::Display for WireBreach {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Varint => f.write_str("a varint construct refused (window, class, or cut)"),
            Self::Tag => f.write_str("an unlawful tag word"),
            Self::Truncated => f.write_str("a record or payload runs past the available input"),
            Self::Depth => f.write_str("container nesting exceeded the configured bound"),
            Self::Minimality => f.write_str("a non-minimal encoding under the strict standard"),
            Self::GroupCode => f.write_str("a group code outside the groupless language"),
            Self::OffsetExhausted => {
                f.write_str("the addressable 2^64 - 1 bytes cannot host the stream")
            }
        }
    }
}

impl core::error::Error for WireBreach {}

/// A rule breach: where (the record head), and which account
/// broke.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuleFault {
    at: u64,
    kind: RuleFaultKind,
}

// The rule-breach carrier's layout budget (see the wire fault's
// pin for the target-padding caveat).
const _: () = assert!(core::mem::size_of::<RuleFault>() <= 24);

impl RuleFault {
    /// The record head's absolute input offset.
    #[inline]
    #[must_use]
    pub const fn at(self) -> u64 {
        self.at
    }

    /// The broken account.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> RuleFaultKind {
        self.kind
    }
}

impl core::fmt::Display for RuleFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at input offset {}", self.kind, self.at)
    }
}

impl core::error::Error for RuleFault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.kind)
    }
}

/// The rule-breach classes (all five are reachable).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RuleFaultKind {
    /// A locked varint rewrite wider than the source.
    RewriteOverflow {
        /// The record's field.
        field: FieldNumber,
        /// The source width.
        width: u8,
        /// The rewrite's minimal width.
        need: u8,
    },
    /// A locked varint rewrite not exactly the source width
    /// (under `CanonicalMinimal`).
    RewriteWidthMismatch {
        /// The record's field.
        field: FieldNumber,
        /// The source width.
        width: u8,
        /// The rewrite's minimal width.
        need: u8,
    },
    /// A replacement's length differs from the announced length.
    ReplaceLenMismatch {
        /// The record's field.
        field: FieldNumber,
        /// The announced length.
        expect: PayloadLen,
        /// The replacement's length.
        got: u64,
    },
    /// A framed transform emitted beyond the announced length.
    TransformOverflow {
        /// The record's field.
        field: FieldNumber,
    },
    /// A framed transform closed short of the announced length.
    TransformShortfall {
        /// The record's field.
        field: FieldNumber,
        /// Bytes still owed.
        owed: PayloadLen,
    },
    /// A chunk source closed (answered empty) short of its
    /// declared account.
    SourceShort {
        /// The record's field.
        field: FieldNumber,
        /// Bytes still owed.
        owed: PayloadLen,
    },
    /// A chunk source handed a chunk past its declared account —
    /// refused whole, never partially emitted.
    SourceOverrun {
        /// The record's field.
        field: FieldNumber,
    },
}

impl core::fmt::Display for RuleFaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::RewriteOverflow { field, width, need } => write!(
                f,
                "field {}: a locked rewrite needs {need} bytes over a {width}-byte source",
                field.as_inner()
            ),
            Self::RewriteWidthMismatch { field, width, need } => write!(
                f,
                "field {}: a rewrite's minimal width {need} is not the source width {width}",
                field.as_inner()
            ),
            Self::ReplaceLenMismatch { field, expect, got } => write!(
                f,
                "field {}: a {got}-byte replacement against an announced {}",
                field.as_inner(),
                expect.as_inner()
            ),
            Self::TransformOverflow { field } => write!(
                f,
                "field {}: a transform emitted beyond the announced length",
                field.as_inner()
            ),
            Self::TransformShortfall { field, owed } => write!(
                f,
                "field {}: a transform closed owing {} bytes",
                field.as_inner(),
                owed.as_inner()
            ),
            Self::SourceShort { field, owed } => write!(
                f,
                "field {}: a chunk source closed owing {} bytes",
                field.as_inner(),
                owed.as_inner()
            ),
            Self::SourceOverrun { field } => write!(
                f,
                "field {}: a chunk source ran past its declared account",
                field.as_inner()
            ),
        }
    }
}

impl core::error::Error for RuleFaultKind {}

/// One committed LEN: the *shadowed* predecessor endpoint (the
/// live one rides the pump) and the field for the exit event.
struct LenFrame {
    prev_zone: u64,
    field: FieldNumber,
}

/// The one-pass groupless streaming transcoder.
///
/// Terminal states are final; only after `finish` returns `Ok`
/// does the emitted byte sequence carry any promise.
#[must_use]
pub struct Transcoder {
    pump: Pump,
    mode: Mode,
    stack: Vec<LenFrame>,
    depth: DepthLimit,
    stage: StagedHead,
}

impl Transcoder {
    /// All configuration is explicit.
    #[inline]
    pub const fn new(standard: Standard, depth: DepthLimit) -> Self {
        Self {
            pump: Pump::new(standard),
            mode: Mode::Head,
            stack: Vec::new(),
            depth,
            stage: StagedHead::new(),
        }
    }

    /// Absolute consumed input offset.
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.pump.off
    }

    /// The current record's head offset (tag staged, construct in
    /// carry).
    #[allow(
        clippy::as_conversions,
        reason = "the staged and carried widths widen losslessly; const `From` is unavailable"
    )]
    const fn head_at(&self) -> u64 {
        self.pump.off - self.pump.carry.len() as u64 - self.stage.len() as u64
    }

    #[cold]
    const fn wire(&mut self, at: u64, breach: WireBreach) -> Fault {
        self.pump.terminal = true;
        Fault::Wire { at, breach }
    }

    #[cold]
    const fn breach(&mut self, at: u64, kind: RuleFaultKind) -> Fault {
        self.pump.terminal = true;
        Fault::Rule(RuleFault { at, kind })
    }

    #[cold]
    const fn halt_wire(&mut self, at: u64, breach: WireBreach) -> ControlFlow<Result<(), Fault>> {
        ControlFlow::Break(Err(self.wire(at, breach)))
    }

    /// A varint construct the innermost sealed extent cut:
    /// [`WireBreach::Varint`] at the sealed endpoint (stream EOF
    /// inside a construct is `finish`'s judgment and summarizes as
    /// [`WireBreach::Truncated`] there).
    #[cold]
    const fn halt_seal_cut(&mut self) -> ControlFlow<Result<(), Fault>> {
        self.halt_wire(self.pump.zone, WireBreach::Varint)
    }

    /// A varint window or class refusal: [`WireBreach::Varint`] at
    /// the construct's first byte, still held by the carry.
    #[cold]
    const fn halt_refused(&mut self) -> ControlFlow<Result<(), Fault>> {
        self.halt_wire(self.pump.construct_start(), WireBreach::Varint)
    }

    /// A minimality refusal (CanonicalMinimal only):
    /// [`WireBreach::Minimality`] at the construct's first byte,
    /// still held by the carry.
    #[cold]
    const fn halt_padded(&mut self) -> ControlFlow<Result<(), Fault>> {
        self.halt_wire(self.pump.construct_start(), WireBreach::Minimality)
    }

    /// A structural refusal of the completed head word: the fault
    /// coordinate (the tag's first byte, still in the carry) is
    /// spent here, off the classification's hot path.
    #[cold]
    const fn halt_head(&mut self, breach: WireBreach) -> ControlFlow<Result<(), Fault>> {
        self.halt_wire(self.pump.construct_start(), breach)
    }

    /// Feeds one chunk. Emissions land in `out` as verdicts
    /// settle; `Ok` means the chunk is exhausted and the residue
    /// is carried.
    ///
    /// # Errors
    ///
    /// The first law violation ends the job: an input wire breach
    /// as [`Fault::Wire`] (summarized, at its absolute input
    /// coordinate), a rule's length-algebra breach as
    /// [`Fault::Rule`] (at the record head).
    /// [`WireBreach::OffsetExhausted`] carries the coordinate-space
    /// refusals: a chunk refused whole at admission (before any of
    /// its bytes are read), and an unsealed LEN head whose declared
    /// payload the space cannot host. Faults latch — the machine
    /// is terminal afterwards.
    ///
    /// # Panics
    ///
    /// After a previous fault, and after a feed whose rule or
    /// output callback unwound (the machine latches terminal
    /// across callbacks, so a caught panic cannot resume a
    /// half-stepped job). The job is over.
    ///
    /// # Examples
    ///
    /// A rule that breaks its length account faults at the record
    /// head:
    ///
    /// ```
    /// use protobuf_edit::transcode::Standard;
    /// use protobuf_edit::transcode::FreeLen;
    /// use protobuf_edit::transcode::groupless::{Fault, Rule, RuleFaultKind, Transcoder};
    /// use protobuf_edit::{DepthLimit, FieldNumber, PayloadLen};
    ///
    /// struct ShortReplace;
    /// impl Rule for ShortReplace {
    ///     fn on_len(&mut self, _at: u64, _field: FieldNumber, _len: PayloadLen) -> FreeLen<'_> {
    ///         FreeLen::Replace(&[0xAA]) // one byte against an announced two
    ///     }
    /// }
    ///
    /// // LEN f2 "hi" (two payload bytes announced).
    /// let msg = [0x12, 0x02, 0x68, 0x69];
    /// let mut t = Transcoder::new(Standard::Tolerant, DepthLimit::REFERENCE);
    /// let fault = t.feed(&msg, &mut ShortReplace, &mut |_: &[u8]| {}).unwrap_err();
    /// let Fault::Rule(rule_fault) = fault else { unreachable!() };
    /// assert_eq!(rule_fault.at(), 0);
    /// assert!(matches!(rule_fault.kind(), RuleFaultKind::ReplaceLenMismatch { .. }));
    /// ```
    #[track_caller]
    pub fn feed<R: Rule, O: FnMut(&[u8])>(
        &mut self,
        chunk: &[u8],
        rule: &mut R,
        out: &mut O,
    ) -> Result<(), Fault> {
        assert!(!self.pump.terminal, "transcoder already terminal");
        // Coordinate admission ([`Pump::admits`]): the gate keeps
        // `off` strictly below the root sentinel through every
        // consuming path of this feed. Judged in this prologue so
        // the drive loop's codegen owes the gate nothing.
        if core::hint::unlikely(!self.pump.admits(chunk)) {
            return Err(self.wire(self.pump.off, WireBreach::OffsetExhausted));
        }
        // Poison across the rule/output callbacks: latch terminal
        // before driving, so a callback that unwinds leaves the
        // machine terminal (every later feed hits the entry assert)
        // rather than resumable mid-construct — a resumed
        // `FixedTail` could re-enter collection against a popped
        // zone and reach the unreachable `Collect::Cut`. A normal
        // return restores the latch to the drive's own verdict.
        // The declared standard picks the drive instance once: the
        // per-record width judgment is a const inside the engine.
        self.pump.terminal = true;
        let outcome = match self.pump.standard {
            Standard::Tolerant => self.drive::<R, O, false>(chunk, rule, out),
            Standard::CanonicalMinimal => self.drive::<R, O, true>(chunk, rule, out),
        };
        self.pump.terminal = outcome.is_err();
        outcome
    }

    /// The feed's drive engine, behind the admission prologue, one
    /// instance per acceptance standard: the width judgment inside
    /// every word settlement and the locked-rewrite width decision
    /// read the instance's constant, and the second monomorphic
    /// body is the selected profile's price.
    #[inline(never)]
    fn drive<R: Rule, O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        chunk: &[u8],
        rule: &mut R,
        out: &mut O,
    ) -> Result<(), Fault> {
        // The engine's const standard and the pump's declared one
        // are the same fact in two representations; the call sites
        // keep them aligned, and this seam pins that.
        debug_assert!(standard_of(MINIMAL) == self.pump.standard);
        let mut chunk = chunk;
        loop {
            // Cascade: resolve every endpoint at the cursor before
            // any construct starts. Uniform LEN frames: the
            // cascade cannot fault.
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
                match self.stack.pop() {
                    Some(LenFrame { prev_zone, field }) => {
                        self.pump.zone = prev_zone;
                        rule.on_len_exit(field, self.pump.off);
                    }
                    // SAFETY: an empty stack leaves the root zone,
                    // `u64::MAX`, and the feed admission gate keeps
                    // `off < u64::MAX` through every consuming path
                    // ([`Pump::admits`]) — the cursor can never
                    // equal the root sentinel.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
            if chunk.is_empty() {
                return Ok(());
            }
            let flow = match self.mode {
                Mode::Head => self.head::<R, O, MINIMAL>(&mut chunk, rule, out),
                Mode::VarintValue { field } => {
                    self.varint_value::<R, O, MINIMAL>(&mut chunk, field, rule, out)
                }
                Mode::LenWord { field } => {
                    self.len_word::<R, O, MINIMAL>(&mut chunk, field, rule, out)
                }
                Mode::FixedTail { field, kind } => {
                    self.fixed_tail(&mut chunk, field, kind, rule, out)
                }
                Mode::Forward { remaining } => self.forward(&mut chunk, remaining, out),
                Mode::Swallow { remaining } => self.swallow(&mut chunk, remaining),
                Mode::Redirect { remaining, owed, field, start } => {
                    self.redirect(&mut chunk, remaining, owed, field, start, rule, out)
                }
            };
            match flow {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(result) => return result,
            }
        }
    }

    /// Declares EOF and consumes the machine: the final verdict,
    /// then the tail-injection ask (`on_end`, root layer).
    ///
    /// # Errors
    ///
    /// EOF inside a construct or a counted payload, or a LEN still
    /// open, is the matching breach summarized into
    /// [`Fault::Wire`] at the final offset. No tail ask runs on a
    /// faulted end.
    ///
    /// # Panics
    ///
    /// After a previous fault, and after a feed whose rule or
    /// output callback unwound.
    #[track_caller]
    pub fn finish<R: Rule, O: FnMut(&[u8])>(
        mut self,
        rule: &mut R,
        out: &mut O,
    ) -> Result<(), Fault> {
        assert!(!self.pump.terminal, "transcoder already terminal");
        debug_assert!(
            self.pump.off != self.pump.zone
                || !(matches!(self.mode, Mode::Head) && self.pump.carry.is_empty()),
            "feed resolves every endpoint it does not leave under a suspended word"
        );
        let at = self.pump.off;
        // Every mid-construct suspension — a tag prefix in the
        // carry, a word in flight, a fixed or counted payload owed
        // — and every still-open LEN summarize alike: the stream
        // ended inside a record, [`WireBreach::Truncated`] at the
        // final offset.
        match self.mode {
            Mode::Head if self.pump.carry.is_empty() => {}
            Mode::Head
            | Mode::VarintValue { .. }
            | Mode::LenWord { .. }
            | Mode::FixedTail { .. }
            | Mode::Forward { .. }
            | Mode::Swallow { .. }
            | Mode::Redirect { .. } => {
                return Err(self.wire(at, WireBreach::Truncated));
            }
        }
        if self.stack.last().is_some() {
            return Err(self.wire(at, WireBreach::Truncated));
        }
        loop {
            let bytes = rule.on_end();
            if bytes.is_empty() {
                return Ok(());
            }
            out(bytes);
        }
    }

    // ─ the drive arms (each returns Break to end the feed) ─

    /// Classifies one head and hands the record to its word
    /// handler: the whole record completes when the chunk allows,
    /// and the handlers write a suspension mode only when it does
    /// not — the mode is resumption state, not a per-record
    /// itinerary.
    fn head<R: Rule, O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        rule: &mut R,
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let word = match self.pump.step_tag_held(chunk, standard_of(MINIMAL)) {
            Verdict::Done(word) => word,
            Verdict::More => return ControlFlow::Break(Ok(())),
            Verdict::Cut => return self.halt_seal_cut(),
            Verdict::TooWide | Verdict::OutOfClass => return self.halt_refused(),
            Verdict::NonMinimal => return self.halt_padded(),
        };
        let low3 = Low3::from_word(word);
        let Some(field) = FieldNumber::from_word(word) else {
            return self.halt_head(WireBreach::Tag);
        };
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                self.stage_head();
                self.varint_value::<R, O, MINIMAL>(chunk, field, rule, out)
            }
            TagClass::Record(kind @ (RecordKind::I32 | RecordKind::I64)) => {
                let fixed =
                    if matches!(kind, RecordKind::I64) { FixedKind::I64 } else { FixedKind::I32 };
                // Admit the width against the zone here, so the
                // kernel's Cut is unreachable in collection.
                if self.pump.zone - self.pump.off < u64::from(fixed.need()) {
                    return self.halt_wire(self.pump.off, WireBreach::Truncated);
                }
                self.stage_head();
                self.fixed_tail(chunk, field, fixed, rule, out)
            }
            TagClass::Record(RecordKind::Len) => {
                self.stage_head();
                self.len_word::<R, O, MINIMAL>(chunk, field, rule, out)
            }
            TagClass::GroupCode => self.halt_head(WireBreach::GroupCode),
            TagClass::Unassigned => self.halt_head(WireBreach::Tag),
        }
    }

    /// Stages the completed head for the record's verdict and
    /// frees the carry for the value construct.
    const fn stage_head(&mut self) {
        // SAFETY: the carry holds the tag construct `step_tag`
        // just completed — the five-byte window is its cap.
        unsafe { self.stage.capture(&self.pump.carry) };
        self.pump.carry.clear();
    }

    #[inline(always)]
    fn varint_value<R: Rule, O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        rule: &mut R,
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let head = self.head_at();
        let value = match self.pump.step_value_held(chunk, standard_of(MINIMAL)) {
            Verdict::Done(value) => value,
            Verdict::More => {
                self.mode = Mode::VarintValue { field };
                return ControlFlow::Break(Ok(()));
            }
            Verdict::Cut => return self.halt_seal_cut(),
            Verdict::TooWide | Verdict::OutOfClass => return self.halt_refused(),
            Verdict::NonMinimal => return self.halt_padded(),
        };
        // The carry holds the construct until the clear below, so
        // its length is the source width.
        let width = self.pump.carry.len();
        if self.pump.locked() {
            match rule.on_varint_locked(head, field, value, width) {
                LockedScalar::Keep => {
                    out(self.stage.bytes());
                    out(self.pump.carry.bytes());
                }
                LockedScalar::Rewrite(new) => {
                    if let Err(fault) =
                        self.emit_equal_width::<O, MINIMAL>(new, width, field, head, out)
                    {
                        return ControlFlow::Break(Err(fault));
                    }
                }
            }
        } else {
            loop {
                match rule.on_varint(head, field, value, width) {
                    FreeScalar::Keep => {
                        out(self.stage.bytes());
                        out(self.pump.carry.bytes());
                        break;
                    }
                    FreeScalar::Rewrite(new) => {
                        out(self.stage.bytes());
                        let mut buf = [MaybeUninit::uninit(); 10];
                        out(emit64_minimal(new, &mut buf));
                        break;
                    }
                    FreeScalar::Drop => break,
                    FreeScalar::Insert(bytes) => out(bytes),
                    FreeScalar::InsertSource(need) => {
                        if let Err(fault) = self.pump_source(rule, out, need, field, head) {
                            return ControlFlow::Break(Err(fault));
                        }
                    }
                }
            }
        }
        self.pump.carry.clear();
        self.mode = Mode::Head;
        ControlFlow::Continue(())
    }

    /// Emits a locked varint rewrite at the source width: padded
    /// under `Tolerant` (must fit), exact under `CanonicalMinimal`
    /// (so the output re-ingests under the declared standard).
    #[allow(clippy::as_conversions, reason = "encoded widths land in 1..=10")]
    fn emit_equal_width<O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        value: u64,
        width: u8,
        field: FieldNumber,
        head: u64,
        out: &mut O,
    ) -> Result<(), Fault> {
        let need = encoded_len64(value);
        if MINIMAL {
            if need != u32::from(width) {
                let kind = RuleFaultKind::RewriteWidthMismatch { field, width, need: need as u8 };
                return Err(self.breach(head, kind));
            }
        } else if need > u32::from(width) {
            let kind = RuleFaultKind::RewriteOverflow { field, width, need: need as u8 };
            return Err(self.breach(head, kind));
        }
        out(self.stage.bytes());
        let mut buf = [MaybeUninit::uninit(); 10];
        // SAFETY: `width` is a completed value construct's carried
        // width — at most ten by the value window — and the
        // standard match above admitted `encoded_len64(value)`
        // within it.
        out(unsafe { emit64_padded(value, width, &mut buf) });
        Ok(())
    }

    #[inline(always)]
    fn fixed_tail<R: Rule, O: FnMut(&[u8])>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        kind: FixedKind,
        rule: &mut R,
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let head = self.head_at();
        match kind {
            FixedKind::I32 => {
                let Some(bytes) = self.pump.grab_fixed::<4>(chunk) else {
                    self.mode = Mode::FixedTail { field, kind };
                    return ControlFlow::Break(Ok(()));
                };
                if self.pump.locked() {
                    match rule.on_i32_locked(head, field, u32::from_le_bytes(bytes)) {
                        LockedScalar::Keep => {
                            out(self.stage.bytes());
                            out(&bytes);
                        }
                        LockedScalar::Rewrite(bits) => {
                            out(self.stage.bytes());
                            out(&bits.to_le_bytes());
                        }
                    }
                } else {
                    loop {
                        match rule.on_i32(head, field, u32::from_le_bytes(bytes)) {
                            FreeScalar::Keep => {
                                out(self.stage.bytes());
                                out(&bytes);
                                break;
                            }
                            FreeScalar::Rewrite(bits) => {
                                out(self.stage.bytes());
                                out(&bits.to_le_bytes());
                                break;
                            }
                            FreeScalar::Drop => break,
                            FreeScalar::Insert(injected) => out(injected),
                            FreeScalar::InsertSource(need) => {
                                if let Err(fault) = self.pump_source(rule, out, need, field, head) {
                                    return ControlFlow::Break(Err(fault));
                                }
                            }
                        }
                    }
                }
            }
            FixedKind::I64 => {
                let Some(bytes) = self.pump.grab_fixed::<8>(chunk) else {
                    self.mode = Mode::FixedTail { field, kind };
                    return ControlFlow::Break(Ok(()));
                };
                if self.pump.locked() {
                    match rule.on_i64_locked(head, field, u64::from_le_bytes(bytes)) {
                        LockedScalar::Keep => {
                            out(self.stage.bytes());
                            out(&bytes);
                        }
                        LockedScalar::Rewrite(bits) => {
                            out(self.stage.bytes());
                            out(&bits.to_le_bytes());
                        }
                    }
                } else {
                    loop {
                        match rule.on_i64(head, field, u64::from_le_bytes(bytes)) {
                            FreeScalar::Keep => {
                                out(self.stage.bytes());
                                out(&bytes);
                                break;
                            }
                            FreeScalar::Rewrite(bits) => {
                                out(self.stage.bytes());
                                out(&bits.to_le_bytes());
                                break;
                            }
                            FreeScalar::Drop => break,
                            FreeScalar::Insert(injected) => out(injected),
                            FreeScalar::InsertSource(need) => {
                                if let Err(fault) = self.pump_source(rule, out, need, field, head) {
                                    return ControlFlow::Break(Err(fault));
                                }
                            }
                        }
                    }
                }
            }
        }
        self.mode = Mode::Head;
        ControlFlow::Continue(())
    }

    #[inline(always)]
    fn len_word<R: Rule, O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        rule: &mut R,
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let head = self.head_at();
        let len = match self.pump.step_len_held(chunk, standard_of(MINIMAL)) {
            Verdict::Done(len) => len,
            Verdict::More => {
                self.mode = Mode::LenWord { field };
                return ControlFlow::Break(Ok(()));
            }
            Verdict::Cut => return self.halt_seal_cut(),
            Verdict::TooWide | Verdict::OutOfClass => return self.halt_refused(),
            Verdict::NonMinimal => return self.halt_padded(),
        };
        // LEN admission: the one widening seam (u64 + u32). The
        // refusals split by what has to change — a finite zone
        // pierced (or a sum past u64 under one) is grammar; at the
        // root, an end needing the sentinel coordinate (or beyond)
        // is beyond this machine's space — capability, summarized
        // with the feed gate's exhaustion.
        let end = match self.pump.off.checked_add(u64::from(len.as_inner())) {
            Some(end) if end <= self.pump.zone && end != u64::MAX => end,
            _ if self.pump.locked() => {
                return self.halt_wire(self.pump.off, WireBreach::Truncated);
            }
            _ => {
                return self.halt_wire(self.pump.off, WireBreach::OffsetExhausted);
            }
        };
        let verb = if self.pump.locked() {
            rule.on_len_locked(head, field, len).into_verb()
        } else {
            loop {
                match rule.on_len(head, field, len) {
                    FreeLen::Pass => break LenVerb::Pass,
                    FreeLen::Commit => break LenVerb::Commit,
                    FreeLen::Replace(bytes) => break LenVerb::Replace(bytes),
                    FreeLen::ReplaceSource => break LenVerb::ReplaceSource,
                    FreeLen::Transform => break LenVerb::Transform,
                    FreeLen::Divert => break LenVerb::Divert,
                    FreeLen::Drop => break LenVerb::Drop,
                    FreeLen::Insert(bytes) => out(bytes),
                    FreeLen::InsertSource(need) => {
                        if let Err(fault) = self.pump_source(rule, out, need, field, head) {
                            return ControlFlow::Break(Err(fault));
                        }
                    }
                }
            }
        };
        let settled = match self.settle_len(verb, field, len, end, head, out) {
            Ok(settled) => settled,
            Err(fault) => return ControlFlow::Break(Err(fault)),
        };
        self.pump.carry.clear();
        match settled {
            Settled::Done => {}
            Settled::FlushRedirect { owed } => {
                if let Err(fault) = self.flush_redirect(rule, out, owed, field, head) {
                    return ControlFlow::Break(Err(fault));
                }
            }
            Settled::PumpSource => {
                if let Err(fault) = self.pump_source(rule, out, len, field, head) {
                    return ControlFlow::Break(Err(fault));
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Settles a LEN verdict: emissions, frames, and the counting
    /// mode. A zero-length redirect completes here but its flush
    /// ask must wait for the verb's borrow to end — the caller
    /// runs it off the returned continuation.
    #[allow(
        clippy::as_conversions,
        reason = "replacement lengths widen losslessly into the account domain \
                  on the crate's 32/64-bit targets"
    )]
    fn settle_len<O: FnMut(&[u8])>(
        &mut self,
        verb: LenVerb<'_>,
        field: FieldNumber,
        len: PayloadLen,
        end: u64,
        head: u64,
        out: &mut O,
    ) -> Result<Settled, Fault> {
        match verb {
            LenVerb::Pass => {
                out(self.stage.bytes());
                out(self.pump.carry.bytes());
                self.mode = NonZeroU32::new(len.as_inner())
                    .map_or(Mode::Head, |remaining| Mode::Forward { remaining });
            }
            LenVerb::Commit => {
                if self.stack.len() >= usize::from(self.depth.as_inner()) {
                    return Err(self.wire(self.pump.off, WireBreach::Depth));
                }
                out(self.stage.bytes());
                out(self.pump.carry.bytes());
                self.stack.push(LenFrame { prev_zone: self.pump.zone, field });
                self.pump.zone = end;
                self.mode = Mode::Head;
            }
            LenVerb::Replace(bytes) => {
                if bytes.len() as u64 != u64::from(len.as_inner()) {
                    let kind = RuleFaultKind::ReplaceLenMismatch {
                        field,
                        expect: len,
                        got: bytes.len() as u64,
                    };
                    return Err(self.breach(head, kind));
                }
                out(self.stage.bytes());
                out(self.pump.carry.bytes());
                out(bytes);
                self.mode = NonZeroU32::new(len.as_inner())
                    .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
            }
            LenVerb::ReplaceSource => {
                // Tag and prefix ride verbatim; the announced
                // length is the pull's account, run off the
                // continuation once the verb's borrow ends.
                out(self.stage.bytes());
                out(self.pump.carry.bytes());
                self.mode = NonZeroU32::new(len.as_inner())
                    .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
                return Ok(Settled::PumpSource);
            }
            LenVerb::Transform => {
                out(self.stage.bytes());
                out(self.pump.carry.bytes());
                match NonZeroU32::new(len.as_inner()) {
                    Some(remaining) => {
                        self.mode =
                            Mode::Redirect { remaining, owed: Some(len), field, start: head };
                    }
                    None => {
                        self.mode = Mode::Head;
                        return Ok(Settled::FlushRedirect { owed: Some(len) });
                    }
                }
            }
            LenVerb::Divert => match NonZeroU32::new(len.as_inner()) {
                Some(remaining) => {
                    self.mode = Mode::Redirect { remaining, owed: None, field, start: head };
                }
                None => {
                    self.mode = Mode::Head;
                    return Ok(Settled::FlushRedirect { owed: None });
                }
            },
            LenVerb::Drop => {
                self.mode = NonZeroU32::new(len.as_inner())
                    .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
            }
        }
        Ok(Settled::Done)
    }

    fn forward<O: FnMut(&[u8])>(
        &mut self,
        chunk: &mut &[u8],
        remaining: NonZeroU32,
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let take = remaining.get().min(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        let (fragment, rest) = chunk.split_at(usize_of(take));
        self.pump.off += u64::from(take);
        *chunk = rest;
        out(fragment);
        self.mode = NonZeroU32::new(remaining.get() - take)
            .map_or(Mode::Head, |remaining| Mode::Forward { remaining });
        ControlFlow::Continue(())
    }

    fn swallow(
        &mut self,
        chunk: &mut &[u8],
        remaining: NonZeroU32,
    ) -> ControlFlow<Result<(), Fault>> {
        let take = remaining.get().min(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        self.pump.off += u64::from(take);
        *chunk = &chunk[usize_of(take)..];
        self.mode = NonZeroU32::new(remaining.get() - take)
            .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
        ControlFlow::Continue(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the four scalars are the Redirect mode's payload, destructured at dispatch; \
                  a carrier struct would be rebuilt and re-destructured immediately"
    )]
    fn redirect<R: Rule, O: FnMut(&[u8])>(
        &mut self,
        chunk: &mut &[u8],
        remaining: NonZeroU32,
        owed: Option<PayloadLen>,
        field: FieldNumber,
        start: u64,
        rule: &mut R,
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let take = remaining.get().min(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        let (fragment, rest) = chunk.split_at(usize_of(take));
        self.pump.off += u64::from(take);
        *chunk = rest;
        let returned = rule.on_fragment(fragment);
        let mut owed = owed;
        if !returned.is_empty() {
            owed = match self.account(owed, returned.len(), field, start) {
                Ok(owed) => owed,
                Err(fault) => return ControlFlow::Break(Err(fault)),
            };
            out(returned);
        }
        match NonZeroU32::new(remaining.get() - take) {
            Some(remaining) => {
                self.mode = Mode::Redirect { remaining, owed, field, start };
                ControlFlow::Continue(())
            }
            None => {
                self.mode = Mode::Head;
                match self.flush_redirect(rule, out, owed, field, start) {
                    Ok(()) => ControlFlow::Continue(()),
                    Err(fault) => ControlFlow::Break(Err(fault)),
                }
            }
        }
    }

    /// The redirect's completion ask: `on_flush` until empty, each
    /// return accounted (Transform) and emitted in place, then the
    /// shortfall judgment.
    fn flush_redirect<R: Rule, O: FnMut(&[u8])>(
        &mut self,
        rule: &mut R,
        out: &mut O,
        mut owed: Option<PayloadLen>,
        field: FieldNumber,
        start: u64,
    ) -> Result<(), Fault> {
        loop {
            let bytes = rule.on_flush();
            if bytes.is_empty() {
                break;
            }
            owed = self.account(owed, bytes.len(), field, start)?;
            out(bytes);
        }
        if let Some(owed) = owed
            && owed.as_inner() != 0
        {
            return Err(self.breach(start, RuleFaultKind::TransformShortfall { field, owed }));
        }
        Ok(())
    }

    /// Debits a rule emission against the transform account
    /// (`None` = divert, no account). Overflow is judged before
    /// the bytes emit — the earliest determined point.
    #[allow(
        clippy::as_conversions,
        reason = "an emission count just bounded by the account narrows losslessly; \
                  usize widens losslessly into u64 on the crate's 32/64-bit targets"
    )]
    fn account(
        &mut self,
        owed: Option<PayloadLen>,
        emitted: usize,
        field: FieldNumber,
        start: u64,
    ) -> Result<Option<PayloadLen>, Fault> {
        let Some(left) = owed else { return Ok(None) };
        if emitted as u64 > u64::from(left.as_inner()) {
            return Err(self.breach(start, RuleFaultKind::TransformOverflow { field }));
        }
        // SAFETY: `emitted ≤ left` was just judged, so the debit
        // stays inside the length class the account started in.
        Ok(Some(unsafe { PayloadLen::new_unchecked(left.as_inner() - emitted as u32) }))
    }

    /// Pulls a declared-length chunk source and emits it directly:
    /// [`Rule::on_source`] answers pieces until the account
    /// settles exactly. An empty answer before settlement is the
    /// short-source breach; a chunk past the account is the
    /// overrun breach, refused whole (it never reaches the
    /// output). Nothing is retained after the pull.
    #[allow(
        clippy::as_conversions,
        reason = "chunk lengths widen losslessly into the account domain \
                  on the crate's 32/64-bit targets"
    )]
    fn pump_source<R: Rule, O: FnMut(&[u8])>(
        &mut self,
        rule: &mut R,
        out: &mut O,
        len: PayloadLen,
        field: FieldNumber,
        head: u64,
    ) -> Result<(), Fault> {
        let mut owed = len;
        while owed.as_inner() != 0 {
            let bytes = rule.on_source();
            if bytes.is_empty() {
                return Err(self.breach(head, RuleFaultKind::SourceShort { field, owed }));
            }
            if bytes.len() as u64 > u64::from(owed.as_inner()) {
                return Err(self.breach(head, RuleFaultKind::SourceOverrun { field }));
            }
            // SAFETY: `bytes.len() ≤ owed` was just judged, so the
            // debit stays inside the length class the account
            // started in.
            owed = unsafe { PayloadLen::new_unchecked(owed.as_inner() - bytes.len() as u32) };
            out(bytes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
