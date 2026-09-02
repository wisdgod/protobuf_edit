//! The groupless streaming rewirer: the four-code wire language,
//! group codes refused as a capability judgment.
//!
//! [`Actions::over`] binds one [`Action`] per program path and
//! judges the bindings once (const-capable); [`Rewirer`] then
//! drives chunked bytes through the shared pump, probing the
//! matcher once per record and emitting through the caller's
//! `FnMut(&[u8])`. In this dialect every crossed container is an
//! entered LEN, so the free layer is exactly the root:
//! [`Actions::over`] refuses variable-length actions on
//! `Field`-prefixed paths outright (no match could ever be free),
//! and a wildcard path's variable-length action that matches
//! after descending faults at the record as
//! [`RuleFaultKind::Cascade`].
//!
//! Coordinates: write · stream · static · groupless · Standard (value-level) · commit-only.
//!
//! # Examples
//!
//! Equal-length rewiring under the strict standard re-ingests
//! strictly:
//!
//! ```
//! use protobuf_edit::path::{Program, Segment};
//! use protobuf_edit::rewire::groupless::{Actions, Rewirer};
//! use protobuf_edit::rewire::{Action, Value};
//! use protobuf_edit::rewire::Standard;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let path: [Segment<'_>; 1] = [Segment::Field(f1)];
//! let paths: [&[Segment<'_>]; 1] = [&path];
//! let program = Program::over(&paths).unwrap();
//! let table = [Action::Rewrite(Value::Varint(5))];
//! let actions = Actions::over(&program, &table).unwrap();
//!
//! let msg = [0x08, 0x96, 0x01, 0x10, 0x02]; // varint f1=150 · varint f2=2
//! let mut out = Vec::new();
//! let mut sink = |bytes: &[u8]| out.extend_from_slice(bytes);
//! let mut rw = Rewirer::new(&actions, Standard::CanonicalMinimal, DepthLimit::REFERENCE);
//! rw.feed(&msg, &mut sink).unwrap();
//! rw.finish().unwrap();
//! assert_eq!(out, [0x08, 0x05, 0x10, 0x02]);
//! ```

use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::num::NonZeroU32;
use core::ops::ControlFlow;

use super::{Action, ActionError, Mode, Value};
use crate::admission::usize_of;
use crate::path::{Hits, Matcher, Program};
use crate::pump::{FixedKind, Pump, StagedHead, Verdict, standard_of};
use crate::varint::{emit64_minimal, emit64_padded, encoded_len64};
use crate::wire::groupless::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, FaultClass, Standard};

/// The admitted (path, action) bindings: the program and its
/// parallel action table, judged together so an unsound pairing is
/// unrepresentable — the rewirer takes only this proof-carrying
/// value.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct Actions<'r> {
    program: Program<'r>,
    actions: &'r [Action<'r>],
}

impl<'r> Actions<'r> {
    /// Binds `actions[i]` to the program's path `i` and judges
    /// every binding (const-capable: a static table pays its
    /// judgment at compile time).
    ///
    /// # Errors
    ///
    /// [`ActionError::CountMismatch`] when the table and the
    /// program disagree on the path count;
    /// [`ActionError::CascadeUnsound`] for a variable-length
    /// action ([`Action::Delete`] / [`Action::Insert`]) on a
    /// `Field`-prefixed path — in this dialect every such match
    /// sits under an entered LEN, so the action could never
    /// lawfully fire; [`ActionError::OversizeReplacement`] for a
    /// [`Value::Len`] replacement no announced length could equal.
    pub const fn over(
        program: &Program<'r>,
        actions: &'r [Action<'r>],
    ) -> Result<Self, ActionError> {
        if let Err(refusal) = super::judge_bindings(program, actions) {
            return Err(refusal);
        }
        if let Err(refusal) = super::judge_groupless_cascade(program, actions) {
            return Err(refusal);
        }
        Ok(Self { program: *program, actions })
    }
}

/// A job refusal: read-side wire law or an action's breach at its
/// match.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// The input broke wire law at `at` (stream coordinates);
    /// group codes arrive as their own breach kind.
    Wire {
        /// Absolute input offset.
        at: u64,
        /// The breach, summarized.
        breach: WireBreach,
    },
    /// An action broke its algebra at a matched record.
    Rule(RuleFault),
}

// The error carrier's layout budget (u64-alignment padding
// differs by target, so the carrier is a ceiling).
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
/// The rewire consumer rejects the input either way — byte-precise
/// diagnosis is the scan validator's or the inspector's job. The
/// repair-action classes are [`crate::FaultClass`]'s judgment,
/// answered by [`class`](Self::class).
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireBreach {
    /// A varint (tag, length, or value) refused: too wide, out of
    /// class, or cut by the input end.
    Varint,
    /// The tag word is unlawful (field zero or an unassigned code).
    Tag,
    /// A fixed-width or LEN payload exceeds the remaining input,
    /// or the stream ended inside a record.
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
    /// read), and a LEN head outside any seal whose declared
    /// payload would end on or past the reserved sentinel
    /// coordinate (`at` is the payload start; the head was read,
    /// the payload cannot follow). Both depend on the accumulated
    /// position, not the bytes.
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

/// An action breach: where (the record head), and which account
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

/// The action-breach classes. Paths are quoted by index into the
/// authored program — the binding is the fix's owner.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RuleFaultKind {
    /// Two paths target one record: their actions are
    /// indeterminate, so the double target is quoted, not
    /// enumerated.
    Conflict {
        /// The first targeting path.
        first: u16,
        /// The second targeting path.
        second: u16,
    },
    /// The bound value's kind does not match the record's kind —
    /// kinds are document facts the authoring could not see, so
    /// the mismatch is judged at the match.
    KindMismatch {
        /// The offending path.
        path: u16,
    },
    /// A variable-length action matched under an entered LEN (a
    /// wildcard that descended): the authoring declared a free
    /// match and the document put it under a sealed length —
    /// the declaration is proven wrong at this record.
    Cascade {
        /// The offending path.
        path: u16,
    },
    /// A varint rewrite under an entered LEN needs more bytes than
    /// the source width holds.
    RewriteOverflow {
        /// The offending path.
        path: u16,
        /// The source width.
        width: u8,
        /// The rewrite's minimal width.
        need: u8,
    },
    /// A varint rewrite under an entered LEN, not exactly the
    /// source width (under `CanonicalMinimal`).
    RewriteWidthMismatch {
        /// The offending path.
        path: u16,
        /// The source width.
        width: u8,
        /// The rewrite's minimal width.
        need: u8,
    },
    /// A LEN replacement's length differs from the announced
    /// length.
    ReplaceLenMismatch {
        /// The offending path.
        path: u16,
        /// The announced length.
        expect: PayloadLen,
        /// The replacement's length.
        got: u64,
    },
}

impl core::fmt::Display for RuleFaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Conflict { first, second } => {
                write!(f, "paths {first} and {second} both target one record")
            }
            Self::KindMismatch { path } => {
                write!(f, "path {path}: the bound value's kind is not the record's kind")
            }
            Self::Cascade { path } => {
                write!(f, "path {path}: a variable-length action matched under an entered LEN")
            }
            Self::RewriteOverflow { path, width, need } => write!(
                f,
                "path {path}: a locked rewrite needs {need} bytes over a {width}-byte source"
            ),
            Self::RewriteWidthMismatch { path, width, need } => write!(
                f,
                "path {path}: a rewrite's minimal width {need} is not the source width {width}"
            ),
            Self::ReplaceLenMismatch { path, expect, got } => write!(
                f,
                "path {path}: a {got}-byte replacement against an announced {}",
                expect.as_inner()
            ),
        }
    }
}

impl core::error::Error for RuleFaultKind {}

/// One committed LEN: the *shadowed* predecessor endpoint (the
/// live one rides the pump).
struct LenFrame {
    prev_zone: u64,
}

/// The one-pass groupless streaming rewirer.
///
/// Terminal states are final; only after `finish` returns `Ok`
/// does the emitted byte sequence carry any promise.
#[must_use]
pub struct Rewirer<'r> {
    pump: Pump,
    mode: Mode,
    stack: Vec<LenFrame>,
    depth: DepthLimit,
    matcher: Matcher<'r, Program<'r>>,
    actions: &'r [Action<'r>],
    stage: StagedHead,
}

impl<'r> Rewirer<'r> {
    /// All configuration is explicit: the admitted bindings, the
    /// input acceptance standard (which also scopes the locked
    /// rewrite widths, so output re-ingests under it), and the
    /// nesting bound.
    pub fn new(actions: &Actions<'r>, standard: Standard, depth: DepthLimit) -> Self {
        Self {
            pump: Pump::new(standard),
            mode: Mode::Head,
            stack: Vec::new(),
            depth,
            matcher: Matcher::new(actions.program),
            actions: actions.actions,
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

    /// The bound action of path `id`.
    fn action(&self, id: u16) -> Action<'r> {
        debug_assert!(usize::from(id) < self.actions.len(), "hits quote admitted bindings");
        // SAFETY: `Actions::over` proved the table's length equals
        // the program's path count (the count-mismatch judgment),
        // and the matcher mints every hit id below that count — so
        // `id` indexes in bounds.
        unsafe { *self.actions.get_unchecked(usize::from(id)) }
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

    #[cold]
    const fn halt_breach(
        &mut self,
        at: u64,
        kind: RuleFaultKind,
    ) -> ControlFlow<Result<(), Fault>> {
        ControlFlow::Break(Err(self.breach(at, kind)))
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

    /// Feeds one chunk. Emissions land in `out` as actions settle;
    /// `Ok` means the chunk is exhausted and the residue is
    /// carried.
    ///
    /// # Errors
    ///
    /// The first law violation ends the job: an input wire breach
    /// as [`Fault::Wire`] (summarized, at its absolute input
    /// coordinate), an action's breach at its match as
    /// [`Fault::Rule`] (at the record head).
    /// [`WireBreach::OffsetExhausted`] carries the coordinate-space
    /// refusals: a chunk refused whole at admission (before any of
    /// its bytes are read), and an unsealed LEN head whose declared
    /// payload the space cannot host. Faults latch — the machine
    /// is terminal afterwards.
    ///
    /// # Panics
    ///
    /// After a previous fault, and after a feed whose output
    /// callback unwound (the machine latches terminal across the
    /// callback, so a caught panic cannot resume a half-stepped
    /// job). The job is over.
    ///
    /// # Examples
    ///
    /// Two paths targeting one record are indeterminate — the
    /// conflict faults at the record, not at authoring (only the
    /// document joins them):
    ///
    /// ```
    /// use protobuf_edit::path::{Program, Segment};
    /// use protobuf_edit::rewire::Action;
    /// use protobuf_edit::rewire::groupless::{Actions, Fault, Rewirer, RuleFaultKind};
    /// use protobuf_edit::rewire::Standard;
    /// use protobuf_edit::{DepthLimit, FieldNumber};
    ///
    /// let f = |n| FieldNumber::new(n).unwrap();
    /// let direct: [Segment<'_>; 1] = [Segment::Field(f(1))];
    /// let route = [f(2)];
    /// let wild: [Segment<'_>; 2] =
    ///     [Segment::AnyDepth { descend: &route }, Segment::Field(f(1))];
    /// let paths: [&[Segment<'_>]; 2] = [&direct, &wild];
    /// let program = Program::over(&paths).unwrap();
    /// let table = [Action::Delete, Action::Delete];
    /// let actions = Actions::over(&program, &table).unwrap();
    ///
    /// let mut rw = Rewirer::new(&actions, Standard::Tolerant, DepthLimit::REFERENCE);
    /// let fault = rw.feed(&[0x08, 0x07], &mut |_: &[u8]| {}).unwrap_err();
    /// let Fault::Rule(rule_fault) = fault else { unreachable!() };
    /// assert!(matches!(
    ///     rule_fault.kind(),
    ///     RuleFaultKind::Conflict { first: 0, second: 1 }
    /// ));
    /// ```
    #[track_caller]
    pub fn feed<O: FnMut(&[u8])>(&mut self, chunk: &[u8], out: &mut O) -> Result<(), Fault> {
        assert!(!self.pump.terminal, "rewirer already terminal");
        // Coordinate admission ([`Pump::admits`]): the gate keeps
        // `off` strictly below the root sentinel through every
        // consuming path of this feed. Judged in this prologue so
        // the drive loop's codegen owes the gate nothing.
        if core::hint::unlikely(!self.pump.admits(chunk)) {
            return Err(self.wire(self.pump.off, WireBreach::OffsetExhausted));
        }
        // Poison across the output callback: latch terminal before
        // driving, so a callback that unwinds leaves the machine
        // terminal (every later feed hits the entry assert) rather
        // than resumable mid-construct — a resumed `FixedTail`
        // could re-enter collection against a popped zone and
        // reach the unreachable `Collect::Cut`. A normal return
        // restores the latch to the drive's own verdict.
        // The declared standard picks the drive instance once: the
        // per-record width judgment is a const inside the engine.
        self.pump.terminal = true;
        let outcome = match self.pump.standard {
            Standard::Tolerant => self.drive::<O, false>(chunk, out),
            Standard::CanonicalMinimal => self.drive::<O, true>(chunk, out),
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
    fn drive<O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        chunk: &[u8],
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
                    Some(LenFrame { prev_zone, .. }) => {
                        self.pump.zone = prev_zone;
                        self.matcher.exit();
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
                Mode::Head => self.head::<O, MINIMAL>(&mut chunk, out),
                Mode::VarintValue { field } => {
                    self.varint_value::<O, MINIMAL>(&mut chunk, field, out)
                }
                Mode::LenWord { field } => self.len_word::<O, MINIMAL>(&mut chunk, field, out),
                Mode::FixedTail { field, kind } => self.fixed_tail(&mut chunk, field, kind, out),
                Mode::Forward { remaining } => self.forward(&mut chunk, remaining, out),
                Mode::Swallow { remaining } => self.swallow(&mut chunk, remaining),
            };
            match flow {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(result) => return result,
            }
        }
    }

    /// Declares EOF and consumes the machine: the final verdict.
    /// No sink: every record's emission settled inside the feeds,
    /// and this machine injects no tail — EOF only judges what is
    /// still open.
    ///
    /// # Errors
    ///
    /// EOF inside a construct or a counted payload, or a LEN still
    /// open, is the matching breach summarized into
    /// [`Fault::Wire`] at the final offset.
    ///
    /// # Panics
    ///
    /// After a previous fault, and after a feed whose output
    /// callback unwound.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::path::{Program, Segment};
    /// use protobuf_edit::rewire::Action;
    /// use protobuf_edit::rewire::groupless::{Actions, Fault, Rewirer, WireBreach};
    /// use protobuf_edit::rewire::Standard;
    /// use protobuf_edit::{DepthLimit, FieldNumber};
    ///
    /// let f1 = FieldNumber::new(1).unwrap();
    /// let path: [Segment<'_>; 1] = [Segment::Field(f1)];
    /// let paths: [&[Segment<'_>]; 1] = [&path];
    /// let program = Program::over(&paths).unwrap();
    /// let table = [Action::Delete];
    /// let actions = Actions::over(&program, &table).unwrap();
    ///
    /// // A varint tag arrived; its value never did.
    /// let mut rw = Rewirer::new(&actions, Standard::Tolerant, DepthLimit::REFERENCE);
    /// rw.feed(&[0x10], &mut |_: &[u8]| {}).unwrap();
    /// let fault = rw.finish().unwrap_err();
    /// assert!(matches!(fault, Fault::Wire { at: 1, breach: WireBreach::Truncated }));
    /// ```
    #[track_caller]
    pub fn finish(mut self) -> Result<(), Fault> {
        assert!(!self.pump.terminal, "rewirer already terminal");
        debug_assert!(
            self.pump.off != self.pump.zone
                || !(matches!(self.mode, Mode::Head) && self.pump.carry.is_empty()),
            "feed resolves every endpoint it does not leave under a suspended word"
        );
        let at = self.pump.off;
        match self.mode {
            Mode::Head => {
                if !self.pump.carry.is_empty() {
                    return Err(self.wire(at, WireBreach::Truncated));
                }
            }
            Mode::VarintValue { .. }
            | Mode::LenWord { .. }
            | Mode::FixedTail { .. }
            | Mode::Forward { .. }
            | Mode::Swallow { .. } => {
                return Err(self.wire(at, WireBreach::Truncated));
            }
        }
        if self.stack.last().is_some() {
            return Err(self.wire(at, WireBreach::Truncated));
        }
        Ok(())
    }

    // ─ the drive arms (each returns Break to end the feed) ─

    /// Classifies one head and hands the record to its word
    /// handler: the whole record completes when the chunk allows,
    /// and the handlers write a suspension mode only when it does
    /// not — the mode is resumption state, not a per-record
    /// itinerary.
    fn head<O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let word = match self.pump.step_tag_held(chunk, standard_of(MINIMAL)) {
            Verdict::Done(word) => word,
            Verdict::More => return ControlFlow::Break(Ok(())),
            Verdict::Cut => return self.halt_seal_cut(),
            Verdict::TooWide => return self.halt_refused(),
            Verdict::OutOfClass => return self.halt_refused(),
            Verdict::NonMinimal => return self.halt_padded(),
        };
        let low3 = Low3::from_word(word);
        let Some(field) = FieldNumber::from_word(word) else {
            return self.halt_head(WireBreach::Tag);
        };
        match classify(low3) {
            TagClass::Record(RecordKind::Varint) => {
                self.stage_head();
                self.varint_value::<O, MINIMAL>(chunk, field, out)
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
                self.fixed_tail(chunk, field, fixed, out)
            }
            TagClass::Record(RecordKind::Len) => {
                self.stage_head();
                self.len_word::<O, MINIMAL>(chunk, field, out)
            }
            TagClass::GroupCode => self.halt_head(WireBreach::GroupCode),
            TagClass::Unassigned => self.halt_head(WireBreach::Tag),
        }
    }

    /// Stages the completed head for the record's action and frees
    /// the carry for the value construct.
    const fn stage_head(&mut self) {
        // SAFETY: the carry holds the tag construct `step_tag`
        // just completed — the five-byte window is its cap.
        unsafe { self.stage.capture(&self.pump.carry) };
        self.pump.carry.clear();
    }

    #[inline(always)]
    fn varint_value<O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let head = self.head_at();
        // The value word completes under wire law but no action
        // consults it — actions are static data, bound before any
        // value exists.
        match self.pump.step_value_held(chunk, standard_of(MINIMAL)) {
            Verdict::Done(_) => {}
            Verdict::More => {
                self.mode = Mode::VarintValue { field };
                return ControlFlow::Break(Ok(()));
            }
            Verdict::Cut => return self.halt_seal_cut(),
            Verdict::TooWide => return self.halt_refused(),
            Verdict::OutOfClass => {
                return self.halt_refused();
            }
            Verdict::NonMinimal => return self.halt_padded(),
        }
        // The carry holds the construct until the clear below, so
        // its length is the source width.
        let width = self.pump.carry.len();
        match self.matcher.probe_target(field) {
            Hits::None => {
                out(self.stage.bytes());
                out(self.pump.carry.bytes());
            }
            Hits::One(id) => match self.action(id) {
                Action::Rewrite(Value::Varint(new)) => {
                    if self.pump.locked() {
                        if let Err(fault) =
                            self.emit_equal_width::<O, MINIMAL>(new, width, id, head, out)
                        {
                            return ControlFlow::Break(Err(fault));
                        }
                    } else {
                        out(self.stage.bytes());
                        let mut buf = [MaybeUninit::uninit(); 10];
                        out(emit64_minimal(new, &mut buf));
                    }
                }
                Action::Rewrite(_) => {
                    return self.halt_breach(head, RuleFaultKind::KindMismatch { path: id });
                }
                Action::Delete => {
                    if self.pump.locked() {
                        return self.halt_breach(head, RuleFaultKind::Cascade { path: id });
                    }
                }
                Action::Insert(bytes) => {
                    if self.pump.locked() {
                        return self.halt_breach(head, RuleFaultKind::Cascade { path: id });
                    }
                    out(bytes);
                    out(self.stage.bytes());
                    out(self.pump.carry.bytes());
                }
            },
            Hits::Conflict(first, second) => {
                return self.halt_breach(head, RuleFaultKind::Conflict { first, second });
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
        path: u16,
        head: u64,
        out: &mut O,
    ) -> Result<(), Fault> {
        let need = encoded_len64(value);
        if MINIMAL {
            if need != u32::from(width) {
                let kind = RuleFaultKind::RewriteWidthMismatch { path, width, need: need as u8 };
                return Err(self.breach(head, kind));
            }
        } else if need > u32::from(width) {
            let kind = RuleFaultKind::RewriteOverflow { path, width, need: need as u8 };
            return Err(self.breach(head, kind));
        }
        out(self.stage.bytes());
        let mut buf = [MaybeUninit::uninit(); 10];
        // SAFETY: `width` is a completed value construct's carried
        // width — at most ten by the value window — and the
        // standard judgment above admitted `encoded_len64(value)`
        // within it.
        out(unsafe { emit64_padded(value, width, &mut buf) });
        Ok(())
    }

    #[inline(always)]
    fn fixed_tail<O: FnMut(&[u8])>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        kind: FixedKind,
        out: &mut O,
    ) -> ControlFlow<Result<(), Fault>> {
        let head = self.head_at();
        // The fixed source bytes, collected into one stack buffer;
        // the record settles whole below (both widths share one
        // action arm — the value kinds differ, the emission
        // algebra does not).
        let mut buf = [0_u8; 8];
        let bytes: &[u8] = match kind {
            FixedKind::I32 => {
                let Some(source) = self.pump.grab_fixed::<4>(chunk) else {
                    self.mode = Mode::FixedTail { field, kind };
                    return ControlFlow::Break(Ok(()));
                };
                buf[..4].copy_from_slice(&source);
                &buf[..4]
            }
            FixedKind::I64 => {
                let Some(source) = self.pump.grab_fixed::<8>(chunk) else {
                    self.mode = Mode::FixedTail { field, kind };
                    return ControlFlow::Break(Ok(()));
                };
                buf = source;
                &buf
            }
        };
        match self.matcher.probe_target(field) {
            Hits::None => {
                out(self.stage.bytes());
                out(bytes);
            }
            Hits::One(id) => match (self.action(id), kind) {
                (Action::Rewrite(Value::I32(bits)), FixedKind::I32) => {
                    out(self.stage.bytes());
                    out(&bits.to_le_bytes());
                }
                (Action::Rewrite(Value::I64(bits)), FixedKind::I64) => {
                    out(self.stage.bytes());
                    out(&bits.to_le_bytes());
                }
                (Action::Rewrite(_), _) => {
                    return self.halt_breach(head, RuleFaultKind::KindMismatch { path: id });
                }
                (Action::Delete, _) => {
                    if self.pump.locked() {
                        return self.halt_breach(head, RuleFaultKind::Cascade { path: id });
                    }
                }
                (Action::Insert(injected), _) => {
                    if self.pump.locked() {
                        return self.halt_breach(head, RuleFaultKind::Cascade { path: id });
                    }
                    out(injected);
                    out(self.stage.bytes());
                    out(bytes);
                }
            },
            Hits::Conflict(first, second) => {
                return self.halt_breach(head, RuleFaultKind::Conflict { first, second });
            }
        }
        self.mode = Mode::Head;
        ControlFlow::Continue(())
    }

    #[inline(always)]
    fn len_word<O: FnMut(&[u8]), const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
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
            Verdict::TooWide => {
                return self.halt_refused();
            }
            Verdict::OutOfClass => {
                return self.halt_refused();
            }
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
        let (hits, routed) = self.matcher.probe(field);
        match hits {
            Hits::None => {
                if let Err(fault) = self.ride_len(len, end, routed, out) {
                    return ControlFlow::Break(Err(fault));
                }
            }
            Hits::One(id) => match self.action(id) {
                Action::Rewrite(Value::Len(bytes)) => {
                    #[allow(
                        clippy::as_conversions,
                        reason = "replacement lengths widen losslessly into the account \
                                  domain on the crate's 32/64-bit targets"
                    )]
                    if bytes.len() as u64 != u64::from(len.as_inner()) {
                        let kind = RuleFaultKind::ReplaceLenMismatch {
                            path: id,
                            expect: len,
                            got: bytes.len() as u64,
                        };
                        return ControlFlow::Break(Err(self.breach(head, kind)));
                    }
                    out(self.stage.bytes());
                    out(self.pump.carry.bytes());
                    out(bytes);
                    self.mode = NonZeroU32::new(len.as_inner())
                        .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
                }
                Action::Rewrite(_) => {
                    return self.halt_breach(head, RuleFaultKind::KindMismatch { path: id });
                }
                Action::Delete => {
                    if self.pump.locked() {
                        return self.halt_breach(head, RuleFaultKind::Cascade { path: id });
                    }
                    self.mode = NonZeroU32::new(len.as_inner())
                        .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
                }
                Action::Insert(bytes) => {
                    if self.pump.locked() {
                        return self.halt_breach(head, RuleFaultKind::Cascade { path: id });
                    }
                    out(bytes);
                    // Terminal insertion: the record then rides as
                    // if unmatched — committed when other paths
                    // continue into it, forwarded otherwise.
                    if let Err(fault) = self.ride_len(len, end, routed, out) {
                        return ControlFlow::Break(Err(fault));
                    }
                }
            },
            Hits::Conflict(first, second) => {
                return self.halt_breach(head, RuleFaultKind::Conflict { first, second });
            }
        }
        self.pump.carry.clear();
        ControlFlow::Continue(())
    }

    /// Settles an untargeted LEN: committed (entered and walked)
    /// when paths continue into it, forwarded opaque otherwise.
    /// Emits the head verbatim either way.
    fn ride_len<O: FnMut(&[u8])>(
        &mut self,
        len: PayloadLen,
        end: u64,
        routed: bool,
        out: &mut O,
    ) -> Result<(), Fault> {
        if routed {
            if self.stack.len() >= usize::from(self.depth.as_inner()) {
                return Err(self.wire(self.pump.off, WireBreach::Depth));
            }
            out(self.stage.bytes());
            out(self.pump.carry.bytes());
            self.stack.push(LenFrame { prev_zone: self.pump.zone });
            self.pump.zone = end;
            self.matcher.commit_descent();
            self.mode = Mode::Head;
        } else {
            out(self.stage.bytes());
            out(self.pump.carry.bytes());
            self.mode = NonZeroU32::new(len.as_inner())
                .map_or(Mode::Head, |remaining| Mode::Forward { remaining });
        }
        Ok(())
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
}

#[cfg(test)]
mod tests;
