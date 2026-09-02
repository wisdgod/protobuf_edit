//! Online source transfers for the splicer: a source-aware rule
//! overlay whose verdicts relocate the current occurrence.
//!
//! The record being asked about is the designation, and the
//! destination is a gap whose ownership is already known at the
//! ask.
//!
//! A transfer verdict is terminal for the current occurrence: it
//! relocates the original input bytes (never another verdict's
//! product), and the occurrence is not also descended or
//! rewritten. Copies ride at the origin and emit again at the
//! gap; moves emit at the gap alone. Whole-record transfers are
//! byte-exact — met framing widths, nested padding, and (in the
//! grouped dialect) the whole structural group closure ride along;
//! payload transfers detach the source LEN's interior and author
//! minimal destination framing for the verdict's field. A payload
//! move suppresses the entire source record — a tag and prefix
//! with no interior have no lawful meaning.
//!
//! [`OnlineGap`] is the destination domain: before or after the
//! current record (resolved at the ask), or the tail of an open
//! container — the current layer or a counted ancestor, settled at
//! that container's close. Heads of already-entered layers and
//! not-yet-seen records are not online destinations; wanting them
//! is the offline editors' designation, not this host's.
//!
//! All three job faces run the sealed-overlay custody discipline:
//! the ask walk builds a source-ordered overlay (input windows,
//! authored words, prefix slots settled at each close, tail claims
//! settled at their containers), and emission folds it only after
//! the whole walk succeeded. A group span settles at its verified
//! exit without exposing partial output, an earlier record is
//! lawfully suppressed after its destination decision, and the
//! fold carries no rule reference — re-designation mid-stream is
//! unspellable. On any fault nothing has been handed over or
//! appended.
//!
//! The plain rule vocabulary and the plain job faces carry none of
//! this machinery.

use alloc::vec::Vec;

use super::{Len, Scalar};
use crate::admission::{self, Coord, admitted_u32, usize_of};
use crate::varint::{emit64, encoded_len32};
use crate::wire::FieldNumber;

/// An online destination: a gap whose ownership is already known
/// when the verdict is asked.
///
/// The crate's other gap-designation vocabularies are this job
/// refitted to other machines: the handle-driven editors'
/// `InsertAt` names one gap of one parsed sibling chain, and
/// `rewrite`'s `Gap` names the interior gaps of containers a
/// rule's anchor path selects — offline designations over
/// structure this online vocabulary cannot reach back into.
///
/// `BeforeCurrent` and `AfterCurrent` resolve at the ask. The tail
/// forms attach to an open container — the current layer, or an
/// ancestor counted outward through the currently open committed
/// containers (LEN commits and, in the grouped dialect, committed
/// groups), the document root included as the outermost layer —
/// and settle at that container's close. A level past the open
/// chain refuses before any mutation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OnlineGap {
    /// Immediately before the current record.
    BeforeCurrent,
    /// Immediately after the current record.
    AfterCurrent,
    /// The tail of the innermost open layer (the document tail at
    /// top level).
    TailOfCurrentLayer,
    /// The tail of the n-th enclosing open layer (1 = the
    /// immediately containing layer; the root is the outermost).
    /// Zero is not a level — spell the current layer's tail as
    /// [`TailOfCurrentLayer`](Self::TailOfCurrentLayer).
    TailOfAncestor(u16),
}

/// A scalar record's source-aware verdict: the host's own verdict,
/// or a whole-record transfer.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceScalar<'a, V> {
    /// The host verdict, unchanged.
    Current(Scalar<'a, V>),
    /// The record's exact bytes also emit at the gap; the record
    /// rides at its origin.
    CopyRecord(OnlineGap),
    /// The record's exact bytes emit at the gap alone; the origin
    /// emits nothing.
    MoveRecord(OnlineGap),
}

impl<'a, V> SourceScalar<'a, V> {
    /// Maps the host verdict's rewrite payload, carrying every
    /// other verdict over — the walks' fixed-kind funnel.
    pub(crate) fn map<W>(self, f: impl FnOnce(V) -> W) -> SourceScalar<'a, W> {
        match self {
            Self::Current(verdict) => SourceScalar::Current(verdict.map(f)),
            Self::CopyRecord(gap) => SourceScalar::CopyRecord(gap),
            Self::MoveRecord(gap) => SourceScalar::MoveRecord(gap),
        }
    }
}

/// A LEN record's source-aware verdict: the host's own verdict, a
/// whole-record transfer, or a payload transfer.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SourceLen<'a> {
    /// The host verdict, unchanged.
    Current(Len<'a>),
    /// The record's exact bytes also emit at the gap; the record
    /// rides at its origin, undescended.
    CopyRecord(OnlineGap),
    /// The record's exact bytes emit at the gap alone.
    MoveRecord(OnlineGap),
    /// The interior bytes emit at the gap behind a crate-authored
    /// minimal tag and prefix for `field`; the record rides at its
    /// origin.
    CopyPayload {
        /// The destination gap.
        to: OnlineGap,
        /// The authored record's field number.
        field: FieldNumber,
    },
    /// The interior bytes emit at the gap behind authored framing;
    /// the entire source record emits nowhere.
    MovePayload {
        /// The destination gap.
        to: OnlineGap,
        /// The authored record's field number.
        field: FieldNumber,
    },
}

// ─── the sealed transfer overlay (custody engine, all faces) ───

/// One overlay instruction, source-ordered. `Hole` is a committed
/// container's claimed prefix slot, rewritten at its close; `Span`
/// is a claimed source window whose end may resolve later (a group
/// span completes at its verified exit) — the fold never sees an
/// unresolved one.
enum Op {
    /// Copy `input[from..to]`.
    Src { from: u32, to: u32 },
    /// Hand `staging[at..at + len]`.
    Staged { at: u32, len: u32 },
    /// Emit a minimal varint word.
    Word { word: u32 },
    /// Copy the claimed source window `spans[index]` — a group
    /// span emitted ahead of its resolution.
    #[cfg(feature = "transfer-splice-grouped")]
    Span { index: u32 },
    /// An unfilled prefix claim.
    Hole,
}

/// One committed LEN container's settle state (the host's sink
/// overlay law: totals roll into the parent at the close).
struct Frame {
    total: u64,
    head: Coord,
    tag_end: Coord,
    payload_start: Coord,
    /// The claimed `Op::Hole`'s index; `u32::MAX` while the
    /// subtree is still clean.
    op: u32,
    /// The staged commit tail (`len == 0` for none).
    tail_at: u32,
    tail_len: u32,
}

/// One pending tail emission, settled at its level's close.
enum Claim {
    /// A whole record's exact bytes.
    Record {
        /// Index into the span table.
        span: u32,
    },
    /// An authored LEN record over a source interior.
    Payload {
        /// The authored minimal head word.
        head: u32,
        /// The interior window.
        from: u32,
        to: u32,
    },
}

/// What kind of open container a claim level belongs to — the
/// close discipline differs (LEN closes settle a prefix, group and
/// root closes do not).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LevelKind {
    /// The document root (always the outermost level).
    Root,
    /// A committed LEN layer.
    Len,
    /// A committed group (grouped dialect only).
    #[cfg(feature = "transfer-splice-grouped")]
    Group,
}

/// One open container's tail-claim list, in ask order.
struct Level {
    kind: LevelKind,
    claims: Vec<Claim>,
}

/// The transfer walk's sealed product: the host sink overlay's
/// source-ordered op/staging/frame discipline, plus the span table
/// (source windows, group ends resolved at their exits) and the
/// claim chain (one tail-claim list per open container, root
/// included). Coordinates only — no source byte is staged.
pub(super) struct Overlay<'i> {
    input: &'i [u8],
    ops: Vec<Op>,
    staging: Vec<u8>,
    /// Committed LEN containers, outermost first.
    frames: Vec<Frame>,
    /// Frames below this index are claimed; claiming is monotone
    /// until the frame pops.
    claimed: usize,
    /// Pending verbatim run, absolute half-open.
    run: Option<(u32, u32)>,
    /// The settled output total so far — the eager cap judgment.
    total: u64,
    /// Claimed source windows; a group window's end is
    /// `u32::MAX` until its verified exit resolves it.
    spans: Vec<(u32, u32)>,
    /// The claim chain: the root plus every open committed
    /// container, innermost last.
    levels: Vec<Level>,
}

/// The unresolved-span sentinel: absolute offsets live in the
/// admitted coordinate class, far below it.
const PENDING: u32 = u32::MAX;

impl<'i> Overlay<'i> {
    pub(super) fn new(input: &'i [u8]) -> Self {
        Self {
            input,
            ops: Vec::new(),
            staging: Vec::new(),
            frames: Vec::new(),
            claimed: 0,
            run: None,
            total: 0,
            spans: Vec::new(),
            levels: alloc::vec![Level { kind: LevelKind::Root, claims: Vec::new() }],
        }
    }

    /// The eager cap judgment, mirroring the physical output
    /// length exactly.
    const fn admit(&mut self, grow: u64) -> Result<(), u64> {
        let total = self.total + grow;
        #[allow(clippy::as_conversions, reason = "MAX is far below u64")]
        if total > admission::MAX as u64 {
            return Err(total);
        }
        self.total = total;
        Ok(())
    }

    /// Accounts `grow` bytes into the innermost committed LEN
    /// container's interior (nothing to write at the root).
    fn account(&mut self, grow: u64) {
        if let Some(frame) = self.frames.last_mut() {
            frame.total += grow;
        }
    }

    /// Extends the pending run, coalescing contiguous extents.
    fn ride(&mut self, from: u32, to: u32) {
        match &mut self.run {
            Some((_, tail)) if *tail == from => *tail = to,
            Some(_) => {
                self.flush();
                self.run = Some((from, to));
            }
            None => self.run = Some((from, to)),
        }
    }

    fn flush(&mut self) {
        if let Some((from, to)) = self.run.take()
            && from < to
        {
            self.ops.push(Op::Src { from, to });
        }
    }

    /// Claims every still-clean committed ancestor, outermost
    /// first — the host overlay's prefix-slot discipline.
    fn materialize(&mut self) {
        for index in self.claimed..self.frames.len() {
            let (tag_end, payload_start) = {
                let frame = &self.frames[index];
                (frame.tag_end.as_inner(), frame.payload_start.as_inner())
            };
            // A still-clean frame's prefix sits inside the pending
            // run: nothing flushed since before its commit.
            debug_assert!(self.run.is_some_and(|(from, to)| from < tag_end && payload_start <= to));
            let Some((from, to)) = self.run.take() else { continue };
            if from < tag_end {
                self.ops.push(Op::Src { from, to: tag_end });
            }
            // Lossless: op counts are bounded by the record count.
            #[allow(clippy::as_conversions, reason = "op indexes stay far under 2^32")]
            {
                self.frames[index].op = self.ops.len() as u32;
            }
            self.ops.push(Op::Hole);
            self.run = Some((payload_start, to));
        }
        self.claimed = self.frames.len();
    }

    /// An authored emission's shared entry: claim ancestors, flush
    /// the run, stage the bytes, account.
    fn edit(&mut self, bytes: &[u8]) -> Result<(), u64> {
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        self.admit(bytes.len() as u64)?;
        self.materialize();
        self.flush();
        let at = admitted_u32(self.staging.len());
        self.staging.extend_from_slice(bytes);
        self.ops.push(Op::Staged { at, len: admitted_u32(bytes.len()) });
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        self.account(bytes.len() as u64);
        Ok(())
    }

    /// The bytes `from..to` ride untouched.
    pub(super) fn verbatim(&mut self, from: u32, to: u32) -> Result<(), u64> {
        self.admit(u64::from(to - from))?;
        self.ride(from, to);
        self.account(u64::from(to - from));
        Ok(())
    }

    /// Caller bytes land here (already judged inside the LEN
    /// class).
    pub(super) fn author(&mut self, bytes: &[u8]) -> Result<(), u64> {
        self.edit(bytes)
    }

    /// A minimal varint word lands here.
    pub(super) fn author_varint(&mut self, word: u64) -> Result<(), u64> {
        let mut window = [0u8; 10];
        let width = emit64(word, &mut window);
        self.edit(&window[..usize_of(width)])
    }

    /// A record vanished without a replacing emission — a drop or
    /// a move's origin suppression: the committed ancestors'
    /// prefixes claim here.
    pub(super) fn dirty(&mut self) {
        self.materialize();
    }

    /// A whole source window emits here, out of the linear ride —
    /// a resolved record transfer landing at the ask.
    pub(super) fn edit_record(&mut self, from: u32, to: u32) -> Result<(), u64> {
        self.admit(u64::from(to - from))?;
        self.materialize();
        self.flush();
        self.ops.push(Op::Src { from, to });
        self.account(u64::from(to - from));
        Ok(())
    }

    /// An authored LEN record over a source interior emits here:
    /// minimal head word, minimal prefix, the window byte-exact.
    pub(super) fn edit_payload(&mut self, head: u32, from: u32, to: u32) -> Result<(), u64> {
        let len = to - from;
        let grow = u64::from(encoded_len32(head)) + u64::from(encoded_len32(len)) + u64::from(len);
        self.admit(grow)?;
        self.materialize();
        self.flush();
        self.ops.push(Op::Word { word: head });
        self.ops.push(Op::Word { word: len });
        self.ops.push(Op::Src { from, to });
        self.account(grow);
        Ok(())
    }

    /// Claims a resolved source window for a deferred emission.
    pub(super) fn claim_span(&mut self, from: u32, to: u32) -> Result<u32, u64> {
        self.admit(u64::from(to - from))?;
        self.spans.push((from, to));
        // Lossless: span counts are bounded by the record count.
        #[allow(clippy::as_conversions, reason = "span indexes stay far under 2^32")]
        Ok((self.spans.len() - 1) as u32)
    }

    /// Opens a group source window at its enter; the end (and the
    /// cap judgment) resolve at [`close_span`](Self::close_span).
    #[cfg(feature = "transfer-splice-grouped")]
    pub(super) fn open_span(&mut self, from: u32) -> u32 {
        self.spans.push((from, PENDING));
        #[allow(clippy::as_conversions, reason = "span indexes stay far under 2^32")]
        {
            (self.spans.len() - 1) as u32
        }
    }

    /// Resolves a group source window consumed by a pending
    /// emission op at its ask position: the cap judgment and the
    /// interior account land here — the op sits inside the same
    /// LEN container at the exit as at the ask, groups never
    /// changing the frame chain.
    #[cfg(feature = "transfer-splice-grouped")]
    pub(super) fn close_span_emitted(&mut self, index: u32, to: u32) -> Result<(), u64> {
        let len = self.resolve_span(index, to);
        self.admit(len)?;
        self.account(len);
        Ok(())
    }

    /// Resolves a group source window held by a tail claim: the
    /// cap judgment lands here, the interior account at the
    /// claim's settle.
    #[cfg(feature = "transfer-splice-grouped")]
    pub(super) fn close_span_claimed(&mut self, index: u32, to: u32) -> Result<(), u64> {
        let len = self.resolve_span(index, to);
        self.admit(len)
    }

    /// Fills a pending span's end, once.
    #[cfg(feature = "transfer-splice-grouped")]
    fn resolve_span(&mut self, index: u32, to: u32) -> u64 {
        let span = &mut self.spans[usize_of(index)];
        debug_assert!(span.1 == PENDING, "a span resolves once");
        span.1 = to;
        u64::from(to - span.0)
    }

    /// A pending source window emits here — the before-the-group
    /// placement, whose length resolves at the group's exit (the
    /// account rides [`close_span`](Self::close_span)).
    #[cfg(feature = "transfer-splice-grouped")]
    pub(super) fn edit_pending(&mut self, index: u32) {
        self.materialize();
        self.flush();
        self.ops.push(Op::Span { index });
    }

    /// The claim-chain length: the root plus every open committed
    /// container.
    pub(super) const fn levels(&self) -> usize {
        self.levels.len()
    }

    /// Attaches a whole-record claim to the level's tail. The
    /// window's cap judgment rode its span claim.
    pub(super) fn claim_record(&mut self, level: usize, span: u32) {
        self.levels[level].claims.push(Claim::Record { span });
    }

    /// Attaches an authored-payload claim to the level's tail.
    pub(super) fn claim_payload(
        &mut self,
        level: usize,
        head: u32,
        from: u32,
        to: u32,
    ) -> Result<(), u64> {
        let len = to - from;
        self.admit(
            u64::from(encoded_len32(head)) + u64::from(encoded_len32(len)) + u64::from(len),
        )?;
        self.levels[level].claims.push(Claim::Payload { head, from, to });
        Ok(())
    }

    /// Settles one level's claims in ask order, returning the
    /// emitted byte count (already admitted at claim time). The
    /// caller has flushed and materialized.
    fn settle_claims(&mut self, level: Level) -> u64 {
        let mut grow: u64 = 0;
        for claim in level.claims {
            match claim {
                Claim::Record { span } => {
                    let (from, to) = self.spans[usize_of(span)];
                    debug_assert!(to != PENDING, "claims settle after their spans resolve");
                    self.ops.push(Op::Src { from, to });
                    grow += u64::from(to - from);
                }
                Claim::Payload { head, from, to } => {
                    let len = to - from;
                    self.ops.push(Op::Word { word: head });
                    self.ops.push(Op::Word { word: len });
                    self.ops.push(Op::Src { from, to });
                    grow += u64::from(encoded_len32(head))
                        + u64::from(encoded_len32(len))
                        + u64::from(len);
                }
            }
        }
        grow
    }

    /// A committed LEN container opens: the host overlay's commit,
    /// plus one claim level.
    pub(super) fn commit(
        &mut self,
        head: u32,
        tag_end: u32,
        payload_start: u32,
        tail: Option<&[u8]>,
    ) -> Result<(), u64> {
        self.admit(u64::from(payload_start - head))?;
        let (tail_at, tail_len) = match tail {
            Some(bytes) => {
                #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
                self.admit(bytes.len() as u64)?;
                let at = admitted_u32(self.staging.len());
                self.staging.extend_from_slice(bytes);
                // Judged inside the LEN class at the ask.
                (at, admitted_u32(bytes.len()))
            }
            None => (0, 0),
        };
        self.ride(head, payload_start);
        // SAFETY (all three mints): the walk hands framing offsets
        // inside the admitted input, so every offset is in class.
        self.frames.push(Frame {
            total: 0,
            head: unsafe { Coord::new_unchecked(head) },
            tag_end: unsafe { Coord::new_unchecked(tag_end) },
            payload_start: unsafe { Coord::new_unchecked(payload_start) },
            op: u32::MAX,
            tail_at,
            tail_len,
        });
        self.levels.push(Level { kind: LevelKind::Len, claims: Vec::new() });
        Ok(())
    }

    /// The innermost committed LEN container closes; `old_len` is
    /// its announced interior length. The staged commit tail lands
    /// first (declared at the open), then the tail claims in ask
    /// order, then the prefix settles.
    pub(super) fn close(&mut self, old_len: u32) -> Result<(), u64> {
        debug_assert!(!self.frames.is_empty(), "closes pair with commits");
        let level = self.levels.pop();
        debug_assert!(
            level.as_ref().is_some_and(|l| l.kind == LevelKind::Len),
            "LEN closes pop LEN levels"
        );
        // The level was popped from the non-empty chain.
        let Some(level) = level else { unreachable!("the claim chain matches the walk") };
        // A tail or a pending claim dirties its container: claim
        // through this frame before judging cleanliness.
        if self.frames.len() > self.claimed
            && let Some(frame) = self.frames.last()
            && (frame.tail_len > 0 || !level.claims.is_empty())
        {
            self.materialize();
        }
        // SAFETY: closes pair with commits (asserted above), so a
        // committed frame is on the stack.
        let frame = unsafe { self.frames.pop().unwrap_unchecked() };
        self.claimed = self.claimed.min(self.frames.len());
        if frame.op == u32::MAX {
            // Clean subtree: byte-identical, riding inside the
            // pending run (claims would have materialized above).
            debug_assert!(frame.total == u64::from(old_len) && frame.tail_len == 0);
            debug_assert!(level.claims.is_empty(), "claims dirty their container");
            self.account(
                u64::from(frame.payload_start.as_inner() - frame.head.as_inner()) + frame.total,
            );
            return Ok(());
        }
        let mut interior = frame.total;
        if frame.tail_len > 0 {
            self.flush();
            self.ops.push(Op::Staged { at: frame.tail_at, len: frame.tail_len });
            interior += u64::from(frame.tail_len);
        }
        if !level.claims.is_empty() {
            self.flush();
            interior += self.settle_claims(level);
        }
        // The interior is a sub-range of the capped output, so it
        // lies inside the LEN class.
        debug_assert!(interior <= u64::from(crate::wire::PayloadLen::MAX.as_inner()));
        #[allow(clippy::as_conversions, reason = "judged inside the LEN class")]
        let new_len = interior as u32;
        let met = frame.payload_start.as_inner() - frame.tag_end.as_inner();
        let width = if new_len == old_len {
            // Unchanged length: the source prefix rides verbatim
            // into the claimed slot.
            self.ops[usize_of(frame.op)] =
                Op::Src { from: frame.tag_end.as_inner(), to: frame.payload_start.as_inner() };
            met
        } else {
            // Changed length: minimal re-author; the account trades
            // met bytes for minimal bytes.
            self.ops[usize_of(frame.op)] = Op::Word { word: new_len };
            let need = encoded_len32(new_len);
            if need > met {
                self.admit(u64::from(need - met))?;
            } else {
                self.total -= u64::from(met - need);
            }
            need
        };
        self.account(
            u64::from(frame.tag_end.as_inner() - frame.head.as_inner())
                + u64::from(width)
                + interior,
        );
        Ok(())
    }

    /// A committed group opens: one claim level, no settle
    /// obligation (groups carry no prefix).
    #[cfg(feature = "transfer-splice-grouped")]
    pub(super) fn group_open(&mut self) {
        self.levels.push(Level { kind: LevelKind::Group, claims: Vec::new() });
    }

    /// A committed group closes: its tail claims settle before the
    /// end tag's emission.
    #[cfg(feature = "transfer-splice-grouped")]
    pub(super) fn group_close(&mut self) {
        let level = self.levels.pop();
        debug_assert!(
            level.as_ref().is_some_and(|l| l.kind == LevelKind::Group),
            "group closes pop group levels"
        );
        // The level was popped from the non-empty chain.
        let Some(level) = level else { unreachable!("the claim chain matches the walk") };
        if level.claims.is_empty() {
            return;
        }
        self.materialize();
        self.flush();
        let grow = self.settle_claims(level);
        self.account(grow);
    }

    /// The document ends: the root level's claims settle at the
    /// output tail.
    pub(super) fn root_close(&mut self) {
        debug_assert!(self.levels.len() == 1, "every committed container closed");
        // The root level is pushed at construction and popped
        // exactly here.
        let Some(level) = self.levels.pop() else { unreachable!("the root level is permanent") };
        debug_assert!(level.kind == LevelKind::Root, "the chain bottoms at the root");
        if level.claims.is_empty() {
            return;
        }
        self.flush();
        // Root claims account into no frame: their bytes were
        // admitted at claim time and land past every container.
        let _ = self.settle_claims(level);
    }

    /// Hands the sealed overlay's windows over, in source order —
    /// infallible and rule-free by signature: every fault preceded
    /// the first handoff, and a re-ask is unspellable.
    pub(super) fn fold<F: FnMut(&[u8])>(mut self, sink: &mut F) {
        debug_assert!(self.frames.is_empty(), "every committed container closed");
        debug_assert!(self.levels.is_empty(), "every claim level settled");
        let run = self.run.take();
        let mut handed: u64 = 0;
        let hand_word = |word: u32, sink: &mut F, handed: &mut u64| {
            let mut window = [0u8; 10];
            let width = emit64(u64::from(word), &mut window);
            *handed += u64::from(width);
            sink(&window[..usize_of(width)]);
        };
        for op in &self.ops {
            let window: &[u8] = match *op {
                Op::Src { from, to } => &self.input[usize_of(from)..usize_of(to)],
                Op::Staged { at, len } => &self.staging[usize_of(at)..usize_of(at + len)],
                Op::Word { word } => {
                    hand_word(word, sink, &mut handed);
                    continue;
                }
                #[cfg(feature = "transfer-splice-grouped")]
                Op::Span { index } => {
                    let (from, to) = self.spans[usize_of(index)];
                    debug_assert!(to != PENDING, "every span resolved before the fold");
                    &self.input[usize_of(from)..usize_of(to)]
                }
                // Every claim fills at its close; the walk closes
                // every layer it commits.
                Op::Hole => unreachable!("an unfilled prefix claim survived the walk"),
            };
            if window.is_empty() {
                continue;
            }
            #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
            {
                handed += window.len() as u64;
            }
            sink(window);
        }
        if let Some((from, to)) = run
            && from < to
        {
            handed += u64::from(to - from);
            sink(&self.input[usize_of(from)..usize_of(to)]);
        }
        assert!(handed == self.total, "the fold handed exactly the walk's account");
    }
}
