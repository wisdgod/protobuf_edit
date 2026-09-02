//! The two emission back-ends behind the dialects' one ask walk:
//! the Vec faces' met-width-hole immediate settler and the sink
//! face's sealed sparse overlay. Both are dialect-blind — they see
//! absolute input extents, authored bytes, and commit/close
//! punctuation; the dialect walks own every wire and verdict
//! judgment.

use alloc::vec::Vec;

use crate::admission::{self, Coord, admitted_u32, usize_of};
use crate::varint::{emit64, encoded_len32, write64_at};

/// One emission back-end behind the shared ask walk. Every
/// coordinate is an absolute input offset; the appending methods'
/// `Err(len)` is the output-cap breach, mapped by the walk into
/// the dialect's `Output` fault at the event's record.
pub(super) trait Back {
    /// The bytes `from..to` ride untouched.
    fn verbatim(&mut self, from: u32, to: u32) -> Result<(), u64>;
    /// Caller bytes land here (already judged inside the LEN
    /// class).
    fn author(&mut self, bytes: &[u8]) -> Result<(), u64>;
    /// A minimal varint word lands here.
    fn author_varint(&mut self, word: u64) -> Result<(), u64>;
    /// A record vanished without a replacing emission — the one
    /// edit shape with no authored bytes. The Vec back-end needs
    /// nothing (its closes read output positions); the overlay
    /// back-end claims the committed ancestors' prefix slots, which
    /// otherwise only an authored emission would claim.
    fn dirty(&mut self);
    /// A committed container opens: the head rides, the prefix
    /// becomes this layer's settle obligation, the tail (already
    /// judged in class) is staged for the close.
    fn commit(
        &mut self,
        head: u32,
        tag_end: u32,
        payload_start: u32,
        tail: Option<&[u8]>,
    ) -> Result<(), u64>;
    /// The innermost committed container closes; `old_len` is its
    /// announced interior length.
    fn close(&mut self, old_len: u32) -> Result<(), u64>;
}

/// A fixed word's little-endian bytes, unifying the two fixed
/// kinds' rewrite arms in the dialect walks.
#[derive(Clone, Copy)]
pub(super) enum Word {
    W32([u8; 4]),
    W64([u8; 8]),
}

impl Word {
    pub(super) const fn bytes(&self) -> &[u8] {
        match self {
            Self::W32(bytes) => bytes,
            Self::W64(bytes) => bytes,
        }
    }
}

impl From<u32> for Word {
    fn from(bits: u32) -> Self {
        Self::W32(bits.to_le_bytes())
    }
}

impl From<u64> for Word {
    fn from(bits: u64) -> Self {
        Self::W64(bits.to_le_bytes())
    }
}

// ─── the Vec back-end: met-width holes, immediate settle ───

/// One open committed container's settle state: two output
/// coordinates bracketing the optimistically copied prefix (their
/// difference is the met width) and the staged tail's length.
/// The hole ledger IS this stack — no arena, no plan, no undo log.
struct Hole {
    hole_at: u32,
    interior_at: u32,
    tail_len: u32,
}

/// The Vec faces' emitter. All output coordinates are relative to
/// `mark` (the caller buffer's length at entry), kept inside the
/// admission cap by the eager append judgment — so they live in
/// `u32` no matter how full the caller's buffer already is.
pub(super) struct Emit<'i, 'o> {
    input: &'i [u8],
    out: &'o mut Vec<u8>,
    mark: usize,
    holes: Vec<Hole>,
    /// Staged commit tails, LIFO: inner commits stage later and
    /// close earlier, so a layer's tail is always the stack's top
    /// `tail_len` bytes at its close.
    tails: Vec<u8>,
}

impl<'i, 'o> Emit<'i, 'o> {
    pub(super) const fn new(input: &'i [u8], out: &'o mut Vec<u8>) -> Self {
        let mark = out.len();
        Self { input, out, mark, holes: Vec::new(), tails: Vec::new() }
    }

    /// The job's output length so far (inside the cap, so `u32`).
    const fn rel(&self) -> u32 {
        admitted_u32(self.out.len() - self.mark)
    }

    /// The eager cap judgment: every append (and every settle
    /// growth) passes here first.
    fn admit(&self, grow: u64) -> Result<(), u64> {
        let total = u64::from(self.rel()) + grow;
        #[allow(clippy::as_conversions, reason = "MAX is far below u64")]
        if total > admission::MAX as u64 {
            return Err(total);
        }
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), u64> {
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        self.admit(bytes.len() as u64)?;
        self.out.extend_from_slice(bytes);
        Ok(())
    }
}

impl Back for Emit<'_, '_> {
    fn verbatim(&mut self, from: u32, to: u32) -> Result<(), u64> {
        let (from, to) = (usize_of(from), usize_of(to));
        // The extent was delivered by the cursor over this input.
        debug_assert!(from <= to && to <= self.input.len());
        // SAFETY: record extents the cursor delivered lie inside
        // the admitted input.
        let src = unsafe { self.input.get_unchecked(from..to) };
        self.append(src)
    }

    fn author(&mut self, bytes: &[u8]) -> Result<(), u64> {
        self.append(bytes)
    }

    fn author_varint(&mut self, word: u64) -> Result<(), u64> {
        let mut window = [0u8; 10];
        let width = emit64(word, &mut window);
        self.append(&window[..usize_of(width)])
    }

    fn dirty(&mut self) {
        // A drop is a gap in the output positions the closes
        // already read — nothing to record.
    }

    fn commit(
        &mut self,
        head: u32,
        tag_end: u32,
        payload_start: u32,
        tail: Option<&[u8]>,
    ) -> Result<(), u64> {
        self.verbatim(head, tag_end)?;
        let hole_at = self.rel();
        self.verbatim(tag_end, payload_start)?;
        let interior_at = self.rel();
        let tail_len = tail.map_or(0, |bytes| {
            self.tails.extend_from_slice(bytes);
            // Judged inside the LEN class at the ask.
            admitted_u32(bytes.len())
        });
        self.holes.push(Hole { hole_at, interior_at, tail_len });
        Ok(())
    }

    fn close(&mut self, old_len: u32) -> Result<(), u64> {
        debug_assert!(!self.holes.is_empty(), "closes pair with commits");
        // SAFETY: the walk closes only layers it committed, and
        // every commit pushed a hole.
        let hole = unsafe { self.holes.pop().unwrap_unchecked() };
        if hole.tail_len > 0 {
            let start = self.tails.len() - usize_of(hole.tail_len);
            #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
            self.admit(u64::from(hole.tail_len))?;
            self.out.extend_from_slice(&self.tails[start..]);
            self.tails.truncate(start);
        }
        let new_len = self.rel() - hole.interior_at;
        if new_len == old_len {
            // The copied prefix already stands — the optimistic
            // ride paid off (padded source bytes ride verbatim,
            // the fidelity every sibling editor honors).
            return Ok(());
        }
        // Changed length: the prefix re-authors minimally.
        let met = hole.interior_at - hole.hole_at;
        let need = encoded_len32(new_len);
        let hole_abs = self.mark + usize_of(hole.hole_at);
        let interior_abs = self.mark + usize_of(hole.interior_at);
        let count = self.out.len() - interior_abs;
        if need == met {
            // In-place backpatch: the minimal width happens to be
            // the met width — nothing moves.
            let mut window = [0u8; 10];
            let width = emit64(u64::from(new_len), &mut window);
            debug_assert!(width == need);
            self.out[hole_abs..interior_abs].copy_from_slice(&window[..usize_of(need)]);
        } else if need > met {
            let grow = usize_of(need - met);
            #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
            self.admit(grow as u64)?;
            let len_now = self.out.len();
            self.out.reserve(grow);
            // SAFETY: `reserve` provided `grow` spare bytes past
            // `len_now`, so the shifted interior lands inside the
            // allocation; the prefix write covers `need` bytes at
            // `hole_abs`, all below the new length — every byte
            // under the published length is initialized before
            // `set_len`.
            unsafe {
                let ptr = self.out.as_mut_ptr();
                core::ptr::copy(ptr.add(interior_abs), ptr.add(interior_abs + grow), count);
                write64_at(ptr.add(hole_abs), u64::from(new_len), need);
                self.out.set_len(len_now + grow);
            }
        } else {
            // Shrink: the prefix writes first (inside the old met
            // width), then the interior slides left over
            // initialized bytes.
            let shrink = usize_of(met - need);
            let mut window = [0u8; 10];
            let width = emit64(u64::from(new_len), &mut window);
            debug_assert!(width == need);
            self.out[hole_abs..hole_abs + usize_of(need)]
                .copy_from_slice(&window[..usize_of(need)]);
            self.out.copy_within(interior_abs.., interior_abs - shrink);
            self.out.truncate(interior_abs - shrink + count);
        }
        Ok(())
    }
}

// ─── the sink back-end: sealed sparse overlay, range fold ───

/// One overlay instruction, source-ordered. `Hole` is a committed
/// container's claimed prefix slot, rewritten at its close — the
/// fold never sees one.
enum Op {
    /// Copy `input[from..to]`.
    Src { from: u32, to: u32 },
    /// Hand `staging[at..at + len]`.
    Staged { at: u32, len: u32 },
    /// Emit a minimal varint word.
    Word { word: u32 },
    /// An unfilled claim.
    Hole,
}

/// One committed container's plan state.
struct Frame {
    /// New interior length, accumulated (rolled into the parent at
    /// the close, exactly the two-pass rewriter's frame law).
    total: u64,
    head: Coord,
    tag_end: Coord,
    payload_start: Coord,
    /// The claimed `Op::Hole`'s index; `u32::MAX` while the
    /// subtree is still clean (no claim exists yet).
    op: u32,
    /// The staged tail (`len == 0` for none).
    tail_at: u32,
    tail_len: u32,
}

/// The sink face's decision-walk artifact: a sparse source-ordered
/// overlay (edits and dirtied ancestors only — clean subtrees ride
/// inside coalesced source runs), staged authored bytes, and the
/// running output total for the eager cap. Prefix slots
/// materialize outer-to-inner at the first edit under each
/// still-clean ancestor, which keeps the op list source-ordered
/// without a sort and keeps clean commits off the plan entirely.
/// The root is implicit — it has no prefix to claim and no parent
/// to roll into, so no frame exists for it and an identity-shaped
/// job allocates nothing here at all.
pub(super) struct Plan<'i> {
    input: &'i [u8],
    ops: Vec<Op>,
    staging: Vec<u8>,
    /// Committed containers, outermost first (empty at the root).
    frames: Vec<Frame>,
    /// Frames below this index are claimed; claiming is monotone
    /// until the frame pops.
    claimed: usize,
    /// Pending verbatim run, absolute half-open.
    run: Option<(u32, u32)>,
    /// The settled output total so far — the physical length the
    /// Vec faces would hold, judged eagerly so staging offsets
    /// stay in the class.
    total: u64,
}

impl<'i> Plan<'i> {
    pub(super) const fn new(input: &'i [u8]) -> Self {
        Self {
            input,
            ops: Vec::new(),
            staging: Vec::new(),
            frames: Vec::new(),
            claimed: 0,
            run: None,
            total: 0,
        }
    }

    /// The eager cap judgment, mirroring the Vec faces' physical
    /// length exactly (met prefixes count until their close
    /// re-judges them).
    const fn admit(&mut self, grow: u64) -> Result<(), u64> {
        let total = self.total + grow;
        #[allow(clippy::as_conversions, reason = "MAX is far below u64")]
        if total > admission::MAX as u64 {
            return Err(total);
        }
        self.total = total;
        Ok(())
    }

    /// Accounts `grow` bytes into the innermost committed
    /// container's interior. At the root there is nothing to
    /// write: the root has no prefix to settle, so its interior
    /// total serves no reader — the settled output total is
    /// [`Plan::total`].
    fn account(&mut self, grow: u64) {
        if let Some(frame) = self.frames.last_mut() {
            frame.total += grow;
        }
    }

    /// Extends the pending run (coalescing contiguous extents)
    /// without touching the frame accounts — the raw motion under
    /// `verbatim` and `commit`.
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
    /// first: each split peels a source run off the pending run's
    /// left edge and leaves a `Hole` op in its place, so the op
    /// list stays source-ordered with no sort. Called before any
    /// edit lands.
    fn materialize(&mut self) {
        for index in self.claimed..self.frames.len() {
            let (tag_end, payload_start) = {
                let frame = &self.frames[index];
                (frame.tag_end.as_inner(), frame.payload_start.as_inner())
            };
            // A still-clean frame's prefix sits inside the pending
            // run: nothing flushed since before its commit (a
            // flush is an edit, and an edit would have claimed
            // it).
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
        // Staging stays inside the class: every staged byte was
        // admitted into `total` first.
        let at = admitted_u32(self.staging.len());
        self.staging.extend_from_slice(bytes);
        self.ops.push(Op::Staged { at, len: admitted_u32(bytes.len()) });
        #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
        self.account(bytes.len() as u64);
        Ok(())
    }

    /// Hands the sealed overlay's windows over, in source order.
    /// Infallible and rule-free by signature: every fault preceded
    /// the first handoff, and a re-ask is unspellable.
    pub(super) fn fold<F: FnMut(&[u8])>(mut self, sink: &mut F) {
        debug_assert!(self.frames.is_empty(), "every committed layer closed");
        // The pending run is the plan's last extent (every flush
        // precedes every op push), so it hands over directly after
        // the ops — never materialized: an identity-shaped job's
        // whole product is this one window, with zero ops and zero
        // allocation behind it.
        let run = self.run.take();
        let mut handed: u64 = 0;
        for op in &self.ops {
            let window: &[u8] = match *op {
                Op::Src { from, to } => &self.input[usize_of(from)..usize_of(to)],
                Op::Staged { at, len } => &self.staging[usize_of(at)..usize_of(at + len)],
                Op::Word { word } => {
                    let mut window = [0u8; 10];
                    let width = emit64(u64::from(word), &mut window);
                    #[allow(clippy::as_conversions, reason = "widths land in 1..=5")]
                    {
                        handed += u64::from(width);
                    }
                    sink(&window[..usize_of(width)]);
                    continue;
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

impl Back for Plan<'_> {
    fn verbatim(&mut self, from: u32, to: u32) -> Result<(), u64> {
        self.admit(u64::from(to - from))?;
        self.ride(from, to);
        self.account(u64::from(to - from));
        Ok(())
    }

    fn author(&mut self, bytes: &[u8]) -> Result<(), u64> {
        self.edit(bytes)
    }

    fn author_varint(&mut self, word: u64) -> Result<(), u64> {
        let mut window = [0u8; 10];
        let width = emit64(word, &mut window);
        self.edit(&window[..usize_of(width)])
    }

    fn dirty(&mut self) {
        // The dropped extent breaks the pending run by itself (the
        // next verbatim starts past it, so no coalesce) — but the
        // committed ancestors' prefixes must be claimed here: their
        // interiors shrank with no authored emission to claim them.
        self.materialize();
    }

    fn commit(
        &mut self,
        head: u32,
        tag_end: u32,
        payload_start: u32,
        tail: Option<&[u8]>,
    ) -> Result<(), u64> {
        // The head and met prefix ride the run optimistically (a
        // clean close folds the whole record into the surrounding
        // source run); the account mirrors the Vec faces' physical
        // length, so met bytes count now and re-judge at the close.
        self.admit(u64::from(payload_start - head))?;
        // A tail is a committed future emission: its account (and
        // its staging) happens here, so staging offsets stay in
        // the class no matter how deep the commit stack grows.
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
        Ok(())
    }

    fn close(&mut self, old_len: u32) -> Result<(), u64> {
        debug_assert!(!self.frames.is_empty(), "closes pair with commits");
        // A tail dirties its container: claim through this frame
        // before judging cleanliness.
        if self.frames.len() > self.claimed
            && let Some(frame) = self.frames.last()
            && frame.tail_len > 0
        {
            self.materialize();
        }
        // SAFETY: closes pair with commits (asserted above), so a
        // committed frame is on the stack.
        let frame = unsafe { self.frames.pop().unwrap_unchecked() };
        self.claimed = self.claimed.min(self.frames.len());
        if frame.op == u32::MAX {
            // Clean subtree: byte-identical, riding inside the
            // pending run; the whole record rolls into the parent.
            debug_assert!(frame.total == u64::from(old_len) && frame.tail_len == 0);
            self.account(
                u64::from(frame.payload_start.as_inner() - frame.head.as_inner()) + frame.total,
            );
            return Ok(());
        }
        let mut interior = frame.total;
        if frame.tail_len > 0 {
            // The tail lands after the last interior byte, inside
            // the container (its account was taken at the commit).
            self.flush();
            self.ops.push(Op::Staged { at: frame.tail_at, len: frame.tail_len });
            interior += u64::from(frame.tail_len);
        }
        // The interior is a sub-range of the capped output, so it
        // lies inside the LEN class.
        debug_assert!(interior <= u64::from(crate::wire::PayloadLen::MAX.as_inner()));
        #[allow(clippy::as_conversions, reason = "judged inside the LEN class")]
        let new_len = interior as u32;
        let met = frame.payload_start.as_inner() - frame.tag_end.as_inner();
        let width = if new_len == old_len {
            // Unchanged length: the source prefix (met bytes) rides
            // verbatim into the claimed slot.
            self.ops[usize_of(frame.op)] =
                Op::Src { from: frame.tag_end.as_inner(), to: frame.payload_start.as_inner() };
            met
        } else {
            // Changed length: minimal re-author; the account traded
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
}
