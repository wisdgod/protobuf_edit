//! The writer cells' shared edit-script stratum: pass one
//! compiles a source-anchored script, pass two folds it against a
//! fresh walk through a splicing pump that parses nothing, judges
//! nothing, and allocates nothing — its fault alphabet is the
//! supply's own refusals plus length-shape tears anchored on the
//! measured total. `replay_rewrite` compiles it from a path
//! program, `replay_splice` from per-record verdicts,
//! `replay_convert` from its output dialect's re-framing laws;
//! all three meet this one shape.

use alloc::vec::Vec;
#[cfg(any(
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
use alloc::collections::TryReserveError;

use crate::replay_pump::Pump;
use crate::replay_source::{ReplayWalk, StableReplaySource, SupplyFault};
use crate::varint::{encoded_len64, write64_at};
#[cfg(any(
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless"
))]
use crate::varint::encoded_len32;
#[cfg(any(
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless"
))]
use crate::wire::PayloadLen;

/// One splicing step, in source order. `Copy` and `Skip`
/// carry absolute end coordinates; every step's span starts
/// where the previous ended, so the pump's cursor is the one
/// register.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Step<'r> {
    /// Copy source bytes forward to `to` (verbatim extents).
    Copy {
        /// Absolute end of the copied extent.
        to: u64,
    },
    /// Seek the source forward to `to` (dropped extents).
    Skip {
        /// Absolute end of the dropped extent.
        to: u64,
    },
    /// Emit staged arena bytes (authored words and answer copies).
    /// The marks are `usize` because the arena is in-memory: its
    /// length is bounded by the address space, not by any wire
    /// class.
    Staged {
        /// Arena range start.
        start: usize,
        /// Arena range end.
        end: usize,
    },
    /// Emit a job-borrowed payload (rewrite's static rule data;
    /// overhaul's authored payloads, whose owners outlive the
    /// save). Splice answers are staged by copy instead, but the
    /// variant stays in every cut: it is the stratum's one bearer
    /// of `'r`, and a lifetime parameter no variant uses is
    /// refused outright.
    #[cfg_attr(
        not(any(
            feature = "replay-rewrite-grouped",
            feature = "replay-rewrite-groupless",
            feature = "overhaul-grouped",
            feature = "overhaul-groupless",
            feature = "maintain-grouped",
            feature = "maintain-groupless",
            feature = "refit-grouped",
            feature = "refit-groupless",
            feature = "commission-grouped",
            feature = "commission-groupless"
        )),
        expect(
            dead_code,
            reason = "the rewrite, overhaul, maintain, refit, and commission cells \
                      construct it, and a cfg cut is unavailable: the variant is the \
                      one use of `'r` in `Step` and `Script`, so the splice-only \
                      cells would strand the parameter (E0392); the shared fold \
                      spells the arm for every writer cell"
        )
    )]
    Borrowed(&'r [u8]),
    /// Emit a settled container prefix
    /// ([`Script::open_prefix`]). Every single-pass compiler books
    /// one: a fidelity walk opens it over the source prefix's span
    /// (verbatim when the interior length held), a canonical walk
    /// mints it over a zero-width span (always re-authored).
    #[cfg(any(
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
        feature = "replay-convert-groupless",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless"
    ))]
    Prefix(u32),
}

/// One authored container's length prefix, settled at its close:
/// verbatim when the slot spans a source prefix whose interior
/// length held, a minimal re-authored word when it moved — and a
/// *minted* prefix (one the conversion authors where the source
/// carries none) opens over a zero-width span and always settles
/// re-authored, since no source spelling exists to ride. Booked by
/// the single-pass compilers alone, so the slot exists only in
/// their cells. The slot's states ride the `(verbatim, width)`
/// pair: open (`!verbatim`, zero width — booked, not yet settled),
/// settled verbatim (`verbatim`, zero width — the source spelling
/// rides), and settled re-authored (`!verbatim`,
/// `width == encoded_len32(word)` in `1..=5`). Every compiler
/// settles the slots it opened before folding, so the fold reads
/// settled slots alone.
#[cfg(any(
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless"
))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct PrefixSlot {
    /// The source prefix's span (copied when verbatim, sought
    /// past when re-authored; zero-width for a minted prefix —
    /// nothing to copy or seek): the settle prices a verbatim
    /// prefix as `end - start`, and the fold replays to `end`.
    start: u64,
    end: u64,
    /// The re-authored word (the settled interior length).
    word: u64,
    /// The re-authored word's minimal width; zero in the open and
    /// verbatim states.
    width: u8,
    /// True when the interior length held and the source
    /// prefix rides verbatim.
    verbatim: bool,
}

/// The compiled script: steps in source order, the staging
/// arena behind them, the single-pass compilers' prefix slots,
/// and the running output length.
pub(crate) struct Script<'r> {
    steps: Vec<Step<'r>>,
    staged: Vec<u8>,
    #[cfg(any(
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
        feature = "replay-convert-groupless",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless"
    ))]
    prefixes: Vec<PrefixSlot>,
    /// The source cursor the next step must start at.
    cursor: u64,
    /// The output length so far (settled prefixes included as
    /// they settle).
    ///
    /// Boundedness theorem: the sum cannot wrap `u64` on any
    /// admitted program. Every booking derives from an
    /// admission-bounded extent — copy spans and verbatim
    /// prefixes are differences of measured coordinates of one
    /// admitted source (at most `u64::MAX − 1` total, the
    /// coordinate class's own cap), staged ranges and borrowed
    /// payloads are resident in-memory extents (address-space
    /// bounded), and re-authored prefixes are single varint
    /// widths — so the compiled output length is at most the
    /// admitted source length plus the in-memory bytes the job
    /// stages and borrows, a sum far inside the class. The
    /// booking sites carry `checked_add` debug asserts as the
    /// theorem's checked form.
    out_len: u64,
}

impl<'r> Script<'r> {
    /// An empty script; the compilers grow it as they book.
    pub(crate) const fn new() -> Self {
        Self {
            steps: Vec::new(),
            staged: Vec::new(),
            #[cfg(any(
                feature = "replay-rewrite-grouped",
                feature = "replay-rewrite-groupless",
                feature = "replay-convert-grouped",
                feature = "replay-convert-groupless",
                feature = "replay-splice-grouped",
                feature = "replay-splice-groupless",
                feature = "maintain-grouped",
                feature = "maintain-groupless",
                feature = "commission-grouped",
                feature = "commission-groupless",
                feature = "refit-grouped",
                feature = "refit-groupless",
                feature = "overhaul-grouped",
                feature = "overhaul-groupless"
            ))]
            prefixes: Vec::new(),
            cursor: 0,
            out_len: 0,
        }
    }

    /// The output length compiled so far.
    pub(crate) const fn out_len(&self) -> u64 {
        self.out_len
    }

    /// Copies source bytes `[cursor, to)` into the output
    /// (adjacent copies coalesce, so an identity job is one
    /// step).
    pub(crate) fn copy_to(&mut self, to: u64) {
        debug_assert!(to >= self.cursor, "steps run in source order");
        if to == self.cursor {
            return;
        }
        debug_assert!(
            self.out_len.checked_add(to - self.cursor).is_some(),
            "admission bounds out_len (the field's theorem)"
        );
        self.out_len += to - self.cursor;
        self.cursor = to;
        if let Some(Step::Copy { to: last }) = self.steps.last_mut() {
            *last = to;
            return;
        }
        self.steps.push(Step::Copy { to });
    }

    /// Seeks the source forward to `to`, emitting nothing
    /// (adjacent skips coalesce).
    pub(crate) fn skip_to(&mut self, to: u64) {
        debug_assert!(to >= self.cursor, "steps run in source order");
        if to == self.cursor {
            return;
        }
        self.cursor = to;
        if let Some(Step::Skip { to: last }) = self.steps.last_mut() {
            *last = to;
            return;
        }
        self.steps.push(Step::Skip { to });
    }

    /// Emits `word` at its minimal varint width (adjacent
    /// staged ranges coalesce).
    pub(crate) fn stage_word(&mut self, word: u64) {
        let width = encoded_len64(word);
        let at = self.staged.len();
        self.staged.resize(at + crate::admission::usize_of(width), 0);
        // SAFETY: the resize reserved exactly `width` bytes at
        // `at`, and `width` is the word's own encoded length.
        unsafe { write64_at(self.staged.as_mut_ptr().add(at), word, width) };
        self.stage_mark(at);
    }

    /// Emits raw staged bytes (fixed-width bits, answer copies).
    /// The convert cells author varint words alone
    /// ([`Script::stage_word`]), so the face compiles with the
    /// byte-staging writers.
    #[cfg(any(
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless"
    ))]
    pub(crate) fn stage_bytes(&mut self, bytes: &[u8]) {
        let at = self.staged.len();
        self.staged.extend_from_slice(bytes);
        self.stage_mark(at);
    }

    /// Books the staged range `[at, len)` as a step, merging
    /// with a trailing staged step.
    #[allow(clippy::as_conversions, reason = "usize widens losslessly into u64")]
    fn stage_mark(&mut self, at: usize) {
        let end = self.staged.len();
        debug_assert!(
            self.out_len.checked_add((end - at) as u64).is_some(),
            "admission bounds out_len (the field's theorem)"
        );
        self.out_len += (end - at) as u64;
        if let Some(Step::Staged { end: last, .. }) = self.steps.last_mut()
            && *last == at
        {
            *last = end;
            return;
        }
        self.steps.push(Step::Staged { start: at, end });
    }

    /// Copies answer bytes into the staging arena without booking
    /// a step — a committed container's tail is staged by copy at
    /// its ask and lands at the close ([`Script::emit_stashed`]).
    #[cfg(any(feature = "replay-splice-grouped", feature = "replay-splice-groupless"))]
    pub(crate) fn stash(&mut self, bytes: &[u8]) -> (usize, usize) {
        let at = self.staged.len();
        self.staged.extend_from_slice(bytes);
        (at, self.staged.len())
    }

    /// Books a stashed arena range as a step at the current output
    /// position (adjacent staged ranges coalesce).
    #[cfg(any(feature = "replay-splice-grouped", feature = "replay-splice-groupless"))]
    #[allow(clippy::as_conversions, reason = "usize widens losslessly into u64")]
    pub(crate) fn emit_stashed(&mut self, start: usize, end: usize) {
        if start == end {
            return;
        }
        debug_assert!(
            self.out_len.checked_add((end - start) as u64).is_some(),
            "admission bounds out_len (the field's theorem)"
        );
        self.out_len += (end - start) as u64;
        if let Some(Step::Staged { end: last, .. }) = self.steps.last_mut()
            && *last == start
        {
            *last = end;
            return;
        }
        self.steps.push(Step::Staged { start, end });
    }

    /// Emits a job-borrowed payload.
    #[cfg(any(
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless"
    ))]
    pub(crate) fn borrow(&mut self, bytes: &'r [u8]) {
        #[allow(
            clippy::as_conversions,
            reason = "rule payloads were admitted to the LEN class, which fits u64"
        )]
        {
            debug_assert!(
                self.out_len.checked_add(bytes.len() as u64).is_some(),
                "admission bounds out_len (the field's theorem)"
            );
            self.out_len += bytes.len() as u64;
        }
        self.steps.push(Step::Borrowed(bytes));
    }

    /// Opens a container's prefix slot over its source span;
    /// the close settles it. The output length is booked at
    /// the settle (the width is unknown here).
    #[cfg(any(
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless"
    ))]
    #[allow(
        clippy::as_conversions,
        reason = "one slot per committed container, admitted far below u32 by the \
                  depth-bounded walk"
    )]
    pub(crate) fn open_prefix(&mut self, start: u64, end: u64) -> u32 {
        debug_assert!(start == self.cursor, "the prefix follows the copied tag");
        let slot = self.prefixes.len() as u32;
        self.prefixes.push(PrefixSlot { start, end, word: 0, width: 0, verbatim: false });
        self.steps.push(Step::Prefix(slot));
        self.cursor = end;
        slot
    }

    /// Settles a container's prefix at its close: verbatim
    /// when the interior length held, a minimal re-authored
    /// word when it moved.
    ///
    /// # Errors
    ///
    /// The settled interior length when it outgrew the LEN
    /// class.
    #[cfg(any(
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless"
    ))]
    pub(crate) fn settle_prefix(
        &mut self,
        slot: u32,
        interior: u64,
        declared: u64,
    ) -> Result<(), u64> {
        let entry = &mut self.prefixes[crate::admission::usize_of(slot)];
        if interior == declared {
            entry.verbatim = true;
            debug_assert!(
                self.out_len.checked_add(entry.end - entry.start).is_some(),
                "admission bounds out_len (the field's theorem)"
            );
            self.out_len += entry.end - entry.start;
            return Ok(());
        }
        if interior > u64::from(PayloadLen::MAX.as_inner()) {
            return Err(interior);
        }
        entry.word = interior;
        #[allow(
            clippy::as_conversions,
            reason = "the settled interior was just judged inside the LEN class"
        )]
        {
            entry.width = encoded_len32(interior as u32) as u8;
        }
        entry.verbatim = false;
        debug_assert!(
            self.out_len.checked_add(u64::from(entry.width)).is_some(),
            "admission bounds out_len (the field's theorem)"
        );
        self.out_len += u64::from(entry.width);
        Ok(())
    }

    /// Opens a minted prefix slot — a container the conversion
    /// authors where the source carries none, so the slot's source
    /// span is zero-width at the cursor; the close settles it.
    /// The output length is booked at the settle (the width is
    /// unknown here).
    #[cfg(any(
        feature = "replay-convert-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless"
    ))]
    #[allow(
        clippy::as_conversions,
        reason = "one slot per authored container, admitted far below u32 by the \
                  depth-bounded walk"
    )]
    pub(crate) fn open_minted_prefix(&mut self) -> u32 {
        let slot = self.prefixes.len() as u32;
        self.prefixes.push(PrefixSlot {
            start: self.cursor,
            end: self.cursor,
            word: 0,
            width: 0,
            verbatim: false,
        });
        self.steps.push(Step::Prefix(slot));
        slot
    }

    /// Settles a minted prefix at its container's close: always a
    /// minimal re-authored word — a zero-width source span has no
    /// spelling to ride verbatim — through the same slot layout
    /// and fold arm as a resized prefix.
    ///
    /// # Errors
    ///
    /// The settled interior length when it outgrew the LEN class.
    #[cfg(any(
        feature = "replay-convert-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless"
    ))]
    pub(crate) fn settle_minted_prefix(&mut self, slot: u32, interior: u64) -> Result<(), u64> {
        let entry = &mut self.prefixes[crate::admission::usize_of(slot)];
        debug_assert!(entry.start == entry.end, "minted prefixes span nothing");
        if interior > u64::from(PayloadLen::MAX.as_inner()) {
            return Err(interior);
        }
        entry.word = interior;
        #[allow(
            clippy::as_conversions,
            reason = "the settled interior was just judged inside the LEN class"
        )]
        {
            entry.width = encoded_len32(interior as u32) as u8;
        }
        entry.verbatim = false;
        debug_assert!(
            self.out_len.checked_add(u64::from(entry.width)).is_some(),
            "admission bounds out_len (the field's theorem)"
        );
        self.out_len += u64::from(entry.width);
        Ok(())
    }
}

/// The per-edge fallible booking faces: the same coalescing
/// bookkeeping as the infallible twins, each edge behind its own
/// reservation, so a refused allocation surfaces as a structured
/// `Err` before anything is booked and the script stays exactly
/// as it was (a merged booking leaves its reserved slot as spare
/// capacity, never a missing one).
#[cfg(any(
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
impl<'r> Script<'r> {
    /// [`Script::copy_to`] behind a one-slot step reservation.
    ///
    /// # Errors
    ///
    /// The allocator's refusal; the script is unchanged.
    pub(crate) fn try_copy_to(&mut self, to: u64) -> Result<(), TryReserveError> {
        self.steps.try_reserve(1)?;
        self.copy_to(to);
        Ok(())
    }

    /// [`Script::skip_to`] behind a one-slot step reservation.
    ///
    /// # Errors
    ///
    /// The allocator's refusal; the script is unchanged.
    pub(crate) fn try_skip_to(&mut self, to: u64) -> Result<(), TryReserveError> {
        self.steps.try_reserve(1)?;
        self.skip_to(to);
        Ok(())
    }

    /// [`Script::stage_word`] behind reservations covering the
    /// word's width and one step slot.
    ///
    /// # Errors
    ///
    /// The allocator's refusal of either column; the script is
    /// unchanged.
    pub(crate) fn try_stage_word(&mut self, word: u64) -> Result<(), TryReserveError> {
        self.staged.try_reserve(crate::admission::usize_of(encoded_len64(word)))?;
        self.steps.try_reserve(1)?;
        self.stage_word(word);
        Ok(())
    }

    /// [`Script::stage_bytes`] behind reservations covering the
    /// bytes and one step slot.
    ///
    /// # Errors
    ///
    /// The allocator's refusal of either column; the script is
    /// unchanged.
    pub(crate) fn try_stage_bytes(&mut self, bytes: &[u8]) -> Result<(), TryReserveError> {
        self.staged.try_reserve(bytes.len())?;
        self.steps.try_reserve(1)?;
        self.stage_bytes(bytes);
        Ok(())
    }

    /// [`Script::borrow`] behind a one-slot step reservation.
    ///
    /// # Errors
    ///
    /// The allocator's refusal; the script is unchanged.
    pub(crate) fn try_borrow(&mut self, bytes: &'r [u8]) -> Result<(), TryReserveError> {
        self.steps.try_reserve(1)?;
        self.borrow(bytes);
        Ok(())
    }

    /// [`Script::open_prefix`] behind one-slot reservations on
    /// both columns.
    ///
    /// # Errors
    ///
    /// The allocator's refusal of either column; the script is
    /// unchanged.
    #[cfg(any(
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless"
    ))]
    pub(crate) fn try_open_prefix(&mut self, start: u64, end: u64) -> Result<u32, TryReserveError> {
        self.steps.try_reserve(1)?;
        self.prefixes.try_reserve(1)?;
        Ok(self.open_prefix(start, end))
    }

    /// [`Script::open_minted_prefix`] behind one-slot reservations
    /// on both columns.
    ///
    /// # Errors
    ///
    /// The allocator's refusal of either column; the script is
    /// unchanged.
    #[cfg(any(feature = "maintain-grouped", feature = "maintain-groupless"))]
    pub(crate) fn try_open_minted_prefix(&mut self) -> Result<u32, TryReserveError> {
        self.steps.try_reserve(1)?;
        self.prefixes.try_reserve(1)?;
        Ok(self.open_minted_prefix())
    }
}

/// A splicing-pump refusal: the supply's own, or a
/// length-shaped tear against the measured coordinates.
pub(crate) enum FoldFault<E> {
    /// Starting the emission walk refused.
    Rewind(SupplyFault<E>),
    /// The supply refused mid-emission.
    Source {
        /// The first unread source offset.
        at: u64,
        /// The provider's refusal.
        source: SupplyFault<E>,
    },
    /// The walk met its end before a measured coordinate, or
    /// ran past the measured total.
    Torn {
        /// The measured coordinate the walk could not honor.
        at: u64,
    },
}

/// Folds the script against a fresh walk, handing output
/// views to `deliver` — the splicing pump: no parse, no
/// judgment, no machine allocation. `total` is the measuring
/// walk's end coordinate; the fold must meet the source's end
/// exactly there (one end probe after the last step).
///
/// # Errors
///
/// [`FoldFault`]; everything already delivered stands
/// (publication custody is the calling face's story).
pub(crate) fn fold<S: StableReplaySource>(
    source: &mut S,
    script: &Script<'_>,
    total: u64,
    deliver: &mut impl FnMut(&[u8]),
) -> Result<(), FoldFault<S::Error>> {
    let walk = match source.begin() {
        Ok(walk) => walk,
        Err(fault) => return Err(FoldFault::Rewind(fault)),
    };
    let mut pump = Pump::new(walk);
    for step in &script.steps {
        match *step {
            Step::Copy { to } => copy(&mut pump, to, deliver)?,
            Step::Skip { to } => seek(&mut pump, to)?,
            Step::Staged { start, end } => deliver(&script.staged[start..end]),
            Step::Borrowed(bytes) => deliver(bytes),
            #[cfg(any(
                feature = "replay-rewrite-grouped",
                feature = "replay-rewrite-groupless",
                feature = "replay-convert-grouped",
                feature = "replay-convert-groupless",
                feature = "replay-splice-grouped",
                feature = "replay-splice-groupless",
                feature = "maintain-grouped",
                feature = "maintain-groupless",
                feature = "commission-grouped",
                feature = "commission-groupless",
                feature = "refit-grouped",
                feature = "refit-groupless",
                feature = "overhaul-grouped",
                feature = "overhaul-groupless"
            ))]
            Step::Prefix(slot) => {
                let entry = script.prefixes[crate::admission::usize_of(slot)];
                if entry.verbatim {
                    copy(&mut pump, entry.end, deliver)?;
                } else {
                    seek(&mut pump, entry.end)?;
                    let mut stage = [0u8; 10];
                    // SAFETY: the stack buffer holds ten
                    // writable bytes and the settle minted the
                    // width as the word's own encoded length.
                    unsafe {
                        write64_at(stage.as_mut_ptr(), entry.word, u32::from(entry.width));
                    }
                    deliver(&stage[..usize::from(entry.width)]);
                }
            }
        }
    }
    // The end probe: the measured total is the anchor — a
    // walk still holding bytes there has grown.
    match pump.probe_more() {
        Ok(false) => Ok(()),
        Ok(true) => Err(FoldFault::Torn { at: total }),
        Err(fault) => Err(FoldFault::Source { at: pump.off, source: fault }),
    }
}

/// One copied extent, view by view.
fn copy<W: ReplayWalk>(
    pump: &mut Pump<W>,
    to: u64,
    deliver: &mut impl FnMut(&[u8]),
) -> Result<(), FoldFault<W::Error>> {
    let owed = to - pump.off;
    match pump.copy_bytes(owed, deliver) {
        Ok(advanced) if advanced == owed => Ok(()),
        Ok(_) => Err(FoldFault::Torn { at: to }),
        Err(fault) => Err(FoldFault::Source { at: pump.off, source: fault }),
    }
}

/// One dropped extent, sought past.
fn seek<W: ReplayWalk>(pump: &mut Pump<W>, to: u64) -> Result<(), FoldFault<W::Error>> {
    let owed = to - pump.off;
    match pump.skip_bytes(owed) {
        Ok(advanced) if advanced == owed => Ok(()),
        Ok(_) => Err(FoldFault::Torn { at: to }),
        Err(fault) => Err(FoldFault::Source { at: pump.off, source: fault }),
    }
}

#[cfg(all(
    test,
    any(
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless"
    )
))]
mod tests {
    use super::*;

    /// Books one program crossing every coalescing boundary of
    /// the revisable face cut; the per-edge fallible booking must
    /// agree with it.
    fn book(script: &mut Script<'static>) {
        script.copy_to(4);
        script.copy_to(9); // merges
        script.skip_to(12);
        script.skip_to(20); // merges
        script.copy_to(20); // zero-length
        script.skip_to(20); // zero-length
        script.stage_word(0x96); // two staged bytes
        script.copy_to(20); // zero-length: the staged tail holds
        script.stage_bytes(&[1, 2, 3]); // merges into the staged tail
        script.borrow(&[7, 7]); // separator
        script.stage_word(1); // fresh staged step
        script.copy_to(33);
    }

    #[test]
    fn the_per_edge_twins_book_the_same_script() {
        let mut plain = Script::new();
        book(&mut plain);
        let mut twin = Script::new();
        twin.try_copy_to(4).unwrap();
        twin.try_copy_to(9).unwrap();
        twin.try_skip_to(12).unwrap();
        twin.try_skip_to(20).unwrap();
        twin.try_copy_to(20).unwrap();
        twin.try_skip_to(20).unwrap();
        twin.try_stage_word(0x96).unwrap();
        twin.try_copy_to(20).unwrap();
        twin.try_stage_bytes(&[1, 2, 3]).unwrap();
        twin.try_borrow(&[7, 7]).unwrap();
        twin.try_stage_word(1).unwrap();
        twin.try_copy_to(33).unwrap();
        assert_eq!(alloc::format!("{:?}", twin.steps), alloc::format!("{:?}", plain.steps));
        assert_eq!(twin.staged, plain.staged);
        assert_eq!((twin.cursor, twin.out_len()), (plain.cursor, plain.out_len()));
    }
}
