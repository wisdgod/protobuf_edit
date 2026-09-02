//! The carry kernel: one primitive construct reassembled across
//! chunk boundaries, bounded by the innermost sealed extent.
//!
//! A streamed construct (tag, varint ≤ 10 B, fixed payload ≤ 8 B)
//! can be cut by a chunk boundary — recoverable, more bytes may
//! arrive — or by a sealed extent end — terminal: no future byte
//! belongs to it. The kernel keeps the two apart ([`Step::More`]
//! vs [`Step::Cut`]), which is what makes verdicts independent of
//! chunking. Skips are not carried (pure counting is the consumer's
//! loop); only the one construct in flight lives here.
//!
//! Width-tolerant, forgery-strict (module doc of [`crate::varint`]).
//! Completion is a typestate, not a prose phase: `Done` delivers a
//! [`Complete`] witness that exclusively owns the held bytes, so the
//! byte-faithful consumers (transcoders) read the exact source
//! encoding through it, and stepping again before the witness is
//! consumed refuses to compile.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::varint::carry::{Carry, Step};
//!
//! // 150 split across two chunks: the boundary never shows in the
//! // verdict.
//! let mut carry = Carry::new();
//! let mut off = 0u64;
//! let mut chunk: &[u8] = &[0x96];
//! assert!(matches!(carry.step_value64(&mut chunk, &mut off, u64::MAX), Step::More));
//! let mut next: &[u8] = &[0x01];
//! match carry.step_value64(&mut next, &mut off, u64::MAX) {
//!     Step::Done(complete) => {
//!         assert_eq!(complete.bytes(), [0x96, 0x01]); // the exact source encoding
//!         assert_eq!(complete.take(), 150); // consume: the carry is empty again
//!     }
//!     other => panic!("the terminal byte arrived: {other:?}"),
//! }
//! assert!(carry.is_empty());
//! ```

use core::mem::MaybeUninit;

use super::{CONT_BIT, LAST_LEN, LAST32, LAST64, MAX_LEN32, MAX_LEN64, PAYLOAD_BITS, PAYLOAD_MASK};
use crate::wire::PayloadLen;

/// Outcome of stepping a varint.
///
/// The domain faces instantiate `T` with a [`Complete`] witness, so
/// a completed construct cannot be left half-consumed; the fault
/// arms leave the refused construct held in the carry (its length
/// is the fault coordinate's width) — [`Carry::clear`] discards it.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step<T> {
    /// Terminated; the payload owns the construct until consumed.
    Done(T),
    /// The chunk ran out first; feed the next one.
    More,
    /// The sealed extent ended mid-construct. Terminal.
    Cut,
    /// Ran past the domain window still continuing.
    TooWide,
    /// The terminal byte at full width exceeds the domain class.
    OutOfClass,
}

/// The completion witness: exclusive ownership of the one completed
/// construct the carry holds, minted by the domain steppers' `Done`.
///
/// While the witness lives, the carry is exclusively borrowed — a
/// further step is a compile error, so a completed construct cannot
/// silently merge into the next one. Consumption is the only path
/// back to a step-capable state: [`Complete::take`] delivers the
/// value and empties the carry, and dropping the witness empties it
/// likewise (discarding the value). Until then the held faces read
/// the construct: [`Complete::bytes`] is the exact source encoding
/// (the byte-faithful re-emission supply) and [`Complete::width`]
/// its width.
#[must_use = "a completed construct must be consumed (take or drop) before the next step"]
pub struct Complete<'c, T: Copy> {
    carry: &'c mut Carry,
    value: T,
}

impl<T: Copy> Complete<'_, T> {
    /// The assembled value, the construct still held.
    #[inline]
    #[must_use]
    pub const fn value(&self) -> T {
        self.value
    }

    /// The construct's source width in bytes.
    #[inline]
    #[must_use]
    pub const fn width(&self) -> u8 {
        self.carry.len()
    }

    /// The construct's exact source encoding.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.carry.bytes()
    }

    /// Consumes the construct: the value out, the carry emptied.
    #[inline]
    #[must_use]
    pub fn take(self) -> T {
        self.value
    }

    /// Releases the witness with the construct left held — the
    /// pumps' fault path: a post-completion refusal (canonical
    /// minimality) keeps the bytes in the carry so the fault
    /// coordinate can subtract the construct's width. The holder
    /// latches terminal or clears before any further step; a step
    /// over a retained completion is the sequencing breach the
    /// steppers' debug assertion names. The pumps are the only
    /// consumers, so the face compiles with their cells.
    #[cfg(any(
        test,
        feature = "scan-grouped",
        feature = "scan-groupless",
        feature = "route-grouped",
        feature = "route-groupless",
        feature = "rewire-grouped",
        feature = "rewire-groupless",
        feature = "transcode-grouped",
        feature = "transcode-groupless"
    ))]
    #[inline]
    pub(crate) const fn retain(self) {
        core::mem::forget(self);
    }
}

impl<T: Copy> Drop for Complete<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.carry.clear();
    }
}

impl<T: Copy + core::fmt::Debug> core::fmt::Debug for Complete<'_, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Complete")
            .field("value", &self.value)
            .field("bytes", &self.bytes())
            .finish()
    }
}

/// Outcome of collecting a fixed-width payload.
#[cfg(any(
    test,
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless",
    feature = "survey-grouped",
    feature = "survey-groupless",
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Collect {
    /// All bytes are in the carry.
    Done,
    /// The chunk ran out first; feed the next one.
    More,
    /// The sealed extent ended mid-payload. Terminal.
    Cut,
}

/// The kernel windows in the stepper's parameter type, pinned to
/// the theorem constants.
const CAP32: u8 = 5;
const CAP64: u8 = 10;
#[allow(
    clippy::as_conversions,
    reason = "widening the pinned window widths for the theorem-constant tie; \
              const `From` is unavailable"
)]
const _: () = assert!(CAP32 as u32 == MAX_LEN32 && CAP64 as u32 == MAX_LEN64);

// Layout pins for the completion typestate: the witness is a
// pointer and the value (16 B), no field lands in the carry
// itself, and the plain verdict keeps its shape. The
// witness-bearing verdict spells its discriminant in a third word;
// the domain steppers and every pump face are inline-forced, so
// the composed form is a register question, not a stored one.
const _: () = assert!(core::mem::size_of::<Carry>() == 24);
const _: () = assert!(core::mem::size_of::<Complete<'static, u64>>() == 16);
const _: () = assert!(core::mem::size_of::<Step<u64>>() == 16);
const _: () = assert!(core::mem::size_of::<Step<Complete<'static, u64>>>() == 24);

/// The construct in flight: at most ten bytes, reassembled here.
///
/// One construct at a time, carried by the types: a stepper's
/// `Done` is a [`Complete`] witness whose exclusive borrow makes a
/// further step unrepresentable until the completion is consumed —
/// this refuses to compile:
///
/// ```compile_fail,E0499
/// use protobuf_edit::varint::carry::{Carry, Step};
///
/// let mut carry = Carry::new();
/// let mut off = 0u64;
/// let mut chunk: &[u8] = &[0x01, 0x02];
/// let Step::Done(first) = carry.step_value64(&mut chunk, &mut off, u64::MAX) else {
///     panic!("one byte terminates");
/// };
/// // A second step while the completion is unconsumed: refused —
/// // it would silently merge two constructs into one reading.
/// let second = carry.step_value64(&mut chunk, &mut off, u64::MAX);
/// assert_eq!(first.take(), 1);
/// ```
///
/// Two contract clauses remain prose. First: handle a closed
/// extent — move `off` past `zone_end` or open the next extent —
/// before stepping again; a fresh construct never starts at a
/// sealed boundary, and a step taken there reports `Cut`, the
/// verdict for a construct the extent cut, not for a cleanly
/// closed one. Second: `off ≤ zone_end` is every step's and
/// collection's precondition (debug-asserted) — handling the
/// closed extent first is exactly what establishes it.
/// The crate-internal fixed-width collection carries its sequencing
/// in its own unsafe contract.
///
/// Invariants: `buf[..len]` is initialized (every write precedes
/// its `len` raise) with `len ≤ 10`, and `acc` holds the assembled
/// payload bits of the loop-fed bytes — so a varint's completion
/// never re-reads the buffer.
#[derive(Clone, Copy)]
pub struct Carry {
    /// Assembled payload bits of the varint in flight.
    acc: u64,
    buf: [MaybeUninit<u8>; 10],
    len: u8,
}

impl Default for Carry {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Carry {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Carry").field("bytes", &self.bytes()).finish()
    }
}

impl Carry {
    /// An empty carry.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { acc: 0, buf: [MaybeUninit::uninit(); 10], len: 0 }
    }

    /// Bytes carried so far (a completed construct's exact source
    /// encoding — the byte-faithful re-emission supply).
    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "the byte count widens losslessly into usize")]
    pub const fn bytes(&self) -> &[u8] {
        // SAFETY: `buf[..len]` is initialized and `len ≤ 10` — the
        // type invariant both writers maintain (`step` caps at
        // `CAP ≤ 10`, `collect` at `need ≤ 10`).
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr().cast::<u8>(), self.len as usize) }
    }

    /// Carried byte count (a completed varint's width).
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// True when nothing is in flight.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Discards the held construct: the fault-recovery face (a
    /// refused construct stays held for its coordinates until the
    /// holder is done quoting it). Completions consume through
    /// [`Complete`] instead.
    #[inline]
    pub const fn clear(&mut self) {
        self.acc = 0;
        self.len = 0;
    }

    /// Continues the varint in flight with bytes from `chunk`,
    /// consuming what it takes and advancing `off`. Consumption is
    /// bounded by `zone_end`: a construct never reads across a
    /// sealed extent (pass `u64::MAX` for the unbounded root).
    /// Precondition, debug-asserted: `*off ≤ zone_end` — the
    /// boundary tests are equalities, so a position already past
    /// the seal is outside the contract. Release builds carry no
    /// entry guard by decision: the machines' cascades establish
    /// the precondition before every step, and a guard costs
    /// instructions on the outlined faces.
    /// The window cap and terminal-class bound are wire facts owned
    /// by the typed domain steppers below — const parameters, so
    /// the buffer bound is proven at compile time.
    ///
    /// Forced inline: the machines dispatch one step per construct,
    /// and with the resumable loop outlined the hot fold is small
    /// enough to live inside their drive loops.
    #[inline(always)]
    #[allow(
        clippy::as_conversions,
        reason = "byte and width widenings are lossless; const `From` is unavailable"
    )]
    const fn step<const CAP: u8, const LAST_MAX: u8>(
        &mut self,
        chunk: &mut &[u8],
        off: &mut u64,
        zone_end: u64,
    ) -> Step<u64> {
        const { assert!(CAP <= 10) };
        debug_assert!(*off <= zone_end, "carry step: position past the sealed endpoint");
        // A held terminal byte below the window cap is a completed
        // (or class-refused) construct someone retained and then
        // stepped over — the sequencing breach the completion
        // witness exists to prevent; reachable only through the
        // crate-internal retain face or a leaked witness.
        debug_assert!(
            self.len == 0 || self.len == CAP || self.bytes()[self.len as usize - 1] >= CONT_BIT,
            "carry step: a held completion was not consumed"
        );
        // The hot body: a fresh construct whose visible window the
        // chunk covers whole — the overwhelming case of buffered
        // and large-chunk traffic. The fold walks the slice with no
        // per-byte cursor bookkeeping: the source bytes bank into
        // the buffer as they fold (the held contract and the fault
        // coordinate both read `len`), and off/chunk advance once.
        // `More` cannot happen here (the chunk covers the window),
        // so `acc` stays untouched — every exit is `Done` or
        // terminal, and `clear` re-zeroes before the next
        // construct. Everything else — a construct resumed from an
        // earlier chunk, or a window the chunk cuts short — takes
        // the outlined resumable loop, byte-for-byte equivalent
        // (pinned by test).
        if self.len == 0 {
            let window = zone_end - *off;
            let cap = if (CAP as u64) <= window { CAP } else { window as u8 };
            if cap > 0 && cap as usize <= chunk.len() {
                let mut value: u64 = 0;
                let mut i: u8 = 0;
                let mut byte: u8 = 0;
                let width = loop {
                    if i == cap {
                        break 0;
                    }
                    byte = chunk[i as usize];
                    self.buf[i as usize] = MaybeUninit::new(byte);
                    value |= ((byte as u64) & PAYLOAD_MASK) << (PAYLOAD_BITS * i as u32);
                    i += 1;
                    if byte < CONT_BIT {
                        break i;
                    }
                };
                self.len = i;
                *off += i as u64;
                let (_, rest) = chunk.split_at(i as usize);
                *chunk = rest;
                if width == 0 {
                    // No terminator inside the window: the domain
                    // cap makes it too wide, the sealed extent's
                    // edge makes it cut.
                    return if cap == CAP { Step::TooWide } else { Step::Cut };
                }
                // `byte` is the construct's terminal byte here.
                if width == CAP && byte > LAST_MAX {
                    return Step::OutOfClass;
                }
                return Step::Done(value);
            }
        }
        self.step_resumable::<CAP, LAST_MAX>(chunk, off, zone_end)
    }

    /// The resumable loop: constructs continued across chunks, and
    /// fresh ones whose window the chunk cuts short. Cold and
    /// outlined — chunk edges are rare against constructs — so the
    /// hot fold in [`Carry::step`] stays small enough to live
    /// inside the machines' drive loops; that the split keeps the
    /// fold inlined there is a standing obligation of the
    /// performance epoch's instruments.
    #[cold]
    #[inline(never)]
    #[allow(
        clippy::as_conversions,
        reason = "byte and width widenings are lossless; const `From` is unavailable"
    )]
    const fn step_resumable<const CAP: u8, const LAST_MAX: u8>(
        &mut self,
        chunk: &mut &[u8],
        off: &mut u64,
        zone_end: u64,
    ) -> Step<u64> {
        while self.len < CAP {
            // Equality suffices under the entry precondition
            // (`off ≤ zone_end`): consumption advances one byte at
            // a time, so the boundary cannot be stepped over.
            if *off == zone_end {
                return Step::Cut;
            }
            let Some((&byte, rest)) = chunk.split_first() else {
                return Step::More;
            };
            *chunk = rest;
            // In bounds by the loop guard: `len < CAP ≤ 10`.
            self.buf[self.len as usize] = MaybeUninit::new(byte);
            self.acc |= ((byte as u64) & PAYLOAD_MASK) << (PAYLOAD_BITS * self.len as u32);
            self.len += 1;
            *off += 1;
            if byte < CONT_BIT {
                if self.len == CAP && byte > LAST_MAX {
                    return Step::OutOfClass;
                }
                return Step::Done(self.acc);
            }
        }
        Step::TooWide
    }

    /// The tag domain: five bytes, fifth byte ≤ `0x0F`. `Done` is
    /// the [`Complete`] witness over the assembled word.
    ///
    /// A step consumes from the front of `chunk` and advances `*off`
    /// by exactly the bytes taken. `zone_end` is the innermost sealed
    /// extent's exclusive end in `off`'s coordinate space: the
    /// construct never reads at or past it (a construct the seal cuts
    /// reports [`Step::Cut`]) — pass `u64::MAX` when no extent bounds
    /// the construct (the unbounded root).
    ///
    /// # Panics
    ///
    /// In debug builds, when `*off > zone_end` — a cursor already
    /// past the sealed endpoint is a caller bug the release build
    /// trusts by contract.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::varint::carry::{Carry, Step};
    ///
    /// let mut carry = Carry::new();
    /// let mut off = 0u64;
    /// let mut chunk: &[u8] = &[0x08, 0x96, 0x01];
    /// match carry.step_tag(&mut chunk, &mut off, u64::MAX) {
    ///     Step::Done(complete) => assert_eq!(complete.take(), 8), // field 1, code 0
    ///     other => panic!("a one-byte tag completes: {other:?}"),
    /// }
    /// // Consumption advanced past the tag; the value bytes remain.
    /// assert_eq!((off, chunk), (1, &[0x96, 0x01][..]));
    /// ```
    #[inline]
    #[allow(
        clippy::as_conversions,
        reason = "four full payload bytes and a fifth capped at 0x0F land exactly in u32"
    )]
    pub const fn step_tag<'c>(
        &'c mut self,
        chunk: &mut &[u8],
        off: &mut u64,
        zone_end: u64,
    ) -> Step<Complete<'c, u32>> {
        match self.step::<CAP32, LAST32>(chunk, off, zone_end) {
            Step::Done(value) => Step::Done(Complete { carry: self, value: value as u32 }),
            Step::More => Step::More,
            Step::Cut => Step::Cut,
            Step::TooWide => Step::TooWide,
            Step::OutOfClass => Step::OutOfClass,
        }
    }

    /// The LEN length domain: five bytes, class `0..=2^31 - 1`. The
    /// class judgment is delivered as the type, inside the
    /// [`Complete`] witness.
    ///
    /// A step consumes from the front of `chunk` and advances `*off`
    /// by exactly the bytes taken. `zone_end` is the innermost sealed
    /// extent's exclusive end in `off`'s coordinate space: the
    /// construct never reads at or past it (a construct the seal cuts
    /// reports [`Step::Cut`]) — pass `u64::MAX` when no extent bounds
    /// the construct (the unbounded root).
    ///
    /// # Panics
    ///
    /// In debug builds, when `*off > zone_end` — a cursor already
    /// past the sealed endpoint is a caller bug the release build
    /// trusts by contract.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::varint::carry::{Carry, Step};
    ///
    /// let mut carry = Carry::new();
    /// let mut off = 0u64;
    /// let mut chunk: &[u8] = &[0x03, b'a', b'b', b'c'];
    /// match carry.step_len(&mut chunk, &mut off, u64::MAX) {
    ///     Step::Done(complete) => assert_eq!(complete.take().as_inner(), 3),
    ///     other => panic!("expected a complete length: {other:?}"),
    /// }
    /// ```
    #[inline]
    #[allow(
        clippy::as_conversions,
        reason = "four full payload bytes and a fifth capped at 0x07 land inside the length class"
    )]
    pub const fn step_len<'c>(
        &'c mut self,
        chunk: &mut &[u8],
        off: &mut u64,
        zone_end: u64,
    ) -> Step<Complete<'c, PayloadLen>> {
        match self.step::<CAP32, LAST_LEN>(chunk, off, zone_end) {
            Step::Done(value) => {
                // SAFETY: four full payload bytes carry 28 bits and
                // the fifth is capped at 0x07, so the value is at
                // most 0x7FFF_FFFF — inside the PayloadLen range.
                let len = unsafe { PayloadLen::new_unchecked(value as u32) };
                Step::Done(Complete { carry: self, value: len })
            }
            Step::More => Step::More,
            Step::Cut => Step::Cut,
            Step::TooWide => Step::TooWide,
            Step::OutOfClass => Step::OutOfClass,
        }
    }

    /// The u64 value domain: ten bytes, tenth byte ≤ `0x01`. `Done`
    /// is the [`Complete`] witness over the assembled value.
    ///
    /// A step consumes from the front of `chunk` and advances `*off`
    /// by exactly the bytes taken. `zone_end` is the innermost sealed
    /// extent's exclusive end in `off`'s coordinate space: the
    /// construct never reads at or past it (a construct the seal cuts
    /// reports [`Step::Cut`]) — pass `u64::MAX` when no extent bounds
    /// the construct (the unbounded root).
    ///
    /// # Panics
    ///
    /// In debug builds, when `*off > zone_end` — a cursor already
    /// past the sealed endpoint is a caller bug the release build
    /// trusts by contract.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::varint::carry::{Carry, Step};
    ///
    /// // A sealed extent ends at offset 2 while the varint still
    /// // continues: terminal — no future byte belongs to it.
    /// let mut carry = Carry::new();
    /// let mut off = 0u64;
    /// let mut chunk: &[u8] = &[0x80, 0x80, 0x01];
    /// assert!(matches!(carry.step_value64(&mut chunk, &mut off, 2), Step::Cut));
    /// ```
    #[inline]
    pub const fn step_value64<'c>(
        &'c mut self,
        chunk: &mut &[u8],
        off: &mut u64,
        zone_end: u64,
    ) -> Step<Complete<'c, u64>> {
        match self.step::<CAP64, LAST64>(chunk, off, zone_end) {
            Step::Done(value) => Step::Done(Complete { carry: self, value }),
            Step::More => Step::More,
            Step::Cut => Step::Cut,
            Step::TooWide => Step::TooWide,
            Step::OutOfClass => Step::OutOfClass,
        }
    }

    /// Collects `need` payload bytes (fixed-width records), bounded
    /// by the chunk and the sealed extent.
    ///
    /// # Safety
    /// `need <= 10`, `self.len() <= need`, and `*off <= zone_end`:
    /// the call continues a collection started for this same `need`
    /// on a cleared carry, inside the sealed extent — at the
    /// fixed-width drivers all three hold by construction (`need`
    /// is a minted 4 or 8, a `Done` is consumed and cleared before
    /// any new construct, and the head admission `zone − off ≥
    /// need` keeps the cursor inside the seal through every partial
    /// collection).
    #[cfg(any(
        test,
        feature = "scan-grouped",
        feature = "scan-groupless",
        feature = "route-grouped",
        feature = "route-groupless",
        feature = "rewire-grouped",
        feature = "rewire-groupless",
        feature = "transcode-grouped",
        feature = "transcode-groupless",
        feature = "survey-grouped",
        feature = "survey-groupless",
        feature = "replay-splice-grouped",
        feature = "replay-splice-groupless",
        feature = "overhaul-grouped",
        feature = "overhaul-groupless",
        feature = "maintain-grouped",
        feature = "maintain-groupless",
        feature = "refit-grouped",
        feature = "refit-groupless",
        feature = "commission-grouped",
        feature = "commission-groupless",
    ))]
    #[allow(
        clippy::as_conversions,
        reason = "`take` is capped by `missing ≤ 10` and by the chunk; \
              stream coordinates widen losslessly"
    )]
    pub(crate) unsafe fn collect(
        &mut self,
        chunk: &mut &[u8],
        off: &mut u64,
        zone_end: u64,
        need: u8,
    ) -> Collect {
        // SAFETY: this function's contract, verbatim.
        unsafe {
            core::hint::assert_unchecked(need <= 10 && self.len <= need && *off <= zone_end);
        }
        let missing = u64::from(need - self.len);
        // In domain by the contract's endpoint clause: `off ≤ zone_end`.
        let zone_room = zone_end - *off;
        let take = missing.min(zone_room).min(chunk.len() as u64) as usize;
        let (head, rest) = chunk.split_at(take);
        // SAFETY: `take ≤ missing = need − len ≤ 10 − len` bounds
        // the destination inside the buffer, `take ≤ chunk.len()`
        // bounds the source, and a borrowed chunk cannot overlap
        // the owned buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                head.as_ptr(),
                self.buf.as_mut_ptr().cast::<u8>().add(self.len as usize),
                take,
            );
        }
        self.len += take as u8;
        *off += take as u64;
        *chunk = rest;
        if self.len == need {
            Collect::Done
        } else if *off == zone_end {
            Collect::Cut
        } else {
            Collect::More
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spends one step: a completion's width read first, then its
    /// value taken; fault and resume variants carried through with
    /// no width — the plain-verdict projection the sweeps compare
    /// on.
    fn spend(step: Step<Complete<'_, u64>>) -> (Step<u64>, Option<u8>) {
        match step {
            Step::Done(complete) => {
                let width = complete.width();
                (Step::Done(complete.take()), Some(width))
            }
            Step::More => (Step::More, None),
            Step::Cut => (Step::Cut, None),
            Step::TooWide => (Step::TooWide, None),
            Step::OutOfClass => (Step::OutOfClass, None),
        }
    }

    /// Feeds `data` in `step`-sized chunks until the varint settles.
    fn feed_value(data: &[u8], step: usize, zone_end: u64) -> (Step<u64>, u64, u8) {
        let mut carry = Carry::new();
        let mut off = 0u64;
        for chunk in data.chunks(step.max(1)) {
            let mut chunk = chunk;
            match carry.step_value64(&mut chunk, &mut off, zone_end) {
                Step::More => continue,
                settled => {
                    let (verdict, width) = spend(settled);
                    // Fault verdicts leave the construct held: the
                    // carry's length is the fault width.
                    return (verdict, off, width.unwrap_or_else(|| carry.len()));
                }
            }
        }
        (Step::More, off, carry.len())
    }

    #[test]
    fn split_constructs_reassemble_under_uniform_chunkings() {
        for step in [1, 2, 3, 10] {
            let (settled, off, width) = feed_value(&[0x96, 0x81, 0x00], step, u64::MAX);
            assert_eq!(settled, Step::Done(150), "step {step}");
            assert_eq!((off, width), (3, 3));
        }
    }

    #[test]
    fn every_cut_partition_of_a_ten_byte_construct_agrees() {
        // The chunking quotient is finite for one construct: a
        // ten-byte window has nine interior boundaries, so 512
        // partitions exhaust every irregular chunk schedule.
        // Swept for the representative terminal classes — the
        // in-class top, a padded minimum, the class forgery, and
        // a full window still continuing — each partition must
        // reproduce the unsplit read's verdict, cursor, and width.
        let mut in_class_max = [0xFFu8; 10];
        in_class_max[9] = 0x01;
        let mut padded_one = [0x80u8; 10];
        padded_one[0] = 0x81;
        padded_one[9] = 0x00;
        let mut wrap = [0x80u8; 10];
        wrap[9] = 0x02;
        let over = [0x80u8; 10];
        for construct in [in_class_max, padded_one, wrap, over] {
            let whole = feed_value(&construct, 10, u64::MAX);
            for mask in 0u32..512 {
                let mut carry = Carry::new();
                let mut off = 0u64;
                let mut settled = None;
                let mut start = 0usize;
                for boundary in 1..=10usize {
                    if boundary != 10 && mask & (1 << (boundary - 1)) == 0 {
                        continue;
                    }
                    let mut chunk = &construct[start..boundary];
                    start = boundary;
                    match carry.step_value64(&mut chunk, &mut off, u64::MAX) {
                        Step::More => {}
                        other => {
                            let (verdict, width) = spend(other);
                            settled = Some((verdict, off, width.unwrap_or_else(|| carry.len())));
                            break;
                        }
                    }
                }
                assert_eq!(
                    settled.expect("ten bytes settle every class"),
                    whole,
                    "partition {mask:#011b} of {construct:02X?}"
                );
            }
        }
    }

    #[test]
    fn the_completion_witness_carries_the_source_encoding() {
        let mut carry = Carry::new();
        let mut off = 0u64;
        let mut chunk: &[u8] = &[0x96, 0x81, 0x00];
        match carry.step_value64(&mut chunk, &mut off, u64::MAX) {
            Step::Done(complete) => {
                // The held face: value, width, and the exact source
                // encoding, all before consumption.
                assert_eq!(complete.value(), 150);
                assert_eq!(complete.width(), 3);
                assert_eq!(complete.bytes(), [0x96, 0x81, 0x00]);
                assert_eq!(complete.take(), 150);
            }
            other => panic!("the construct terminated: {other:?}"),
        }
        assert!(carry.is_empty());
    }

    #[test]
    fn every_witness_death_returns_a_step_capable_carry() {
        // Drop is consumption-by-discard: the next construct steps
        // cleanly, no residue of the first.
        let mut carry = Carry::new();
        let mut off = 0u64;
        let mut chunk: &[u8] = &[0x01, 0x02];
        match carry.step_value64(&mut chunk, &mut off, u64::MAX) {
            Step::Done(complete) => drop(complete),
            other => panic!("one byte terminates: {other:?}"),
        }
        assert!(carry.is_empty());
        match carry.step_value64(&mut chunk, &mut off, u64::MAX) {
            Step::Done(complete) => {
                // The second byte reads as its own construct — not
                // 257, which a merged continuation would produce.
                assert_eq!(complete.bytes(), [0x02]);
                assert_eq!(complete.take(), 2);
            }
            other => panic!("one byte terminates: {other:?}"),
        }

        // The crate-internal retain face leaves the construct held
        // (the pumps' post-completion fault path); clear recovers.
        let mut carry = Carry::new();
        let mut off = 0u64;
        let mut chunk: &[u8] = &[0x96, 0x01];
        match carry.step_value64(&mut chunk, &mut off, u64::MAX) {
            Step::Done(complete) => complete.retain(),
            other => panic!("the construct terminated: {other:?}"),
        }
        assert_eq!(carry.bytes(), [0x96, 0x01]);
        assert_eq!(carry.len(), 2);
        carry.clear();
        assert!(carry.is_empty());
    }

    #[test]
    fn a_sealed_extent_cuts_terminally_but_a_chunk_end_does_not() {
        // Zone sealed at 2: the verdict is Cut within the same call
        // that exhausts the zone — the earliest deterministic point,
        // independent of chunking (no waiting for bytes that cannot
        // belong to the construct).
        let mut carry = Carry::new();
        let mut off = 0u64;
        let mut chunk: &[u8] = &[0x80, 0x80];
        assert!(matches!(carry.step_value64(&mut chunk, &mut off, 2), Step::Cut));

        // Chunk end before the zone: recoverable, more may arrive.
        let mut carry = Carry::new();
        let mut off = 0u64;
        let mut chunk: &[u8] = &[0x80, 0x80];
        assert!(matches!(carry.step_value64(&mut chunk, &mut off, 3), Step::More));
        let mut tail: &[u8] = &[0x80];
        assert!(matches!(carry.step_value64(&mut tail, &mut off, 3), Step::Cut));

        let (settled, ..) = feed_value(&[0x80, 0x80, 0x01], 2, u64::MAX);
        assert_eq!(settled, Step::Done(1 << 14));
    }

    #[test]
    fn windows_classes_and_the_typed_len_hold_across_chunks() {
        let wide = [0x80; 11];
        assert_eq!(feed_value(&wide, 3, u64::MAX).0, Step::TooWide);

        let wrap = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert_eq!(feed_value(&wrap, 1, u64::MAX).0, Step::OutOfClass);

        let mut carry = Carry::new();
        let mut off = 0u64;
        let mut chunk: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        match carry.step_len(&mut chunk, &mut off, u64::MAX) {
            Step::Done(complete) => assert_eq!(complete.take().as_inner(), i32::MAX as u32),
            other => panic!("expected the class top, got {other:?}"),
        }
    }

    #[test]
    fn the_bulk_and_resumable_paths_agree_verdict_cursor_and_bank() {
        // The bulk arm (whole window visible) and the per-byte loop
        // (chunk edges) are byte-for-byte equivalent: same verdict,
        // same cursor advance, same banked width — swept across
        // every Done width, both terminal wides, the class edge,
        // and a sealed cut.
        let mut cases: alloc::vec::Vec<(alloc::vec::Vec<u8>, u64)> = alloc::vec::Vec::new();
        for width in 1..=10usize {
            let mut v = alloc::vec![0x80u8; width];
            v[width - 1] = 0x01;
            cases.push((v, u64::MAX));
        }
        cases.push((alloc::vec![0x80; 11], u64::MAX)); // TooWide
        {
            let mut wrap = alloc::vec![0x80u8; 10];
            wrap[9] = 0x02;
            cases.push((wrap, u64::MAX)); // OutOfClass at the cap
        }
        cases.push((alloc::vec![0x80, 0x80, 0x80], 2)); // sealed Cut
        for (data, zone) in cases {
            let whole = {
                let mut carry = Carry::new();
                let mut off = 0u64;
                let mut chunk: &[u8] = &data;
                let (verdict, width) = spend(carry.step_value64(&mut chunk, &mut off, zone));
                (verdict, off, width.unwrap_or_else(|| carry.len()))
            };
            let bytewise = feed_value(&data, 1, zone);
            assert_eq!(whole, bytewise, "path divergence on {data:02X?} zone {zone}");
        }
    }

    #[test]
    fn a_position_at_the_seal_judges_cut_without_consuming() {
        // At the seal: the documented boundary verdict — no byte
        // is consumed, the cursor does not move.
        let mut carry = Carry::new();
        let mut off = 2u64;
        let mut chunk: &[u8] = &[0x01, 0x02];
        assert!(matches!(carry.step_value64(&mut chunk, &mut off, 2), Step::Cut));
        assert_eq!((off, chunk.len()), (2, 2));
    }

    /// The endpoint precondition (`off ≤ zone_end`) is
    /// debug-asserted, not a release branch: a position past the
    /// seal is a driver ordering breach, and this pin holds the
    /// assertion in place. Debug builds only — release compiles
    /// the check out by design.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "position past the sealed endpoint")]
    fn a_position_past_the_seal_is_a_contract_breach() {
        let mut carry = Carry::new();
        let mut off = 5u64;
        let mut chunk: &[u8] = &[0x01, 0x02];
        let _ = carry.step_tag(&mut chunk, &mut off, 2);
    }

    #[test]
    fn fixed_collection_is_bounded_by_chunk_and_zone() {
        let mut carry = Carry::new();
        let mut off = 0u64;
        let mut chunk: &[u8] = &[1, 0, 0];
        // SAFETY: `need` is 4 and the carry holds at most the bytes
        // collected toward it (starting empty).
        unsafe {
            assert_eq!(carry.collect(&mut chunk, &mut off, u64::MAX, 4), Collect::More);
            let mut tail: &[u8] = &[0];
            assert_eq!(carry.collect(&mut tail, &mut off, u64::MAX, 4), Collect::Done);
        }
        assert_eq!(carry.bytes(), [1, 0, 0, 0]);

        let mut carry = Carry::new();
        let mut off = 0u64;
        let mut chunk: &[u8] = &[1, 2, 3];
        // SAFETY: as above — `need` is 4, the carry starts empty.
        unsafe {
            assert_eq!(carry.collect(&mut chunk, &mut off, 2, 4), Collect::Cut);
        }
        assert_eq!(off, 2);
        assert_eq!(chunk, [3]);
    }
}
