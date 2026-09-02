//! The bounded slice kernel: varint reads over buffered bytes,
//! bounded by an extent end.
//!
//! Width-tolerant, forgery-strict (module doc of [`crate::varint`]).
//! Domain wrappers carry the corpus-pinned window facts; the length
//! wrapper delivers its class judgment as a [`PayloadLen`] — the
//! proof rides the type, not the call sites.
//!
//! Each domain has two entries over one judgment: a checked public
//! face that asserts the extent contract (`end <= data.len()`), and
//! a crate-internal `unsafe` twin for callers whose extent is
//! already a type invariant (admitted inputs, sealed zones) — same
//! verdicts, no re-check.
//!
//! Dispatch is three tiers: the single-byte
//! fast path first (the dominant arm of real traffic), then a
//! contiguous unchecked walk whenever the window provably cannot
//! cross the extent end, and a cold bounds-checked walk for the one
//! remaining case — a short extent whose last byte still continues,
//! where the terminator may sit mid-extent or the construct may be
//! genuinely cut.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::varint::slice::{self, ReadFault};
//!
//! // Two constructs back to back; `end` bounds each read's zone.
//! let data = [0x96, 0x01, 0x08];
//! assert_eq!(slice::value64(&data, 0, data.len()), Ok((150, 2)));
//! assert_eq!(slice::tag_word(&data, 2, data.len()), Ok((8, 1)));
//! // An extent cut mid-construct refuses as truncation.
//! assert_eq!(slice::value64(&data, 0, 1), Err(ReadFault::Truncated));
//! ```

use core::hint::{likely, unlikely};

use super::{CONT_BIT, LAST32, LAST64, LAST_LEN, MAX_LEN32, MAX_LEN64, PAYLOAD_BITS, PAYLOAD_MASK};
use crate::wire::PayloadLen;

/// The kernel's refusal classes, in the caller's extent coordinates.
///
/// The three variants are the kernel's complete refusal alphabet —
/// every bounded read concludes as a value or as exactly one of
/// them, and the enum is deliberately exhaustive: consumers may
/// match it without a wildcard arm.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadFault {
    /// The extent ended while the construct could still complete.
    Truncated,
    /// Ran past the domain window still continuing.
    TooWide,
    /// The terminal byte at full width exceeds the domain class.
    OutOfClass,
}

impl core::fmt::Display for ReadFault {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated by the extent",
            Self::TooWide => "continued past the domain window",
            Self::OutOfClass => "terminal byte outside the domain class",
        })
    }
}

impl core::error::Error for ReadFault {}

/// Reads the varint at `at` within `data[..end]`, capped at `CAP`
/// bytes with the terminal byte at full width bounded by `LAST` —
/// the checked core: the extent contract is asserted here.
///
/// The window caps and terminal classes are corpus-pinned wire
/// facts, not caller knobs — the entries are the domain faces
/// below, each its own monomorphic instance: the cap and class
/// comparisons are immediates, not threaded arguments. (The
/// session pair's canonical judgment composes on this: tolerant
/// read, then a minimality check.) Tolerant: any terminating
/// in-class width within the window is accepted, non-minimal
/// included.
#[inline]
#[track_caller]
pub(crate) fn tolerant<const CAP: u32, const LAST: u8>(
    data: &[u8],
    at: usize,
    end: usize,
) -> Result<(u64, u8), ReadFault> {
    assert!(end <= data.len(), "varint extent end exceeds data length");
    // SAFETY: just asserted the extent contract.
    unsafe { tiers::<CAP, LAST>(data, at, end) }
}

/// [`tolerant`] for extents already proven by the caller's type
/// invariant: the contract is restated to the optimizer instead of
/// re-checked.
///
/// # Safety
/// `end <= data.len()`.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
#[inline]
unsafe fn tolerant_trusted<const CAP: u32, const LAST: u8>(
    data: &[u8],
    at: usize,
    end: usize,
) -> Result<(u64, u8), ReadFault> {
    // SAFETY: the caller's contract, restated so the tier indexing
    // folds exactly as under the checked core's assert.
    unsafe {
        core::hint::assert_unchecked(end <= data.len());
        tiers::<CAP, LAST>(data, at, end)
    }
}

/// The tier dispatch both cores share.
///
/// # Safety
/// `end <= data.len()` — established by [`tolerant`]'s assert or
/// [`tolerant_trusted`]'s restatement; the tier-2 derivation below
/// is unsound without it.
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "the window cap fits usize on the crate's 32/64-bit targets"
)]
unsafe fn tiers<const CAP: u32, const LAST: u8>(
    data: &[u8],
    at: usize,
    end: usize,
) -> Result<(u64, u8), ReadFault> {
    if unlikely(at >= end) {
        return Err(ReadFault::Truncated);
    }
    // Tier 1: a single terminal byte. Always in class — every
    // domain here is at least two bytes wide, so the terminal-class
    // bound never applies at width one.
    let first = data[at];
    if likely(first < CONT_BIT) {
        return Ok((u64::from(first), 1));
    }
    // Tier 2 precondition: the walk cannot read past `end` — either
    // the whole window fits, or the extent's last byte terminates
    // (the walk exits at the first terminal byte, so it never reads
    // beyond it).
    if likely(end - at >= CAP as usize || data[end - 1] < CONT_BIT) {
        let (value, code) = contiguous::<CAP, LAST>(data, at);
        unpack(value, code)
    } else {
        let (value, code) = short::<CAP, LAST>(data, at, end);
        unpack(value, code)
    }
}

// ─── the packed walk verdict ───
//
// The walk tiers conclude as a `(u64, PackedCode)` pair: the code
// is one byte, so the pair is two scalars where the public
// `Result<(u64, u8), ReadFault>` spells three — the shape chosen
// for the outlined walk boundaries' return convention. That the
// pair actually returns in registers is a compiled-shape fact and
// belongs to the performance epoch's standing instruments, not to
// this comment. `unpack` translates to the public vocabulary at
// the dispatch, which inlines into the callers.

/// The packed walk verdict: the fault alphabet negative, widths
/// positive — the whole domain is spelled, so an out-of-alphabet
/// code is unrepresentable rather than silently classified.
#[repr(i8)]
#[derive(Clone, Copy)]
#[expect(
    dead_code,
    reason = "the width variants are minted as a family through `width_unchecked`'s \
              discriminant transmute, which the lint cannot see; a named-match mint \
              would spell an eleven-arm ladder for what the repr(i8) declaration \
              already states — the discriminant is the width — so the transmute stays"
)]
enum PackedCode {
    /// [`ReadFault::Truncated`].
    Truncated = -3,
    /// [`ReadFault::OutOfClass`].
    OutOfClass = -2,
    /// [`ReadFault::TooWide`].
    TooWide = -1,
    /// Widths `1..=10`, minted by [`PackedCode::width_unchecked`].
    Width1 = 1,
    /// Width 2.
    Width2 = 2,
    /// Width 3.
    Width3 = 3,
    /// Width 4.
    Width4 = 4,
    /// Width 5.
    Width5 = 5,
    /// Width 6.
    Width6 = 6,
    /// Width 7.
    Width7 = 7,
    /// Width 8.
    Width8 = 8,
    /// Width 9.
    Width9 = 9,
    /// Width 10.
    Width10 = 10,
}

impl PackedCode {
    /// The width verdict — the one dynamic construction point.
    ///
    /// # Safety
    /// `width` must lie in `1..=10`; the walks' `CAP ≤ 10` const
    /// pin is the proof at both call sites.
    #[inline(always)]
    #[allow(
        clippy::as_conversions,
        reason = "the width was just proven to lie in `1..=10`, inside i8"
    )]
    const unsafe fn width_unchecked(width: u32) -> Self {
        debug_assert!(1 <= width && width <= 10);
        // SAFETY: `1..=10` are exactly this enum's positive
        // discriminants (this function's contract).
        unsafe { core::mem::transmute::<i8, Self>(width as i8) }
    }
}

/// Translates a packed walk verdict: the sign is the discriminant,
/// a positive magnitude the width. The width test leads with the
/// hint — it is the dominant arm, and the fault compares must stay
/// behind it.
#[inline(always)]
#[allow(clippy::as_conversions, reason = "positive codes are widths in `1..=10`")]
const fn unpack(value: u64, code: PackedCode) -> Result<(u64, u8), ReadFault> {
    let raw = code as i8;
    if likely(raw > 0) {
        Ok((value, raw as u8))
    } else if matches!(code, PackedCode::Truncated) {
        Err(ReadFault::Truncated)
    } else if matches!(code, PackedCode::TooWide) {
        Err(ReadFault::TooWide)
    } else {
        // The one value the alphabet still admits here.
        Err(ReadFault::OutOfClass)
    }
}

/// The unchecked walk under the tier-2 precondition, concluding as
/// a packed verdict.
///
/// # Safety (internal)
/// Callers established: for every `i < CAP` reached with all prior
/// bytes continuing, `at + i < data.len()` — by window room
/// (`end - at >= CAP`) or by a guaranteed in-extent terminator
/// (`data[end - 1] < CONT_BIT`).
///
/// The walks index through `get_unchecked` under that
/// precondition, and the dispatch's own two reads are guarded
/// (`at < end <= data.len()` covers both), so no language-level
/// index check can fire on any tier path — the checked entries'
/// one live panic is their stated extent-contract assert. Whether
/// the guarded reads compile without residual checks is the
/// performance epoch's standing instrument question.
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "walk positions fit usize on the crate's 32/64-bit targets"
)]
fn contiguous<const CAP: u32, const LAST: u8>(data: &[u8], at: usize) -> (u64, PackedCode) {
    // Widths land in the packed alphabet, and the terminal-class
    // bound is a terminal-byte value (so the class judgment below
    // is never vacuous).
    const { assert!(CAP <= 10 && LAST < CONT_BIT) };
    let mut value: u64 = 0;
    let mut i: u32 = 0;
    while i < CAP {
        // SAFETY: in bounds by the tier-2 precondition above.
        let byte = unsafe { *data.get_unchecked(at + i as usize) };
        if byte < CONT_BIT {
            if unlikely(i == CAP - 1 && byte > LAST) {
                return (0, PackedCode::OutOfClass);
            }
            value |= u64::from(byte) << (PAYLOAD_BITS * i);
            // SAFETY: `i < CAP ≤ 10` by the loop guard and the
            // const pin, so the width `i + 1` lies in `1..=10`.
            return (value, unsafe { PackedCode::width_unchecked(i + 1) });
        }
        value |= (u64::from(byte) & PAYLOAD_MASK) << (PAYLOAD_BITS * i);
        i += 1;
    }
    (0, PackedCode::TooWide)
}

/// The bounds-checked walk for a short extent whose last byte still
/// continues: the terminator may legitimately sit mid-extent
/// (trailing bytes belong to later constructs never reached here),
/// or the construct is genuinely cut — running out of extent *is*
/// truncation. Concludes as a packed verdict so the hot tier's
/// register convention is not dragged through this cold path's
/// return slot at the dispatch join.
#[cold]
#[inline(never)]
#[allow(
    clippy::as_conversions,
    reason = "walk positions fit usize on the crate's 32/64-bit targets"
)]
fn short<const CAP: u32, const LAST: u8>(data: &[u8], at: usize, end: usize) -> (u64, PackedCode) {
    // The same pins as the contiguous walk: packed-alphabet widths,
    // judgeable terminal class.
    const { assert!(CAP <= 10 && LAST < CONT_BIT) };
    let mut value: u64 = 0;
    let mut i: u32 = 0;
    while i < CAP {
        let pos = at + i as usize;
        if pos >= end {
            return (0, PackedCode::Truncated);
        }
        let byte = data[pos];
        if byte < CONT_BIT {
            if i == CAP - 1 && byte > LAST {
                return (0, PackedCode::OutOfClass);
            }
            value |= u64::from(byte) << (PAYLOAD_BITS * i);
            // SAFETY: `i < CAP ≤ 10` by the loop guard and the
            // const pin, so the width `i + 1` lies in `1..=10`.
            return (value, unsafe { PackedCode::width_unchecked(i + 1) });
        }
        value |= (u64::from(byte) & PAYLOAD_MASK) << (PAYLOAD_BITS * i);
        i += 1;
    }
    (0, PackedCode::TooWide)
}

/// The tag domain: five bytes, fifth byte ≤ `0x0F` (u32 words).
///
/// # Errors
///
/// [`ReadFault::Truncated`] when the extent ends while the word
/// could still complete, [`ReadFault::TooWide`] past five bytes
/// still continuing, [`ReadFault::OutOfClass`] when the fifth byte
/// exceeds `0x0F` (a wrap forgery).
///
/// # Panics
///
/// If `end > data.len()` — the extent contract is the caller's (an
/// extent is always within its buffer).
///
/// # Examples
///
/// ```
/// use protobuf_edit::varint::slice::{self, ReadFault};
///
/// // Field 1, code 0 — minimal, then the same word padded wider.
/// assert_eq!(slice::tag_word(&[0x08], 0, 1), Ok((8, 1)));
/// assert_eq!(slice::tag_word(&[0x88, 0x80, 0x00], 0, 3), Ok((8, 3)));
/// // A fifth byte above 0x0F would wrap past u32: refused.
/// let forged = [0xF8, 0xFF, 0xFF, 0xFF, 0x10];
/// assert_eq!(slice::tag_word(&forged, 0, 5), Err(ReadFault::OutOfClass));
/// ```
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "four full payload bytes and a fifth capped at 0x0F land exactly in u32"
)]
#[track_caller]
pub fn tag_word(data: &[u8], at: usize, end: usize) -> Result<(u32, u8), ReadFault> {
    match tolerant::<MAX_LEN32, LAST32>(data, at, end) {
        // Four full payload bytes carry 28 bits and the fifth is
        // capped at 0x0F: exactly the u32 range.
        Ok((value, width)) => Ok((value as u32, width)),
        Err(fault) => Err(fault),
    }
}

/// [`tag_word`] for callers whose extent is a type invariant —
/// the same judgment, no extent re-check.
///
/// # Safety
/// `end <= data.len()`.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "four full payload bytes and a fifth capped at 0x0F land exactly in u32"
)]
pub(crate) unsafe fn tag_word_trusted(
    data: &[u8],
    at: usize,
    end: usize,
) -> Result<(u32, u8), ReadFault> {
    // SAFETY: the caller's contract is the delegate's.
    match unsafe { tolerant_trusted::<MAX_LEN32, LAST32>(data, at, end) } {
        Ok((value, width)) => Ok((value as u32, width)),
        Err(fault) => Err(fault),
    }
}

/// The LEN length domain: five bytes, class `0..=2^31 - 1` (fifth
/// byte ≤ `0x07`). The class judgment is delivered as the type.
///
/// # Errors
///
/// [`ReadFault::Truncated`] when the extent ends while the word
/// could still complete, [`ReadFault::TooWide`] past five bytes
/// still continuing, [`ReadFault::OutOfClass`] when the fifth byte
/// exceeds `0x07` (beyond the length class).
///
/// # Panics
///
/// If `end > data.len()` — the extent contract is the caller's.
///
/// # Examples
///
/// ```
/// use protobuf_edit::varint::slice::{self, ReadFault};
///
/// // A LEN record's length word, then its payload.
/// let record = [0x03, b'a', b'b', b'c'];
/// let (len, width) = slice::len_word(&record, 0, record.len()).unwrap();
/// assert_eq!((len.as_inner(), width), (3, 1));
/// assert_eq!(&record[1..4], b"abc"); // the three payload bytes
/// // A fifth byte above 0x07 leaves the length class: refused.
/// let over = [0x80, 0x80, 0x80, 0x80, 0x08];
/// assert_eq!(slice::len_word(&over, 0, 5), Err(ReadFault::OutOfClass));
/// ```
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "four full payload bytes and a fifth capped at 0x07 land inside the length class"
)]
#[track_caller]
pub fn len_word(data: &[u8], at: usize, end: usize) -> Result<(PayloadLen, u8), ReadFault> {
    match tolerant::<MAX_LEN32, LAST_LEN>(data, at, end) {
        // SAFETY: four full payload bytes carry 28 bits and the
        // fifth is capped at 0x07, so the value is at most
        // 0x7FFF_FFFF — inside the PayloadLen range.
        Ok((value, width)) => Ok((unsafe { PayloadLen::new_unchecked(value as u32) }, width)),
        Err(fault) => Err(fault),
    }
}

/// [`len_word`] for callers whose extent is a type invariant —
/// the same judgment, no extent re-check.
///
/// # Safety
/// `end <= data.len()`.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "four full payload bytes and a fifth capped at 0x07 land inside the length class"
)]
pub(crate) unsafe fn len_word_trusted(
    data: &[u8],
    at: usize,
    end: usize,
) -> Result<(PayloadLen, u8), ReadFault> {
    // SAFETY: the caller's contract is the delegate's.
    match unsafe { tolerant_trusted::<MAX_LEN32, LAST_LEN>(data, at, end) } {
        // SAFETY: four full payload bytes carry 28 bits and the
        // fifth is capped at 0x07, so the value is at most
        // 0x7FFF_FFFF — inside the PayloadLen range.
        Ok((value, width)) => Ok((unsafe { PayloadLen::new_unchecked(value as u32) }, width)),
        Err(fault) => Err(fault),
    }
}

/// The u64 value domain: ten bytes, tenth byte ≤ `0x01`.
///
/// # Errors
///
/// [`ReadFault::Truncated`] when the extent ends while the value
/// could still complete, [`ReadFault::TooWide`] past ten bytes
/// still continuing, [`ReadFault::OutOfClass`] when the tenth byte
/// exceeds `0x01` (a wrap forgery).
///
/// # Panics
///
/// If `end > data.len()` — the extent contract is the caller's.
///
/// # Examples
///
/// ```
/// use protobuf_edit::varint::slice::{self, ReadFault};
///
/// assert_eq!(slice::value64(&[0x96, 0x01], 0, 2), Ok((150, 2)));
/// // Ten in-class bytes reach u64::MAX exactly.
/// let max = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
/// assert_eq!(slice::value64(&max, 0, 10), Ok((u64::MAX, 10)));
/// // A tenth byte above 0x01 would wrap: refused.
/// let wrap = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
/// assert_eq!(slice::value64(&wrap, 0, 10), Err(ReadFault::OutOfClass));
/// ```
#[inline]
#[track_caller]
pub fn value64(data: &[u8], at: usize, end: usize) -> Result<(u64, u8), ReadFault> {
    tolerant::<MAX_LEN64, LAST64>(data, at, end)
}

/// [`value64`] for callers whose extent is a type invariant —
/// the same judgment, no extent re-check.
///
/// # Safety
/// `end <= data.len()`.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "fixed-patch-grouped",
    feature = "fixed-patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
#[inline]
pub(crate) unsafe fn value64_trusted(
    data: &[u8],
    at: usize,
    end: usize,
) -> Result<(u64, u8), ReadFault> {
    // SAFETY: the caller's contract is the delegate's.
    unsafe { tolerant_trusted::<MAX_LEN64, LAST64>(data, at, end) }
}

/// The width of the varint at `at`, judged exactly as
/// [`value64`] judges it (termination, ten-byte window, class)
/// without assembling the value — for walks that index records
/// and read values lazily.
///
/// # Safety
/// `end <= data.len()`.
/// # Errors
///
/// [`ReadFault::Truncated`] when the extent ends mid-construct,
/// [`ReadFault::TooWide`] past the ten-byte window,
/// [`ReadFault::OutOfClass`] when the terminal byte at full width
/// exceeds the u64 class — the same verdicts, in the same order,
/// as the assembling read.
#[cfg(any(
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless"
))]
#[inline]
pub(crate) unsafe fn width64_trusted(data: &[u8], at: usize, end: usize) -> Result<u8, ReadFault> {
    #[allow(clippy::as_conversions, reason = "the window cap widens losslessly to usize")]
    const MAX: usize = MAX_LEN64 as usize;
    let mut i = 0usize;
    loop {
        if at + i >= end {
            return Err(ReadFault::Truncated);
        }
        // SAFETY: `at + i < end <= data.len()` by the caller's
        // extent contract and the check above.
        let byte = unsafe { *data.get_unchecked(at + i) };
        if byte < CONT_BIT {
            if i == MAX - 1 && byte > LAST64 {
                return Err(ReadFault::OutOfClass);
            }
            #[allow(clippy::as_conversions, reason = "width is at most ten")]
            return Ok(i as u8 + 1);
        }
        i += 1;
        if i >= MAX {
            return Err(ReadFault::TooWide);
        }
    }
}

/// Re-reads a varint an earlier bounded read already judged. No
/// judgment is repeated: no `Result`, no class check, no panic
/// path — the walk assembles bytes until the terminator the proof
/// promises.
///
/// # Safety
/// A prior in-class read (e.g. [`value64`]) over these same bytes
/// must have admitted a varint at `at`: terminated within ten
/// bytes, entirely inside `data`. An unproven call reads out of
/// bounds. Callers typically hold the proof as a type invariant
/// (a structure owning both the bytes and the judgment records).
///
/// # Examples
///
/// ```
/// use protobuf_edit::varint::slice;
///
/// let data = [0x96, 0x01];
/// let (value, _) = slice::value64(&data, 0, 2).expect("in class");
/// // SAFETY: the checked read above admitted the varint at 0.
/// assert_eq!(unsafe { slice::value64_unchecked(&data, 0) }, value);
/// assert_eq!(value, 150);
/// ```
#[inline]
#[must_use]
#[allow(
    clippy::as_conversions,
    reason = "walk positions fit usize on the crate's 32/64-bit targets"
)]
pub unsafe fn value64_unchecked(data: &[u8], at: usize) -> u64 {
    let mut value: u64 = 0;
    let mut i: u32 = 0;
    loop {
        // SAFETY: the admitted varint, terminator included, lies
        // within `data` (this function's contract).
        let byte = unsafe { *data.get_unchecked(at + i as usize) };
        if byte < CONT_BIT {
            return value | (u64::from(byte) << (PAYLOAD_BITS * i));
        }
        value |= (u64::from(byte) & PAYLOAD_MASK) << (PAYLOAD_BITS * i);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_single_byte_fast_path_is_a_whole_judgment() {
        // Terminal first byte: width one, in class in every domain.
        assert_eq!(value64(&[0x05, 0x80], 0, 2), Ok((5, 1)));
        assert_eq!(tag_word(&[0x08, 0xFF], 0, 1), Ok((8, 1)));
        let (len, w) = len_word(&[0x00], 0, 1).expect("zero length");
        assert_eq!((len.as_inner(), w), (0, 1));
    }

    #[test]
    fn tolerance_accepts_any_terminating_in_class_width() {
        // 150 minimal (two bytes) and padded (three bytes).
        assert_eq!(value64(&[0x96, 0x01], 0, 2), Ok((150, 2)));
        assert_eq!(value64(&[0x96, 0x81, 0x00], 0, 3), Ok((150, 3)));
        // Ten in-class bytes reach u64::MAX.
        let max = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
        assert_eq!(value64(&max, 0, 10), Ok((u64::MAX, 10)));
    }

    #[test]
    fn a_mid_extent_terminator_behind_a_continuing_last_byte_reads() {
        // The short-walk correctness arm: the extent is narrower
        // than the window and its last byte continues (it belongs
        // to a later construct), yet the varint terminates inside —
        // the cold walk must find it, not misreport truncation.
        let data = [0x80, 0x80, 0x01, 0xFF];
        assert_eq!(value64(&data, 0, 4), Ok((1 << 14, 3)));
        // The same shape genuinely cut: every extent byte continues.
        assert_eq!(value64(&[0x80, 0x80, 0x80], 0, 3), Err(ReadFault::Truncated));
    }

    #[test]
    fn windows_and_classes_refuse_precisely() {
        // Truncation: the extent ends first (bytes exist past it).
        let cut = [0x80, 0x01];
        assert_eq!(value64(&cut, 0, 1), Err(ReadFault::Truncated));
        // Eleven bytes: past the value window.
        let wide = [0x80; 11];
        assert_eq!(value64(&wide, 0, 11), Err(ReadFault::TooWide));
        // Tenth byte above 0x01: wrap forgery, refused.
        let wrap = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert_eq!(value64(&wrap, 0, 10), Err(ReadFault::OutOfClass));
        // Tag window is exactly five bytes, non-minimal or not.
        let tag6 = [0x88, 0x80, 0x80, 0x80, 0x80, 0x00];
        assert_eq!(tag_word(&tag6, 0, 6), Err(ReadFault::TooWide));
        // Fifth tag byte above 0x0F: beyond u32, refused.
        let tag_wrap = [0xF8, 0xFF, 0xFF, 0xFF, 0x10];
        assert_eq!(tag_word(&tag_wrap, 0, 5), Err(ReadFault::OutOfClass));
    }

    #[cfg(any(
        feature = "inspect-grouped",
        feature = "inspect-groupless",
        feature = "retain-grouped",
        feature = "retain-groupless",
        feature = "patch-grouped",
        feature = "patch-groupless",
        feature = "fixed-patch-grouped",
        feature = "fixed-patch-groupless",
        feature = "adopt-grouped",
        feature = "adopt-groupless",
        feature = "amend-grouped",
        feature = "amend-groupless",
        feature = "intake-grouped",
        feature = "intake-groupless",
        feature = "session-grouped",
        feature = "session-groupless"
    ))]
    #[test]
    fn the_trusted_framing_faces_match_the_checked_faces() {
        let data = [0x96, 0x81, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        // SAFETY: every extent below is at most `data.len()`.
        unsafe {
            assert_eq!(tag_word_trusted(&data, 3, 4), tag_word(&data, 3, 4));
            assert_eq!(len_word_trusted(&data, 4, 9), len_word(&data, 4, 9));
        }
    }

    #[cfg(any(
        feature = "patch-grouped",
        feature = "patch-groupless",
        feature = "fixed-patch-grouped",
        feature = "fixed-patch-groupless",
        feature = "adopt-grouped",
        feature = "adopt-groupless",
        feature = "amend-grouped",
        feature = "amend-groupless",
        feature = "intake-grouped",
        feature = "intake-groupless",
        feature = "session-grouped",
        feature = "session-groupless"
    ))]
    #[test]
    fn the_trusted_value_face_matches_the_checked_face() {
        let data = [0x96, 0x81, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        // SAFETY: every extent below is at most `data.len()`.
        unsafe {
            assert_eq!(value64_trusted(&data, 0, data.len()), value64(&data, 0, data.len()));
            assert_eq!(value64_trusted(&data, 0, 2), value64(&data, 0, 2));
        }
    }

    #[test]
    fn the_unchecked_reread_matches_the_judged_read() {
        let cases: [&[u8]; 4] = [
            &[0x05],
            &[0x96, 0x01],
            &[0x96, 0x81, 0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
        ];
        for data in cases {
            let (value, _) = value64(data, 0, data.len()).expect("judged in class");
            // SAFETY: just judged over the same bytes.
            assert_eq!(unsafe { value64_unchecked(data, 0) }, value);
        }
    }

    #[test]
    fn the_len_class_rides_the_type() {
        // The class top in five padded bytes.
        let top = [0xFF, 0xFF, 0xFF, 0xFF, 0x07];
        let (len, width) = len_word(&top, 0, 5).expect("in class");
        assert_eq!((len.as_inner(), width), (i32::MAX as u32, 5));
        // One past the class: refused at the kernel, so PayloadLen
        // holders never see it.
        let over = [0x80, 0x80, 0x80, 0x80, 0x08];
        assert_eq!(len_word(&over, 0, 5), Err(ReadFault::OutOfClass));
    }
}
