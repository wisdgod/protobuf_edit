//! The varint stratum: format theorems and the two reading kernels.
//!
//! Theorems (this module's root) judge no input: encoded lengths,
//! canonical emission, zigzag in both directions. The kernels judge
//! wire bytes under the corpus-pinned window facts — tag and length
//! words ride a five-byte window, values a ten-byte window, and each
//! window's terminal byte is class-bounded — and are
//! **width-tolerant, forgery-strict**: any terminating in-class
//! encoding is accepted however padded, while an out-of-class
//! terminal (which the reference runtime silently wraps, fabricating
//! values and field numbers) refuses. Scenario-specific acceptance
//! beyond that — canonical minimality, caller-declared standards —
//! is a per-scenario conclusion and lives with those scenarios.
//!
//! Two kernels for the two presence shapes (`slice`: buffered,
//! bounded by an extent end; `carry`: streamed, one construct
//! reassembled across chunk boundaries). The theorems are
//! unconditional; each kernel compiles exactly when a scenario
//! cell of its presence shape consumes it or its direct feature
//! (`varint-slice`, `varint-carry`) selects it. The width formula
//! is branch-free at source (bit-width over nine), and both
//! kernels keep their error paths cold — each kernel's own doc
//! carries its dispatch shape.
//!
//! Both kernels read one byte at a time; there is no SIMD path.
//!
//! Emission is one primitive: [`write64_at`] writes a value at an
//! explicit width — minimal when the width is the value's own
//! encoded length, continuation-padded when wider (lawful wire the
//! tolerant kernels accept). Every other emission face reserves,
//! then delegates.
//!
//! # Choosing a face
//!
//! Kernel choice follows the presence shape, settled above; within
//! a kernel, the read face is the construct's domain — each face
//! carries its own window and class facts:
//!
//! - a record head: `slice::tag_word` / `carry::Carry::step_tag` —
//!   five-byte window, the u32 tag domain;
//! - a LEN length prefix: `slice::len_word` /
//!   `carry::Carry::step_len` — five-byte window, judged into
//!   [`PayloadLen`](crate::wire::PayloadLen);
//! - a varint record's value: `slice::value64` /
//!   `carry::Carry::step_value64` — ten-byte window, all of u64.
//!
//! Emission is picked by the destination you hold: [`emit64`]
//! writes minimally at a slice head, [`emit64_at`]/[`emit32_at`]
//! write at an explicit width there (the padded exact-width faces,
//! contracts asserted), `push64` appends minimally to a `Vec`
//! (compiled with the cells that hold one — a build without an
//! allocator has no such destination), and the unsafe
//! [`write64_at`]/[`write32_at`] write at an explicit width into a
//! reservation you already proved. The
//! theorems ([`encoded_len32`], [`encoded_len64`], the zigzag
//! pairs) judge no input; their assignment to schema types is
//! the `scalar` module's (feature `scalar`), and whole records
//! (head plus value) are authored by `construct` (feature
//! `construct-*`).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "varint-slice")] {
//! use protobuf_edit::varint::{emit64, encoded_len64, slice};
//!
//! // Minimal emission, read back by the bounded kernel.
//! let mut buf = [0u8; 10];
//! let width = emit64(150, &mut buf);
//! assert_eq!(width, encoded_len64(150));
//! assert_eq!(buf[..2], [0x96, 0x01]);
//! assert_eq!(slice::value64(&buf, 0, 2), Ok((150, 2)));
//!
//! // The same value continuation-padded is lawful wire too.
//! assert_eq!(slice::value64(&[0x96, 0x81, 0x00], 0, 3), Ok((150, 3)));
//! # }
//! ```
//!
//! # Recipes
//!
//! The hand-rolled record read — `slice::tag_word`, the wire
//! tables' classify, then the value face the class names — is
//! compiled end to end in [the crate root's examples](crate);
//! the scenario machines are the same chain with extent
//! discipline, state, and faults attached.

use core::hint::assert_unchecked;

#[cfg(any(
    test,
    feature = "varint-carry",
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
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
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
pub mod carry;
#[cfg(any(
    test,
    feature = "varint-slice",
    feature = "select-grouped",
    feature = "select-groupless",
    feature = "traverse-grouped",
    feature = "traverse-groupless",
    feature = "rewrite-grouped",
    feature = "rewrite-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "convert-grouped",
    feature = "convert-groupless",
    feature = "splice-grouped",
    feature = "splice-groupless",
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
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
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
pub mod slice;

/// Payload bits per varint byte.
pub(crate) const PAYLOAD_BITS: u32 = 7;
/// The continuation bit: the byte's remaining bit.
pub(crate) const CONT_BIT: u8 = 1 << PAYLOAD_BITS;
/// The payload mask, the continuation bit's complement.
pub(crate) const PAYLOAD_MASK: u64 = (1 << PAYLOAD_BITS) - 1;

/// Maximum encoded width of the u32 domain: 32 payload bits, 7 per
/// byte.
pub(crate) const MAX_LEN32: u32 = u32::BITS.div_ceil(PAYLOAD_BITS);
/// Maximum encoded width of the u64 domain.
pub(crate) const MAX_LEN64: u32 = u64::BITS.div_ceil(PAYLOAD_BITS);

/// The largest terminal byte of a full-width u32-domain varint:
/// after four seven-bit groups, four value bits remain.
#[allow(
    clippy::as_conversions,
    reason = "the shift leaves at most seven value bits — inside the byte domain"
)]
pub(crate) const LAST32: u8 = (u32::MAX >> ((MAX_LEN32 - 1) * PAYLOAD_BITS)) as u8;
/// The largest terminal byte of a full-width u64-domain varint:
/// after nine seven-bit groups, one value bit remains.
#[allow(
    clippy::as_conversions,
    reason = "the shift leaves at most seven value bits — inside the byte domain"
)]
pub(crate) const LAST64: u8 = (u64::MAX >> ((MAX_LEN64 - 1) * PAYLOAD_BITS)) as u8;
/// The largest terminal byte of a full-width LEN-class word
/// (`0..=2^31 - 1`): three value bits remain.
#[allow(
    clippy::as_conversions,
    reason = "the shift leaves at most seven value bits — inside the byte domain"
)]
pub(crate) const LAST_LEN: u8 =
    (i32::MAX.cast_unsigned() >> ((MAX_LEN32 - 1) * PAYLOAD_BITS)) as u8;

const _: () = {
    assert!(CONT_BIT == 0x80);
    assert!(PAYLOAD_MASK == 0x7F);
    assert!(MAX_LEN32 == 5);
    assert!(MAX_LEN64 == 10);
    assert!(LAST32 == 0x0F);
    assert!(LAST64 == 0x01);
    assert!(LAST_LEN == 0x07);
};

// ─── encode: one canonical emitter ───

/// The minimal encoded width of a `u32` value: `1..=5`, branchless.
#[inline]
#[must_use]
pub const fn encoded_len32(value: u32) -> u32 {
    // bit_width * 9 / 64 + 1 — exact for widths up to 64 bits.
    let len = ((value.bit_width() * 9) >> 6) + 1;
    // SAFETY: bit_width is 0..=32, so the formula lands in 1..=5 —
    // callers reserve and index buffers by this value.
    unsafe { assert_unchecked(len >= 1 && len <= MAX_LEN32) };
    len
}

/// The minimal encoded width of a `u64` value: `1..=10`, branchless.
///
/// # Examples
///
/// ```
/// use protobuf_edit::varint::encoded_len64;
///
/// assert_eq!(encoded_len64(0), 1);
/// assert_eq!(encoded_len64(127), 1);
/// assert_eq!(encoded_len64(128), 2);
/// assert_eq!(encoded_len64(u64::MAX), 10);
/// ```
#[inline]
#[must_use]
pub const fn encoded_len64(value: u64) -> u32 {
    let len = ((value.bit_width() * 9) >> 6) + 1;
    // SAFETY: bit_width is 0..=64, so the formula lands in 1..=10.
    unsafe { assert_unchecked(len >= 1 && len <= MAX_LEN64) };
    len
}

// ─── the width vocabulary ───

#[cfg(any(
    test,
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
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
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
crate::_macro::define_valid_range_type! {
    /// Met or minimal spelling width of one framing word — a head
    /// tag, a LEN length prefix, or a group end tag: every framing
    /// word rides the u32 domain's five-byte window. A stored input
    /// fact where the holder read it off the wire (tolerant
    /// admission accepts padded framing, so spans must be rebuilt
    /// from the width actually met, never re-derived from the
    /// decoded value); a stored theorem fact where the holder
    /// minted it from the word in hand. Each holding field names
    /// which.
    pub(crate) struct WordWidth(u8 as u8 in 1..=5) with new_unchecked;
}

#[cfg(any(
    test,
    feature = "construct-grouped",
    feature = "construct-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless"
))]
impl WordWidth {
    crate::_macro::define_valid_range_face!(min: WordWidth(u8 as u8));
}

#[cfg(any(
    all(
        test,
        any(
            feature = "maintain-grouped",
            feature = "maintain-groupless",
            feature = "commission-grouped",
            feature = "commission-groupless"
        )
    ),
    feature = "construct-grouped",
    feature = "construct-groupless",
    feature = "transfer-draft-grouped",
    feature = "transfer-draft-groupless",
    feature = "transfer-stream-draft-grouped",
    feature = "transfer-stream-draft-groupless",
    feature = "transfer-markup-grouped",
    feature = "transfer-markup-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "overhaul-grouped"
))]
impl WordWidth {
    /// The word's own minimal spelling width — the min-provenance
    /// door: minimality holds by construction because the value is
    /// in hand at the mint (`encoded_len32` theorem).
    #[inline]
    #[allow(
        clippy::as_conversions,
        reason = "the width theorem lands in 1..=5 — inside the byte domain"
    )]
    pub(crate) const fn minimal_of(word: u32) -> Self {
        // SAFETY: the width theorem lands in 1..=5.
        unsafe { Self::new_unchecked(encoded_len32(word) as u8) }
    }
}

#[cfg(any(
    test,
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
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless"
))]
impl WordWidth {
    /// The met-provenance door.
    ///
    /// # Safety
    /// `width` was counted by a terminated framing-window read (a
    /// kernel step, a stepper loop, or geometry subtraction over
    /// coordinates such a read minted): `1 <= width && width <= 5`.
    #[inline]
    pub(crate) const unsafe fn met_unchecked(width: u8) -> Self {
        // SAFETY: the caller's terminated framing-window read
        // bounds `width` in the type's own range.
        unsafe { Self::new_unchecked(width) }
    }
}

#[cfg(any(
    test,
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
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
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
))]
impl WordWidth {
    /// The width as a coordinate-class integer (span arithmetic).
    #[inline]
    #[allow(clippy::as_conversions, reason = "widening the byte into the coordinate domain")]
    pub(crate) const fn w(self) -> u32 {
        self.as_inner() as u32
    }
}

#[cfg(any(
    test,
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
crate::_macro::define_valid_range_type! {
    /// Met spelling width of one varint value: the u64 domain's
    /// ten-byte window. A stored input fact where the holder read
    /// it off the wire (tolerant admission accepts padded values,
    /// so spans must be rebuilt from the width actually met, never
    /// re-derived from the decoded value). Only the met door
    /// exists: no consumer mints a stored minimal value width.
    pub(crate) struct ValueWidth(u8 as u8 in 1..=10) with new_unchecked;
}

#[cfg(any(
    test,
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless"
))]
impl ValueWidth {
    /// The met-provenance door.
    ///
    /// # Safety
    /// `width` was counted by a terminated value-window read (a
    /// kernel step, a stepper loop, or geometry subtraction over
    /// coordinates such a read minted): `1 <= width && width <= 10`.
    #[inline]
    pub(crate) const unsafe fn met_unchecked(width: u8) -> Self {
        // SAFETY: the caller's terminated value-window read bounds
        // `width` in the type's own range.
        unsafe { Self::new_unchecked(width) }
    }
}

#[cfg(any(
    test,
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
))]
impl ValueWidth {
    /// The width as a coordinate-class integer (span arithmetic).
    #[inline]
    #[allow(clippy::as_conversions, reason = "widening the byte into the coordinate domain")]
    pub(crate) const fn w(self) -> u32 {
        self.as_inner() as u32
    }
}

/// Framing words widen into the value window losslessly: `1..=5`
/// sits inside `1..=10`.
#[cfg(any(
    test,
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless"
))]
impl From<WordWidth> for ValueWidth {
    #[inline]
    fn from(width: WordWidth) -> Self {
        // SAFETY: the word window's 1..=5 sits inside 1..=10.
        unsafe { Self::new_unchecked(width.as_inner()) }
    }
}

/// Ties a window type to its cap so a counting loop can mint the
/// width it counted, generically over the domain.
#[cfg(any(
    test,
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
pub(crate) trait StepWidth: Copy {
    /// The window cap the type's range tops at.
    const CAP: u8;

    /// The met-provenance door, generic over the window.
    ///
    /// # Safety
    /// `width` was counted by a terminated in-window read:
    /// `1 <= width && width <= Self::CAP`.
    unsafe fn met_unchecked(width: u8) -> Self;
}

#[cfg(any(
    test,
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
))]
impl StepWidth for WordWidth {
    const CAP: u8 = 5;

    #[inline]
    unsafe fn met_unchecked(width: u8) -> Self {
        // SAFETY: the trait door's contract is the type's range.
        unsafe { Self::new_unchecked(width) }
    }
}

#[cfg(any(
    test,
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
))]
impl StepWidth for ValueWidth {
    const CAP: u8 = 10;

    #[inline]
    unsafe fn met_unchecked(width: u8) -> Self {
        // SAFETY: the trait door's contract is the type's range.
        unsafe { Self::new_unchecked(width) }
    }
}

// The window caps are the width theorems'.
#[cfg(any(
    test,
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "refit-grouped",
    feature = "refit-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless",
))]
#[allow(clippy::as_conversions, reason = "widening the byte caps into the theorem domain")]
const _: () = {
    assert!(WordWidth::CAP as u32 == MAX_LEN32);
    assert!(ValueWidth::CAP as u32 == MAX_LEN64);
};

// `Option` rides the pattern types' niches in both windows.
#[cfg(any(
    test,
    feature = "inspect-grouped",
    feature = "inspect-groupless",
    feature = "retain-grouped",
    feature = "retain-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
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
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "fixed-inspect-grouped",
    feature = "fixed-inspect-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless"
))]
const _: () = assert!(size_of::<Option<WordWidth>>() == 1);
#[cfg(any(
    test,
    feature = "survey-grouped",
    feature = "survey-groupless",
    feature = "overhaul-grouped",
    feature = "overhaul-groupless",
    feature = "replay-rewrite-grouped",
    feature = "replay-rewrite-groupless",
    feature = "replay-convert-grouped",
    feature = "replay-convert-groupless",
    feature = "replay-splice-grouped",
    feature = "replay-splice-groupless",
    feature = "inplace-grouped",
    feature = "inplace-groupless",
    feature = "fixed-inplace-grouped",
    feature = "fixed-inplace-groupless",
    feature = "collect-grouped",
    feature = "collect-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless"
))]
const _: () = assert!(size_of::<Option<ValueWidth>>() == 1);

/// Writes `value` as exactly `len` LEB128 bytes forward at `ptr`.
///
/// Continuation bits ride bytes through `len - 1`, the terminal is
/// bare. Minimal when `len == encoded_len64(value)`; a wider `len`
/// emits the continuation-padded form — lawful wire the tolerant
/// kernels accept.
///
/// # Safety
/// `ptr` must be valid for writes of exactly `len` bytes, and `len`
/// must lie in `encoded_len64(value)..=10` (narrower would drop
/// value bits, wider would leave the ten-byte window; both bounds
/// are debug-asserted).
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "varint-slice")] {
/// use protobuf_edit::varint::{slice, write64_at};
///
/// let mut buf = [0u8; 10];
/// // SAFETY: ten writable bytes; 3 lies in encoded_len64(1)..=10.
/// unsafe { write64_at(buf.as_mut_ptr(), 1, 3) };
/// assert_eq!(buf[..3], [0x81, 0x80, 0x00]); // padded encoding of 1
/// assert_eq!(slice::value64(&buf, 0, 3), Ok((1, 3)));
/// # }
/// ```
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "masked and shifted-out bytes stay in the byte domain; \
              the width fits usize on the crate's 32/64-bit targets"
)]
pub const unsafe fn write64_at(ptr: *mut u8, mut value: u64, len: u32) {
    debug_assert!(encoded_len64(value) <= len && len <= MAX_LEN64);
    // SAFETY: the caller reserves `len` bytes; the loop writes
    // indexes 0..len-1 and the final store writes len-1.
    unsafe {
        let limit = (len - 1) as usize;
        let mut i = 0;
        while i < limit {
            *ptr.add(i) = (value & PAYLOAD_MASK) as u8 | CONT_BIT;
            value >>= PAYLOAD_BITS;
            i += 1;
        }
        *ptr.add(limit) = value as u8;
    }
}

/// Writes a `u32` value as exactly `len` LEB128 bytes forward at
/// `ptr` — [`write64_at`]'s emission over the u32 domain.
///
/// The domain's window is five bytes: a wider emission would be
/// lawful u64-value wire, but every u32-domain read face (tag and
/// length words) refuses six-plus-byte words as too wide.
///
/// # Safety
/// `ptr` must be valid for writes of exactly `len` bytes, and `len`
/// must lie in `encoded_len32(value)..=5` (the u32 domain's window;
/// both bounds are debug-asserted).
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "widening preserves bit width; const `From` is unavailable"
)]
pub const unsafe fn write32_at(ptr: *mut u8, value: u32, len: u32) {
    debug_assert!(encoded_len32(value) <= len && len <= MAX_LEN32);
    // SAFETY: widening preserves bit width, so
    // encoded_len32(v) == encoded_len64(v as u64), and the u32
    // window (five bytes) sits inside the delegate's ten — the
    // caller's contract implies the delegate's.
    unsafe { write64_at(ptr, value as u64, len) }
}

/// Emits `value` minimally at the head of `out`; returns the width.
///
/// # Panics
///
/// If `out.len() < encoded_len64(value)` — the reservation is the
/// caller's; asserted here, then the write is judgment-free.
///
/// # Examples
///
/// ```
/// use protobuf_edit::varint::emit64;
///
/// let mut buf = [0u8; 10];
/// let width = emit64(300, &mut buf);
/// assert_eq!(width, 2);
/// assert_eq!(buf[..2], [0xAC, 0x02]);
/// ```
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "the encoded width fits usize on the crate's 32/64-bit targets"
)]
#[track_caller]
pub const fn emit64(value: u64, out: &mut [u8]) -> u32 {
    let len = encoded_len64(value);
    assert!(out.len() >= len as usize, "emit64: buffer shorter than the value's width");
    // SAFETY: just asserted `len` writable bytes at the head, and
    // `len` is the value's own encoded width.
    unsafe { write64_at(out.as_mut_ptr(), value, len) };
    len
}

/// Emits `value` at exactly `width` bytes at the head of `out`.
///
/// Continuation bits ride bytes through `width − 1`, the terminal
/// is bare. Minimal when `width == encoded_len64(value)`,
/// continuation-padded when wider — lawful wire the tolerant
/// kernels accept, at exactly this width.
///
/// The contract-carrying safe face over [`write64_at`]: the width
/// and reservation judgments are asserted here once, and the write
/// past them is judgment-free. Emitters that already hold a proven
/// raw reservation (spare `Vec` capacity) stay on the unsafe face.
///
/// # Panics
///
/// If `width` lies outside `encoded_len64(value)..=10` (narrower
/// would drop value bits, wider would leave the ten-byte window),
/// or if `out.len() < width` — the reservation is the caller's,
/// asserted here.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "varint-slice")] {
/// use protobuf_edit::varint::{emit64_at, slice};
///
/// let mut buf = [0u8; 4];
/// emit64_at(150, 4, &mut buf);
/// assert_eq!(buf, [0x96, 0x81, 0x80, 0x00]); // 150 padded to 4
/// assert_eq!(slice::value64(&buf, 0, 4), Ok((150, 4)));
/// # }
/// ```
#[inline]
#[allow(clippy::as_conversions, reason = "the width fits usize on the crate's 32/64-bit targets")]
#[track_caller]
pub const fn emit64_at(value: u64, width: u32, out: &mut [u8]) {
    assert!(
        encoded_len64(value) <= width && width <= MAX_LEN64,
        "emit64_at: width outside the value's lawful range"
    );
    assert!(out.len() >= width as usize, "emit64_at: buffer shorter than the width");
    // SAFETY: just asserted `width` writable bytes at the head and
    // `width` inside `encoded_len64(value)..=10`.
    unsafe { write64_at(out.as_mut_ptr(), value, width) };
}

/// Emits a `u32` word at exactly `width` bytes at the head of
/// `out`.
///
/// [`emit64_at`]'s twin over the u32 window — framing words: tags
/// and LEN length prefixes, whose read faces refuse six-plus-byte
/// spellings as too wide.
///
/// # Panics
///
/// If `width` lies outside `encoded_len32(word)..=5` (the u32
/// domain's window), or if `out.len() < width`.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "varint-slice")] {
/// use protobuf_edit::varint::{emit32_at, slice};
///
/// let mut buf = [0u8; 3];
/// emit32_at(0x08, 3, &mut buf); // field 1, varint — padded tag
/// assert_eq!(buf, [0x88, 0x80, 0x00]);
/// assert_eq!(slice::tag_word(&buf, 0, 3), Ok((0x08, 3)));
/// # }
/// ```
#[inline]
#[allow(clippy::as_conversions, reason = "the width fits usize on the crate's 32/64-bit targets")]
#[track_caller]
pub const fn emit32_at(word: u32, width: u32, out: &mut [u8]) {
    assert!(
        encoded_len32(word) <= width && width <= MAX_LEN32,
        "emit32_at: width outside the word's lawful range"
    );
    assert!(out.len() >= width as usize, "emit32_at: buffer shorter than the width");
    // SAFETY: just asserted `width` writable bytes at the head and
    // `width` inside `encoded_len32(word)..=5` — inside the
    // delegate's u32-domain contract.
    unsafe { write32_at(out.as_mut_ptr(), word, width) };
}

/// Emits `value` minimally by appending to `out`: one reservation,
/// then a direct write into the spare capacity — no intermediate
/// copy.
///
/// One of the two alloc faces of this stratum (with the
/// value-width pair's append), so it compiles with the buffered
/// editing and construction cells that consume it — the theorem
/// and slice-emission faces above carry no allocator obligation.
///
/// # Examples
///
/// ```
/// use protobuf_edit::varint::push64;
///
/// let mut out = vec![0x08]; // a record head already emitted
/// push64(&mut out, 150);
/// assert_eq!(out, [0x08, 0x96, 0x01]);
/// ```
#[cfg(any(
    test,
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
#[inline]
pub fn push64(out: &mut alloc::vec::Vec<u8>, value: u64) {
    Minimal64::of(value).append_to(out);
}

/// A word paired with its own minimal encoded width, minted whole:
/// the constructor is the only mint and computes the width, so the
/// pair cannot drift apart. Callers that need the width for
/// accounting read it from the object and spend the same object on
/// the emission — the width is reused, never recomputed and never
/// re-judged.
#[cfg(any(
    test,
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
#[derive(Clone, Copy)]
pub(crate) struct Minimal64 {
    value: u64,
    width: u32,
}

#[cfg(any(
    test,
    feature = "patch-grouped",
    feature = "patch-groupless",
    feature = "adopt-grouped",
    feature = "adopt-groupless",
    feature = "amend-grouped",
    feature = "amend-groupless",
    feature = "intake-grouped",
    feature = "intake-groupless",
    feature = "markup-grouped",
    feature = "markup-groupless",
    feature = "draft-grouped",
    feature = "draft-groupless",
    feature = "review-grouped",
    feature = "review-groupless",
    feature = "session-grouped",
    feature = "session-groupless",
    feature = "stream-adopt-grouped",
    feature = "stream-adopt-groupless",
    feature = "stream-draft-grouped",
    feature = "stream-draft-groupless",
    feature = "stream-intake-grouped",
    feature = "stream-intake-groupless",
    feature = "construct-grouped",
    feature = "construct-groupless"
))]
impl Minimal64 {
    /// Mints the pair; framing words widen in losslessly
    /// (`encoded_len32(w) == encoded_len64(w as u64)` — widening
    /// preserves bit width).
    #[inline]
    pub(crate) const fn of(value: u64) -> Self {
        Self { value, width: encoded_len64(value) }
    }

    /// The minimal encoded width, `1..=10` — the accounting face.
    /// The value builder's budget arithmetic is its one consumer,
    /// so it compiles with the construct cells.
    #[cfg(any(test, feature = "construct-grouped", feature = "construct-groupless"))]
    #[inline]
    pub(crate) const fn width(self) -> u32 {
        self.width
    }

    /// Appends the word at its width by direct spare-capacity
    /// write — the emission face. The width is the constructor's
    /// own `encoded_len64`, so it is nonzero and at most ten by
    /// the width theorem: the reservation below covers the raw
    /// write exactly.
    #[inline]
    #[allow(
        clippy::as_conversions,
        reason = "the encoded width fits usize on the crate's 32/64-bit targets"
    )]
    pub(crate) fn append_to(self, out: &mut alloc::vec::Vec<u8>) {
        let n = self.width as usize;
        out.reserve(n);
        // SAFETY: `reserve` guarantees `n` spare bytes past the
        // current length; `width` is the value's own encoded width
        // by the type's one mint, so `write64_at` initializes
        // exactly the `n` bytes `set_len` then covers.
        unsafe {
            write64_at(out.as_mut_ptr().add(out.len()), self.value, self.width);
            out.set_len(out.len() + n);
        }
    }
}

/// Emits `value` at its own minimal width and returns the
/// initialized prefix — the derived-minimal staging face: the
/// width is this function's own [`encoded_len64`], so the write
/// is judgment-free by the width theorem (the formula lands in
/// `1..=10`).
///
/// Stack staging is necessary here: the streaming sink faces
/// receive borrowed slices (`FnMut(&[u8])`), so there is no heap
/// buffer to write into directly.
#[cfg(any(
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]
#[allow(
    clippy::as_conversions,
    reason = "the encoded width lands in 1..=10 and fits usize on the crate's targets"
)]
pub(crate) const fn emit64_minimal(
    value: u64,
    out: &mut [core::mem::MaybeUninit<u8>; 10],
) -> &[u8] {
    let width = encoded_len64(value);
    // SAFETY: the staging array holds ten writable bytes and the
    // width theorem bounds `width` in `1..=10`; `write64_at`
    // initializes exactly `out[..width]`, the slice handed back.
    unsafe {
        write64_at(out.as_mut_ptr().cast::<u8>(), value, width);
        core::slice::from_raw_parts(out.as_ptr().cast::<u8>(), width as usize)
    }
}

/// Emits `value` padded to exactly `width` bytes (continuation
/// bits through `width − 1`, a bare terminal) and returns the
/// initialized prefix. Padding is lawful wire — the tolerant
/// kernels accept any in-class terminated width — and is the
/// equal-length writers' emission form: their width is a completed
/// construct's own carried width, so the judgment already happened
/// where the width was minted and none is repeated here.
///
/// Stack staging is necessary here, as for [`emit64_minimal`].
///
/// # Safety
/// `encoded_len64(value) <= width <= 10` (debug-asserted through
/// the delegate): narrower would drop value bits, wider would
/// leave the ten-byte staging window.
#[cfg(any(
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]
pub(crate) unsafe fn emit64_padded(
    value: u64,
    width: u8,
    out: &mut [core::mem::MaybeUninit<u8>; 10],
) -> &[u8] {
    // SAFETY: the staging array holds ten writable bytes and the
    // caller's contract bounds `width` in `encoded_len64(value)..=10`;
    // `write64_at` initializes exactly `out[..width]`, the slice
    // handed back.
    unsafe {
        write64_at(out.as_mut_ptr().cast::<u8>(), value, u32::from(width));
        core::slice::from_raw_parts(out.as_ptr().cast::<u8>(), usize::from(width))
    }
}

// ─── zigzag ───

/// Zigzag encoding: signed to wire (`sint64` direction).
///
/// # Examples
///
/// ```
/// use protobuf_edit::varint::{unzigzag64, zigzag64};
///
/// assert_eq!(zigzag64(0), 0);
/// assert_eq!(zigzag64(-1), 1);
/// assert_eq!(zigzag64(1), 2);
/// assert_eq!(unzigzag64(zigzag64(i64::MIN)), i64::MIN);
/// ```
#[inline]
#[must_use]
pub const fn zigzag64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)).cast_unsigned()
}

/// Zigzag decoding: wire to signed (`sint64` direction).
#[inline]
#[must_use]
pub const fn unzigzag64(wire: u64) -> i64 {
    (wire >> 1).cast_signed() ^ -((wire & 1).cast_signed())
}

/// Zigzag encoding in 32 bits (`sint32` direction; the wire word is
/// the zero-extension of this result).
#[inline]
#[must_use]
pub const fn zigzag32(value: i32) -> u32 {
    ((value << 1) ^ (value >> 31)).cast_unsigned()
}

/// Zigzag decoding in 32 bits.
#[inline]
#[must_use]
pub const fn unzigzag32(wire: u32) -> i32 {
    (wire >> 1).cast_signed() ^ -((wire & 1).cast_signed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoded_lengths_step_at_every_seven_bit_boundary() {
        // The bw9 form against the ceil definition, at every
        // boundary of the u64 domain plus the fixed pins.
        for k in 1..=9u32 {
            let below = (1u64 << (7 * k)) - 1;
            let at = 1u64 << (7 * k);
            assert_eq!(encoded_len64(below), k, "below 2^(7*{k})");
            assert_eq!(encoded_len64(at), k + 1, "at 2^(7*{k})");
        }
        assert_eq!(encoded_len64(0), 1);
        assert_eq!(encoded_len64(150), 2);
        assert_eq!(encoded_len64(u64::MAX), 10);
        assert_eq!(encoded_len32(0), 1);
        assert_eq!(encoded_len32(u32::MAX), 5);
    }

    #[test]
    fn encoded_lengths_hold_on_every_bit_width_class() {
        // The width formula is constant on each bit-width class,
        // so the classes are the theorem's exact finite quotient:
        // all 65 u64 classes and all 33 u32 classes, each judged
        // at its bottom and top against the ceil definition (the
        // zero class encodes as one byte).
        for bw in 0..=64u32 {
            let expected = if bw == 0 { 1 } else { bw.div_ceil(7) };
            let bottom = if bw == 0 { 0 } else { 1u64 << (bw - 1) };
            let top = if bw == 64 { u64::MAX } else { (1u64 << bw) - 1 };
            assert_eq!(encoded_len64(bottom), expected, "u64 class {bw} bottom");
            assert_eq!(encoded_len64(top), expected, "u64 class {bw} top");
        }
        for bw in 0..=32u32 {
            let expected = if bw == 0 { 1 } else { bw.div_ceil(7) };
            let bottom = if bw == 0 { 0 } else { 1u32 << (bw - 1) };
            let top = if bw == 32 { u32::MAX } else { (1u32 << bw) - 1 };
            assert_eq!(encoded_len32(bottom), expected, "u32 class {bw} bottom");
            assert_eq!(encoded_len32(top), expected, "u32 class {bw} top");
        }
    }

    #[test]
    fn width_vocabulary_mints_span_both_windows() {
        fn cap_mint<W: StepWidth>() -> W {
            // SAFETY: a window's cap terminates its own in-window
            // read.
            unsafe { W::met_unchecked(W::CAP) }
        }
        // The trait door mints through both impls at the caps…
        assert_eq!(cap_mint::<WordWidth>().w(), MAX_LEN32);
        assert_eq!(cap_mint::<ValueWidth>().w(), MAX_LEN64);
        // …and the met doors admit the windows' floors.
        // SAFETY: width 1 lies in both windows.
        let (word, value) = unsafe { (WordWidth::met_unchecked(1), ValueWidth::met_unchecked(1)) };
        assert_eq!((word.w(), value.w()), (1, 1));
        // The placeholder is the word window's floor, and framing
        // words widen into the value window losslessly.
        assert_eq!(WordWidth::MIN.as_inner(), 1);
        assert_eq!(ValueWidth::from(WordWidth::MIN).w(), 1);
    }

    #[test]
    #[cfg(any(feature = "inspect-grouped", feature = "inspect-groupless"))]
    fn width_only_reads_judge_exactly_as_value_reads() {
        // The width-only walk must agree with the assembling read
        // on every verdict — width, truncation, over-width, class.
        let mut cases: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec![
            alloc::vec![0x00],
            alloc::vec![0x7F],
            alloc::vec![0x80, 0x01],
            alloc::vec![0xFF; 9],
            alloc::vec![0x80; 10],
            alloc::vec![0x80, 0x80],
        ];
        cases.push({
            let mut v = alloc::vec![0xFF; 9];
            v.push(0x01);
            v
        });
        cases.push({
            let mut v = alloc::vec![0xFF; 9];
            v.push(0x02); // out of class at full width
            v
        });
        for data in &cases {
            let value = slice::value64(data, 0, data.len());
            // SAFETY: end == data.len().
            let width = unsafe { slice::width64_trusted(data, 0, data.len()) };
            assert_eq!(value.map(|(_, w)| w), width, "input {data:02X?}");
        }
    }

    #[test]
    fn emission_is_minimal_and_the_kernels_read_it_back() {
        for value in [0u64, 1, 127, 128, 150, 300, u64::from(u32::MAX), 1 << 63, u64::MAX] {
            let mut buf = [0u8; 10];
            let width = emit64(value, &mut buf);
            assert_eq!(width, encoded_len64(value));
            let (read, read_width) =
                slice::value64(&buf, 0, width as usize).expect("own emission reads back");
            assert_eq!((read, u32::from(read_width)), (value, width));
        }
    }

    #[test]
    fn push_appends_by_direct_spare_capacity_write() {
        let mut grown = alloc::vec![0xAA];
        push64(&mut grown, 150);
        push64(&mut grown, 0);
        assert_eq!(grown, [0xAA, 0x96, 0x01, 0x00]);
        // A reallocation boundary: push into a full Vec.
        let mut tight: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(1);
        tight.push(1);
        push64(&mut tight, u64::MAX);
        assert_eq!(tight.len(), 11);
        assert_eq!(tight[1..], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]);
    }

    #[test]
    fn the_minted_pair_serves_accounting_and_emission_alike() {
        for value in [0u64, 127, 128, 150, u64::MAX] {
            let mut computed = alloc::vec::Vec::new();
            push64(&mut computed, value);
            let minted = Minimal64::of(value);
            // The accounting face is the width theorem's own value…
            assert_eq!(minted.width(), encoded_len64(value));
            // …and the emission face spends the same pair.
            let mut spent = alloc::vec::Vec::new();
            minted.append_to(&mut spent);
            assert_eq!(computed, spent);
            assert_eq!(u32::try_from(spent.len()).ok(), Some(minted.width()));
        }
    }

    #[test]
    fn exact_width_emission_round_trips_over_the_u64_domain_edges() {
        // Every lawful (value, width) pair at the domain edges:
        // zero, the seven-bit boundaries below/at each width step,
        // and the full-width values. The width-10 terminal byte
        // carries one value bit, so both inhabitants of its class
        // are pinned: `(1 << 63) - 1` padded to ten ends 0x00,
        // `1 << 63` and `u64::MAX` end 0x01 (`LAST64`).
        let mut edges = alloc::vec![0u64, u64::MAX];
        for k in 1..=9u32 {
            edges.push((1 << (7 * k)) - 1);
            edges.push(1 << (7 * k));
        }
        edges.push((1 << 63) - 1);
        edges.push(1 << 63);
        for &value in &edges {
            let min = encoded_len64(value);
            for width in min..=MAX_LEN64 {
                let mut buf = [0u8; 10];
                emit64_at(value, width, &mut buf);
                let (read, read_width) = slice::value64(&buf, 0, width as usize)
                    .expect("exact-width emission is lawful wire");
                assert_eq!((read, u32::from(read_width)), (value, width), "value {value:#x}");
                if width == min {
                    // The minimal spelling is emit64's own.
                    let mut minimal = [0u8; 10];
                    emit64(value, &mut minimal);
                    assert_eq!(minimal[..width as usize], buf[..width as usize]);
                }
            }
        }
    }

    #[test]
    fn exact_width_word_emission_round_trips_over_the_u32_window() {
        // The framing-word twin at the u32 domain edges, read back
        // through both word faces: every emitted width is met by
        // `tag_word`, and every in-class word by `len_word` at the
        // same verdict. The width-5 terminal-byte classes are
        // pinned at both tops: `u32::MAX` ends 0x0F (`LAST32`),
        // the LEN-class top ends 0x07 (`LAST_LEN`).
        let edges =
            [0u32, 1, 8, 127, 128, (1 << 14) - 1, 1 << 14, (1 << 28) - 1, 1 << 28, u32::MAX];
        for &word in &edges {
            let min = encoded_len32(word);
            for width in min..=MAX_LEN32 {
                let mut buf = [0u8; 5];
                emit32_at(word, width, &mut buf);
                let (read, read_width) = slice::tag_word(&buf, 0, width as usize)
                    .expect("exact-width word emission is lawful wire");
                assert_eq!((read, u32::from(read_width)), (word, width), "word {word:#x}");
                if let Some(len) = crate::wire::PayloadLen::new(word) {
                    let (read, read_width) = slice::len_word(&buf, 0, width as usize)
                        .expect("in-class words read back as length prefixes");
                    assert_eq!((read, u32::from(read_width)), (len, width), "word {word:#x}");
                }
            }
        }
        // The LEN-class top's own terminal pin.
        let top = crate::wire::PayloadLen::MAX.as_inner();
        let mut buf = [0u8; 5];
        emit32_at(top, 5, &mut buf);
        assert_eq!(buf[4], LAST_LEN);
        assert_eq!(slice::len_word(&buf, 0, 5), Ok((crate::wire::PayloadLen::MAX, 5)));
    }

    #[test]
    #[should_panic(expected = "emit64_at: width outside the value's lawful range")]
    fn exact_width_emission_refuses_a_width_below_minimal() {
        emit64_at(128, 1, &mut [0u8; 10]);
    }

    #[test]
    #[should_panic(expected = "emit64_at: width outside the value's lawful range")]
    fn exact_width_emission_refuses_a_width_past_the_window() {
        emit64_at(0, 11, &mut [0u8; 16]);
    }

    #[test]
    #[should_panic(expected = "emit64_at: buffer shorter than the width")]
    fn exact_width_emission_refuses_a_short_buffer() {
        emit64_at(0, 4, &mut [0u8; 3]);
    }

    #[test]
    #[should_panic(expected = "emit32_at: width outside the word's lawful range")]
    fn exact_width_word_emission_refuses_a_width_past_the_window() {
        emit32_at(0, 6, &mut [0u8; 8]);
    }

    #[test]
    #[should_panic(expected = "emit32_at: buffer shorter than the width")]
    fn exact_width_word_emission_refuses_a_short_buffer() {
        emit32_at(0, 2, &mut [0u8; 1]);
    }

    #[test]
    fn padded_emission_is_lawful_wire_the_kernel_reads_back() {
        // 150 at its minimal width and padded to the full window.
        for width in [2u32, 3, 10] {
            let mut buf = [0u8; 10];
            // SAFETY: the stack buffer holds ten writable bytes and
            // `width` lies in `encoded_len64(150) = 2 ..= 10`.
            unsafe { write64_at(buf.as_mut_ptr(), 150, width) };
            let (read, read_width) =
                slice::value64(&buf, 0, width as usize).expect("padding is lawful wire");
            assert_eq!((read, u32::from(read_width)), (150, width));
        }
    }

    #[test]
    fn write32_covers_the_u32_window_and_reads_back_as_a_word() {
        // The u32 emission domain is the five-byte window: every
        // lawful width of every value reads back through the
        // u32-domain word face at that exact width.
        for value in [0u32, 1, 127, 128, 150, 1 << 21, u32::MAX] {
            let min = encoded_len32(value);
            for len in min..=MAX_LEN32 {
                let mut buf = [0u8; 5];
                // SAFETY: five writable bytes at the head, and
                // `len` lies in `encoded_len32(value)..=5`.
                unsafe { write32_at(buf.as_mut_ptr(), value, len) };
                let (read, width) = slice::tag_word(&buf, 0, len as usize)
                    .expect("a u32-window emission is a lawful u32-domain word");
                assert_eq!((read, u32::from(width)), (value, len));
            }
        }
    }

    #[test]
    fn zigzag_pins() {
        assert_eq!(zigzag64(0), 0);
        assert_eq!(zigzag64(-1), 1);
        assert_eq!(zigzag64(1), 2);
        assert_eq!(unzigzag64(zigzag64(i64::MIN)), i64::MIN);
        assert_eq!(zigzag32(-1), 1);
        assert_eq!(unzigzag32(zigzag32(i32::MIN)), i32::MIN);
    }
}
