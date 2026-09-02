//! The stream-stepping pump: the private stratum the scan, route,
//! and transcode families drive (both dialects each) and the
//! rewirer composes.
//!
//! One pump carries the whole cross-chunk reading state
//! ([`Pump`] itemizes it). The step faces split by
//! delivery — the held face retains a completed construct's source
//! bytes for byte-faithful re-emission, the spent face clears them
//! inside the step — and the fixed-collection faces read whole
//! payload windows against the seal the drivers admitted. The
//! stackless verdict machines ride [`RootPump`], the same stepping
//! over the root-only window; the streaming writers add the staged
//! head ([`StagedHead`]) so a record's tag survives while its
//! value construct reuses the carry.
//!
//! Every machine speaks its own public vocabulary: nothing in this
//! module is a public face, and each driver maps [`Verdict`] into
//! its own fault types at its own coordinates.

use crate::Standard;
use crate::varint::carry::{Carry, Collect, Step};
use crate::varint::{encoded_len32, encoded_len64};
use crate::wire::PayloadLen;

/// The [`Standard`] a split drive instance projects: the machines
/// match the runtime configuration once at feed admission and pick
/// an engine instance, so inside the instance the standard is this
/// literal and the settle test folds away after inlining.
#[cfg(any(
    feature = "scan-grouped",
    feature = "scan-groupless",
    feature = "route-grouped",
    feature = "route-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless",
    feature = "rewire-grouped",
    feature = "rewire-groupless"
))]
pub(crate) const fn standard_of(minimal: bool) -> Standard {
    if minimal { Standard::CanonicalMinimal } else { Standard::Tolerant }
}

/// Which fixed width is being collected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FixedKind {
    I32,
    I64,
}

impl FixedKind {
    pub(crate) const fn need(self) -> u8 {
        match self {
            Self::I32 => 4,
            Self::I64 => 8,
        }
    }
}

/// A word-step's verdicts, dialect-free. The dialect drivers map
/// these one-to-one into their own fault vocabularies (mirroring
/// how the carry kernel's domain wrappers map `step`).
pub(crate) enum Verdict<T> {
    /// Construct complete. On the held step face the carry still
    /// holds the construct's source bytes, so the source width —
    /// the re-emission fact the transcoder spends — is
    /// `carry.len()`, not a payload; on the spent face the step
    /// already cleared them (both pinned in this module's tests).
    Done(T),
    /// Chunk exhausted mid-construct; resume next feed.
    More,
    /// The sealed extent ended mid-construct (terminal).
    Cut,
    /// Ran past the domain window still continuing.
    TooWide,
    /// The terminal byte exceeds the domain class.
    OutOfClass,
    /// Wider than the value's minimal encoding (only under
    /// [`Standard::CanonicalMinimal`]). The carry still holds the
    /// refused construct, so the fault coordinate (the construct's
    /// first byte) is [`Pump::construct_start`].
    NonMinimal,
}

/// The stepping pump: absolute offset, innermost sealed LEN
/// endpoint, the one construct in flight (the carry kernel), the
/// declared standard, and the terminal latch — the whole
/// cross-chunk reading state (the module doc names the drivers).
///
/// The step face is the delivery split, machined: on the held face
/// `Done` leaves the carry holding the completed construct's
/// source bytes — the kernel's completion witness is retained
/// inside the step, the transcoder re-emits or stages the bytes
/// and then clears — while the spent face consumes the witness
/// inside the step, so a value consumer (validator, extractor)
/// owes no clear at all. Fault verdicts hold the refused construct
/// on both faces (the coordinate is [`Pump::construct_start`]).
pub(crate) struct Pump {
    /// Absolute stream offset (bytes consumed), kept strictly below
    /// `u64::MAX` by feed admission ([`Pump::admits`]).
    pub(crate) off: u64,
    /// Innermost sealed LEN endpoint (root: `u64::MAX`). The live
    /// value rides here; stack frames keep only shadowed
    /// predecessors (`prev_zone`), making pops O(1).
    pub(crate) zone: u64,
    pub(crate) carry: Carry,
    pub(crate) standard: Standard,
    /// Latched by a fault or an early stop. Terminality is its own
    /// axis, not a resume position: driving a terminal machine is
    /// the named caller bug, gated at every entry.
    pub(crate) terminal: bool,
}

impl Pump {
    pub(crate) const fn new(standard: Standard) -> Self {
        Self { off: 0, zone: u64::MAX, carry: Carry::new(), standard, terminal: false }
    }

    /// Coordinate admission for one chunk: true when the whole
    /// chunk fits the addressable stream,
    /// `off + chunk.len() ≤ u64::MAX − 1`.
    ///
    /// Within a feed, `off` grows only by bytes consumed from the
    /// admitted chunk — the carry steps and fixed collection
    /// advance it per byte taken, and the counting modes'
    /// `off += take` clamp `take` to the chunk residue — so
    /// admission at every feed keeps `off < u64::MAX` through
    /// every path: the root sentinel is unreachable as a cursor
    /// value, and the counting additions cannot wrap. Refusal is
    /// the machines' capability fault, judged before any byte of
    /// the chunk is read: a stream longer than `u64::MAX − 1`
    /// bytes has no lawful coordinate here.
    #[allow(
        clippy::as_conversions,
        reason = "chunk lengths widen losslessly into stream coordinates \
                  on the crate's 32/64-bit targets"
    )]
    pub(crate) const fn admits(&self, chunk: &[u8]) -> bool {
        chunk.len() as u64 <= (u64::MAX - 1).saturating_sub(self.off)
    }

    /// The current construct's first byte (fault coordinates): the
    /// carry holds everything consumed so far.
    #[allow(
        clippy::as_conversions,
        reason = "the carried width widens losslessly; const `From` is unavailable"
    )]
    pub(crate) const fn construct_start(&self) -> u64 {
        self.off - self.carry.len() as u64
    }

    /// Steps the head/tag word (five-byte u32 window) — the held
    /// face: `Done` retains the kernel's completion witness, so the
    /// construct's source bytes stay in the carry for the
    /// byte-faithful consumer (the transcoders re-emit or stage
    /// them, then clear). The width judgment reads the witness
    /// before it is released; the standard arrives as a value — a
    /// driver that split its engine per standard passes the
    /// instance's literal (the test folds away after inlining —
    /// [`standard_of`]), a unified driver passes its runtime
    /// configuration, and either way the tolerant path never
    /// computes a minimal width.
    ///
    /// The step methods sit inside every machine's per-construct
    /// dispatch; each is forced inline so the verdict can stay in
    /// registers instead of materializing through a return slot
    /// per construct — the register fact itself is a standing
    /// obligation of the performance epoch's instruments.
    #[inline(always)]
    pub(crate) fn step_tag_held(&mut self, chunk: &mut &[u8], standard: Standard) -> Verdict<u32> {
        match self.carry.step_tag(chunk, &mut self.off, self.zone) {
            Step::Done(complete) => {
                let width = complete.width();
                let word = complete.value();
                complete.retain();
                if width_padded(width, word, standard, encoded_len32) {
                    Verdict::NonMinimal
                } else {
                    Verdict::Done(word)
                }
            }
            Step::More => Verdict::More,
            Step::Cut => Verdict::Cut,
            Step::TooWide => Verdict::TooWide,
            Step::OutOfClass => Verdict::OutOfClass,
        }
    }

    /// Steps the LEN length word (five-byte length-class window) —
    /// the held face ([`Pump::step_tag_held`]).
    #[inline(always)]
    pub(crate) fn step_len_held(
        &mut self,
        chunk: &mut &[u8],
        standard: Standard,
    ) -> Verdict<PayloadLen> {
        match self.carry.step_len(chunk, &mut self.off, self.zone) {
            Step::Done(complete) => {
                let width = complete.width();
                let len = complete.value();
                complete.retain();
                if width_padded(width, len, standard, |len| encoded_len32(len.as_inner())) {
                    Verdict::NonMinimal
                } else {
                    Verdict::Done(len)
                }
            }
            Step::More => Verdict::More,
            Step::Cut => Verdict::Cut,
            Step::TooWide => Verdict::TooWide,
            Step::OutOfClass => Verdict::OutOfClass,
        }
    }

    /// Steps a varint value (ten-byte u64 window) — the held face
    /// ([`Pump::step_tag_held`]).
    #[inline(always)]
    pub(crate) fn step_value_held(
        &mut self,
        chunk: &mut &[u8],
        standard: Standard,
    ) -> Verdict<u64> {
        match self.carry.step_value64(chunk, &mut self.off, self.zone) {
            Step::Done(complete) => {
                let width = complete.width();
                let value = complete.value();
                complete.retain();
                if width_padded(width, value, standard, encoded_len64) {
                    Verdict::NonMinimal
                } else {
                    Verdict::Done(value)
                }
            }
            Step::More => Verdict::More,
            Step::Cut => Verdict::Cut,
            Step::TooWide => Verdict::TooWide,
            Step::OutOfClass => Verdict::OutOfClass,
        }
    }

    /// The spent face of [`Pump::step_tag_held`]: `Done` clears the
    /// carry in the same step, so a value consumer (validator,
    /// extractor) owes no bookkeeping. Fault verdicts still leave
    /// the refused construct held — the fault coordinate is
    /// [`Pump::construct_start`] — and a consumer that needs the
    /// completed construct's start reads it before stepping (the
    /// carry holds any resumed prefix there, so the coordinate is
    /// the same). The verdict machines are the spent faces' only
    /// consumers, so the faces compile with their cells.
    #[cfg(any(feature = "scan-grouped", feature = "scan-groupless"))]
    #[inline(always)]
    pub(crate) fn step_tag(&mut self, chunk: &mut &[u8], standard: Standard) -> Verdict<u32> {
        let verdict = self.step_tag_held(chunk, standard);
        if let Verdict::Done(_) = verdict {
            self.carry.clear();
        }
        verdict
    }

    /// The spent face of [`Pump::step_len_held`]
    /// ([`Pump::step_tag`]).
    #[cfg(any(feature = "scan-grouped", feature = "scan-groupless"))]
    #[inline(always)]
    pub(crate) fn step_len(
        &mut self,
        chunk: &mut &[u8],
        standard: Standard,
    ) -> Verdict<PayloadLen> {
        let verdict = self.step_len_held(chunk, standard);
        if let Verdict::Done(_) = verdict {
            self.carry.clear();
        }
        verdict
    }

    /// The spent face of [`Pump::step_value_held`]
    /// ([`Pump::step_tag`]).
    #[cfg(any(test, feature = "scan-grouped", feature = "scan-groupless"))]
    #[inline(always)]
    pub(crate) fn step_value(&mut self, chunk: &mut &[u8], standard: Standard) -> Verdict<u64> {
        let verdict = self.step_value_held(chunk, standard);
        if let Verdict::Done(_) = verdict {
            self.carry.clear();
        }
        verdict
    }

    /// Takes a fixed payload of `NEED` bytes; `Some` once whole.
    /// When the carry is empty the payload is read straight from
    /// the chunk (the dominant, whole-window path); a chunk-edge
    /// split falls through to
    /// [`collect_fixed`](Self::collect_fixed). The head admission
    /// (`zone − off ≥ NEED`, in force while the carry is empty)
    /// keeps the straight read inside the seal.
    #[allow(
        clippy::as_conversions,
        reason = "the pinned fixed widths (4, 8) widen losslessly into the stream coordinate"
    )]
    pub(crate) fn grab_fixed<const NEED: usize>(
        &mut self,
        chunk: &mut &[u8],
    ) -> Option<[u8; NEED]> {
        const { assert!(NEED == 4 || NEED == 8) };
        if self.carry.is_empty()
            && let Some((&bytes, rest)) = chunk.split_first_chunk::<NEED>()
        {
            self.off += NEED as u64;
            *chunk = rest;
            return Some(bytes);
        }
        self.collect_fixed::<NEED>(chunk)
    }

    /// Collects a fixed payload of `NEED` bytes; `Some` once whole,
    /// with the carry cleared for the next construct. The array is
    /// the source bytes themselves — a fixed payload is its own
    /// encoding, so it serves the value ask and the verbatim
    /// re-emission alike. The dialect drivers admit the width
    /// against the zone at head classification, so the kernel
    /// cannot report a cut here.
    #[allow(
        clippy::as_conversions,
        reason = "the pinned fixed widths (4, 8) narrow losslessly into the kernel's u8"
    )]
    pub(crate) fn collect_fixed<const NEED: usize>(
        &mut self,
        chunk: &mut &[u8],
    ) -> Option<[u8; NEED]> {
        const { assert!(NEED == 4 || NEED == 8) };
        // SAFETY: `NEED ≤ 10` by the const assertion; the carry
        // held nothing when this record's collection began (the
        // scan drivers' spent head face clears inside the step,
        // the transcoders' `stage_head` captures then clears) —
        // only this collection has grown it since, so `len ≤ NEED`
        // until `Done` clears; and the head admission
        // (`zone − off ≥ NEED`) holds the cursor inside the seal,
        // `off ≤ zone`, through every partial collection.
        match unsafe { self.carry.collect(chunk, &mut self.off, self.zone, NEED as u8) } {
            Collect::Done => {
                // SAFETY: `Done` means the carry holds exactly
                // `NEED` initialized bytes, and a byte array is
                // align-1 — the buffer prefix reads whole.
                let bytes = unsafe { self.carry.bytes().as_ptr().cast::<[u8; NEED]>().read() };
                self.carry.clear();
                Some(bytes)
            }
            Collect::More => None,
            // SAFETY: the drivers admit `NEED` against the zone
            // before entering collection (`zone − off ≥ NEED` at
            // the head), so the extent cannot end mid-payload.
            Collect::Cut => unsafe { core::hint::unreachable_unchecked() },
        }
    }
}

/// The one width judgment both pump forms settle with: true when
/// the declared standard is canonical and the met width is padded.
fn width_padded<T: Copy>(
    width: u8,
    value: T,
    standard: Standard,
    minimal: impl FnOnce(T) -> u32,
) -> bool {
    matches!(standard, Standard::CanonicalMinimal) && u32::from(width) != minimal(value)
}

// ─── the stackless verdict machines' pump ───

/// A completed step's verdicts on the root-only pump: [`Verdict`]
/// without the seal arm — no seal below the root sentinel exists
/// on a machine that never descends, so the kernel's cut is
/// discharged inside the pump and the drive arms match exactly
/// the verdicts that can occur.
#[cfg(feature = "scan-groupless")]
pub(crate) enum RootVerdict<T> {
    /// Construct complete, carry cleared (the spent face).
    Done(T),
    /// Chunk exhausted mid-construct; resume next feed.
    More,
    /// Ran past the domain window still continuing.
    TooWide,
    /// The terminal byte exceeds the domain class.
    OutOfClass,
    /// Wider than the value's minimal encoding (only under
    /// [`Standard::CanonicalMinimal`]); the carry holds the
    /// refused construct, so the fault coordinate is
    /// [`RootPump::construct_start`].
    NonMinimal,
}

/// The stackless verdict machines' pump: [`Pump`] with the sealed
/// zone dropped — never descending, no endpoint below the root
/// sentinel can exist, so the kernels judge against the constant
/// and the eight-byte field does not.
#[cfg(feature = "scan-groupless")]
pub(crate) struct RootPump {
    /// Absolute stream offset (bytes consumed), kept strictly below
    /// `u64::MAX` by feed admission ([`RootPump::admits`]).
    pub(crate) off: u64,
    pub(crate) carry: Carry,
    pub(crate) standard: Standard,
    /// Latched by a fault. Terminality is its own axis, not a
    /// resume position: driving a terminal machine is the named
    /// caller bug, gated at every entry.
    pub(crate) terminal: bool,
}

#[cfg(feature = "scan-groupless")]
impl RootPump {
    /// The whole window: the root sentinel, by construction rather
    /// than by field.
    const ZONE: u64 = u64::MAX;

    pub(crate) const fn new(standard: Standard) -> Self {
        Self { off: 0, carry: Carry::new(), standard, terminal: false }
    }

    /// Coordinate admission for one chunk ([`Pump::admits`]).
    #[allow(
        clippy::as_conversions,
        reason = "chunk lengths widen losslessly into stream coordinates \
                  on the crate's 32/64-bit targets"
    )]
    pub(crate) const fn admits(&self, chunk: &[u8]) -> bool {
        chunk.len() as u64 <= (u64::MAX - 1).saturating_sub(self.off)
    }

    /// The current construct's first byte (fault coordinates): the
    /// carry holds everything consumed so far.
    #[allow(
        clippy::as_conversions,
        reason = "the carried width widens losslessly; const `From` is unavailable"
    )]
    pub(crate) const fn construct_start(&self) -> u64 {
        self.off - self.carry.len() as u64
    }

    /// Steps the head/tag word — the spent face ([`Pump::step_tag`])
    /// on the root-only window: a clean completion is consumed
    /// inside the step (the verdict machines re-emit nothing), a
    /// padded one is retained for its fault coordinate. The
    /// standard arrives as a value: the driver's per-standard
    /// engine passes its literal, so the tolerant instance folds
    /// the width judgment away.
    #[inline(always)]
    pub(crate) fn step_tag(&mut self, chunk: &mut &[u8], standard: Standard) -> RootVerdict<u32> {
        match self.carry.step_tag(chunk, &mut self.off, Self::ZONE) {
            Step::Done(complete) => {
                if width_padded(complete.width(), complete.value(), standard, encoded_len32) {
                    complete.retain();
                    return RootVerdict::NonMinimal;
                }
                RootVerdict::Done(complete.take())
            }
            Step::More => RootVerdict::More,
            // SAFETY: the zone is the root sentinel and feed
            // admission keeps `off + residue < u64::MAX`, so the
            // kernel's window is never seal-clipped.
            Step::Cut => unsafe { core::hint::unreachable_unchecked() },
            Step::TooWide => RootVerdict::TooWide,
            Step::OutOfClass => RootVerdict::OutOfClass,
        }
    }

    /// Steps the LEN length word — the spent face
    /// ([`Pump::step_len`]) on the root-only window
    /// ([`RootPump::step_tag`]).
    #[inline(always)]
    pub(crate) fn step_len(
        &mut self,
        chunk: &mut &[u8],
        standard: Standard,
    ) -> RootVerdict<PayloadLen> {
        match self.carry.step_len(chunk, &mut self.off, Self::ZONE) {
            Step::Done(complete) => {
                if width_padded(complete.width(), complete.value(), standard, |len| {
                    encoded_len32(len.as_inner())
                }) {
                    complete.retain();
                    return RootVerdict::NonMinimal;
                }
                RootVerdict::Done(complete.take())
            }
            Step::More => RootVerdict::More,
            // SAFETY: the zone is the root sentinel and feed
            // admission keeps `off + residue < u64::MAX`, so the
            // kernel's window is never seal-clipped.
            Step::Cut => unsafe { core::hint::unreachable_unchecked() },
            Step::TooWide => RootVerdict::TooWide,
            Step::OutOfClass => RootVerdict::OutOfClass,
        }
    }

    /// Steps a varint value — the spent face ([`Pump::step_value`])
    /// on the root-only window ([`RootPump::step_tag`]).
    #[inline(always)]
    pub(crate) fn step_value(&mut self, chunk: &mut &[u8], standard: Standard) -> RootVerdict<u64> {
        match self.carry.step_value64(chunk, &mut self.off, Self::ZONE) {
            Step::Done(complete) => {
                if width_padded(complete.width(), complete.value(), standard, encoded_len64) {
                    complete.retain();
                    return RootVerdict::NonMinimal;
                }
                RootVerdict::Done(complete.take())
            }
            Step::More => RootVerdict::More,
            // SAFETY: the zone is the root sentinel and feed
            // admission keeps `off + residue < u64::MAX`, so the
            // kernel's window is never seal-clipped.
            Step::Cut => unsafe { core::hint::unreachable_unchecked() },
            Step::TooWide => RootVerdict::TooWide,
            Step::OutOfClass => RootVerdict::OutOfClass,
        }
    }

    /// Takes a fixed payload of `NEED` bytes; `Some` once whole
    /// ([`Pump::grab_fixed`] on the root-only window — the driver's
    /// head admission judges `NEED` against the coordinate space,
    /// so the kernel cannot report a cut here).
    #[allow(
        clippy::as_conversions,
        reason = "the pinned fixed widths (4, 8) widen losslessly into the stream coordinate"
    )]
    pub(crate) fn grab_fixed<const NEED: usize>(
        &mut self,
        chunk: &mut &[u8],
    ) -> Option<[u8; NEED]> {
        const { assert!(NEED == 4 || NEED == 8) };
        if self.carry.is_empty()
            && let Some((&bytes, rest)) = chunk.split_first_chunk::<NEED>()
        {
            self.off += NEED as u64;
            *chunk = rest;
            return Some(bytes);
        }
        self.collect_fixed::<NEED>(chunk)
    }

    /// Collects a fixed payload across chunk edges
    /// ([`Pump::collect_fixed`] on the root-only window).
    #[allow(
        clippy::as_conversions,
        reason = "the pinned fixed widths (4, 8) narrow losslessly into the kernel's u8"
    )]
    pub(crate) fn collect_fixed<const NEED: usize>(
        &mut self,
        chunk: &mut &[u8],
    ) -> Option<[u8; NEED]> {
        const { assert!(NEED == 4 || NEED == 8) };
        // SAFETY: `NEED ≤ 10` by the const assertion; the carry
        // held nothing when this record's collection began (the
        // spent head face clears inside the step) — only this
        // collection has grown it since, so `len ≤ NEED` until
        // `Done` clears; and the driver's head admission
        // (`u64::MAX − off ≥ NEED`) holds the cursor inside the
        // coordinate space through every partial collection.
        match unsafe { self.carry.collect(chunk, &mut self.off, Self::ZONE, NEED as u8) } {
            Collect::Done => {
                // SAFETY: `Done` means the carry holds exactly
                // `NEED` initialized bytes, and a byte array is
                // align-1 — the buffer prefix reads whole.
                let bytes = unsafe { self.carry.bytes().as_ptr().cast::<[u8; NEED]>().read() };
                self.carry.clear();
                Some(bytes)
            }
            Collect::More => None,
            // SAFETY: the driver admits `NEED` against the
            // coordinate space before entering collection, and the
            // root sentinel clips nothing below it.
            Collect::Cut => unsafe { core::hint::unreachable_unchecked() },
        }
    }
}

// The field-absence pin: the root-only pump is exactly the shared
// pump minus its eight-byte zone word.
#[cfg(feature = "scan-groupless")]
const _: () = assert!(core::mem::size_of::<RootPump>() + 8 == core::mem::size_of::<Pump>());

// ─── the write machines' staging ledger ───
//
// The streaming writers (transcode, rewire) drive this pump and
// hold each record's completed tag here while its value construct
// reuses the carry; the read machines never stage, so the ledger
// rides behind the writers' features.

#[cfg(any(
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]
impl Pump {
    /// True when an entered LEN ancestor seals the length algebra:
    /// the streaming writers' judgment over the pump's zone, which
    /// doubles as the locked-layer latch — entered ancestors exist
    /// iff `zone != u64::MAX` (groups never move it).
    pub(crate) const fn locked(&self) -> bool {
        self.zone != u64::MAX
    }
}

/// The staged record head: tag bytes held between tag completion
/// and the record's verdict (the ≤ 5 B half of the staging
/// ledger; the carry holds the current construct's ≤ 10 B).
///
/// The copy out of the carry is structurally necessary with a
/// single carry: the value construct starts assembling there
/// before the record's verdict frees the tag. Dissolving it means
/// a second carry, or a kernel split at tag boundaries — more
/// state than the five bytes it saves.
///
/// Invariant: `buf[..len]` is initialized with `len ≤ 5` —
/// `capture` writes exactly `len` bytes before setting it.
#[cfg(any(
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]
pub(crate) struct StagedHead {
    buf: [core::mem::MaybeUninit<u8>; 5],
    len: u8,
}

#[cfg(any(
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]
impl StagedHead {
    pub(crate) const fn new() -> Self {
        Self { buf: [core::mem::MaybeUninit::uninit(); 5], len: 0 }
    }

    /// Captures the completed tag's source bytes out of the carry,
    /// freeing it for the record's value construct.
    ///
    /// # Safety
    /// The carry must hold a completed *tag* construct — at most
    /// five bytes, the tag window's cap (`step_tag` can carry no
    /// more).
    #[allow(clippy::as_conversions, reason = "a count just proven ≤ 5 narrows losslessly into u8")]
    pub(crate) const unsafe fn capture(&mut self, carry: &Carry) {
        let bytes = carry.bytes();
        // SAFETY: the caller's contract, verbatim.
        unsafe { core::hint::assert_unchecked(bytes.len() <= 5) };
        // SAFETY: `bytes.len() ≤ 5` bounds the destination inside
        // the five-byte buffer, the source is the carry's own
        // initialized prefix, and a borrowed carry cannot overlap
        // the owned buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.buf.as_mut_ptr().cast::<u8>(),
                bytes.len(),
            );
        }
        self.len = bytes.len() as u8;
    }

    /// The staged bytes (the record head's exact source encoding).
    #[allow(clippy::as_conversions, reason = "the byte count widens losslessly into usize")]
    pub(crate) const fn bytes(&self) -> &[u8] {
        // SAFETY: `buf[..len]` is initialized with `len ≤ 5` — the
        // type invariant `capture` maintains.
        unsafe { core::slice::from_raw_parts(self.buf.as_ptr().cast::<u8>(), self.len as usize) }
    }

    /// Staged byte count (the head's source width).
    pub(crate) const fn len(&self) -> u8 {
        self.len
    }
}

#[cfg(any(
    feature = "rewire-grouped",
    feature = "rewire-groupless",
    feature = "transcode-grouped",
    feature = "transcode-groupless"
))]
const _: () = assert!(core::mem::size_of::<StagedHead>() == 6);

#[cfg(test)]
mod tests;
