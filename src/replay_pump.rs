//! The replay-stepping pump: the private stratum every replay
//! cell's walks drive — the carry kernel pulled over one
//! [`ReplayWalk`], in whole-source (`u64`) coordinates.
//!
//! The stream cells' pump is push-shaped (arrival is the caller's
//! fact); this one pulls — the machine decides when to fill, how
//! much to consume, and what to skip. One pump carries one walk's
//! reading state: the walk itself, the absolute offset, the
//! innermost sealed LEN endpoint, and the one construct in flight
//! (the carry kernel), so verdicts are independent of how the
//! provider partitions its views. Skips report their actual
//! advance, which is how a document end inside a never-read
//! extent stays visible.
//!
//! Refused constructs stay held in the carry (their width is the
//! fault coordinate's subtrahend, [`Pump::construct_start`]); a
//! driver that resumes past a refusal — the offline cells'
//! speculation unwind — clears explicitly
//! ([`Pump::clear_construct`]).
//!
//! Every machine speaks its own public vocabulary: nothing here
//! is a public face, and each driver maps [`StepRead`] into its
//! own fault types at its own coordinates.

use crate::Standard;
use crate::replay_source::{Chunk, ReplayWalk, SupplyFault};
#[cfg(any(
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
use crate::varint::carry::Collect;
use crate::varint::carry::{Carry, Step};
use crate::varint::{ValueWidth, WordWidth, encoded_len32, encoded_len64};
use crate::wire::PayloadLen;

/// One construct-step's verdicts, dialect-free. The drivers map
/// these one-to-one into their fault vocabularies.
pub(crate) enum StepRead<T, W, E> {
    /// Construct complete: the assembled value and its met source
    /// width (the carry is spent).
    Done {
        /// The assembled word.
        value: T,
        /// The construct's met source width.
        width: W,
    },
    /// The walk's finite end at a construct boundary (nothing in
    /// flight) — only the head face judges it; the interior faces
    /// report [`StepRead::SourceEnd`] instead.
    End,
    /// The innermost sealed extent ended mid-construct
    /// (terminal; the construct stays held).
    SealCut,
    /// The walk ended mid-construct (terminal; the construct
    /// stays held).
    SourceEnd,
    /// Ran past the domain window still continuing (held).
    TooWide,
    /// The terminal byte exceeds the domain class (held).
    OutOfClass,
    /// Wider than the value's minimal encoding, only under
    /// [`Standard::CanonicalMinimal`]. The construct was spent
    /// inside the step, so its met width rides the verdict — the
    /// fault coordinate is [`Pump::off`] minus this width.
    NonMinimal {
        /// The construct's met source width. The
        /// standard-parameterized cells read it for the fault
        /// coordinate; the tolerant-only editor never meets the
        /// verdict.
        #[cfg_attr(
            not(any(
                feature = "survey-grouped",
                feature = "survey-groupless",
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
            )),
            expect(
                dead_code,
                reason = "the standard-parameterized cells read the width for their \
                          fault coordinates"
            )
        )]
        width: W,
    },
    /// The accumulated offset would leave the addressable
    /// coordinate space (`u64::MAX − 1`).
    Exhausted,
    /// The provider refused; the first unread offset is
    /// [`Pump::off`].
    Fault(SupplyFault<E>),
}

/// A fixed collection's verdicts — the exact outcome set of a
/// count-bounded read: no window, no class, no minimality (a fixed
/// payload has no spelling variance), no clean End (the drivers
/// admit the count against the zone before asking).
#[cfg(any(
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
pub(crate) enum GrabRead<const NEED: usize, E> {
    /// Collection complete: the payload bytes themselves.
    Done([u8; NEED]),
    /// The walk ended mid-collection (terminal; the collected
    /// prefix stays held).
    SourceEnd,
    /// The accumulated offset would leave the addressable
    /// coordinate space (`u64::MAX − 1`).
    Exhausted,
    /// The provider refused; the first unread offset is
    /// [`Pump::off`].
    Fault(SupplyFault<E>),
}

/// The one width judgment every step settles with: true when the
/// declared standard is canonical and the met width is padded.
fn width_padded<T: Copy>(
    width: u32,
    value: T,
    standard: Standard,
    minimal: impl FnOnce(T) -> u32,
) -> bool {
    matches!(standard, Standard::CanonicalMinimal) && width != minimal(value)
}

/// One fill's outcome, position-admitted.
enum ViewRead<'a, E> {
    Bytes(Chunk<'a>),
    End,
    Exhausted,
    Fault(SupplyFault<E>),
}

/// Fills and admits the view against the coordinate space:
/// consuming it whole must keep the offset strictly below
/// `u64::MAX` (the root sentinel is reserved), the same admission
/// the stream cells judge per feed. A free function over the walk
/// alone, so the carry and the coordinates stay borrowable beside
/// the lent view.
#[allow(
    clippy::as_conversions,
    reason = "view lengths widen losslessly into stream coordinates \
              on the crate's 32/64-bit targets"
)]
fn view_of<W: ReplayWalk>(walk: &mut W, off: u64) -> ViewRead<'_, W::Error> {
    match walk.fill() {
        Ok(Some(view)) => {
            if view.len() as u64 > (u64::MAX - 1).saturating_sub(off) {
                ViewRead::Exhausted
            } else {
                ViewRead::Bytes(view)
            }
        }
        Ok(None) => ViewRead::End,
        Err(fault) => ViewRead::Fault(fault),
    }
}

/// The pulled reading state over one walk. The zone is the
/// innermost sealed LEN endpoint (`u64::MAX`: the unbounded
/// root); drivers push and restore it through their own frames,
/// exactly as the stream drivers do over their pump.
pub(crate) struct Pump<W: ReplayWalk> {
    walk: W,
    /// Absolute source offset (bytes consumed or skipped), kept
    /// strictly below `u64::MAX` by the per-view admission in
    /// [`Pump::view`].
    pub(crate) off: u64,
    /// Innermost sealed LEN endpoint (root: `u64::MAX`). The live
    /// value rides here; driver frames keep shadowed
    /// predecessors.
    pub(crate) zone: u64,
    carry: Carry,
}

/// The step loop over one carry-kernel domain face: fills, steps
/// across view boundaries, and books consumption — one body for
/// the three windows. `$W` names the face's width window; the
/// completion's counted width mints once here, at verdict
/// construction. `$end` is the verdict for a walk end at a
/// construct boundary (the head face's clean end; mid-record for
/// the interior faces).
macro_rules! step_loop {
    ($self:ident, $face:ident, $W:ty, $standard:ident, $minimal:expr, $end:expr) => {{
        loop {
            let view = match view_of(&mut $self.walk, $self.off) {
                ViewRead::Bytes(view) => view,
                ViewRead::End => {
                    return if $self.carry.is_empty() { $end } else { StepRead::SourceEnd };
                }
                ViewRead::Exhausted => return StepRead::Exhausted,
                ViewRead::Fault(fault) => return StepRead::Fault(fault),
            };
            let whole = view.len();
            let mut chunk = view.bytes();
            let step = $self.carry.$face(&mut chunk, &mut $self.off, $self.zone);
            let taken = whole - chunk.len();
            match step {
                Step::Done(complete) => {
                    // SAFETY: the completion's width is the
                    // kernel's counted window under this face's
                    // cap.
                    let width = unsafe {
                        <$W as crate::varint::StepWidth>::met_unchecked(complete.width())
                    };
                    let value = complete.take();
                    $self.walk.consume(taken);
                    if width_padded(width.w(), value, $standard, $minimal) {
                        return StepRead::NonMinimal { width };
                    }
                    return StepRead::Done { value, width };
                }
                Step::More => {
                    $self.walk.consume(taken);
                }
                Step::Cut => {
                    $self.walk.consume(taken);
                    return StepRead::SealCut;
                }
                Step::TooWide => {
                    $self.walk.consume(taken);
                    return StepRead::TooWide;
                }
                Step::OutOfClass => {
                    $self.walk.consume(taken);
                    return StepRead::OutOfClass;
                }
            }
        }
    }};
}

impl<W: ReplayWalk> Pump<W> {
    /// Mounts a fresh walk (position zero).
    pub(crate) const fn new(walk: W) -> Self {
        Self { walk, off: 0, zone: u64::MAX, carry: Carry::new() }
    }

    /// The current construct's first byte (fault coordinates):
    /// the carry holds everything consumed toward it so far —
    /// refused constructs included, until
    /// [`Pump::clear_construct`].
    #[allow(
        clippy::as_conversions,
        reason = "the carried width widens losslessly; const `From` is unavailable"
    )]
    pub(crate) const fn construct_start(&self) -> u64 {
        self.off - self.carry.len() as u64
    }

    /// Discards a refused construct — the resume face of the
    /// offline cells' speculation unwind (a refusal stays held
    /// for its coordinates until the holder is done quoting it).
    /// The unwinding cells and the writers' post-refusal source
    /// probes are its consumers.
    #[cfg(any(
        feature = "survey-grouped",
        feature = "survey-groupless",
        feature = "replay-rewrite-grouped",
        feature = "replay-rewrite-groupless",
        feature = "replay-convert-grouped",
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
    pub(crate) const fn clear_construct(&mut self) {
        self.carry.clear();
    }

    /// Steps the head/tag word (five-byte u32 window). The one
    /// face that can lawfully meet the walk's end: at a construct
    /// boundary it judges [`StepRead::End`] — the drivers resolve
    /// extent closes before stepping, so a clean end is exactly
    /// "nothing in flight at the root".
    pub(crate) fn step_tag(&mut self, standard: Standard) -> StepRead<u32, WordWidth, W::Error> {
        step_loop!(self, step_tag, WordWidth, standard, encoded_len32, StepRead::End)
    }

    /// Steps the LEN length word (five-byte length-class window).
    /// A walk end here is mid-record: [`StepRead::SourceEnd`].
    pub(crate) fn step_len(
        &mut self,
        standard: Standard,
    ) -> StepRead<PayloadLen, WordWidth, W::Error> {
        step_loop!(
            self,
            step_len,
            WordWidth,
            standard,
            |len: PayloadLen| encoded_len32(len.as_inner()),
            StepRead::SourceEnd
        )
    }

    /// Steps a varint value (ten-byte u64 window). A walk end
    /// here is mid-record: [`StepRead::SourceEnd`].
    pub(crate) fn step_value(&mut self, standard: Standard) -> StepRead<u64, ValueWidth, W::Error> {
        step_loop!(self, step_value64, ValueWidth, standard, encoded_len64, StepRead::SourceEnd)
    }

    /// Collects a fixed payload of `NEED` bytes. The drivers
    /// admit the width against the zone at head classification
    /// (`zone − off ≥ NEED`), so the seal cannot cut it; the walk
    /// end still can ([`GrabRead::SourceEnd`], collected prefix
    /// held). The word-banking cells are its consumers: the rule
    /// writer seeks past fixed payloads instead of reading them.
    #[cfg(any(
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
    pub(crate) fn grab_fixed<const NEED: usize>(&mut self) -> GrabRead<NEED, W::Error> {
        const { assert!(NEED == 4 || NEED == 8) };
        loop {
            let view = match view_of(&mut self.walk, self.off) {
                ViewRead::Bytes(view) => view,
                ViewRead::End => return GrabRead::SourceEnd,
                ViewRead::Exhausted => return GrabRead::Exhausted,
                ViewRead::Fault(fault) => return GrabRead::Fault(fault),
            };
            let whole = view.len();
            let mut chunk = view.bytes();
            // SAFETY: `NEED ≤ 10` by the const assertion; the
            // carry held nothing when this collection began (every
            // completed construct is spent inside its step, and
            // refusals are terminal for the extent) and only this
            // collection has grown it since, so `len ≤ NEED` until
            // it completes; the drivers' head admission
            // (`zone − off ≥ NEED`) holds `off ≤ zone` through
            // every partial collection.
            let collect = unsafe {
                #[allow(
                    clippy::as_conversions,
                    reason = "the pinned fixed widths (4, 8) narrow losslessly into the \
                              kernel's u8"
                )]
                self.carry.collect(&mut chunk, &mut self.off, self.zone, NEED as u8)
            };
            let taken = whole - chunk.len();
            self.walk.consume(taken);
            match collect {
                Collect::Done => {
                    // SAFETY: `Done` means the carry holds exactly
                    // `NEED` initialized bytes, and a byte array
                    // is align-1 — the buffer prefix reads whole.
                    let bytes = unsafe { self.carry.bytes().as_ptr().cast::<[u8; NEED]>().read() };
                    self.carry.clear();
                    return GrabRead::Done(bytes);
                }
                Collect::More => {}
                // The head admission keeps the seal out of fixed
                // collections; reaching it is a driver ordering
                // bug, judged loudly.
                Collect::Cut => unreachable!("fixed collection admitted against the zone"),
            }
        }
    }

    /// Advances `n` bytes without lending them; reports the count
    /// actually advanced (shorter exactly when the walk's end
    /// arrives first — the supply contract's skip clause, with
    /// the offset already booked).
    ///
    /// # Errors
    ///
    /// The provider's refusal; the machine quotes the offset it
    /// last established.
    pub(crate) fn skip_bytes(&mut self, n: u64) -> Result<u64, SupplyFault<W::Error>> {
        debug_assert!(self.carry.is_empty(), "skips start at construct boundaries");
        let advanced = self.walk.skip(n)?;
        self.off += advanced;
        Ok(advanced)
    }

    /// Copies `n` bytes forward into `deliver`, view by view;
    /// reports the count actually delivered (shorter exactly when
    /// the walk's end arrives first). The views are the
    /// provider's own; nothing is staged.
    ///
    /// # Errors
    ///
    /// The provider's refusal, with everything already delivered
    /// standing (publication honesty is the caller's face-level
    /// story).
    pub(crate) fn copy_bytes(
        &mut self,
        n: u64,
        mut deliver: impl FnMut(&[u8]),
    ) -> Result<u64, SupplyFault<W::Error>> {
        debug_assert!(self.carry.is_empty(), "copies start at construct boundaries");
        let mut left = n;
        while left > 0 {
            let Some(view) = self.walk.fill()? else {
                return Ok(n - left);
            };
            #[allow(
                clippy::as_conversions,
                reason = "the min of a u64 and a usize-length view fits usize on the \
                          crate's 32/64-bit targets"
            )]
            let take = left.min(view.len() as u64) as usize;
            deliver(&view.bytes()[..take]);
            self.walk.consume(take);
            #[allow(clippy::as_conversions, reason = "usize widens losslessly into u64")]
            {
                left -= take as u64;
                self.off += take as u64;
            }
        }
        Ok(n)
    }

    /// True when at least one more byte exists — the end probe
    /// that arms a measured total length against a grown source.
    /// The splicing passes are its consumers, so it compiles with
    /// the writer cells.
    ///
    /// # Errors
    ///
    /// The provider's refusal.
    #[cfg(any(
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
    pub(crate) fn probe_more(&mut self) -> Result<bool, SupplyFault<W::Error>> {
        Ok(self.walk.fill()?.is_some())
    }
}
