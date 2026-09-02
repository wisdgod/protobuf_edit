//! The grouped router: groups walk structurally.
//!
//! The mixed stack interleaves committed-LEN frames and open-group
//! frames; the innermost sealed endpoint rides the cursor register
//! and frames keep only shadowed predecessors, so pops are O(1) and
//! the endpoint check is `off == zone`. A targeted group is a tap
//! like a targeted LEN, framed by [`Sink::on_group_enter`] and
//! [`Sink::on_group_exit`]: its body streams as segments between
//! the two framing tags, and neither tag ever enters its segments
//! — the end tag is body only to the taps outside the closing
//! group.
//!
//! Coordinates: read · stream · static · grouped · Standard (value-level).
//!
//! # Examples
//!
//! A targeted group streams its body — here across a chunk
//! boundary that splits the end tag, which the machine classifies
//! before it forwards anything.
//!
//! ```
//! use core::ops::ControlFlow;
//! use protobuf_edit::path::{PathId, Program, Segment};
//! use protobuf_edit::route::grouped::{Router, Sink};
//! use protobuf_edit::route::Standard;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! #[derive(Default)]
//! struct Body {
//!     bytes: Vec<u8>,
//!     framed: u32,
//! }
//! impl Sink for Body {
//!     fn on_segment(
//!         &mut self,
//!         _path: PathId,
//!         _at: u64,
//!         _seg_at: u64,
//!         bytes: &[u8],
//!     ) -> ControlFlow<()> {
//!         self.bytes.extend_from_slice(bytes);
//!         ControlFlow::Continue(())
//!     }
//!     fn on_group_exit(
//!         &mut self,
//!         _path: PathId,
//!         _field: FieldNumber,
//!         _at: u64,
//!         _body_end: u64,
//!         _end: u64,
//!     ) -> ControlFlow<()> {
//!         self.framed += 1;
//!         ControlFlow::Continue(())
//!     }
//! }
//!
//! // Target the field-1000 group (its tags span two bytes each).
//! let big = FieldNumber::new(1000).unwrap();
//! let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(big)]];
//! let program = Program::over(&paths).unwrap();
//!
//! // group f1000 { varint f1=150 } — split inside the end tag.
//! let msg = [0xC3, 0x3E, 0x08, 0x96, 0x01, 0xC4, 0x3E];
//! let mut sink = Body::default();
//! let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::REFERENCE);
//! router.feed(&msg[..6], &mut sink).unwrap();
//! router.feed(&msg[6..], &mut sink).unwrap();
//! router.finish().unwrap();
//! assert_eq!(sink.bytes, [0x08, 0x96, 0x01]);
//! assert_eq!(sink.framed, 1);
//! ```

use alloc::vec::Vec;
use core::num::NonZeroU32;
use core::ops::ControlFlow;

use super::{Flow, ReadFault};
use crate::admission::usize_of;
use crate::path::{Matcher, PathId, Program};
use crate::pump::{FixedKind, Pump, Verdict, standard_of};
use crate::wire::grouped::{RecordKind, TagClass, classify};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, FaultClass, Stage, Standard};

/// The event consumer; every `Break` is an orderly early stop
/// (terminal). Every event names the path that selected it — the
/// program decides delivery, the sink only watches.
///
/// All defaults continue: a sink that overrides nothing turns the
/// router into a pure validator of everything the program commits
/// and every group the syntax walks (with an empty program, the
/// wire-level validator itself).
///
/// Segment delivery: one piece of a tapped container's body, once
/// per open tap — outermost container first, ascending [`PathId`]
/// within one container. Pieces of one tap instance are contiguous
/// and tile its body exactly in source order; a tapped group's
/// framing tags are outside its body.
pub trait Sink {
    /// A targeted varint record completed: the wire word by value
    /// (schema semantics belong to the caller via the `scalar`
    /// matrix). `at` is the record head — position is identity in
    /// a stream, so nested occurrences stay distinguishable.
    #[inline]
    fn on_varint(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        value: u64,
    ) -> ControlFlow<()> {
        let _ = (path, field, at, value);
        ControlFlow::Continue(())
    }

    /// A targeted I32 record completed: four little-endian bits;
    /// `at` is the record head.
    #[inline]
    fn on_i32(&mut self, path: PathId, field: FieldNumber, at: u64, bits: u32) -> ControlFlow<()> {
        let _ = (path, field, at, bits);
        ControlFlow::Continue(())
    }

    /// A targeted I64 record completed: eight little-endian bits;
    /// `at` is the record head.
    #[inline]
    fn on_i64(&mut self, path: PathId, field: FieldNumber, at: u64, bits: u64) -> ControlFlow<()> {
        let _ = (path, field, at, bits);
        ControlFlow::Continue(())
    }

    /// A targeted LEN's head: a tap opens. `at` is the record head
    /// (the tap's identity in every following [`on_segment`]);
    /// `len` is the declared body length. The body follows as
    /// segments, then [`on_len_exit`] closes the pair.
    ///
    /// [`on_segment`]: Self::on_segment
    /// [`on_len_exit`]: Self::on_len_exit
    #[inline]
    fn on_len(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        len: PayloadLen,
    ) -> ControlFlow<()> {
        let _ = (path, field, at, len);
        ControlFlow::Continue(())
    }

    /// One piece of an open tap's body, borrowing the current feed
    /// (copy to retain). `at` names the tap (its record head),
    /// `seg_at` this piece's own absolute offset. Inside a parsed
    /// container a piece is one proven construct; inside a counted
    /// tap pieces are raw and chunk-bounded. A zero-length body
    /// delivers no piece.
    #[inline]
    fn on_segment(&mut self, path: PathId, at: u64, seg_at: u64, bytes: &[u8]) -> ControlFlow<()> {
        let _ = (path, at, seg_at, bytes);
        ControlFlow::Continue(())
    }

    /// A tapped LEN's body ended: the tap closes. `at` is the
    /// record head [`on_len`] announced; `end` is the payload end.
    ///
    /// [`on_len`]: Self::on_len
    #[inline]
    fn on_len_exit(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        end: u64,
    ) -> ControlFlow<()> {
        let _ = (path, field, at, end);
        ControlFlow::Continue(())
    }

    /// A targeted group opened: a tap on its body. `at` is the
    /// record head (the open tag's start — the tap's identity in
    /// every following [`on_segment`]); `body_at` is the open
    /// tag's end, where the body begins.
    ///
    /// [`on_segment`]: Self::on_segment
    #[inline]
    fn on_group_enter(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        body_at: u64,
    ) -> ControlFlow<()> {
        let _ = (path, field, at, body_at);
        ControlFlow::Continue(())
    }

    /// A targeted group closed at its verified end tag. `at` is
    /// the record head [`on_group_enter`] announced, `body_end`
    /// the end tag's start (where the body ended), `end` the end
    /// tag's end (the whole record's end).
    ///
    /// [`on_group_enter`]: Self::on_group_enter
    #[inline]
    fn on_group_exit(
        &mut self,
        path: PathId,
        field: FieldNumber,
        at: u64,
        body_end: u64,
        end: u64,
    ) -> ControlFlow<()> {
        let _ = (path, field, at, body_end, end);
        ControlFlow::Continue(())
    }
}

/// The all-default sink: watch nothing — with an empty program,
/// the pure wire-level validator's consumer face.
impl Sink for () {}

/// One law violation, terminal: where, and which law.
///
/// `at`'s meaning per kind: a [`FaultKind::Read`] names the
/// refused construct's first byte, except that a
/// [`ReadFault::SealCut`] and
/// [`GroupUnclosedAtLenEnd`](FaultKind::GroupUnclosedAtLenEnd)
/// name the sealed endpoint and a [`ReadFault::StreamEnd`] names
/// the stream end; structural faults name the judgment point; an
/// [`OffsetExhausted`](FaultKind::OffsetExhausted) names the
/// current offset (the refused chunk would begin there);
/// `FixedTruncated`, `PayloadTruncated`,
/// [`UnclosedLen`](FaultKind::UnclosedLen), and
/// [`GroupUnclosed`](FaultKind::GroupUnclosed) name the stream
/// end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fault {
    at: u64,
    kind: FaultKind,
}

// The error arm's layout budget: the kind stays at 12 bytes and
// the carrier within 24 (u64-alignment padding differs by target,
// so the carrier is a ceiling, not an equality).
const _: () = assert!(core::mem::size_of::<FaultKind>() == 12);
const _: () = assert!(core::mem::size_of::<Fault>() <= 24);

impl Fault {
    /// The coordinate (absolute stream offset).
    #[inline]
    #[must_use]
    pub const fn at(self) -> u64 {
        self.at
    }

    /// The violated law.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> FaultKind {
        self.kind
    }
}

impl core::fmt::Display for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at input offset {}", self.kind, self.at)
    }
}

impl core::error::Error for Fault {
    #[inline]
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.kind)
    }
}

/// The grouped router's refusal classes, sectioned by
/// [`FaultClass`] (grammar sites, then policy, then capability);
/// [`class`](Self::class) answers the section.
///
/// The set is the grouped scanner's — the machines drive one pump,
/// one LEN admission, and one group-framing law — spelled as this
/// module's own type (scenario modules share no public types).
///
/// A fault judged after the head tag revealed its field number
/// carries that field — inside the [`Stage`] coordinate for varint
/// reads (the tag stage carries none: no field exists yet), on the
/// variant elsewhere. The one exception is [`PayloadTruncated`]:
/// a counted payload — a silent skip or an open tap's body —
/// counts down without its field (the resume mode keeps only the
/// owed count), so the fault quotes what the machine still owes.
///
/// [`PayloadTruncated`]: Self::PayloadTruncated
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultKind {
    // ─ grammar: varint sites ─
    /// A varint construct refused at one of the record's stages
    /// (tag: five-byte window, u32 word class; length prefix:
    /// five-byte window, 2^31 − 1 length class; value: ten-byte
    /// window, u64 class).
    Read {
        /// The construct the read was serving.
        stage: Stage,
        /// The refusal, in stream coordinates.
        cause: ReadFault,
    },
    /// A tag decoded to field number zero.
    FieldZero,
    /// A tag carried a code unassigned by the format (6 or 7).
    Unassigned {
        /// The field the tag names (judged before the code).
        field: FieldNumber,
        /// The unassigned code.
        code: Low3,
    },
    /// A declared length punctures the enclosing seal.
    LenOverrun {
        /// The record's field number.
        field: FieldNumber,
        /// The declared payload length.
        len: PayloadLen,
    },
    // ─ grammar: payload sites ─
    /// A fixed payload does not fit the enclosing extent.
    FixedOverrun {
        /// The record's field number.
        field: FieldNumber,
    },
    /// The stream ended inside a fixed payload.
    FixedTruncated {
        /// The record's field number.
        field: FieldNumber,
    },
    /// The stream ended inside a counted payload.
    PayloadTruncated {
        /// Bytes still owed (a counting mode always owes).
        remaining: NonZeroU32,
    },
    /// The stream ended with a committed LEN still open.
    UnclosedLen {
        /// The innermost open LEN's field.
        field: FieldNumber,
    },
    // ─ grammar: group framing ─
    /// An end-of-group tag with no open group.
    GroupEndOrphan {
        /// The end tag's field.
        end: FieldNumber,
    },
    /// An end-of-group tag whose field differs from the innermost
    /// open group's.
    GroupEndMismatch {
        /// The end tag's field.
        end: FieldNumber,
        /// The innermost open group's field.
        open: FieldNumber,
    },
    /// An end-of-group tag arriving while the innermost frame is a
    /// LEN whose endpoint has not been reached: closing would
    /// pierce the seal.
    GroupEndAcrossLen {
        /// The end tag's field.
        end: FieldNumber,
        /// The innermost (unfinished) LEN's field.
        open_len: FieldNumber,
    },
    /// A LEN endpoint arrived while a group inside it is open.
    GroupUnclosedAtLenEnd {
        /// The open group's field.
        group: FieldNumber,
    },
    /// The stream ended with a group still open.
    GroupUnclosed {
        /// The innermost open group's field.
        field: FieldNumber,
    },
    // ─ policy: the declared standard and bound ─
    /// A tag wider than minimal (CanonicalMinimal only).
    NonMinimalTag,
    /// A length prefix wider than minimal (CanonicalMinimal only).
    NonMinimalLen {
        /// The record's field number.
        field: FieldNumber,
    },
    /// A value varint wider than minimal (CanonicalMinimal only).
    NonMinimalValue {
        /// The record's field number.
        field: FieldNumber,
    },
    /// Opening this container would exceed the caller's declared
    /// [`DepthLimit`] bound.
    DepthExceeded {
        /// The container's field number.
        field: FieldNumber,
    },
    // ─ capability: the coordinate space ─
    /// The accumulated stream offset would leave the addressable
    /// coordinate space: the machine admits streams of at most
    /// `u64::MAX − 1` bytes, and the offered chunk runs past that
    /// top. Judged whole at feed admission, before any byte of the
    /// chunk is read, and terminal like every fault — a stream
    /// this long has no lawful coordinate to continue at.
    OffsetExhausted,
    /// A declared length the coordinate space cannot host: outside
    /// any LEN seal (at the root — or inside an open group, which
    /// never moves the seal), the payload's end would land on (or
    /// past) the reserved sentinel coordinate. Read after the tag
    /// and the length prefix; the same bytes are lawful at a lower
    /// cursor — the refusal depends on the accumulated position,
    /// like the feed gate's exhaustion, so it repairs by
    /// capability rather than by editing the bytes.
    LenUnsatisfiable {
        /// The record's field number.
        field: FieldNumber,
        /// The declared payload length.
        len: PayloadLen,
    },
}

impl FaultKind {
    /// The minimality refusal at a varint stage (the pump's
    /// minimal-width verdict, placed into this vocabulary).
    const fn padded(stage: Stage) -> Self {
        match stage {
            Stage::Tag => Self::NonMinimalTag,
            Stage::LenPrefix { field } => Self::NonMinimalLen { field },
            Stage::Value { field } => Self::NonMinimalValue { field },
        }
    }

    /// The refusal's [`FaultClass`] — which repair the fault asks
    /// for. Policy membership names its configuration datum on the
    /// variant (the [`Standard`] for the `NonMinimal*` family, the
    /// [`DepthLimit`] bound for `DepthExceeded`); the capability
    /// members are the coordinate-space refusals — the dialect's
    /// language is the format's whole code alphabet, so no tag
    /// code is a capability matter here.
    #[inline]
    pub const fn class(self) -> FaultClass {
        match self {
            Self::Read { .. }
            | Self::FieldZero
            | Self::Unassigned { .. }
            | Self::LenOverrun { .. }
            | Self::FixedOverrun { .. }
            | Self::FixedTruncated { .. }
            | Self::PayloadTruncated { .. }
            | Self::UnclosedLen { .. }
            | Self::GroupEndOrphan { .. }
            | Self::GroupEndMismatch { .. }
            | Self::GroupEndAcrossLen { .. }
            | Self::GroupUnclosedAtLenEnd { .. }
            | Self::GroupUnclosed { .. } => FaultClass::Grammar,
            Self::NonMinimalTag
            | Self::NonMinimalLen { .. }
            | Self::NonMinimalValue { .. }
            | Self::DepthExceeded { .. } => FaultClass::Policy,
            Self::OffsetExhausted | Self::LenUnsatisfiable { .. } => FaultClass::Capability,
        }
    }
}

impl core::fmt::Display for FaultKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Read { stage, cause } => {
                match cause {
                    ReadFault::SealCut => f.write_str("the sealed extent ends inside ")?,
                    ReadFault::StreamEnd => f.write_str("the stream ended inside ")?,
                    ReadFault::TooWide | ReadFault::OutOfClass => {}
                }
                let (window, class) = match stage {
                    Stage::Tag => {
                        f.write_str("a tag")?;
                        ("five", "u32 class")
                    }
                    Stage::LenPrefix { field } => {
                        write!(f, "the length prefix of field {}", field.as_inner())?;
                        ("five", "length class")
                    }
                    Stage::Value { field } => {
                        write!(f, "the varint value of field {}", field.as_inner())?;
                        ("ten", "u64 class")
                    }
                };
                match cause {
                    ReadFault::SealCut | ReadFault::StreamEnd => Ok(()),
                    ReadFault::TooWide => write!(f, " ran past the {window}-byte window"),
                    ReadFault::OutOfClass => write!(f, " exceeds the {class}"),
                }
            }
            Self::FieldZero => f.write_str("a tag names field zero"),
            Self::Unassigned { field, code } => {
                write!(f, "field {} carries unassigned code {}", field.as_inner(), code.as_inner())
            }
            Self::LenOverrun { field, len } => write!(
                f,
                "field {} declares {} payload bytes beyond its seal",
                field.as_inner(),
                len.as_inner()
            ),
            Self::LenUnsatisfiable { field, len } => write!(
                f,
                "field {} declares {} payload bytes the coordinate space cannot host",
                field.as_inner(),
                len.as_inner()
            ),
            Self::FixedOverrun { field } => {
                write!(f, "the fixed payload of field {} does not fit its extent", field.as_inner())
            }
            Self::FixedTruncated { field } => {
                write!(f, "the stream ended inside the fixed payload of field {}", field.as_inner())
            }
            Self::PayloadTruncated { remaining } => {
                write!(f, "the stream ended {remaining} bytes short of a length-prefixed payload")
            }
            Self::UnclosedLen { field } => {
                write!(f, "the stream ended inside the committed LEN of field {}", field.as_inner())
            }
            Self::GroupEndOrphan { end } => {
                write!(f, "an end-of-group tag for field {} with no open group", end.as_inner())
            }
            Self::GroupEndMismatch { end, open } => write!(
                f,
                "an end-of-group tag for field {} while group field {} is open",
                end.as_inner(),
                open.as_inner()
            ),
            Self::GroupEndAcrossLen { end, open_len } => write!(
                f,
                "an end-of-group tag for field {} inside the unfinished LEN of field {}",
                end.as_inner(),
                open_len.as_inner()
            ),
            Self::GroupUnclosedAtLenEnd { group } => {
                write!(f, "a LEN endpoint arrived while group field {} is open", group.as_inner())
            }
            Self::GroupUnclosed { field } => {
                write!(f, "the stream ended with group field {} open", field.as_inner())
            }
            Self::NonMinimalTag => f.write_str("a tag is wider than its minimal encoding"),
            Self::NonMinimalLen { field } => write!(
                f,
                "the length prefix of field {} is wider than its minimal encoding",
                field.as_inner()
            ),
            Self::NonMinimalValue { field } => write!(
                f,
                "the varint value of field {} is wider than its minimal encoding",
                field.as_inner()
            ),
            Self::DepthExceeded { field } => write!(
                f,
                "opening the container of field {} would exceed the bound",
                field.as_inner()
            ),
            Self::OffsetExhausted => {
                f.write_str("the stream ran past the addressable 2^64 - 1 bytes")
            }
        }
    }
}

impl core::error::Error for FaultKind {}

/// The mark of one pushed tap frame: minted only by
/// [`Router::open_tap`] (the single push site) and consumed only by
/// [`Router::take_tap`] (the single pop seam), so a close without
/// its open cannot be spelled — the pairing the walk proves rides
/// the type instead of a runtime check. Copies can only arise
/// through the carriers' own `Copy` (a frame or a resume mode),
/// which never outlive the container that closes them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct OpenTap(());

/// One open container. LEN frames keep the *shadowed* predecessor
/// endpoint (the live one rides the cursor); both kinds keep their
/// field for exit judgment and — when tapped — the open-tap mark
/// their close consumes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Extent {
    Len { prev_zone: u64, field: FieldNumber, tap: Option<OpenTap> },
    Group { field: FieldNumber, tap: Option<OpenTap> },
}

const _: () = assert!(core::mem::size_of::<Extent>() == 16);

/// One open tap: the tapped container's record head (the instance
/// identity every segment quotes), its field for the exit events,
/// and where its targeting paths start in the id arena (they run
/// to the next frame's start, or the arena's end for the
/// innermost).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Tap {
    record_at: u64,
    field: FieldNumber,
    /// Arena start. In u32 by domain arithmetic: open taps are
    /// bounded by the depth bound plus one counted tap, each
    /// holding at most the program's 65,535 paths.
    ids_at: u32,
}

const _: () = assert!(core::mem::size_of::<Tap>() == 16);

/// Where to resume when the next chunk arrives — scan's resumption
/// law, with the head-tag width riding the word modes so the
/// record coordinate (position is identity) survives suspension.
/// Groups have no mode: their memory is entirely on the stack, and
/// a group end is just a classified head word.
///
/// The counting modes are nonzero by construction: a zero-length
/// payload completes at its head — were zero admitted, a chunk
/// ending right after the length word would leave a counting mode
/// owing nothing, and EOF would misjudge a complete stream as
/// truncated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Quiescent: expecting a record head (the carry may hold a
    /// cut head-word prefix).
    Head,
    /// A varint value in flight (head classified, field proven);
    /// `tag` is the head tag's width, so the record head is the
    /// construct start minus it.
    VarintValue { field: FieldNumber, tag: u8 },
    /// A LEN length word in flight.
    LenWord { field: FieldNumber, tag: u8 },
    /// A fixed payload collecting across chunks.
    FixedTail { field: FieldNumber, kind: FixedKind, tag: u8 },
    /// Counted body of the innermost tap (an uncommitted tapped
    /// LEN): raw pieces pour to every open tap; exhaustion closes
    /// the tap, consuming the mark minted when it opened.
    Forward { remaining: NonZeroU32, tap: OpenTap },
    /// Counted silent skip: raw pieces still pour to whatever taps
    /// are open (a skipped record is body to its tapped ancestors);
    /// with none open the count is pure arithmetic.
    Swallow { remaining: NonZeroU32 },
}

const _: () = assert!(core::mem::size_of::<Mode>() <= 12);

/// Pours one body piece to every open tap: outermost container
/// first, ascending path within one container (the arena keeps
/// each frame's ids in the matcher's ascending visit order).
fn pour<S: Sink>(
    taps: &[Tap],
    ids: &[PathId],
    sink: &mut S,
    seg_at: u64,
    bytes: &[u8],
) -> ControlFlow<()> {
    for (i, tap) in taps.iter().enumerate() {
        let end = taps.get(i + 1).map_or(ids.len(), |inner| usize_of(inner.ids_at));
        for &path in &ids[usize_of(tap.ids_at)..end] {
            sink.on_segment(path, tap.record_at, seg_at, bytes)?;
        }
    }
    ControlFlow::Continue(())
}

/// The one-pass grouped routing machine.
///
/// Terminal states are final: after a fault or an early stop,
/// another `feed`/`finish` call panics (a caller bug, named); a
/// clean end goes through `finish(self)`, which consumes the
/// machine.
#[must_use]
pub struct Router<'r> {
    pump: Pump,
    mode: Mode,
    stack: Vec<Extent>,
    depth: DepthLimit,
    matcher: Matcher<'r, Program<'r>>,
    /// Open taps, outermost first.
    taps: Vec<Tap>,
    /// Targeting paths of the open taps (arena; each frame marks
    /// its start) — paid only when containers are targeted.
    tap_paths: Vec<PathId>,
}

impl<'r> Router<'r> {
    /// All configuration is explicit: the program, the acceptance
    /// standard, and the nesting bound have no defaults. Compiles
    /// the matcher's root layer, so a machine is per stream while
    /// the program is per process.
    #[inline]
    pub fn new(program: &Program<'r>, standard: Standard, limit: DepthLimit) -> Self {
        Self {
            pump: Pump::new(standard),
            mode: Mode::Head,
            stack: Vec::new(),
            depth: limit,
            matcher: Matcher::new(*program),
            taps: Vec::new(),
            tap_paths: Vec::new(),
        }
    }

    /// Absolute consumed offset (progress observation — skips emit
    /// no events, this is where progress is read).
    #[inline]
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.pump.off
    }

    /// Feeds one chunk. Events flow to `sink` as the program's
    /// designations complete; `Flow::More` means the chunk is
    /// exhausted and the machine carries the residue.
    ///
    /// # Errors
    ///
    /// The first law violation under the declared standard ends the
    /// stream: the fault carries its absolute coordinate
    /// ([`Fault::at`]) and the violated law ([`Fault::kind`]). A
    /// chunk that would run the stream past its addressable
    /// coordinate space (`u64::MAX − 1` bytes) is refused whole at
    /// admission as [`FaultKind::OffsetExhausted`], before any of
    /// its bytes are read.
    ///
    /// # Panics
    ///
    /// After a previous fault or early stop, and after a feed whose
    /// sink callback unwound (the machine latches terminal across
    /// callbacks, so a caught panic cannot resume a half-stepped
    /// stream). The stream is over — feeding again is a caller
    /// bug.
    #[track_caller]
    pub fn feed<S: Sink>(&mut self, chunk: &[u8], sink: &mut S) -> Result<Flow, Fault> {
        assert!(!self.pump.terminal, "stream already terminal");
        // Coordinate admission: the gate keeps `off` strictly below
        // the root sentinel through every consuming path of this
        // feed. Judged in this prologue so the drive loop's codegen
        // owes the gate nothing.
        if core::hint::unlikely(!self.pump.admits(chunk)) {
            return Err(self.fault(self.pump.off, FaultKind::OffsetExhausted));
        }
        // Poison across the sink callbacks: latch terminal before
        // driving, so a callback that unwinds leaves the machine
        // terminal (every later feed hits the entry assert) rather
        // than resumable mid-construct — a resumed `FixedTail`
        // could re-enter collection against a popped zone and reach
        // the unreachable `Collect::Cut`. A normal return restores
        // the latch to the drive's own verdict (fault terminal,
        // otherwise live). The declared standard picks the drive
        // instance once: the per-record minimality test is a const
        // inside the engine.
        self.pump.terminal = true;
        let flow = match self.pump.standard {
            Standard::Tolerant => self.drive::<S, false>(chunk, sink),
            Standard::CanonicalMinimal => self.drive::<S, true>(chunk, sink),
        };
        // Only `More` leaves the machine live for the next chunk; a
        // fault or an orderly stop is terminal (and a panic skips
        // this line, leaving the armed latch).
        self.pump.terminal = !matches!(flow, Ok(Flow::More));
        flow
    }

    /// The feed's drive engine, behind the admission prologue, one
    /// instance per acceptance standard.
    #[inline(never)]
    fn drive<S: Sink, const MINIMAL: bool>(
        &mut self,
        chunk: &[u8],
        sink: &mut S,
    ) -> Result<Flow, Fault> {
        // The engine's const standard and the pump's declared one
        // are the same fact in two representations; the call sites
        // keep them aligned, and this seam pins that.
        debug_assert!(standard_of(MINIMAL) == self.pump.standard);
        let mut chunk = chunk;
        loop {
            // Cascade: resolve every endpoint at the cursor before
            // any construct starts.
            match self.cascade(sink) {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(flow) => return flow,
            }
            if chunk.is_empty() {
                return Ok(Flow::More);
            }
            let flow = match self.mode {
                Mode::Head => self.head::<_, MINIMAL>(&mut chunk, sink),
                Mode::VarintValue { field, tag } => {
                    let record_at = self.pump.construct_start() - u64::from(tag);
                    self.varint_value::<_, MINIMAL>(&mut chunk, field, record_at, sink)
                }
                Mode::LenWord { field, tag } => {
                    let record_at = self.pump.construct_start() - u64::from(tag);
                    self.len_word::<_, MINIMAL>(&mut chunk, field, record_at, sink)
                }
                Mode::FixedTail { field, kind, tag } => {
                    let record_at = self.pump.construct_start() - u64::from(tag);
                    self.fixed_tail(&mut chunk, field, record_at, kind, sink)
                }
                Mode::Forward { remaining, tap } => self.forward(&mut chunk, remaining, tap, sink),
                Mode::Swallow { remaining } => self.swallow(&mut chunk, remaining, sink),
            };
            match flow {
                ControlFlow::Continue(()) => {}
                ControlFlow::Break(flow) => return flow,
            }
        }
    }

    /// Declares EOF and consumes the machine: the final verdict.
    ///
    /// No cascade runs here — every endpoint not under a suspended
    /// word was resolved inside `feed`, and an endpoint a word
    /// straddles is the truncation the mode match below reports.
    /// The sink receives nothing at EOF, so `finish` takes none:
    /// an open tap is an owed count or an open frame, and either
    /// is the truncation verdict itself.
    ///
    /// # Errors
    ///
    /// EOF inside a construct or a counted payload is the matching
    /// truncation fault; a still-open container is the matching
    /// unclosed fault — every one at the final offset. A non-`Head`
    /// mode is truncation whether or not any byte of the pending
    /// word arrived: verdict and coordinate agree either way.
    ///
    /// # Panics
    ///
    /// After a previous fault or early stop, and after a feed whose
    /// sink callback unwound.
    #[track_caller]
    pub fn finish(self) -> Result<(), Fault> {
        assert!(!self.pump.terminal, "stream already terminal");
        debug_assert!(
            self.pump.off != self.pump.zone
                || !(matches!(self.mode, Mode::Head) && self.pump.carry.is_empty()),
            "feed resolves every endpoint it does not leave under a suspended word"
        );
        let at = self.pump.off;
        match self.mode {
            Mode::Head => {
                if !self.pump.carry.is_empty() {
                    let kind = FaultKind::Read { stage: Stage::Tag, cause: ReadFault::StreamEnd };
                    return Err(Fault { at, kind });
                }
            }
            Mode::VarintValue { field, .. } => {
                let kind =
                    FaultKind::Read { stage: Stage::Value { field }, cause: ReadFault::StreamEnd };
                return Err(Fault { at, kind });
            }
            Mode::LenWord { field, .. } => {
                let kind = FaultKind::Read {
                    stage: Stage::LenPrefix { field },
                    cause: ReadFault::StreamEnd,
                };
                return Err(Fault { at, kind });
            }
            Mode::FixedTail { field, .. } => {
                return Err(Fault { at, kind: FaultKind::FixedTruncated { field } });
            }
            Mode::Forward { remaining, .. } | Mode::Swallow { remaining } => {
                return Err(Fault { at, kind: FaultKind::PayloadTruncated { remaining } });
            }
        }
        match self.stack.last() {
            Some(&Extent::Len { field, .. }) => {
                Err(Fault { at, kind: FaultKind::UnclosedLen { field } })
            }
            Some(&Extent::Group { field, .. }) => {
                Err(Fault { at, kind: FaultKind::GroupUnclosed { field } })
            }
            None => Ok(()),
        }
    }

    // ─ the drive arms (each returns Break to end the feed) ─

    /// Resolves every sealed endpoint at the cursor: pops the LEN
    /// frame, restores the shadowed zone, closes the matcher
    /// layer, and — for a tapped frame — closes its tap with the
    /// exit events. A group open at a LEN endpoint is the framing
    /// fault.
    fn cascade<S: Sink>(&mut self, sink: &mut S) -> ControlFlow<Result<Flow, Fault>> {
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
                Some(Extent::Len { prev_zone, field: _, tap }) => {
                    self.pump.zone = prev_zone;
                    self.matcher.exit();
                    if let Some(open) = tap
                        && self.close_tap(sink, open).is_break()
                    {
                        return ControlFlow::Break(Ok(Flow::Stopped));
                    }
                }
                // The fault latches terminal, so the popped frame
                // has no further observer.
                Some(Extent::Group { field, .. }) => {
                    return ControlFlow::Break(Err(self
                        .fault(self.pump.off, FaultKind::GroupUnclosedAtLenEnd { group: field })));
                }
                // SAFETY: an empty stack leaves the root zone,
                // `u64::MAX`, and the feed admission gate keeps
                // `off < u64::MAX` through every consuming path —
                // the cursor can never equal the root sentinel.
                None => unsafe { core::hint::unreachable_unchecked() },
            }
        }
        ControlFlow::Continue(())
    }

    /// Classifies the tag and hands the record to its word
    /// handler: the whole record completes when the chunk allows,
    /// and the handlers write a suspension mode only when it does
    /// not — the mode is resumption state, not a per-record
    /// itinerary.
    fn head<S: Sink, const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        // The record's first byte, read before stepping: the carry
        // holds exactly the resumed prefix here, so the coordinate
        // equals the completed tag's start (events quote it, the
        // group punctuation and structural refusals below spend
        // it).
        let start = self.pump.construct_start();
        let word = match self.pump.step_tag_held(chunk, standard_of(MINIMAL)) {
            Verdict::Done(word) => word,
            Verdict::More => return ControlFlow::Break(Ok(Flow::More)),
            Verdict::Cut => return self.halt_read(Stage::Tag, ReadFault::SealCut),
            Verdict::TooWide => return self.halt_read(Stage::Tag, ReadFault::TooWide),
            Verdict::OutOfClass => return self.halt_read(Stage::Tag, ReadFault::OutOfClass),
            Verdict::NonMinimal => return self.halt_padded(Stage::Tag),
        };
        let low3 = Low3::from_word(word);
        let Some(field) = FieldNumber::from_word(word) else {
            return self.halt(start, FaultKind::FieldZero);
        };
        match classify(low3) {
            TagClass::Record(RecordKind::Group) => {
                // A group-open tag is proven body of every tap
                // already open; the group's own tap begins past it.
                if self.spill(sink, start).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                if self.stack.len() >= usize::from(self.depth.as_inner()) {
                    return self.halt(start, FaultKind::DepthExceeded { field });
                }
                // Targets stage into the arena before the route
                // probe reads the same layer; groups cross by
                // syntax, so even an empty child layer commits,
                // keeping matcher and stack scopes paired.
                let ids_at = self.tap_paths.len();
                {
                    let arena = &mut self.tap_paths;
                    self.matcher.visit_targets(field, |id| arena.push(PathId::mint(id)));
                }
                let tapped = self.tap_paths.len() > ids_at;
                self.matcher.probe_routes(field);
                self.matcher.commit_descent();
                let tap = tapped.then(|| self.open_tap(start, field, ids_at));
                self.stack.push(Extent::Group { field, tap });
                if tapped {
                    let body_at = self.pump.off;
                    let mut flow = ControlFlow::Continue(());
                    for &path in &self.tap_paths[ids_at..] {
                        flow = sink.on_group_enter(path, field, start, body_at);
                        if flow.is_break() {
                            break;
                        }
                    }
                    if self.event(flow).is_break() {
                        return ControlFlow::Break(Ok(Flow::Stopped));
                    }
                }
                ControlFlow::Continue(())
            }
            // The tag of every record class is proven body of the
            // taps already open the moment it classifies: each arm
            // pours it (spill), then spends the carry for the next
            // construct.
            TagClass::Record(RecordKind::Varint) => {
                if self.spill(sink, start).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                self.varint_value::<_, MINIMAL>(chunk, field, start, sink)
            }
            TagClass::Record(kind @ (RecordKind::I32 | RecordKind::I64)) => {
                if self.spill(sink, start).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                let fixed =
                    if matches!(kind, RecordKind::I64) { FixedKind::I64 } else { FixedKind::I32 };
                // Admit the width against the zone here, so the
                // kernel's Cut is unreachable in collection.
                if self.pump.zone - self.pump.off < u64::from(fixed.need()) {
                    return self.halt(self.pump.off, FaultKind::FixedOverrun { field });
                }
                self.fixed_tail(chunk, field, start, fixed, sink)
            }
            TagClass::Record(RecordKind::Len) => {
                if self.spill(sink, start).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                self.len_word::<_, MINIMAL>(chunk, field, start, sink)
            }
            TagClass::GroupEnd => self.group_end(field, start, sink),
            TagClass::Unassigned => self.halt(start, FaultKind::Unassigned { field, code: low3 }),
        }
    }

    /// A verified group close: the frame and its matcher layer
    /// retire; the end tag pours only to the taps outside the
    /// closing group (framing tags never enter a group's own
    /// segments), and the exit events follow it.
    fn group_end<S: Sink>(
        &mut self,
        end: FieldNumber,
        at: u64,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        // The refusal arms latch terminal, so popping ahead of the
        // judgment leaves no observer of the removed frame.
        match self.stack.pop() {
            None => self.halt(at, FaultKind::GroupEndOrphan { end }),
            Some(Extent::Len { field, .. }) => {
                self.halt(at, FaultKind::GroupEndAcrossLen { end, open_len: field })
            }
            Some(Extent::Group { field, .. }) if field != end => {
                self.halt(at, FaultKind::GroupEndMismatch { end, open: field })
            }
            Some(Extent::Group { field, tap }) => {
                self.matcher.exit();
                // The closing group's own tap detaches first: its
                // body ended where this tag starts.
                let closing = tap.map(|open| self.take_tap(open));
                // The end tag pours only to the remaining (outer)
                // taps: the arena view stops at the closing tap's
                // mark — its ids stay staged for the exit events
                // below, but they are no tap anymore.
                let ids_end =
                    closing.as_ref().map_or(self.tap_paths.len(), |tap| usize_of(tap.ids_at));
                if !self.taps.is_empty() {
                    let flow = pour(
                        &self.taps,
                        &self.tap_paths[..ids_end],
                        sink,
                        at,
                        self.pump.carry.bytes(),
                    );
                    if self.event(flow).is_break() {
                        return ControlFlow::Break(Ok(Flow::Stopped));
                    }
                }
                self.pump.carry.clear();
                if let Some(tap) = closing {
                    let record_end = self.pump.off;
                    let mut flow = ControlFlow::Continue(());
                    for &path in &self.tap_paths[usize_of(tap.ids_at)..] {
                        flow = sink.on_group_exit(path, field, tap.record_at, at, record_end);
                        if flow.is_break() {
                            break;
                        }
                    }
                    self.tap_paths.truncate(usize_of(tap.ids_at));
                    if self.event(flow).is_break() {
                        return ControlFlow::Break(Ok(Flow::Stopped));
                    }
                }
                ControlFlow::Continue(())
            }
        }
    }

    #[inline(always)]
    fn varint_value<S: Sink, const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        record_at: u64,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        match self.pump.step_value_held(chunk, standard_of(MINIMAL)) {
            Verdict::Done(value) => {
                self.mode = Mode::Head;
                let seg_at = self.pump.construct_start();
                if self.spill(sink, seg_at).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                let mut flow = ControlFlow::Continue(());
                self.matcher.visit_targets(field, |id| {
                    if flow.is_continue() {
                        flow = sink.on_varint(PathId::mint(id), field, record_at, value);
                    }
                });
                if self.event(flow).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                ControlFlow::Continue(())
            }
            Verdict::More => {
                self.mode = Mode::VarintValue { field, tag: self.tag_width(record_at) };
                ControlFlow::Break(Ok(Flow::More))
            }
            Verdict::Cut => self.halt_read(Stage::Value { field }, ReadFault::SealCut),
            Verdict::TooWide => self.halt_read(Stage::Value { field }, ReadFault::TooWide),
            Verdict::OutOfClass => self.halt_read(Stage::Value { field }, ReadFault::OutOfClass),
            Verdict::NonMinimal => self.halt_padded(Stage::Value { field }),
        }
    }

    #[inline(always)]
    fn len_word<S: Sink, const MINIMAL: bool>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        record_at: u64,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        let len = match self.pump.step_len_held(chunk, standard_of(MINIMAL)) {
            Verdict::Done(len) => len,
            Verdict::More => {
                self.mode = Mode::LenWord { field, tag: self.tag_width(record_at) };
                return ControlFlow::Break(Ok(Flow::More));
            }
            Verdict::Cut => return self.halt_read(Stage::LenPrefix { field }, ReadFault::SealCut),
            Verdict::TooWide => {
                return self.halt_read(Stage::LenPrefix { field }, ReadFault::TooWide);
            }
            Verdict::OutOfClass => {
                return self.halt_read(Stage::LenPrefix { field }, ReadFault::OutOfClass);
            }
            Verdict::NonMinimal => {
                return self.halt_padded(Stage::LenPrefix { field });
            }
        };
        // LEN admission: the one widening seam (u64 + u32). The
        // refusals split by what has to change. Inside a finite
        // zone, an end past it (or a sum past u64 entirely)
        // contradicts the enclosing declaration wherever the
        // document sits — grammar. At the root the same bytes are
        // lawful at a lower cursor; the end merely needs the
        // reserved sentinel coordinate (or beyond), which this
        // machine's space cannot host — capability, like the feed
        // gate's exhaustion.
        let end = match self.pump.off.checked_add(u64::from(len.as_inner())) {
            Some(end) if end <= self.pump.zone && end != u64::MAX => end,
            _ if self.pump.zone != u64::MAX => {
                return self.halt(self.pump.off, FaultKind::LenOverrun { field, len });
            }
            _ => return self.halt(self.pump.off, FaultKind::LenUnsatisfiable { field, len }),
        };
        // The admitted length prefix is proven body: pour, spend.
        let seg_at = self.pump.construct_start();
        if self.spill(sink, seg_at).is_break() {
            return ControlFlow::Break(Ok(Flow::Stopped));
        }
        // The four-arm question is the program's alone. Targets
        // stage into the arena (ascending visit order) before the
        // route probe reads the same layer.
        let ids_at = self.tap_paths.len();
        {
            let arena = &mut self.tap_paths;
            self.matcher.visit_targets(field, |id| arena.push(PathId::mint(id)));
        }
        let tapped = self.tap_paths.len() > ids_at;
        let routed = self.matcher.probe_routes(field);
        if tapped {
            let mut flow = ControlFlow::Continue(());
            for &path in &self.tap_paths[ids_at..] {
                flow = sink.on_len(path, field, record_at, len);
                if flow.is_break() {
                    break;
                }
            }
            if self.event(flow).is_break() {
                return ControlFlow::Break(Ok(Flow::Stopped));
            }
        }
        if routed {
            // Commit (tapped or silent): descend for the interior.
            if self.stack.len() >= usize::from(self.depth.as_inner()) {
                return self.halt(self.pump.off, FaultKind::DepthExceeded { field });
            }
            let tap = tapped.then(|| self.open_tap(record_at, field, ids_at));
            self.stack.push(Extent::Len { prev_zone: self.pump.zone, field, tap });
            self.pump.zone = end;
            self.matcher.commit_descent();
            self.mode = Mode::Head;
        } else if tapped {
            // A pure tap: the body is counted out, never parsed.
            let open = self.open_tap(record_at, field, ids_at);
            match NonZeroU32::new(len.as_inner()) {
                Some(remaining) => self.mode = Mode::Forward { remaining, tap: open },
                None => {
                    // A zero-length body closes at its head: no
                    // counting state, no piece.
                    if self.close_tap(sink, open).is_break() {
                        return ControlFlow::Break(Ok(Flow::Stopped));
                    }
                    self.mode = Mode::Head;
                }
            }
        } else {
            // The silent skip: counted, eventless (open ancestor
            // taps still receive the bytes as raw pieces).
            self.mode = NonZeroU32::new(len.as_inner())
                .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
        }
        ControlFlow::Continue(())
    }

    #[inline(always)]
    fn fixed_tail<S: Sink>(
        &mut self,
        chunk: &mut &[u8],
        field: FieldNumber,
        record_at: u64,
        kind: FixedKind,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        match kind {
            FixedKind::I32 => {
                let Some(bytes) = self.pump.grab_fixed::<4>(chunk) else {
                    self.mode = Mode::FixedTail { field, kind, tag: self.tag_width(record_at) };
                    return ControlFlow::Break(Ok(Flow::More));
                };
                self.mode = Mode::Head;
                if self.pour_fixed(sink, &bytes).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                let mut flow = ControlFlow::Continue(());
                let bits = u32::from_le_bytes(bytes);
                self.matcher.visit_targets(field, |id| {
                    if flow.is_continue() {
                        flow = sink.on_i32(PathId::mint(id), field, record_at, bits);
                    }
                });
                if self.event(flow).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
            }
            FixedKind::I64 => {
                let Some(bytes) = self.pump.grab_fixed::<8>(chunk) else {
                    self.mode = Mode::FixedTail { field, kind, tag: self.tag_width(record_at) };
                    return ControlFlow::Break(Ok(Flow::More));
                };
                self.mode = Mode::Head;
                if self.pour_fixed(sink, &bytes).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
                let mut flow = ControlFlow::Continue(());
                let bits = u64::from_le_bytes(bytes);
                self.matcher.visit_targets(field, |id| {
                    if flow.is_continue() {
                        flow = sink.on_i64(PathId::mint(id), field, record_at, bits);
                    }
                });
                if self.event(flow).is_break() {
                    return ControlFlow::Break(Ok(Flow::Stopped));
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Counts out the innermost tap's body: every open tap
    /// receives the raw piece, and exhaustion closes the tap with
    /// its exit events.
    fn forward<S: Sink>(
        &mut self,
        chunk: &mut &[u8],
        remaining: NonZeroU32,
        tap: OpenTap,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        // The take stays in the length class: chunk lengths beyond
        // it clamp to the class top, and `min` then picks the owed
        // count, which fits by construction.
        let take = remaining.get().min(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        let (piece, rest) = chunk.split_at(usize_of(take));
        let seg_at = self.pump.off;
        self.pump.off += u64::from(take);
        *chunk = rest;
        let left = NonZeroU32::new(remaining.get() - take);
        self.mode = left.map_or(Mode::Head, |remaining| Mode::Forward { remaining, tap });
        let flow = pour(&self.taps, &self.tap_paths, sink, seg_at, piece);
        if self.event(flow).is_break() {
            return ControlFlow::Break(Ok(Flow::Stopped));
        }
        if left.is_none() && self.close_tap(sink, tap).is_break() {
            return ControlFlow::Break(Ok(Flow::Stopped));
        }
        ControlFlow::Continue(())
    }

    /// Counts out a skipped payload: eventless for the program,
    /// but still body to every open ancestor tap.
    fn swallow<S: Sink>(
        &mut self,
        chunk: &mut &[u8],
        remaining: NonZeroU32,
        sink: &mut S,
    ) -> ControlFlow<Result<Flow, Fault>> {
        let take = remaining.get().min(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
        let (piece, rest) = chunk.split_at(usize_of(take));
        let seg_at = self.pump.off;
        self.pump.off += u64::from(take);
        *chunk = rest;
        self.mode = NonZeroU32::new(remaining.get() - take)
            .map_or(Mode::Head, |remaining| Mode::Swallow { remaining });
        if !self.taps.is_empty() {
            let flow = pour(&self.taps, &self.tap_paths, sink, seg_at, piece);
            if self.event(flow).is_break() {
                return ControlFlow::Break(Ok(Flow::Stopped));
            }
        }
        ControlFlow::Continue(())
    }

    // ─ delivery helpers ─

    /// The completed construct the carry holds, poured to every
    /// open tap and spent. The pour is skipped outright with no
    /// taps open — the common validating walk pays one branch.
    #[inline]
    fn spill<S: Sink>(&mut self, sink: &mut S, seg_at: u64) -> ControlFlow<()> {
        if !self.taps.is_empty() {
            let flow = pour(&self.taps, &self.tap_paths, sink, seg_at, self.pump.carry.bytes());
            if self.event(flow).is_break() {
                return ControlFlow::Break(());
            }
        }
        self.pump.carry.clear();
        ControlFlow::Continue(())
    }

    /// A completed fixed payload (its own encoding), poured to
    /// every open tap; the collection already spent the carry.
    #[inline]
    fn pour_fixed<S: Sink>(&mut self, sink: &mut S, bytes: &[u8]) -> ControlFlow<()> {
        if self.taps.is_empty() {
            return ControlFlow::Continue(());
        }
        #[allow(
            clippy::as_conversions,
            reason = "the pinned fixed widths (4, 8) widen losslessly into the stream coordinate"
        )]
        let seg_at = self.pump.off - bytes.len() as u64;
        let flow = pour(&self.taps, &self.tap_paths, sink, seg_at, bytes);
        self.event(flow)
    }

    /// Pushes the tap frame for a targeted container and mints the
    /// mark its close consumes.
    fn open_tap(&mut self, record_at: u64, field: FieldNumber, ids_at: usize) -> OpenTap {
        self.taps.push(Tap { record_at, field, ids_at: arena_mark(ids_at) });
        OpenTap(())
    }

    /// Retires the innermost tap frame, consuming its open mark —
    /// the one pop seam.
    fn take_tap(&mut self, _open: OpenTap) -> Tap {
        debug_assert!(!self.taps.is_empty(), "a mark exists only while its tap is open");
        // SAFETY: `_open` was minted when its tap frame was pushed
        // ([`Self::open_tap`] is the only mint) and taps retire
        // LIFO with their containers: every tap nested inside this
        // one closed with its own frame, counted mode, or verified
        // group end before this close could run. No path abandons a
        // mark over a live machine — a sink callback that unwinds
        // mid-feed leaves the terminal latch armed, so no later
        // feed can reach a close site over a half-stepped stack.
        unsafe { self.taps.pop().unwrap_unchecked() }
    }

    /// Closes the innermost tap — a LEN tap: exit events for its
    /// paths (ascending — the arena kept visit order), then the
    /// frame and its ids retire, consuming the open mark. Group
    /// taps close inside [`Self::group_end`], whose exit events
    /// carry the framing geometry.
    fn close_tap<S: Sink>(&mut self, sink: &mut S, open: OpenTap) -> ControlFlow<()> {
        let tap = self.take_tap(open);
        let end = self.pump.off;
        let mut flow = ControlFlow::Continue(());
        for &path in &self.tap_paths[usize_of(tap.ids_at)..] {
            flow = sink.on_len_exit(path, tap.field, tap.record_at, end);
            if flow.is_break() {
                break;
            }
        }
        self.tap_paths.truncate(usize_of(tap.ids_at));
        self.event(flow)
    }

    /// The head tag's width for a suspension mode: the construct
    /// in flight starts where the tag ended.
    #[allow(
        clippy::as_conversions,
        reason = "a head tag spans at most five bytes; the difference narrows losslessly"
    )]
    const fn tag_width(&self, record_at: u64) -> u8 {
        (self.pump.construct_start() - record_at) as u8
    }

    // ─ terminal helpers ─

    #[cold]
    const fn fault(&mut self, at: u64, kind: FaultKind) -> Fault {
        self.pump.terminal = true;
        Fault { at, kind }
    }

    #[cold]
    const fn halt(&mut self, at: u64, kind: FaultKind) -> ControlFlow<Result<Flow, Fault>> {
        ControlFlow::Break(Err(self.fault(at, kind)))
    }

    /// A varint read refusal: builds the fault and its coordinate
    /// here, keeping both off the drive arms' hot paths (the seal
    /// cut names the sealed endpoint; the window and class refusals
    /// name the construct's first byte, still held by the carry).
    #[cold]
    const fn halt_read(
        &mut self,
        stage: Stage,
        cause: ReadFault,
    ) -> ControlFlow<Result<Flow, Fault>> {
        let at = match cause {
            ReadFault::SealCut => self.pump.zone,
            ReadFault::StreamEnd | ReadFault::TooWide | ReadFault::OutOfClass => {
                self.pump.construct_start()
            }
        };
        self.halt(at, FaultKind::Read { stage, cause })
    }

    /// A minimality refusal at a varint stage (CanonicalMinimal
    /// only), built off the hot paths like [`Self::halt_read`]; the
    /// pump's carry still holds the construct, so its first byte
    /// needs no companion datum.
    #[cold]
    const fn halt_padded(&mut self, stage: Stage) -> ControlFlow<Result<Flow, Fault>> {
        self.halt(self.pump.construct_start(), FaultKind::padded(stage))
    }

    /// An event's control flow: Break marks the machine terminal.
    const fn event(&mut self, flow: ControlFlow<()>) -> ControlFlow<()> {
        if flow.is_break() {
            self.pump.terminal = true;
        }
        flow
    }
}

/// Narrows an arena mark into the tap frame's u32 coordinate.
#[allow(
    clippy::as_conversions,
    reason = "open taps are depth-bounded and each holds at most 65,535 paths, \
              so arena marks stay far inside u32"
)]
const fn arena_mark(ids_at: usize) -> u32 {
    ids_at as u32
}

#[cfg(test)]
mod tests;
