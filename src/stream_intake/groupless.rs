//! The groupless stream-ingest intake: chunked input judged
//! canonical-minimal as it arrives, sealed at `finish` into a
//! one-shot editing intake.
//!
//! The finished machine carries owned tenure, derived-width rows,
//! commit-only edits, and a byte-fidelity save — the buffered
//! intake's faces over a source that arrived in chunks.
//!
//! This dialect speaks the four-code wire language: group codes
//! are well-formed wire outside it, refused as a capability
//! judgment ([`Refusal::GroupCode`]) distinct from grammar faults
//! — during ingest that refusal ends the job (the accumulated
//! source rides back beside it), inside a payload it is a resident
//! verdict and the payload stays readable as bytes.
//!
//! The ingest phase is the fused copy/parse loop: [`Ingest::feed`]
//! reserves room for the whole chunk first, then examines each
//! source byte exactly once — one append into the reserved final
//! backing and one fold into the varint carry per byte, as
//! source-level traffic — so the retained
//! source itself is the raw-byte bank and a construct cut by a
//! chunk edge keeps only its accumulator and width across feeds.
//! Opaque LEN bodies and fixed payloads append in bulk. The grammar
//! is the buffered root scan's, judged as bytes arrive: lazy-top —
//! LEN interiors stay opaque (their bytes are counted, never
//! wire-judged) until an explicit [`Intake::descend`] after the
//! seal. Chunk boundaries are never faults; [`Ingest::finish`] is
//! the only EOF declaration, and it judges the carried phase state,
//! seals the source, and moves the parts — at the source level, no
//! reparse step and no walk over the accumulated length. The saving
//! over collect-then-open, as source-level traffic, is
//! exactly the post-collection read of the framing bytes: near the
//! whole input for parse-dense documents, small for opaque-heavy
//! ones.
//!
//! Admission is canonical-minimal, and the judgment is fused into
//! the same pass: every framing word and varint value is judged
//! minimal the moment its last byte arrives — across chunk edges
//! through the carry — so a padded tag, length prefix, or varint
//! value refuses at collection time ([`Refusal::NonMinimalTag`]
//! and kin, the buffered intake's vocabulary, at the padded
//! word's first byte). Every admitted framing word is therefore
//! minimal: the finished rows store no width column, spans derive
//! from the record's own facts, and saved documents re-ingest
//! under the same admission. Every feed is admitted against the
//! finished editor's coordinate class before a byte is read
//! ([`IngestFaultKind::CoordinateLimit`]), and a completed LEN
//! prefix is judged the moment it completes — an endpoint past
//! the class faults even though its bytes have not arrived.
//!
//! Tenure is transactional at failure: a [`Failure`] returns the
//! accumulated source, and [`Failure::chunk`] says exactly whether
//! the failing feed's chunk is inside it —
//! [`ChunkDisposition::Unabsorbed`] (admission refused; nothing of
//! the chunk was read) or [`ChunkDisposition::Absorbed`] (a fault
//! landed mid-parse; the cold path bulk-copied the unexamined
//! suffix, so the source ends with the whole chunk). There is never
//! a partially absorbed chunk. Faults carry two coordinates: the
//! absolute stream offset ([`IngestFault::at`], `u64`, stream
//! convention — truncation names the stream end) and the buffered
//! diagnosis inside the kind (construct coordinates, the buffered
//! twin's convention).
//!
//! Allocation refusal aborts rather than erring — the shared-layer
//! partition rule ([`crate::stream_intake`]): a one-shot machine
//! holds nothing a re-run cannot rebuild.
//!
//! The finished machine is the buffered intake's shape over the
//! ingested source: the same commands, saves, and transactional
//! release. Its only door is the seal — the cell's input presence
//! is the stream, so no buffered `open` exists here (the buffered
//! cell is feature `intake-groupless`).
//!
//! Coordinates: write · stream · offline · groupless · canonical (type-level) · owned · commit-only.
//!
//! # Examples
//!
//! ```
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::stream_intake::groupless::Ingest;
//!
//! // varint f1=150 · LEN f2 "hi", fed byte by byte: chunk edges
//! // never show in the product.
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut ingest = Ingest::new(DepthLimit::REFERENCE);
//! for byte in msg {
//!     ingest.feed(&[byte]).unwrap();
//! }
//!
//! let mut intake = ingest.finish().unwrap();
//! let tops: Vec<_> = intake.top().collect();
//! intake.set_payload(tops[1], b"no").unwrap();
//!
//! // The untouched varint rode verbatim; the same-length payload
//! // kept its prefix.
//! let mut out = Vec::new();
//! intake.save_into(&mut out).unwrap();
//! assert_eq!(out, [0x08, 0x96, 0x01, 0x12, 0x02, 0x6E, 0x6F]);
//! ```
//!
//! Padded framing is lawful wire this cell refuses at collection
//! time — the fault names the padded word's first byte with the
//! buffered intake's vocabulary, and the accumulated source rides
//! back:
//!
//! ```
//! use protobuf_edit::DepthLimit;
//! use protobuf_edit::stream_intake::groupless::{Ingest, IngestFaultKind, Refusal};
//!
//! // Field 1 varint 1, tag padded to two bytes: the second tag
//! // byte decides, mid-chunk, and the chunk is absorbed whole.
//! let mut ingest = Ingest::new(DepthLimit::REFERENCE);
//! ingest.feed(&[0x88]).unwrap();
//! let failure = ingest.feed(&[0x00, 0x01]).unwrap_err();
//! assert_eq!(failure.fault().at(), 0);
//! assert!(matches!(
//!     failure.fault().kind(),
//!     IngestFaultKind::Refused(Refusal::NonMinimalTag { at: 0, width: 2 })
//! ));
//! assert_eq!(failure.source(), [0x88, 0x00, 0x01]);
//! ```

use core::num::NonZeroU32;

use alloc::vec::Vec;

use crate::admission::{Coord, Extent, admitted_u32, usize_of};
use crate::stream_intake::{
    BorrowedPayloadStore, CopiedPayloadStore, Handle, PayloadAt, PayloadStore, RowId, WordAt,
    WordStore, admit, parts_len_usize,
};
use crate::varint::slice::{self, ReadFault};
use crate::varint::{
    CONT_BIT, LAST_LEN, LAST32, LAST64, PAYLOAD_BITS, PAYLOAD_MASK, StepWidth, ValueWidth,
    WordWidth, encoded_len32, encoded_len64, push64,
};
use crate::wire::groupless::{RecordKind, TagClass, classify, head_word};
use crate::wire::{FieldNumber, Low3, PayloadLen};
use crate::{DepthLimit, Span};

pub use crate::stream_intake::{EditStatus, InsertAt};

#[cfg(feature = "transfer-stream-intake-groupless")]
pub mod transfer;

#[cfg(feature = "transfer-stream-intake-groupless")]
pub use transfer::TransferIntake;

#[cfg(test)]
mod tests;

crate::editor::groupless::one_shot_machine! {
    vocabulary stream(
        Ancestors, Children, Descent, EditFault, Fault, FaultKind,
        FrameFault, PayloadWrite, RecordSpans, Refusal, SaveFault,
        SaveSpans, SizedPayloadWrite,
    ),
    capability: plain,
    acceptance: canonical,
    noun: "intake",
    a_noun: "an intake",
    A_noun: "An intake",
}

crate::editor::groupless::one_shot_machine! {
    /// A one-shot editing intake sealed from a chunked stream.
    ///
    /// The buffered intake's editing machine over the ingested
    /// source: plain data over an owned `Vec<u8>` — no share
    /// counting, no interior mutability — `Send` because there is
    /// nothing to engineer around, and the saved product is the
    /// caller's own `Vec<u8>`. No source lifetime exists, so a
    /// mid-edit intake moves, returns, and caches (rows address the
    /// source by `u32` offsets, never pointers). Handles stay valid
    /// for the intake's life; rows and stored values are never
    /// reclaimed (re-setting a copied payload leaves the old bytes
    /// behind inert — the commit-only trade). `'p` backs the
    /// borrowed payloads (`set_payload`, `insert_payload`): each is
    /// held until the save copies it into the output, and an intake
    /// with no borrowed payloads inhabits `Intake<'static>`. The
    /// only door is [`Ingest::finish`] — the input arrived as a
    /// stream, so no buffered open exists on this type. The thin
    /// payload-backing siblings [`BorrowIntake`] and [`CopyIntake`]
    /// seal through [`Ingest::finish_borrow`]/[`Ingest::finish_copy`];
    /// the transfer sibling `TransferIntake` (feature
    /// `transfer-stream-intake-groupless`) seals through
    /// `Ingest::finish_transfer` and adds whole-record relocation,
    /// payload relocation, and external import.
    machine Intake<'p> { source: Vec<u8> }
    capability: plain,
    payloads: PayloadStore<'p>,
    backing: mixed(PayloadWrite, SizedPayloadWrite),
    payload: 'p,
    tenure: stream,
    acceptance: canonical,
    noun: "intake",
    a_noun: "an intake",
    A_noun: "An intake",
    doc_mod: "protobuf_edit::stream_intake::groupless",
    doc_open: "{ let mut ingest = protobuf_edit::stream_intake::groupless::Ingest::new(DepthLimit::REFERENCE); ingest.feed(&msg).unwrap(); ingest.finish() }",
    doc_open_empty: "protobuf_edit::stream_intake::groupless::Ingest::new(DepthLimit::REFERENCE).finish()",
    doc_recipes: " Price-reserve-save composes growth-free: reserve exactly [`Intake::save_len`]'s answer and [`Intake::save_into`] never grows the buffer.",
}

crate::editor::groupless::one_shot_machine! {
    /// The borrowed-only intake sealed from a chunked stream: every
    /// authored payload is borrowed until the save copies it once
    /// into the output.
    ///
    /// [`Intake`]'s command and save faces over the borrowed supply
    /// alone, sealed by [`Ingest::finish_borrow`]. No copied column
    /// exists, so neither the `_copy` faces nor the staged frames
    /// do, and the payload store is one `Vec` lighter; everything
    /// else — vocabulary, custody, the seal — is the mixed
    /// machine's. `'p` backs the borrowed payloads, so every
    /// payload owner must outlive the intake.
    machine BorrowIntake<'p> { source: Vec<u8> }
    capability: plain,
    payloads: BorrowedPayloadStore<'p>,
    backing: borrowed(mixed: Intake),
    payload: 'p,
    tenure: stream,
    acceptance: canonical,
    noun: "intake",
    a_noun: "an intake",
    A_noun: "An intake",
    doc_mod: "protobuf_edit::stream_intake::groupless",
    doc_open: "{ let mut ingest = protobuf_edit::stream_intake::groupless::Ingest::new(DepthLimit::REFERENCE); ingest.feed(&msg).unwrap(); ingest.finish_borrow() }",
    doc_open_empty: "protobuf_edit::stream_intake::groupless::Ingest::new(DepthLimit::REFERENCE).finish_borrow()",
    doc_recipes: " Price-reserve-save composes growth-free: reserve exactly [`BorrowIntake::save_len`]'s answer and [`BorrowIntake::save_into`] never grows the buffer.",
}

crate::editor::groupless::one_shot_machine! {
    /// The copy-only intake sealed from a chunked stream: every
    /// authored payload is staged by copy at the command.
    ///
    /// [`Intake`]'s command and save faces over the copied supply
    /// alone, sealed by [`Ingest::finish_copy`] — a payload slot is
    /// a bare extent, no slot tag exists, and no lifetime parameter
    /// remains at all: the source accumulates through the feeds and
    /// the payloads copy, so a mid-edit machine moves, returns, and
    /// caches with nothing pinning any caller frame.
    machine CopyIntake<> { source: Vec<u8> }
    capability: plain,
    payloads: CopiedPayloadStore,
    backing: copied(mixed: Intake, CopyPayloadWrite, SizedCopyPayloadWrite),
    tenure: stream,
    acceptance: canonical,
    noun: "intake",
    a_noun: "an intake",
    A_noun: "An intake",
    doc_mod: "protobuf_edit::stream_intake::groupless",
    doc_open: "{ let mut ingest = protobuf_edit::stream_intake::groupless::Ingest::new(DepthLimit::REFERENCE); ingest.feed(&msg).unwrap(); ingest.finish_copy() }",
    doc_open_empty: "protobuf_edit::stream_intake::groupless::Ingest::new(DepthLimit::REFERENCE).finish_copy()",
    doc_recipes: " Price-reserve-save composes growth-free: reserve exactly [`CopyIntake::save_len`]'s answer and [`CopyIntake::save_into`] never grows the buffer.",
}

// The thin siblings' savings, pinned at the machine level exactly as
// for the buffered cell and on every pointer width (the 32-bit
// layout gate is a check build, and only unconditional assertions
// reach it): the borrowed-only store drops the copied column whole —
// one Vec of three words, 24 bytes on 64-bit pointers and 12 on
// 32-bit — and the copy-only machine keeps the mixed footprint over
// untagged extent slots.
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(
        core::mem::size_of::<BorrowIntake<'_>>() + if w64 { 24 } else { 12 }
            == core::mem::size_of::<Intake<'_>>()
    );
    assert!(core::mem::size_of::<CopyIntake>() == core::mem::size_of::<Intake<'_>>());
};

// ─── the ingest phase ───

/// The finished editor's source cap in byte-length form: the
/// coordinate class every feed and every completed LEN endpoint is
/// admitted against.
const LIMIT: u32 = admitted_u32(crate::admission::MAX);
#[allow(
    clippy::as_conversions,
    reason = "the admission cap widens losslessly into the stream coordinate space"
)]
const SOURCE_CAP: u64 = LIMIT as u64;

/// Whether the failing feed's chunk ended up inside the returned
/// source.
///
/// Every feed is all-or-none with respect to the caller's chunk,
/// so the answer is exactly whether to append that chunk when
/// retaining the failed document.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ChunkDisposition {
    /// Nothing of the chunk was read or retained: the failure was
    /// judged at admission or reservation, and
    /// [`Failure::into_source`] holds exactly the prior successful
    /// feeds.
    Unabsorbed,
    /// The chunk is retained whole: a fault landed mid-parse and the
    /// cold path bulk-copied the unexamined suffix into the already
    /// reserved backing. [`Ingest::finish`] failures also answer
    /// `Absorbed` — every offered byte is in the source.
    Absorbed,
}

/// What ended the ingest job, beside where.
///
/// The wire and refusal alphabets are the buffered twin's own
/// ([`Fault`], [`Refusal`]), so a fault here names the same
/// construct, with the same buffered coordinates, that opening the
/// concatenated bytes would name. The coordinate-class refusal is
/// this cell's own: the stream is admitted against the finished
/// editor's source cap before bytes are read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IngestFaultKind {
    /// The stream violates the wire grammar. Truncation faults are
    /// judged at [`Ingest::finish`] — a chunk edge is never one.
    Wire(Fault),
    /// Lawful wire this cell refuses: padding outside the
    /// canonical-minimal policy (judged the moment the padded
    /// word's last byte arrives) or a group code.
    Refused(Refusal),
    /// The stream (or a completed LEN prefix's declared endpoint)
    /// runs past the finished editor's coordinate class. Judged
    /// before any byte of the offending chunk is read — and for a
    /// LEN endpoint, the moment its prefix completes, even though
    /// the body bytes have not arrived.
    CoordinateLimit {
        /// The finished editor's source cap (`i32::MAX`).
        limit: u32,
        /// Where the refused stream or declared endpoint would end.
        attempted_end: u64,
    },
}

/// One terminal ingest fault: an absolute stream coordinate beside
/// the judgment.
///
/// `at` follows the stream convention (the scanners' own): a wire
/// fault or refusal names the refused construct's first byte, a
/// structural judgment its judgment point, and a truncation the
/// stream end. The buffered diagnosis — the construct's own `u32`
/// coordinates — rides inside [`IngestFaultKind::Wire`] and
/// [`IngestFaultKind::Refused`], so both conventions stay readable
/// and distinct.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IngestFault {
    at: u64,
    kind: IngestFaultKind,
}

impl IngestFault {
    /// The coordinate (absolute stream offset).
    #[inline]
    #[must_use]
    pub const fn at(self) -> u64 {
        self.at
    }

    /// The judgment.
    #[inline]
    #[must_use]
    pub const fn kind(self) -> IngestFaultKind {
        self.kind
    }
}

impl core::fmt::Display for IngestFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.kind {
            IngestFaultKind::Wire(fault) => write!(f, "stream offset {}: {fault}", self.at),
            IngestFaultKind::Refused(refusal) => {
                write!(f, "stream offset {}: {refusal}", self.at)
            }
            IngestFaultKind::CoordinateLimit { limit, attempted_end } => write!(
                f,
                "stream offset {}: end {attempted_end} runs past the editor's {limit}-byte cap",
                self.at
            ),
        }
    }
}

impl core::error::Error for IngestFault {}

/// A failed ingest job: the accumulated source beside the fault and
/// the failing chunk's custody answer.
///
/// The construction transaction publishes either one complete
/// editor or none — a failure never returns a partially callable
/// machine. The source is every byte the job retained, chunk
/// custody exact per [`ChunkDisposition`].
#[must_use]
pub struct Failure {
    source: Vec<u8>,
    fault: IngestFault,
    chunk: ChunkDisposition,
}

impl Failure {
    /// The accumulated source retained by the failed job.
    #[inline]
    #[must_use]
    pub fn source(&self) -> &[u8] {
        &self.source
    }

    /// Releases the accumulated source — a move, zero copies.
    #[inline]
    #[must_use]
    pub fn into_source(self) -> Vec<u8> {
        self.source
    }

    /// The terminal fault.
    #[inline]
    #[must_use]
    pub const fn fault(&self) -> IngestFault {
        self.fault
    }

    /// The failing chunk's custody answer.
    #[inline]
    #[must_use]
    pub const fn chunk(&self) -> ChunkDisposition {
        self.chunk
    }
}

impl core::fmt::Debug for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Failure")
            .field("fault", &self.fault)
            .field("chunk", &self.chunk)
            .field("source_len", &self.source.len())
            .finish()
    }
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ingest failed: {}", self.fault)
    }
}

impl core::error::Error for Failure {}

/// Why an ingest refused to start.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartFault {
    /// The declared capacity exceeds the finished editor's
    /// coordinate class (`i32::MAX` bytes) — no lawful stream can
    /// fill it.
    TooLarge {
        /// The refused capacity.
        capacity: usize,
    },
}

impl core::fmt::Display for StartFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::TooLarge { capacity } => {
                write!(f, "capacity of {capacity} bytes exceeds the coordinate class")
            }
        }
    }
}

impl core::error::Error for StartFault {}

/// The varint construct in flight across chunk edges: assembled
/// payload bits and the byte count consumed so far. The raw bytes
/// themselves are not banked here — they already live in the
/// reserved final backing, appended as they were loaded — and the
/// construct's start is the accumulated length minus the width.
#[derive(Clone, Copy)]
struct VarintCarry {
    acc: u64,
    width: u8,
}

impl VarintCarry {
    const fn new() -> Self {
        Self { acc: 0, width: 0 }
    }
}

/// One varint stepper verdict, generic over the window's width
/// domain. No `Cut` arm exists: the root layer has no sealed
/// interior extent (LEN bodies are counted opaquely), and the
/// stream end is judged by `finish` alone.
enum Step<W> {
    /// Terminated in class; the carry is reset.
    Done {
        /// The assembled value.
        value: u64,
        /// The construct's consumed width.
        width: W,
    },
    /// The chunk ran out first; feed the next one.
    More,
    /// Ran past the domain window still continuing.
    TooWide,
    /// The terminal byte at full width exceeds the domain class.
    OutOfClass,
}

/// A record head whose value side is still in flight: everything
/// the row mint needs once the extent completes.
#[derive(Clone, Copy)]
struct PendingHead {
    /// Source offset of the head tag.
    start: Coord,
    field: FieldNumber,
    /// The head tag's width, met at the stepper; the canonical
    /// gate judged it minimal before this head was minted, so met
    /// and minimal coincide here.
    tag_width: WordWidth,
}

impl PendingHead {
    /// The value side's source offset.
    const fn value_at(self) -> u32 {
        self.start.as_inner() + self.tag_width.w()
    }
}

/// The parse state a chunk edge can cut — nothing more: scalar rows
/// publish whole when their extent completes, and a LEN row waits as
/// its own pending row while its opaque body is counted.
#[derive(Clone, Copy)]
enum Phase {
    /// Between records; the carry may hold a partial tag.
    Head,
    /// A varint record's value is in flight.
    VarintValue {
        /// The completed head.
        head: PendingHead,
    },
    /// A LEN record's length prefix is in flight.
    LenWord {
        /// The completed head.
        head: PendingHead,
    },
    /// A fixed payload is being collected.
    Fixed {
        /// The completed head.
        head: PendingHead,
        /// `I32` or `I64` — the publish kind and the fault's `need`.
        kind: RecordKind,
        /// Payload bytes still owed.
        remaining: u8,
    },
    /// A LEN body is being counted; the row publishes at zero.
    LenBody {
        /// The fully minted row, waiting on its body bytes.
        row: Row,
        /// Body bytes still owed.
        remaining: NonZeroU32,
    },
}

/// Appends one byte into capacity the feed already reserved.
///
/// # Safety
/// `source` has spare capacity for at least one more byte — the
/// feed door reserved the whole chunk before the first load.
#[inline(always)]
unsafe fn push_reserved(source: &mut Vec<u8>, byte: u8) {
    let len = source.len();
    debug_assert!(len < source.capacity());
    // SAFETY: one spare byte exists past `len` (this function's
    // contract), and the write initializes it before the raise.
    unsafe {
        source.as_mut_ptr().add(len).write(byte);
        source.set_len(len + 1);
    }
}

/// Bulk-appends bytes into capacity the feed already reserved.
///
/// # Safety
/// `source` has spare capacity for at least `bytes.len()` more
/// bytes — the feed door reserved the whole chunk before the first
/// load.
#[inline]
unsafe fn extend_reserved(source: &mut Vec<u8>, bytes: &[u8]) {
    let len = source.len();
    debug_assert!(bytes.len() <= source.capacity() - len);
    // SAFETY: the spare capacity covers the copy (this function's
    // contract), the borrowed chunk cannot overlap the owned
    // backing, and the raise covers exactly the initialized bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), source.as_mut_ptr().add(len), bytes.len());
        source.set_len(len + bytes.len());
    }
}

/// A mid-stream wire fault: both conventions name the same byte
/// (the refused construct's first, the scanners' own coordinate).
#[cold]
const fn wire_now(at: u32, kind: FaultKind) -> IngestFault {
    IngestFault { at: at as u64, kind: IngestFaultKind::Wire(Fault { at, kind }) }
}

/// A mid-stream policy or capability refusal: both conventions
/// name the same byte (the refused construct's first).
#[cold]
const fn refused_now(at: u32, refusal: Refusal) -> IngestFault {
    IngestFault { at: at as u64, kind: IngestFaultKind::Refused(refusal) }
}

/// A truncation fault at the stream end: the stream coordinate is
/// EOF, the buffered diagnosis keeps the construct's own offset.
#[cold]
const fn wire_eof(eof: u64, at: u32, kind: FaultKind) -> IngestFault {
    IngestFault { at: eof, kind: IngestFaultKind::Wire(Fault { at, kind }) }
}

/// The live ingest state behind the terminal-use shell.
struct IngestCore {
    source: Vec<u8>,
    rows: Vec<Row>,
    /// The root chain's head — the finished editor's `top`.
    first: Option<RowId>,
    /// The root chain's tail — the sibling-link anchor.
    last: Option<RowId>,
    carry: VarintCarry,
    phase: Phase,
    limit: DepthLimit,
}

impl IngestCore {
    /// The absolute stream offset: every accepted byte is in the
    /// backing, so the offset is its length.
    #[allow(
        clippy::as_conversions,
        reason = "the accumulated length is admission-bounded, far inside u64"
    )]
    const fn offset(&self) -> u64 {
        self.source.len() as u64
    }

    /// Steps the varint construct in flight: each source byte is
    /// examined once — one append to the reserved backing and one
    /// fold into the carry. A terminated read mints its counted
    /// width in the verdict's window domain `W`.
    fn step<W: StepWidth, const LAST_MAX: u8>(&mut self, rest: &mut &[u8]) -> Step<W> {
        const { assert!(W::CAP <= 10 && LAST_MAX < CONT_BIT) };
        while let Some((&byte, tail)) = rest.split_first() {
            // SAFETY: the feed door reserved the whole chunk before
            // the drive started, and every prior append consumed a
            // chunk byte — spare capacity covers this one.
            unsafe { push_reserved(&mut self.source, byte) };
            *rest = tail;
            self.carry.acc |=
                (u64::from(byte) & PAYLOAD_MASK) << (PAYLOAD_BITS * u32::from(self.carry.width));
            self.carry.width += 1;
            if byte < CONT_BIT {
                if self.carry.width == W::CAP && byte > LAST_MAX {
                    return Step::OutOfClass;
                }
                // SAFETY: a terminated in-window read: the carry
                // re-enters this loop only below the cap (`More`
                // exits below it; every capped verdict spends the
                // machine), and each byte increments the width
                // once, so `1 <= width && width <= W::CAP`.
                let width = unsafe { W::met_unchecked(self.carry.width) };
                let done = Step::Done { value: self.carry.acc, width };
                self.carry = VarintCarry::new();
                return done;
            }
            if self.carry.width == W::CAP {
                return Step::TooWide;
            }
        }
        Step::More
    }

    /// Publishes one completed row at the root chain's tail.
    fn publish(&mut self, row: Row) {
        let Some(id) = u32::try_from(self.rows.len()).ok().and_then(RowId::new) else {
            // Every published row spends at least one source byte
            // and feed admission bounds the stream at `i32::MAX`
            // bytes — the same bound the buffered root scan cites —
            // so the arena cannot leave the row domain.
            debug_assert!(false, "root ingest exhausted the row domain");
            // SAFETY: the row-count bound argued above.
            unsafe { core::hint::unreachable_unchecked() }
        };
        match self.last {
            Some(prev) => {
                // SAFETY: `prev` was minted by this ingest's publish.
                unsafe { self.rows.get_unchecked_mut(prev.index()) }.next = Some(id);
            }
            None => self.first = Some(id),
        }
        self.rows.push(row);
        self.last = Some(id);
    }

    /// Drives the fused loop over one admitted, reservation-backed
    /// chunk. On a fault the unexamined suffix is bulk-copied into
    /// the reservation — the chunk is absorbed whole.
    fn drive(&mut self, chunk: &[u8]) -> Result<(), IngestFault> {
        let mut rest = chunk;
        match self.advance(&mut rest) {
            Ok(()) => {
                debug_assert!(rest.is_empty());
                Ok(())
            }
            Err(fault) => {
                // SAFETY: the feed door reserved the whole chunk;
                // the examined prefix consumed exactly its own
                // bytes, so the suffix fits the spare capacity.
                unsafe { extend_reserved(&mut self.source, rest) };
                Err(fault)
            }
        }
    }

    /// The grammar loop: each arm settles one construct stage and
    /// leaves the phase at the next. A drained chunk exits through
    /// the loop guard — `Step::More` can only be answered on an
    /// empty rest.
    fn advance(&mut self, rest: &mut &[u8]) -> Result<(), IngestFault> {
        while !rest.is_empty() {
            match self.phase {
                Phase::Head => self.head(rest)?,
                Phase::VarintValue { head } => self.varint_value(rest, head)?,
                Phase::LenWord { head } => self.len_word(rest, head)?,
                Phase::Fixed { head, kind, remaining } => self.fixed(rest, head, kind, remaining),
                Phase::LenBody { row, remaining } => self.len_body(rest, row, remaining),
            }
        }
        Ok(())
    }

    /// Steps the head tag; a completed tag is judged minimal, then
    /// classifies and opens its value stage.
    #[allow(
        clippy::as_conversions,
        reason = "four full payload bytes and a fifth capped at 0x0F land exactly in u32"
    )]
    fn head(&mut self, rest: &mut &[u8]) -> Result<(), IngestFault> {
        let (word, width) = match self.step::<WordWidth, LAST32>(rest) {
            Step::Done { value, width } => (value as u32, width),
            Step::More => return Ok(()),
            Step::TooWide => {
                return Err(self.head_fault(FaultKind::Tag { fault: ReadFault::TooWide }));
            }
            Step::OutOfClass => {
                return Err(self.head_fault(FaultKind::Tag { fault: ReadFault::OutOfClass }));
            }
        };
        let start = admitted_u32(self.source.len() - usize::from(width.as_inner()));
        // The canonical gate, first as in the buffered root scan:
        // a padded tag refuses before its word is read for field
        // or class.
        if width.w() > encoded_len32(word) {
            let refusal = Refusal::NonMinimalTag { at: start, width: width.as_inner() };
            return Err(refused_now(start, refusal));
        }
        let Some(field) = FieldNumber::from_word(word) else {
            return Err(wire_now(start, FaultKind::FieldZero));
        };
        let low3 = Low3::from_word(word);
        let kind = match classify(low3) {
            TagClass::Record(kind) => kind,
            TagClass::GroupCode => {
                return Err(refused_now(start, Refusal::GroupCode { at: start, field, low3 }));
            }
            TagClass::Unassigned => {
                return Err(wire_now(start, FaultKind::Unassigned { field, low3 }));
            }
        };
        // SAFETY: every feed gate held the accumulated source at or
        // below the cap, so the head offset is in class.
        let start = unsafe { Coord::new_unchecked(start) };
        let head = PendingHead { start, field, tag_width: width };
        match kind {
            RecordKind::Varint => self.phase = Phase::VarintValue { head },
            RecordKind::I32 | RecordKind::I64 => {
                let need: u8 = if matches!(kind, RecordKind::I32) { 4 } else { 8 };
                let attempted_end = self.offset() + u64::from(need);
                if attempted_end > SOURCE_CAP {
                    return Err(IngestFault {
                        at: self.offset(),
                        kind: IngestFaultKind::CoordinateLimit { limit: LIMIT, attempted_end },
                    });
                }
                self.phase = Phase::Fixed { head, kind, remaining: need };
            }
            RecordKind::Len => self.phase = Phase::LenWord { head },
        }
        Ok(())
    }

    /// A tag-stage stepper fault: the construct's first byte in
    /// both conventions.
    #[cold]
    fn head_fault(&self, kind: FaultKind) -> IngestFault {
        let at = admitted_u32(self.source.len() - usize::from(self.carry.width));
        wire_now(at, kind)
    }

    /// Steps a varint record's value; a completed value is judged
    /// minimal, and completion publishes the row.
    fn varint_value(&mut self, rest: &mut &[u8], head: PendingHead) -> Result<(), IngestFault> {
        let (value, width) = match self.step::<ValueWidth, LAST64>(rest) {
            Step::Done { value, width } => (value, width),
            Step::More => return Ok(()),
            Step::TooWide => {
                let kind = FaultKind::Value { field: head.field, fault: ReadFault::TooWide };
                return Err(wire_now(head.value_at(), kind));
            }
            Step::OutOfClass => {
                let kind = FaultKind::Value { field: head.field, fault: ReadFault::OutOfClass };
                return Err(wire_now(head.value_at(), kind));
            }
        };
        if width.w() > encoded_len64(value) {
            let refusal = Refusal::NonMinimalValue {
                at: head.value_at(),
                field: head.field,
                width: width.as_inner(),
            };
            return Err(refused_now(head.value_at(), refusal));
        }
        self.publish(Row::scanned(
            head.field,
            RecordKind::Varint,
            head.start,
            Extent::from_width(width.as_inner()),
            None,
        ));
        self.phase = Phase::Head;
        Ok(())
    }

    /// Steps a LEN length prefix; a completed prefix is judged
    /// minimal, then against the coordinate class immediately —
    /// even though its body bytes have not arrived — and a
    /// zero-length body publishes at once.
    #[allow(
        clippy::as_conversions,
        reason = "four full payload bytes and a fifth capped at 0x07 land inside the length class"
    )]
    fn len_word(&mut self, rest: &mut &[u8], head: PendingHead) -> Result<(), IngestFault> {
        let (value, width) = match self.step::<WordWidth, LAST_LEN>(rest) {
            Step::Done { value, width } => (value, width),
            Step::More => return Ok(()),
            Step::TooWide => {
                let kind = FaultKind::Len { field: head.field, fault: ReadFault::TooWide };
                return Err(wire_now(head.value_at(), kind));
            }
            Step::OutOfClass => {
                let kind = FaultKind::Len { field: head.field, fault: ReadFault::OutOfClass };
                return Err(wire_now(head.value_at(), kind));
            }
        };
        if width.w() > encoded_len32(value as u32) {
            let refusal = Refusal::NonMinimalLen {
                at: head.value_at(),
                field: head.field,
                width: width.as_inner(),
            };
            return Err(refused_now(head.value_at(), refusal));
        }
        // SAFETY: four full payload bytes carry 28 bits and the
        // fifth is capped at 0x07, so the value is at most
        // 0x7FFF_FFFF — inside the PayloadLen range.
        let len = unsafe { PayloadLen::new_unchecked(value as u32) };
        let attempted_end = self.offset() + u64::from(len.as_inner());
        if attempted_end > SOURCE_CAP {
            return Err(IngestFault {
                at: self.offset(),
                kind: IngestFaultKind::CoordinateLimit { limit: LIMIT, attempted_end },
            });
        }
        let row =
            Row::scanned(head.field, RecordKind::Len, head.start, Extent::from_len(len), None);
        match NonZeroU32::new(len.as_inner()) {
            None => {
                self.publish(row);
                self.phase = Phase::Head;
            }
            Some(remaining) => self.phase = Phase::LenBody { row, remaining },
        }
        Ok(())
    }

    /// Collects a fixed payload in bulk; completion publishes.
    /// Fixed payloads carry no varint word, so no canonical
    /// judgment exists here.
    #[allow(clippy::as_conversions, reason = "the take is bounded by `remaining ≤ 8`, inside u8")]
    fn fixed(&mut self, rest: &mut &[u8], head: PendingHead, kind: RecordKind, remaining: u8) {
        let take = usize::from(remaining).min(rest.len());
        let (bytes, tail) = rest.split_at(take);
        // SAFETY: the feed door reserved the whole chunk; the take
        // is bounded by the chunk's own remainder.
        unsafe { extend_reserved(&mut self.source, bytes) };
        *rest = tail;
        let remaining = remaining - take as u8;
        if remaining == 0 {
            let width: u8 = if matches!(kind, RecordKind::I32) { 4 } else { 8 };
            self.publish(Row::scanned(
                head.field,
                kind,
                head.start,
                Extent::from_width(width),
                None,
            ));
            self.phase = Phase::Head;
        } else {
            self.phase = Phase::Fixed { head, kind, remaining };
        }
    }

    /// Counts an opaque LEN body in bulk — its bytes are copied,
    /// never wire-judged (the lazy-top grammar; a later explicit
    /// descend commits them). The pending row publishes at zero.
    #[allow(
        clippy::as_conversions,
        reason = "the take is bounded by the u32 `remaining`, inside u32"
    )]
    fn len_body(&mut self, rest: &mut &[u8], row: Row, remaining: NonZeroU32) {
        let take = usize_of(remaining.get()).min(rest.len());
        let (bytes, tail) = rest.split_at(take);
        // SAFETY: the feed door reserved the whole chunk; the take
        // is bounded by the chunk's own remainder.
        unsafe { extend_reserved(&mut self.source, bytes) };
        *rest = tail;
        match NonZeroU32::new(remaining.get() - take as u32) {
            Some(remaining) => self.phase = Phase::LenBody { row, remaining },
            None => {
                self.publish(row);
                self.phase = Phase::Head;
            }
        }
    }

    /// The seal's truncation judgment: the carried phase state
    /// alone answers whether the stream ended between records.
    fn truncation(&self) -> Option<IngestFault> {
        let eof = self.offset();
        match self.phase {
            Phase::Head => {
                if self.carry.width == 0 {
                    return None;
                }
                let at = admitted_u32(self.source.len() - usize::from(self.carry.width));
                Some(wire_eof(eof, at, FaultKind::Tag { fault: ReadFault::Truncated }))
            }
            Phase::VarintValue { head } => Some(wire_eof(
                eof,
                head.value_at(),
                FaultKind::Value { field: head.field, fault: ReadFault::Truncated },
            )),
            Phase::LenWord { head } => Some(wire_eof(
                eof,
                head.value_at(),
                FaultKind::Len { field: head.field, fault: ReadFault::Truncated },
            )),
            Phase::Fixed { head, kind, remaining } => {
                let need: u32 = if matches!(kind, RecordKind::I32) { 4 } else { 8 };
                let have = need - u32::from(remaining);
                Some(wire_eof(
                    eof,
                    head.value_at(),
                    FaultKind::PayloadCut { field: head.field, need, have },
                ))
            }
            Phase::LenBody { row, remaining } => {
                let need = row.payload_len.as_inner();
                let have = need - remaining.get();
                let body = row.start.as_inner() + row.tag_w() + row.delim_w();
                Some(wire_eof(eof, body, FaultKind::PayloadCut { field: row.field, need, have }))
            }
        }
    }
}

/// The sealed parts every finish door consumes.
struct Sealed {
    source: Vec<u8>,
    rows: Vec<Row>,
    top: Option<RowId>,
    limit: DepthLimit,
}

/// Spends the shell on the cold failure path: the core moves out
/// whole and its source rides the failure.
#[cold]
fn spend(core: &mut Option<IngestCore>, fault: IngestFault, chunk: ChunkDisposition) -> Failure {
    // Every caller reached here through the live gate, holding the
    // core it is now spending.
    let Some(core) = core.take() else { unreachable!("the live gate precedes every spend") };
    Failure { source: core.source, fault, chunk }
}

/// The stream-ingest phase: accepts chunks, parses and judges them
/// canonical-minimal as they arrive, and seals into the finished
/// editing intake.
///
/// One fused pass: `feed` reserves room for the whole chunk, then
/// examines each byte once — one append into the reserved final
/// backing and one fold into the varint carry; every completed
/// framing word and varint value is judged minimal at that moment.
/// The phase owns no query, command, or save face; only a
/// successful [`Ingest::finish`] (or a payload-backing sibling
/// door) publishes a machine those faces exist on.
///
/// Terminal states are final: after a returned [`Failure`] the
/// shell is spent, and another `feed`/`finish`/`into_source` call
/// panics (a caller bug, named). Dropping a live ingest abandons
/// the job — allocations are freed, nothing is published.
#[must_use]
pub struct Ingest {
    core: Option<IngestCore>,
}

impl Ingest {
    /// Starts an ingest job. The depth bound is retained for the
    /// finished intake's future LEN descents — ingest itself never
    /// descends (LEN interiors stay opaque), so no depth judgment
    /// runs before the seal.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::stream_intake::groupless::Ingest;
    ///
    /// let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    /// ingest.feed(&[0x08, 0x2A]).unwrap();
    /// assert_eq!(ingest.offset(), 2);
    /// ```
    #[inline]
    pub const fn new(limit: DepthLimit) -> Self {
        Self {
            core: Some(IngestCore {
                source: Vec::new(),
                rows: Vec::new(),
                first: None,
                last: None,
                carry: VarintCarry::new(),
                phase: Phase::Head,
                limit,
            }),
        }
    }

    /// Starts an ingest job with one initial source reservation —
    /// the door for framed streams whose total length is known:
    /// provided the cumulative feeds stay within `capacity`, the
    /// backing never regrows and the whole job runs on a single
    /// physical source allocation. `capacity` is an initial
    /// reservation, not a bound — a stream that outgrows it stays
    /// lawful and regrows the backing like [`Ingest::new`]'s.
    ///
    /// # Errors
    ///
    /// [`StartFault::TooLarge`] when `capacity` exceeds the
    /// finished editor's coordinate class (`i32::MAX` bytes) — no
    /// lawful stream can fill such a reservation.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::stream_intake::groupless::Ingest;
    ///
    /// let mut ingest = Ingest::with_capacity(DepthLimit::REFERENCE, 2).unwrap();
    /// ingest.feed(&[0x08, 0x2A]).unwrap();
    /// let intake = ingest.finish().unwrap();
    /// assert_eq!(intake.source(), [0x08, 0x2A]);
    /// ```
    pub fn with_capacity(limit: DepthLimit, capacity: usize) -> Result<Self, StartFault> {
        if admit(capacity).is_none() {
            return Err(StartFault::TooLarge { capacity });
        }
        let mut ingest = Self::new(limit);
        // The live gate is vacuous on a fresh shell.
        if let Some(core) = ingest.core.as_mut() {
            core.source.reserve_exact(capacity);
        }
        Ok(ingest)
    }

    /// The absolute stream offset: bytes accepted so far.
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`] — the shell is spent, terminal
    /// like every other face.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn offset(&self) -> u64 {
        let Some(core) = self.core.as_ref() else { panic!("ingest already terminal") };
        core.offset()
    }

    /// Feeds one chunk: coordinate admission, one reservation, then
    /// the fused copy/parse loop with the canonical judgment fused
    /// in. A chunk edge is never a fault — a construct cut here
    /// resumes on the next feed, and only [`Ingest::finish`]
    /// declares EOF.
    ///
    /// # Errors
    ///
    /// [`IngestFaultKind::CoordinateLimit`] when the chunk would
    /// run the stream past the finished editor's source cap
    /// (`i32::MAX` bytes) — judged whole, before any byte is read,
    /// with the chunk [`ChunkDisposition::Unabsorbed`]. Wire
    /// faults, canonical-minimality refusals, and capability
    /// refusals ([`IngestFaultKind::Wire`],
    /// [`IngestFaultKind::Refused`]) are judged as their deciding
    /// byte arrives — a padded word the moment its last byte lands,
    /// at the construct's first byte — with the chunk absorbed
    /// whole. Every failure returns the accumulated source and
    /// spends the shell.
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`] — the stream is over; feeding
    /// again is a caller bug.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::stream_intake::groupless::Ingest;
    ///
    /// // A varint value split across three feeds.
    /// let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    /// ingest.feed(&[0x08]).unwrap();
    /// ingest.feed(&[0x96]).unwrap();
    /// ingest.feed(&[0x01]).unwrap();
    /// let intake = ingest.finish().unwrap();
    /// assert_eq!(intake.top().count(), 1);
    /// ```
    #[track_caller]
    #[allow(
        clippy::as_conversions,
        reason = "slice lengths cap at isize::MAX, so the widened sum stays in u64"
    )]
    pub fn feed(&mut self, chunk: &[u8]) -> Result<(), Failure> {
        let Some(core) = self.core.as_mut() else { panic!("ingest already terminal") };
        let offset = core.offset();
        let attempted_end = offset + chunk.len() as u64;
        if attempted_end > SOURCE_CAP {
            let fault = IngestFault {
                at: offset,
                kind: IngestFaultKind::CoordinateLimit { limit: LIMIT, attempted_end },
            };
            return Err(spend(&mut self.core, fault, ChunkDisposition::Unabsorbed));
        }
        core.source.reserve(chunk.len());
        if let Err(fault) = core.drive(chunk) {
            return Err(spend(&mut self.core, fault, ChunkDisposition::Absorbed));
        }
        Ok(())
    }

    /// Declares EOF, seals the source, and moves the parts out —
    /// no reparse: the carried phase state is judged, root anchors
    /// finalize, and no byte of the source is traversed again (the
    /// canonical judgment already ran at collection, so no second
    /// judging pass exists either).
    ///
    /// # Errors
    ///
    /// The stream truncation judgments, each with the stream
    /// coordinate at EOF and the buffered construct diagnosis
    /// inside the kind: a tag, value, or length prefix cut
    /// mid-word ([`ReadFault::Truncated`] at its stage), or a fixed
    /// or counted payload still owed bytes
    /// ([`FaultKind::PayloadCut`]). The accumulated source rides
    /// back inside the [`Failure`], absorbed.
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`] — the shell is spent.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::stream_intake::groupless::Ingest;
    ///
    /// let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    /// ingest.feed(&[0x08, 0x96, 0x01, 0x10, 0x2A]).unwrap();
    /// let mut intake = ingest.finish().unwrap();
    /// let first = intake.top().next().unwrap();
    /// intake.set_varint(first, 7).unwrap();
    /// assert_eq!(intake.save().unwrap(), [0x08, 0x07, 0x10, 0x2A]);
    /// ```
    pub fn finish<'p>(self) -> Result<Intake<'p>, Failure> {
        let sealed = self.seal()?;
        Ok(Intake {
            source: sealed.source,
            rows: sealed.rows,
            words: WordStore::new(),
            payloads: PayloadStore::new(),
            faults: Vec::new(),
            top: sealed.top,
            limit: sealed.limit,
            dirty: false,
        })
    }

    /// [`Ingest::finish`] into the borrowed-only machine: the same
    /// sealed parts under [`BorrowIntake`]'s payload supply.
    ///
    /// # Errors
    ///
    /// As [`Ingest::finish`].
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`] — the shell is spent.
    pub fn finish_borrow<'p>(self) -> Result<BorrowIntake<'p>, Failure> {
        let sealed = self.seal()?;
        Ok(BorrowIntake {
            source: sealed.source,
            rows: sealed.rows,
            words: WordStore::new(),
            payloads: BorrowedPayloadStore::new(),
            faults: Vec::new(),
            top: sealed.top,
            limit: sealed.limit,
            dirty: false,
        })
    }

    /// [`Ingest::finish`] into the copy-only machine: the same
    /// sealed parts under [`CopyIntake`]'s payload supply.
    ///
    /// # Errors
    ///
    /// As [`Ingest::finish`].
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`] — the shell is spent.
    pub fn finish_copy(self) -> Result<CopyIntake, Failure> {
        let sealed = self.seal()?;
        Ok(CopyIntake {
            source: sealed.source,
            rows: sealed.rows,
            words: WordStore::new(),
            payloads: CopiedPayloadStore::new(),
            faults: Vec::new(),
            top: sealed.top,
            limit: sealed.limit,
            dirty: false,
        })
    }

    /// Abandons the job and releases the accumulated backing — a
    /// move, zero copies. A construct in flight needs no
    /// reconstruction: its bytes are already in the backing.
    ///
    /// # Panics
    ///
    /// After a returned [`Failure`] — the source already left with
    /// the failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::DepthLimit;
    /// use protobuf_edit::stream_intake::groupless::Ingest;
    ///
    /// let mut ingest = Ingest::new(DepthLimit::REFERENCE);
    /// ingest.feed(&[0x08, 0x96]).unwrap(); // value still in flight
    /// assert_eq!(ingest.into_source(), [0x08, 0x96]);
    /// ```
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn into_source(mut self) -> Vec<u8> {
        let Some(core) = self.core.take() else { panic!("ingest already terminal") };
        core.source
    }

    /// The shared seal: judge the carried phase, then move the
    /// parts.
    fn seal(mut self) -> Result<Sealed, Failure> {
        let Some(core) = self.core.take() else { panic!("ingest already terminal") };
        if let Some(fault) = core.truncation() {
            return Err(Failure { source: core.source, fault, chunk: ChunkDisposition::Absorbed });
        }
        Ok(Sealed { source: core.source, rows: core.rows, top: core.first, limit: core.limit })
    }
}
