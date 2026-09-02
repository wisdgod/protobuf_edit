//! One-pass scanning over chunked protobuf bytes
//! (read · stream · online), per wire dialect — the
//! dialect-orthogonal shared layer.
//!
//! No document is retained. The machine's state is: a cursor
//! (absolute `u64` offset, plus the innermost sealed-extent end),
//! one [`crate::varint::carry::Carry`] for the construct in flight,
//! a resume mode for the next chunk, and the dialect's container
//! stack. The stream's admission bound is the coordinate space
//! itself — `u64::MAX − 1` bytes, judged per chunk at every feed.
//! Verdicts are independent of chunking: the carry kernel keeps
//! chunk ends (recoverable) apart from sealed-extent ends
//! (terminal), and every extent close is
//! resolved before a construct starts.
//!
//! Every varint steps through the carry kernel: its single-byte
//! fast path covers the dominant arm, and running one arm keeps
//! the chunk-end/zone-end attribution in one place.
//!
//! Per LEN the sink disposes between the interpretation poles —
//! Commit, or Opaque split by delivery ([`LenDisposition`]); no
//! speculation exists in a stream.
//!
//! Allocation policy: the dialects' container stacks grow under
//! the global allocator's panic/abort discipline. The groupless
//! validator carries no stack at all — it never descends, and no
//! group exists to frame; the grouped machines' stacks grow with
//! group frames even when nothing descends, which is why their
//! constructors take the depth bound.
//!
//! Coordinates: read · stream · online · Standard (value-level).
//!
//! # Choosing a face
//!
//! Two machines per dialect, split by what you want out:
//!
//! - `Validator` — the verdict alone: feed chunks, `finish`, and
//!   the answer is "legal under the declared [`Standard`]".
//!   Groupless construction takes the standard only (that
//!   validator never descends); the grouped twin also takes the
//!   depth bound (the allocation note above says why).
//! - `Parser` — the same verdicts plus events into your sink
//!   (record values, payload fragments, container enter/exit),
//!   with one [`LenDisposition`] question per LEN head.
//!
//! Answering [`LenDisposition`] is declaring schema knowledge:
//! [`Commit`](LenDisposition::Commit) where the field is a
//! message — the parser descends, and wire faults inside are
//! real; [`OpaqueBytes`](LenDisposition::OpaqueBytes) where you
//! want the payload delivered (zero-copy fragments, never
//! stitched); [`OpaqueSkip`](LenDisposition::OpaqueSkip) — the
//! default — where it should pass silently by count.
//!
//! Both machines drive the same way: construct with the declared
//! [`Standard`] (acceptance is configuration, never detection),
//! `feed` each chunk as it arrives, and `finish` to declare EOF —
//! itself a judgment: a construct the stream end cuts faults
//! there.
//!
//! Elsewhere: bytes you hold whole read better through `traverse`
//! or `inspect`; emitting a judged stream, not just reading it,
//! is `transcode`, which drives the same stepping pump (each
//! behind its feature).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "scan-groupless")] {
//! use protobuf_edit::scan::Standard;
//! use protobuf_edit::scan::groupless::Validator;
//!
//! // varint f1=150 · LEN f2 "hi", fed in chunks that split the
//! // varint — chunk boundaries carry no meaning.
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let mut validator = Validator::new(Standard::Tolerant);
//! validator.feed(&msg[..2]).unwrap();
//! validator.feed(&msg[2..]).unwrap();
//! assert!(validator.finish().is_ok());
//! # }
//! ```
//!
//! # Recipes
//!
//! The arrival loop, with selective delivery: feed each chunk as
//! it lands — buffering the stream to feed it whole forfeits the
//! shape — and let the default
//! [`OpaqueSkip`](LenDisposition::OpaqueSkip) pass every LEN the
//! job does not want (skipping counts, it never copies; committing
//! "just in case" buys parse faults inside payloads the job never
//! asked about). One
//! [`OpaqueBytes`](LenDisposition::OpaqueBytes) answer delivers
//! the wanted payload as borrowed fragments, never stitched — the
//! sink owns the buffer that joins them:
//!
//! ```
//! # #[cfg(feature = "scan-groupless")] {
//! use core::ops::ControlFlow;
//! use protobuf_edit::scan::groupless::{Parser, Sink};
//! use protobuf_edit::scan::{LenDisposition, Standard};
//! use protobuf_edit::{DepthLimit, FieldNumber, PayloadLen};
//!
//! struct Body(Vec<u8>);
//! impl Sink for Body {
//!     fn on_len(
//!         &mut self,
//!         field: FieldNumber,
//!         _len: PayloadLen,
//!         _at: u64,
//!     ) -> ControlFlow<(), LenDisposition> {
//!         ControlFlow::Continue(if field.as_inner() == 2 {
//!             LenDisposition::OpaqueBytes
//!         } else {
//!             LenDisposition::OpaqueSkip
//!         })
//!     }
//!     fn on_segment(&mut self, bytes: &[u8]) -> ControlFlow<()> {
//!         self.0.extend_from_slice(bytes);
//!         ControlFlow::Continue(())
//!     }
//! }
//!
//! // LEN f1 "xx" (skipped) · LEN f2 "hello" (delivered), chunked
//! // mid-payload.
//! let msg = [0x0A, 0x02, 0x78, 0x78, 0x12, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
//! let mut sink = Body(Vec::new());
//! let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
//! for chunk in msg.chunks(3) {
//!     parser.feed(chunk, &mut sink).unwrap();
//! }
//! parser.finish().unwrap();
//! assert_eq!(sink.0, b"hello");
//! # }
//! ```
//!
//! The ancestry stack the sink traits describe, compiled: push the
//! field when answering [`Commit`](LenDisposition::Commit) — the
//! enter notification — and pop on the exit; the stack then holds
//! exactly the committed containers:
//!
//! ```
//! # #[cfg(feature = "scan-groupless")] {
//! use core::ops::ControlFlow;
//! use protobuf_edit::scan::groupless::{Parser, Sink};
//! use protobuf_edit::scan::{LenDisposition, Standard};
//! use protobuf_edit::{DepthLimit, FieldNumber, PayloadLen};
//!
//! struct Paths {
//!     stack: Vec<u32>,
//!     seen: Vec<(Vec<u32>, u64)>,
//! }
//! impl Sink for Paths {
//!     fn on_len(
//!         &mut self,
//!         field: FieldNumber,
//!         _len: PayloadLen,
//!         _at: u64,
//!     ) -> ControlFlow<(), LenDisposition> {
//!         self.stack.push(field.as_inner()); // Commit is the enter
//!         ControlFlow::Continue(LenDisposition::Commit)
//!     }
//!     fn on_len_exit(
//!         &mut self,
//!         _field: FieldNumber,
//!         _at: u64,
//!     ) -> ControlFlow<()> {
//!         self.stack.pop();
//!         ControlFlow::Continue(())
//!     }
//!     fn on_varint(&mut self, _field: FieldNumber, value: u64) -> ControlFlow<()> {
//!         self.seen.push((self.stack.clone(), value));
//!         ControlFlow::Continue(())
//!     }
//! }
//!
//! // varint f1=1 · LEN f3 wrapping { varint f1=2 }
//! let msg = [0x08, 0x01, 0x1A, 0x02, 0x08, 0x02];
//! let mut sink = Paths { stack: Vec::new(), seen: Vec::new() };
//! let mut parser = Parser::new(Standard::Tolerant, DepthLimit::REFERENCE);
//! parser.feed(&msg, &mut sink).unwrap();
//! parser.finish().unwrap();
//! assert_eq!(sink.seen, [(vec![], 1), (vec![3], 2)]);
//! # }
//! ```

use crate::pump::FixedKind;
use crate::wire::FieldNumber;

pub use crate::Stage;

/// A varint read refusal in stream coordinates: the carry kernel's
/// refusal alphabet with the boundary folded into the cause.
///
/// The kernel keeps chunk ends (recoverable, [`Step::More`])
/// apart from these terminal ends, and the two terminal ends stay
/// apart from each other.
///
/// [`Step::More`]: crate::varint::carry::Step::More
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadFault {
    /// The innermost sealed extent ended mid-construct.
    SealCut,
    /// The stream ended mid-construct (declared at EOF).
    StreamEnd,
    /// Ran past the domain window still continuing.
    TooWide,
    /// The terminal byte exceeds the domain class.
    OutOfClass,
}

pub use crate::Standard;

/// A feed's orderly outcomes.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flow {
    /// The chunk is exhausted; feed the next one.
    More,
    /// The sink answered `Break`: the stream is over (terminal).
    Stopped,
}

/// The caller's per-LEN interpretation pole: commit, or opaque
/// split by delivery (no speculation exists in a stream — bytes
/// that failed a parse are gone).
#[must_use = "the disposition decides how the LEN payload is streamed"]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LenDisposition {
    /// Committed as a message: descend; parse faults inside are
    /// real faults.
    Commit,
    /// Opaque, delivered: never parsed; the payload arrives
    /// zero-copy as arrival fragments (never stitched).
    OpaqueBytes,
    /// Opaque, silent: never parsed; skipped by declared length,
    /// no events.
    OpaqueSkip,
}

// The event-consumer trait (`Sink`) is per dialect — the grouped
// vocabulary has group enter/exit events that the groupless one
// must not invite implementors to override — mirroring the wire
// tables' precedent of same-name, per-dialect vocabularies.

/// Where to resume when the next chunk arrives. Modes exist for
/// exactly the constructs a chunk boundary can cut; groups have no
/// mode (their memory is entirely on the stack, and a group end is
/// just a classified head word).
///
/// The counting modes are nonzero by construction: a zero-length
/// payload completes at its head — were zero admitted, a chunk
/// ending right after the length word would leave a counting mode
/// owing nothing, and EOF would misjudge a complete stream as
/// truncated.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Mode {
    /// Quiescent: expecting a record head (the carry may hold a
    /// cut head-word prefix).
    Head,
    /// A varint value in flight (head classified, field proven).
    VarintValue { field: FieldNumber },
    /// A LEN length word in flight.
    LenWord { field: FieldNumber },
    /// A fixed payload collecting across chunks.
    FixedTail { field: FieldNumber, kind: FixedKind },
    /// Counted delivery to the sink (an `OpaqueBytes` payload).
    Forward { remaining: core::num::NonZeroU32 },
    /// Counted silent skip (an `OpaqueSkip` payload).
    Swallow { remaining: core::num::NonZeroU32 },
}

const _: () = assert!(core::mem::size_of::<Mode>() == 8);

#[cfg(feature = "scan-grouped")]
pub mod grouped;
#[cfg(feature = "scan-groupless")]
pub mod groupless;
