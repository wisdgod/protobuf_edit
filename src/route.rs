//! Path-program record routing over chunked protobuf bytes
//! (read · stream · static), per wire dialect — the
//! dialect-orthogonal shared layer.
//!
//! One job: feed chunks as they arrive, and a compiled
//! [`Program`](crate::path::Program) delivers what it designates
//! as PathId-tagged sink events — decoded scalars, and tapped
//! container bodies as borrowed segments. No document is retained:
//! the machine's state is the stream-stepping pump (absolute
//! offset, innermost sealed end, the one construct in flight, the
//! declared [`Standard`]), the compiled matcher's
//! layer tables, the container stack, and the open-tap stack. The
//! program precedes the stream: admission judged its shape once,
//! and a `static` program pays even that judgment at compile
//! time.
//!
//! The program, never the sink, answers every LEN's four-arm
//! question: {no target, no continuing path} — counted skip;
//! {targets, none continuing} — a tap, the payload counted out as
//! raw borrowed segments, never parsed; {no target, continuing
//! paths} — a commitment, silently descended, wire faults inside
//! it real; {targets and continuing paths} — tap *and* commit,
//! the body streamed as segments while its interior's own events
//! interleave. Inside a parsed container each construct's bytes
//! forward as one segment once parsing proves them body, before
//! that construct's own events; inside a counted tap the pieces
//! are raw and chunk-bounded. Overlap fans out as in `select`:
//! every targeting path delivers, ascending
//! [`PathId`](crate::path::PathId) per record, and one segment
//! piece reaches every open tap — outermost container first,
//! ascending path within one container. Groups (grouped dialect)
//! always walk; a targeted group taps its body between the two
//! framing tags, which never enter its segments. Committed
//! containers and groups spend one account of the caller's
//! [`DepthLimit`](crate::DepthLimit) budget.
//!
//! Allocation policy: every allocation is single-job working
//! memory — the matcher's layer tables, the container stack, and
//! the tap stack with its path-id arena — grown under the global
//! allocator's panic/abort discipline. Stream content is never
//! buffered: a delivered segment borrows the fed chunk or the
//! pump's bounded carry (at most one construct), and no payload
//! byte survives the feed that delivered it.
//!
//! Coordinates: read · stream · static · Standard (value-level).
//!
//! # Choosing a face
//!
//! One machine per dialect: construct `Router::new` with the
//! program, the declared [`Standard`]
//! (acceptance is configuration, never detection), and the depth
//! bound; `feed` each chunk as it lands; `finish(self)` declares
//! EOF — itself a judgment, faulting a construct the stream end
//! cuts. An empty program makes the router a wire-level validator
//! of everything it walks.
//!
//! Choosing between the selection twins is the presence axis:
//! bytes in hand → `select`; bytes arriving chunked → `route` —
//! both exist, the consumer chooses. Elsewhere: judging a stream
//! record by record without a program, disposing each LEN at the
//! sink's own discretion → `scan`, which drives the same stepping
//! pump (each behind its feature).
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "route-groupless")] {
//! use core::ops::ControlFlow;
//! use protobuf_edit::path::{PathId, Program, Segment};
//! use protobuf_edit::route::groupless::{Router, Sink};
//! use protobuf_edit::route::Standard;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! // Select every top-level field 2 varint, streaming.
//! struct Values(Vec<u64>);
//! impl Sink for Values {
//!     fn on_varint(
//!         &mut self,
//!         _path: PathId,
//!         _field: FieldNumber,
//!         _at: u64,
//!         value: u64,
//!     ) -> ControlFlow<()> {
//!         self.0.push(value);
//!         ControlFlow::Continue(())
//!     }
//! }
//!
//! let f2 = FieldNumber::new(2).unwrap();
//! let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f2)]];
//! let program = Program::over(&paths).unwrap();
//!
//! // varint f1=150 · varint f2=7, fed in chunks that split the
//! // first varint — chunk boundaries carry no meaning.
//! let msg = [0x08, 0x96, 0x01, 0x10, 0x07];
//! let mut sink = Values(Vec::new());
//! let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::REFERENCE);
//! router.feed(&msg[..2], &mut sink).unwrap();
//! router.feed(&msg[2..], &mut sink).unwrap();
//! router.finish().unwrap();
//! assert_eq!(sink.0, [7]);
//! # }
//! ```
//!
//! # Recipes
//!
//! A tapped payload arrives as borrowed segments that tile its
//! body in source order — the sink owns the buffer that joins
//! them:
//!
//! ```
//! # #[cfg(feature = "route-groupless")] {
//! use core::ops::ControlFlow;
//! use protobuf_edit::path::{PathId, Program, Segment};
//! use protobuf_edit::route::groupless::{Router, Sink};
//! use protobuf_edit::route::Standard;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! struct Body(Vec<u8>);
//! impl Sink for Body {
//!     fn on_segment(
//!         &mut self,
//!         _path: PathId,
//!         _at: u64,
//!         _seg_at: u64,
//!         bytes: &[u8],
//!     ) -> ControlFlow<()> {
//!         self.0.extend_from_slice(bytes);
//!         ControlFlow::Continue(())
//!     }
//! }
//!
//! // Tap field 2's payload; field 1's passes silently by count.
//! let f2 = FieldNumber::new(2).unwrap();
//! let paths: [&[Segment<'_>]; 1] = [&[Segment::Field(f2)]];
//! let program = Program::over(&paths).unwrap();
//!
//! // LEN f1 "xx" (skipped) · LEN f2 "hello", chunked mid-payload.
//! let msg = [0x0A, 0x02, 0x78, 0x78, 0x12, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F];
//! let mut sink = Body(Vec::new());
//! let mut router = Router::new(&program, Standard::Tolerant, DepthLimit::REFERENCE);
//! for chunk in msg.chunks(3) {
//!     router.feed(chunk, &mut sink).unwrap();
//! }
//! router.finish().unwrap();
//! assert_eq!(sink.0, b"hello");
//! # }
//! ```
//!
//! A process-reused routing: the program lives in a `static` (its
//! judgment ran at compile time — building it is the doctest's own
//! proof), and each connection runs a judgment-free machine over
//! its chunks:
//!
//! ```
//! # #[cfg(feature = "route-groupless")] {
//! use core::ops::ControlFlow;
//! use protobuf_edit::path::{PathId, Program, Segment};
//! use protobuf_edit::route::groupless::{Router, Sink};
//! use protobuf_edit::route::Standard;
//! use protobuf_edit::{DepthLimit, FieldNumber};
//!
//! const F1: FieldNumber = FieldNumber::new(1).unwrap();
//! const F3: FieldNumber = FieldNumber::new(3).unwrap();
//! static ROUTE: [FieldNumber; 1] = [F3];
//! static PATHS: [&[Segment<'static>]; 1] =
//!     [&[Segment::AnyDepth { descend: &ROUTE }, Segment::Field(F1)]];
//! static PROGRAM: Program<'static> = match Program::over(&PATHS) {
//!     Ok(program) => program,
//!     Err(_) => panic!("the paths are lawful"),
//! };
//!
//! struct Starts(Vec<u64>);
//! impl Sink for Starts {
//!     fn on_varint(
//!         &mut self,
//!         _path: PathId,
//!         _field: FieldNumber,
//!         at: u64,
//!         _value: u64,
//!     ) -> ControlFlow<()> {
//!         self.0.push(at);
//!         ControlFlow::Continue(())
//!     }
//! }
//!
//! // varint f1=1 · LEN f3 { varint f1=2 }, one chunk per byte.
//! let request = [0x08, 0x01, 0x1A, 0x02, 0x08, 0x02];
//! let mut sink = Starts(Vec::new());
//! let mut router = Router::new(&PROGRAM, Standard::Tolerant, DepthLimit::REFERENCE);
//! for chunk in request.chunks(1) {
//!     router.feed(chunk, &mut sink).unwrap();
//! }
//! router.finish().unwrap();
//! assert_eq!(sink.0, [0, 4]);
//! # }
//! ```

pub use crate::Stage;
pub use crate::Standard;

/// A varint read refusal in stream coordinates: the carry kernel's
/// refusal alphabet with the boundary folded into the cause,
/// spelled as this module's own type (scenario modules share no
/// public types).
///
/// The kernel keeps chunk ends (recoverable — the feed simply asks
/// for the next chunk) apart from these terminal ends, and the two
/// terminal ends stay apart from each other.
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

/// A feed's orderly outcomes.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flow {
    /// The chunk is exhausted; feed the next one.
    More,
    /// The sink answered `Break`: the stream is over (terminal).
    Stopped,
}

#[cfg(feature = "route-grouped")]
pub mod grouped;
#[cfg(feature = "route-groupless")]
pub mod groupless;
