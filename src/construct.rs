//! The value-side constructor: typed values in, message bytes out.
//!
//! Two dialect builders (`grouped`, `groupless`) share one
//! account-and-replay core. Every push charges the output account
//! first — each width is computed once and spent on both the charge
//! and the write — then its bytes enter the replay program: encoded
//! words land in an owned staging store in push order, while the
//! payload faces (`push_len`, `push_string`, `raw_bytes`) register
//! the caller's slice as a borrow, copied once, at emission,
//! straight into the output — except slices under a cache line
//! (64 bytes), which stage immediately: the one extra tiny copy is
//! strictly cheaper than borrow bookkeeping, and the lifetime
//! bound is unchanged. Each payload face has a `_copy` twin
//! that stages the bytes instead, for temporaries that cannot
//! outlive the builder. LEN frames record a placeholder event at
//! open and patch it at close with the body length and the prefix
//! width the close already paid for, so `finish` replays the
//! program into a buffer reserved once, up front, for the exact
//! total — the amortized `reserve` may round capacity above it,
//! but no later growth ever runs — without re-deriving anything.
//!
//! Framing is lawful by construction: the root builders accept only
//! complete typed records, frames pair by closure scope (there are
//! no begin/end verbs to mismatch), and every authored varint is
//! minimal width — an emission duty, not a taste. The author side
//! mirrors the interpretation poles as two forms: a message
//! closure authors the Commit form (its frame is a message by
//! construction), and the bytes faces author the Opaque form
//! (payloads the builder never interprets). Interior validity
//! of raw-face bytes is the raw caller's declaration. Construction
//! is transactional: a refused job leaves the caller's buffer
//! untouched, and a dropped builder leaves no trace.
//!
//! Output acceptance: every word the builder authors is minimal,
//! so the output re-ingests under `CanonicalMinimal` — except
//! where a raw or payload face carried caller-declared bytes,
//! whose interiors pass through unchanged.
//!
//! Allocation policy: the owned staging, borrow-table, event,
//! frame, and output vectors grow under the global allocator's
//! panic/abort discipline; the only structured data error is the
//! construction cap ([`OverCap`]). Under the crate root's
//! partition rule the builder sits on the abort side: its holdings
//! are the in-flight product of one authoring job, and an abort's
//! loss ends with that job.
//!
//! Coordinates: author (outside the input axes).
//!
//! # Choosing a face
//!
//! - Machine, by payload backing: `Builder` borrows its payloads
//!   by default (`'p` role lifetime) and carries `_copy` twins for
//!   temporaries; its sibling `CopyBuilder` copies every payload
//!   at the push under the unsuffixed face names — no borrow
//!   table, no lifetime parameter, temporaries welcome everywhere.
//!   Scalar and packed pushes are identical on both.
//! - Opening: `Builder::new`, or `Builder::with_capacity` with an
//!   output estimate a well-estimated build never regrows.
//! - Pushes: the typed faces carry the `.proto` scalar names
//!   (`push_int32`, `push_sint64`, `push_string`, the
//!   `push_packed_*` family, …) and compose [`crate::scalar`]'s
//!   encode matrix over the wire faces
//!   (`push_varint`/`push_i32`/`push_i64`/`push_len`) — reach for
//!   the wire faces when you already hold wire words.
//! - Payloads: `push_len`, `push_string`, and `raw_bytes` borrow
//!   their argument until the finish — zero staging copies — so
//!   the payload owner must outlive the builder; the `_copy` twins
//!   (`push_len_copy`, `push_string_copy`, `raw_bytes_copy`) stage
//!   a copy at the push instead, for temporaries. Typed scalars
//!   and the packed families always encode into the staging store
//!   — they transform values, so there is nothing to borrow.
//!   A payload you hold whole goes through `push_len`; one that
//!   arrives in pieces goes through `bytes_frame`, whose closure
//!   writes chunks ([`Bytes::write`] stages a copy,
//!   [`Bytes::write_borrowed`] keeps the one-copy path) into a
//!   single LEN record — same framing, chunked supply.
//! - Nesting: `message` frames a closure as a LEN record (the
//!   grouped builder adds `group`); inside a frame, the `raw_*`
//!   faces append unframed words whose interior meaning is your
//!   declaration.
//! - Finishing: `finish` allocates the output, `finish_into`
//!   appends to yours with one up-front reservation of the exact
//!   remaining need (amortized, so capacity may round up), and
//!   `finish_sink` hands the same bytes to a caller sink slice by
//!   slice — choose the `Vec` faces when the product accumulates
//!   locally, the sink face when the bytes leave through a writer
//!   and an intermediate buffer would only be copied out again.
//!   All three are transactional: on `Err` nothing is emitted and
//!   the sink is handed nothing. The one data refusal is
//!   [`OverCap`], queryable mid-build as `poisoned` — pushes
//!   after a break are inert, so checking once before the finish
//!   suffices — and `planned_len` prices the finish exactly,
//!   before any output exists, for quota and MTU consumers.
//!
//! Both dialect builders ship the same faces. To edit existing
//! bytes rather than author fresh ones → `patch` or `session`
//! (each behind its feature); a finished construct's bytes are
//! exactly what their `set_payload`/`insert_payload` take.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "construct-groupless")] {
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::construct::groupless::Builder;
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let f2 = FieldNumber::new(2).unwrap();
//! let mut builder = Builder::new();
//! builder.push_varint(f1, 150);
//! builder.message(f2, |m| {
//!     m.push_string(f1, "hi");
//! });
//! assert!(builder.poisoned().is_none());
//!
//! // Append into an existing buffer: one up-front reservation.
//! let mut out = vec![0xAA];
//! builder.finish_into(&mut out).unwrap();
//! assert_eq!(out, [0xAA, 0x08, 0x96, 0x01, 0x12, 0x04, 0x0A, 0x02, 0x68, 0x69]);
//! # }
//! ```
#![cfg_attr(
    feature = "construct-groupless",
    doc = "
A borrowed payload must outlive the builder — the type refuses
an owner that dies before the finish (the `_copy` twins are the
escape hatch for that case):

```compile_fail,E0505
use protobuf_edit::FieldNumber;
use protobuf_edit::construct::groupless::Builder;

let f1 = FieldNumber::new(1).unwrap();
let mut builder = Builder::new();
let payload = vec![0xAB; 4];
builder.push_len(f1, &payload);
drop(payload); // the builder still holds the borrow
let bytes = builder.finish().unwrap();
```"
)]
//!
//! # Recipes
//!
//! Pre-encoded bytes splice in as payloads: `push_len` authors the
//! Opaque form over a message some other machine already
//! serialized (an editor's save, another builder's finish) — and
//! it agrees with the Commit form (the `message` closure) whenever
//! the payload is one lawful message:
//!
//! ```
//! # #[cfg(feature = "construct-groupless")] {
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::construct::groupless::Builder;
//!
//! let f1 = FieldNumber::new(1).unwrap();
//! let f2 = FieldNumber::new(2).unwrap();
//!
//! // A message serialized elsewhere.
//! let mut inner = Builder::new();
//! inner.push_varint(f1, 150);
//! let encoded = inner.finish().unwrap();
//!
//! // Splice it in whole, uninterpreted…
//! let mut outer = Builder::new();
//! outer.push_len(f2, &encoded);
//!
//! // …and the closure form authors the same bytes.
//! let mut twin = Builder::new();
//! twin.message(f2, |m| m.push_varint(f1, 150));
//! assert_eq!(outer.finish().unwrap(), twin.finish().unwrap());
//! # }
//! ```
//!
//! Frames nest by closure scope alone — `message` within `message`,
//! and the grouped builder's `group` mixes freely with both (its
//! nesting examples sit on that face); output-buffer reuse is
//! `finish_into`'s single up-front reservation, shown above.

use alloc::vec::Vec;
use core::fmt;

use crate::varint::{Minimal64, WordWidth, encoded_len64, push64, write32_at};
use crate::wire::{FieldNumber, PayloadLen};

/// The construction cap: one message stays inside the LEN length
/// class (`i32::MAX` bytes). Policy, not format law — the wire
/// grammar puts no bound on a top-level stream, but a serialized
/// message under 2 GiB is the maximum every protobuf implementation
/// supports
/// (<https://protobuf.dev/programming-guides/proto-limits/>), and
/// [`PayloadLen`] must be able to prefix the result if it is ever
/// embedded.
#[allow(
    clippy::as_conversions,
    reason = "widening the proven length-class ceiling; const `From` is unavailable"
)]
const CAP: u64 = PayloadLen::MAX.as_inner() as u64;

/// A byte count leaving the `usize` domain.
#[inline]
#[allow(
    clippy::as_conversions,
    reason = "usize is at most 64 bits on the crate's 32/64-bit targets"
)]
const fn len_u64(len: usize) -> u64 {
    len as u64
}

/// A byte count the account has admitted, narrowed to the run
/// domain.
#[inline]
#[allow(clippy::as_conversions, reason = "the account admitted the amount under the 2^31 - 1 cap")]
const fn run32(admitted: u64) -> u32 {
    debug_assert!(admitted <= CAP);
    admitted as u32
}

/// The one structured data error: the message under construction
/// crossed the cap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OverCap {
    field: Option<FieldNumber>,
    len: u64,
}

impl OverCap {
    /// The innermost open frame's field at the break (`None` when
    /// the break landed at the top level).
    #[inline]
    #[must_use]
    pub const fn field(self) -> Option<FieldNumber> {
        self.field
    }

    /// The attempted total, in bytes — the first sum past the cap.
    #[inline]
    #[must_use]
    #[allow(
        clippy::len_without_is_empty,
        reason = "a break report's byte count, not a container length"
    )]
    pub const fn len(self) -> u64 {
        self.len
    }
}

impl fmt::Display for OverCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "construction reached {} bytes, past the {CAP}-byte cap", self.len)?;
        if let Some(field) = self.field {
            write!(f, " (inside field {})", field.as_inner())?;
        }
        Ok(())
    }
}

impl core::error::Error for OverCap {}

const _: () = assert!(core::mem::size_of::<OverCap>() == 16);

/// A borrow-table coordinate: minted by
/// [`Core::push_borrow`], read judgment-free at emission — the
/// table never shrinks. Every registered slice is non-empty and
/// accounted, so fewer than 2^31 entries exist under the cap.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct BorrowAt(u32);

impl BorrowAt {
    /// The table index this coordinate names.
    const fn index(self) -> usize {
        crate::admission::usize_of(self.0)
    }
}

/// One step of the mixed machine's replay program.
#[derive(Clone, Copy)]
enum Event {
    /// Copy the next `n` bytes of the owned staging store.
    Owned(u32),
    /// Copy one registered borrowed slice — the payload's single
    /// copy, straight from the caller's memory to the output.
    Borrowed(BorrowAt),
    /// Emit a LEN prefix: `body` at exactly `width` bytes — the
    /// minimal width minted from the body at the close patch
    /// ([`WordWidth::minimal_of`]), stored so emission never
    /// recomputes it.
    Len { body: PayloadLen, width: WordWidth },
}

/// [`Event`]'s copy-only declension: the copy machine registers no
/// borrows, so its replay core carries no borrowed arm — every
/// payload byte is an owned-run literal.
#[derive(Clone, Copy)]
enum CopyEvent {
    /// Copy the next `n` bytes of the owned staging store.
    Owned(u32),
    /// Emit a LEN prefix: `body` at exactly `width` bytes — the
    /// minimal width minted from the body at the close patch
    /// ([`WordWidth::minimal_of`]), stored so emission never
    /// recomputes it.
    Len { body: PayloadLen, width: WordWidth },
}

/// An open frame. `head` serves the break report ([`OverCap::field`]
/// quotes the innermost frame); `begin` and `start_total` are the
/// LEN patch coordinates — `begin` is meaningful only on a program
/// that was healthy when the frame opened.
#[derive(Clone, Copy)]
struct Frame {
    head: u32,
    begin: u32,
    start_total: u64,
}

const _: () = assert!(core::mem::size_of::<Event>() == 8);
const _: () = assert!(core::mem::size_of::<CopyEvent>() == 8);
const _: () = assert!(core::mem::size_of::<Frame>() == 16);

/// The shared construction machine: an account, an owned staging
/// store, a borrow table, and a replay program.
///
/// Invariant (the emission's safety root): every successful
/// [`account`](Self::account) of `n` bytes is matched by exactly
/// `n` bytes entering the program — literal bytes appended to
/// `owned` under an [`Event::Owned`] run, a caller slice
/// registered in `borrows` under an [`Event::Borrowed`], or a LEN
/// prefix width recorded in its patched [`Event::Len`]. On a
/// healthy (never poisoned) program, therefore, `total = Σ
/// owned-run lengths + Σ borrowed slice lengths + Σ LEN prefix
/// widths` and `owned.len() = Σ owned-run lengths`: one
/// `total`-sized reservation covers the whole replay, and the
/// owned cursor never leaves `owned`. Every registered borrow is
/// non-empty (empty payloads take the framing-only path), so
/// `borrows.len() ≤ total ≤` the cap keeps borrow indexes under
/// 2^31.
struct Core<'p> {
    owned: Vec<u8>,
    borrows: Vec<&'p [u8]>,
    events: Vec<Event>,
    stack: Vec<Frame>,
    total: u64,
    over: Option<OverCap>,
}

/// [`Core`]'s copy-only declension: no borrow table exists, so no
/// payload lifetime binds the caller and the machine is one `Vec`
/// lighter — every payload byte lands in the owned staging store
/// at its push.
///
/// Invariant (the emission's safety root, [`Core`]'s with the
/// borrow term gone): every successful [`account`](Self::account)
/// of `n` bytes is matched by exactly `n` bytes entering the
/// program — literal bytes appended to `owned` under a
/// [`CopyEvent::Owned`] run, or a LEN prefix width recorded in its
/// patched [`CopyEvent::Len`]. On a healthy program, therefore,
/// `total = Σ owned-run lengths + Σ LEN prefix widths` and
/// `owned.len() = Σ owned-run lengths`: one `total`-sized
/// reservation covers the whole replay, and the owned cursor never
/// leaves `owned`. Every event costs at least one accounted byte,
/// so event indexes stay under 2^31.
struct CopyCore {
    owned: Vec<u8>,
    events: Vec<CopyEvent>,
    stack: Vec<Frame>,
    total: u64,
    over: Option<OverCap>,
}

// The declension's saving, pinned at the core on every pointer
// width: the copy machine drops the borrow table whole (one `Vec`
// — 24 bytes on 64-bit pointers; on 32-bit the reordered fields
// absorb part of it and the saving is eight).
const _: () = {
    let w64 = cfg!(target_pointer_width = "64");
    assert!(
        core::mem::size_of::<CopyCore>() + if w64 { 24 } else { 8 }
            == core::mem::size_of::<Core<'_>>()
    );
};

impl<'p> Core<'p> {
    /// Payloads shorter than this stage into `owned` instead of
    /// registering a borrow. A registered borrow costs a table
    /// entry (16 bytes, first one allocates the table), an event,
    /// and an emission run split; staging costs one extra copy of
    /// the payload bytes. Under a cache line the copy is strictly
    /// cheaper (probe-measured on the small-nested shape: the
    /// borrow path's table alloc/free pair alone outweighs a
    /// 13-byte copy).
    const BORROW_MIN: usize = 64;

    const fn new() -> Self {
        Self {
            owned: Vec::new(),
            borrows: Vec::new(),
            events: Vec::new(),
            stack: Vec::new(),
            total: 0,
            over: None,
        }
    }

    /// Registers a non-empty borrowed slice as one event. Callers
    /// charge first (a poisoned program never reaches here) and
    /// exclude empty slices — every event costs at least one
    /// accounted byte, which the index mints rely on.
    fn push_borrow(&mut self, payload: &'p [u8]) {
        debug_assert!(!payload.is_empty(), "empty payloads take the framing-only path");
        #[allow(
            clippy::as_conversions,
            reason = "borrow indexes stay under the 2^31 - 1 cap (one accounted byte \
                      minimum per registered slice)"
        )]
        let at = BorrowAt(self.borrows.len() as u32);
        self.borrows.push(payload);
        self.events.push(Event::Borrowed(at));
    }

    // ─── records (the borrow doors; the shared records live in
    // `construct_core!`) ───

    /// One complete LEN record over a borrowed payload: head and
    /// minimal prefix land as owned literals; a payload of
    /// [`BORROW_MIN`](Self::BORROW_MIN) bytes or more registers as
    /// a borrow and is copied once, at emission, while a shorter
    /// one stages immediately (one extra sub-cache-line copy,
    /// strictly cheaper than borrow bookkeeping). An empty payload
    /// is framing only — no table entry, no borrow event — so
    /// every event costs at least one accounted byte.
    fn put_len(&mut self, head: u32, payload: &'p [u8]) {
        let head = Minimal64::of(u64::from(head));
        let len = len_u64(payload.len());
        let prefix = Minimal64::of(len);
        if !self.account(u64::from(head.width()) + u64::from(prefix.width()) + len) {
            return;
        }
        self.push_run(head.width() + prefix.width());
        head.append_to(&mut self.owned);
        prefix.append_to(&mut self.owned);
        if payload.len() >= Self::BORROW_MIN {
            self.push_borrow(payload);
        } else if !payload.is_empty() {
            #[allow(
                clippy::as_conversions,
                reason = "elided payloads are under BORROW_MIN (64), well inside u32"
            )]
            self.push_run(payload.len() as u32);
            self.owned.extend_from_slice(payload);
        }
    }

    /// Appends caller-final bytes — a run of
    /// [`BORROW_MIN`](Self::BORROW_MIN) or more registers as a
    /// borrow (copied once, at emission), a shorter one stages
    /// immediately. Empty appends are no-ops: every event must
    /// cost at least one accounted byte (the index mints rely on
    /// it).
    fn put_raw_bytes(&mut self, bytes: &'p [u8]) {
        if bytes.is_empty() {
            return;
        }
        if self.account(len_u64(bytes.len())) {
            if bytes.len() >= Self::BORROW_MIN {
                self.push_borrow(bytes);
            } else {
                #[allow(
                    clippy::as_conversions,
                    reason = "elided appends are under BORROW_MIN (64), well inside u32"
                )]
                self.push_run(bytes.len() as u32);
                self.owned.extend_from_slice(bytes);
            }
        }
    }

    // ─── emission ───

    /// Replays the program into `out`: one reservation of the
    /// accounted total, then direct writes into the spare capacity
    /// and a single length commit. `out` is untouched on refusal.
    #[allow(
        clippy::as_conversions,
        reason = "runs, widths, and the total are accounted under the 2^31 - 1 cap \
                  and fit usize on the crate's 32/64-bit targets"
    )]
    #[track_caller]
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), OverCap> {
        if let Some(over) = self.over {
            return Err(over);
        }
        // Every frame must have closed. A non-empty stack means a
        // frame body unwound between its open and close (a panicking
        // closure caught with `catch_unwind`): the account and the
        // event/staging stream are then out of pairing, so the
        // emission invariant below does not hold. Refuse by panic
        // rather than trust it — a caught body panic can reach here
        // through entirely safe code, and the alternative is a
        // `set_len` over uninitialized spare. Release build too: the
        // unsafe write is downstream.
        assert!(
            self.stack.is_empty(),
            "construction abandoned mid-frame (a message/group body unwound)"
        );
        let total = self.total as usize;
        out.reserve(total);
        // SAFETY: the reservation guarantees `total` spare bytes,
        // and the type invariant (account ⇔ write pairing, see
        // [`Core`]) proves the events sum to exactly `total` with
        // owned runs summing to `owned.len()` — every read stays
        // inside `owned` or one registered borrow, every write
        // inside the reservation, and the final length is fully
        // initialized. Borrow indexes were minted by `push_borrow`
        // over a table that never shrinks, and `'p` outlives
        // `self`, so every registered slice is live. Source and
        // destination cannot overlap: the borrows hold their
        // owners shared for `'p` while `out` is exclusively
        // borrowed here, and `owned` is a disjoint allocation.
        // Each stored `Len` pair is coherent: the close patch
        // mints `width` from `body` itself
        // (`WordWidth::minimal_of`), and the placeholder pair —
        // `PayloadLen::MIN` with `WordWidth::MIN` — is value zero
        // at its own one-byte width, so every prefix write lands
        // exactly its value's encoded width.
        unsafe {
            let mut dst = out.as_mut_ptr().add(out.len());
            let mut cursor = 0usize;
            for event in &self.events {
                match *event {
                    Event::Owned(run) => {
                        let run = run as usize;
                        core::ptr::copy_nonoverlapping(self.owned.as_ptr().add(cursor), dst, run);
                        cursor += run;
                        dst = dst.add(run);
                    }
                    Event::Borrowed(at) => {
                        let slice = *self.borrows.get_unchecked(at.index());
                        core::ptr::copy_nonoverlapping(slice.as_ptr(), dst, slice.len());
                        dst = dst.add(slice.len());
                    }
                    Event::Len { body, width } => {
                        let width = u32::from(width.as_inner());
                        write32_at(dst, body.as_inner(), width);
                        dst = dst.add(width as usize);
                    }
                }
            }
            debug_assert!(cursor == self.owned.len(), "owned runs sum to the store");
            out.set_len(out.len() + total);
        }
        Ok(())
    }

    /// Replays the program into `sink`, slice by slice: owned runs
    /// and registered borrows are handed out verbatim, LEN
    /// prefixes through a five-byte stack window. Every slice is
    /// non-empty (each event costs at least one accounted byte),
    /// and the refusal check runs first — a refused job hands the
    /// sink nothing.
    #[track_caller]
    fn emit_sink(&self, sink: &mut impl FnMut(&[u8])) -> Result<(), OverCap> {
        if let Some(over) = self.over {
            return Err(over);
        }
        // The same pairing judgment as `emit_into`: an unwound
        // frame body left the account and the program out of step,
        // so nothing may be published.
        assert!(
            self.stack.is_empty(),
            "construction abandoned mid-frame (a message/group body unwound)"
        );
        let mut cursor = 0usize;
        for event in &self.events {
            match *event {
                Event::Owned(run) => {
                    let run = crate::admission::usize_of(run);
                    // SAFETY: the type invariant (account ⇔ write
                    // pairing, see [`Core`]) proves the owned runs
                    // of a healthy program sum to `owned.len()`,
                    // so every run window lies inside the store.
                    sink(unsafe { self.owned.get_unchecked(cursor..cursor + run) });
                    cursor += run;
                }
                Event::Borrowed(at) => {
                    // SAFETY: `at` was minted by `push_borrow`
                    // over a table that never shrinks.
                    sink(unsafe { self.borrows.get_unchecked(at.index()) });
                }
                Event::Len { body, width } => {
                    let width = u32::from(width.as_inner());
                    let mut prefix = [0u8; 5];
                    // SAFETY: the stack window holds five writable
                    // bytes, and the stored `WordWidth` — at most
                    // five by its range — was minted from the body
                    // at the close patch: the body's own encoded
                    // width.
                    unsafe { write32_at(prefix.as_mut_ptr(), body.as_inner(), width) };
                    sink(&prefix[..crate::admission::usize_of(width)]);
                }
            }
        }
        debug_assert!(cursor == self.owned.len(), "owned runs sum to the store");
        Ok(())
    }
}

impl CopyCore {
    const fn new() -> Self {
        Self { owned: Vec::new(), events: Vec::new(), stack: Vec::new(), total: 0, over: None }
    }

    // ─── emission (no borrowed arm: the event declension) ───

    /// Replays the program into `out`: one reservation of the
    /// accounted total, then direct writes into the spare capacity
    /// and a single length commit. `out` is untouched on refusal.
    #[allow(
        clippy::as_conversions,
        reason = "runs, widths, and the total are accounted under the 2^31 - 1 cap \
                  and fit usize on the crate's 32/64-bit targets"
    )]
    #[track_caller]
    fn emit_into(&self, out: &mut Vec<u8>) -> Result<(), OverCap> {
        if let Some(over) = self.over {
            return Err(over);
        }
        // Every frame must have closed. A non-empty stack means a
        // frame body unwound between its open and close (a panicking
        // closure caught with `catch_unwind`): the account and the
        // event/staging stream are then out of pairing, so the
        // emission invariant below does not hold. Refuse by panic
        // rather than trust it — a caught body panic can reach here
        // through entirely safe code, and the alternative is a
        // `set_len` over uninitialized spare. Release build too: the
        // unsafe write is downstream.
        assert!(
            self.stack.is_empty(),
            "construction abandoned mid-frame (a message/group body unwound)"
        );
        let total = self.total as usize;
        out.reserve(total);
        // SAFETY: the reservation guarantees `total` spare bytes,
        // and the type invariant (account ⇔ write pairing, see
        // [`CopyCore`]) proves the events sum to exactly `total`
        // with owned runs summing to `owned.len()` — every read
        // stays inside `owned`, every write inside the reservation,
        // and the final length is fully initialized. Source and
        // destination cannot overlap: `owned` and `out` are
        // disjoint allocations. Each stored `Len` pair is
        // coherent: the close patch mints `width` from `body`
        // itself (`WordWidth::minimal_of`), and the placeholder
        // pair — `PayloadLen::MIN` with `WordWidth::MIN` — is
        // value zero at its own one-byte width, so every prefix
        // write lands exactly its value's encoded width.
        unsafe {
            let mut dst = out.as_mut_ptr().add(out.len());
            let mut cursor = 0usize;
            for event in &self.events {
                match *event {
                    CopyEvent::Owned(run) => {
                        let run = run as usize;
                        core::ptr::copy_nonoverlapping(self.owned.as_ptr().add(cursor), dst, run);
                        cursor += run;
                        dst = dst.add(run);
                    }
                    CopyEvent::Len { body, width } => {
                        let width = u32::from(width.as_inner());
                        write32_at(dst, body.as_inner(), width);
                        dst = dst.add(width as usize);
                    }
                }
            }
            debug_assert!(cursor == self.owned.len(), "owned runs sum to the store");
            out.set_len(out.len() + total);
        }
        Ok(())
    }

    /// Replays the program into `sink`, slice by slice: owned runs
    /// are handed out verbatim, LEN prefixes through a five-byte
    /// stack window. Every slice is non-empty (each event costs at
    /// least one accounted byte), and the refusal check runs first
    /// — a refused job hands the sink nothing.
    #[track_caller]
    fn emit_sink(&self, sink: &mut impl FnMut(&[u8])) -> Result<(), OverCap> {
        if let Some(over) = self.over {
            return Err(over);
        }
        // The same pairing judgment as `emit_into`: an unwound
        // frame body left the account and the program out of step,
        // so nothing may be published.
        assert!(
            self.stack.is_empty(),
            "construction abandoned mid-frame (a message/group body unwound)"
        );
        let mut cursor = 0usize;
        for event in &self.events {
            match *event {
                CopyEvent::Owned(run) => {
                    let run = crate::admission::usize_of(run);
                    // SAFETY: the type invariant (account ⇔ write
                    // pairing, see [`CopyCore`]) proves the owned
                    // runs of a healthy program sum to
                    // `owned.len()`, so every run window lies
                    // inside the store.
                    sink(unsafe { self.owned.get_unchecked(cursor..cursor + run) });
                    cursor += run;
                }
                CopyEvent::Len { body, width } => {
                    let width = u32::from(width.as_inner());
                    let mut prefix = [0u8; 5];
                    // SAFETY: the stack window holds five writable
                    // bytes, and the stored `WordWidth` — at most
                    // five by its range — was minted from the body
                    // at the close patch: the body's own encoded
                    // width.
                    unsafe { write32_at(prefix.as_mut_ptr(), body.as_inner(), width) };
                    sink(&prefix[..crate::admission::usize_of(width)]);
                }
            }
        }
        debug_assert!(cursor == self.owned.len(), "owned runs sum to the store");
        Ok(())
    }
}

/// Emits one construction core's shared machinery — the account,
/// the owned-run program, the record and frame arithmetic — inside
/// an `impl` of the named core over the named event type. The two
/// cores share every stretch here byte-for-byte; what stays
/// outside are each core's own fields (`new`), the mixed machine's
/// borrow doors, and the replay cores, whose event declension the
/// borrowed arm's presence is.
macro_rules! construct_core {
    (@machinery $Core:ident $(<$p:lifetime>)?, $Event:ident) => {
        impl$(<$p>)? $Core$(<$p>)? {
            /// Seeds the owned staging store and derives an event
            /// reservation: events are born at frame boundaries (two per
            /// message), not per push, so a sixteenth of the byte estimate
            /// covers typical densities (div 32 re-reserves mid-size
            /// builds +12%; div 8 lands in layout noise).
            fn with_capacity(bytes: usize) -> Self {
                let mut core = Self::new();
                if bytes > 0 {
                    core.owned.reserve(bytes);
                    // Floor 8: a small nested build (one message
                    // frame + a handful of records) crosses 4
                    // events, and the 4→8 regrow was a measured
                    // realloc on the hot small-build path.
                    core.events.reserve((bytes / 16).clamp(8, 1024));
                }
                core
            }

            const fn poisoned(&self) -> Option<OverCap> {
                self.over
            }

            /// The account's verdict: the running total on a healthy
            /// program, the recorded break on a poisoned one. The total is
            /// exact only over closed frames — the price of any still-open
            /// frame's prefix joins at its close — so the callers behind
            /// the public face assert frame pairing first.
            const fn planned(&self) -> Result<u64, OverCap> {
                match self.over {
                    Some(over) => Err(over),
                    None => Ok(self.total),
                }
            }

            /// Charges `bytes` against the cap. `false` means the bytes
            /// must not move: either the program was already poisoned, or
            /// this very charge crossed the cap and poisoned it. The total
            /// freezes at the first break, so later frame arithmetic stays
            /// in domain while the balance axis keeps running.
            fn account(&mut self, bytes: u64) -> bool {
                if self.over.is_some() {
                    return false;
                }
                // No overflow: `total ≤ CAP` and any single charge is
                // bounded by a live allocation's size plus framing bytes.
                let attempted = self.total + bytes;
                if attempted > CAP {
                    self.poison_over_cap(attempted);
                    return false;
                }
                self.total = attempted;
                true
            }

            /// Freezes the program and records the break: the attempted
            /// total, quoted with the innermost open frame's field.
            #[cold]
            fn poison_over_cap(&mut self, len: u64) {
                let field = self.stack.last().and_then(|frame| FieldNumber::from_word(frame.head));
                self.over = Some(OverCap { field, len });
            }

            #[cfg(test)]
            fn force_poison_for_test(&mut self) {
                self.poison_over_cap(self.total + 1);
            }

            /// Extends the current owned run by `bytes`; a new event only
            /// where a LEN prefix (or, on the mixed machine, a borrowed
            /// slice) split the run, so the program is O(frames + borrowed
            /// pushes), not O(pushes). Callers pass amounts the account
            /// just admitted — run totals stay under the cap and cannot
            /// overflow.
            fn push_run(&mut self, bytes: u32) {
                if let Some($Event::Owned(run)) = self.events.last_mut() {
                    *run += bytes;
                    return;
                }
                self.events.push($Event::Owned(bytes));
            }

            // ─── records ───

            /// One varint record: head, then value. Both pairs are
            /// minted once and spent on the charge and the write alike.
            fn put_varint(&mut self, head: u32, value: u64) {
                let head = Minimal64::of(u64::from(head));
                let value = Minimal64::of(value);
                if !self.account(u64::from(head.width() + value.width())) {
                    return;
                }
                self.push_run(head.width() + value.width());
                head.append_to(&mut self.owned);
                value.append_to(&mut self.owned);
            }

            /// One fixed 32-bit record: head, then four little-endian
            /// bytes.
            fn put_i32(&mut self, head: u32, bits: u32) {
                let head = Minimal64::of(u64::from(head));
                if !self.account(u64::from(head.width()) + 4) {
                    return;
                }
                self.push_run(head.width() + 4);
                head.append_to(&mut self.owned);
                self.owned.extend_from_slice(&bits.to_le_bytes());
            }

            /// One fixed 64-bit record: head, then eight little-endian
            /// bytes.
            fn put_i64(&mut self, head: u32, bits: u64) {
                let head = Minimal64::of(u64::from(head));
                if !self.account(u64::from(head.width()) + 8) {
                    return;
                }
                self.push_run(head.width() + 8);
                head.append_to(&mut self.owned);
                self.owned.extend_from_slice(&bits.to_le_bytes());
            }

            /// One staged LEN record: head, minimal prefix, and payload
            /// all land as owned literals — the mixed machine's `_copy`
            /// twin and the copy machine's only LEN door.
            fn put_len_copy(&mut self, head: u32, payload: &[u8]) {
                let head = Minimal64::of(u64::from(head));
                let len = len_u64(payload.len());
                let prefix = Minimal64::of(len);
                if !self.account(u64::from(head.width()) + u64::from(prefix.width()) + len) {
                    return;
                }
                self.push_run(head.width() + prefix.width() + run32(len));
                head.append_to(&mut self.owned);
                prefix.append_to(&mut self.owned);
                self.owned.extend_from_slice(payload);
            }

            // ─── raw words (frame interiors) ───

            fn put_raw_varint(&mut self, value: u64) {
                let value = Minimal64::of(value);
                if self.account(u64::from(value.width())) {
                    self.push_run(value.width());
                    value.append_to(&mut self.owned);
                }
            }

            fn put_raw_i32(&mut self, bits: u32) {
                if self.account(4) {
                    self.push_run(4);
                    self.owned.extend_from_slice(&bits.to_le_bytes());
                }
            }

            fn put_raw_i64(&mut self, bits: u64) {
                if self.account(8) {
                    self.push_run(8);
                    self.owned.extend_from_slice(&bits.to_le_bytes());
                }
            }

            /// Appends caller bytes as owned literals at the push — the
            /// mixed machine's `_copy` twin and the copy machine's only
            /// raw-bytes door. Empty appends are no-ops.
            fn put_raw_bytes_copy(&mut self, bytes: &[u8]) {
                if bytes.is_empty() {
                    return;
                }
                let len = len_u64(bytes.len());
                if self.account(len) {
                    self.push_run(run32(len));
                    self.owned.extend_from_slice(bytes);
                }
            }

            // ─── packed families ───

            /// One packed LEN record of varint elements. A slice input
            /// walks twice by necessity — the prefix wants the body length
            /// before any element byte lands. The second walk re-derives
            /// each element's width inside `push64`: a handful of register
            /// ops per element, cheaper than materializing a per-element
            /// width cache (the builder's only buffer stays the fragments).
            fn put_packed_varints<T: Copy>(&mut self, head: u32, items: &[T], word: impl Fn(T) -> u64) {
                let count = len_u64(items.len());
                if count > CAP {
                    // Each element emits at least one byte, so the count
                    // alone breaks the cap — refused before the sum walk,
                    // which the bound also keeps overflow-free.
                    self.account(count);
                    return;
                }
                let head = Minimal64::of(u64::from(head));
                let mut body = 0u64;
                for &item in items {
                    body += u64::from(encoded_len64(word(item)));
                }
                let prefix = Minimal64::of(body);
                if !self.account(u64::from(head.width()) + u64::from(prefix.width()) + body) {
                    return;
                }
                self.push_run(head.width() + prefix.width() + run32(body));
                head.append_to(&mut self.owned);
                prefix.append_to(&mut self.owned);
                for &item in items {
                    push64(&mut self.owned, word(item));
                }
            }

            /// One packed LEN record of four-byte elements.
            fn put_packed_fixed32<T: Copy>(&mut self, head: u32, items: &[T], bits: impl Fn(T) -> u32) {
                let head = Minimal64::of(u64::from(head));
                let body = 4 * len_u64(items.len());
                let prefix = Minimal64::of(body);
                if !self.account(u64::from(head.width()) + u64::from(prefix.width()) + body) {
                    return;
                }
                self.push_run(head.width() + prefix.width() + run32(body));
                head.append_to(&mut self.owned);
                prefix.append_to(&mut self.owned);
                self.owned.reserve(items.len() * 4);
                for &item in items {
                    self.owned.extend_from_slice(&bits(item).to_le_bytes());
                }
            }

            /// One packed LEN record of eight-byte elements.
            fn put_packed_fixed64<T: Copy>(&mut self, head: u32, items: &[T], bits: impl Fn(T) -> u64) {
                let head = Minimal64::of(u64::from(head));
                let body = 8 * len_u64(items.len());
                let prefix = Minimal64::of(body);
                if !self.account(u64::from(head.width()) + u64::from(prefix.width()) + body) {
                    return;
                }
                self.push_run(head.width() + prefix.width() + run32(body));
                head.append_to(&mut self.owned);
                prefix.append_to(&mut self.owned);
                self.owned.reserve(items.len() * 8);
                for &item in items {
                    self.owned.extend_from_slice(&bits(item).to_le_bytes());
                }
            }

            // ─── frames ───

            /// Runs `body` inside a LEN frame of `head`: the paired
            /// [`begin_len`](Self::begin_len)/[`end_len`](Self::end_len)
            /// live only here, so frame balance is a property of the call
            /// shape, not of caller discipline.
            fn len_frame(&mut self, head: u32, body: impl FnOnce(&mut Self)) {
                self.begin_len(head);
                body(self);
                self.end_len();
            }

            /// Opens a LEN frame: the head lands now, the prefix's slot is
            /// held by a placeholder event that [`end_len`](Self::end_len)
            /// patches. The frame pushes even on a poisoned program — the
            /// balance axis keeps running so a well-paired caller is never
            /// mis-judged — but no bytes or events move there, and `begin`
            /// is then never read (poison is sticky).
            fn begin_len(&mut self, head: u32) {
                let head_word = Minimal64::of(u64::from(head));
                let begin = if self.account(u64::from(head_word.width())) {
                    self.push_run(head_word.width());
                    head_word.append_to(&mut self.owned);
                    // Mint the placeholder's index after the run split
                    // settles. It fits: every event costs at least one
                    // accounted byte, so event indexes stay under the cap.
                    #[allow(
                        clippy::as_conversions,
                        reason = "event indexes stay under the 2^31 - 1 cap (one accounted byte minimum per event)"
                    )]
                    let begin = self.events.len() as u32;
                    self.events.push($Event::Len { body: PayloadLen::MIN, width: WordWidth::MIN });
                    begin
                } else {
                    0
                };
                self.stack.push(Frame { head, begin, start_total: self.total });
            }

            /// Closes the innermost LEN frame: the body length is the
            /// account's growth since the open, and the prefix width it
            /// implies is charged here and stored for the replay.
            fn end_len(&mut self) {
                // SAFETY: `end_len` runs only as the closing half of
                // `len_frame`, whose `begin_len` pushed one frame, and every
                // face a frame body can reach pops exactly what it pushes —
                // the frame is still on top.
                let frame = unsafe { *self.stack.last().unwrap_unchecked() };
                if self.over.is_none() {
                    // Monotonic account: `start_total` was read from
                    // `total`, which never decreases.
                    let body = self.total - frame.start_total;
                    let width = encoded_len64(body);
                    // A prefix that itself crosses the cap poisons here —
                    // with this frame still on the stack, so the break
                    // quotes its field. The patch below stays in domain
                    // either way, and a poisoned program never emits.
                    self.account(u64::from(width));
                    #[allow(
                        clippy::as_conversions,
                        reason = "minted event indexes fit usize on the crate's 32/64-bit targets"
                    )]
                    // SAFETY: poison is sticky, so a healthy program here
                    // was healthy at `begin_len`, which minted `begin` and
                    // pushed the placeholder it points at; events never
                    // shrink.
                    let slot = unsafe { self.events.get_unchecked_mut(frame.begin as usize) };
                    // SAFETY: `body ≤ total ≤ CAP`, the length-class
                    // ceiling `PayloadLen` admits.
                    let body = unsafe { PayloadLen::new_unchecked(run32(body)) };
                    // The account charged the u64-domain width above;
                    // the slot's typed width re-derives from the
                    // narrowed body (~3 ops) — the mint is the
                    // minimality proof.
                    *slot = $Event::Len { body, width: WordWidth::minimal_of(body.as_inner()) };
                }
                self.stack.pop();
            }

            /// Runs `body` inside a group frame: open tag now, matching end
            /// tag on return, no length prefix — the whole framing is
            /// literal bytes. The frame entry serves the break report; the
            /// balance axis runs even poisoned.
            #[cfg(feature = "construct-grouped")]
            fn group_frame(&mut self, open: u32, end: u32, body: impl FnOnce(&mut Self)) {
                let open_word = Minimal64::of(u64::from(open));
                let end_word = Minimal64::of(u64::from(end));
                // Open and end tags differ only in the low three bits, and
                // an eight-aligned window never straddles a seven-bit width
                // step — the pair shares one width, charged together.
                debug_assert!(end_word.width() == open_word.width());
                if self.account(2 * u64::from(open_word.width())) {
                    self.push_run(open_word.width());
                    open_word.append_to(&mut self.owned);
                }
                self.stack.push(Frame { head: open, begin: 0, start_total: self.total });
                body(self);
                self.stack.pop();
                // The end word was charged with the open; it lands only on
                // a healthy program (a poisoned one never emits).
                if self.over.is_none() {
                    self.push_run(end_word.width());
                    end_word.append_to(&mut self.owned);
                }
            }
        }
    };
}

construct_core!(@machinery Core<'p>, Event);
construct_core!(@machinery CopyCore, CopyEvent);

/// One open chunked LEN frame: byte chunks land in call order and
/// close as a single LEN record.
///
/// Lent to the closure of the dialect builders' `bytes_frame`. The
/// chunks concatenate into the record's payload behind an exact
/// minimal prefix (patched at frame close, as for `message`); an
/// untouched frame closes as an empty LEN record — lawful wire.
/// The payload's interior meaning is the caller's declaration,
/// never interpreted, exactly as for `push_len`.
pub struct Bytes<'a, 'p> {
    core: &'a mut Core<'p>,
}

impl<'p> Bytes<'_, 'p> {
    /// Appends `chunk` by copying it into the owned staging store
    /// at the call — the honest price of a source that cannot
    /// outlive the builder: once into the store, once at emission.
    /// An empty chunk is a no-op.
    #[inline]
    pub fn write(&mut self, chunk: &[u8]) {
        self.core.put_raw_bytes_copy(chunk);
    }

    /// Appends `chunk` as a borrow held until the finish, where
    /// its single copy lands in the output — the one-copy path of
    /// `push_len` and `raw_bytes`, per chunk. Mixes freely with
    /// [`write`](Self::write): addressable chunks stay single-copy
    /// while transient ones pay the staging price. An empty chunk
    /// is a no-op.
    #[inline]
    pub fn write_borrowed(&mut self, chunk: &'p [u8]) {
        self.core.put_raw_bytes(chunk);
    }
}

/// [`Bytes`]'s copy-only declension: one open chunked LEN frame on
/// the copy machine, whose every chunk copies into the staging
/// store at the call — the machine's one supply, so no borrow door
/// exists here.
///
/// Lent to the closure of the copy builders' `bytes_frame`. The
/// chunks concatenate into the record's payload behind an exact
/// minimal prefix (patched at frame close, as for `message`); an
/// untouched frame closes as an empty LEN record — lawful wire.
/// The payload's interior meaning is the caller's declaration,
/// never interpreted, exactly as for `push_len`.
pub struct CopyBytes<'a> {
    core: &'a mut CopyCore,
}

impl CopyBytes<'_> {
    /// Appends `chunk` by copying it into the owned staging store
    /// at the call. An empty chunk is a no-op.
    #[inline]
    pub fn write(&mut self, chunk: &[u8]) {
        self.core.put_raw_bytes_copy(chunk);
    }
}

// ─── the dialect faces (templates over one core) ───

/// The root face: construction, the poison query, and the two
/// outputs. Expands inside a dialect module; the declension arm
/// names the machine and its core (whose field is `core`), and
/// spells the two faces whose teaching diverges with the payload
/// backing — everything else lives once in the shared arm.
macro_rules! root_faces {
    (mixed: $Builder:ty, $core:ident) => {
        impl $Builder {
            /// Opens a builder seeded for roughly `bytes` of owned
            /// staging — the store holding encoded words, frame
            /// literals, and `_copy` payloads reserves that much
            /// and the event program a proportionate slice, so a
            /// well-estimated build never regrows either. Borrowed
            /// payloads never enter the store, so a mostly
            /// borrowed build estimates only its framing and
            /// scalar bytes.
            #[inline]
            pub fn with_capacity(bytes: usize) -> Self {
                Self { core: $core::with_capacity(bytes) }
            }

            /// Emits the message by handing the finished bytes to
            /// `sink` as borrowed slices, in output order — no
            /// output buffer exists: owned runs and borrowed
            /// payloads pass through verbatim, LEN prefixes ride a
            /// five-byte stack window. Every slice is non-empty,
            /// and the concatenation is exactly
            /// [`finish`](Self::finish)'s output.
            ///
            /// # Errors
            ///
            /// The recorded [`OverCap`] when any push crossed the
            /// construction cap. The refusal is judged ahead of
            /// the replay, so on `Err` the sink has been handed
            /// nothing — the transactional contract survives the
            /// streaming shape.
            ///
            /// # Panics
            ///
            /// If a message or group body closure unwound (and the
            /// panic was caught): the frame stack is unpaired, so
            /// the builder refuses to emit rather than publish a
            /// half-authored stream.
            #[inline]
            #[track_caller]
            pub fn finish_sink(self, mut sink: impl FnMut(&[u8])) -> Result<(), OverCap> {
                self.core.emit_sink(&mut sink)
            }
        }
        root_faces!(@shared $Builder, $core);
    };
    (copy: $Builder:ty, $core:ident) => {
        impl $Builder {
            /// Opens a builder seeded for roughly `bytes` of owned
            /// staging — the store holding encoded words, frame
            /// literals, and every payload reserves that much and
            /// the event program a proportionate slice, so a
            /// well-estimated build never regrows either. Every
            /// payload copies into the store at its push, so the
            /// estimate is the whole message's bytes.
            #[inline]
            pub fn with_capacity(bytes: usize) -> Self {
                Self { core: $core::with_capacity(bytes) }
            }

            /// Emits the message by handing the finished bytes to
            /// `sink` as borrowed slices, in output order — no
            /// output buffer exists: owned runs pass through
            /// verbatim, LEN prefixes ride a five-byte stack
            /// window. Every slice is non-empty, and the
            /// concatenation is exactly [`finish`](Self::finish)'s
            /// output.
            ///
            /// # Errors
            ///
            /// The recorded [`OverCap`] when any push crossed the
            /// construction cap. The refusal is judged ahead of
            /// the replay, so on `Err` the sink has been handed
            /// nothing — the transactional contract survives the
            /// streaming shape.
            ///
            /// # Panics
            ///
            /// If a message or group body closure unwound (and the
            /// panic was caught): the frame stack is unpaired, so
            /// the builder refuses to emit rather than publish a
            /// half-authored stream.
            #[inline]
            #[track_caller]
            pub fn finish_sink(self, mut sink: impl FnMut(&[u8])) -> Result<(), OverCap> {
                self.core.emit_sink(&mut sink)
            }
        }
        root_faces!(@shared $Builder, $core);
    };
    (@shared $Builder:ty, $core:ident) => {
        impl $Builder {
            /// Opens an empty builder. Nothing allocates until the
            /// first push.
            #[inline]
            pub const fn new() -> Self {
                Self { core: $core::new() }
            }

            /// The cap break, if one has landed: every push after
            /// it is inert, and [`finish`](Self::finish) refuses
            /// with this same value.
            #[inline]
            #[must_use]
            pub const fn poisoned(&self) -> Option<OverCap> {
                self.core.poisoned()
            }

            /// Emits the message: one up-front reservation of the
            /// exact total (amortized — capacity may round above
            /// it, but nothing grows later), then the fragment
            /// runs and patched LEN prefixes replay in order.
            ///
            /// # Errors
            ///
            /// The recorded [`OverCap`] when any push crossed the
            /// construction cap; nothing is allocated or emitted
            /// then.
            ///
            /// # Panics
            ///
            /// If a message or group body closure unwound (and the
            /// panic was caught): the frame stack is unpaired, so
            /// the builder refuses to emit rather than publish a
            /// half-authored buffer.
            #[inline]
            #[track_caller]
            pub fn finish(self) -> Result<Vec<u8>, OverCap> {
                let mut out = Vec::new();
                self.core.emit_into(&mut out)?;
                Ok(out)
            }

            /// Appends the finished message to `out` without
            /// allocating a new output buffer. The emission is
            /// [`finish`](Self::finish)'s; bytes already in `out`
            /// are untouched.
            ///
            /// # Errors
            ///
            /// The recorded [`OverCap`] when any push crossed the
            /// construction cap; the refusal happens before any
            /// write, so `out` is untouched.
            ///
            /// # Panics
            ///
            /// If a message or group body closure unwound (and the
            /// panic was caught): the frame stack is unpaired, so
            /// the builder refuses to emit rather than publish a
            /// half-authored buffer.
            #[inline]
            #[track_caller]
            pub fn finish_into(self, out: &mut Vec<u8>) -> Result<(), OverCap> {
                self.core.emit_into(out)
            }

            /// The exact byte length [`finish`](Self::finish)
            /// would emit, priced from the account the pushes
            /// already carry — no walk, no emission. The
            /// pre-finish question for quota and MTU consumers.
            ///
            /// # Errors
            ///
            /// The recorded [`OverCap`] when any push crossed the
            /// construction cap — a poisoned build prices nothing.
            ///
            /// # Panics
            ///
            /// If a message or group body closure unwound (and the
            /// panic was caught): the account is missing the
            /// unclosed frames' prefixes, so the builder refuses
            /// to price rather than misquote.
            #[inline]
            #[track_caller]
            pub fn planned_len(&self) -> Result<u64, OverCap> {
                if self.core.poisoned().is_none() {
                    assert!(
                        self.core.stack.is_empty(),
                        "construction abandoned mid-frame (a message/group body unwound)"
                    );
                }
                self.core.planned()
            }
        }

        impl Default for $Builder {
            #[inline]
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

/// The typed record faces: the wire-word core, the semantic
/// spellings over it, the packed families, and the LEN frame.
/// Expands inside `impl` blocks whose type holds a core as `core`;
/// `$dialect` names the wire table the heads come from, the
/// declension arm the payload backing — the mixed arm declares the
/// payload-borrow lifetime `$p` and carries the `_copy` twins, the
/// copy arm copies at the push under the unsuffixed names — and
/// `$Body` the frame-interior builder the frame faces lend.
macro_rules! typed_faces {
    (mixed: $dialect:ident, $p:lifetime, $Body:ident) => {
        typed_faces!(@scalars $dialect);

        /// Pushes a LEN record carrying `payload` verbatim, behind
        /// a minimal length prefix. A payload of 64 bytes or more
        /// is borrowed until the finish, where its single copy
        /// lands in the output; a shorter one stages immediately
        /// (the tiny extra copy undercuts borrow bookkeeping, and
        /// the lifetime bound is the same either way). Its
        /// interior is the caller's declaration, never
        /// interpreted.
        #[inline]
        pub fn push_len(&mut self, field: FieldNumber, payload: &$p [u8]) {
            self.core.put_len(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                payload,
            );
        }

        /// [`push_len`](Self::push_len)'s staging twin: copies
        /// `payload` into the builder at the push, for temporaries
        /// that cannot outlive it. The interior stays the caller's
        /// declaration.
        #[inline]
        pub fn push_len_copy(&mut self, field: FieldNumber, payload: &[u8]) {
            self.core.put_len_copy(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                payload,
            );
        }

        /// Pushes a `string`: the `&str` type is the UTF-8 proof.
        /// The value is borrowed until the finish, as
        /// [`push_len`](Self::push_len).
        #[inline]
        pub fn push_string(&mut self, field: FieldNumber, value: &$p str) {
            self.push_len(field, value.as_bytes());
        }

        /// [`push_string`](Self::push_string)'s staging twin:
        /// copies `value` into the builder at the push, for
        /// temporaries that cannot outlive it. The `&str` type
        /// stays the UTF-8 proof.
        #[inline]
        pub fn push_string_copy(&mut self, field: FieldNumber, value: &str) {
            self.push_len_copy(field, value.as_bytes());
        }

        typed_faces!(@packed $dialect);

        /// Frames `body`'s records as a LEN message of `field`: the
        /// frame closes when the closure returns, and the prefix is
        /// the body's exact length. Closure pairing is the whole
        /// discipline — there are no open/close verbs to mismatch.
        #[inline]
        pub fn message(&mut self, field: FieldNumber, body: impl FnOnce(&mut $Body<'_, $p>)) {
            self.core.len_frame(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                |core| body(&mut $Body { core }),
            );
        }

        /// Frames `body`'s byte chunks as one LEN record of
        /// `field`: the chunk concatenation becomes the payload
        /// behind an exact minimal prefix, patched at close
        /// through the same placeholder mechanism as
        /// [`message`](Self::message) — chunks are accounted as
        /// they arrive and never re-measured. The chunked twin of
        /// `push_len`, for payloads that arrive in pieces; an
        /// untouched frame closes as an empty LEN record. The
        /// payload's interior is the caller's declaration.
        #[inline]
        pub fn bytes_frame(
            &mut self,
            field: FieldNumber,
            body: impl FnOnce(&mut crate::construct::Bytes<'_, $p>),
        ) {
            self.core.len_frame(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                |core| body(&mut crate::construct::Bytes { core }),
            );
        }
    };
    (copy: $dialect:ident, $Body:ident) => {
        typed_faces!(@scalars $dialect);

        /// Pushes a LEN record carrying `payload` verbatim, behind
        /// a minimal length prefix. The payload copies into the
        /// builder at the push — this machine's one supply, so
        /// temporaries are welcome; its interior is the caller's
        /// declaration, never interpreted.
        #[inline]
        pub fn push_len(&mut self, field: FieldNumber, payload: &[u8]) {
            self.core.put_len_copy(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                payload,
            );
        }

        /// Pushes a `string`: the `&str` type is the UTF-8 proof.
        /// The value copies into the builder at the push, as
        /// [`push_len`](Self::push_len).
        #[inline]
        pub fn push_string(&mut self, field: FieldNumber, value: &str) {
            self.push_len(field, value.as_bytes());
        }

        typed_faces!(@packed $dialect);

        /// Frames `body`'s records as a LEN message of `field`: the
        /// frame closes when the closure returns, and the prefix is
        /// the body's exact length. Closure pairing is the whole
        /// discipline — there are no open/close verbs to mismatch.
        #[inline]
        pub fn message(&mut self, field: FieldNumber, body: impl FnOnce(&mut $Body<'_>)) {
            self.core.len_frame(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                |core| body(&mut $Body { core }),
            );
        }

        /// Frames `body`'s byte chunks as one LEN record of
        /// `field`: the chunk concatenation becomes the payload
        /// behind an exact minimal prefix, patched at close
        /// through the same placeholder mechanism as
        /// [`message`](Self::message) — chunks are accounted as
        /// they arrive and never re-measured. The chunked twin of
        /// `push_len`, for payloads that arrive in pieces; an
        /// untouched frame closes as an empty LEN record. The
        /// payload's interior is the caller's declaration.
        #[inline]
        pub fn bytes_frame(
            &mut self,
            field: FieldNumber,
            body: impl FnOnce(&mut crate::construct::CopyBytes<'_>),
        ) {
            self.core.len_frame(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                |core| body(&mut crate::construct::CopyBytes { core }),
            );
        }
    };
    (@scalars $dialect:ident) => {
        /// Pushes a varint record; `value` is the wire word (the
        /// `uint64` reading).
        #[inline]
        pub fn push_varint(&mut self, field: FieldNumber, value: u64) {
            self.core.put_varint(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Varint),
                value,
            );
        }

        /// Pushes a fixed 32-bit record; `bits` is the wire word
        /// (the `fixed32` reading), little-endian on the wire.
        #[inline]
        pub fn push_i32(&mut self, field: FieldNumber, bits: u32) {
            self.core.put_i32(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::I32),
                bits,
            );
        }

        /// Pushes a fixed 64-bit record; `bits` is the wire word
        /// (the `fixed64` reading), little-endian on the wire.
        #[inline]
        pub fn push_i64(&mut self, field: FieldNumber, bits: u64) {
            self.core.put_i64(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::I64),
                bits,
            );
        }

        /// Pushes an `int32`: negatives sign-extend to the
        /// ten-byte wire form, the reference decoders' reading.
        #[inline]
        pub fn push_int32(&mut self, field: FieldNumber, value: i32) {
            self.push_varint(field, crate::scalar::encode_int64(i64::from(value)));
        }

        /// Pushes an `int64`: the signed value reinterpreted as its
        /// wire word.
        #[inline]
        pub fn push_int64(&mut self, field: FieldNumber, value: i64) {
            self.push_varint(field, crate::scalar::encode_int64(value));
        }

        /// Pushes a `sint32`: zigzag, so small magnitudes stay
        /// small on the wire.
        #[inline]
        pub fn push_sint32(&mut self, field: FieldNumber, value: i32) {
            self.push_varint(field, crate::scalar::encode_sint32(value));
        }

        /// Pushes a `sint64`: zigzag.
        #[inline]
        pub fn push_sint64(&mut self, field: FieldNumber, value: i64) {
            self.push_varint(field, crate::scalar::encode_sint64(value));
        }

        /// Pushes a `bool`: one byte, `0` or `1`.
        #[inline]
        pub fn push_bool(&mut self, field: FieldNumber, value: bool) {
            self.push_varint(field, crate::scalar::encode_bool(value));
        }

        /// Pushes an enum number: `int32`'s wire form (negatives
        /// sign-extend).
        #[inline]
        pub fn push_enum(&mut self, field: FieldNumber, value: i32) {
            self.push_varint(field, crate::scalar::encode_int64(i64::from(value)));
        }

        /// Pushes an `sfixed32`: the signed bits in a fixed 32-bit
        /// record.
        #[inline]
        pub fn push_sfixed32(&mut self, field: FieldNumber, value: i32) {
            self.push_i32(field, value.cast_unsigned());
        }

        /// Pushes a `float`: its bits in a fixed 32-bit record.
        #[inline]
        pub fn push_float(&mut self, field: FieldNumber, value: f32) {
            self.push_i32(field, crate::scalar::encode_float(value));
        }

        /// Pushes an `sfixed64`: the signed bits in a fixed 64-bit
        /// record.
        #[inline]
        pub fn push_sfixed64(&mut self, field: FieldNumber, value: i64) {
            self.push_i64(field, value.cast_unsigned());
        }

        /// Pushes a `double`: its bits in a fixed 64-bit record.
        #[inline]
        pub fn push_double(&mut self, field: FieldNumber, value: f64) {
            self.push_i64(field, crate::scalar::encode_double(value));
        }

    };
    (@packed $dialect:ident) => {
        /// Pushes packed `uint32`s: one LEN record of varint
        /// elements.
        #[inline]
        pub fn push_packed_uint32(&mut self, field: FieldNumber, items: &[u32]) {
            self.core.put_packed_varints(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                u64::from,
            );
        }

        /// Pushes packed `uint64`s.
        #[inline]
        pub fn push_packed_uint64(&mut self, field: FieldNumber, items: &[u64]) {
            self.core.put_packed_varints(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                |item| item,
            );
        }

        /// Pushes packed `int32`s (negatives sign-extend to ten
        /// bytes each).
        #[inline]
        pub fn push_packed_int32(&mut self, field: FieldNumber, items: &[i32]) {
            self.core.put_packed_varints(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                |item| crate::scalar::encode_int64(i64::from(item)),
            );
        }

        /// Pushes packed `int64`s.
        #[inline]
        pub fn push_packed_int64(&mut self, field: FieldNumber, items: &[i64]) {
            self.core.put_packed_varints(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                crate::scalar::encode_int64,
            );
        }

        /// Pushes packed `sint32`s (zigzag).
        #[inline]
        pub fn push_packed_sint32(&mut self, field: FieldNumber, items: &[i32]) {
            self.core.put_packed_varints(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                crate::scalar::encode_sint32,
            );
        }

        /// Pushes packed `sint64`s (zigzag).
        #[inline]
        pub fn push_packed_sint64(&mut self, field: FieldNumber, items: &[i64]) {
            self.core.put_packed_varints(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                crate::scalar::encode_sint64,
            );
        }

        /// Pushes packed `bool`s: one byte per element.
        #[inline]
        pub fn push_packed_bool(&mut self, field: FieldNumber, items: &[bool]) {
            self.core.put_packed_varints(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                crate::scalar::encode_bool,
            );
        }

        /// Pushes packed enum numbers (`int32` wire form).
        #[inline]
        pub fn push_packed_enum(&mut self, field: FieldNumber, items: &[i32]) {
            self.core.put_packed_varints(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                |item| crate::scalar::encode_int64(i64::from(item)),
            );
        }

        /// Pushes packed `fixed32`s: four bytes per element.
        #[inline]
        pub fn push_packed_fixed32(&mut self, field: FieldNumber, items: &[u32]) {
            self.core.put_packed_fixed32(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                |item| item,
            );
        }

        /// Pushes packed `sfixed32`s.
        #[inline]
        pub fn push_packed_sfixed32(&mut self, field: FieldNumber, items: &[i32]) {
            self.core.put_packed_fixed32(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                i32::cast_unsigned,
            );
        }

        /// Pushes packed `float`s.
        #[inline]
        pub fn push_packed_float(&mut self, field: FieldNumber, items: &[f32]) {
            self.core.put_packed_fixed32(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                crate::scalar::encode_float,
            );
        }

        /// Pushes packed `fixed64`s: eight bytes per element.
        #[inline]
        pub fn push_packed_fixed64(&mut self, field: FieldNumber, items: &[u64]) {
            self.core.put_packed_fixed64(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                |item| item,
            );
        }

        /// Pushes packed `sfixed64`s.
        #[inline]
        pub fn push_packed_sfixed64(&mut self, field: FieldNumber, items: &[i64]) {
            self.core.put_packed_fixed64(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                i64::cast_unsigned,
            );
        }

        /// Pushes packed `double`s.
        #[inline]
        pub fn push_packed_double(&mut self, field: FieldNumber, items: &[f64]) {
            self.core.put_packed_fixed64(
                crate::wire::$dialect::head_word(field, crate::wire::$dialect::RecordKind::Len),
                items,
                crate::scalar::encode_double,
            );
        }
    };
}

/// The raw word faces, carried by frame interiors only: inside a
/// frame the enclosing framing is already lawful, and what the
/// bytes mean there is the frame author's declaration. The
/// declension arm names the payload backing: the mixed arm
/// declares the payload-borrow lifetime `$p` and carries the
/// `_copy` twin, the copy arm copies at the push under the
/// unsuffixed name.
macro_rules! raw_faces {
    (mixed: $p:lifetime) => {
        raw_faces!(@words);

        /// Appends `bytes` verbatim — 64 bytes or more ride
        /// borrowed until the finish (the single copy lands in
        /// the output), shorter runs stage immediately, as
        /// [`push_len`](Self::push_len). Framing stays lawful;
        /// interior validity is the caller's declaration.
        #[inline]
        pub fn raw_bytes(&mut self, bytes: &$p [u8]) {
            self.core.put_raw_bytes(bytes);
        }

        /// [`raw_bytes`](Self::raw_bytes)'s staging twin: copies
        /// `bytes` into the builder at the push, for temporaries
        /// that cannot outlive it. Framing stays lawful; interior
        /// validity is the caller's declaration.
        #[inline]
        pub fn raw_bytes_copy(&mut self, bytes: &[u8]) {
            self.core.put_raw_bytes_copy(bytes);
        }
    };
    (copy) => {
        raw_faces!(@words);

        /// Appends `bytes` verbatim, copied into the builder at
        /// the push — this machine's one supply, so temporaries
        /// are welcome. Framing stays lawful; interior validity is
        /// the caller's declaration.
        #[inline]
        pub fn raw_bytes(&mut self, bytes: &[u8]) {
            self.core.put_raw_bytes_copy(bytes);
        }
    };
    (@words) => {
        /// Appends one bare varint word — no head. Framing stays
        /// lawful; the word's meaning inside this frame is the
        /// caller's declaration.
        #[inline]
        pub fn raw_varint(&mut self, value: u64) {
            self.core.put_raw_varint(value);
        }

        /// Appends four little-endian bytes — no head.
        #[inline]
        pub fn raw_i32(&mut self, bits: u32) {
            self.core.put_raw_i32(bits);
        }

        /// Appends eight little-endian bytes — no head.
        #[inline]
        pub fn raw_i64(&mut self, bits: u64) {
            self.core.put_raw_i64(bits);
        }
    };
}

// The dialect modules expand the face macros above, so they are
// declared after them (textual macro scope).
#[cfg(feature = "construct-grouped")]
pub mod grouped;
#[cfg(feature = "construct-groupless")]
pub mod groupless;

#[cfg(test)]
mod tests {
    use super::*;

    /// The account arithmetic at the cap edge, without allocating
    /// gigabytes: total is hand-set, then charged.
    #[test]
    fn the_account_refuses_at_the_cap_edge_and_poisons_once() {
        let mut core = Core::new();
        core.total = CAP - 2;
        assert!(core.account(2), "exactly at the cap is lawful");
        assert_eq!(core.total, CAP);
        assert!(!core.account(1), "one past the cap poisons");
        let cap = core.poisoned().expect("poisoned");
        assert_eq!(cap.len, CAP + 1);
        assert_eq!(cap.field, None, "top-level break carries no frame field");
        // Poison is sticky and the account stops moving.
        assert!(!core.account(1));
        assert_eq!(core.total, CAP);
    }

    #[test]
    fn the_break_inside_a_frame_quotes_its_field() {
        let mut core = Core::new();
        // A LEN frame for field 5 (head word 0x2A = 5 << 3 | 2).
        core.begin_len(0x2A);
        core.total = CAP;
        assert!(!core.account(1));
        let cap = core.poisoned().expect("poisoned");
        assert_eq!(cap.field, crate::wire::FieldNumber::new(5));
    }

    #[test]
    fn the_prefix_break_at_close_quotes_the_closing_frame() {
        // The LEN prefix joins the account at `end`; when that
        // charge breaks the cap, the fault names the frame being
        // closed (the innermost open frame at the break).
        let mut core = Core::new();
        core.begin_len(0x2A); // field 5
        core.total = CAP;
        core.end_len();
        let cap = core.poisoned().expect("prefix charge poisoned");
        assert_eq!(cap.field, crate::wire::FieldNumber::new(5));
    }
}
