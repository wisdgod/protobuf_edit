//! The shared editing-session layer: the owning byte carrier, the
//! value store, the edit algebra, and the coordinate types both
//! dialect sessions build on.
//!
//! Allocation policy: every growth edge in this scenario is
//! fallible. The carrier and the raw output document use fallible
//! raw allocation, the store and the sessions'
//! arenas grow through `try_reserve`, and a refusal surfaces as a
//! structured `Err` (`LoadFault::Resource` here, the dialects'
//! `OpenFault`/`EditFault`/`SaveFault` above) — never an abort.
//!
//! The dialect modules (`grouped`, `groupless`) are separate
//! concrete machines sharing this layer; they share no dialect
//! types with each other. Descending a LEN is the Commit pole of
//! the per-LEN interpretation axis: an explicit commitment that
//! the payload parses as records — a write machine never
//! speculates.
//!
//! Output acceptance: admission is canonical-minimal and authored
//! words are minimal, so saved documents re-ingest under
//! `CanonicalMinimal` — with one caller-declared exception: an
//! authored payload's interior passes through unchanged.
//!
//! Coordinates: write · buffered · offline · canonical (type-level) · owned · revisable.
//!
//! # Choosing a face
//!
//! - Opening: [`DocBytes::load`] seals bytes into the owned
//!   carrier once; `Session::open` opens a carrier you already
//!   hold (clones share the one allocation), and
//!   `Session::open_copy` folds load-then-open for the borrowed
//!   common case. Admission is canonical-minimal — padded wire
//!   refuses at open; the tolerant editor over borrowed bytes is
//!   `patch` (feature `patch-*`).
//! - Commands: `set_varint`/`set_i32`/`set_i64`/`set_payload`
//!   replace values; `insert_varint`/`insert_i32`/`insert_i64`/
//!   `insert_payload` (the grouped session adds `insert_group`)
//!   author records; `delete` shrouds and `undelete` restores
//!   exactly; `clear_edit` clears a replacement back to the
//!   scanned state.
//! - Revision — the axis the one-shot editors lack: every command
//!   logs one step; `revert` pops the last, `revert_all` empties
//!   the log, `pending` counts it.
//! - Saving: `save` emits a fresh sealed [`DocBytes`] — output
//!   that re-opens, so sessions chain; `save_into` emits the same
//!   bytes into a plain `Vec<u8>` — the carrier is `!Send` by
//!   design, the `Vec` is the portable product for bytes leaving
//!   the editing thread (choose `save` to keep editing, `save_into`
//!   to ship); `save_sink` hands the same bytes to a caller sink
//!   slice by slice, no output buffer (every fault precedes the
//!   first handoff, so the sink receives nothing on `Err`);
//!   `save_len` prices any of them without emitting, and
//!   `save_spans` maps every emitted record to its output span —
//!   the cross-save identity supply (recipe below). When the price
//!   is asked after every command, the priced typestate cells
//!   (`priced-session-*`) add `Session::into_priced`: the same
//!   faces with the price settled incrementally, so `save_len`
//!   answers in O(1) while every rewritten body sits in the length
//!   class.
//! - Payload backing, by type: `Session` copies payloads at the
//!   command — temporaries welcome, no payload lifetime on the
//!   type, and the staged frames (`begin_set_payload` and kin)
//!   ride the copying store. Its sibling `BorrowSession<'p>`
//!   retains borrowed slices instead: `set_payload` and
//!   `insert_payload` take `&'p [u8]` and append one immutable
//!   slot per install — no staging copy, no staged frames, and
//!   every payload owner must outlive the session. Undo is the
//!   same algebra: earlier installs keep their slots, so a revert
//!   restores the exact prior payload. Saves copy each live
//!   payload once into the owned product (`save_sink` hands the
//!   slices through), so the saved document carries no borrow.
//!   The third sibling `MixSession<'p>` selects the backing per
//!   install: its unsuffixed faces retain like `BorrowSession`,
//!   its `_copy` twins and staged frames copy like `Session`, and
//!   every install appends one immutable slot on one revision log —
//!   long-lived templates and dying temporaries interleave. No
//!   priced typestate door rides the mixed form.
//! - Relocation and import: the dialect's `transfer` submodule
//!   (feature `transfer-session-*`) ships `TransferSession`
//!   (copying) and `TransferBorrowSession` (borrowing) — the same
//!   faces plus `copy_record`/`move_record` for whole records,
//!   `copy_payload`/`move_payload` for LEN interiors, and
//!   `copy_record_from` importing one designated record from
//!   another document; a move is one command, one pending step,
//!   one revert. The priced typestate door rides the copying form
//!   too: `PricedTransferSession` (feature
//!   `priced-transfer-session-*`).
//! - Hex-view supply: `span`/`source_spans` give record geometry,
//!   and `narrowest` answers "which record covers this byte".
//!
//! Both dialect sessions ship the same faces; the crate root's
//! feature guide picks the dialect.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "session-grouped")] {
//! use protobuf_edit::session::DocBytes;
//! use protobuf_edit::session::grouped::Session;
//!
//! // Seal a document, edit it in a session, save the result.
//! let doc = DocBytes::load(&[0x08, 0x96, 0x01]).unwrap();
//! let mut session = Session::open(doc).unwrap();
//! let record = session.top().next().unwrap();
//! session.set_varint(record, 7).unwrap();
//! assert_eq!(session.save().unwrap()[..], [0x08, 0x07]);
//! # }
//! ```
//!
//! Revision: every command logs one step, and a revert restores it
//! exactly — the save is again byte-identical to the source.
//!
//! ```
//! # #[cfg(feature = "session-groupless")] {
//! use protobuf_edit::session::DocBytes;
//! use protobuf_edit::session::groupless::Session;
//!
//! let doc = DocBytes::load(&[0x08, 0x96, 0x01]).unwrap();
//! let mut session = Session::open(doc).unwrap();
//! let record = session.top().next().unwrap();
//! session.set_varint(record, 7).unwrap();
//! assert_eq!(session.pending(), 1);
//! session.revert();
//! assert_eq!(session.pending(), 0);
//! assert_eq!(session.save().unwrap()[..], [0x08, 0x96, 0x01]);
//! # }
//! ```
//!
//! # Recipes
//!
//! Sessions chain through their saves: the sealed output re-opens
//! as the next session's carrier — no byte copy, no reload:
//!
//! ```
//! # #[cfg(feature = "session-groupless")] {
//! use protobuf_edit::session::groupless::Session;
//!
//! let mut draft = Session::open_copy(&[0x08, 0x96, 0x01]).unwrap();
//! let record = draft.top().next().unwrap();
//! draft.set_varint(record, 7).unwrap();
//! let saved = draft.save().unwrap();
//!
//! // The saved carrier moves straight into the next session.
//! let mut next = Session::open(saved).unwrap();
//! let record = next.top().next().unwrap();
//! next.set_varint(record, 8).unwrap();
//! assert_eq!(next.save().unwrap()[..], [0x08, 0x08]);
//! # }
//! ```
//!
//! The undo bracket — a hand-rolled transaction over the revision
//! log: mark `pending` before a compound edit, and on failure pop
//! back to the mark:
//!
//! ```
//! # #[cfg(feature = "session-groupless")] {
//! use protobuf_edit::FieldNumber;
//! use protobuf_edit::session::groupless::{InsertAt, Session};
//!
//! let mut session = Session::open_copy(&[0x08, 0x2A]).unwrap();
//! let record = session.top().next().unwrap();
//! session.set_varint(record, 7).unwrap(); // the committed prefix
//!
//! let mark = session.pending();
//! let f2 = FieldNumber::new(2).unwrap();
//! session.insert_varint(InsertAt::TailOf(None), f2, 1).unwrap();
//! session.insert_varint(InsertAt::TailOf(None), f2, 2).unwrap();
//! // The compound edit is abandoned: unwind to the mark, exactly.
//! while session.pending() > mark {
//!     session.revert();
//! }
//! assert_eq!(session.save().unwrap()[..], [0x08, 0x07]);
//! # }
//! ```
//!
//! Cross-save identity: handles survive saves in their owning
//! session — saving borrows the machine, so every handle keeps
//! naming its record afterwards — but they are machine-local: a
//! newly opened session mints its own arena and cannot answer
//! another machine's handles. A record's output span is the
//! cross-machine identity — take the span from `save_spans`, save,
//! reopen, and `narrowest` recovers the record on the other side
//! (two lines where a viewer would otherwise re-derive whole
//! paths):
//!
//! ```
//! # #[cfg(feature = "session-groupless")] {
//! use protobuf_edit::session::groupless::Session;
//!
//! // varint f1=1 · LEN f2 { varint f1=7 }; the edit target sits
//! // inside the container.
//! let mut session = Session::open_copy(&[0x08, 0x01, 0x12, 0x02, 0x08, 0x07]).unwrap();
//! let container = session.top().nth(1).unwrap();
//! let inner = match session.descend(container).unwrap() {
//!     protobuf_edit::session::groupless::Descent::Opened { first: Some(first) } => first,
//!     _ => unreachable!(),
//! };
//! session.set_varint(inner, 300).unwrap();
//!
//! let spans = session.save_spans().unwrap();
//! let (_, span) = spans.iter().find(|(handle, _)| *handle == inner).unwrap();
//! let saved = session.save().unwrap();
//! // The save borrowed the session: its own handles still answer.
//! assert_eq!(session.varint_word(inner), Ok(300));
//!
//! // The next session never saw the old handles. LEN interiors
//! // materialize on descend, so the byte coordinate names the
//! // covering container first, then the exact record.
//! let mut next = Session::open(saved).unwrap();
//! let container = next.narrowest(span.start()).unwrap();
//! next.descend(container).unwrap();
//! let recovered = next.narrowest(span.start()).unwrap();
//! assert_eq!(next.varint_word(recovered), Ok(300));
//! # }
//! ```
//!
//! The hex-view click: `narrowest` answers which record covers a
//! byte, `source_spans` names the segment under it, and the value
//! faces read the record out:
//!
//! ```
//! # #[cfg(feature = "session-groupless")] {
//! use protobuf_edit::session::groupless::{RecordSpans, Session};
//!
//! // varint f1=150 · LEN f2 "hi"; the viewer clicks byte 5.
//! let msg = [0x08, 0x96, 0x01, 0x12, 0x02, 0x68, 0x69];
//! let session = Session::open_copy(&msg).unwrap();
//! let record = session.narrowest(5).unwrap();
//! let spans = session.source_spans(record).unwrap().unwrap();
//! let RecordSpans::Len { payload, .. } = spans else { unreachable!() };
//! assert!(payload.as_range().contains(&5));
//! assert_eq!(session.payload_bytes(record).unwrap(), *b"hi");
//! # }
//! ```
//!
//! The borrowed-payload profile: a long-lived template document
//! outlives every request session built over it, so its slices
//! install without a staging copy, and the machine moves and
//! returns like any value whose borrows are alive:
//!
//! ```
//! # #[cfg(feature = "session-groupless")] {
//! use protobuf_edit::session::DocBytes;
//! use protobuf_edit::session::groupless::BorrowSession;
//!
//! fn stamp<'cfg>(template: &'cfg [u8], doc: DocBytes) -> BorrowSession<'cfg> {
//!     let mut session = BorrowSession::open(doc).unwrap();
//!     let record = session.top().next().unwrap();
//!     session.set_payload(record, template).unwrap();
//!     session
//! }
//!
//! let template = vec![0x08, 0x2A];
//! let doc = DocBytes::load(&[0x12, 0x00]).unwrap();
//! let session = stamp(&template, doc);
//! assert_eq!(session.save().unwrap()[..], [0x12, 0x02, 0x08, 0x2A]);
//! # }
//! ```
#![cfg_attr(
    feature = "session-groupless",
    doc = "
A borrowed payload must outlive the session — the type refuses
an owner that dies while the machine can still read the slot
(the copy-only `Session` is the escape hatch for temporaries):

```compile_fail,E0597
use protobuf_edit::session::groupless::BorrowSession;

let msg = [0x12, 0x01, 0x61];
let mut session = BorrowSession::open_copy(&msg).unwrap();
let record = session.top().next().unwrap();
{
    let transient = vec![0x08, 0x07];
    session.set_payload(record, &transient).unwrap();
} // the owner dies here; the session still holds the borrow
session.save().unwrap();
```"
)]
#![cfg_attr(
    feature = "session-groupless",
    doc = "
And a retained owner may not be mutated while the machine can
still read the slot — the install borrows it for the machine's
remaining life:

```compile_fail,E0502
use protobuf_edit::session::groupless::BorrowSession;

let msg = [0x12, 0x01, 0x61];
let mut payload = vec![0x08, 0x07];
let mut session = BorrowSession::open_copy(&msg).unwrap();
let record = session.top().next().unwrap();
session.set_payload(record, &payload).unwrap();
payload.clear(); // the session still holds the borrow
session.save().unwrap();
```"
)]

use core::alloc::Layout;
use core::cell::Cell;
use core::ptr::NonNull;

use alloc::alloc::{alloc as raw_alloc, dealloc as raw_dealloc};
use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use crate::admission::usize_of;
use crate::varint::{encoded_len64, write64_at};
#[cfg(feature = "session-grouped")]
pub mod grouped;
#[cfg(feature = "session-groupless")]
pub mod groupless;

#[cfg(test)]
mod tests;

crate::revise::revising_store! {
    coordinates,
    tenure: carrier,
    acceptance: canonical,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
}

// ─── the carrier ───

/// Allocation header ahead of the document bytes: the share count.
struct Header {
    count: Cell<u32>,
}

/// Bytes begin at this offset — the header rounded to the data
/// alignment.
const HEADER_SIZE: usize = 8;
/// Initialized zero bytes past the document end: with the header
/// they hold the allocation overhead at exactly 32, and they give
/// windowed readers a lawful in-allocation overhang.
const TAIL_PAD: usize = 24;
/// Allocation alignment: the data offset stays eight-aligned.
const ALIGN: usize = 8;

const _: () = {
    assert!(core::mem::size_of::<Header>() <= HEADER_SIZE);
    assert!(core::mem::align_of::<Header>() <= ALIGN);
    assert!(HEADER_SIZE + TAIL_PAD == 32);
    // The layout budget: a full-cap document plus overhead lands on
    // 2^31 exactly, within `u32` and (on 64-bit targets) within
    // `isize::MAX`; 32-bit targets re-judge against `isize::MAX` at
    // admission.
    assert!(usize_of(DocBytes::CAP) + HEADER_SIZE + TAIL_PAD == 1 << 31);
};

/// Why a byte carrier refused to build.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoadFault {
    /// The input exceeds [`DocBytes::CAP`].
    TooLarge {
        /// The refused input length.
        len: usize,
    },
    /// The allocator refused the carrier allocation.
    Resource,
}

impl core::fmt::Display for LoadFault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::TooLarge { len } => {
                write!(f, "document of {len} bytes exceeds the carrier cap")
            }
            Self::Resource => f.write_str("allocator refused the document carrier"),
        }
    }
}

impl core::error::Error for LoadFault {}

/// The layout of a carrier allocation for `len` document bytes.
///
/// # Safety
/// `len` must be admitted (`len <= CAP` and the total below
/// `isize::MAX`, judged by [`admit`]): the const assertions above
/// prove the align and the size bound for admitted lengths.
#[inline]
const unsafe fn carrier_layout(len: usize) -> Layout {
    // SAFETY: ALIGN is a nonzero power of two and the admitted size
    // is at most 2^31 minus what `admit` reserved for `isize::MAX`.
    unsafe { Layout::from_size_align_unchecked(HEADER_SIZE + len + TAIL_PAD, ALIGN) }
}

/// The target's allocation bound in the byte-length domain.
#[allow(
    clippy::as_conversions,
    reason = "isize::MAX is non-negative and widens losslessly into usize"
)]
const HARD_CAP: usize = isize::MAX as usize;

/// Judges a byte length against the carrier cap and the target's
/// allocation bound.
#[inline]
const fn admit(len: usize) -> Result<u32, LoadFault> {
    if len <= usize_of(DocBytes::CAP) && HEADER_SIZE + len + TAIL_PAD <= HARD_CAP {
        #[allow(
            clippy::as_conversions,
            reason = "just judged against CAP, which is below u32::MAX"
        )]
        let len = len as u32;
        Ok(len)
    } else {
        Err(LoadFault::TooLarge { len })
    }
}

/// An owned, sealed protobuf document: one allocation, shared by
/// count.
///
/// The seal is the dialects' proof source: the bytes are immutable
/// and initialized through `len` plus the zeroed tail pad, both
/// established by [`DocBytes::load`], so every extent a session
/// derives from its own bookkeeping stays inside the allocation.
///
/// Deliberately `!Send + !Sync`: the share count is a plain
/// [`Cell`], and the editing scenario is single-threaded by design.
///
/// ```compile_fail
/// fn sendable<T: Send>() {}
/// sendable::<protobuf_edit::session::DocBytes>();
/// ```
pub struct DocBytes {
    /// The allocation base (the header).
    base: NonNull<u8>,
    len: u32,
}

impl DocBytes {
    /// The largest admissible document: the allocation overhead
    /// (header and tail pad) keeps a full carrier at `2^31` bytes.
    pub const CAP: u32 = (1 << 31) - 32;

    /// Copies `bytes` into a fresh sealed carrier.
    ///
    /// # Errors
    ///
    /// [`LoadFault::TooLarge`] beyond [`Self::CAP`] (or beyond the
    /// target's allocation bound), [`LoadFault::Resource`] when the
    /// allocator refuses.
    ///
    /// # Examples
    ///
    /// ```
    /// use protobuf_edit::session::DocBytes;
    ///
    /// let doc = DocBytes::load(&[0x08, 0x2A]).unwrap();
    /// assert_eq!(doc.len(), 2);
    /// assert_eq!(doc[..], [0x08, 0x2A]);
    /// // Clones share the one allocation by count.
    /// let share = doc.clone();
    /// assert!(DocBytes::ptr_eq(&doc, &share));
    /// ```
    pub fn load(bytes: &[u8]) -> Result<Self, LoadFault> {
        let len = admit(bytes.len())?;
        // SAFETY: `admit` just judged the length.
        let layout = unsafe { carrier_layout(bytes.len()) };
        // SAFETY: the layout has nonzero size (header plus pad).
        let base = unsafe { raw_alloc(layout) };
        let Some(base) = NonNull::new(base) else {
            return Err(LoadFault::Resource);
        };
        // SAFETY: the allocation spans header + len + pad; the
        // header write, the byte copy, and the pad zeroing each
        // stay inside their region.
        unsafe {
            base.cast::<Header>().write(Header { count: Cell::new(1) });
            let data = base.add(HEADER_SIZE);
            data.copy_from_nonoverlapping(NonNull::from_ref(bytes).cast(), bytes.len());
            data.add(bytes.len()).write_bytes(0, TAIL_PAD);
        }
        Ok(Self { base, len })
    }

    /// Byte length of the document.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// True when the document is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The sealed bytes.
    #[inline]
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        // SAFETY: `load` initialized `len` bytes at the data offset
        // and the seal keeps them immutable and alive while any
        // share exists.
        unsafe {
            core::slice::from_raw_parts(self.base.add(HEADER_SIZE).as_ptr(), usize_of(self.len))
        }
    }

    /// True when both carriers are the same allocation.
    #[inline]
    #[must_use]
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        a.base == b.base
    }

    /// The share count cell.
    const fn count(&self) -> &Cell<u32> {
        // SAFETY: `load` initialized the header at the base and the
        // allocation outlives every share.
        unsafe { &self.base.cast::<Header>().as_ref().count }
    }
}

impl Clone for DocBytes {
    /// Shares the allocation by count.
    ///
    /// # Panics
    ///
    /// If the share count overflows `u32` — four billion live
    /// shares are a caller bug, not a load the carrier supports.
    #[inline]
    #[track_caller]
    fn clone(&self) -> Self {
        let count = self.count();
        count.set(count.get().checked_add(1).expect("DocBytes share count overflow"));
        Self { base: self.base, len: self.len }
    }
}

impl Drop for DocBytes {
    #[inline]
    fn drop(&mut self) {
        let count = self.count();
        let n = count.get();
        if n == 1 {
            // SAFETY: last share; the layout is the one `load` (or
            // `RawDoc::finish`) allocated for this admitted length.
            unsafe { raw_dealloc(self.base.as_ptr(), carrier_layout(usize_of(self.len))) };
        } else {
            count.set(n - 1);
        }
    }
}

impl core::ops::Deref for DocBytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// An unpublished output document: the save passes' write target.
///
/// Allocated at the exact emitted size, written front to back, and
/// published by [`RawDoc::finish`] into a sealed [`DocBytes`].
/// Dropping an unfinished one frees the allocation without
/// publishing.
///
/// The write faces carry no failure edge: the emit pass writes
/// exactly the bytes the size pass paid for, so capacity is a crate
/// invariant (debug-asserted per write, hard-asserted at `finish`).
pub(crate) struct RawDoc {
    base: NonNull<u8>,
    len: u32,
    cap: u32,
}

impl RawDoc {
    /// Allocates an output carrier for exactly `cap` bytes; `None`
    /// when the length is beyond the carrier bound or the allocator
    /// refuses.
    pub(crate) fn alloc(cap: u32) -> Option<Self> {
        let cap = admit(usize_of(cap)).ok()?;
        // SAFETY: `admit` just judged the length.
        let layout = unsafe { carrier_layout(usize_of(cap)) };
        // SAFETY: the layout has nonzero size (header plus pad).
        let base = unsafe { raw_alloc(layout) };
        Some(Self { base: NonNull::new(base)?, len: 0, cap })
    }

    /// The write cursor (also the number of initialized bytes).
    const fn cursor(&self) -> NonNull<u8> {
        // SAFETY: `len <= cap` is this type's invariant, so the
        // cursor stays inside the data region.
        unsafe { self.base.add(HEADER_SIZE + usize_of(self.len)) }
    }

    /// Appends `bytes` at the cursor.
    pub(crate) fn put_slice(&mut self, bytes: &[u8]) {
        debug_assert!(usize_of(self.cap) - usize_of(self.len) >= bytes.len());
        // SAFETY: the size pass reserved every emitted byte, so the
        // remaining capacity covers `bytes` (debug-asserted above;
        // `finish` hard-asserts the total).
        unsafe {
            self.cursor().copy_from_nonoverlapping(NonNull::from_ref(bytes).cast(), bytes.len());
        }
        #[allow(
            clippy::as_conversions,
            reason = "the size pass judged the carrier total against `CAP`, so every emitted slice length fits in `u32`"
        )]
        {
            self.len += bytes.len() as u32;
        }
    }

    /// Appends `value` as a minimal varint at the cursor.
    pub(crate) fn put_varint(&mut self, value: u64) {
        let width = encoded_len64(value);
        debug_assert!(self.cap - self.len >= width);
        // SAFETY: the size pass reserved this construct's width
        // (same debug/hard assertion pair as `put_slice`), and
        // `width` is the value's own encoded length.
        unsafe { write64_at(self.cursor().as_ptr(), value, width) };
        self.len += width;
    }

    /// Appends four little-endian bytes at the cursor.
    pub(crate) fn put_bits32(&mut self, bits: u32) {
        debug_assert!(self.cap - self.len >= 4);
        // SAFETY: capacity per the size pass, as in `put_slice`;
        // the write is byte-aligned by construction.
        unsafe { self.cursor().cast::<u32>().write_unaligned(bits.to_le()) };
        self.len += 4;
    }

    /// Appends eight little-endian bytes at the cursor.
    pub(crate) fn put_bits64(&mut self, bits: u64) {
        debug_assert!(self.cap - self.len >= 8);
        // SAFETY: capacity per the size pass, as in `put_slice`;
        // the write is byte-aligned by construction.
        unsafe { self.cursor().cast::<u64>().write_unaligned(bits.to_le()) };
        self.len += 8;
    }

    /// Publishes the finished document as a sealed carrier.
    ///
    /// # Panics
    ///
    /// If the written length differs from the allocated capacity —
    /// the size and emit passes disagreeing is a crate bug, pinned
    /// here so a drifted save can never publish.
    pub(crate) fn finish(self) -> DocBytes {
        assert!(self.len == self.cap, "RawDoc::finish: emitted length differs from the sized cap");
        let this = core::mem::ManuallyDrop::new(self);
        // SAFETY: the allocation spans header + cap + pad; `len ==
        // cap` bytes are initialized, and the header write and pad
        // zeroing complete the carrier seal.
        unsafe {
            this.base.cast::<Header>().write(Header { count: Cell::new(1) });
            this.cursor().write_bytes(0, TAIL_PAD);
        }
        DocBytes { base: this.base, len: this.len }
    }
}

impl Drop for RawDoc {
    fn drop(&mut self) {
        // SAFETY: unpublished carrier; the layout is the one
        // `alloc` built for this capacity.
        unsafe { raw_dealloc(self.base.as_ptr(), carrier_layout(usize_of(self.cap))) };
    }
}

crate::revise::revising_store! {
    layer plain,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
}

#[cfg(any(feature = "transfer-session-grouped", feature = "transfer-session-groupless"))]
crate::revise::revising_store! {
    layer transfer,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
}

#[cfg(any(
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
crate::revise::revising_store! {
    store priced,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
}

// ─── the priced ledger's arithmetic theorem ───
//
// Every ledger value — a container body, the document total — is an
// exact sum of record emission widths, and the machine's own
// domains bound every such sum below `PRICE_CEILING`. That bound is
// what lets the priced wrappers' release arithmetic run branch-free
// with no representable-overflow case: the signed widening behind
// the price delta, the admission accumulator's plain additions, and
// both wrapping additions in the settling climb never wrap in
// truth; the debug asserts at those sites and the price oracle stay
// the checked form.
//
// The decomposition "per-row framing, plus each byte zone emitted
// at most once" holds on the base priced cell because no
// designation faces exist there: every emitted payload byte is a
// source byte or a copied-column byte, each emitted at most once.
// A machine with designation faces breaks the second addend — N
// designations alias one subspan with zero column growth — so the
// transfer priced cell carries its own per-row ceiling below.
//
// Census corollary: `over_caps` counts the ledger entries whose
// body passes the length class, so `over_caps <= bodies.len()`, and
// the ledger is keyed by arena coordinates, so
// `bodies.len() < ROW_CEILING` — a downward crossing decrements a
// count its own upward crossing raised, and the subtraction cannot
// underflow.

/// Source bytes sit in the carrier: [`DocBytes::CAP`]'s enclosing
/// power of two.
#[cfg(any(
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
const SOURCE_CEILING: u64 = 1 << 31;

/// The store's copied byte column ends inside the `At32` offset
/// domain.
#[cfg(any(
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
const COLUMN_CEILING: u64 = 1 << 32;

/// Live rows sit in the arena domain.
#[cfg(any(
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
const ROW_CEILING: u64 = 1 << 31;

/// One live row's framing and scalar emission beyond the byte
/// columns: a minimal head word is at most five bytes, a scalar
/// value or LEN prefix at most ten more (group framing is two head
/// words, inside the same bound). Pinned against the encoders in
/// the shared-layer tests.
#[cfg(any(
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
const ROW_FRAMING_CEILING: u64 = 15;

/// Every exact sum of row prices sits below this ceiling — under
/// `2^36`, so every signed delta between two such sums widens into
/// `i64` with 27 bits to spare.
#[cfg(any(
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
pub(crate) const PRICE_CEILING: u64 =
    ROW_CEILING * ROW_FRAMING_CEILING + SOURCE_CEILING + COLUMN_CEILING;

/// One row's value-side emission under the transfer profile, proven
/// per row form: a designated payload sits in the length class
/// (< 2^31); an imported record's exact bytes fit its admitted
/// (≤ 2^31) source; a local whole-record alias prices the whole
/// occurrence at its one root row, itself inside the admitted-source
/// class; a grouped import root prices framing only.
#[cfg(any(
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
const VALUE_CEILING: u64 = 1 << 31;

/// The transfer profile's ceiling: designation aliasing lets N rows
/// each re-emit a whole subspan with zero column growth, so the sum
/// decomposes per row — framing plus one value-side emission each —
/// not per byte zone. Signed deltas still widen into `i64`, with
/// one bit to spare instead of the base cell's 27.
#[cfg(any(
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
pub(crate) const TRANSFER_PRICE_CEILING: u64 = ROW_CEILING * (ROW_FRAMING_CEILING + VALUE_CEILING);

/// The dialect test modules' giant-fixture serializer: each
/// giant row stages a real 2 GiB payload (no smaller input can
/// cross the length class end to end), and two staged
/// concurrently would double a peak footprint that already
/// dominates small CI hosts. The whole module is test territory —
/// the `std` name it declares reaches nothing shipped, and the
/// library proper names no `std` anywhere.
#[cfg(all(
    test,
    not(target_family = "wasm"),
    not(miri),
    any(feature = "priced-session-grouped", feature = "priced-session-groupless")
))]
pub(crate) mod giant_fixture {
    extern crate std;

    /// The one lock; poisoning is ignored — a panicked twin
    /// already failed its own row.
    pub static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
}

#[cfg(any(
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
#[allow(clippy::as_conversions, reason = "domain caps widen losslessly into the u64 ceilings")]
const _: () = {
    assert!(PRICE_CEILING == 38_654_705_664);
    assert!(PRICE_CEILING < 1 << 36);
    assert!(PRICE_CEILING < i64::MAX.unsigned_abs());
    // Each component ceiling encloses its owning domain.
    assert!((DocBytes::CAP as u64) < SOURCE_CEILING);
    assert!((At32::MAX.as_inner() as u64) < COLUMN_CEILING);
    // The arena domain's exact edge sits below the row ceiling.
    assert!(RowId::new((1 << 31) - 2).is_some());
    assert!(RowId::new((1 << 31) - 1).is_none());
};

#[cfg(any(
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
#[allow(clippy::as_conversions, reason = "domain caps widen losslessly into the u64 ceilings")]
const _: () = {
    assert!(TRANSFER_PRICE_CEILING == (1 << 62) + 15 * (1 << 31));
    assert!(TRANSFER_PRICE_CEILING < i64::MAX.unsigned_abs());
    // One value-side emission fits the row budget: the length class
    // and the admitted-source cap both end at or below 2^31.
    assert!((crate::wire::PayloadLen::MAX.as_inner() as u64) < VALUE_CEILING);
    assert!((DocBytes::CAP as u64) <= VALUE_CEILING);
    // The aliasing arc that falsified the base constant, as checked
    // arithmetic: 37,000 designations of a 1 MiB source payload — a
    // sum lawful designation faces produce — crosses the base
    // ceiling and stays under the transfer one (the positive
    // control for the theorem swap).
    assert!(37_000 * ((1 << 20) + 15) > PRICE_CEILING);
    assert!(37_000 * ((1 << 20) + 15) < TRANSFER_PRICE_CEILING);
    // The per-row worst case sums exactly to the ceiling's terms:
    // every arena row at full framing plus a whole value-side
    // emission each.
    assert!(
        ROW_CEILING * ROW_FRAMING_CEILING + ROW_CEILING * VALUE_CEILING == TRANSFER_PRICE_CEILING
    );
};

crate::revise::revising_store! {
    store borrow,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
}

crate::revise::revising_store! {
    store mixed,
    noun: "session",
    a_noun: "a session",
    A_noun: "A session",
}
