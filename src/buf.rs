//! Compact byte buffer with inline, owned-heap, and borrowed representations.
//!
//! Layout model:
//! - inline: up to `INLINE_CAP` bytes stored inside the struct
//! - heap: owned allocation for larger payloads
//! - borrowed: read-only external memory view that can be upgraded to owned
//!
//! Safety model:
//! - tag payload and allocation metadata must remain consistent
//! - borrowed buffers must never outlive the referenced memory
//! - `set_len` must only expose initialized bytes

use alloc::alloc::{alloc, dealloc, handle_alloc_error, realloc, Layout};
use core::fmt;
use core::intrinsics;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::slice;

/// Inline capacity in bytes.
pub const INLINE_CAP: u32 = 12;
/// Hard max capacity.
const MAX_CAP: u32 = i32::MAX as u32;

const TAG_BORROWED: u32 = MAX_CAP + 1;
const TAG_PAYLOAD_MASK: u32 = !TAG_BORROWED;

/// Error for fallible allocation/growth APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufAllocError {
    /// Capacity arithmetic overflowed `u32` or exceeded `MAX_CAP`.
    CapacityOverflow,
}

/// Compact 16-byte buffer storing payloads inline (up to `INLINE_CAP` bytes),
/// in an owned heap allocation, or as a borrowed read-only view.
///
/// Capacity is hard-capped at `i32::MAX` bytes; fallible APIs report
/// [`BufAllocError::CapacityOverflow`] beyond that.
pub union Buf {
    inline: InlineData,
    heap: HeapData,
}

// SAFETY:
// - `Buf` only contains raw bytes and ownership metadata.
// - Owned storage follows allocator thread-safety guarantees.
// - Borrowed storage construction is `unsafe`; caller must guarantee pointee
//   validity/lifetime and absence of unsynchronized mutation.
unsafe impl Send for Buf {}
// SAFETY: same rationale as `Send`; shared access is read-only unless guarded by `&mut Buf`.
unsafe impl Sync for Buf {}

#[derive(Copy, Clone)]
struct InlineData {
    buf: MaybeUninit<[u8; 12]>,
    tag: u32, // bit31=borrowed(0), low31=inline len
}

#[derive(Copy, Clone)]
struct HeapData {
    ptr: NonNull<u8>,
    len: u32,
    #[cfg(target_pointer_width = "32")]
    _padding: u32,
    tag: u32, // bit31=is_borrowed, low31=heap cap
}

#[derive(Clone, Copy)]
struct Triple {
    ptr: *const u8,
    len: u32,
    cap: u32,
    inline: bool,
    borrowed: bool,
}

struct TripleMut {
    buf: *mut Buf,
    ptr: *mut u8,
    len: u32,
    cap: u32,
    inline: bool,
    borrowed: bool,
}

impl TripleMut {
    #[inline]
    const fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    #[inline]
    const fn len(&self) -> u32 {
        self.len
    }

    #[inline]
    const fn cap(&self) -> u32 {
        self.cap
    }

    #[inline]
    const unsafe fn set_len(&mut self, new_len: u32) {
        debug_assert!(new_len <= self.cap);
        debug_assert!(!self.inline || !self.borrowed);
        if self.inline {
            (*self.buf).inline.tag = make_tag(new_len, false);
        } else {
            (*self.buf).heap.len = new_len;
        }
        self.len = new_len;
    }
}

const _: () = {
    assert!(MAX_CAP == TAG_PAYLOAD_MASK);
    assert!(core::mem::size_of::<Buf>() == 16);
    assert!(core::mem::size_of::<InlineData>() == 16);
    assert!(core::mem::size_of::<HeapData>() == 16);
    assert!(core::mem::offset_of!(InlineData, tag) == 12);
    assert!(core::mem::offset_of!(HeapData, tag) == 12);
};

impl Buf {
    /// Creates an empty buffer using inline storage.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { inline: InlineData { buf: MaybeUninit::uninit(), tag: 0 } }
    }

    /// Creates an empty owned buffer with room for at least `capacity` bytes.
    ///
    /// # Errors
    /// Returns `CapacityOverflow` if `capacity` exceeds the hard cap.
    #[inline]
    pub fn with_capacity(capacity: u32) -> Result<Self, BufAllocError> {
        let mut b = Self::new();
        b.try_reserve_exact(capacity)?;
        Ok(b)
    }

    /// Builds an owned `Buf` from a `Vec<u8>`.
    ///
    /// Small payloads (`len <= INLINE_CAP`) are copied into the inline representation.
    ///
    /// # Panics
    /// Panics if the vector length or capacity exceeds `MAX_CAP`.
    #[must_use]
    pub fn from_vec(bytes: alloc::vec::Vec<u8>) -> Self {
        assert!(bytes.len() <= MAX_CAP as usize, "vec len exceeds MAX_CAP");

        let len = bytes.len() as u32;
        if len <= INLINE_CAP {
            let mut out = Self::new();
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    out.inline.buf.as_mut_ptr().cast::<u8>(),
                    len as usize,
                );
                out.inline.tag = make_tag(len, false);
            }
            return out;
        }

        let mut bytes = ManuallyDrop::new(bytes);
        let cap = bytes.capacity();
        assert!(cap <= MAX_CAP as usize, "vec capacity exceeds MAX_CAP");
        let ptr = bytes.as_mut_ptr();
        let ptr = NonNull::new(ptr).expect("Vec::as_mut_ptr returned null");

        Self {
            heap: HeapData {
                ptr,
                len,
                #[cfg(target_pointer_width = "32")]
                _padding: 0,
                tag: make_tag(cap as u32, false),
            },
        }
    }

    /// Builds a borrowed `Buf` from raw pointer/length.
    ///
    /// # Panics
    /// Panics if `len` exceeds the hard cap.
    ///
    /// # Safety
    /// - `ptr` must point to at least `len` readable bytes.
    /// - That memory must remain valid for the entire lifetime of returned `Buf`.
    /// - The pointed memory must not be mutated through this `Buf`.
    #[inline]
    #[must_use]
    pub const unsafe fn from_borrowed_parts(ptr: NonNull<u8>, len: u32) -> Self {
        assert!(len <= MAX_CAP, "borrowed len exceeds MAX_CAP");
        Self {
            heap: HeapData {
                ptr,
                len,
                #[cfg(target_pointer_width = "32")]
                _padding: 0,
                tag: make_tag(len, true), // cap = len for borrowed buffers (read-only view)
            },
        }
    }

    /// Builds a borrowed `Buf` from a byte slice.
    ///
    /// # Panics
    /// Panics if the slice length exceeds the hard cap.
    ///
    /// # Safety
    /// - The input slice must outlive all uses of the returned `Buf`.
    /// - The referenced bytes are treated as borrowed/read-only payload.
    #[inline]
    #[must_use]
    pub const unsafe fn from_borrowed_slice(slice: &[u8]) -> Self {
        assert!(slice.len() <= MAX_CAP as usize, "borrowed len exceeds MAX_CAP");
        let len = slice.len() as u32;
        // SAFETY: `slice.as_ptr()` is non-null even for empty slices, and the caller must ensure
        // the backing memory lives as long as this Buf is used.
        let ptr = unsafe { NonNull::new_unchecked(slice.as_ptr().cast_mut()) };
        unsafe { Self::from_borrowed_parts(ptr, len) }
    }

    /// Builds a borrowed `Buf` over `'static` bytes.
    ///
    /// # Panics
    /// Panics if the slice length exceeds the hard cap.
    #[inline]
    #[must_use]
    pub const fn from_static(bytes: &'static [u8]) -> Self {
        unsafe { Self::from_borrowed_slice(bytes) }
    }

    #[inline]
    const fn raw_tag(&self) -> u32 {
        unsafe { self.inline.tag }
    }

    /// Whether the payload lives in the inline representation.
    #[inline]
    #[must_use]
    pub const fn is_inline(&self) -> bool {
        let tag = self.raw_tag();
        let payload = tag_payload(tag);
        !tag_is_borrowed(tag) && payload <= INLINE_CAP
    }

    /// Whether the payload is a borrowed read-only view of external memory.
    #[inline]
    #[must_use]
    pub const fn is_borrowed(&self) -> bool {
        tag_is_borrowed(self.raw_tag())
    }

    /// Whether the payload lives outside the inline representation.
    #[inline]
    #[must_use]
    pub const fn spilled(&self) -> bool {
        !self.is_inline()
    }

    /// Payload length in bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> u32 {
        let tag = self.raw_tag();
        let payload = tag_payload(tag);
        if !tag_is_borrowed(tag) && payload <= INLINE_CAP {
            payload
        } else {
            unsafe { self.heap.len }
        }
    }

    /// Whether the payload is zero bytes long.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Writable capacity in bytes: `INLINE_CAP` when inline, the allocation
    /// size when owned on the heap, and `len()` when borrowed.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> u32 {
        let tag = self.raw_tag();
        let payload = tag_payload(tag);
        if !tag_is_borrowed(tag) && payload <= INLINE_CAP { INLINE_CAP } else { payload }
    }

    #[inline]
    const fn triple(&self) -> Triple {
        unsafe {
            let tag = self.raw_tag();
            let payload = tag_payload(tag);
            let borrowed = tag_is_borrowed(tag);
            let triple = if !borrowed && payload <= INLINE_CAP {
                Triple {
                    ptr: self.inline.buf.as_ptr().cast::<u8>(),
                    len: payload,
                    cap: INLINE_CAP,
                    inline: true,
                    borrowed: false,
                }
            } else {
                Triple {
                    ptr: self.heap.ptr.as_ptr().cast_const(),
                    len: self.heap.len,
                    cap: payload,
                    inline: false,
                    borrowed,
                }
            };
            intrinsics::assume(triple.cap <= MAX_CAP && triple.len <= triple.cap);
            triple
        }
    }

    #[inline]
    const fn triple_mut(&mut self) -> TripleMut {
        unsafe {
            let tag = self.raw_tag();
            let payload = tag_payload(tag);
            let borrowed = tag_is_borrowed(tag);
            let (ptr, len, cap, inline, borrowed) = if !borrowed && payload <= INLINE_CAP {
                (self.inline.buf.as_mut_ptr().cast::<u8>(), payload, INLINE_CAP, true, false)
            } else {
                (self.heap.ptr.as_ptr(), self.heap.len, payload, false, borrowed)
            };
            intrinsics::assume(cap <= MAX_CAP && len <= cap);
            TripleMut { buf: self, ptr, len, cap, inline, borrowed }
        }
    }

    /// Payload bytes as a shared slice.
    #[inline]
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        unsafe {
            let t = self.triple();
            slice::from_raw_parts(t.ptr, t.len as usize)
        }
    }

    /// Payload bytes as a mutable slice; copies borrowed data into owned
    /// storage first.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.make_owned();
        unsafe {
            let t = self.triple_mut();
            slice::from_raw_parts_mut(t.ptr(), t.len() as usize)
        }
    }

    /// Copies a borrowed payload into owned storage; no-op when already owned.
    ///
    /// Small payloads move into the inline representation, larger ones into a
    /// fresh heap allocation.
    pub fn make_owned(&mut self) {
        let t = self.triple();
        if !t.borrowed {
            return;
        }
        debug_assert!(!t.inline, "inline storage should never be marked borrowed");

        let len = t.len;

        unsafe {
            if len <= INLINE_CAP {
                let old_ptr = self.heap.ptr.as_ptr();

                let mut inline_data =
                    InlineData { buf: MaybeUninit::uninit(), tag: make_tag(len, false) };
                ptr::copy_nonoverlapping(
                    old_ptr,
                    inline_data.buf.as_mut_ptr().cast::<u8>(),
                    len as usize,
                );
                self.inline = inline_data;
                return;
            }

            let new_cap = match growth_target(len) {
                Ok(cap) => cap,
                // SAFETY: `triple` guarantees `len <= MAX_CAP`, the only
                // failure condition of `growth_target`.
                Err(_) => intrinsics::unreachable(),
            };
            let layout = layout_u8(new_cap);
            let new_ptr = alloc_non_null(layout);
            ptr::copy_nonoverlapping(t.ptr, new_ptr.as_ptr(), len as usize);
            self.heap = HeapData {
                ptr: new_ptr,
                len,
                #[cfg(target_pointer_width = "32")]
                _padding: 0,
                tag: make_tag(new_cap, false),
            };
        }
    }

    /// Read-only pointer to the payload bytes.
    #[inline]
    #[must_use]
    pub const fn as_ptr(&self) -> *const u8 {
        self.triple().ptr
    }

    /// Mutable pointer to the payload bytes; copies borrowed data into owned
    /// storage first.
    #[inline]
    pub fn as_ptr_mut(&mut self) -> *mut u8 {
        self.make_owned();
        self.triple_mut().ptr()
    }

    /// Set logical length without initializing new bytes.
    ///
    /// # Safety
    /// - `new_len` must be `<= capacity()`.
    /// - Any newly exposed bytes in `0..new_len` must be initialized.
    /// - For borrowed buffers, caller must uphold borrowed memory validity.
    #[inline]
    pub const unsafe fn set_len(&mut self, new_len: u32) {
        let mut t = self.triple_mut();
        debug_assert!(new_len <= t.cap());
        t.set_len(new_len);
    }

    /// Reserves `additional` bytes and returns the write pointer one past
    /// the current payload end, for in-place tail encoding without a
    /// scratch copy. Bytes written there become visible only after a
    /// matching [`set_len`](Self::set_len).
    ///
    /// The storage is owned on return: `additional >= 1` forces a
    /// borrowed payload through the reserve path, which copies it out.
    ///
    /// # Errors
    /// Returns `CapacityOverflow` if growth would exceed the hard cap.
    #[inline]
    pub(crate) fn reserve_tail(&mut self, additional: u32) -> Result<*mut u8, BufAllocError> {
        debug_assert!(additional >= 1, "reserve_tail needs a non-empty window");
        self.try_reserve(additional)?;
        let t = self.triple_mut();
        debug_assert!(!t.borrowed);
        // SAFETY: `try_reserve` guaranteed `len + additional <= cap`, so
        // one-past-the-payload stays inside the allocation.
        Ok(unsafe { t.ptr().add(t.len() as usize) })
    }

    /// Resets the payload length to zero without touching capacity.
    #[inline]
    pub const fn clear(&mut self) {
        unsafe { self.set_len(0) }
    }

    /// Appends one byte.
    ///
    /// # Errors
    /// Returns `CapacityOverflow` if growth would exceed the hard cap.
    #[inline]
    pub fn push(&mut self, b: u8) -> Result<(), BufAllocError> {
        if self.len() == self.capacity() {
            self.grow_for_push()?;
        }
        unsafe {
            let mut t = self.triple_mut();
            let len = t.len();
            t.ptr().add(len as usize).write(b);
            t.set_len(len + 1);
        }
        Ok(())
    }

    #[cold]
    fn grow_for_push(&mut self) -> Result<(), BufAllocError> {
        debug_assert_eq!(self.len(), self.capacity());
        let required = self.len().checked_add(1).ok_or(BufAllocError::CapacityOverflow)?;
        let new_cap = growth_target(required)?;
        self.realloc_exact(new_cap);
        Ok(())
    }

    /// Removes and returns the last byte; `None` when empty.
    #[inline]
    pub const fn pop(&mut self) -> Option<u8> {
        let mut t = self.triple_mut();
        let len = t.len();
        if len == 0 {
            return None;
        }
        unsafe {
            let idx = len - 1;
            let v = t.ptr().add(idx as usize).read();
            t.set_len(idx);
            Some(v)
        }
    }

    /// Appends all bytes from `src`.
    ///
    /// # Errors
    /// Returns `CapacityOverflow` if growth would exceed the hard cap.
    #[inline]
    pub fn extend_from_slice(&mut self, src: &[u8]) -> Result<(), BufAllocError> {
        let add = u32::try_from(src.len()).map_err(|_| BufAllocError::CapacityOverflow)?;
        self.try_reserve(add)?;
        unsafe {
            let mut t = self.triple_mut();
            let len = t.len();
            ptr::copy_nonoverlapping(src.as_ptr(), t.ptr().add(len as usize), src.len());
            t.set_len(len + add);
        }
        Ok(())
    }

    /// Shortens the payload to `len` bytes; no-op when already shorter.
    #[inline]
    pub const fn truncate(&mut self, len: u32) {
        if len >= self.len() {
            return;
        }
        unsafe { self.set_len(len) }
    }

    /// Reserves capacity for at least `additional` more bytes, growing
    /// geometrically.
    ///
    /// # Panics
    /// Panics if growth would exceed the hard cap; use `try_reserve` to handle
    /// that case.
    #[inline]
    pub fn reserve(&mut self, additional: u32) {
        if let Err(e) = self.try_reserve(additional) {
            intrinsics::cold_path();
            panic!("Buf::reserve failed: {e:?}");
        }
    }

    /// Reserves capacity for at least `additional` more bytes, growing
    /// geometrically.
    ///
    /// # Errors
    /// Returns `CapacityOverflow` if growth would exceed the hard cap.
    pub fn try_reserve(&mut self, additional: u32) -> Result<(), BufAllocError> {
        let t = self.triple();

        if t.cap - t.len >= additional {
            return Ok(());
        }

        let required = t.len.checked_add(additional).ok_or(BufAllocError::CapacityOverflow)?;
        let new_cap = growth_target(required)?;
        self.realloc_exact(new_cap);
        Ok(())
    }

    /// Reserves capacity for exactly `additional` more bytes.
    ///
    /// # Panics
    /// Panics if growth would exceed the hard cap; use `try_reserve_exact` to
    /// handle that case.
    #[inline]
    pub fn reserve_exact(&mut self, additional: u32) {
        if let Err(e) = self.try_reserve_exact(additional) {
            intrinsics::cold_path();
            panic!("Buf::reserve_exact failed: {e:?}");
        }
    }

    /// Reserves capacity for exactly `additional` more bytes.
    ///
    /// # Errors
    /// Returns `CapacityOverflow` if growth would exceed the hard cap.
    pub fn try_reserve_exact(&mut self, additional: u32) -> Result<(), BufAllocError> {
        let t = self.triple();

        if t.cap - t.len >= additional {
            return Ok(());
        }

        let new_cap = t.len.checked_add(additional).ok_or(BufAllocError::CapacityOverflow)?;

        if new_cap > MAX_CAP {
            return Err(BufAllocError::CapacityOverflow);
        }

        self.realloc_exact(new_cap);
        Ok(())
    }

    /// Moves the payload into owned storage of exactly `new_cap` bytes:
    /// inline when `new_cap <= INLINE_CAP`, otherwise a heap allocation.
    /// Borrowed payloads are copied and become owned.
    ///
    /// # Panics
    /// Panics unless `len <= new_cap <= MAX_CAP`. The lower bound is
    /// load-bearing for memory safety (the body copies `len` bytes into the
    /// new storage); every caller validates the range before calling.
    fn realloc_exact(&mut self, new_cap: u32) {
        let t = self.triple();
        let len = t.len;
        let cap = t.cap;
        let inline = t.inline;
        let borrowed = t.borrowed;

        assert!(len <= new_cap && new_cap <= MAX_CAP, "realloc_exact capacity out of range");

        unsafe {
            if inline {
                if new_cap <= INLINE_CAP {
                    return;
                }

                let layout = layout_u8(new_cap);
                let new_ptr = alloc_non_null(layout);
                ptr::copy_nonoverlapping(
                    self.inline.buf.as_ptr().cast::<u8>(),
                    new_ptr.as_ptr(),
                    len as usize,
                );
                self.heap = HeapData {
                    ptr: new_ptr,
                    len,
                    #[cfg(target_pointer_width = "32")]
                    _padding: 0,
                    tag: make_tag(new_cap, false),
                };
                return;
            }

            if new_cap <= INLINE_CAP {
                let old_ptr = self.heap.ptr.as_ptr();
                let old_cap = tag_payload(self.heap.tag);
                let old_borrowed = tag_is_borrowed(self.heap.tag);

                let mut inline_data =
                    InlineData { buf: MaybeUninit::uninit(), tag: make_tag(len, false) };
                ptr::copy_nonoverlapping(
                    old_ptr,
                    inline_data.buf.as_mut_ptr().cast::<u8>(),
                    len as usize,
                );
                self.inline = inline_data;
                if !old_borrowed {
                    dealloc(old_ptr, layout_u8(old_cap));
                }
                return;
            }

            if new_cap == cap {
                return;
            }

            if borrowed {
                let layout = layout_u8(new_cap);
                let new_ptr = alloc_non_null(layout);
                ptr::copy_nonoverlapping(self.heap.ptr.as_ptr(), new_ptr.as_ptr(), len as usize);
                self.heap.ptr = new_ptr;
                self.heap.tag = make_tag(new_cap, false);
                return;
            }

            let old_cap = tag_payload(self.heap.tag);
            let old_layout = layout_u8(old_cap);
            let new_ptr = realloc_non_null(self.heap.ptr.as_ptr(), old_layout, new_cap);
            self.heap.ptr = new_ptr;
            self.heap.tag = make_tag(new_cap, false);
        }
    }

    /// Reduces capacity to match the current length; no-op for inline storage
    /// or when capacity is already tight.
    pub fn shrink_to_fit(&mut self) {
        let t = self.triple();
        if !t.inline && t.cap > t.len {
            self.realloc_exact(t.len);
        }
    }

    /// Forces the backing storage onto the heap.
    ///
    /// After this call, the data pointer returned by `as_ptr()` / `as_slice()`
    /// remains valid across moves of the `Buf` value itself. No-op when the
    /// payload is empty or already on the heap (owned or borrowed).
    pub fn ensure_heap(&mut self) {
        if self.is_inline() && !self.is_empty() {
            self.realloc_exact(INLINE_CAP + 1);
        }
    }

    /// Converts into a `Vec<u8>`, transferring the heap allocation when owned
    /// and copying the bytes otherwise (inline or borrowed).
    #[must_use]
    pub fn into_vec(self) -> alloc::vec::Vec<u8> {
        let t = self.triple();
        unsafe {
            if t.inline || t.borrowed {
                slice::from_raw_parts(t.ptr, t.len as usize).to_vec()
            } else {
                let ptr = self.heap.ptr.as_ptr();
                let len = t.len as usize;
                let cap = t.cap as usize;
                let v = alloc::vec::Vec::from_raw_parts(ptr, len, cap);
                core::mem::forget(self);
                v
            }
        }
    }
}

impl Drop for Buf {
    fn drop(&mut self) {
        unsafe {
            let t = self.triple();
            if !t.inline && !t.borrowed {
                dealloc(self.heap.ptr.as_ptr(), layout_u8(t.cap));
            }
        }
    }
}

impl Default for Buf {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl From<alloc::vec::Vec<u8>> for Buf {
    #[inline]
    fn from(bytes: alloc::vec::Vec<u8>) -> Self {
        Self::from_vec(bytes)
    }
}

impl Deref for Buf {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DerefMut for Buf {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Clone for Buf {
    fn clone(&self) -> Self {
        let mut out = Self::new();
        out.try_reserve_exact(self.len()).expect("clone reserve_exact must not fail");
        out.extend_from_slice(self.as_slice())
            .expect("clone reserve/extend must not fail after reserve_exact");
        out
    }
}

impl PartialEq for Buf {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for Buf {}

impl fmt::Debug for Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Buf").field(&self.as_slice()).finish()
    }
}

#[inline]
const fn tag_payload(tag: u32) -> u32 {
    tag & TAG_PAYLOAD_MASK
}

#[inline]
const fn tag_is_borrowed(tag: u32) -> bool {
    (tag & TAG_BORROWED) != 0
}

#[inline]
const fn make_tag(payload: u32, borrowed: bool) -> u32 {
    debug_assert!(payload <= MAX_CAP);
    payload | if borrowed { TAG_BORROWED } else { 0 }
}

#[inline]
const fn layout_u8(n: u32) -> Layout {
    debug_assert!(n <= MAX_CAP);
    unsafe { Layout::from_size_align_unchecked(n as usize, 1) }
}

#[inline]
const fn growth_target(required: u32) -> Result<u32, BufAllocError> {
    if required > MAX_CAP {
        return Err(BufAllocError::CapacityOverflow);
    }
    if required <= INLINE_CAP {
        return Ok(required);
    }
    match required.checked_next_power_of_two() {
        Some(next_pow2) if next_pow2 != TAG_BORROWED => Ok(next_pow2),
        Some(_) => Ok(MAX_CAP),
        _ => unsafe {
            // Because required <= i32::MAX
            intrinsics::unreachable();
        },
    }
}

#[inline]
unsafe fn alloc_non_null(layout: Layout) -> NonNull<u8> {
    let raw = alloc(layout);
    if let Some(ptr) = NonNull::new(raw) {
        ptr
    } else {
        intrinsics::cold_path();
        handle_alloc_error(layout);
    }
}

#[inline]
unsafe fn realloc_non_null(ptr: *mut u8, old_layout: Layout, new_cap: u32) -> NonNull<u8> {
    let raw = realloc(ptr, old_layout, new_cap as usize);
    NonNull::new(raw).unwrap_or_else(|| {
        intrinsics::cold_path();
        handle_alloc_error(layout_u8(new_cap));
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::{growth_target, Buf, BufAllocError, INLINE_CAP, MAX_CAP};

    #[test]
    fn growth_target_can_reach_max_cap() {
        assert_eq!(growth_target(MAX_CAP).unwrap(), MAX_CAP);
        assert_eq!(growth_target(MAX_CAP - 1).unwrap(), MAX_CAP);
    }

    #[test]
    fn growth_target_rejects_over_max_cap() {
        assert_eq!(growth_target(MAX_CAP + 1), Err(BufAllocError::CapacityOverflow));
    }

    #[test]
    fn buf_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Buf>();
    }

    #[test]
    fn from_vec_inlines_small_payload() {
        let buf = Buf::from_vec(vec![1, 2, 3]);
        assert!(buf.is_inline());
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_slice(), &[1, 2, 3]);
    }

    #[test]
    fn from_vec_reuses_allocation_for_large_payload() {
        let len = (INLINE_CAP + 1) as usize;
        let mut v = vec![0u8; len];
        v[0] = 7;
        v[len - 1] = 9;

        let ptr = v.as_ptr();
        let cap = v.capacity() as u32;

        let buf = Buf::from_vec(v);
        assert!(!buf.is_inline());
        assert!(!buf.is_borrowed());
        assert_eq!(buf.as_ptr(), ptr);
        assert_eq!(buf.len(), len as u32);
        assert_eq!(buf.capacity(), cap);
        assert_eq!(buf.as_slice()[0], 7);
        assert_eq!(buf.as_slice()[len - 1], 9);

        let v2 = buf.into_vec();
        assert_eq!(v2.as_ptr(), ptr);
        assert_eq!(v2.len(), len);
        assert_eq!(v2.capacity(), cap as usize);
    }
}
