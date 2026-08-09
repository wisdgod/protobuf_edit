//! Tail-write buffer for reverse one-pass encoding.
//!
//! A forward encoder must pre-compute every sub-message length before it
//! can lay frames down front to back — a recursive measuring pass whose
//! nested lengths the writing pass then re-derives at each level. Writing
//! *backwards* removes the pre-computation entirely: a body is written
//! before its frame, so its length is the write cursor's travel, known
//! exactly when the frame is emitted.
//!
//! [`RevBuf`] owns one block; the valid output is its tail `buf[pos..]`
//! and `pos` counts down. Growth moves the finished tail to the end of a
//! larger block, so finished bytes are never invalidated. Error plumbing
//! is poison-based: a length-cap violation or allocation failure records
//! the first error, drops the block, and turns every later write into a
//! no-op (the check rides on the existing headroom branch, so the hot
//! path pays nothing); [`RevBuf::finish`] reports the failure once.

use alloc::vec::Vec;
use core::mem::MaybeUninit;

use crate::buf::Buf;
use crate::varint::Varint;

use super::EncodeError;

/// Protobuf message hard cap: bodies must stay below `i32::MAX` bytes.
const MAX_LEN: usize = i32::MAX as usize;

/// A byte slice viewed as uninit storage — the safe direction
/// (`MaybeUninit` only weakens the validity requirement).
#[inline(always)]
fn as_uninit(bytes: &[u8]) -> &[MaybeUninit<u8>] {
    // SAFETY: identical layout and alignment; every initialized byte is a
    // valid `MaybeUninit<u8>`.
    unsafe { core::slice::from_raw_parts(bytes.as_ptr().cast(), bytes.len()) }
}

/// Tail-write buffer: output accumulates backwards in `buf[pos..]`.
///
/// Buffer invariant: `pos <= buf.len()` and `buf[pos..]` is initialized —
/// `pos` starts at `buf.len()`, every write initializes `[new_pos,
/// old_pos)` as it descends, and growth copies exactly that initialized
/// tail to the new block's end. The block below `pos` is headroom and
/// never read, which is what lets the storage stay `MaybeUninit` with no
/// zero-fill on allocation or growth.
pub(crate) struct RevBuf {
    buf: Vec<MaybeUninit<u8>>,
    pos: usize,
    /// First failure, if any; writes are no-ops once set.
    poison: Option<EncodeError>,
}

impl RevBuf {
    /// Creates an empty buffer; the first write allocates (cold path).
    #[inline]
    pub(crate) const fn new() -> Self {
        Self { buf: Vec::new(), pos: 0, poison: None }
    }

    /// Creates a buffer with exactly `cap` bytes of headroom — one
    /// allocation up front for callers with a size prior. Exposes
    /// exactly `cap` (allocator rounding stays hidden in the block's
    /// spare capacity), so an *exact* prior finishes at `pos == 0` and
    /// [`take_buf`](Self::take_buf) skips its move. Allocation failure
    /// poisons the buffer (reported by [`finish`](Self::finish)), as it
    /// would on any write.
    pub(crate) fn with_capacity(cap: usize) -> Self {
        let mut rb = Self::new();
        if cap > 0 {
            let mut buf: Vec<MaybeUninit<u8>> = Vec::new();
            if buf.try_reserve_exact(cap).is_err() {
                rb.poison(EncodeError::AllocFailed);
                return rb;
            }
            // SAFETY: `MaybeUninit` imposes no validity requirement, and
            // the capacity was just reserved.
            unsafe { buf.set_len(cap) };
            rb.pos = cap;
            rb.buf = buf;
        }
        rb
    }

    /// Bytes written so far — the stable mark coordinate: growth rebases
    /// the internal cursor but never the written count. Take a mark
    /// before a body, pass it to [`body_len`](Self::body_len) after.
    #[inline]
    pub(crate) const fn written(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Body length since `mark`, saturating to 0 after poisoning (the
    /// value is then meaningless and [`finish`](Self::finish) reports
    /// the failure instead).
    #[inline]
    pub(crate) const fn body_len(&self, mark: usize) -> usize {
        self.written().saturating_sub(mark)
    }

    /// Ensures `need` bytes of headroom; `false` means the buffer is
    /// poisoned and the write must be skipped.
    #[inline]
    fn ensure(&mut self, need: usize) -> bool {
        if self.pos < need && !self.grow(need) {
            return false;
        }
        // SAFETY: on the grow path `grow` just set
        // `pos = new_len - written` with `new_len >= written + need`; on
        // the direct path `pos >= need` held already. `pos <= buf.len()`
        // is the struct invariant. Restating both facts here lets LLVM
        // drop the bounds checks of the `buf[pos - k..]` writes behind
        // this call, which `grow`'s `inline(never)` boundary would
        // otherwise discard.
        unsafe { core::hint::assert_unchecked(self.pos >= need && self.pos <= self.buf.len()) };
        true
    }

    /// Grows to at least `need` headroom, moving the finished tail to the
    /// new block's end; also the funnel where poisoned writes die.
    #[cold]
    #[inline(never)]
    fn grow(&mut self, need: usize) -> bool {
        if self.poison.is_some() {
            return false;
        }
        let written = self.buf.len() - self.pos;
        let target = (self.buf.len() * 2).max(written.saturating_add(need)).max(64);
        let mut new_buf: Vec<MaybeUninit<u8>> = Vec::new();
        if new_buf.try_reserve_exact(target).is_err() {
            self.poison(EncodeError::AllocFailed);
            return false;
        }
        // SAFETY: `MaybeUninit` imposes no validity requirement, and the
        // capacity was just reserved.
        unsafe { new_buf.set_len(new_buf.capacity()) };
        let new_len = new_buf.len();
        new_buf[new_len - written..].copy_from_slice(&self.buf[self.pos..]);
        self.buf = new_buf;
        self.pos = new_len - written;
        true
    }

    /// Records the first failure and drops the block, so every later
    /// write funnels into `grow` and exits without touching memory.
    #[cold]
    fn poison(&mut self, err: EncodeError) {
        self.poison.get_or_insert(err);
        self.buf = Vec::new();
        self.pos = 0;
    }

    /// Writes one byte.
    #[inline]
    pub(crate) fn put_byte(&mut self, byte: u8) {
        if !self.ensure(1) {
            return;
        }
        self.pos -= 1;
        self.buf[self.pos] = MaybeUninit::new(byte);
    }

    /// Writes a slice (it reads forward in the final output). The bulk
    /// entry point also carries the cumulative cap check: varint/byte
    /// writes can only overshoot the cap by a few bytes before a bulk
    /// write or [`finish`](Self::finish) catches it, which bounds total
    /// allocation without a per-write branch.
    #[inline]
    pub(crate) fn put_bytes(&mut self, bytes: &[u8]) {
        if self.written() + bytes.len() > MAX_LEN {
            self.poison(EncodeError::LengthOverflow);
            return;
        }
        if !self.ensure(bytes.len()) {
            return;
        }
        self.pos -= bytes.len();
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(as_uninit(bytes));
    }

    /// Writes a varint. The single-byte case — most tags, most small
    /// lengths — stays on the fast path; longer values step the cursor
    /// back by the exact encoded length and let the shared forward
    /// kernel fill the window in place, with no scratch copy.
    #[inline]
    pub(crate) fn put_varint64(&mut self, value: u64) {
        if value < 0x80 {
            self.put_byte(value as u8);
            return;
        }
        let len = crate::varint::encoded_len64(value) as usize;
        if !self.ensure(len) {
            return;
        }
        self.pos -= len;
        // SAFETY: `ensure` reserved `len` writable bytes at `pos`, and
        // `len` is the canonical encoded length — the write initializes
        // exactly `[pos, pos + len)`.
        unsafe {
            <u64 as Varint>::encode_to_ptr(self.buf.as_mut_ptr().add(self.pos).cast::<u8>(), value);
        }
    }

    /// [`put_varint64`](Self::put_varint64) over the `u32` domain (tags,
    /// length prefixes) — the narrower encoder is the point.
    #[inline]
    pub(crate) fn put_varint32(&mut self, value: u32) {
        if value < 0x80 {
            self.put_byte(value as u8);
            return;
        }
        let len = crate::varint::encoded_len32(value) as usize;
        if !self.ensure(len) {
            return;
        }
        self.pos -= len;
        // SAFETY: as in `put_varint64`.
        unsafe {
            <u32 as Varint>::encode_to_ptr(self.buf.as_mut_ptr().add(self.pos).cast::<u8>(), value);
        }
    }

    /// Writes a length prefix. A value over the message cap poisons the
    /// buffer; the truncated low bits written by a poisoned encode are
    /// bounded garbage that [`finish`](Self::finish) discards.
    #[inline]
    pub(crate) fn put_len(&mut self, len: usize) {
        if len > MAX_LEN {
            self.poison(EncodeError::LengthOverflow);
            return;
        }
        self.put_varint32(len as u32);
    }

    /// The encoded bytes, or the first failure the walk hit.
    ///
    /// # Errors
    /// `LengthOverflow` when a body or the total output exceeds the
    /// message cap, `AllocFailed` when growth failed.
    #[inline]
    pub(crate) fn finish(&self) -> Result<&[u8], EncodeError> {
        if let Some(err) = self.poison {
            return Err(err);
        }
        if self.written() > MAX_LEN {
            return Err(EncodeError::LengthOverflow);
        }
        Ok(self.out())
    }

    /// The written tail as initialized bytes.
    #[inline]
    fn out(&self) -> &[u8] {
        let tail = &self.buf[self.pos..];
        // SAFETY: the buffer invariant — everything at and above `pos`
        // was written (or copied from written bytes by growth).
        unsafe { core::slice::from_raw_parts(tail.as_ptr().cast::<u8>(), tail.len()) }
    }

    /// Moves the block out as a `Buf` whose front is the written tail
    /// (one in-place `copy_within`; the block's spare capacity rides
    /// along). Callers check [`finish`](Self::finish) first.
    ///
    /// # Errors
    /// `AllocFailed` on the cold copy-out path taken when the grown
    /// block's capacity exceeds `Buf`'s hard cap.
    pub(crate) fn take_buf(&mut self) -> Result<Buf, EncodeError> {
        let written = self.written();
        if self.buf.capacity() > MAX_LEN {
            // The doubled block cannot become a `Buf` (its capacity is
            // over the cap even though the payload is not): copy out.
            let mut out = Buf::with_capacity(written as u32).map_err(EncodeError::from)?;
            out.extend_from_slice(self.out()).map_err(EncodeError::from)?;
            return Ok(out);
        }
        let mut block = core::mem::take(&mut self.buf);
        if self.pos != 0 {
            // An exact capacity prior lands the tail at the block start,
            // making this move (the only O(bytes) overhead of the
            // reverse form) vanish.
            block.copy_within(self.pos.., 0);
        }
        self.pos = 0;
        let ptr = block.as_mut_ptr();
        let cap = block.capacity();
        core::mem::forget(block);
        // SAFETY: same allocation (ptr/cap taken from the forgotten
        // `Vec`; `MaybeUninit<u8>` and `u8` share layout); the first
        // `written` bytes were just copied from the initialized tail and
        // `written <= cap`.
        let vec = unsafe { Vec::from_raw_parts(ptr.cast::<u8>(), written, cap) };
        Ok(Buf::from_vec(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_match_forward_encoders() {
        for &v in &[0u64, 1, 0x7F, 0x80, 0x3FFF, 0x4000, u32::MAX as u64, u64::MAX] {
            let mut forward = Buf::new();
            crate::varint::encode64(&mut forward, v).unwrap();
            let mut rb = RevBuf::new();
            rb.put_varint64(v);
            assert_eq!(rb.finish().unwrap(), forward.as_slice(), "value {v}");
        }
        for &v in &[0u32, 1, 0x7F, 0x80, 0x3FFF, 0x4000, u32::MAX] {
            let mut forward = Buf::new();
            crate::varint::encode32(&mut forward, v).unwrap();
            let mut rb = RevBuf::new();
            rb.put_varint32(v);
            assert_eq!(rb.finish().unwrap(), forward.as_slice(), "value {v}");
        }
    }

    #[test]
    fn writes_read_forward() {
        let mut rb = RevBuf::new();
        let mark = rb.written();
        rb.put_bytes(b"hi");
        rb.put_len(rb.body_len(mark));
        rb.put_varint32(0x0A);
        assert_eq!(rb.finish().unwrap(), &[0x0A, 0x02, b'h', b'i']);
    }

    #[test]
    fn growth_preserves_written_tail() {
        let mut rb = RevBuf::new();
        for i in 0..2048u32 {
            rb.put_byte((i % 251) as u8);
        }
        let out = rb.finish().unwrap();
        assert_eq!(out.len(), 2048);
        // Written backwards: out[k] corresponds to i = 2047 - k.
        for (k, &byte) in out.iter().enumerate() {
            assert_eq!(u32::from(byte), (2047 - k as u32) % 251, "offset {k}");
        }
    }

    #[test]
    fn marks_survive_growth() {
        // A mark taken before growth must still frame the body exactly:
        // the written count is growth-invariant where a raw cursor
        // position is not.
        let mut rb = RevBuf::new();
        let mark = rb.written();
        for _ in 0..300 {
            rb.put_byte(0xAB);
        }
        assert_eq!(rb.body_len(mark), 300);
        rb.put_len(rb.body_len(mark));
        let out = rb.finish().unwrap();
        assert_eq!(&out[..2], &[0xAC, 0x02]); // varint(300)
        assert!(out[2..].iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn oversized_len_poisons_until_finish() {
        let mut rb = RevBuf::new();
        rb.put_bytes(b"payload");
        rb.put_len(MAX_LEN + 1);
        rb.put_varint32(0x0A); // ignored: poisoned
        assert_eq!(rb.finish(), Err(EncodeError::LengthOverflow));
    }

    #[test]
    fn with_capacity_preallocates() {
        let mut rb = RevBuf::with_capacity(128);
        for i in 0..100u8 {
            rb.put_byte(i);
        }
        let out = rb.finish().unwrap();
        assert_eq!(out.len(), 100);
        assert_eq!(out[0], 99, "writes read forward");
    }

    #[test]
    fn take_buf_fronts_the_tail() {
        let mut rb = RevBuf::new();
        rb.put_bytes(b"tail");
        rb.put_bytes(b"head ");
        rb.finish().unwrap();
        let buf = rb.take_buf().unwrap();
        assert_eq!(buf.as_slice(), b"head tail");
    }
}
