//! The fixed families' shared carving stratum: one caller slab,
//! one head alignment, typed extents split off front to back in
//! descending alignment order.
//!
//! Every fixed cell borrows its whole working set as one slab
//! (`&mut [MaybeUninit<u8>]`) and carves it once at the door. This
//! module carries the carve mechanism alone — the split and its
//! alignment proof; each family keeps its own lane types over the
//! carved extents, its own capacity field types, and its own
//! pricing arithmetic.
//!
//! The carve-order theorem: the head aligns once to the ladder's
//! declared `HEAD_ALIGN` — its maximum lane alignment, derived per
//! ladder through [`head_align`] — lanes split in descending
//! alignment order ([`descending`], const-asserted per ladder),
//! and each lane's byte size is a multiple of its own alignment,
//! hence of every later lane's smaller-or-equal alignment. The
//! running offset therefore stays aligned for every lane and no
//! interior padding exists, so a ladder's exact price is the
//! head's worst-case pad (`HEAD_ALIGN - 1`) plus the lanes' exact
//! byte sizes, at any slab address.

use core::mem::MaybeUninit;

/// The ladder's head alignment: its maximum lane alignment (`1`
/// for a ladder of bare bytes, which needs no head step). Each
/// ladder emission derives its `HEAD_ALIGN` through this from the
/// one lane list, so the declared parameter and the ladder's
/// maximum lane alignment cannot disagree; [`Carver::split`]
/// refuses any lane aligned past the declaration at compile time.
pub(crate) const fn head_align(aligns: &[usize]) -> usize {
    let mut max = 1;
    let mut i = 0;
    while i < aligns.len() {
        if aligns[i] > max {
            max = aligns[i];
        }
        i += 1;
    }
    max
}

/// The carve-order theorem's static side: true exactly when every
/// entry is at most its predecessor. Each ladder emission
/// const-asserts its whole lane list's alignments through this at
/// module scope, so an out-of-order lane is a compile error, never
/// a misaligned carve.
pub(crate) const fn descending(aligns: &[usize]) -> bool {
    let mut i = 1;
    while i < aligns.len() {
        if aligns[i] > aligns[i - 1] {
            return false;
        }
        i += 1;
    }
    true
}

/// One door's carve over the caller's slab: aligns once to the
/// ladder's `HEAD_ALIGN`, then splits typed extents front to back
/// in the ladder's descending alignment order. The door judged the
/// slab against the ladder's exact price — worst-case head pad
/// included — before constructing this, so every split below is in
/// bounds by the pricing theorem.
pub(crate) struct Carver<'s, const HEAD_ALIGN: usize> {
    rest: &'s mut [MaybeUninit<u8>],
}

impl<'s, const HEAD_ALIGN: usize> Carver<'s, HEAD_ALIGN> {
    /// Aligns the slab head to `HEAD_ALIGN` and takes custody of
    /// the rest. The door's demand judgment covered the worst-case
    /// pad (`HEAD_ALIGN - 1`).
    pub(crate) fn new(slab: &'s mut [MaybeUninit<u8>]) -> Self {
        let pad = slab.as_ptr().addr().wrapping_neg() % HEAD_ALIGN;
        debug_assert!(pad <= slab.len(), "the door's demand judgment covered the pad");
        let (_, rest) = slab.split_at_mut(pad);
        Self { rest }
    }

    /// Splits `count` slots of `T` off the front as one raw
    /// uninitialized extent — each family's lane constructor wraps
    /// it under that family's own element law.
    ///
    /// The head is aligned for `T` by the carve theorem: it starts
    /// `HEAD_ALIGN`-aligned, every lane's byte size is a multiple
    /// of its own alignment, and the ladder this door carves from
    /// const-asserts its descending order at module scope — so the
    /// running offset is always a multiple of the next lane's
    /// alignment. The split can neither overflow nor run short:
    /// the door judged the slab against the ladder's price, whose
    /// arithmetic bounds every listed lane's exact byte size (an
    /// unsatisfiable demand refuses at the door and never reaches
    /// the carve).
    pub(crate) fn split<T>(&mut self, count: usize) -> &'s mut [MaybeUninit<T>] {
        const {
            assert!(align_of::<T>() <= HEAD_ALIGN, "lane alignment exceeds the ladder's head");
        }
        debug_assert!(
            self.rest.as_ptr().addr().is_multiple_of(align_of::<T>()),
            "descending-alignment carve order keeps every lane head aligned"
        );
        let (head, rest) = core::mem::take(&mut self.rest).split_at_mut(count * size_of::<T>());
        self.rest = rest;
        // SAFETY: `head` spans exactly `count * size_of::<T>()`
        // bytes of one exclusive borrow, and its start is aligned
        // for `T` — the head aligned once to the ladder's declared
        // ceiling and the ladder const-asserts its descending order
        // at module scope, so the running offset stays a multiple
        // of every later alignment (the debug assert above restates
        // it); `MaybeUninit<u8>` bytes reinterpret as
        // `MaybeUninit<T>` slots without any validity claim.
        unsafe {
            core::slice::from_raw_parts_mut(head.as_mut_ptr().cast::<MaybeUninit<T>>(), count)
        }
    }
}
