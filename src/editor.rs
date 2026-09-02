//! The one-shot editor family's internal core: the store stratum
//! (emitted per machine by [`one_shot_store!`]) and the dialect
//! machine cores in the submodules. Six machines consume it — the
//! borrowed patch and amend, the owned adopt and intake, and the
//! chunk-ingesting stream adopt and stream intake — each declaring
//! its capability and acceptance. Everything here is emitted into
//! the machines' own modules — the family shares machinery, never
//! public types.

#[cfg(any(
    feature = "patch-grouped",
    feature = "adopt-grouped",
    feature = "amend-grouped",
    feature = "intake-grouped",
    feature = "stream-adopt-grouped",
    feature = "stream-intake-grouped"
))]
pub mod grouped;
#[cfg(any(
    feature = "patch-groupless",
    feature = "adopt-groupless",
    feature = "amend-groupless",
    feature = "intake-groupless",
    feature = "stream-adopt-groupless",
    feature = "stream-intake-groupless"
))]
pub mod groupless;

/// Emits the one-shot editors' shared store stratum: the coordinate
/// types, the command vocabulary, `Handle`, and the word and
/// payload stores — inside the caller's module (names resolve
/// against its imports).
macro_rules! one_shot_store {
    (@payload_target plain) => {};
    (@payload_target $cap:ident) => {
            /// Where a payload transfer lands: an existing LEN whose
            /// payload is replaced wholesale, or a fresh LEN authored
            /// into a gap under the supplied field.
            #[derive(Clone, Copy, PartialEq, Eq, Debug)]
            pub enum PayloadTarget {
                /// Replace this LEN record's payload; its own tag and
                /// framing law are untouched.
                Replace(Handle),
                /// Author a fresh LEN at the gap, its head and prefix
                /// minimal.
                Insert {
                    /// The gap the fresh record splices into.
                    at: InsertAt,
                    /// The fresh record's field.
                    field: crate::wire::FieldNumber,
                },
            }
    };
    (@command_export plain) => {
        pub use command::{EditStatus, InsertAt};
    };
    (@command_export $cap:ident) => {
        pub use command::{EditStatus, InsertAt, PayloadTarget};
    };
    (@stage_faces) => {
            /// Appends one staged chunk into bytes a sized door reserved.
            /// The door judged the declaration into the length class and
            /// the column's `u32` offset domain and reserved its bytes
            /// exactly; the frame's declaration gate bounds every staged
            /// total inside it — so the append can neither regrow the
            /// column nor leave the domain, and no judgment re-runs here.
            pub(crate) fn stage_chunk_reserved(&mut self, chunk: &[u8]) {
                let at = self.copied.len();
                debug_assert!(chunk.len() <= self.copied.capacity() - at);
                // SAFETY: the sized door's reservation covers the staged
                // extent through the declaration, and the caller's gate
                // proved this chunk keeps the total inside it.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        chunk.as_ptr(),
                        self.copied.as_mut_ptr().add(at),
                        chunk.len(),
                    );
                    self.copied.set_len(at + chunk.len());
                }
            }

            /// Truncates the copied column to a staged frame's entry
            /// mark, reclaiming an abandoned or refused frame's staged
            /// bytes — offset space included. Sound because no slot
            /// extent crosses the mark: every extent below it was staged
            /// before the frame opened, the staged extent's own slot is
            /// minted only by the publishing finish, and the frame's
            /// exclusive machine borrow keeps every other staging out.
            pub(crate) fn stage_abandon(&mut self, mark: u32) {
                self.copied.truncate(usize_of(mark));
            }
    };
    (capability: transfer, noun: $noun:literal $(,)?) => {
        /// The transfer capability's facade stratum: the transfer
        /// machines' payload-target vocabulary, emitted beside the
        /// plain stratum so the base machines never carry a transfer
        /// face. The dialect transfer submodules re-export it.
        pub(crate) mod transfer {
            use super::Handle;
            use super::command::InsertAt;

            /// Where a payload transfer lands: an existing LEN whose
            /// payload is replaced wholesale, or a fresh LEN authored
            /// into a gap under the supplied field.
            #[derive(Clone, Copy, PartialEq, Eq, Debug)]
            pub enum PayloadTarget {
                /// Replace this LEN record's payload; its own tag and
                /// framing law are untouched.
                Replace(Handle),
                /// Author a fresh LEN at the gap, its head and prefix
                /// minimal.
                Insert {
                    /// The gap the fresh record splices into.
                    at: InsertAt,
                    /// The fresh record's field.
                    field: crate::wire::FieldNumber,
                },
            }
        }
    };
    (capability: $cap:ident, noun: $noun:literal, A_noun: $A_noun:literal $(,)?) => {
        $crate::editor::one_shot_store!(@store $cap, noun: $noun, A_noun: $A_noun);
    };
    (@store $cap:ident, noun: $noun:literal, A_noun: $A_noun:literal $(,)?) => {
        $crate::_macro::define_valid_range_type! {
            /// A row-arena coordinate, judgment-free downstream of its mint.
            ///
            /// The domain is the admission bound's image: a scanned row
            /// costs at least one source byte and admission caps the source
            /// at `i32::MAX` bytes, so the document scan alone can never
            /// leave the class. Authored rows share the arena and are unbounded,
            /// so every mint that can follow an insertion is judged
            /// (`IndexSpaceExhausted`). The excluded top value keeps
            /// `Option<RowId>` word-free.
            pub(crate) struct RowId(u32 as u32 in 0..=0x7FFF_FFFE) with new;
        }

        impl RowId {
            /// The arena index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        /// Admits a source length into the coordinate class
        /// ([`crate::admission`]): the length-class judgment this machine
        /// folds into its own fault vocabulary.
        #[inline]
        pub(crate) const fn admit(len: usize) -> Option<u32> {
            if len > admission::MAX {
                return None;
            }
            Some(admission::admitted_u32(len))
        }

        /// Narrows the copied byte column's tail into its `u32` offset
        /// domain. The contract is the column's own judgment — every
        /// staging append judges its end into the domain before
        /// occupying bytes — so the narrowing is lossless however many
        /// inert extents the column accumulates (re-sets leave their
        /// old bytes behind, and the admission class does not bound the
        /// column). The debug assertion attributes a violation to the
        /// append that broke the column judgment, not to this
        /// projection.
        #[inline]
        #[track_caller]
        #[allow(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "every staging append judged the column end into the u32 domain"
        )]
        const fn column_u32(len: usize) -> u32 {
            debug_assert!(len <= u32::MAX as usize);
            len as u32
        }

        // ─── the shared command vocabulary ───

        mod command {
            use super::Handle;

            /// A record's observable edit state.
            #[derive(Clone, Copy, PartialEq, Eq, Debug)]
            pub enum EditStatus {
                /// As scanned; the source bytes ride verbatim.
                Intact,
                /// Value replaced; the source tag still rides verbatim.
                Replaced,
                /// Deleted: the record vanishes whole at save.
                Deleted,
                /// Command-authored; emitted minimally.
                Inserted,
            }

            /// Where an insertion splices. Anchors name gaps, not
            /// neighboring records: each variant picks exactly one gap of
            /// one sibling chain.
            ///
            /// The crate's other gap-designation vocabularies refit
            /// this job for other machines: `rewrite`'s `Gap` names
            /// the interior gaps of containers a rule's anchor path
            /// selects, and the splice transfer overlay's `OnlineGap`
            /// names gaps whose ownership a streaming walk already
            /// knows at the ask.
            #[derive(Clone, Copy, PartialEq, Eq, Debug)]
            pub enum InsertAt {
                /// First child of the container (`None`: the top layer).
                HeadOf(Option<Handle>),
                /// Last child of the container (`None`: the top layer).
                TailOf(Option<Handle>),
                /// Immediately after this sibling.
                After(Handle),
            }

            $crate::editor::one_shot_store!(@payload_target $cap);
        }

        $crate::editor::one_shot_store!(@command_export $cap);

        #[doc = concat!(" ", $A_noun, "'s name for one record row.")]
        ///
        #[doc = concat!(" Minted by the ", $noun, " that owns the row; forging one (an")]
        /// out-of-range coordinate) panics at the arena gate, which is the
        #[doc = concat!(" documented index contract. Handles stay valid for the ", $noun, "'s")]
        /// life — commit-only editing never orphans a row.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        #[repr(transparent)]
        pub struct Handle(pub(crate) RowId);

        // ─── the store ───

        /// A word-column coordinate: minted by [`Store::push_word`], read
        #[doc = concat!(" and overwritten judgment-free for the ", $noun, "'s life (the column")]
        #[doc = concat!(" never shrinks). Full `u32` domain — the ", $noun, " never stores an")]
        /// `Option` of a value coordinate, so no niche is bought.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[repr(transparent)]
        pub(crate) struct WordAt(u32);

        impl WordAt {
            /// Rebuilds the coordinate from a row's value slot, which is
            /// only ever written from [`Self::raw`].
            #[inline]
            pub(crate) const fn of_slot(raw: u32) -> Self {
                Self(raw)
            }

            /// The inner index, for the row's value slot.
            #[inline]
            pub(crate) const fn raw(self) -> u32 {
                self.0
            }
        }

        /// A payload-slot coordinate: minted by the payload pushes, read
        #[doc = concat!(" and overwritten judgment-free for the ", $noun, "'s life (the slot")]
        /// table never shrinks). Full `u32` domain, as [`WordAt`].
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[repr(transparent)]
        pub(crate) struct PayloadAt(u32);

        impl PayloadAt {
            /// Rebuilds the coordinate from a row's value slot, which is
            /// only ever written from [`Self::raw`].
            #[inline]
            pub(crate) const fn of_slot(raw: u32) -> Self {
                Self(raw)
            }

            /// The inner index, for the row's value slot.
            #[inline]
            pub(crate) const fn raw(self) -> u32 {
                self.0
            }
        }

        /// One live payload: the caller's borrowed slice (whole or
        /// scattered), held until the save copies it once, or an extent of
        /// the copied column.
        #[derive(Clone, Copy)]
        pub(crate) enum PayloadSlot<'p> {
            /// The caller's slice, borrowed for `'p`.
            Borrowed(&'p [u8]),
            /// The caller's pieces, borrowed for `'p`: they concatenate at
            /// the save's gather — no contiguous view exists before it.
            BorrowedParts(&'p [&'p [u8]]),
            /// Offset and length into the copied column.
            Copied { start: u32, len: u32 },
        }

        /// Authored scalar words, one dense `u64` column for every scalar
        /// kind (the row's kind says how the word reads back).
        ///
        /// One word column, not per-kind columns: commit-only re-sets
        /// overwrite in place, so the column holds exactly the live
        /// authored scalars — for this scenario's profile (a few edits over
        /// a large borrowed document) the four bytes a zero-extended
        /// I32 wastes are bounded by the count of live authored
        /// I32s, while a second column would cost a second coordinate
        /// class and a kind split across every push and read face.
        ///
        /// Coordinates are minted by [`Self::push_word`] and never
        /// invalidated: the column never truncates, so a read is
        /// judgment-free for the coordinate's whole life.
        pub(crate) struct WordStore {
            /// Scalar words: varint values, or fixed bits zero-extended.
            words: Vec<u64>,
        }

        /// Authored payloads: one slot per live payload, plus the byte
        /// column backing the `_copy` faces. A borrowed payload occupies
        /// its slot only — the caller's bytes are copied once, at save,
        /// straight into the output; a copied payload stages its bytes in
        /// the column at the command.
        ///
        /// Coordinates are minted by the pushes and never invalidated: the
        /// slot table never truncates, so a read is judgment-free for the
        /// coordinate's whole life. Re-sets overwrite the slot in place; a
        /// replaced copied extent stays behind inert — the commit-only
        /// trade, paid in bytes rather than bookkeeping.
        ///
        /// Invariant: every slot's length sits in the length class — the
        /// command faces judge `PayloadTooLarge` before any push, and the
        /// copied column's offset domain is judged at staging.
        pub(crate) struct PayloadStore<'p> {
            /// Staged `_copy` bytes, end to end.
            copied: Vec<u8>,
            /// The live payload per minted coordinate.
            slots: Vec<PayloadSlot<'p>>,
        }

        /// Mints the next coordinate of a column (`None`: the `u32`
        /// coordinate space is spent).
        fn mint(len: usize) -> Option<u32> {
            u32::try_from(len).ok()
        }

        /// The concatenated length of a scatter payload, for the command
        /// gates' judgment. Saturating: the gates refuse anything past the
        /// LEN class, so a saturated sum is already over the cap.
        pub(crate) fn parts_len_usize(parts: &[&[u8]]) -> usize {
            parts.iter().fold(0usize, |total, part| total.saturating_add(part.len()))
        }

        impl WordStore {
            /// An empty store; allocation happens per push.
            pub(crate) const fn new() -> Self {
                Self { words: Vec::new() }
            }

            /// The live word count, for the construction snapshot.
            #[cfg(test)]
            pub(crate) const fn words_len(&self) -> usize {
                self.words.len()
            }

            /// Registers a scalar word; returns its coordinate, or `None`
            /// when the column's coordinate space is spent.
            pub(crate) fn push_word(&mut self, word: u64) -> Option<WordAt> {
                let at = mint(self.words.len())?;
                self.words.push(word);
                Some(WordAt(at))
            }

            /// Overwrites a minted word in place — the re-set path, which
            /// cannot fail.
            #[inline]
            pub(crate) fn set_word(&mut self, at: WordAt, word: u64) {
                // SAFETY: `at` was minted by `push_word` and the column
                // never shrinks.
                unsafe { *self.words.get_unchecked_mut(usize_of(at.0)) = word };
            }

            /// The scalar word at a minted coordinate.
            #[inline]
            pub(crate) fn word(&self, at: WordAt) -> u64 {
                // SAFETY: `at` was minted by `push_word` and the column
                // never shrinks.
                unsafe { *self.words.get_unchecked(usize_of(at.0)) }
            }
        }

        impl<'p> PayloadStore<'p> {
            /// An empty store; allocation happens per push.
            pub(crate) const fn new() -> Self {
                Self { copied: Vec::new(), slots: Vec::new() }
            }

            /// The live slot count, for the construction snapshot.
            #[cfg(test)]
            pub(crate) const fn slots_len(&self) -> usize {
                self.slots.len()
            }

            /// Registers a borrowed payload; returns its coordinate, or
            /// `None` when the slot column's coordinate space is spent.
            pub(crate) fn push_borrowed(&mut self, payload: &'p [u8]) -> Option<PayloadAt> {
                let at = mint(self.slots.len())?;
                self.slots.push(PayloadSlot::Borrowed(payload));
                Some(PayloadAt(at))
            }

            /// Registers a borrowed scatter payload; returns its
            /// coordinate, or `None` when the slot column's coordinate
            /// space is spent. The concatenated length was judged against
            /// the LEN class by the command face.
            pub(crate) fn push_parts(&mut self, parts: &'p [&'p [u8]]) -> Option<PayloadAt> {
                let at = mint(self.slots.len())?;
                self.slots.push(PayloadSlot::BorrowedParts(parts));
                Some(PayloadAt(at))
            }

            /// Stages a copied payload; returns its coordinate, or `None`
            /// when the slot column's coordinate space or the copied
            /// column's offset domain is spent — judged before anything is
            /// occupied.
            pub(crate) fn push_copied(&mut self, payload: &[u8]) -> Option<PayloadAt> {
                let at = mint(self.slots.len())?;
                let slot = self.stage(payload)?;
                self.slots.push(slot);
                Some(PayloadAt(at))
            }

            /// Overwrites a minted slot with a borrowed payload — the
            /// re-set path, which cannot fail. A replaced copied extent
            /// stays behind inert.
            #[inline]
            pub(crate) fn set_borrowed(&mut self, at: PayloadAt, payload: &'p [u8]) {
                // SAFETY: `at` was minted by a push and the slot table
                // never shrinks.
                unsafe {
                    *self.slots.get_unchecked_mut(usize_of(at.0)) = PayloadSlot::Borrowed(payload)
                };
            }

            /// Overwrites a minted slot with a borrowed scatter payload —
            /// the re-set path, which cannot fail ([`Self::set_borrowed`]).
            #[inline]
            pub(crate) fn set_parts(&mut self, at: PayloadAt, parts: &'p [&'p [u8]]) {
                // SAFETY: `at` was minted by a push and the slot table
                // never shrinks.
                unsafe {
                    *self.slots.get_unchecked_mut(usize_of(at.0)) =
                        PayloadSlot::BorrowedParts(parts);
                };
            }

            /// Overwrites a minted slot with a staged copy; `None` when
            /// the copied column's offset domain is spent — judged before
            /// anything is occupied.
            pub(crate) fn set_copied(&mut self, at: PayloadAt, payload: &[u8]) -> Option<()> {
                let slot = self.stage(payload)?;
                // SAFETY: `at` was minted by a push and the slot table
                // never shrinks.
                unsafe { *self.slots.get_unchecked_mut(usize_of(at.0)) = slot };
                Some(())
            }

            /// Appends the bytes to the copied column and shapes their
            /// slot; `None` when the column's `u32` offset domain is spent
            /// — judged before anything is occupied.
            fn stage(&mut self, payload: &[u8]) -> Option<PayloadSlot<'p>> {
                let end = self.copied.len().checked_add(payload.len())?;
                let end = u32::try_from(end).ok()?;
                self.copied.extend_from_slice(payload);
                #[allow(
                    clippy::as_conversions,
                    clippy::cast_possible_truncation,
                    reason = "the payload length is bounded by the column-end judgment above"
                )]
                let len = payload.len() as u32;
                Some(PayloadSlot::Copied { start: end - len, len })
            }

            /// The slot at a minted coordinate.
            #[inline]
            fn slot(&self, at: PayloadAt) -> PayloadSlot<'p> {
                // SAFETY: `at` was minted by a push and the slot table
                // never shrinks.
                unsafe { *self.slots.get_unchecked(usize_of(at.0)) }
            }

            /// The length of the payload at a minted coordinate, in the
            /// length class (the store invariant).
            #[inline]
            pub(crate) fn len(&self, at: PayloadAt) -> u32 {
                match self.slot(at) {
                    PayloadSlot::Borrowed(bytes) => admission::admitted_u32(bytes.len()),
                    PayloadSlot::BorrowedParts(parts) => {
                        // In class by the command face's concatenated-length
                        // judgment, restated through the admission witness.
                        admission::admitted_u32(parts.iter().map(|part| part.len()).sum())
                    }
                    PayloadSlot::Copied { len, .. } => len,
                }
            }

            /// The payload at a minted coordinate as one contiguous slice —
            /// `None` for a scatter slot, whose pieces concatenate only at
            /// the save's gather.
            #[inline]
            pub(crate) fn contiguous(&self, at: PayloadAt) -> Option<&[u8]> {
                match self.slot(at) {
                    PayloadSlot::Borrowed(bytes) => Some(bytes),
                    PayloadSlot::BorrowedParts(_) => None,
                    PayloadSlot::Copied { start, len } => {
                        let start = usize_of(start);
                        // SAFETY: the extent was staged in bounds by
                        // `stage` or a publishing finish, and the copied
                        // column never truncates below a published extent.
                        Some(unsafe { self.copied.get_unchecked(start..start + usize_of(len)) })
                    }
                }
            }

            /// Hands the payload's bytes to `piece` in emission order: one
            /// call for a contiguous backing, one per piece for a scatter —
            /// the save's gather point.
            #[inline]
            pub(crate) fn for_each_piece(&self, at: PayloadAt, mut piece: impl FnMut(&[u8])) {
                match self.slot(at) {
                    PayloadSlot::Borrowed(bytes) => piece(bytes),
                    PayloadSlot::BorrowedParts(parts) => {
                        for part in parts {
                            piece(part);
                        }
                    }
                    PayloadSlot::Copied { start, len } => {
                        let start = usize_of(start);
                        // SAFETY: the extent was staged in bounds by
                        // `stage` or a publishing finish, and the copied
                        // column never truncates below a published extent.
                        piece(unsafe { self.copied.get_unchecked(start..start + usize_of(len)) });
                    }
                }
            }

            // ── the staged frame (chunks into the copied column) ──

            /// The copied column's tail, marking a staged frame's start.
            /// In the `u32` domain: every prior append was judged by
            /// [`stage`](Self::stage) or [`stage_chunk`](Self::stage_chunk).
            #[inline]
            pub(crate) const fn stage_mark(&self) -> u32 {
                column_u32(self.copied.len())
            }

            /// Appends one staged chunk to the copied column; `None` when
            /// the column's `u32` offset domain would be spent — judged
            /// before anything is occupied. Nothing references the staged
            /// extent until a finish mints (or overwrites) its slot, so
            /// the frame reclaims it with
            /// [`stage_abandon`](Self::stage_abandon) on every path that
            /// does not publish.
            pub(crate) fn stage_chunk(&mut self, chunk: &[u8]) -> Option<()> {
                let end = self.copied.len().checked_add(chunk.len())?;
                u32::try_from(end).ok()?;
                self.copied.extend_from_slice(chunk);
                Some(())
            }

            /// Reserves the copied column for `len` more staged bytes — the
            /// sized frame's single exact reservation. The caller judged
            /// `len` into the length class and the column's offset domain.
            pub(crate) fn stage_reserve(&mut self, len: usize) {
                self.copied.reserve(len);
            }

            $crate::editor::one_shot_store!(@stage_faces);

            /// The staged extent's length since `mark`, in the length
            /// class (the frame judges every chunk against it).
            #[inline]
            pub(crate) const fn staged_len(&self, mark: u32) -> u32 {
                admission::admitted_u32(self.copied.len() - usize_of(mark))
            }

            /// Mints a slot over the staged extent; `None` when the slot
            /// column's coordinate space is spent.
            pub(crate) fn stage_finish_push(&mut self, mark: u32) -> Option<PayloadAt> {
                let len = self.staged_len(mark);
                let at = mint(self.slots.len())?;
                self.slots.push(PayloadSlot::Copied { start: mark, len });
                Some(PayloadAt(at))
            }

            /// Overwrites a minted slot with the staged extent — the
            /// re-set path, which cannot fail.
            #[inline]
            pub(crate) fn stage_finish_set(&mut self, at: PayloadAt, mark: u32) {
                let len = self.staged_len(mark);
                // SAFETY: `at` was minted by a push and the slot table
                // never shrinks.
                unsafe {
                    *self.slots.get_unchecked_mut(usize_of(at.0)) =
                        PayloadSlot::Copied { start: mark, len };
                };
            }
        }

        // ─── the payload-backing declension: the thin stores ───

        /// One live borrowed payload: the caller's slice (whole or
        /// scattered), held until the save copies it once — the
        /// borrowed-only sibling's slot. Two same-shaped pointer
        /// variants leave no niche, so the tag word stays; the
        /// sibling's saving is the dropped copied column, not the
        /// slot.
        #[derive(Clone, Copy)]
        pub(crate) enum BorrowedSlot<'p> {
            /// The caller's slice, borrowed for `'p`.
            Borrowed(&'p [u8]),
            /// The caller's pieces, borrowed for `'p`: they
            /// concatenate at the save's gather — no contiguous
            /// view exists before it.
            BorrowedParts(&'p [&'p [u8]]),
        }

        /// Authored payloads for the borrowed-only sibling: one
        /// slot per live payload and nothing else — no copied
        /// column exists, so neither the `_copy` faces nor the
        /// staged frames do, and the store is one `Vec` lighter
        #[doc = concat!("than the mixed ", $noun, "'s.")]
        ///
        /// Coordinates are minted by the pushes and never
        /// invalidated: the slot table never truncates, so a read
        /// is judgment-free for the coordinate's whole life.
        /// Re-sets overwrite the slot in place.
        ///
        /// Invariant: every slot's length sits in the length class
        /// — the command faces judge `PayloadTooLarge` before any
        /// push.
        pub(crate) struct BorrowedPayloadStore<'p> {
            /// The live payload per minted coordinate.
            slots: Vec<BorrowedSlot<'p>>,
        }

        impl<'p> BorrowedPayloadStore<'p> {
            /// An empty store; allocation happens per push.
            pub(crate) const fn new() -> Self {
                Self { slots: Vec::new() }
            }

            /// The live slot count, for the construction snapshot.
            #[cfg(test)]
            pub(crate) const fn slots_len(&self) -> usize {
                self.slots.len()
            }

            /// Registers a borrowed payload; returns its
            /// coordinate, or `None` when the slot column's
            /// coordinate space is spent.
            pub(crate) fn push_borrowed(&mut self, payload: &'p [u8]) -> Option<PayloadAt> {
                let at = mint(self.slots.len())?;
                self.slots.push(BorrowedSlot::Borrowed(payload));
                Some(PayloadAt(at))
            }

            /// Registers a borrowed scatter payload; returns its
            /// coordinate, or `None` when the slot column's
            /// coordinate space is spent. The concatenated length
            /// was judged against the LEN class by the command
            /// face.
            pub(crate) fn push_parts(&mut self, parts: &'p [&'p [u8]]) -> Option<PayloadAt> {
                let at = mint(self.slots.len())?;
                self.slots.push(BorrowedSlot::BorrowedParts(parts));
                Some(PayloadAt(at))
            }

            /// Overwrites a minted slot with a borrowed payload —
            /// the re-set path, which cannot fail.
            #[inline]
            pub(crate) fn set_borrowed(&mut self, at: PayloadAt, payload: &'p [u8]) {
                // SAFETY: `at` was minted by a push and the slot
                // table never shrinks.
                unsafe {
                    *self.slots.get_unchecked_mut(usize_of(at.0)) = BorrowedSlot::Borrowed(payload);
                };
            }

            /// Overwrites a minted slot with a borrowed scatter
            /// payload — the re-set path, which cannot fail.
            #[inline]
            pub(crate) fn set_parts(&mut self, at: PayloadAt, parts: &'p [&'p [u8]]) {
                // SAFETY: `at` was minted by a push and the slot
                // table never shrinks.
                unsafe {
                    *self.slots.get_unchecked_mut(usize_of(at.0)) =
                        BorrowedSlot::BorrowedParts(parts);
                };
            }

            /// The slot at a minted coordinate.
            #[inline]
            fn slot(&self, at: PayloadAt) -> BorrowedSlot<'p> {
                // SAFETY: `at` was minted by a push and the slot
                // table never shrinks.
                unsafe { *self.slots.get_unchecked(usize_of(at.0)) }
            }

            /// The length of the payload at a minted coordinate,
            /// in the length class (the store invariant).
            #[inline]
            pub(crate) fn len(&self, at: PayloadAt) -> u32 {
                match self.slot(at) {
                    BorrowedSlot::Borrowed(bytes) => admission::admitted_u32(bytes.len()),
                    BorrowedSlot::BorrowedParts(parts) => {
                        // In class by the command face's
                        // concatenated-length judgment, restated
                        // through the admission witness.
                        admission::admitted_u32(parts.iter().map(|part| part.len()).sum())
                    }
                }
            }

            /// The payload at a minted coordinate as one
            /// contiguous slice — `None` for a scatter slot, whose
            /// pieces concatenate only at the save's gather.
            #[inline]
            pub(crate) fn contiguous(&self, at: PayloadAt) -> Option<&[u8]> {
                match self.slot(at) {
                    BorrowedSlot::Borrowed(bytes) => Some(bytes),
                    BorrowedSlot::BorrowedParts(_) => None,
                }
            }

            /// Hands the payload's bytes to `piece` in emission
            /// order: one call for a whole slice, one per piece
            /// for a scatter — the save's gather point.
            #[inline]
            pub(crate) fn for_each_piece(&self, at: PayloadAt, mut piece: impl FnMut(&[u8])) {
                match self.slot(at) {
                    BorrowedSlot::Borrowed(bytes) => piece(bytes),
                    BorrowedSlot::BorrowedParts(parts) => {
                        for part in parts {
                            piece(part);
                        }
                    }
                }
            }
        }

        /// Authored payloads for the copy-only sibling: every
        /// payload stages its bytes in the copied column at the
        /// command, so a slot is a bare extent — no borrow
        /// variants, no slot tag, and no payload lifetime binds
        /// the caller.
        ///
        /// Coordinates are minted by the pushes and never
        /// invalidated: the slot table never truncates, so a read
        /// is judgment-free for the coordinate's whole life.
        /// Re-sets overwrite the slot in place; a replaced copied
        /// extent stays behind inert — the commit-only trade, paid
        /// in bytes rather than bookkeeping.
        ///
        /// Invariant: every slot's length sits in the length class
        /// — the command faces judge `PayloadTooLarge` before any
        /// push, and the copied column's offset domain is judged
        /// at staging.
        pub(crate) struct CopiedPayloadStore {
            /// Staged bytes, end to end.
            copied: Vec<u8>,
            /// The live extent (offset, length) per minted
            /// coordinate.
            slots: Vec<(u32, u32)>,
        }

        impl CopiedPayloadStore {
            /// An empty store; allocation happens per push.
            pub(crate) const fn new() -> Self {
                Self { copied: Vec::new(), slots: Vec::new() }
            }

            /// The live slot count, for the construction snapshot.
            #[cfg(test)]
            pub(crate) const fn slots_len(&self) -> usize {
                self.slots.len()
            }

            /// Stages a copied payload; returns its coordinate, or
            /// `None` when the slot column's coordinate space or
            /// the copied column's offset domain is spent — judged
            /// before anything is occupied.
            pub(crate) fn push_copied(&mut self, payload: &[u8]) -> Option<PayloadAt> {
                let at = mint(self.slots.len())?;
                let slot = self.stage(payload)?;
                self.slots.push(slot);
                Some(PayloadAt(at))
            }

            /// Overwrites a minted slot with a staged copy; `None`
            /// when the copied column's offset domain is spent —
            /// judged before anything is occupied.
            pub(crate) fn set_copied(&mut self, at: PayloadAt, payload: &[u8]) -> Option<()> {
                let slot = self.stage(payload)?;
                // SAFETY: `at` was minted by a push and the slot
                // table never shrinks.
                unsafe { *self.slots.get_unchecked_mut(usize_of(at.0)) = slot };
                Some(())
            }

            /// Appends the bytes to the copied column and shapes
            /// their slot; `None` when the column's `u32` offset
            /// domain is spent — judged before anything is
            /// occupied.
            fn stage(&mut self, payload: &[u8]) -> Option<(u32, u32)> {
                let end = self.copied.len().checked_add(payload.len())?;
                let end = u32::try_from(end).ok()?;
                self.copied.extend_from_slice(payload);
                #[allow(
                    clippy::as_conversions,
                    clippy::cast_possible_truncation,
                    reason = "the payload length is bounded by the column-end judgment above"
                )]
                let len = payload.len() as u32;
                Some((end - len, len))
            }

            /// The extent at a minted coordinate.
            #[inline]
            fn slot(&self, at: PayloadAt) -> (u32, u32) {
                // SAFETY: `at` was minted by a push and the slot
                // table never shrinks.
                unsafe { *self.slots.get_unchecked(usize_of(at.0)) }
            }

            /// The length of the payload at a minted coordinate,
            /// in the length class (the store invariant).
            #[inline]
            pub(crate) fn len(&self, at: PayloadAt) -> u32 {
                self.slot(at).1
            }

            /// The payload at a minted coordinate as one
            /// contiguous slice — every copied extent is
            /// contiguous, so the answer never refuses; the
            /// `Option` is the shared read shape.
            #[inline]
            pub(crate) fn contiguous(&self, at: PayloadAt) -> Option<&[u8]> {
                let (start, len) = self.slot(at);
                let start = usize_of(start);
                // SAFETY: the extent was staged in bounds by `stage` or
                // a publishing finish, and the copied column never
                // truncates below a published extent.
                Some(unsafe { self.copied.get_unchecked(start..start + usize_of(len)) })
            }

            /// Hands the payload's bytes to `piece` in emission
            /// order: one call — copied extents are contiguous.
            #[inline]
            pub(crate) fn for_each_piece(&self, at: PayloadAt, mut piece: impl FnMut(&[u8])) {
                let (start, len) = self.slot(at);
                let start = usize_of(start);
                // SAFETY: the extent was staged in bounds by `stage` or
                // a publishing finish, and the copied column never
                // truncates below a published extent.
                piece(unsafe { self.copied.get_unchecked(start..start + usize_of(len)) });
            }

            // ── the staged frame (chunks into the copied column) ──

            /// The copied column's tail, marking a staged frame's
            /// start. In the `u32` domain: every prior append was
            /// judged by [`stage`](Self::stage) or
            /// [`stage_chunk`](Self::stage_chunk).
            #[inline]
            pub(crate) const fn stage_mark(&self) -> u32 {
                column_u32(self.copied.len())
            }

            /// Appends one staged chunk to the copied column;
            /// `None` when the column's `u32` offset domain would
            /// be spent — judged before anything is occupied.
            /// Nothing references the staged extent until a finish
            /// mints (or overwrites) its slot, so the frame
            /// reclaims it with
            /// [`stage_abandon`](Self::stage_abandon) on every
            /// path that does not publish.
            pub(crate) fn stage_chunk(&mut self, chunk: &[u8]) -> Option<()> {
                let end = self.copied.len().checked_add(chunk.len())?;
                u32::try_from(end).ok()?;
                self.copied.extend_from_slice(chunk);
                Some(())
            }

            /// Reserves the copied column for `len` more staged
            /// bytes — the sized frame's single exact reservation.
            /// The caller judged `len` into the length class and
            /// the column's offset domain.
            pub(crate) fn stage_reserve(&mut self, len: usize) {
                self.copied.reserve(len);
            }

            $crate::editor::one_shot_store!(@stage_faces);

            /// The staged extent's length since `mark`, in the
            /// length class (the frame judges every chunk against
            /// it).
            #[inline]
            pub(crate) const fn staged_len(&self, mark: u32) -> u32 {
                admission::admitted_u32(self.copied.len() - usize_of(mark))
            }

            /// Mints a slot over the staged extent; `None` when
            /// the slot column's coordinate space is spent.
            pub(crate) fn stage_finish_push(&mut self, mark: u32) -> Option<PayloadAt> {
                let len = self.staged_len(mark);
                let at = mint(self.slots.len())?;
                self.slots.push((mark, len));
                Some(PayloadAt(at))
            }

            /// Overwrites a minted slot with the staged extent —
            /// the re-set path, which cannot fail.
            #[inline]
            pub(crate) fn stage_finish_set(&mut self, at: PayloadAt, mark: u32) {
                let len = self.staged_len(mark);
                // SAFETY: `at` was minted by a push and the slot
                // table never shrinks.
                unsafe { *self.slots.get_unchecked_mut(usize_of(at.0)) = (mark, len) };
            }
        }

        // Two borrowed pointer variants leave no niche for the copied
        // extent's tag: the slot pays one tag word beyond the
        // two-variant layout. Per-slot cost, O(edited payloads).
        const _: () = {
            let w64 = cfg!(target_pointer_width = "64");
            assert!(core::mem::size_of::<PayloadSlot<'_>>() == if w64 { 24 } else { 12 });
            assert!(core::mem::size_of::<WordStore>() == if w64 { 24 } else { 12 });
            assert!(core::mem::size_of::<PayloadStore<'_>>() == if w64 { 48 } else { 24 });
        };
        // The declension's savings, pinned: the borrowed-only store
        // drops the copied column whole (its slot keeps the mixed
        // tag shape — two same-shaped pointer variants leave no
        // niche), and the copy-only slot is a bare eight-byte
        // extent behind the mixed store footprint.
        const _: () = {
            let w64 = cfg!(target_pointer_width = "64");
            assert!(core::mem::size_of::<BorrowedSlot<'_>>() == if w64 { 24 } else { 12 });
            assert!(
                core::mem::size_of::<BorrowedPayloadStore<'_>>() + if w64 { 24 } else { 12 }
                    == core::mem::size_of::<PayloadStore<'_>>()
            );
            assert!(
                core::mem::size_of::<CopiedPayloadStore>()
                    == core::mem::size_of::<PayloadStore<'_>>()
            );
        };
    };
}

pub(crate) use one_shot_store;
