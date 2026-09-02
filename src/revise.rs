//! The revising editor family's shared layer core: the coordinate
//! types, the edit algebra, the command vocabulary, and the value
//! stores the five facades (session, draft, markup, review, and
//! the stream-ingest draft) emit through [`revising_store!`], plus
//! the dialect machine cores in the submodules. The
//! payload-backing declension emits three store forms: the copied
//! store every facade carries, the borrowed slot store behind the
//! borrowed-payload siblings (`BorrowSession`, `BorrowDraft`,
//! `BorrowMarkup`, `BorrowReview`, and the stream draft's finished
//! `BorrowDraft`), and the mixed slot store behind the buffered
//! facades' per-install siblings (`MixSession`, `MixDraft`,
//! `MixMarkup`, `MixReview`), whose faces select the backing per
//! payload.
//!
//! The sharing boundary: scenario modules share no public types
//! with one another, while sibling machines inside one facade
//! module intentionally share that module's command vocabulary
//! (faults, views, geometry) — cost-invariant across siblings; the
//! staged frames carry their own fault alphabet, so no sibling pays
//! a frame judgment in its command faces.

#[cfg(any(
    feature = "markup-grouped",
    feature = "draft-grouped",
    feature = "review-grouped",
    feature = "session-grouped",
    feature = "stream-draft-grouped"
))]
pub mod grouped;
#[cfg(any(
    feature = "markup-groupless",
    feature = "draft-groupless",
    feature = "review-groupless",
    feature = "session-groupless",
    feature = "stream-draft-groupless"
))]
pub mod groupless;

/// The priced typestates' ledger shape: a hash map under the Fx
/// hasher, growable only through `try_reserve` at the priced faces
/// (the map type itself carries no policy — the wrappers do).
#[cfg(any(
    feature = "priced-session-grouped",
    feature = "priced-session-groupless",
    feature = "priced-transfer-session-grouped",
    feature = "priced-transfer-session-groupless"
))]
pub type FxMap<K, V> = hashbrown::HashMap<K, V, rustc_hash::FxBuildHasher>;

/// Emits the revising editors' shared facade stratum —
/// `coordinates` the coordinate classes (with the tolerant width
/// class and the non-carrier admission judgment where the sections
/// call for them), `layer` the edit algebra, command vocabulary,
/// and value store — inside the caller's module (names resolve
/// against its imports).
macro_rules! revising_store {
    (
        coordinates,
        tenure: $src:ident,
        acceptance: $acc:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        $crate::revise::revising_store!(@coords $src $acc, noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
    };
    (
        layer plain,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        $crate::revise::revising_store!(@algebra plain, noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
        $crate::revise::revising_store!(@command plain, noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
        $crate::revise::revising_store!(@store noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
    };
    (
        layer transfer,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        /// The transfer capability's facade stratum: the transfer
        /// machines' edit algebra and command vocabulary, emitted
        /// beside the plain stratum so the base machines never carry
        /// a transfer state. The dialect transfer submodules import
        /// the algebra from here and re-export the public vocabulary.
        #[allow(
            clippy::redundant_pub_crate,
            reason = "the algebra arm's one text serves the facade root and this \
                      stratum module alike; the item visibility is the arm's"
        )]
        pub(crate) mod transfer {
            use super::command::InsertAt;
            use super::{Handle, RowId, ValueAt};

            $crate::revise::revising_store!(@algebra transfer, noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
            $crate::revise::revising_store!(@command transfer, noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
        }
    };
    (
        store borrow,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        $crate::revise::revising_store!(@store_borrow noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
    };
    (
        store priced,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        $crate::revise::revising_store!(@store_priced noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
    };
    (
        store mixed,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        $crate::revise::revising_store!(@store_mixed noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
    };
    (@coords vec tolerant, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        $crate::_macro::define_valid_range_type! {
            /// A row-arena coordinate: minted by arena append, judgment-free
            /// downstream. The domain ends below 2³¹, keeping `Option` free
            /// and leaving bit 31 for [`Transition`]'s packed fresh mark —
            /// nothing reachable is lost, since 2³¹ rows would weigh 72 GiB
            /// of arena against a 2 GiB-capped backing.
            pub(crate) struct RowId(u32 as u32 in 0..=2_147_483_646) with new, new_unchecked;

            /// A byte offset into a sealed backing zone (the moved-in
            /// source or the store's byte column); each zone judges its own
            /// end against this domain at admission. The excluded top value
            /// keeps `Option` free.
            pub(crate) struct At32(u32 as u32 in 0..=4_294_967_294) with max, new_unchecked;

            /// A store-column coordinate: minted by the column's push,
            /// judgment-free downstream. The excluded top value keeps
            /// `Option` free.
            pub(crate) struct ValueAt(u32 as u32 in 0..=4_294_967_294) with new;
        }

        impl RowId {
            /// The arena index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        impl ValueAt {
            /// The column index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        /// Admits a source length into the coordinate class
        /// ([`crate::admission`]): the open judgment the dialect machines
        /// fold into their own fault vocabulary.
        #[inline]
        pub(crate) const fn admit(len: usize) -> Option<u32> {
            if len > admission::MAX {
                return None;
            }
            Some(admission::admitted_u32(len))
        }

    };
    (@coords borrow tolerant, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        $crate::_macro::define_valid_range_type! {
            /// A row-arena coordinate: minted by arena append, judgment-free
            /// downstream. The domain ends below 2³¹, keeping `Option` free
            /// and leaving bit 31 for [`Transition`]'s packed fresh mark —
            /// nothing reachable is lost, since 2³¹ rows would weigh 72 GiB
            /// of arena against a 2 GiB-capped backing.
            pub(crate) struct RowId(u32 as u32 in 0..=2_147_483_646) with new, new_unchecked;

            /// A byte offset into a sealed backing zone (the borrowed
            /// source or the store's byte column); each zone judges its own
            /// end against this domain at admission. The excluded top value
            /// keeps `Option` free.
            pub(crate) struct At32(u32 as u32 in 0..=4_294_967_294) with max, new_unchecked;

            /// A store-column coordinate: minted by the column's push,
            /// judgment-free downstream. The excluded top value keeps
            /// `Option` free.
            pub(crate) struct ValueAt(u32 as u32 in 0..=4_294_967_294) with new;
        }

        impl RowId {
            /// The arena index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        impl ValueAt {
            /// The column index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        /// Admits a source length into the coordinate class
        /// ([`crate::admission`]): the open judgment the dialect machines
        /// fold into their own fault vocabulary.
        #[inline]
        pub(crate) const fn admit(len: usize) -> Option<u32> {
            if len > admission::MAX {
                return None;
            }
            Some(admission::admitted_u32(len))
        }

    };
    (@coords borrow canonical, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        $crate::_macro::define_valid_range_type! {
            /// A row-arena coordinate: minted by arena append, judgment-free
            /// downstream. The domain ends below 2³¹, keeping `Option` free
            /// and leaving bit 31 for [`Transition`]'s packed fresh mark —
            /// nothing reachable is lost, since 2³¹ rows would weigh 72 GiB
            /// of arena against a 2 GiB-capped backing.
            pub(crate) struct RowId(u32 as u32 in 0..=2_147_483_646) with new, new_unchecked;

            /// A byte offset into a sealed backing zone (the borrowed
            /// source or the store's byte column); each zone judges its own
            /// end against this domain at admission. The excluded top value
            /// keeps `Option` free.
            pub(crate) struct At32(u32 as u32 in 0..=4_294_967_294) with max, new_unchecked;

            /// A store-column coordinate: minted by the column's push,
            /// judgment-free downstream. The excluded top value keeps
            /// `Option` free.
            pub(crate) struct ValueAt(u32 as u32 in 0..=4_294_967_294) with new;
        }

        impl RowId {
            /// The arena index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        impl ValueAt {
            /// The column index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        /// Admits a source length into the coordinate class
        /// ([`crate::admission`]): the open judgment the dialect machines
        /// fold into their own fault vocabulary.
        #[inline]
        pub(crate) const fn admit(len: usize) -> Option<u32> {
            if len > admission::MAX {
                return None;
            }
            Some(admission::admitted_u32(len))
        }

    };
    (@coords carrier canonical, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        $crate::_macro::define_valid_range_type! {
            /// A row-arena coordinate: minted by arena append, judgment-free
            /// downstream. The domain ends below 2³¹, keeping `Option` free
            /// and leaving bit 31 for [`Transition`]'s packed fresh mark —
            /// nothing reachable is lost, since 2³¹ rows would weigh 72 GiB
            /// of arena against a 4 GiB-capped backing.
            pub(crate) struct RowId(u32 as u32 in 0..=2_147_483_646) with new, new_unchecked;

            /// A byte offset into a sealed backing zone (the document or the
            /// store's byte column); each zone judges its own end against
            /// this domain at admission. The excluded top value keeps
            /// `Option` free.
            pub(crate) struct At32(u32 as u32 in 0..=4_294_967_294) with max, new_unchecked;

            /// A store-column coordinate: minted by the column's push,
            /// judgment-free downstream. The excluded top value keeps
            /// `Option` free.
            pub(crate) struct ValueAt(u32 as u32 in 0..=4_294_967_294) with new;
        }

        impl RowId {
            /// The arena index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        impl ValueAt {
            /// The column index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

    };
    (@algebra plain, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        // ─── the edit algebra ───

        /// A row's edit state: the closed algebra every command transitions
        /// within.
        ///
        /// Two families never mix: scanned rows move through `Intact`,
        /// `Replaced`, and `Deleted`; command-authored rows through
        /// `Inserted` and `InsertedDeleted` (they have no virgin state to
        /// return to). Deletion shrouds — the pre-deletion value rides the
        /// shroud so undeletion restores it exactly.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub(crate) enum Edit {
            /// As scanned; the source bytes speak.
            Intact,
            /// The store value speaks for the record's value side.
            Replaced(ValueAt),
            /// Shrouded; the pre-deletion replacement (if any) rides along.
            Deleted(Option<ValueAt>),
            /// Command-authored and live; the store value speaks.
            Inserted(ValueAt),
            /// Command-authored and shrouded (a ghost): stays in the
            /// topology, never emits, and is not dirt.
            InsertedDeleted(ValueAt),
        }

        impl Edit {
            /// The store value speaking for the record's value side, if any
            /// — the row's backing flips exactly when this answer changes.
            pub(crate) const fn effective(self) -> Option<ValueAt> {
                match self {
                    Self::Intact | Self::Deleted(None) => None,
                    Self::Replaced(v)
                    | Self::Deleted(Some(v))
                    | Self::Inserted(v)
                    | Self::InsertedDeleted(v) => Some(v),
                }
            }

            /// True when this state alone makes the row dirty. Ghosts are
            /// not dirty: an insert undone changes nothing observable.
            pub(crate) const fn own_dirty(self) -> bool {
                !matches!(self, Self::Intact | Self::InsertedDeleted(_))
            }
        }

        /// One undo-log step: the row, the state to restore, and — packed
        /// into bit 31 of the coordinate word — whether this entry opened
        /// the row's pending history.
        ///
        /// Insertion logs the ghost as its past — reverting a birth shrouds
        /// the row, keeping topology monotone. The packing rides the spare
        /// bit [`RowId`]'s domain leaves free and keeps the entry at 12
        /// bytes; a separate flag would pad the log's working set — the
        /// bytes the undo path streams — to 16.
        #[derive(Clone, Copy)]
        pub(crate) struct Transition {
            /// Bit 31: the fresh mark. Low 31 bits: the row coordinate.
            word: u32,
            pub(crate) from: Edit,
        }

        const _: () = assert!(core::mem::size_of::<Transition>() == 12);

        impl Transition {
            /// Packs one entry; the dialects' `log_push` is the sole
            /// construction point.
            #[inline]
            pub(crate) const fn new(row: RowId, from: Edit, fresh: bool) -> Self {
                Self { word: row.as_inner() | if fresh { 1 << 31 } else { 0 }, from }
            }

            /// The row this entry restores.
            #[inline]
            pub(crate) const fn row(self) -> RowId {
                // SAFETY: `new` packed a valid coordinate into the low 31
                // bits, and the mask strips exactly the mark bit.
                unsafe { RowId::new_unchecked(self.word & 0x7FFF_FFFF) }
            }

            /// True when the row had no earlier pending entry: the push
            /// raised the row's own-history mark, and the pop releases it.
            /// Exact because reverts run strictly last-in-first-out.
            #[inline]
            pub(crate) const fn fresh(self) -> bool {
                self.word >> 31 != 0
            }
        }

    };
    (@algebra transfer, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        $crate::revise::revising_store!(
            @algebra_body transfer,
            noun: $noun, a_noun: $a_noun, A_noun: $A_noun,
            imported_doc: "A live imported external record: the row's own zone \
                geometry speaks — the whole closure is first-class rows over \
                the import zone — and the store span is the zone witness."
        );
    };
    // Import roots speak from their own zone geometry — the whole
    // closure is first-class rows over the import zone — so the
    // scanned side speaks and the store span is only the zone
    // witness. Shrouds keep the mapping, so no live transition
    // changes its flip verdict (imports enter and leave only through
    // their own shroud pair).
    (@speaker_map transfer, $it:expr) => {
        match $it {
            Self::Intact
            | Self::Deleted(None)
            | Self::Moved { .. }
            | Self::SourceRecord
            | Self::SourceRecordDeleted
            | Self::Imported(_)
            | Self::ImportedDeleted(_) => Speaker::Scanned,
            Self::Replaced(v)
            | Self::Deleted(Some(v))
            | Self::Inserted(v)
            | Self::InsertedDeleted(v) => Speaker::Store(v),
            Self::SourcePayload(row)
            | Self::SourcePayloadDeleted(row)
            | Self::SourceInserted(row)
            | Self::SourceInsertedDeleted(row) => Speaker::SourceRow(row),
        }
    };
    (
        @algebra_body $cap:ident,
        noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal,
        imported_doc: $imported_doc:literal
    ) => {
        // ─── the edit algebra ───

        /// A row's edit state: the closed algebra every command transitions
        /// within.
        ///
        /// The families never mix: scanned rows move through `Intact`,
        /// `Replaced`, `Deleted`, `SourcePayload`, and `Moved`;
        /// command-authored rows through the `Inserted` pair (they have
        /// no virgin state to return to); transfer-minted rows through
        /// their own live/shrouded pairs. Deletion shrouds — the
        /// pre-deletion value rides the shroud so undeletion restores it
        /// exactly.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub(crate) enum Edit {
            /// As scanned; the source bytes speak.
            Intact,
            /// The store value speaks for the record's value side.
            Replaced(ValueAt),
            /// Shrouded; the pre-deletion replacement (if any) rides along.
            Deleted(Option<ValueAt>),
            /// Command-authored and live; the store value speaks.
            Inserted(ValueAt),
            /// Command-authored and shrouded (a ghost): stays in the
            /// topology, never emits, and is not dirt.
            InsertedDeleted(ValueAt),
            /// Suppressed by a move: the record emits nowhere, its exact
            /// source bytes emit at the destination alias instead, and
            /// the one transition that entered this state restores both
            /// sides on revert.
            Moved {
                /// The destination alias the move made live.
                destination: RowId,
            },
            /// A live local whole-record copy: the row's own cloned
            /// geometry speaks — the exact source occurrence bytes emit
            /// at this row's position.
            SourceRecord,
            /// [`Edit::SourceRecord`]'s shroud (a deleted or ghosted
            /// copy): stays in the topology, never emits, and is not
            /// dirt — undoing a copy restores the untouched reading.
            SourceRecordDeleted,
            /// A scanned LEN whose payload is a designated source
            /// interior: its own tag speaks, the named row's source
            /// payload subspan emits behind it.
            SourcePayload(RowId),
            /// [`Edit::SourcePayload`]'s shroud; the designation rides
            /// so undeletion restores it exactly. Dirt: a shrouded
            /// scanned record changes the output.
            SourcePayloadDeleted(RowId),
            /// A command-authored LEN whose payload is a designated
            /// source interior: minimal framing, the named row's source
            /// payload subspan behind it.
            SourceInserted(RowId),
            /// [`Edit::SourceInserted`]'s ghost: stays in the topology,
            /// never emits, and is not dirt.
            SourceInsertedDeleted(RowId),
            #[doc = $imported_doc]
            Imported(ValueAt),
            /// [`Edit::Imported`]'s ghost: stays in the topology, never
            /// emits, and is not dirt.
            ImportedDeleted(ValueAt),
        }

        /// Which bytes speak for a row's value side — the backing-flip
        /// criterion: a container's parsed interior survives a
        /// transition exactly when its speaker is unchanged.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub(crate) enum Speaker {
            /// The row's own scanned (or cloned) geometry.
            Scanned,
            /// A typed store value.
            Store(ValueAt),
            /// A designated row's source payload subspan.
            SourceRow(RowId),
        }

        impl Edit {
            /// The bytes speaking for the row's value side. Shrouds keep
            /// their pre-shroud speaker: deletion never flips a backing.
            pub(crate) const fn speaker(self) -> Speaker {
                $crate::revise::revising_store!(@speaker_map $cap, self)
            }

            /// True when this state alone makes the row dirty. Ghosts are
            /// not dirty: an insert undone changes nothing observable —
            /// and a shrouded copy or import likewise restores the
            /// untouched reading. A live transfer is dirt (it emits at a
            /// new position), as is a moved or shrouded scanned record
            /// (its span stops emitting).
            pub(crate) const fn own_dirty(self) -> bool {
                !matches!(
                    self,
                    Self::Intact
                        | Self::InsertedDeleted(_)
                        | Self::SourceRecordDeleted
                        | Self::SourceInsertedDeleted(_)
                        | Self::ImportedDeleted(_)
                )
            }
        }

        /// One undo-log step: the row, the state to restore, and — packed
        /// into bit 31 of the coordinate word — whether this entry opened
        /// the row's pending history.
        ///
        /// Insertion logs the ghost as its past — reverting a birth shrouds
        /// the row, keeping topology monotone. The packing rides the spare
        /// bit [`RowId`]'s domain leaves free and keeps the entry at 12
        /// bytes; a separate flag would pad the log's working set — the
        /// bytes the undo path streams — to 16.
        #[derive(Clone, Copy)]
        pub(crate) struct Transition {
            /// Bit 31: the fresh mark. Low 31 bits: the row coordinate.
            word: u32,
            pub(crate) from: Edit,
        }

        const _: () = assert!(core::mem::size_of::<Transition>() == 12);

        impl Transition {
            /// Packs one entry; the dialects' `log_push` is the sole
            /// construction point.
            #[inline]
            pub(crate) const fn new(row: RowId, from: Edit, fresh: bool) -> Self {
                Self { word: row.as_inner() | if fresh { 1 << 31 } else { 0 }, from }
            }

            /// The row this entry restores.
            #[inline]
            pub(crate) const fn row(self) -> RowId {
                // SAFETY: `new` packed a valid coordinate into the low 31
                // bits, and the mask strips exactly the mark bit.
                unsafe { RowId::new_unchecked(self.word & 0x7FFF_FFFF) }
            }

            /// True when the row had no earlier pending entry: the push
            /// raised the row's own-history mark, and the pop releases it.
            /// Exact because reverts run strictly last-in-first-out.
            #[inline]
            pub(crate) const fn fresh(self) -> bool {
                self.word >> 31 != 0
            }
        }

    };
    (@command plain, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        // ─── the shared command vocabulary ───

        mod command {
            use super::Handle;

            /// A record's observable edit state.
            #[derive(Clone, Copy, PartialEq, Eq, Debug)]
            pub enum EditStatus {
                /// As scanned.
                Intact,
                /// Value replaced.
                Replaced,
                /// Shrouded (restorable by `undelete`).
                Deleted,
                /// Command-authored and live.
                Inserted,
                /// Command-authored and shrouded — a ghost the UI filters.
                InsertedDeleted,
            }

            /// Where an insertion splices. Anchors name gaps, not
            /// neighboring records: each variant picks exactly one gap
            /// of one sibling chain.
            ///
            /// The crate's other gap-designation vocabularies are this
            /// job refitted to other machines: `rewrite`'s `Gap` names
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
        }

        #[doc = concat!(" ", $A_noun, "'s name for one record row.")]
        ///
        #[doc = concat!(" Minted by the ", $noun, " that owns the row; forging one (an")]
        /// out-of-range coordinate) panics at the arena gate, which is the
        /// documented index contract.
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
        #[repr(transparent)]
        pub struct Handle(pub(crate) RowId);

    };
    (@command transfer, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        /// A record's observable edit state under the transfer
        /// capability.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum EditStatus {
            /// As scanned.
            Intact,
            /// Value replaced.
            Replaced,
            /// Shrouded (restorable by `undelete`).
            Deleted,
            /// Command-authored and live.
            Inserted,
            /// Command-authored and shrouded — a ghost the UI filters.
            InsertedDeleted,
            /// Suppressed by a move: the record emits nowhere and its
            /// exact bytes emit at the destination alias. Commands
            /// refuse; one `revert` of the move restores it.
            Moved,
        }

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
    (@store noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        // ─── the store ───

        /// Why a store push refused.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub(crate) enum StoreFault {
            /// The allocator refused column growth.
            Resource,
            /// A column's `u32` coordinate space is spent.
            Exhausted,
        }

        /// Replacement and insertion values, in dense per-kind columns.
        ///
        /// Coordinates are minted by the pushes and never invalidated: the
        /// byte column never truncates below a minted span (only a staged
        /// frame's unpublished tail is ever reclaimed), so a span read is
        /// judgment-free for the coordinate's whole life. Failure ordering
        /// inside a push (allocator refusal against coordinate exhaustion)
        /// is deliberately unpromised.
        pub(crate) struct Store {
            /// Varint words.
            varints: Vec<u64>,
            /// Fixed 32-bit values.
            bits32: Vec<u32>,
            /// Fixed 64-bit values.
            bits64: Vec<u64>,
            /// Byte payloads, end to end.
            bytes: Vec<u8>,
            /// Payload extents into `bytes`: offset and length. Lengths
            /// sit in the length class; an empty extent minted at a full
            /// column may start at the column cap (`At32::MAX + 1`), one
            /// past [`At32`]'s domain.
            spans: Vec<(u32, u32)>,
        }

        /// Appends to a column after a fallible one-slot reservation.
        fn append<T>(column: &mut Vec<T>, value: T) -> Result<(), StoreFault> {
            column.try_reserve(1).map_err(store_resource)?;
            let len = column.len();
            // SAFETY: the reservation above guarantees one spare slot past
            // the current length.
            unsafe {
                column.as_mut_ptr().add(len).write(value);
                column.set_len(len + 1);
            }
            Ok(())
        }

        /// Mints the next coordinate of a column.
        fn mint(len: usize) -> Result<ValueAt, StoreFault> {
            u32::try_from(len).ok().and_then(ValueAt::new).ok_or(StoreFault::Exhausted)
        }

        #[cold]
        const fn store_resource(_refused: TryReserveError) -> StoreFault {
            StoreFault::Resource
        }

        impl Store {
            /// An empty store; allocation happens per push.
            pub(crate) const fn new() -> Self {
                Self {
                    varints: Vec::new(),
                    bits32: Vec::new(),
                    bits64: Vec::new(),
                    bytes: Vec::new(),
                    spans: Vec::new(),
                }
            }

            /// Registers a varint word; returns its coordinate.
            pub(crate) fn push_varint(&mut self, word: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.varints.len())?;
                append(&mut self.varints, word)?;
                Ok(at)
            }

            /// Registers a fixed 32-bit value; returns its coordinate.
            pub(crate) fn push_bits32(&mut self, bits: u32) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits32.len())?;
                append(&mut self.bits32, bits)?;
                Ok(at)
            }

            /// Registers a fixed 64-bit value; returns its coordinate.
            pub(crate) fn push_bits64(&mut self, bits: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits64.len())?;
                append(&mut self.bits64, bits)?;
                Ok(at)
            }

            /// Registers a byte payload; returns its span coordinate.
            ///
            /// The byte column is bounded by the zone-offset domain (all
            /// offsets into it must stay addressable as [`At32`]), so the
            /// end of the incoming payload is judged before anything is
            /// occupied.
            pub(crate) fn push_bytes(&mut self, payload: &[u8]) -> Result<ValueAt, StoreFault> {
                let at = mint(self.spans.len())?;
                let start = self.bytes.len();
                let end = start.checked_add(payload.len()).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(At32::MAX.as_inner()) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(payload.len()).map_err(store_resource)?;
                self.spans.try_reserve(1).map_err(store_resource)?;
                // Both reservations held: the suffix cannot fail.
                self.bytes.extend_from_slice(payload);
                #[allow(
                    clippy::as_conversions,
                    reason = "start and the payload length are bounded by the At32 end judgment above"
                )]
                self.spans.push((start as u32, payload.len() as u32));
                Ok(at)
            }

            /// The byte column's tail, marking a staged frame's start — in
            /// the `u32` domain by the push judgments (the column's end
            /// never passes `At32::MAX + 1`).
            #[allow(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "the column end is bounded by the At32 end judgment of every append"
            )]
            #[inline]
            pub(crate) const fn stage_mark(&self) -> u32 {
                self.bytes.len() as u32
            }

            /// Appends one staged chunk to the byte column —
            /// [`push_bytes`](Self::push_bytes)'s bounds and reservation,
            /// without the span mint. Nothing references the staged extent
            /// until [`stage_finish`](Self::stage_finish) mints its span,
            /// so the frame reclaims it with
            /// [`stage_abandon`](Self::stage_abandon) on every path that
            /// does not publish.
            pub(crate) fn stage_chunk(&mut self, chunk: &[u8]) -> Result<(), StoreFault> {
                let end = self.bytes.len().checked_add(chunk.len()).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(At32::MAX.as_inner()) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(chunk.len()).map_err(store_resource)?;
                self.bytes.extend_from_slice(chunk);
                Ok(())
            }

            /// Appends one staged chunk into bytes
            /// [`stage_reserve`](Self::stage_reserve) already judged and
            /// reserved — no judgment or reservation re-runs here. The
            /// caller proves the reserved extent covers this chunk: the
            /// sized door reserved the full declaration past the staging
            /// mark, its frame's declaration gate bounds every staged
            /// total inside it, and the frame's exclusive machine borrow
            /// keeps every other append out.
            pub(crate) fn stage_chunk_reserved(&mut self, chunk: &[u8]) {
                let at = self.bytes.len();
                debug_assert!(chunk.len() <= self.bytes.capacity() - at);
                // SAFETY: the door's reservation covers the staged extent
                // through the declaration, and the caller's gate proved
                // this chunk keeps the staged total inside it.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        chunk.as_ptr(),
                        self.bytes.as_mut_ptr().add(at),
                        chunk.len(),
                    );
                    self.bytes.set_len(at + chunk.len());
                }
            }

            /// Truncates the byte column to a staged frame's entry mark,
            /// reclaiming an abandoned or refused frame's staged bytes —
            /// offset space included. Sound because no minted span
            /// crosses the mark: every span below it was minted before
            /// the frame opened, the staged extent's own span is minted
            /// only by the publishing finish, and the frame's exclusive
            /// machine borrow keeps every other push out.
            pub(crate) fn stage_abandon(&mut self, mark: u32) {
                self.bytes.truncate(usize_of(mark));
            }

            /// Reserves the byte column for `len` more staged bytes — the
            /// sized frame's single exact reservation, behind
            /// [`stage_chunk`](Self::stage_chunk)'s own domain judgment so
            /// nothing is reserved for a frame that could never finish.
            pub(crate) fn stage_reserve(&mut self, len: usize) -> Result<(), StoreFault> {
                let end = self.bytes.len().checked_add(len).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(At32::MAX.as_inner()) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(len).map_err(store_resource)
            }

            /// Mints the span of the staged extent since `mark` —
            /// [`push_bytes`](Self::push_bytes)'s span mint, decoupled
            /// from the bytes it covers.
            pub(crate) fn stage_finish(&mut self, mark: u32) -> Result<ValueAt, StoreFault> {
                let at = mint(self.spans.len())?;
                self.spans.try_reserve(1).map_err(store_resource)?;
                self.spans.push((mark, self.stage_mark() - mark));
                Ok(at)
            }

            /// The varint word at a minted coordinate.
            #[inline]
            pub(crate) fn varint(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_varint` and the column
                // never shrinks.
                unsafe { *self.varints.get_unchecked(at.index()) }
            }

            /// The fixed 32-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits32(&self, at: ValueAt) -> u32 {
                // SAFETY: `at` was minted by `push_bits32` and the column
                // never shrinks.
                unsafe { *self.bits32.get_unchecked(at.index()) }
            }

            /// The fixed 64-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits64(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_bits64` and the column
                // never shrinks.
                unsafe { *self.bits64.get_unchecked(at.index()) }
            }

            /// The extent of a registered payload: offset into the byte
            /// column and length.
            #[inline]
            pub(crate) fn span(&self, at: ValueAt) -> (u32, u32) {
                // SAFETY: `at` was minted by `push_bytes` and the span
                // table never shrinks.
                unsafe { *self.spans.get_unchecked(at.index()) }
            }

            /// The bytes of a registered payload.
            #[inline]
            pub(crate) fn span_bytes(&self, at: ValueAt) -> &[u8] {
                let (start, len) = self.span(at);
                let start = usize_of(start);
                // SAFETY: the span was minted in bounds by `push_bytes` or
                // `stage_finish`, and the byte column never truncates
                // below a minted span's end.
                unsafe { self.bytes.get_unchecked(start..start + usize_of(len)) }
            }

            /// The whole byte column: the backing zone for rows scanned out
            /// of authored payloads.
            #[inline]
            pub(crate) fn zone(&self) -> &[u8] {
                &self.bytes
            }
        }

        // The copied store's layout, pinned exactly per width: five
        // columns, one Vec each. A size pin, not a field-semantics
        // proof — any layout change lands here for review.
        const _: () = assert!(
            core::mem::size_of::<Store>() == if cfg!(target_pointer_width = "64") { 120 } else { 60 }
        );

    };
    (@store_priced noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        /// The priced command plan's store obligations: each push face
        /// splits into a fallible reservation (coordinate judged, slot
        /// capacity held, nothing written) and an infallible reserved
        /// push, so a priced command can secure every store obligation
        /// before its ledger reservation and commit without a fallible
        /// step behind it. The caller holds the machine exclusively
        /// between the pair, so the judged coordinate is the pushed one.
        impl Store {
            /// Judges the next varint coordinate and holds its slot.
            pub(crate) fn reserve_varint(&mut self) -> Result<ValueAt, StoreFault> {
                let at = mint(self.varints.len())?;
                self.varints.try_reserve(1).map_err(store_resource)?;
                Ok(at)
            }

            /// Registers a varint word behind
            /// [`reserve_varint`](Self::reserve_varint)'s held slot.
            pub(crate) fn push_varint_reserved(&mut self, word: u64) {
                debug_assert!(self.varints.len() < self.varints.capacity());
                self.varints.push(word);
            }

            /// Judges the next fixed 32-bit coordinate and holds its slot.
            pub(crate) fn reserve_bits32(&mut self) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits32.len())?;
                self.bits32.try_reserve(1).map_err(store_resource)?;
                Ok(at)
            }

            /// Registers a fixed 32-bit value behind
            /// [`reserve_bits32`](Self::reserve_bits32)'s held slot.
            pub(crate) fn push_bits32_reserved(&mut self, bits: u32) {
                debug_assert!(self.bits32.len() < self.bits32.capacity());
                self.bits32.push(bits);
            }

            /// Judges the next fixed 64-bit coordinate and holds its slot.
            pub(crate) fn reserve_bits64(&mut self) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits64.len())?;
                self.bits64.try_reserve(1).map_err(store_resource)?;
                Ok(at)
            }

            /// Registers a fixed 64-bit value behind
            /// [`reserve_bits64`](Self::reserve_bits64)'s held slot.
            pub(crate) fn push_bits64_reserved(&mut self, bits: u64) {
                debug_assert!(self.bits64.len() < self.bits64.capacity());
                self.bits64.push(bits);
            }

            /// Judges the next span coordinate and the byte column's
            /// domain for `len` more bytes, holding both capacities —
            /// [`push_bytes`](Self::push_bytes)'s judgments and
            /// reservations with nothing occupied.
            pub(crate) fn reserve_bytes(&mut self, len: usize) -> Result<ValueAt, StoreFault> {
                let at = mint(self.spans.len())?;
                let end = self.bytes.len().checked_add(len).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(At32::MAX.as_inner()) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(len).map_err(store_resource)?;
                self.spans.try_reserve(1).map_err(store_resource)?;
                Ok(at)
            }

            /// Registers a byte payload behind
            /// [`reserve_bytes`](Self::reserve_bytes)'s held capacities.
            pub(crate) fn push_bytes_reserved(&mut self, payload: &[u8]) {
                debug_assert!(payload.len() <= self.bytes.capacity() - self.bytes.len());
                debug_assert!(self.spans.len() < self.spans.capacity());
                let start = self.bytes.len();
                self.bytes.extend_from_slice(payload);
                #[allow(
                    clippy::as_conversions,
                    reason = "start and the payload length are bounded by reserve_bytes's At32 end
                              judgment"
                )]
                self.spans.push((start as u32, payload.len() as u32));
            }

            /// Judges the staged extent's span coordinate and holds its
            /// slot — [`stage_finish`](Self::stage_finish)'s judgment and
            /// reservation with the span not yet minted.
            pub(crate) fn stage_finish_reserve(&mut self) -> Result<ValueAt, StoreFault> {
                let at = mint(self.spans.len())?;
                self.spans.try_reserve(1).map_err(store_resource)?;
                Ok(at)
            }

            /// Mints the span of the staged extent since `mark` behind
            /// [`stage_finish_reserve`](Self::stage_finish_reserve)'s
            /// held slot.
            pub(crate) fn stage_finish_reserved(&mut self, mark: u32) {
                debug_assert!(self.spans.len() < self.spans.capacity());
                self.spans.push((mark, self.stage_mark() - mark));
            }
        }

    };
    (@store_borrow noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        /// Replacement and insertion values for the borrowed-payload
        #[doc = concat!(" ", $noun, ": the scalar columns of [`Store`], with the copied")]
        /// byte column replaced by an append-only table of borrowed
        /// payload slots.
        ///
        /// One immutable slot per install, never overwritten and never
        /// truncated: a revert's restored coordinate therefore still
        /// names the exact bytes its command installed. Each slot is
        /// its own backing zone — the slice the caller handed over,
        #[doc = concat!(" immutable and alive for `'p`, which outlives the ", $noun, ".")]
        ///
        /// Coordinates are minted by the pushes and never invalidated,
        /// so a slot read is judgment-free for the coordinate's whole
        /// life. Invariant: every slot's length sits in the length
        /// class — the command faces judge `PayloadTooLarge` before
        /// any push. Failure ordering inside a push (allocator
        /// refusal against coordinate exhaustion) is deliberately
        /// unpromised.
        pub(crate) struct BorrowStore<'p> {
            /// Varint words.
            varints: Vec<u64>,
            /// Fixed 32-bit values.
            bits32: Vec<u32>,
            /// Fixed 64-bit values.
            bits64: Vec<u64>,
            /// Borrowed payload slots, one per install.
            slots: Vec<&'p [u8]>,
        }

        impl<'p> BorrowStore<'p> {
            /// An empty store; allocation happens per push.
            pub(crate) const fn new() -> Self {
                Self { varints: Vec::new(), bits32: Vec::new(), bits64: Vec::new(), slots: Vec::new() }
            }

            /// Registers a varint word; returns its coordinate.
            pub(crate) fn push_varint(&mut self, word: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.varints.len())?;
                append(&mut self.varints, word)?;
                Ok(at)
            }

            /// Registers a fixed 32-bit value; returns its coordinate.
            pub(crate) fn push_bits32(&mut self, bits: u32) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits32.len())?;
                append(&mut self.bits32, bits)?;
                Ok(at)
            }

            /// Registers a fixed 64-bit value; returns its coordinate.
            pub(crate) fn push_bits64(&mut self, bits: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits64.len())?;
                append(&mut self.bits64, bits)?;
                Ok(at)
            }

            /// Retains a borrowed payload as a fresh immutable slot;
            /// returns its coordinate. Nothing is copied: the slot table
            /// holds the caller's slice until the store drops, and the
            /// caller proved the length class before pushing.
            pub(crate) fn push_slot(&mut self, payload: &'p [u8]) -> Result<ValueAt, StoreFault> {
                let at = mint(self.slots.len())?;
                append(&mut self.slots, payload)?;
                Ok(at)
            }

            /// The varint word at a minted coordinate.
            #[inline]
            pub(crate) fn varint(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_varint` and the column
                // never shrinks.
                unsafe { *self.varints.get_unchecked(at.index()) }
            }

            /// The fixed 32-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits32(&self, at: ValueAt) -> u32 {
                // SAFETY: `at` was minted by `push_bits32` and the column
                // never shrinks.
                unsafe { *self.bits32.get_unchecked(at.index()) }
            }

            /// The fixed 64-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits64(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_bits64` and the column
                // never shrinks.
                unsafe { *self.bits64.get_unchecked(at.index()) }
            }

            /// The extent of a registered payload within its own zone: a
            /// slot is a whole zone, so the offset is zero and the length
            /// is the slice's, in the length class by the store invariant.
            #[inline]
            pub(crate) fn span(&self, at: ValueAt) -> (u32, u32) {
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::as_conversions,
                    reason = "every slot's length was judged into the length class before its push"
                )]
                let len = self.span_bytes(at).len() as u32;
                (0, len)
            }

            /// The bytes of a registered payload: the installed slice,
            /// whole.
            #[inline]
            pub(crate) fn span_bytes(&self, at: ValueAt) -> &[u8] {
                // SAFETY: `at` was minted by `push_slot` and the slot
                // table is append-only — never overwritten, never
                // truncated — while the slice itself is immutable and
                // alive for `'p`, which covers the store's whole life.
                unsafe { *self.slots.get_unchecked(at.index()) }
            }
        }

        // The borrowed store's layout, pinned exactly per width (four
        // columns), with the cross-form delta retained. Both are size
        // pins, not field-semantics proofs: the delta alone would stay
        // green under a same-sized field substitution in both forms,
        // so the absolutes force any layout change through review.
        const _: () = {
            let w64 = cfg!(target_pointer_width = "64");
            assert!(core::mem::size_of::<BorrowStore<'_>>() == if w64 { 96 } else { 48 });
            assert!(
                core::mem::size_of::<BorrowStore<'_>>() + if w64 { 24 } else { 12 }
                    == core::mem::size_of::<Store>()
            );
        };

    };
    (@store_mixed noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        /// One payload install in [`MixStore`]: the backing the
        /// caller's face selected, tagged per slot.
        ///
        /// Either variant is one sealed backing zone of its own. On
        /// 64-bit targets the enum stays at the borrowed slice's 16
        /// bytes (the tag rides the slice pointer's niche) — pinned
        /// below so any representation change lands there for review;
        /// correctness never leans on the niche, every read matches
        /// the tag.
        #[derive(Clone, Copy)]
        pub(crate) enum MixSlot<'p> {
            /// A retained caller slice: immutable and alive for `'p`.
            Borrowed(&'p [u8]),
            /// A copied extent of the store's byte column — offset
            /// and length, so column reallocation cannot invalidate
            /// it.
            Copied {
                /// The extent's start in the byte column. An empty extent
                /// minted at a full column may start at the column cap
                /// (`At32::MAX + 1`), one past [`At32`]'s domain.
                start: u32,
                /// The extent's byte length, in the length class.
                len: u32,
            },
        }

        /// Replacement and insertion values for the mixed-backing
        #[doc = concat!(" ", $noun, ": the scalar columns of [`Store`], its copied byte")]
        /// column, and one append-only slot table naming both payload
        /// backings — the unsuffixed command faces retain borrowed
        /// slices, the `_copy` and staged-frame faces copy their
        /// bytes in.
        ///
        /// One immutable slot per install, never overwritten and
        /// never truncated: a revert's restored coordinate therefore
        /// still names the exact bytes its command installed,
        /// whichever backing they live in. Each slot is its own
        /// backing zone — a borrowed slot is the caller's slice,
        #[doc = concat!(" immutable and alive for `'p`, which outlives the ", $noun, "; a")]
        /// copied slot is its byte-column extent, which no later push
        /// or frame reclamation moves or truncates.
        ///
        /// Coordinates are minted by the pushes into one unified slot
        /// space and never invalidated, so a slot read is
        /// judgment-free for the coordinate's whole life. Invariant:
        /// every slot's length sits in the length class — the command
        /// faces judge `PayloadTooLarge` before any push. Failure
        /// ordering inside a push (allocator refusal against
        /// coordinate exhaustion) is deliberately unpromised.
        pub(crate) struct MixStore<'p> {
            /// Varint words.
            varints: Vec<u64>,
            /// Fixed 32-bit values.
            bits32: Vec<u32>,
            /// Fixed 64-bit values.
            bits64: Vec<u64>,
            /// Copied payload bytes, end to end.
            bytes: Vec<u8>,
            /// Payload slots, one per install, tagged per backing.
            slots: Vec<MixSlot<'p>>,
        }

        impl<'p> MixStore<'p> {
            /// An empty store; allocation happens per push.
            pub(crate) const fn new() -> Self {
                Self {
                    varints: Vec::new(),
                    bits32: Vec::new(),
                    bits64: Vec::new(),
                    bytes: Vec::new(),
                    slots: Vec::new(),
                }
            }

            /// Registers a varint word; returns its coordinate.
            pub(crate) fn push_varint(&mut self, word: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.varints.len())?;
                append(&mut self.varints, word)?;
                Ok(at)
            }

            /// Registers a fixed 32-bit value; returns its coordinate.
            pub(crate) fn push_bits32(&mut self, bits: u32) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits32.len())?;
                append(&mut self.bits32, bits)?;
                Ok(at)
            }

            /// Registers a fixed 64-bit value; returns its coordinate.
            pub(crate) fn push_bits64(&mut self, bits: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits64.len())?;
                append(&mut self.bits64, bits)?;
                Ok(at)
            }

            /// Retains a borrowed payload as a fresh immutable slot;
            /// returns its coordinate. Nothing is copied: the slot
            /// table holds the caller's slice until the store drops,
            /// and the caller proved the length class before pushing.
            /// The copied byte column is untouched.
            pub(crate) fn push_slot(&mut self, payload: &'p [u8]) -> Result<ValueAt, StoreFault> {
                let at = mint(self.slots.len())?;
                append(&mut self.slots, MixSlot::Borrowed(payload))?;
                Ok(at)
            }

            /// Copies a payload into the byte column and registers its
            /// extent as a fresh immutable slot; returns its
            /// coordinate — the same unified slot space
            /// [`push_slot`](Self::push_slot) mints from.
            ///
            /// The byte column is bounded by the zone-offset domain
            /// (all offsets into it must stay addressable as
            /// [`At32`]), so the end of the incoming payload is
            /// judged before anything is occupied; both reservations
            /// precede the writes, so the suffix cannot fail.
            pub(crate) fn push_bytes(&mut self, payload: &[u8]) -> Result<ValueAt, StoreFault> {
                let at = mint(self.slots.len())?;
                let start = self.bytes.len();
                let end = start.checked_add(payload.len()).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(At32::MAX.as_inner()) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(payload.len()).map_err(store_resource)?;
                self.slots.try_reserve(1).map_err(store_resource)?;
                // Both reservations held: the suffix cannot fail.
                self.bytes.extend_from_slice(payload);
                #[allow(
                    clippy::as_conversions,
                    reason = "start and the payload length are bounded by the At32 end judgment above"
                )]
                self.slots.push(MixSlot::Copied { start: start as u32, len: payload.len() as u32 });
                Ok(at)
            }

            /// The copied byte column's tail, marking a staged frame's
            /// start — in the `u32` domain by the push judgments (the
            /// column's end never passes `At32::MAX + 1`).
            #[allow(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "the column end is bounded by the At32 end judgment of every append"
            )]
            #[inline]
            pub(crate) const fn stage_mark(&self) -> u32 {
                self.bytes.len() as u32
            }

            /// Appends one staged chunk to the copied byte column —
            /// [`push_bytes`](Self::push_bytes)'s bounds and
            /// reservation, without the slot mint. Nothing references
            /// the staged extent until
            /// [`stage_finish`](Self::stage_finish) mints its slot, so
            /// the frame reclaims it with
            /// [`stage_abandon`](Self::stage_abandon) on every path
            /// that does not publish.
            pub(crate) fn stage_chunk(&mut self, chunk: &[u8]) -> Result<(), StoreFault> {
                let end = self.bytes.len().checked_add(chunk.len()).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(At32::MAX.as_inner()) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(chunk.len()).map_err(store_resource)?;
                self.bytes.extend_from_slice(chunk);
                Ok(())
            }

            /// Appends one staged chunk into bytes
            /// [`stage_reserve`](Self::stage_reserve) already judged
            /// and reserved — no judgment or reservation re-runs here.
            /// The caller proves the reserved extent covers this
            /// chunk: the sized door reserved the full declaration
            /// past the staging mark, its frame's declaration gate
            /// bounds every staged total inside it, and the frame's
            /// exclusive machine borrow keeps every other append out.
            pub(crate) fn stage_chunk_reserved(&mut self, chunk: &[u8]) {
                let at = self.bytes.len();
                debug_assert!(chunk.len() <= self.bytes.capacity() - at);
                // SAFETY: the door's reservation covers the staged extent
                // through the declaration, and the caller's gate proved
                // this chunk keeps the staged total inside it.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        chunk.as_ptr(),
                        self.bytes.as_mut_ptr().add(at),
                        chunk.len(),
                    );
                    self.bytes.set_len(at + chunk.len());
                }
            }

            /// Truncates the copied byte column to a staged frame's
            /// entry mark, reclaiming an abandoned or refused frame's
            /// staged bytes — offset space included. Sound because no
            /// minted slot crosses the mark: every copied extent below
            /// it was minted before the frame opened, borrowed slots
            /// never touch the column, the staged extent's own slot is
            /// minted only by the publishing finish, and the frame's
            /// exclusive machine borrow keeps every other push out.
            pub(crate) fn stage_abandon(&mut self, mark: u32) {
                self.bytes.truncate(usize_of(mark));
            }

            /// Reserves the copied byte column for `len` more staged
            /// bytes — the sized frame's single exact reservation,
            /// behind [`stage_chunk`](Self::stage_chunk)'s own domain
            /// judgment so nothing is reserved for a frame that could
            /// never finish.
            pub(crate) fn stage_reserve(&mut self, len: usize) -> Result<(), StoreFault> {
                let end = self.bytes.len().checked_add(len).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(At32::MAX.as_inner()) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(len).map_err(store_resource)
            }

            /// Mints the slot of the staged extent since `mark` —
            /// [`push_bytes`](Self::push_bytes)'s slot mint, decoupled
            /// from the bytes it covers.
            pub(crate) fn stage_finish(&mut self, mark: u32) -> Result<ValueAt, StoreFault> {
                let at = mint(self.slots.len())?;
                self.slots.try_reserve(1).map_err(store_resource)?;
                self.slots.push(MixSlot::Copied { start: mark, len: self.stage_mark() - mark });
                Ok(at)
            }

            /// The varint word at a minted coordinate.
            #[inline]
            pub(crate) fn varint(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_varint` and the column
                // never shrinks.
                unsafe { *self.varints.get_unchecked(at.index()) }
            }

            /// The fixed 32-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits32(&self, at: ValueAt) -> u32 {
                // SAFETY: `at` was minted by `push_bits32` and the column
                // never shrinks.
                unsafe { *self.bits32.get_unchecked(at.index()) }
            }

            /// The fixed 64-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits64(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_bits64` and the column
                // never shrinks.
                unsafe { *self.bits64.get_unchecked(at.index()) }
            }

            /// The slot at a minted coordinate.
            #[inline]
            fn slot(&self, at: ValueAt) -> MixSlot<'p> {
                // SAFETY: `at` was minted by a payload push or a staged
                // finish, and the slot table is append-only — never
                // overwritten, never truncated.
                unsafe { *self.slots.get_unchecked(at.index()) }
            }

            /// The extent of a registered payload within its own zone:
            /// a slot is a whole zone whichever backing it names, so
            /// the offset is zero and the length is the slot's, in
            /// the length class by the store invariant.
            #[inline]
            pub(crate) fn span(&self, at: ValueAt) -> (u32, u32) {
                match self.slot(at) {
                    MixSlot::Borrowed(bytes) => {
                        #[allow(
                            clippy::cast_possible_truncation,
                            clippy::as_conversions,
                            reason = "every slot's length was judged into the length class before \
                                      its push"
                        )]
                        let len = bytes.len() as u32;
                        (0, len)
                    }
                    MixSlot::Copied { len, .. } => (0, len),
                }
            }

            /// The bytes of a registered payload, whole: the installed
            /// slice, or the copied extent.
            #[inline]
            pub(crate) fn span_bytes(&self, at: ValueAt) -> &[u8] {
                match self.slot(at) {
                    // The slice is immutable and alive for `'p`, which
                    // covers the store's whole life.
                    MixSlot::Borrowed(bytes) => bytes,
                    MixSlot::Copied { start, len } => {
                        let start = usize_of(start);
                        // SAFETY: the extent was minted in bounds by
                        // `push_bytes` or `stage_finish`, and the byte
                        // column never truncates below a minted
                        // extent's end (only a staged frame's unminted
                        // tail is ever reclaimed).
                        unsafe { self.bytes.get_unchecked(start..start + usize_of(len)) }
                    }
                }
            }
        }

        // The mixed store's 64-bit layout, pinned exactly: the copied
        // store's five columns with the extent table replaced by the
        // tagged slot table, whose entry the pin holds at the
        // borrowed slice's own 16 bytes — the tag rides the slice
        // pointer's niche. Size pins, not field-semantics proofs: any
        // layout or representation change lands here for review.
        const _: () = {
            let w64 = cfg!(target_pointer_width = "64");
            assert!(core::mem::size_of::<MixSlot<'_>>() == if w64 { 16 } else { 12 });
            assert!(core::mem::size_of::<MixStore<'_>>() == if w64 { 120 } else { 60 });
            assert!(core::mem::size_of::<MixStore<'_>>() == core::mem::size_of::<Store>());
        };

    };
}

pub(crate) use revising_store;
