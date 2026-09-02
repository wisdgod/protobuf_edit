//! The revisable replay editors' shared store strata: the
//! coordinate classes, the kind-split edit algebra with its
//! revision-log entry, the 48-byte row with its two kind-coupled
//! role unions, and the three fallible value-store forms, emitted
//! as template arms the revisable replay cells (the maintain and
//! commission pairs) instantiate inside their own dialect modules
//! — names resolve against the instantiating module's imports,
//! exactly as the buffered revising template hosts its layer.
//!
//! The row banks what a replay walk cannot re-read: the scanned
//! scalar word rides an immutable role column (replacements go to
//! the store, so revert re-speaks the scanned reading with zero
//! walks), geometry rides one zone-relative coordinate column
//! plus derivable widths, and the tolerant variant banks the met
//! framing widths as stored input facts. Kind disjointness pays
//! for the layout: a scalar's end derives from its widths, a
//! LEN's from its declared length, a group's end rides the role
//! column — no end column exists, and both acceptance variants
//! pin at 48 bytes.
//!
//! Allocation policy: both instantiating cells sit on the
//! fallible side of the crate root's partition rule, so every
//! store face reserves before it occupies and surfaces refusal as
//! a structured fault. One command's infallible suffix is funded
//! by reservations covering the sum of its obligations — a face
//! that grows one column twice reserves the two counts' sum,
//! never relying on sequential reservations, which guarantee only
//! the larger count.

/// Emits the revisable replay store strata inside the caller's
/// module. Arms: `@coords` (the row, zone-offset, and store
/// coordinate classes), `@algebra` (the kind-split edit states
/// and the revision-log entry), `@word_role scalar`/`@word_role
/// full` (the 8-byte role union, the full form adding the
/// grouped dialect's end arm), `@len_role plain`/`@len_role met`
/// (the 4-byte role union, the met form adding the tolerant
/// varint's met-width arm), `@row tolerant`/`@row canonical`
/// (the 48-byte row), and `@store copied`/`@store borrow`/
/// `@store mixed` (the value-store forms; the copied arm carries
/// the shared fault and push helpers).
///
/// The instantiating module supplies by import: its dialect's
/// `RecordKind`, `FieldNumber`, `PayloadLen`, `WordWidth`,
/// `ValueWidth` (met arms), `SlotAt` and `AuthoredAt` from the
/// replay-source stratum, `Vec`, `TryReserveError`, and
/// `usize_of`.
macro_rules! revising_replay_store {
    (@coords) => {
        $crate::_macro::define_valid_range_type! {
            /// A row-arena coordinate: minted by arena append,
            /// judgment-free downstream. The domain ends below 2³¹,
            /// keeping `Option` free and leaving bit 31 for the
            /// revision-log entry's packed fresh mark.
            pub(crate) struct RowId(u32 as u32 in 0..=2_147_483_646) with new, new_unchecked;

            /// A byte offset into a sealed backing zone — the walked
            /// source, or one authored payload slot's own zone; the
            /// owning layer names which. Each zone judges its own
            /// end against this domain at admission (the source at
            /// the walk, an authored zone at its store push), so a
            /// held offset addresses admitted bytes. The excluded
            /// top value keeps `Option` free.
            pub(crate) struct At64(u64 as u64 in 0..=18_446_744_073_709_551_614)
                with new_unchecked;

            /// A store-column coordinate for the scalar columns:
            /// minted by the column's push, judgment-free
            /// downstream. The excluded top value keeps `Option`
            /// free.
            pub(crate) struct ValueAt(u32 as u32 in 0..=4_294_967_294) with new;
        }

        impl RowId {
            /// The arena index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        impl At64 {
            /// A source-zone offset: the whole-source coordinate
            /// class embeds identically (both domains exclude only
            /// their top value).
            #[inline]
            pub(crate) const fn from_source(at: SourceAt) -> Self {
                // SAFETY: `SourceAt` admits exactly this type's own
                // range, so the inner value is in range.
                unsafe { Self::new_unchecked(at.as_inner()) }
            }

            /// An authored-zone offset: the slot-relative class
            /// widens losslessly (its domain top sits far below
            /// this type's).
            #[inline]
            #[allow(
                clippy::as_conversions,
                reason = "u32 widens losslessly into u64, and `From` is not const"
            )]
            pub(crate) const fn from_authored(at: AuthoredAt) -> Self {
                // SAFETY: `AuthoredAt` tops at `u32::MAX - 1`, far
                // inside this type's range.
                unsafe { Self::new_unchecked(at.as_inner() as u64) }
            }
        }

        impl ValueAt {
            /// The column index this coordinate names.
            #[inline]
            pub(crate) const fn index(self) -> usize {
                usize_of(self.as_inner())
            }
        }

        // The niches pay for themselves: `Option` of each
        // coordinate is free.
        const _: () = {
            assert!(core::mem::size_of::<Option<RowId>>() == 4);
            assert!(core::mem::size_of::<Option<At64>>() == 8);
            assert!(core::mem::size_of::<Option<ValueAt>>() == 4);
        };
    };
    (@algebra) => {
        /// A row's edit state: the closed algebra every command
        /// transitions within, split by the row kind's store space
        /// — scalar-backed states carry a scalar-column
        /// coordinate, payload-backed states an authored-slot
        /// coordinate, so no stored coordinate can impersonate the
        /// other space.
        ///
        /// The families never mix: scanned scalar rows move
        /// through `Intact`, `Replaced`, and `Deleted`; scanned
        /// LEN rows through `Intact`, `ReplacedPayload`, and
        /// `DeletedPayload`; command-authored rows through their
        /// `Inserted` pairs (they have no virgin state to return
        /// to). Group rows are value-less and ride the scalar
        /// family's coordinate-free states (`Intact`,
        /// `Deleted(None)`, and — under the group sentinel their
        /// instantiating machine documents — the `Inserted` pair);
        /// the kind gates keep every value and payload reader off
        /// them. Deletion shrouds: the pre-deletion value rides
        /// the shroud so undeletion restores it exactly.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub(crate) enum Edit {
            /// As scanned; the row's immutable banked reading
            /// speaks.
            Intact,
            /// A scalar store value speaks for the value side.
            Replaced(ValueAt),
            /// Scalar shrouded; the pre-deletion replacement (if
            /// any) rides along.
            Deleted(Option<ValueAt>),
            /// Command-authored scalar, live; the store value
            /// speaks.
            Inserted(ValueAt),
            /// Command-authored scalar, shrouded (a ghost): stays
            /// in the topology, never emits, and is not dirt.
            InsertedDeleted(ValueAt),
            /// An authored payload slot speaks for the LEN's
            /// payload side.
            ReplacedPayload(SlotAt),
            /// LEN shrouded; the pre-deletion slot (if any) rides
            /// along.
            DeletedPayload(Option<SlotAt>),
            /// Command-authored LEN, live; the slot speaks.
            InsertedPayload(SlotAt),
            /// Command-authored LEN, shrouded (a ghost): stays in
            /// the topology, never emits, and is not dirt.
            InsertedDeletedPayload(SlotAt),
        }

        impl Edit {
            /// The scalar store value speaking for the row's value
            /// side, if any.
            pub(crate) const fn effective_value(self) -> Option<ValueAt> {
                match self {
                    Self::Replaced(v)
                    | Self::Deleted(Some(v))
                    | Self::Inserted(v)
                    | Self::InsertedDeleted(v) => Some(v),
                    _ => None,
                }
            }

            /// The authored slot speaking for the row's payload
            /// side, if any.
            pub(crate) const fn effective_slot(self) -> Option<SlotAt> {
                match self {
                    Self::ReplacedPayload(s)
                    | Self::DeletedPayload(Some(s))
                    | Self::InsertedPayload(s)
                    | Self::InsertedDeletedPayload(s) => Some(s),
                    _ => None,
                }
            }

            /// True when this state alone makes the row dirty.
            /// Ghosts are not dirty: an insert undone changes
            /// nothing observable.
            pub(crate) const fn own_dirty(self) -> bool {
                !matches!(
                    self,
                    Self::Intact
                        | Self::InsertedDeleted(_)
                        | Self::InsertedDeletedPayload(_)
                )
            }
        }

        /// One undo-log step: the row, the state to restore, and —
        /// packed into bit 31 of the coordinate word — whether this
        /// entry opened the row's pending history.
        ///
        /// Insertion logs the ghost as its past — reverting a birth
        /// shrouds the row, keeping topology monotone. The packing
        /// rides the spare bit `RowId`'s domain leaves free and
        /// keeps the entry at 12 bytes; a separate flag would pad
        /// the log's working set — the bytes the undo path streams
        /// — to 16.
        #[derive(Clone, Copy)]
        pub(crate) struct Transition {
            /// Bit 31: the fresh mark. Low 31 bits: the row
            /// coordinate.
            word: u32,
            pub(crate) from: Edit,
        }

        const _: () = assert!(core::mem::size_of::<Edit>() == 8);
        const _: () = assert!(core::mem::size_of::<Transition>() == 12);

        impl Transition {
            /// Packs one entry; the instantiating machine's log
            /// push is the sole construction point.
            #[inline]
            pub(crate) const fn new(row: RowId, from: Edit, fresh: bool) -> Self {
                Self { word: row.as_inner() | if fresh { 1 << 31 } else { 0 }, from }
            }

            /// The row this entry restores.
            #[inline]
            pub(crate) const fn row(self) -> RowId {
                // SAFETY: `new` packed a valid coordinate into the
                // low 31 bits, and the mask strips exactly the mark
                // bit.
                unsafe { RowId::new_unchecked(self.word & 0x7FFF_FFFF) }
            }

            /// True when the row had no earlier pending entry: the
            /// push raised the row's own-history mark, and the pop
            /// releases it. Exact because reverts run strictly
            /// last-in-first-out.
            #[inline]
            pub(crate) const fn fresh(self) -> bool {
                self.word >> 31 != 0
            }
        }
    };
    (@word_role scalar) => {
        $crate::replay_revise::revising_replay_store!(@word_role_base);
    };
    (@word_role full) => {
        $crate::replay_revise::revising_replay_store!(@word_role_base);

        impl ScalarWordOrGroupEnd {
            /// Banks a scanned group's end: the zone-relative
            /// coordinate one past the whole record (the interior
            /// and its end tag included).
            pub(crate) const fn group_end(kind: RecordKind, end: At64) -> Self {
                debug_assert!(
                    matches!(kind, RecordKind::Group),
                    "the end arm serves group rows alone"
                );
                Self { word: end.as_inner() }
            }

            /// The group's end coordinate, raw: one past the whole
            /// record in the row's zone (domain: the zone-offset
            /// class).
            pub(crate) const fn end(self, kind: RecordKind) -> u64 {
                debug_assert!(
                    matches!(kind, RecordKind::Group),
                    "the end arm serves group rows alone"
                );
                self.word
            }
        }
    };
    (@word_role_base) => {
        /// The row's 8-byte role column: a scanned scalar's
        /// immutable decoded word, a scanned group's end
        /// coordinate, or vacant (LEN and authored rows) — the row
        /// kind is the discriminant, so the column spends no tag.
        ///
        /// A private contract wrapper, not a raw union: every
        /// constructor takes the row kind it serves and refuses a
        /// foreign pairing, and every projection re-judges the
        /// kind, so a LEN row can never speak a scalar word nor a
        /// scalar row a group end.
        #[derive(Clone, Copy)]
        pub(crate) struct ScalarWordOrGroupEnd {
            /// The role's packed word; which reading is lawful is
            /// the row kind's to say.
            word: u64,
        }

        const _: () = assert!(core::mem::size_of::<ScalarWordOrGroupEnd>() == 8);

        impl ScalarWordOrGroupEnd {
            /// Banks a scanned scalar's decoded word — immutable
            /// for the row's life: replacements go to the store,
            /// so revert re-speaks this reading with zero walks.
            pub(crate) const fn scalar(kind: RecordKind, word: u64) -> Self {
                debug_assert!(
                    matches!(kind, RecordKind::Varint | RecordKind::I32 | RecordKind::I64),
                    "the word arm serves scalar rows alone"
                );
                Self { word }
            }

            /// The vacant role: LEN rows (their end derives from
            /// the declared length) and authored rows (their value
            /// lives in the store).
            pub(crate) const fn vacant() -> Self {
                Self { word: 0 }
            }

            /// The scanned scalar's decoded word.
            pub(crate) const fn word(self, kind: RecordKind) -> u64 {
                debug_assert!(
                    matches!(kind, RecordKind::Varint | RecordKind::I32 | RecordKind::I64),
                    "the word arm serves scalar rows alone"
                );
                self.word
            }
        }
    };
    (@len_role plain) => {
        $crate::replay_revise::revising_replay_store!(@len_role_base);
    };
    (@len_role met) => {
        $crate::replay_revise::revising_replay_store!(@len_role_base);

        impl PayloadLenOrValueWidth {
            /// Banks a tolerant varint's met value width: the
            /// ten-byte window, a stored input fact the save's
            /// verbatim windows are rebuilt from.
            #[allow(
                clippy::as_conversions,
                reason = "u8 widens losslessly into u32, and `From` is not const"
            )]
            pub(crate) const fn met(kind: RecordKind, width: ValueWidth) -> Self {
                debug_assert!(
                    matches!(kind, RecordKind::Varint),
                    "the met arm serves varint rows alone"
                );
                Self { len_or_width: width.as_inner() as u32 }
            }

            /// The met value width, raw (domain `1..=10`: minted
            /// from the ten-byte window type).
            pub(crate) const fn met_width(self, kind: RecordKind) -> u8 {
                debug_assert!(
                    matches!(kind, RecordKind::Varint),
                    "the met arm serves varint rows alone"
                );
                #[allow(
                    clippy::cast_possible_truncation,
                    clippy::as_conversions,
                    reason = "the met constructor stored a ten-byte-window width, which \
                              rides the byte domain"
                )]
                {
                    self.len_or_width as u8
                }
            }
        }
    };
    (@len_role_base) => {
        /// The row's 4-byte role column: a LEN's declared payload
        /// length, a tolerant varint's met value width, or vacant
        /// (fixed scalars, groups, authored rows) — the row kind
        /// is the discriminant, so the column spends no tag.
        ///
        /// A private contract wrapper, not a raw union: every
        /// constructor takes the row kind it serves and refuses a
        /// foreign pairing, and every projection re-judges the
        /// kind, so a five-byte site can never carry a value-window
        /// width nor a value site a payload length.
        #[derive(Clone, Copy)]
        pub(crate) struct PayloadLenOrValueWidth {
            /// The role's packed word: a length-class value for a
            /// LEN, a `1..=10` met width for a tolerant varint,
            /// zero when vacant; which reading is lawful is the
            /// row kind's to say.
            len_or_width: u32,
        }

        const _: () = assert!(core::mem::size_of::<PayloadLenOrValueWidth>() == 4);

        impl PayloadLenOrValueWidth {
            /// Banks a LEN's declared payload length.
            pub(crate) const fn len(kind: RecordKind, len: PayloadLen) -> Self {
                debug_assert!(
                    matches!(kind, RecordKind::Len),
                    "the length arm serves LEN rows alone"
                );
                Self { len_or_width: len.as_inner() }
            }

            /// The vacant role: fixed scalars (their widths are
            /// the kind's own), groups (their end rides the
            /// 8-byte role), and authored rows.
            pub(crate) const fn vacant() -> Self {
                Self { len_or_width: 0 }
            }

            /// The declared payload length, raw (domain: the
            /// length class, minted from `PayloadLen`).
            #[allow(
                clippy::as_conversions,
                reason = "u32 widens losslessly into u64, and `From` is not const"
            )]
            pub(crate) const fn payload_len(self, kind: RecordKind) -> u64 {
                debug_assert!(
                    matches!(kind, RecordKind::Len),
                    "the length arm serves LEN rows alone"
                );
                self.len_or_width as u64
            }
        }
    };
    (@row tolerant) => {
        /// One record row, 48 bytes. The arena is the tree: parent
        /// and sibling links thread it, so every walk climbs
        /// instead of recursing.
        ///
        /// Kind disjointness is the layout: no end column exists —
        /// a scalar's end derives from its met widths and the
        /// banked word, a LEN's from its declared length, a
        /// group's end rides the 8-byte role column. The scanned
        /// scalar word is immutable for the row's life
        /// (replacements go to the store), so revert re-speaks the
        /// scanned reading with zero walks. Widths are stored
        /// input facts: tolerant admission accepts padded framing,
        /// and span arithmetic must reproduce it byte-exactly.
        #[derive(Clone, Copy)]
        struct Row {
            /// The record head's offset in its backing zone — the
            /// walked source for source-backed layers, one
            /// authored slot's own zone for authored-zone layers
            /// (the owning layer names which). `None` for
            /// command-authored rows, which carry no geometry.
            at: Option<At64>,
            /// The row's edit state; the log restores it.
            edit: Edit,
            /// The kind-coupled 8-byte role: scalar word, group
            /// end, or vacant.
            word_or_end: ScalarWordOrGroupEnd,
            /// The head tag's field number.
            field: FieldNumber,
            /// The kind-coupled 4-byte role: declared LEN length,
            /// met varint value width, or vacant.
            len_or_met: PayloadLenOrValueWidth,
            /// Enclosing container (`None`: root level).
            parent: Option<RowId>,
            /// Next sibling in the chain.
            next: Option<RowId>,
            /// The child-slot column's packed payload; the
            /// instantiating machine's slot vocabulary reads it
            /// under its own flag bits.
            kids: u32,
            /// The record kind (the dialect table's vocabulary,
            /// verbatim) — the role columns' discriminant.
            kind: RecordKind,
            /// The machine's state bits.
            flags: u8,
            /// The head tag's met input width; `None` for authored
            /// rows, which have no source geometry.
            tag_width: Option<WordWidth>,
            /// The delimiter's met input width — a LEN's length
            /// prefix, or a group's end tag settled at its close.
            /// `None` for scalars and authored rows.
            delim_width: Option<WordWidth>,
        }

        const _: () = assert!(core::mem::size_of::<Row>() == 48);
    };
    (@row canonical) => {
        /// One record row, 48 bytes. The arena is the tree: parent
        /// and sibling links thread it, so every walk climbs
        /// instead of recursing.
        ///
        /// Kind disjointness is the layout: no end column exists —
        /// a scalar's end derives from the banked word (canonical
        /// admission proved met ≡ minimal, so widths are theorems
        /// of the word and field, never stored), a LEN's from its
        /// declared length, a group's end rides the 8-byte role
        /// column. The scanned scalar word is immutable for the
        /// row's life (replacements go to the store), so revert
        /// re-speaks the scanned reading with zero walks. The two
        /// met columns of the tolerant variant are erased here;
        /// padding absorbs the bytes — the erasure's value is
        /// type-level (no width fact exists to keep coherent), not
        /// size.
        #[derive(Clone, Copy)]
        struct Row {
            /// The record head's offset in its backing zone — the
            /// walked source for source-backed layers, one
            /// authored slot's own zone for authored-zone layers
            /// (the owning layer names which). `None` for
            /// command-authored rows, which carry no geometry.
            at: Option<At64>,
            /// The row's edit state; the log restores it.
            edit: Edit,
            /// The kind-coupled 8-byte role: scalar word, group
            /// end, or vacant.
            word_or_end: ScalarWordOrGroupEnd,
            /// The head tag's field number.
            field: FieldNumber,
            /// The kind-coupled 4-byte role: declared LEN length
            /// or vacant.
            len_or_met: PayloadLenOrValueWidth,
            /// Enclosing container (`None`: root level).
            parent: Option<RowId>,
            /// Next sibling in the chain.
            next: Option<RowId>,
            /// The child-slot column's packed payload; the
            /// instantiating machine's slot vocabulary reads it
            /// under its own flag bits.
            kids: u32,
            /// The record kind (the dialect table's vocabulary,
            /// verbatim) — the role columns' discriminant.
            kind: RecordKind,
            /// The machine's state bits.
            flags: u8,
        }

        const _: () = assert!(core::mem::size_of::<Row>() <= 48);
        const _: () = assert!(core::mem::size_of::<Row>() == 48);
    };
    (@store copied) => {
        /// Why a store push refused.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub(crate) enum StoreFault {
            /// The allocator refused column growth.
            Resource,
            /// A column's coordinate space is spent.
            Exhausted,
        }

        /// Appends to a column after a fallible one-slot
        /// reservation.
        fn append<T>(column: &mut Vec<T>, value: T) -> Result<(), StoreFault> {
            column.try_reserve(1).map_err(store_resource)?;
            let len = column.len();
            // SAFETY: the reservation above guarantees one spare
            // slot past the current length.
            unsafe {
                column.as_mut_ptr().add(len).write(value);
                column.set_len(len + 1);
            }
            Ok(())
        }

        /// Mints the next scalar-column coordinate.
        fn mint(len: usize) -> Result<ValueAt, StoreFault> {
            u32::try_from(len).ok().and_then(ValueAt::new).ok_or(StoreFault::Exhausted)
        }

        /// Mints the next authored-slot coordinate.
        fn mint_slot(len: usize) -> Result<SlotAt, StoreFault> {
            u32::try_from(len).ok().and_then(SlotAt::new).ok_or(StoreFault::Exhausted)
        }

        #[cold]
        const fn store_resource(_refused: TryReserveError) -> StoreFault {
            StoreFault::Resource
        }

        /// Replacement and insertion values, in dense per-kind
        /// columns: the copying form — payload installs copy their
        /// bytes into the store's byte column.
        ///
        /// Coordinates are minted by the pushes and never
        /// invalidated: every column is append-only and the byte
        /// column never truncates below a minted extent (only a
        /// staged frame's unpublished tail is ever reclaimed), so
        /// a read is judgment-free for the coordinate's whole
        /// life. Each authored payload is its own sealed zone —
        /// its end is admitted against the zone-offset domain at
        /// the push, the judgment the fault carriers' slot
        /// coordinates rely on. Invariant: every slot's length
        /// sits in the length class — the command faces judge
        /// `PayloadTooLarge` before any push. Failure ordering
        /// inside a push (allocator refusal against coordinate
        /// exhaustion) is deliberately unpromised.
        pub(crate) struct Store {
            /// Varint words.
            varints: Vec<u64>,
            /// Fixed 32-bit values.
            bits32: Vec<u32>,
            /// Fixed 64-bit values.
            bits64: Vec<u64>,
            /// Copied payload bytes, end to end.
            bytes: Vec<u8>,
            /// Authored-slot extents into `bytes`: offset and
            /// length. An empty extent minted at a full column may
            /// start one past the zone-offset domain's top.
            spans: Vec<(u32, u32)>,
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

            /// Registers a fixed 32-bit value; returns its
            /// coordinate.
            pub(crate) fn push_bits32(&mut self, bits: u32) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits32.len())?;
                append(&mut self.bits32, bits)?;
                Ok(at)
            }

            /// Registers a fixed 64-bit value; returns its
            /// coordinate.
            pub(crate) fn push_bits64(&mut self, bits: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits64.len())?;
                append(&mut self.bits64, bits)?;
                Ok(at)
            }

            /// Copies a payload into the byte column and registers
            /// it as a fresh immutable authored slot; returns its
            /// coordinate.
            ///
            /// The byte column is bounded by the zone-offset
            /// domain (all offsets into it must stay addressable),
            /// so the end of the incoming payload is judged before
            /// anything is occupied; both reservations precede the
            /// writes, so the suffix cannot fail — one push's two
            /// obligations land in two columns, each behind its
            /// own held reservation.
            pub(crate) fn push_bytes(&mut self, payload: &[u8]) -> Result<SlotAt, StoreFault> {
                let at = mint_slot(self.spans.len())?;
                let start = self.bytes.len();
                let end = start.checked_add(payload.len()).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(u32::MAX - 1) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(payload.len()).map_err(store_resource)?;
                self.spans.try_reserve(1).map_err(store_resource)?;
                // Both reservations held: the suffix cannot fail.
                self.bytes.extend_from_slice(payload);
                #[allow(
                    clippy::as_conversions,
                    reason = "start and the payload length are bounded by the zone-offset \
                              end judgment above"
                )]
                self.spans.push((start as u32, payload.len() as u32));
                Ok(at)
            }

            /// The byte column's tail, marking a staged frame's
            /// start — in the `u32` domain by the push judgments
            /// (the column's end never passes the zone-offset
            /// domain's top plus one).
            #[allow(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "the column end is bounded by the zone-offset end judgment of \
                          every append"
            )]
            #[inline]
            pub(crate) const fn stage_mark(&self) -> u32 {
                self.bytes.len() as u32
            }

            /// Appends one staged chunk to the byte column —
            /// `push_bytes`'s bounds and reservation, without the
            /// slot mint. Nothing references the staged extent
            /// until `stage_finish` mints its slot, so the frame
            /// reclaims it with `stage_abandon` on every path that
            /// does not publish.
            pub(crate) fn stage_chunk(&mut self, chunk: &[u8]) -> Result<(), StoreFault> {
                let end = self.bytes.len().checked_add(chunk.len()).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(u32::MAX - 1) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(chunk.len()).map_err(store_resource)?;
                self.bytes.extend_from_slice(chunk);
                Ok(())
            }

            /// Reserves the byte column for `len` more staged
            /// bytes — the sized frame's single exact reservation
            /// (one reservation funds the frame's whole staged
            /// total), behind `stage_chunk`'s own domain judgment
            /// so nothing is reserved for a frame that could never
            /// finish.
            pub(crate) fn stage_reserve(&mut self, len: usize) -> Result<(), StoreFault> {
                let end = self.bytes.len().checked_add(len).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(u32::MAX - 1) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(len).map_err(store_resource)
            }

            /// Appends one staged chunk into bytes `stage_reserve`
            /// already judged and reserved — no judgment or
            /// reservation re-runs here. The caller proves the
            /// reserved extent covers this chunk: the sized door
            /// reserved the full declaration past the staging
            /// mark, its frame's declaration gate bounds every
            /// staged total inside it, and the frame's exclusive
            /// machine borrow keeps every other append out.
            pub(crate) fn stage_chunk_reserved(&mut self, chunk: &[u8]) {
                let at = self.bytes.len();
                debug_assert!(chunk.len() <= self.bytes.capacity() - at);
                // SAFETY: the door's reservation covers the staged
                // extent through the declaration, and the caller's
                // gate proved this chunk keeps the staged total
                // inside it.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        chunk.as_ptr(),
                        self.bytes.as_mut_ptr().add(at),
                        chunk.len(),
                    );
                    self.bytes.set_len(at + chunk.len());
                }
            }

            /// Truncates the byte column to a staged frame's entry
            /// mark, reclaiming an abandoned or refused frame's
            /// staged bytes — offset space included. Sound because
            /// no minted extent crosses the mark: every extent
            /// below it was minted before the frame opened, the
            /// staged extent's own slot is minted only by the
            /// publishing finish, and the frame's exclusive
            /// machine borrow keeps every other push out.
            pub(crate) fn stage_abandon(&mut self, mark: u32) {
                self.bytes.truncate(usize_of(mark));
            }

            /// Mints the slot of the staged extent since `mark` —
            /// `push_bytes`'s slot mint, decoupled from the bytes
            /// it covers.
            pub(crate) fn stage_finish(&mut self, mark: u32) -> Result<SlotAt, StoreFault> {
                let at = mint_slot(self.spans.len())?;
                self.spans.try_reserve(1).map_err(store_resource)?;
                self.spans.push((mark, self.stage_mark() - mark));
                Ok(at)
            }

            /// The varint word at a minted coordinate.
            #[inline]
            pub(crate) fn varint(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_varint` and the
                // column never shrinks.
                unsafe { *self.varints.get_unchecked(at.index()) }
            }

            /// The fixed 32-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits32(&self, at: ValueAt) -> u32 {
                // SAFETY: `at` was minted by `push_bits32` and the
                // column never shrinks.
                unsafe { *self.bits32.get_unchecked(at.index()) }
            }

            /// The fixed 64-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits64(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_bits64` and the
                // column never shrinks.
                unsafe { *self.bits64.get_unchecked(at.index()) }
            }

            /// One authored slot's bytes: the slot's own sealed
            /// zone, whole.
            #[inline]
            pub(crate) fn zone_bytes(&self, at: SlotAt) -> &[u8] {
                // SAFETY: the extent was minted in bounds by
                // `push_bytes` or `stage_finish`, the slot table
                // never shrinks, and the byte column never
                // truncates below a minted extent's end (only a
                // staged frame's unminted tail is ever reclaimed).
                unsafe {
                    let (start, len) = *self.spans.get_unchecked(usize_of(at.as_inner()));
                    let start = usize_of(start);
                    self.bytes.get_unchecked(start..start + usize_of(len))
                }
            }
        }

        // The copied store's layout, pinned exactly per width:
        // five columns, one Vec each. A size pin, not a
        // field-semantics proof — any layout change lands here for
        // review.
        const _: () = assert!(
            core::mem::size_of::<Store>() == if cfg!(target_pointer_width = "64") { 120 } else { 60 }
        );
    };
    (@store borrow) => {
        /// Replacement and insertion values for the borrowed-
        /// payload form: the scalar columns of the copying store,
        /// with the copied byte column replaced by an append-only
        /// table of borrowed payload slots.
        ///
        /// One immutable slot per install, never overwritten and
        /// never truncated: a revert's restored coordinate
        /// therefore still names the exact bytes its command
        /// installed. Each slot is its own sealed zone — the slice
        /// the caller handed over, immutable and alive for `'p`,
        /// which outlives the machine; its end is admitted against
        /// the zone-offset domain by the length-class invariant
        /// (the command faces judge `PayloadTooLarge` before any
        /// push). Coordinates are minted by the pushes and never
        /// invalidated. Failure ordering inside a push (allocator
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
                Self {
                    varints: Vec::new(),
                    bits32: Vec::new(),
                    bits64: Vec::new(),
                    slots: Vec::new(),
                }
            }

            /// Registers a varint word; returns its coordinate.
            pub(crate) fn push_varint(&mut self, word: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.varints.len())?;
                append(&mut self.varints, word)?;
                Ok(at)
            }

            /// Registers a fixed 32-bit value; returns its
            /// coordinate.
            pub(crate) fn push_bits32(&mut self, bits: u32) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits32.len())?;
                append(&mut self.bits32, bits)?;
                Ok(at)
            }

            /// Registers a fixed 64-bit value; returns its
            /// coordinate.
            pub(crate) fn push_bits64(&mut self, bits: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits64.len())?;
                append(&mut self.bits64, bits)?;
                Ok(at)
            }

            /// Retains a borrowed payload as a fresh immutable
            /// slot; returns its coordinate. Nothing is copied:
            /// the slot table holds the caller's slice until the
            /// store drops, and the caller proved the length class
            /// before pushing.
            pub(crate) fn push_slot(&mut self, payload: &'p [u8]) -> Result<SlotAt, StoreFault> {
                let at = mint_slot(self.slots.len())?;
                append(&mut self.slots, payload)?;
                Ok(at)
            }

            /// The varint word at a minted coordinate.
            #[inline]
            pub(crate) fn varint(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_varint` and the
                // column never shrinks.
                unsafe { *self.varints.get_unchecked(at.index()) }
            }

            /// The fixed 32-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits32(&self, at: ValueAt) -> u32 {
                // SAFETY: `at` was minted by `push_bits32` and the
                // column never shrinks.
                unsafe { *self.bits32.get_unchecked(at.index()) }
            }

            /// The fixed 64-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits64(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_bits64` and the
                // column never shrinks.
                unsafe { *self.bits64.get_unchecked(at.index()) }
            }

            /// One authored slot's bytes: the installed slice,
            /// whole — the slot's own sealed zone.
            #[inline]
            pub(crate) fn zone_bytes(&self, at: SlotAt) -> &[u8] {
                // SAFETY: `at` was minted by `push_slot` and the
                // slot table is append-only — never overwritten,
                // never truncated — while the slice itself is
                // immutable and alive for `'p`, which covers the
                // store's whole life.
                unsafe { *self.slots.get_unchecked(usize_of(at.as_inner())) }
            }
        }

        // The borrowed store's layout, pinned exactly per width
        // (four columns), with the cross-form delta retained. Both
        // are size pins, not field-semantics proofs: the delta
        // alone would stay green under a same-sized field
        // substitution in both forms, so the absolutes force any
        // layout change through review.
        const _: () = {
            let w64 = cfg!(target_pointer_width = "64");
            assert!(core::mem::size_of::<BorrowStore<'_>>() == if w64 { 96 } else { 48 });
            assert!(
                core::mem::size_of::<BorrowStore<'_>>() + if w64 { 24 } else { 12 }
                    == core::mem::size_of::<Store>()
            );
        };
    };
    (@store mixed) => {
        /// One payload install in [`MixStore`]: the backing the
        /// caller's face selected, tagged per slot.
        ///
        /// Either variant is one sealed backing zone of its own.
        /// On 64-bit targets the enum stays at the borrowed
        /// slice's 16 bytes (the tag rides the slice pointer's
        /// niche) — pinned below so any representation change
        /// lands there for review; correctness never leans on the
        /// niche, every read matches the tag.
        #[derive(Clone, Copy)]
        pub(crate) enum MixSlot<'p> {
            /// A retained caller slice: immutable and alive for
            /// `'p`.
            Borrowed(&'p [u8]),
            /// A copied extent of the store's byte column — offset
            /// and length, so column reallocation cannot
            /// invalidate it.
            Copied {
                /// The extent's start in the byte column. An empty
                /// extent minted at a full column may start one
                /// past the zone-offset domain's top.
                start: u32,
                /// The extent's byte length, in the length class.
                len: u32,
            },
        }

        /// Replacement and insertion values for the mixed-backing
        /// form: the scalar columns, the copied byte column, and
        /// one append-only slot table naming both payload backings
        /// — the unsuffixed command faces retain borrowed slices,
        /// the `_copy` and staged-frame faces copy their bytes in.
        ///
        /// One immutable slot per install, never overwritten and
        /// never truncated: a revert's restored coordinate
        /// therefore still names the exact bytes its command
        /// installed, whichever backing they live in. Each slot is
        /// its own sealed zone, its end admitted against the
        /// zone-offset domain at the push. Coordinates are minted
        /// by the pushes into one unified slot space and never
        /// invalidated. Invariant: every slot's length sits in the
        /// length class — the command faces judge
        /// `PayloadTooLarge` before any push. Failure ordering
        /// inside a push (allocator refusal against coordinate
        /// exhaustion) is deliberately unpromised.
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

            /// Registers a fixed 32-bit value; returns its
            /// coordinate.
            pub(crate) fn push_bits32(&mut self, bits: u32) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits32.len())?;
                append(&mut self.bits32, bits)?;
                Ok(at)
            }

            /// Registers a fixed 64-bit value; returns its
            /// coordinate.
            pub(crate) fn push_bits64(&mut self, bits: u64) -> Result<ValueAt, StoreFault> {
                let at = mint(self.bits64.len())?;
                append(&mut self.bits64, bits)?;
                Ok(at)
            }

            /// Retains a borrowed payload as a fresh immutable
            /// slot; returns its coordinate. Nothing is copied:
            /// the slot table holds the caller's slice until the
            /// store drops, and the caller proved the length class
            /// before pushing. The copied byte column is
            /// untouched.
            pub(crate) fn push_slot(&mut self, payload: &'p [u8]) -> Result<SlotAt, StoreFault> {
                let at = mint_slot(self.slots.len())?;
                append(&mut self.slots, MixSlot::Borrowed(payload))?;
                Ok(at)
            }

            /// Copies a payload into the byte column and registers
            /// its extent as a fresh immutable slot; returns its
            /// coordinate — the same unified slot space
            /// `push_slot` mints from.
            ///
            /// The byte column is bounded by the zone-offset
            /// domain (all offsets into it must stay addressable),
            /// so the end of the incoming payload is judged before
            /// anything is occupied; both reservations precede the
            /// writes, so the suffix cannot fail.
            pub(crate) fn push_bytes(&mut self, payload: &[u8]) -> Result<SlotAt, StoreFault> {
                let at = mint_slot(self.slots.len())?;
                let start = self.bytes.len();
                let end = start.checked_add(payload.len()).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(u32::MAX - 1) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(payload.len()).map_err(store_resource)?;
                self.slots.try_reserve(1).map_err(store_resource)?;
                // Both reservations held: the suffix cannot fail.
                self.bytes.extend_from_slice(payload);
                #[allow(
                    clippy::as_conversions,
                    reason = "start and the payload length are bounded by the zone-offset \
                              end judgment above"
                )]
                self.slots.push(MixSlot::Copied { start: start as u32, len: payload.len() as u32 });
                Ok(at)
            }

            /// The copied byte column's tail, marking a staged
            /// frame's start — in the `u32` domain by the push
            /// judgments (the column's end never passes the
            /// zone-offset domain's top plus one).
            #[allow(
                clippy::cast_possible_truncation,
                clippy::as_conversions,
                reason = "the column end is bounded by the zone-offset end judgment of \
                          every append"
            )]
            #[inline]
            pub(crate) const fn stage_mark(&self) -> u32 {
                self.bytes.len() as u32
            }

            /// Appends one staged chunk to the copied byte column
            /// — `push_bytes`'s bounds and reservation, without
            /// the slot mint. Nothing references the staged extent
            /// until `stage_finish` mints its slot, so the frame
            /// reclaims it with `stage_abandon` on every path that
            /// does not publish.
            pub(crate) fn stage_chunk(&mut self, chunk: &[u8]) -> Result<(), StoreFault> {
                let end = self.bytes.len().checked_add(chunk.len()).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(u32::MAX - 1) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(chunk.len()).map_err(store_resource)?;
                self.bytes.extend_from_slice(chunk);
                Ok(())
            }

            /// Reserves the copied byte column for `len` more
            /// staged bytes — the sized frame's single exact
            /// reservation (one reservation funds the frame's
            /// whole staged total), behind `stage_chunk`'s own
            /// domain judgment so nothing is reserved for a frame
            /// that could never finish.
            pub(crate) fn stage_reserve(&mut self, len: usize) -> Result<(), StoreFault> {
                let end = self.bytes.len().checked_add(len).ok_or(StoreFault::Exhausted)?;
                if end > usize_of(u32::MAX - 1) + 1 {
                    return Err(StoreFault::Exhausted);
                }
                self.bytes.try_reserve(len).map_err(store_resource)
            }

            /// Appends one staged chunk into bytes `stage_reserve`
            /// already judged and reserved — no judgment or
            /// reservation re-runs here. The caller proves the
            /// reserved extent covers this chunk: the sized door
            /// reserved the full declaration past the staging
            /// mark, its frame's declaration gate bounds every
            /// staged total inside it, and the frame's exclusive
            /// machine borrow keeps every other append out.
            pub(crate) fn stage_chunk_reserved(&mut self, chunk: &[u8]) {
                let at = self.bytes.len();
                debug_assert!(chunk.len() <= self.bytes.capacity() - at);
                // SAFETY: the door's reservation covers the staged
                // extent through the declaration, and the caller's
                // gate proved this chunk keeps the staged total
                // inside it.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        chunk.as_ptr(),
                        self.bytes.as_mut_ptr().add(at),
                        chunk.len(),
                    );
                    self.bytes.set_len(at + chunk.len());
                }
            }

            /// Truncates the copied byte column to a staged
            /// frame's entry mark, reclaiming an abandoned or
            /// refused frame's staged bytes — offset space
            /// included. Sound because no minted slot crosses the
            /// mark: every copied extent below it was minted
            /// before the frame opened, borrowed slots never touch
            /// the column, the staged extent's own slot is minted
            /// only by the publishing finish, and the frame's
            /// exclusive machine borrow keeps every other push
            /// out.
            pub(crate) fn stage_abandon(&mut self, mark: u32) {
                self.bytes.truncate(usize_of(mark));
            }

            /// Mints the slot of the staged extent since `mark` —
            /// `push_bytes`'s slot mint, decoupled from the bytes
            /// it covers.
            pub(crate) fn stage_finish(&mut self, mark: u32) -> Result<SlotAt, StoreFault> {
                let at = mint_slot(self.slots.len())?;
                self.slots.try_reserve(1).map_err(store_resource)?;
                self.slots.push(MixSlot::Copied { start: mark, len: self.stage_mark() - mark });
                Ok(at)
            }

            /// The varint word at a minted coordinate.
            #[inline]
            pub(crate) fn varint(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_varint` and the
                // column never shrinks.
                unsafe { *self.varints.get_unchecked(at.index()) }
            }

            /// The fixed 32-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits32(&self, at: ValueAt) -> u32 {
                // SAFETY: `at` was minted by `push_bits32` and the
                // column never shrinks.
                unsafe { *self.bits32.get_unchecked(at.index()) }
            }

            /// The fixed 64-bit value at a minted coordinate.
            #[inline]
            pub(crate) fn bits64(&self, at: ValueAt) -> u64 {
                // SAFETY: `at` was minted by `push_bits64` and the
                // column never shrinks.
                unsafe { *self.bits64.get_unchecked(at.index()) }
            }

            /// One authored slot's bytes, whole: the installed
            /// slice, or the copied extent — the slot's own sealed
            /// zone.
            #[inline]
            pub(crate) fn zone_bytes(&self, at: SlotAt) -> &[u8] {
                // SAFETY: `at` was minted by a payload push or a
                // staged finish, and the slot table is append-only
                // — never overwritten, never truncated.
                match unsafe { *self.slots.get_unchecked(usize_of(at.as_inner())) } {
                    // The slice is immutable and alive for `'p`,
                    // which covers the store's whole life.
                    MixSlot::Borrowed(bytes) => bytes,
                    MixSlot::Copied { start, len } => {
                        let start = usize_of(start);
                        // SAFETY: the extent was minted in bounds
                        // by `push_bytes` or `stage_finish`, and
                        // the byte column never truncates below a
                        // minted extent's end (only a staged
                        // frame's unminted tail is ever reclaimed).
                        unsafe { self.bytes.get_unchecked(start..start + usize_of(len)) }
                    }
                }
            }
        }

        // The mixed store's layout, pinned exactly: the copied
        // store's five columns with the extent table replaced by
        // the tagged slot table, whose entry the pin holds at the
        // borrowed slice's own 16 bytes — the tag rides the slice
        // pointer's niche. Size pins, not field-semantics proofs:
        // any layout or representation change lands here for
        // review.
        const _: () = {
            let w64 = cfg!(target_pointer_width = "64");
            assert!(core::mem::size_of::<MixSlot<'_>>() == if w64 { 16 } else { 12 });
            assert!(core::mem::size_of::<MixStore<'_>>() == if w64 { 120 } else { 60 });
            assert!(core::mem::size_of::<MixStore<'_>>() == core::mem::size_of::<Store>());
        };
    };
}

#[cfg(any(
    test,
    feature = "maintain-grouped",
    feature = "maintain-groupless",
    feature = "commission-grouped",
    feature = "commission-groupless"
))]
pub(crate) use revising_replay_store;

#[cfg(test)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "the strata templates spell crate-wide visibility because their \
              shipping instantiations live in public facade and dialect modules; \
              this module's private re-instantiation is the one context where \
              that spelling reads as redundant"
)]
mod tests {
    /// One instantiation of the dialect-invariant arms — the
    /// coordinate classes, the edit algebra with its log entry,
    /// and the three store forms — exercised whole; the row
    /// modules below import these types instead of re-emitting
    /// them.
    mod strata {
        use alloc::collections::TryReserveError;
        use alloc::vec::Vec;

        use crate::admission::usize_of;
        use crate::replay_source::{AuthoredAt, SlotAt, SourceAt};

        crate::replay_revise::revising_replay_store!(@coords);
        crate::replay_revise::revising_replay_store!(@algebra);
        crate::replay_revise::revising_replay_store!(@store copied);
        crate::replay_revise::revising_replay_store!(@store borrow);
        crate::replay_revise::revising_replay_store!(@store mixed);

        #[test]
        fn the_shared_columns_hold_their_pins() {
            assert_eq!(core::mem::size_of::<Edit>(), 8);
            assert_eq!(core::mem::size_of::<Transition>(), 12);
            assert_eq!(core::mem::size_of::<Option<RowId>>(), 4);
            assert_eq!(core::mem::size_of::<Option<At64>>(), 8);
            assert_eq!(core::mem::size_of::<Option<ValueAt>>(), 4);
        }

        #[test]
        fn the_coordinates_mint_and_index() {
            let row = RowId::new(7).unwrap();
            assert_eq!((row.index(), row.as_inner()), (7, 7));
            let value = ValueAt::new(3).unwrap();
            assert_eq!(value.index(), 3);
        }

        #[test]
        fn zone_offsets_embed_both_coordinate_spaces() {
            // SAFETY: the source coordinate lies within its range.
            let source = unsafe { SourceAt::new_unchecked(u64::MAX - 1) };
            assert_eq!(At64::from_source(source).as_inner(), u64::MAX - 1);
            let authored = AuthoredAt::new(u32::MAX - 1).unwrap();
            assert_eq!(At64::from_authored(authored).as_inner(), u64::from(u32::MAX - 1));
        }

        #[test]
        fn the_edit_families_project_their_own_store_space() {
            let value = ValueAt::new(4).unwrap();
            let slot = SlotAt::new(9).unwrap();
            // The scalar-backed family speaks the scalar columns.
            assert_eq!(Edit::Replaced(value).effective_value(), Some(value));
            assert_eq!(Edit::Deleted(Some(value)).effective_value(), Some(value));
            assert_eq!(Edit::Deleted(None).effective_value(), None);
            assert_eq!(Edit::Inserted(value).effective_value(), Some(value));
            assert_eq!(Edit::InsertedDeleted(value).effective_value(), Some(value));
            assert_eq!(Edit::Replaced(value).effective_slot(), None);
            // The payload-backed family speaks the slot table.
            assert_eq!(Edit::ReplacedPayload(slot).effective_slot(), Some(slot));
            assert_eq!(Edit::DeletedPayload(Some(slot)).effective_slot(), Some(slot));
            assert_eq!(Edit::DeletedPayload(None).effective_slot(), None);
            assert_eq!(Edit::InsertedPayload(slot).effective_slot(), Some(slot));
            assert_eq!(Edit::InsertedDeletedPayload(slot).effective_slot(), Some(slot));
            assert_eq!(Edit::InsertedPayload(slot).effective_value(), None);
            // Ghosts are not dirt; everything else is its own.
            assert!(!Edit::Intact.own_dirty());
            assert!(!Edit::InsertedDeleted(value).own_dirty());
            assert!(!Edit::InsertedDeletedPayload(slot).own_dirty());
            assert!(Edit::Deleted(None).own_dirty());
            assert!(Edit::ReplacedPayload(slot).own_dirty());
        }

        #[test]
        fn the_log_entry_packs_the_fresh_mark_beside_the_row() {
            let row = RowId::new(2_147_483_646).unwrap();
            let slot = ValueAt::new(5).unwrap();
            let fresh = Transition::new(row, Edit::Replaced(slot), true);
            assert_eq!(fresh.row(), row);
            assert!(fresh.fresh());
            assert_eq!(fresh.from, Edit::Replaced(slot));
            let stale = Transition::new(RowId::new(0).unwrap(), Edit::Intact, false);
            assert_eq!(stale.row(), RowId::new(0).unwrap());
            assert!(!stale.fresh());
        }

        #[test]
        fn one_reservation_for_the_counted_sum_funds_the_log_suffix() {
            let mut log: Vec<Transition> = Vec::new();
            // Two obligations land in one column: reserve their
            // sum once, then the infallible suffix never grows or
            // moves the column.
            log.try_reserve(2).unwrap();
            let ptr = log.as_ptr();
            let cap = log.capacity();
            log.push(Transition::new(RowId::new(1).unwrap(), Edit::Intact, true));
            log.push(Transition::new(
                RowId::new(2).unwrap(),
                Edit::ReplacedPayload(SlotAt::new(0).unwrap()),
                false,
            ));
            assert!(core::ptr::eq(log.as_ptr(), ptr));
            assert_eq!(log.capacity(), cap);
        }

        #[test]
        fn the_copied_store_roundtrips_and_seals_its_zones() {
            let mut store = Store::new();
            assert_eq!(store.push_varint(150).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.push_varint(7).unwrap(), ValueAt::new(1).unwrap());
            assert_eq!(store.push_bits32(0xAB).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.push_bits64(0xCD).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.varint(ValueAt::new(1).unwrap()), 7);
            assert_eq!(store.bits32(ValueAt::new(0).unwrap()), 0xAB);
            assert_eq!(store.bits64(ValueAt::new(0).unwrap()), 0xCD);

            let first = store.push_bytes(&[1, 2, 3]).unwrap();
            let second = store.push_bytes(&[9]).unwrap();
            assert_eq!((first, second), (SlotAt::new(0).unwrap(), SlotAt::new(1).unwrap()));
            assert_eq!(store.zone_bytes(first), &[1, 2, 3][..]);
            // A minted zone's reading survives later growth: the
            // extent is re-derived per read, never a held pointer
            // — and the filler pushes mint monotone coordinates.
            for filler in 0..64u32 {
                assert_eq!(
                    store.push_bytes(&[0xEE; 33]).unwrap(),
                    SlotAt::new(2 + filler).unwrap()
                );
            }
            assert_eq!(store.zone_bytes(first), &[1, 2, 3][..]);
            assert_eq!(store.zone_bytes(second), &[9][..]);
        }

        #[test]
        fn the_staged_frame_publishes_or_reclaims_whole() {
            let mut store = Store::new();
            let anchor = store.push_bytes(&[5, 5]).unwrap();
            // An abandoned frame reclaims its staged tail, offset
            // space included.
            let mark = store.stage_mark();
            store.stage_chunk(&[1, 2]).unwrap();
            store.stage_abandon(mark);
            assert_eq!(store.stage_mark(), mark);
            // A sized frame: one exact reservation funds every
            // reserved chunk, and the finish mints the slot.
            let mark = store.stage_mark();
            store.stage_reserve(4).unwrap();
            store.stage_chunk_reserved(&[7, 8]);
            store.stage_chunk_reserved(&[9, 10]);
            let slot = store.stage_finish(mark).unwrap();
            assert_eq!(store.zone_bytes(slot), &[7, 8, 9, 10][..]);
            assert_eq!(store.zone_bytes(anchor), &[5, 5][..]);
        }

        #[test]
        fn the_zone_domain_judges_before_anything_is_occupied() {
            let mut store = Store::new();
            assert_eq!(store.stage_reserve(usize::MAX), Err(StoreFault::Exhausted));
            assert_eq!(store.stage_mark(), 0);
        }

        #[test]
        fn the_borrowed_store_retains_the_callers_slices() {
            let payload = [8u8, 7, 6];
            let mut store = BorrowStore::new();
            assert_eq!(store.push_varint(1).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.push_bits32(2).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.push_bits64(3).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.varint(ValueAt::new(0).unwrap()), 1);
            assert_eq!(store.bits32(ValueAt::new(0).unwrap()), 2);
            assert_eq!(store.bits64(ValueAt::new(0).unwrap()), 3);
            let slot = store.push_slot(&payload).unwrap();
            assert_eq!(slot, SlotAt::new(0).unwrap());
            assert!(core::ptr::eq(store.zone_bytes(slot).as_ptr(), payload.as_ptr()));
        }

        #[test]
        fn the_mixed_store_seals_both_backings_in_one_slot_space() {
            let retained = [3u8, 1, 4];
            let mut store = MixStore::new();
            assert_eq!(store.push_varint(6).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.push_bits32(7).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.push_bits64(8).unwrap(), ValueAt::new(0).unwrap());
            assert_eq!(store.varint(ValueAt::new(0).unwrap()), 6);
            assert_eq!(store.bits32(ValueAt::new(0).unwrap()), 7);
            assert_eq!(store.bits64(ValueAt::new(0).unwrap()), 8);
            let borrowed = store.push_slot(&retained).unwrap();
            let copied = store.push_bytes(&[2, 7]).unwrap();
            assert_eq!((borrowed, copied), (SlotAt::new(0).unwrap(), SlotAt::new(1).unwrap()));
            assert!(core::ptr::eq(store.zone_bytes(borrowed).as_ptr(), retained.as_ptr()));
            assert_eq!(store.zone_bytes(copied), &[2, 7][..]);
            // The staged frame publishes into the same unified
            // slot space, and an abandoned frame reclaims whole.
            let mark = store.stage_mark();
            store.stage_chunk(&[4]).unwrap();
            store.stage_abandon(mark);
            assert_eq!(store.stage_mark(), mark);
            let mark = store.stage_mark();
            store.stage_reserve(2).unwrap();
            store.stage_chunk_reserved(&[6, 6]);
            let staged = store.stage_finish(mark).unwrap();
            assert_eq!(store.zone_bytes(staged), &[6, 6][..]);
            assert_eq!(store.zone_bytes(copied), &[2, 7][..]);
            assert_eq!(store.stage_reserve(usize::MAX), Err(StoreFault::Exhausted));
        }
    }

    /// The tolerant grouped row: met columns present, the word
    /// role carrying the grouped dialect's end arm.
    mod tolerant_grouped {
        use super::strata::{At64, Edit, RowId};
        use crate::varint::{ValueWidth, WordWidth};
        use crate::wire::grouped::RecordKind;
        use crate::wire::{FieldNumber, PayloadLen};

        crate::replay_revise::revising_replay_store!(@word_role full);
        crate::replay_revise::revising_replay_store!(@len_role met);
        crate::replay_revise::revising_replay_store!(@row tolerant);

        #[test]
        fn the_row_and_its_role_columns_hold_their_pins() {
            assert_eq!(core::mem::size_of::<Row>(), 48);
            assert_eq!(core::mem::size_of::<ScalarWordOrGroupEnd>(), 8);
            assert_eq!(core::mem::size_of::<PayloadLenOrValueWidth>(), 4);
            assert_eq!(core::mem::size_of::<Option<WordWidth>>(), 1);
        }

        #[test]
        fn the_role_unions_couple_to_their_kinds() {
            // SAFETY: 33 lies within the zone-offset range.
            let end = unsafe { At64::new_unchecked(33) };
            let group = ScalarWordOrGroupEnd::group_end(RecordKind::Group, end);
            assert_eq!(group.end(RecordKind::Group), 33);
            let len = PayloadLenOrValueWidth::len(RecordKind::Len, PayloadLen::new(7).unwrap());
            assert_eq!(len.payload_len(RecordKind::Len), 7);
            // SAFETY: the fixture's met width lies in the value
            // window 1..=10.
            let met_width = unsafe { ValueWidth::met_unchecked(3) };
            let met = PayloadLenOrValueWidth::met(RecordKind::Varint, met_width);
            assert_eq!(met.met_width(RecordKind::Varint), 3);
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic(expected = "the word arm serves scalar rows alone")]
        fn a_len_row_cannot_bank_a_scalar_word() {
            let _refused = ScalarWordOrGroupEnd::scalar(RecordKind::Len, 150);
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic(expected = "the end arm serves group rows alone")]
        fn a_scalar_row_cannot_speak_a_group_end() {
            let word = ScalarWordOrGroupEnd::scalar(RecordKind::Varint, 150);
            let _refused = word.end(RecordKind::Varint);
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic(expected = "the length arm serves LEN rows alone")]
        fn a_varint_row_cannot_bank_a_payload_length() {
            let _refused =
                PayloadLenOrValueWidth::len(RecordKind::Varint, PayloadLen::new(7).unwrap());
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic(expected = "the met arm serves varint rows alone")]
        fn a_len_row_cannot_speak_a_met_value_width() {
            let len = PayloadLenOrValueWidth::len(RecordKind::Len, PayloadLen::new(7).unwrap());
            let _refused = len.met_width(RecordKind::Len);
        }

        #[test]
        fn a_scanned_varint_row_composes_and_every_column_reads() {
            // SAFETY: the fixture's met value width lies in the
            // value window 1..=10.
            let met_width = unsafe { ValueWidth::met_unchecked(3) };
            // A one-byte fixture tag: met and minimal coincide, so
            // the min-provenance door is the proven mint.
            let tag_width = WordWidth::minimal_of(8);
            let row = Row {
                at: Some(At64::from_source(
                    // SAFETY: 9 lies within the source range.
                    unsafe { crate::replay_source::SourceAt::new_unchecked(9) },
                )),
                edit: Edit::Intact,
                word_or_end: ScalarWordOrGroupEnd::scalar(RecordKind::Varint, 150),
                field: FieldNumber::new(1).unwrap(),
                len_or_met: PayloadLenOrValueWidth::met(RecordKind::Varint, met_width),
                parent: None,
                next: Some(RowId::new(2).unwrap()),
                kids: 0,
                kind: RecordKind::Varint,
                flags: 0,
                tag_width: Some(tag_width),
                delim_width: None,
            };
            assert_eq!(row.word_or_end.word(row.kind), 150);
            assert_eq!(row.len_or_met.met_width(row.kind), 3);
            assert_eq!(row.at.unwrap().as_inner(), 9);
            assert!(!row.edit.own_dirty());
            assert_eq!(row.field, FieldNumber::new(1).unwrap());
            assert!(row.parent.is_none());
            assert_eq!(row.next, Some(RowId::new(2).unwrap()));
            assert_eq!((row.kids, row.flags), (0, 0));
            assert_eq!(row.tag_width.unwrap().as_inner(), 1);
            assert!(row.delim_width.is_none());

            // A scanned LEN beside it: both roles ride their
            // vacant readings — the end derives from the declared
            // length, and no met value width exists off the
            // varint kind.
            let len_row = Row {
                word_or_end: ScalarWordOrGroupEnd::vacant(),
                len_or_met: PayloadLenOrValueWidth::len(
                    RecordKind::Len,
                    PayloadLen::new(2).unwrap(),
                ),
                kind: RecordKind::Len,
                ..row
            };
            assert_eq!(len_row.len_or_met.payload_len(len_row.kind), 2);
            let fixed_row = Row {
                word_or_end: ScalarWordOrGroupEnd::scalar(RecordKind::I32, 5),
                len_or_met: PayloadLenOrValueWidth::vacant(),
                kind: RecordKind::I32,
                ..row
            };
            assert_eq!(fixed_row.word_or_end.word(fixed_row.kind), 5);
        }
    }

    /// The tolerant groupless row: met columns present, the word
    /// role scalar-only.
    mod tolerant_groupless {
        use super::strata::{At64, Edit, RowId};
        use crate::replay_source::SlotAt;
        use crate::varint::{ValueWidth, WordWidth};
        use crate::wire::groupless::RecordKind;
        use crate::wire::{FieldNumber, PayloadLen};

        crate::replay_revise::revising_replay_store!(@word_role scalar);
        crate::replay_revise::revising_replay_store!(@len_role met);
        crate::replay_revise::revising_replay_store!(@row tolerant);

        #[test]
        fn the_row_holds_its_pin() {
            assert_eq!(core::mem::size_of::<Row>(), 48);
        }

        #[test]
        fn an_authored_len_row_composes_and_every_column_reads() {
            let word = ScalarWordOrGroupEnd::scalar(RecordKind::I64, 0xFEED);
            assert_eq!(word.word(RecordKind::I64), 0xFEED);
            let len =
                PayloadLenOrValueWidth::len(RecordKind::Len, PayloadLen::new(0x7FFF_FFFF).unwrap());
            assert_eq!(len.payload_len(RecordKind::Len), 0x7FFF_FFFF);
            // SAFETY: the fixture's met width tops the value
            // window 1..=10.
            let met_width = unsafe { ValueWidth::met_unchecked(10) };
            let met = PayloadLenOrValueWidth::met(RecordKind::Varint, met_width);
            assert_eq!(met.met_width(RecordKind::Varint), 10);
            let row = Row {
                at: None,
                edit: Edit::InsertedPayload(SlotAt::new(0).unwrap()),
                word_or_end: ScalarWordOrGroupEnd::vacant(),
                field: FieldNumber::new(2).unwrap(),
                len_or_met: PayloadLenOrValueWidth::vacant(),
                parent: None,
                next: None,
                kids: 0,
                kind: RecordKind::Len,
                flags: 0,
                tag_width: None,
                delim_width: None,
            };
            assert!(row.edit.own_dirty());
            assert!(row.at.is_none() && row.parent.is_none() && row.next.is_none());
            assert_eq!((row.kids, row.flags), (0, 0));
            assert_eq!(row.field, FieldNumber::new(2).unwrap());
            assert!(matches!(row.kind, RecordKind::Len));
            assert!(row.tag_width.is_none() && row.delim_width.is_none());

            // A scanned varint beside it: the role columns and the
            // met facts read back through the row's own kind.
            let scanned = Row {
                at: Some(At64::from_source(
                    // SAFETY: 4 lies within the source range.
                    unsafe { crate::replay_source::SourceAt::new_unchecked(4) },
                )),
                edit: Edit::Intact,
                word_or_end: ScalarWordOrGroupEnd::scalar(RecordKind::Varint, 7),
                field: FieldNumber::new(3).unwrap(),
                len_or_met: PayloadLenOrValueWidth::met(RecordKind::Varint, met_width),
                parent: None,
                next: None,
                kids: 0,
                kind: RecordKind::Varint,
                flags: 0,
                tag_width: Some(WordWidth::minimal_of(24)),
                delim_width: None,
            };
            assert_eq!(scanned.word_or_end.word(scanned.kind), 7);
            assert_eq!(scanned.len_or_met.met_width(scanned.kind), 10);
            assert_eq!(scanned.tag_width.unwrap().as_inner(), 1);
        }

        #[cfg(debug_assertions)]
        #[test]
        #[should_panic(expected = "the word arm serves scalar rows alone")]
        fn a_len_row_cannot_speak_a_scalar_word() {
            let vacant = ScalarWordOrGroupEnd::vacant();
            let _refused = vacant.word(RecordKind::Len);
        }
    }

    /// The canonical grouped row: met columns erased, the group
    /// end still riding the word role.
    mod canonical_grouped {
        use super::strata::{At64, Edit, RowId};
        use crate::wire::grouped::RecordKind;
        use crate::wire::{FieldNumber, PayloadLen};

        crate::replay_revise::revising_replay_store!(@word_role full);
        crate::replay_revise::revising_replay_store!(@len_role plain);
        crate::replay_revise::revising_replay_store!(@row canonical);

        #[test]
        fn the_erased_met_columns_leave_the_pin_at_48() {
            assert_eq!(core::mem::size_of::<Row>(), 48);
        }

        #[test]
        fn a_scanned_group_row_composes_and_every_column_reads() {
            let scalar = ScalarWordOrGroupEnd::scalar(RecordKind::I32, 0xAA);
            assert_eq!(scalar.word(RecordKind::I32), 0xAA);
            let vacant_len =
                PayloadLenOrValueWidth::len(RecordKind::Len, PayloadLen::new(1).unwrap());
            assert_eq!(vacant_len.payload_len(RecordKind::Len), 1);
            // SAFETY: 1024 lies within the zone-offset range.
            let end = unsafe { At64::new_unchecked(1024) };
            let row = Row {
                at: Some(At64::from_authored(crate::replay_source::AuthoredAt::new(3).unwrap())),
                edit: Edit::Intact,
                word_or_end: ScalarWordOrGroupEnd::group_end(RecordKind::Group, end),
                field: FieldNumber::new(3).unwrap(),
                len_or_met: PayloadLenOrValueWidth::vacant(),
                parent: Some(RowId::new(0).unwrap()),
                next: None,
                kids: 0,
                kind: RecordKind::Group,
                flags: 0,
            };
            assert_eq!(row.word_or_end.end(row.kind), 1024);
            assert_eq!(row.at.unwrap().as_inner(), 3);
            assert_eq!(row.parent, Some(RowId::new(0).unwrap()));
            assert!(row.next.is_none());
            assert_eq!((row.kids, row.flags), (0, 0));
            assert_eq!(row.field, FieldNumber::new(3).unwrap());
            assert!(!row.edit.own_dirty());

            // A scanned LEN beside it: the length role reads back
            // through the row's own kind.
            let len_row = Row {
                word_or_end: ScalarWordOrGroupEnd::vacant(),
                len_or_met: vacant_len,
                kind: RecordKind::Len,
                ..row
            };
            assert_eq!(len_row.len_or_met.payload_len(len_row.kind), 1);
        }
    }

    /// The canonical groupless row: the smallest cut — scalar
    /// word role, plain length role, erased met columns.
    mod canonical_groupless {
        use super::strata::{At64, Edit, RowId};
        use crate::replay_source::SlotAt;
        use crate::wire::groupless::RecordKind;
        use crate::wire::{FieldNumber, PayloadLen};

        crate::replay_revise::revising_replay_store!(@word_role scalar);
        crate::replay_revise::revising_replay_store!(@len_role plain);
        crate::replay_revise::revising_replay_store!(@row canonical);

        #[test]
        fn the_erased_met_columns_leave_the_pin_at_48() {
            assert_eq!(core::mem::size_of::<Row>(), 48);
        }

        #[test]
        fn the_widthless_row_composes_and_every_column_reads() {
            let word = ScalarWordOrGroupEnd::scalar(RecordKind::Varint, 5);
            assert_eq!(word.word(RecordKind::Varint), 5);
            let vacant = PayloadLenOrValueWidth::vacant();
            let row = Row {
                at: None,
                edit: Edit::DeletedPayload(Some(SlotAt::new(2).unwrap())),
                word_or_end: ScalarWordOrGroupEnd::vacant(),
                field: FieldNumber::new(4).unwrap(),
                len_or_met: PayloadLenOrValueWidth::len(
                    RecordKind::Len,
                    PayloadLen::new(11).unwrap(),
                ),
                parent: None,
                next: None,
                kids: 0,
                kind: RecordKind::Len,
                flags: 0,
            };
            assert_eq!(row.len_or_met.payload_len(row.kind), 11);
            assert_eq!(row.edit.effective_slot(), Some(SlotAt::new(2).unwrap()));
            assert!(row.at.is_none() && row.parent.is_none() && row.next.is_none());
            assert_eq!((row.kids, row.flags), (0, 0));
            assert_eq!(row.field, FieldNumber::new(4).unwrap());

            // A scanned varint beside it: the scalar role and the
            // vacant length role compose, and the word reads back
            // through the row's own kind.
            let scanned = Row {
                edit: Edit::Intact,
                word_or_end: word,
                len_or_met: vacant,
                kind: RecordKind::Varint,
                ..row
            };
            assert_eq!(scanned.word_or_end.word(scanned.kind), 5);
        }
    }
}
