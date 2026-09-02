//! The groupless one-shot editor family core, emitted per machine
//! by [`one_shot_machine!`] for the six one-shot editors: the
//! borrowed patch and amend, the owned adopt and intake, and the
//! chunk-ingesting stream adopt and stream intake. Two declared
//! sections parameterize a machine — the source holder with its tenure
//! doors, and the payload backing — plus the capability,
//! acceptance, and naming literals that ride them; the internal
//! arms below hold each stretch of shared text exactly once.

/// Emits the groupless one-shot editor family into the invoking
/// module: `vocabulary` lays down the module-wide types (faults,
/// rows, the layer scan, save plumbing, iterators) once, and each
/// `machine` invocation emits one editing machine — struct, tenure
/// doors, command and save faces, and its payload-backing face set
/// — against that vocabulary. Names resolve at the invocation
/// site. The parenthesized roster on `vocabulary` names every
/// public type the module's invocations lay down beyond the
/// `machine`, `backing`, and `frames` lines; the public-type
/// census reads it, so each name must face the auto-trait matrix
/// under the module's path.
macro_rules! one_shot_machine {
    (
        vocabulary($($public:ident),+ $(,)?),
        capability: $cap:ident,
        acceptance: $acc:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        $crate::editor::groupless::one_shot_machine!(@vocabulary $cap buffered, acceptance: $acc, noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
    };
    (
        vocabulary stream($($public:ident),+ $(,)?),
        capability: $cap:ident,
        acceptance: $acc:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        $crate::editor::groupless::one_shot_machine!(@vocabulary $cap stream, acceptance: $acc, noun: $noun, a_noun: $a_noun, A_noun: $A_noun);
    };
    (
        @vocabulary $cap:ident $doors:ident,
        acceptance: $acc:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal $(,)?
    ) => {
        // ─── faults ───

        /// A wire-grammar violation: where it struck and what it is.
        ///
        /// `at` is the offset of the construct the kind names — the tag
        /// word, length word, varint value, or payload start.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct Fault {
            /// Offset of the faulted construct.
            pub at: u32,
            /// The violation found there.
            pub kind: FaultKind,
        }

        /// Wire-grammar violations this dialect can meet. The set is the
        /// grammar's own closed alphabet — deliberately exhaustive, so
        /// downstream matches are a stable promise.
        ///
        /// A fault judged after the head tag revealed its field number
        /// carries that field; the tag's own faults carry none — no field
        /// exists yet.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum FaultKind {
            /// The tag word failed to read.
            Tag {
                /// The kernel's refusal.
                fault: ReadFault,
            },
            /// The tag word names field zero, which the format never
            /// assigns.
            FieldZero,
            /// The tag word carries a code the format leaves unassigned.
            Unassigned {
                /// The field the tag names (judged before the code).
                field: FieldNumber,
                /// The unassigned code bits.
                low3: Low3,
            },
            /// A LEN length word failed to read.
            Len {
                /// The record's field number.
                field: FieldNumber,
                /// The kernel's refusal.
                fault: ReadFault,
            },
            /// A varint value failed to read.
            Value {
                /// The record's field number.
                field: FieldNumber,
                /// The kernel's refusal.
                fault: ReadFault,
            },
            /// A fixed-width value or a LEN payload runs past its extent.
            PayloadCut {
                /// The record's field number.
                field: FieldNumber,
                /// Bytes the record claims.
                need: u32,
                /// Bytes the extent still holds.
                have: u32,
            },
        }

        impl core::fmt::Display for Fault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let at = self.at;
                match self.kind {
                    FaultKind::Tag { fault } => {
                        write!(f, "tag word at {at}: {fault}")
                    }
                    FaultKind::FieldZero => write!(f, "tag word at {at} names field zero"),
                    FaultKind::Unassigned { field, low3 } => write!(
                        f,
                        "tag word at {at} carries unassigned code {} on field {}",
                        low3.as_inner(),
                        field.as_inner()
                    ),
                    FaultKind::Len { field, fault } => {
                        write!(f, "length word of field {} at {at}: {fault}", field.as_inner())
                    }
                    FaultKind::Value { field, fault } => {
                        write!(f, "varint value of field {} at {at}: {fault}", field.as_inner())
                    }
                    FaultKind::PayloadCut { field, need, have } => write!(
                        f,
                        "payload of field {} at {at} claims {need} bytes but the extent holds {have}",
                        field.as_inner()
                    ),
                }
            }
        }

        impl core::error::Error for Fault {}

        $crate::editor::groupless::one_shot_machine!(@refusal $acc, [$noun]);
        $crate::editor::groupless::one_shot_machine!(@open_fault $doors, [$noun] [$a_noun]);

        $crate::editor::groupless::one_shot_machine!(@1s_edit_fault $cap, noun: $noun, a_noun: $a_noun, A_noun: $A_noun);

        /// Why a sized payload frame refused: the declaration
        /// judgments, plus exactly the one failure class the
        /// publishing close can meet.
        ///
        /// The frame faces carry their own alphabet because the
        /// declaration judgments exist nowhere else — the
        #[doc = concat!(" ", $noun, "'s command faces keep a frame-free")]
        /// [`EditFault`].
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum FrameFault {
            /// The staged bytes would pass the frame's declaration.
            OverDeclared {
                /// The declared payload length.
                declared: u32,
                /// The staged total the refused write would reach.
                total: u64,
            },
            /// The frame finished short of its declaration; nothing
            /// was installed.
            UnderDeclared {
                /// The declared payload length.
                declared: u32,
                /// The bytes actually staged.
                staged: u32,
            },
            #[doc = concat!(" The ", $noun, "'s edit storage is full; the refusal is")]
            #[doc = concat!(" permanent for this ", $noun, ".")]
            IndexSpaceExhausted,
        }

        impl core::fmt::Display for FrameFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::OverDeclared { declared, total } => {
                        write!(f, "staged payload of {total} bytes passes its declared length {declared}")
                    }
                    Self::UnderDeclared { declared, staged } => write!(
                        f,
                        "staged payload of {staged} bytes falls short of its declared length {declared}"
                    ),
                    Self::IndexSpaceExhausted => f.write_str(concat!("the ", $noun, "'s edit storage is full")),
                }
            }
        }

        impl core::error::Error for FrameFault {}

        /// Maps the publishing close's faults onto the frame alphabet.
        /// Total by the close's own domain: it mints coordinates only,
        /// so only the coordinate-exhaustion class arises there.
        #[cold]
        fn close_fault(fault: EditFault) -> FrameFault {
            match fault {
                EditFault::IndexSpaceExhausted => FrameFault::IndexSpaceExhausted,
                _ => unreachable!("the publishing close mints coordinates only"),
            }
        }

        /// Why a save refused. On any `Err` the caller's `Vec` is
        /// untouched in length and content.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum SaveFault {
            /// A rewritten LEN body outgrew the length class.
            BodyOverCap {
                /// Source offset of the overflowing LEN record.
                at: u32,
            },
            /// The rewritten document outgrew the coordinate class.
            DocOverCap {
                /// The oversized total.
                total: u64,
            },
        }

        impl core::fmt::Display for SaveFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::BodyOverCap { at } => {
                        write!(f, "rewritten body of the LEN at {at} exceeds the length class")
                    }
                    Self::DocOverCap { total } => {
                        write!(f, "rewritten document of {total} bytes exceeds the coordinate class")
                    }
                }
            }
        }

        impl core::error::Error for SaveFault {}

        // ─── verdicts and geometry ───

        /// A descend verdict. Faults and refusals are resident: they park
        /// on the record and project unchanged on every later call, while
        /// the payload stays readable as bytes.
        #[must_use = "the verdict reports whether the payload opened, faulted, or was refused"]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Descent<'p> {
            /// The payload parsed; its first child, if any.
            Opened {
                /// First record of the interior layer.
                first: Option<Handle>,
            },
            /// The payload violates the wire grammar (resident).
            Faulted(&'p Fault),
            #[doc = concat!(" The payload is lawful wire outside this ", $noun, "'s language or")]
            /// declared bounds (resident).
            Refused(&'p Refusal),
        }

        /// Source geometry of one scanned record.
        ///
        /// The segments partition the record's span exactly, at the widths
        /// the scan actually met — padded framing included. Coordinates
        /// answer for the source bytes, not for any pending edit.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum RecordSpans {
            /// Tag, then the varint value.
            Varint {
                /// The tag word.
                tag: Span,
                /// The value bytes.
                value: Span,
            },
            /// Tag, then eight value bytes.
            I64 {
                /// The tag word.
                tag: Span,
                /// The value bytes.
                value: Span,
            },
            /// Tag, length prefix, payload.
            Len {
                /// The tag word.
                tag: Span,
                /// The length prefix.
                prefix: Span,
                /// The payload bytes.
                payload: Span,
            },
            /// Tag, then four value bytes.
            I32 {
                /// The tag word.
                tag: Span,
                /// The value bytes.
                value: Span,
            },
        }

        // ─── rows ───

        /// `Row.state` bits 0–1: the base edit state ([`Base`]).
        const BASE_MASK: u8 = 0b11;
        const BASE_INTACT: u8 = 0;
        const BASE_REPLACED: u8 = 1;
        const BASE_INSERTED: u8 = 2;
        /// `Row.state`: deleted — the record vanishes whole at save,
        /// subtree included. Orthogonal to the base: the value side stays
        /// readable.
        const FLAG_DELETED: u8 = 1 << 2;
        /// `Row.state`: a LEN's payload parsed; `Row.kid` anchors the
        /// interior chain.
        const FLAG_OPENED: u8 = 1 << 3;
        /// `Row.state`: a LEN's descent parked a resident verdict;
        /// `Row.value` holds its fault-table index.
        const FLAG_FAULTED: u8 = 1 << 4;
        /// The subtree edit witness: this record, or one beneath it, was
        /// replaced, deleted, or had an insertion spliced in. Monotone —
        /// commit-only offers no path that clears an edit — so ancestors
        /// accumulate it on the way up and the save's verbatim arm trusts
        /// its absence.
        const FLAG_DIRTY: u8 = 1 << 5;
        $crate::editor::groupless::one_shot_machine!(@1s_src_marks $cap);

        $crate::editor::groupless::one_shot_machine!(@1s_base_enum $cap);

        $crate::editor::groupless::one_shot_machine!(@row_struct $acc);

        impl Row {
            $crate::editor::groupless::one_shot_machine!(@row_ctor $cap $acc);

            $crate::editor::groupless::one_shot_machine!(@1s_row_base $cap);

            const fn set_replaced(&mut self) {
                self.state = (self.state & !BASE_MASK) | BASE_REPLACED;
            }

            $crate::editor::groupless::one_shot_machine!(@1s_row_src_marks $cap);

            const fn deleted(&self) -> bool {
                self.state & FLAG_DELETED != 0
            }

            const fn set_deleted(&mut self) {
                self.state |= FLAG_DELETED;
            }

            const fn opened(&self) -> bool {
                self.state & FLAG_OPENED != 0
            }

            const fn set_opened(&mut self) {
                self.state |= FLAG_OPENED;
            }

            const fn faulted(&self) -> bool {
                self.state & FLAG_FAULTED != 0
            }

            const fn set_faulted(&mut self) {
                self.state |= FLAG_FAULTED;
            }

            const fn clear_faulted(&mut self) {
                self.state &= !FLAG_FAULTED;
            }

            const fn dirty(&self) -> bool {
                self.state & FLAG_DIRTY != 0
            }

            const fn set_dirty(&mut self) {
                self.state |= FLAG_DIRTY;
            }

            $crate::editor::groupless::one_shot_machine!(@1s_rides_verbatim $cap, );

            $crate::editor::groupless::one_shot_machine!(@row_widths $cap $acc);

            /// The whole-record source span end: one formula for all
            /// kinds, per the partition theorem.
            const fn span_end(&self) -> u32 {
                self.start.as_inner() + self.tag_w() + self.delim_w() + self.payload_len.as_inner()
            }

            /// The payload's offset in the row's zone: past the tag,
            /// and past the length prefix for LENs. In the coordinate
            /// class: the payload's bytes follow the offset inside the
            /// admitted zone, so the sum cannot leave it.
            const fn payload_at(&self) -> Coord {
                // SAFETY: the scan bound the start and both framing
                // widths to a record whose payload bytes follow them
                // inside the admitted zone.
                unsafe {
                    Coord::new_unchecked(self.start.as_inner() + self.tag_w() + self.delim_w())
                }
            }
        }

        /// A resident descend verdict.
        #[derive(Clone, Copy)]
        enum SlotFault {
            Wire(Fault),
            Refused(Refusal),
        }

        /// Projects a resident verdict off the fault table.
        const fn project(faults: &[SlotFault], index: u32) -> Descent<'_> {
            match &faults[usize_of(index)] {
                SlotFault::Wire(fault) => Descent::Faulted(fault),
                SlotFault::Refused(refusal) => Descent::Refused(refusal),
            }
        }

        // ─── the layer scan ───

        /// Why a layer scan halted.
        enum Halt {
            Wire(Fault),
            Refused(Refusal),
            Exhausted,
        }

        #[cold]
        const fn halt_wire(at: u32, kind: FaultKind) -> Halt {
            Halt::Wire(Fault { at, kind })
        }

        /// Mints the next row coordinate. The arena may already hold
        /// authored rows (a descend after insertions), so the domain is
        /// judged; the root scan alone can never exhaust it (see
        /// [`RowId`]).
        fn mint_row(rows: &[Row]) -> Result<RowId, Halt> {
            u32::try_from(rows.len()).ok().and_then(RowId::new).ok_or(Halt::Exhausted)
        }

        $crate::editor::groupless::one_shot_machine!(@scan $acc);

        // ─── the machine ───

        #[doc = concat!(" The arena gate: forged handles (coordinates the ", $noun, " never")]
        /// minted) panic right here on the index bound.
        #[track_caller]
        const fn gate(rows: &[Row], handle: Handle) -> &Row {
            &rows[handle.0.index()]
        }

        /// An insertion's resolved splice point, proven before anything is
        /// occupied.
        #[derive(Clone, Copy)]
        struct Plan {
            parent: Option<RowId>,
            prev: Option<RowId>,
        }

        /// A scalar value headed for the output.
        #[derive(Clone, Copy)]
        enum Word {
            Varint(u64),
            Bits32(u32),
            Bits64(u64),
        }

        impl Word {
            /// The value's canonical emitted width.
            const fn width(self) -> u32 {
                match self {
                    Self::Varint(word) => encoded_len64(word),
                    Self::Bits32(_) => 4,
                    Self::Bits64(_) => 8,
                }
            }
        }

        $crate::editor::groupless::one_shot_machine!(@1s_arm_enum $cap);

        /// One frame of the save passes' container spine.
        struct SizeFrame {
            /// Where the walk resumes after the close.
            next: Option<RowId>,
            /// The enclosing accumulator, restored at close.
            outer: u64,
            /// The spine LEN's framing decision, waiting on the body size.
            close: Close,
        }

        /// What a size-pass frame contributes at close.
        struct Close {
            /// The body's slot in the size table.
            slot: usize,
            /// The source prefix's met width (the verbatim candidate).
            prefix_w: WordWidth,
            /// The source body length (the verbatim criterion).
            src_len: u32,
            /// Source offset, for the over-cap fault.
            at: u32,
            /// The source tag's met width.
            tag_w: WordWidth,
        }

        $crate::editor::groupless::one_shot_machine!(@1s_out_family $cap);

        /// The output-order span table of one priced save: every live
        /// record's handle against its whole-record span in the output —
        /// the `save_spans` faces' product.
        ///
        /// Entries follow output order (a container precedes and encloses
        /// its interior), and the last entry's end is the save's exact
        /// length.
        #[must_use]
        #[derive(Debug)]
        pub struct SaveSpans {
            entries: Vec<(Handle, Span)>,
        }

        impl SaveSpans {
            /// The number of live records in the table.
            #[inline]
            #[must_use]
            pub const fn len(&self) -> usize {
                self.entries.len()
            }

            /// True when the save carries no records.
            #[inline]
            #[must_use]
            pub const fn is_empty(&self) -> bool {
                self.entries.is_empty()
            }

            /// The entries in output order.
            #[inline]
            pub fn iter(&self) -> impl Iterator<Item = (Handle, Span)> + '_ {
                self.entries.iter().copied()
            }
        }

        $crate::editor::groupless::one_shot_machine!(@1s_import_value_at $cap, );

        /// The arena row a machine-minted link names.
        ///
        /// # Safety
        ///
        /// `index` must come from a link this machine minted: a row id
        /// from an arena append or the `next`/`parent` links rows store.
        /// The arena never shrinks, so every minted link stays in-table
        /// for the machine's whole life.
        #[inline]
        unsafe fn linked(rows: &[Row], index: usize) -> &Row {
            debug_assert!(index < rows.len(), "links are minted in-table");
            // SAFETY: the caller's link provenance covers the index.
            unsafe { rows.get_unchecked(index) }
        }

        // ─── iterators ───

        /// Sibling records in wire order (deleted records included —
        /// topology is stable, presentation filters).
        #[must_use]
        pub struct Children<'p> {
            rows: &'p [Row],
            cur: Option<RowId>,
        }

        impl<'p> Children<'p> {
            /// Narrows to records of one field, preserving wire order.
            #[inline]
            pub fn by_field(self, field: FieldNumber) -> impl Iterator<Item = Handle> + 'p {
                let rows = self.rows;
                // SAFETY: the iterator yields minted links only (see
                // `next`).
                self.filter(move |handle| unsafe { linked(rows, handle.0.index()) }.field == field)
            }
        }

        impl Iterator for Children<'_> {
            type Item = Handle;

            #[inline]
            fn next(&mut self) -> Option<Handle> {
                let id = self.cur?;
                // SAFETY: the chain starts at a layer's minted anchor and
                // every later id is again a row's own `next` link.
                self.cur = unsafe { linked(self.rows, id.index()) }.next;
                Some(Handle(id))
            }
        }

        impl core::iter::FusedIterator for Children<'_> {}

        /// A record's ancestor chain, innermost container first.
        #[must_use]
        pub struct Ancestors<'p> {
            rows: &'p [Row],
            cur: Option<RowId>,
        }

        impl Iterator for Ancestors<'_> {
            type Item = Handle;

            #[inline]
            fn next(&mut self) -> Option<Handle> {
                let id = self.cur?;
                // SAFETY: the chain starts at a live row's parent link and
                // every later id is again a row's own `parent` link.
                self.cur = unsafe { linked(self.rows, id.index()) }.parent;
                Some(Handle(id))
            }
        }

        impl core::iter::FusedIterator for Ancestors<'_> {}

        /// The command a staged payload frame closes with.
        #[derive(Clone, Copy)]
        enum WriteOp {
            /// Replace an existing LEN's payload.
            Set {
                /// The gated target.
                handle: Handle,
            },
            /// Insert a fresh LEN record at a resolved splice point.
            Insert {
                /// The proven anchor.
                plan: Plan,
                /// The new record's field.
                field: FieldNumber,
            },
        }

        $crate::editor::groupless::one_shot_machine!(@canonical_vocab $cap $acc);
    };
    (@1s_out_family transfer) => {
        /// One save emitter: the emit walk drives these faces, and the
        /// buffered and sink twins implement them — one walk shape, two
        /// custodies for the bytes.
        trait Out<'a> {
            /// Publishes the pending verbatim run, if any.
            fn flush(&mut self);
            /// Copies `at..end` of the source, merging contiguous runs.
            fn verbatim(&mut self, at: u32, end: u32);
            /// Copies `at..end` of `zone`, merging contiguous runs
            /// within one zone; a zone crossing publishes the pending
            /// run first.
            fn verbatim_in(&mut self, zone: &'a [u8], at: u32, end: u32);
            /// Emits one minimal head word.
            fn word(&mut self, word: u32);
            /// Emits one authored scalar value.
            fn value(&mut self, value: Word);
            /// Emits one minimal varint (LEN prefixes).
            fn varint(&mut self, value: u64);
            /// Emits authored payload bytes.
            fn bytes(&mut self, bytes: &[u8]);
        }

        /// The forward emitter: a pending verbatim run rides between
        /// writes so contiguous untouched records coalesce into one copy.
        struct Emit<'o, 'a> {
            out: &'o mut Vec<u8>,
            src: &'a [u8],
            run: Option<(&'a [u8], u32, u32)>,
        }

        impl<'a> Out<'a> for Emit<'_, 'a> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: `from..to` was minted by one of the walk's
                    // three span producers — a settle arm's framing or
                    // whole-record span (the row's `Coord` start plus its
                    // scan-admitted widths and payload length), the span
                    // walk's clean run (adjacent sibling spans, which
                    // tile their layer), or the canonical pass's value
                    // and payload spans (`payload_at` plus the row's
                    // admitted length) — each inside the zone its row was
                    // scanned in, which is the `zone` held beside it; the
                    // merge guard publishes before any zone crossing and
                    // joins only end-to-start contiguous spans.
                    self.out
                        .extend_from_slice(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let src = self.src;
                self.verbatim_in(src, at, end);
            }

            fn verbatim_in(&mut self, zone: &'a [u8], at: u32, end: u32) {
                match &mut self.run {
                    Some((z, _, to)) if *to == at && core::ptr::eq(*z, zone) => *to = end,
                    _ => {
                        self.flush();
                        self.run = Some((zone, at, end));
                    }
                }
            }

            fn word(&mut self, word: u32) {
                self.flush();
                push64(self.out, u64::from(word));
            }

            fn value(&mut self, value: Word) {
                self.flush();
                match value {
                    Word::Varint(word) => push64(self.out, word),
                    Word::Bits32(bits) => self.out.extend_from_slice(&bits.to_le_bytes()),
                    Word::Bits64(bits) => self.out.extend_from_slice(&bits.to_le_bytes()),
                }
            }

            fn varint(&mut self, value: u64) {
                self.flush();
                push64(self.out, value);
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.out.extend_from_slice(bytes);
            }
        }

        /// [`Emit`]'s sink twin: the same walk hands borrowed slices to
        /// the caller's sink — verbatim runs as windows of the source,
        /// authored words through a ten-byte stack window. The written
        /// count serves the seam pins the buffered twin reads off its
        /// buffer.
        struct SinkEmit<'a, 's, F> {
            src: &'a [u8],
            sink: &'s mut F,
            run: Option<(&'a [u8], u32, u32)>,
            /// Bytes handed to the sink so far.
            written: u64,
        }

        impl<F: FnMut(&[u8])> SinkEmit<'_, '_, F> {
            /// Hands one non-empty slice to the sink (empty handoffs are
            /// dropped: they carry no bytes to account).
            fn hand(&mut self, bytes: &[u8]) {
                if bytes.is_empty() {
                    return;
                }
                #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
                {
                    self.written += bytes.len() as u64;
                }
                (self.sink)(bytes);
            }

            /// Hands one minimal varint through the stack window.
            fn hand_varint(&mut self, value: u64) {
                let mut window = [0u8; 10];
                let width = crate::varint::emit64(value, &mut window);
                self.hand(&window[..usize_of(width)]);
            }
        }

        impl<'a, F: FnMut(&[u8])> Out<'a> for SinkEmit<'a, '_, F> {
            fn flush(&mut self) {
                if let Some((zone, from, to)) = self.run.take() {
                    // SAFETY: `from..to` was minted by one of the walk's
                    // three span producers — a settle arm's framing or
                    // whole-record span (the row's `Coord` start plus its
                    // scan-admitted widths and payload length), the span
                    // walk's clean run (adjacent sibling spans, which
                    // tile their layer), or the canonical pass's value
                    // and payload spans (`payload_at` plus the row's
                    // admitted length) — each inside the zone its row was
                    // scanned in, which is the `zone` held beside it; the
                    // merge guard publishes before any zone crossing and
                    // joins only end-to-start contiguous spans.
                    self.hand(unsafe { zone.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                let src = self.src;
                self.verbatim_in(src, at, end);
            }

            fn verbatim_in(&mut self, zone: &'a [u8], at: u32, end: u32) {
                match &mut self.run {
                    Some((z, _, to)) if *to == at && core::ptr::eq(*z, zone) => *to = end,
                    _ => {
                        self.flush();
                        self.run = Some((zone, at, end));
                    }
                }
            }

            fn word(&mut self, word: u32) {
                self.flush();
                self.hand_varint(u64::from(word));
            }

            fn value(&mut self, value: Word) {
                self.flush();
                match value {
                    Word::Varint(word) => self.hand_varint(word),
                    Word::Bits32(bits) => self.hand(&bits.to_le_bytes()),
                    Word::Bits64(bits) => self.hand(&bits.to_le_bytes()),
                }
            }

            fn varint(&mut self, value: u64) {
                self.flush();
                self.hand_varint(value);
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.hand(bytes);
            }
        }
    };
    (@1s_out_family $cap:ident) => {
        /// One save emitter: the emit walk drives these faces, and the
        /// buffered and sink twins implement them — one walk shape, two
        /// custodies for the bytes.
        trait Out {
            /// Publishes the pending verbatim run, if any.
            fn flush(&mut self);
            /// Copies `at..end` of the source, merging contiguous runs.
            fn verbatim(&mut self, at: u32, end: u32);
            /// Emits one minimal head word.
            fn word(&mut self, word: u32);
            /// Emits one authored scalar value.
            fn value(&mut self, value: Word);
            /// Emits one minimal varint (LEN prefixes).
            fn varint(&mut self, value: u64);
            /// Emits authored payload bytes.
            fn bytes(&mut self, bytes: &[u8]);
        }

        /// The forward emitter: a pending verbatim run rides between
        /// writes so contiguous untouched records coalesce into one copy.
        struct Emit<'o, 'a> {
            out: &'o mut Vec<u8>,
            src: &'a [u8],
            run: Option<(u32, u32)>,
        }

        impl Out for Emit<'_, '_> {
            fn flush(&mut self) {
                if let Some((from, to)) = self.run.take() {
                    // SAFETY: `from..to` was minted by one of the walk's
                    // three span producers — a settle arm's framing or
                    // whole-record span (the row's `Coord` start plus its
                    // scan-admitted widths and payload length), the span
                    // walk's clean run (adjacent sibling spans, which
                    // tile their layer), or the canonical pass's value
                    // and payload spans (`payload_at` plus the row's
                    // admitted length) — each inside the admitted source
                    // the rows were scanned over, with runs joining only
                    // end-to-start contiguous spans.
                    self.out
                        .extend_from_slice(unsafe { self.src.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                match &mut self.run {
                    Some((_, to)) if *to == at => *to = end,
                    _ => {
                        self.flush();
                        self.run = Some((at, end));
                    }
                }
            }

            fn word(&mut self, word: u32) {
                self.flush();
                push64(self.out, u64::from(word));
            }

            fn value(&mut self, value: Word) {
                self.flush();
                match value {
                    Word::Varint(word) => push64(self.out, word),
                    Word::Bits32(bits) => self.out.extend_from_slice(&bits.to_le_bytes()),
                    Word::Bits64(bits) => self.out.extend_from_slice(&bits.to_le_bytes()),
                }
            }

            fn varint(&mut self, value: u64) {
                self.flush();
                push64(self.out, value);
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.out.extend_from_slice(bytes);
            }
        }

        /// [`Emit`]'s sink twin: the same walk hands borrowed slices to
        /// the caller's sink — verbatim runs as windows of the source,
        /// authored words through a ten-byte stack window. The written
        /// count serves the seam pins the buffered twin reads off its
        /// buffer.
        struct SinkEmit<'a, 's, F> {
            src: &'a [u8],
            sink: &'s mut F,
            run: Option<(u32, u32)>,
            /// Bytes handed to the sink so far.
            written: u64,
        }

        impl<F: FnMut(&[u8])> SinkEmit<'_, '_, F> {
            /// Hands one non-empty slice to the sink (empty handoffs are
            /// dropped: they carry no bytes to account).
            fn hand(&mut self, bytes: &[u8]) {
                if bytes.is_empty() {
                    return;
                }
                #[allow(clippy::as_conversions, reason = "usize widens losslessly to u64")]
                {
                    self.written += bytes.len() as u64;
                }
                (self.sink)(bytes);
            }

            /// Hands one minimal varint through the stack window.
            fn hand_varint(&mut self, value: u64) {
                let mut window = [0u8; 10];
                let width = crate::varint::emit64(value, &mut window);
                self.hand(&window[..usize_of(width)]);
            }
        }

        impl<F: FnMut(&[u8])> Out for SinkEmit<'_, '_, F> {
            fn flush(&mut self) {
                if let Some((from, to)) = self.run.take() {
                    let src = self.src;
                    // SAFETY: `from..to` was minted by one of the walk's
                    // three span producers — a settle arm's framing or
                    // whole-record span (the row's `Coord` start plus its
                    // scan-admitted widths and payload length), the span
                    // walk's clean run (adjacent sibling spans, which
                    // tile their layer), or the canonical pass's value
                    // and payload spans (`payload_at` plus the row's
                    // admitted length) — each inside the admitted source
                    // the rows were scanned over, with runs joining only
                    // end-to-start contiguous spans.
                    self.hand(unsafe { src.get_unchecked(usize_of(from)..usize_of(to)) });
                }
            }

            fn verbatim(&mut self, at: u32, end: u32) {
                match &mut self.run {
                    Some((_, to)) if *to == at => *to = end,
                    _ => {
                        self.flush();
                        self.run = Some((at, end));
                    }
                }
            }

            fn word(&mut self, word: u32) {
                self.flush();
                self.hand_varint(u64::from(word));
            }

            fn value(&mut self, value: Word) {
                self.flush();
                match value {
                    Word::Varint(word) => self.hand_varint(word),
                    Word::Bits32(bits) => self.hand(&bits.to_le_bytes()),
                    Word::Bits64(bits) => self.hand(&bits.to_le_bytes()),
                }
            }

            fn varint(&mut self, value: u64) {
                self.flush();
                self.hand_varint(value);
            }

            fn bytes(&mut self, bytes: &[u8]) {
                self.flush();
                self.hand(bytes);
            }
        }
    };
    (@1s_container_base plain, $row:ident) => { !matches!($row.base(), Base::Intact) };
    (@1s_container_base transfer, $row:ident) => {
        // A live import's descended interior is first-class: it takes
        // insertions like any opened scanned layer; replaced or
        // authored payloads and designations stay browse-only.
        match $row.base() {
            Base::Intact => false,
            Base::Src => !matches!($row.src_value(), SrcValue::Imported(_)),
            Base::Replaced | Base::Inserted => true,
        }
    };
    (@1s_edit_fault plain, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        /// Why an edit command refused. Failure classes are judged in no
        /// promised order within one call.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum EditFault {
            /// The record's wire kind does not fit the command.
            KindMismatch {
                /// The record's actual kind.
                have: RecordKind,
            },
            /// The record is deleted; commit-only editing cannot restore
            /// it.
            DeletedTarget,
            /// The record's interior is open for editing; edit it in place
            /// or delete the record instead of replacing the payload
            /// wholesale.
            OpenedTarget,
            /// Descend the container before inserting into it.
            TargetUnopened,
            /// The record's payload is authored; there is no source
            /// interior to open.
            AuthoredPayload,
            /// The payload exceeds the length class.
            PayloadTooLarge {
                /// The refused payload length.
                len: usize,
            },
            #[doc = concat!(" The ", $noun, "'s edit storage is full; the refusal is permanent")]
            #[doc = concat!(" for this ", $noun, ".")]
            IndexSpaceExhausted,
        }

        impl core::fmt::Display for EditFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::KindMismatch { have } => {
                        write!(f, "the command expects another wire kind; the record is {have}")
                    }
                    Self::DeletedTarget => f.write_str("the record is deleted and cannot be restored"),
                    Self::OpenedTarget => {
                        f.write_str("the record's interior is open for editing; edit it in place")
                    }
                    Self::TargetUnopened => f.write_str("descend the container before inserting into it"),
                    Self::AuthoredPayload => {
                        f.write_str("the record's payload is authored; there is no source interior")
                    }
                    Self::PayloadTooLarge { len } => {
                        write!(f, "payload of {len} bytes exceeds the length class")
                    }
                    Self::IndexSpaceExhausted => f.write_str(concat!("the ", $noun, "'s edit storage is full")),
                }
            }
        }

        impl core::error::Error for EditFault {}
    };
    (@1s_edit_fault $cap:ident, noun: $noun:literal, a_noun: $a_noun:literal, A_noun: $A_noun:literal) => {
        /// Why an edit command refused. Failure classes are judged in no
        /// promised order within one call.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum EditFault {
            /// The record's wire kind does not fit the command.
            KindMismatch {
                /// The record's actual kind.
                have: RecordKind,
            },
            /// The record is deleted; commit-only editing cannot restore
            /// it.
            DeletedTarget,
            /// The record's interior is open for editing; edit it in place
            /// or delete the record instead of replacing the payload
            /// wholesale.
            OpenedTarget,
            /// Descend the container before inserting into it.
            TargetUnopened,
            /// The record's payload is authored; there is no source
            /// interior to open.
            AuthoredPayload,
            /// The payload exceeds the length class.
            PayloadTooLarge {
                /// The refused payload length.
                len: usize,
            },
            /// The transfer source is not a live original source
            /// occurrence: authored, copied, and imported rows carry no
            /// designation.
            SourceNotBacked,
            /// A move's source subtree is not the source reading: a
            /// replacement, deletion, or interior edit sits on it, and
            /// relocating would silently discard that edit. Copying
            /// stays lawful; moving refuses.
            SourceModified,
            /// The destination gap is owned by the moved record's own
            /// subtree: once the source is suppressed, that gap has no
            /// emitted owner.
            MoveIntoSource,
            #[doc = concat!(" The ", $noun, "'s edit storage is full; the refusal is permanent")]
            #[doc = concat!(" for this ", $noun, ".")]
            IndexSpaceExhausted,
        }

        impl core::fmt::Display for EditFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::KindMismatch { have } => {
                        write!(f, "the command expects another wire kind; the record is {have}")
                    }
                    Self::DeletedTarget => f.write_str("the record is deleted and cannot be restored"),
                    Self::OpenedTarget => {
                        f.write_str("the record's interior is open for editing; edit it in place")
                    }
                    Self::TargetUnopened => f.write_str("descend the container before inserting into it"),
                    Self::AuthoredPayload => {
                        f.write_str("the record's payload is authored; there is no source interior")
                    }
                    Self::PayloadTooLarge { len } => {
                        write!(f, "payload of {len} bytes exceeds the length class")
                    }
                    Self::SourceNotBacked => {
                        f.write_str("the transfer source is not a live original source occurrence")
                    }
                    Self::SourceModified => {
                        f.write_str("the move's source subtree is not the source reading")
                    }
                    Self::MoveIntoSource => {
                        f.write_str("the destination gap is owned by the moved record's own subtree")
                    }
                    Self::IndexSpaceExhausted => f.write_str(concat!("the ", $noun, "'s edit storage is full")),
                }
            }
        }

        impl core::error::Error for EditFault {}
    };
    (@1s_src_marks plain) => {};
    (@1s_src_marks transfer) => {
        /// `Row.state` bits 6–7: the row's zone identity — which byte
        /// zone backs its geometry and whether the public identity
        /// answers the authored side.
        const ZONE_MASK: u8 = 0b11 << 6;
        /// Zone 1: output-authored identity over source-zone geometry —
        /// a row scanned out of a local whole-record copy's retained
        /// interior. The geometry stays readable (the save emits it),
        /// while the public identity answers (status, spans, reverse
        /// lookup, designation) speak the authored side.
        const ZONE_ALIAS: u8 = 1 << 6;
        /// Zone 2: a transfer-minted splice root — a whole-record copy
        /// or move destination. Distinguishes a clean copied root (whose
        /// span cannot join its chain's verbatim tiling) from the alias
        /// interiors beneath it.
        const ZONE_ALIAS_ROOT: u8 = 2 << 6;
        /// Zone 3: a first-class import interior — a row scanned out of
        /// an import slot at slot-local offsets, editable like a scanned
        /// row while the public identity stays authored.
        const ZONE_IMPORT: u8 = 3 << 6;
        /// `Row.state` base value 3: the value side is
        /// transfer-designated — an imported external record or a local
        /// source-payload designation, discriminated by `Row.value`
        /// ([`SrcValue`]). The designation rides rows, never the payload
        /// stores: ordinary slots stay untouched by the transfer faces.
        const BASE_SRC: u8 = 3;

        /// `Row.value` bit 31 under [`BASE_SRC`]: a designated payload —
        /// the masked word names the designated source row, or carries
        /// [`SRC_PAYLOAD_NEW`]. Clear: an imported record's payload-store
        /// slot — the import mint keeps its coordinates below the bit,
        /// as the arena's own `RowId` domain does.
        const SRC_PAYLOAD: u32 = 1 << 31;
        /// `Row.value` under [`BASE_SRC`]: a designated payload on an
        /// authored row — the subspan rides the row's own (otherwise
        /// meaningless) geometry words. Outside the designated-row
        /// domain: `RowId` tops out one below this mask's low bits.
        const SRC_PAYLOAD_NEW: u32 = u32::MAX;
    };
    (@1s_base_enum plain) => {
        /// A row's base edit state: which side speaks for the value. The
        /// deleted flag rides orthogonally so a deleted record's value
        /// side stays answerable.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Base {
            /// As scanned; the source bytes speak.
            Intact,
            /// The store value speaks; the source tag still rides.
            Replaced,
            /// Command-authored; the store value speaks and there is no
            /// source geometry.
            Inserted,
        }
    };
    (@1s_base_enum $cap:ident) => {
        /// A row's base edit state: which side speaks for the value. The
        /// deleted flag rides orthogonally so a deleted record's value
        /// side stays answerable.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Base {
            /// As scanned; the source bytes speak.
            Intact,
            /// The store value speaks; the source tag still rides.
            Replaced,
            /// Command-authored; the store value speaks and there is no
            /// source geometry.
            Inserted,
            /// Transfer-designated: an imported external record or a
            /// designated source payload — [`Row::src_value`] resolves
            /// the shape off the value word.
            Src,
        }

        /// A [`BASE_SRC`] row's value-side shape, decoded off the value
        /// word.
        #[derive(Clone, Copy)]
        enum SrcValue {
            /// An imported external record: the payload-store slot holds
            /// its exact bytes, which speak whole — framing included.
            Imported(PayloadAt),
            /// A designated payload behind the row's own scanned
            /// framing: the named source row's payload subspan speaks —
            /// resolved against the machine's own source at every read.
            PayloadRe(RowId),
            /// A designated payload on an authored row: the subspan
            /// rides the row's geometry words behind minimal authored
            /// framing.
            PayloadNew,
        }
    };
    (@1s_row_base plain) => {
            const fn base(&self) -> Base {
                match self.state & BASE_MASK {
                    BASE_INTACT => Base::Intact,
                    BASE_REPLACED => Base::Replaced,
                    _ => Base::Inserted,
                }
            }
    };
    (@1s_row_base $cap:ident) => {
            const fn base(&self) -> Base {
                match self.state & BASE_MASK {
                    BASE_INTACT => Base::Intact,
                    BASE_REPLACED => Base::Replaced,
                    BASE_INSERTED => Base::Inserted,
                    _ => Base::Src,
                }
            }

            /// The transfer-designated value side's shape. Only meaningful
            /// under [`BASE_SRC`]: the import mint keeps slot coordinates
            /// below bit 31, and the designated-row domain leaves the
            /// all-ones word free for the authored-designation mark.
            const fn src_value(&self) -> SrcValue {
                if self.value & SRC_PAYLOAD == 0 {
                    SrcValue::Imported(PayloadAt::of_slot(self.value))
                } else if self.value == SRC_PAYLOAD_NEW {
                    SrcValue::PayloadNew
                } else {
                    match RowId::new(self.value & !SRC_PAYLOAD) {
                        Some(row) => SrcValue::PayloadRe(row),
                        None => unreachable!(),
                    }
                }
            }
    };
    (@1s_row_src_marks plain) => {};
    (@1s_row_src_marks transfer) => {
            /// Re-authors an imported or transferred value side as an
            /// ordinary insertion — the transition every value command
            /// takes on an imported record.
            const fn set_inserted(&mut self) {
                self.state = (self.state & !BASE_MASK) | BASE_INSERTED;
            }

            /// Marks the value side transfer-designated; `value` carries
            /// the shape per [`SrcValue`].
            const fn set_src(&mut self, value: u32) {
                self.state = (self.state & !BASE_MASK) | BASE_SRC;
                self.value = value;
            }

            const fn alias(&self) -> bool {
                self.state & ZONE_MASK != 0
            }

            /// Read only by the debug dirty-witness re-derivation;
            /// the release save walk asks [`Self::rides_verbatim`].
            #[cfg(debug_assertions)]
            const fn alias_root(&self) -> bool {
                self.state & ZONE_MASK == ZONE_ALIAS_ROOT
            }

            const fn import_zone(&self) -> bool {
                self.state & ZONE_MASK == ZONE_IMPORT
            }
    };
    (@1s_rides_verbatim plain, ) => {
            /// One mask test for the save walk's hot question: intact base
            /// (`BASE_INTACT` is zero), not deleted, subtree clean — the
            /// record and everything beneath it ride the source verbatim.
            const fn rides_verbatim(&self) -> bool {
                self.state & (BASE_MASK | FLAG_DELETED | FLAG_DIRTY) == BASE_INTACT
            }
    };
    (@1s_rides_verbatim $cap:ident, ) => {
            /// One mask test for the save walk's hot question: intact base
            /// (`BASE_INTACT` is zero), not deleted, subtree clean, and
            /// not a source alias — the record and everything beneath it
            /// ride the source verbatim, and its span tiles its chain
            /// (an alias row's span sits elsewhere in the source, so it
            /// splices instead of joining the run).
            const fn rides_verbatim(&self) -> bool {
                self.state & (BASE_MASK | FLAG_DELETED | FLAG_DIRTY | ZONE_MASK) == BASE_INTACT
            }
    };
    (@1s_arm_enum plain) => {
        /// The save passes' verdict for one row, every value resolved at
        /// judgment time so neither pass re-derives anything.
        enum Arm {
            /// Deleted: contributes nothing, subtree included.
            Skip,
            /// An untouched leaf or sealed container: the whole source
            /// span rides verbatim.
            Clean { at: u32, end: u32 },
            /// A replaced scalar: source tag verbatim, then the value.
            ReValue { tag_at: u32, tag_end: u32, value: Word },
            /// An authored scalar: minimal head, then the value.
            NewValue { head: u32, value: Word },
            /// A replaced LEN: source tag verbatim; the prefix rides
            /// verbatim iff the authored payload keeps the source length.
            ReBody { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, value: PayloadAt },
            /// An authored LEN: minimal head, prefix, payload.
            NewBody { head: u32, value: PayloadAt },
            /// A source-framed LEN with an opened interior: recurse; the
            /// prefix rides verbatim iff the interior lands back on the
            /// source length.
            Spine { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, first: Option<RowId> },
        }
    };
    (@1s_arm_enum transfer) => {
        /// The save passes' verdict for one row, every value resolved at
        /// judgment time so neither pass re-derives anything.
        enum Arm {
            /// Deleted: contributes nothing, subtree included.
            Skip,
            /// An untouched leaf or sealed container: the whole source
            /// span rides verbatim.
            Clean { at: u32, end: u32 },
            /// A replaced scalar: source tag verbatim, then the value.
            ReValue { tag_at: u32, tag_end: u32, value: Word },
            /// An authored scalar: minimal head, then the value.
            NewValue { head: u32, value: Word },
            /// A replaced LEN: source tag verbatim; the prefix rides
            /// verbatim iff the authored payload keeps the source length.
            ReBody { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, value: PayloadAt },
            /// An authored LEN: minimal head, prefix, payload.
            NewBody { head: u32, value: PayloadAt },
            /// A source-framed LEN with an opened interior: recurse; the
            /// prefix rides verbatim iff the interior lands back on the
            /// source length.
            Spine { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, first: Option<RowId> },
            /// An imported external record with a clean interior: its
            /// slot's exact bytes emit whole — framing included, nothing
            /// re-encoded.
            Import { value: PayloadAt },
            /// An imported record with interior edits: the slot tag
            /// rides verbatim, the prefix rides verbatim iff the walked
            /// body keeps the slot's length, and the walk recurses into
            /// the first-class interior rows. Offsets are slot-local.
            ImportSpine {
                /// The record tag's window in the slot.
                tag_at: u32,
                /// One past the tag; the LEN prefix starts here.
                tag_end: u32,
                /// One past the slot's met LEN prefix.
                prefix_end: u32,
                /// The slot's met body length.
                src_len: u32,
                /// The import slot: the interior windows' zone.
                value: PayloadAt,
                /// The interior's first row.
                first: Option<RowId>,
            },
            /// A designated payload behind scanned framing: source tag
            /// verbatim; the prefix rides verbatim iff the designated
            /// subspan keeps the source length; the subspan emits as a
            /// source window.
            ReSrcBody { tag_at: u32, tag_end: u32, prefix_end: u32, src_len: u32, at: u32, len: u32 },
            /// A designated payload on an authored row: minimal head and
            /// prefix; the subspan emits as a source window.
            NewSrcBody { head: u32, at: u32, len: u32 },
        }
    };
    (@1s_zone_of plain, ) => {};
    (@1s_zone_of transfer, ) => {
            /// The byte zone a row's scanned geometry indexes: the
            /// admitted source for document rows, the owning import slot
            /// (slot-local offsets by construction) for first-class
            /// import interiors.
            fn zone_of(&self, row: &Row) -> &[u8] {
                if row.import_zone() { self.import_bytes(self.import_root(row)) } else { &self.source }
            }

            /// The import root owning a first-class interior row: the
            /// nearest ancestor whose value side is the import
            /// designation. The climb holds because import interiors
            /// parse only out of an import slot, and designations are
            /// refused on import-zone rows — no other `Src` carrier can
            /// sit between an interior and its root.
            fn import_root(&self, row: &Row) -> &Row {
                let mut cur = row;
                loop {
                    let parent = match cur.parent {
                        Some(id) => self.row(id),
                        None => unreachable!("import interiors sit under their import root"),
                    };
                    if matches!(parent.base(), Base::Src) {
                        return parent;
                    }
                    cur = parent;
                }
            }
    };
    (@1s_import_value_at plain, ) => {
    };
    (@1s_import_value_at $cap:ident, ) => {
        /// The value offset inside an imported record's bytes: past its
        /// met head tag. Imported designations are structurally
        /// complete, so the bounded read cannot refuse.
        fn import_value_at(bytes: &[u8]) -> usize {
            match slice::tag_word(bytes, 0, bytes.len()) {
                Ok((_, width)) => usize::from(width),
                Err(_) => unreachable!("imported records are structurally complete"),
            }
        }
    };
    (@1s_transfer_readers plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
    };
    (@1s_transfer_readers $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// A designated payload's source subspan `(start, len)`,
            /// resolved against the arena: the named source row's
            /// geometry for a replacement designation, the row's own
            /// carried words for an authored one. Scanned geometry never
            /// changes, so the answer is the subspan the transfer face
            /// judged.
            fn designated_span(&self, row: &Row) -> (Coord, u32) {
                match row.src_value() {
                    SrcValue::PayloadRe(src) => {
                        let src = self.row(src);
                        (src.payload_at(), src.payload_len.as_inner())
                    }
                    SrcValue::PayloadNew => (row.start, row.payload_len.as_inner()),
                    SrcValue::Imported(_) => {
                        unreachable!("imported records speak whole slots, not subspans")
                    }
                }
            }

            /// A designated payload's bytes: the resolved subspan of the
            /// machine's own source.
            fn designated_bytes(&self, row: &Row) -> &[u8] {
                let (at, len) = self.designated_span(row);
                let at = at.as_inner();
                // SAFETY: the transfer face judged the subspan inside
                // the admitted source, and scanned geometry never
                // changes.
                unsafe { self.source.get_unchecked(usize_of(at)..usize_of(at + len)) }
            }

            /// An imported record's exact bytes — the slot the import
            /// registered. Imported records land in whole slots, never
            /// scatter ones.
            fn import_slot(&self, value: PayloadAt) -> &[u8] {
                match self.payloads.contiguous(value) {
                    Some(bytes) => bytes,
                    None => unreachable!("imported records land in contiguous slots"),
                }
            }

            /// The imported record's exact bytes, off its row.
            fn import_bytes(&self, row: &Row) -> &[u8] {
                self.import_slot(PayloadAt::of_slot(row.value))
            }

            /// The payload subspan inside an imported LEN's bytes.
            /// Imported designations are structurally complete, so the
            /// bounded reads cannot refuse.
            fn import_payload(&self, value: PayloadAt) -> &[u8] {
                let bytes = self.import_slot(value);
                let at = import_value_at(bytes);
                match slice::len_word(bytes, at, bytes.len()) {
                    Ok((len, width)) => {
                        let body = at + usize::from(width);
                        &bytes[body..body + usize_of(len.as_inner())]
                    }
                    Err(_) => unreachable!("imported records are structurally complete"),
                }
            }
    };
    (@1s_status plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The record's observable edit state.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn status(&self, handle: Handle) -> EditStatus {
                let row = gate(&self.rows, handle);
                if row.deleted() {
                    return EditStatus::Deleted;
                }
                match row.base() {
                    Base::Intact => EditStatus::Intact,
                    Base::Replaced => EditStatus::Replaced,
                    Base::Inserted => EditStatus::Inserted,
                }
            }
    };
    (@1s_status $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The record's observable edit state.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn status(&self, handle: Handle) -> EditStatus {
                let row = gate(&self.rows, handle);
                if row.deleted() {
                    return EditStatus::Deleted;
                }
                // Local whole-record copies and their retained interiors
                // are output-authored whatever their internal base: the
                // copy was inserted, and later value commands keep the
                // ordinary inserted answer.
                if row.alias() {
                    return EditStatus::Inserted;
                }
                match row.base() {
                    Base::Intact => EditStatus::Intact,
                    Base::Replaced => EditStatus::Replaced,
                    Base::Inserted => EditStatus::Inserted,
                    // A replacement designation reads as an ordinary
                    // replacement (its scanned tag still rides); imports
                    // and authored designations read as insertions.
                    Base::Src => match row.src_value() {
                        SrcValue::PayloadRe(_) => EditStatus::Replaced,
                        SrcValue::Imported(_) | SrcValue::PayloadNew => EditStatus::Inserted,
                    },
                }
            }
    };
    (@1s_value_reads plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The varint record's current value (`None`: not a VARINT
            /// record): the pending replacement if one is set, the scanned
            /// value otherwise (deleted records keep answering — deletion
            /// only prunes the save).
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn varint_word(&self, handle: Handle) -> Option<u64> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Varint) {
                    return None;
                }
                Some(match row.base() {
                    // SAFETY: the scan judged a terminating in-class varint
                    // at this offset inside the admitted source, and the
                    // stored tag width binds the offset.
                    Base::Intact => unsafe {
                        slice::value64_unchecked(&self.source, usize_of(row.start.as_inner() + row.tag_w()))
                    },
                    Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
                })
            }

            /// The fixed 32-bit record's current value bits (`None`: not
            /// an I32 record).
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn i32_bits(&self, handle: Handle) -> Option<u32> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::I32) {
                    return None;
                }
                Some(match row.base() {
                    // SAFETY: the scan judged four value bytes inside the
                    // admitted source, right after the stored tag width.
                    Base::Intact => u32::from_le(unsafe {
                        self.source
                            .as_ptr()
                            .add(usize_of(row.start.as_inner() + row.tag_w()))
                            .cast::<u32>()
                            .read_unaligned()
                    }),
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "fixed 32-bit words are stored zero-extended"
                    )]
                    #[allow(clippy::as_conversions, reason = "the stored word is the value's own bits")]
                    Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)) as u32,
                })
            }

            /// The fixed 64-bit record's current value bits (`None`: not
            /// an I64 record).
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn i64_bits(&self, handle: Handle) -> Option<u64> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::I64) {
                    return None;
                }
                Some(match row.base() {
                    // SAFETY: the scan judged eight value bytes inside the
                    // admitted source, right after the stored tag width.
                    Base::Intact => u64::from_le(unsafe {
                        self.source
                            .as_ptr()
                            .add(usize_of(row.start.as_inner() + row.tag_w()))
                            .cast::<u64>()
                            .read_unaligned()
                    }),
                    Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
                })
            }
    };
    (@1s_value_reads transfer, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The varint record's current value (`None`: not a VARINT
            /// record): the pending replacement if one is set, the scanned
            /// value otherwise (deleted records keep answering — deletion
            /// only prunes the save).
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn varint_word(&self, handle: Handle) -> Option<u64> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Varint) {
                    return None;
                }
                Some(match row.base() {
                    // SAFETY: the scan judged a terminating in-class varint
                    // at this offset inside the admitted source, and the
                    // stored tag width binds the offset.
                    Base::Intact => unsafe {
                        slice::value64_unchecked(self.zone_of(row), usize_of(row.start.as_inner() + row.tag_w()))
                    },
                    Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
                    // Scalar rows import whole records; designated
                    // payloads are LENs and never reach a scalar read.
                    Base::Src => {
                        let bytes = self.import_bytes(row);
                        match slice::value64(bytes, import_value_at(bytes), bytes.len()) {
                            Ok((value, _)) => value,
                            Err(_) => unreachable!("imported records are structurally complete"),
                        }
                    }
                })
            }

            /// The fixed 32-bit record's current value bits (`None`: not
            /// an I32 record).
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn i32_bits(&self, handle: Handle) -> Option<u32> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::I32) {
                    return None;
                }
                Some(match row.base() {
                    // SAFETY: the scan judged four value bytes inside the
                    // admitted source, right after the stored tag width.
                    Base::Intact => u32::from_le(unsafe {
                        self.zone_of(row)
                            .as_ptr()
                            .add(usize_of(row.start.as_inner() + row.tag_w()))
                            .cast::<u32>()
                            .read_unaligned()
                    }),
                    #[allow(
                        clippy::cast_possible_truncation,
                        reason = "fixed 32-bit words are stored zero-extended"
                    )]
                    #[allow(clippy::as_conversions, reason = "the stored word is the value's own bits")]
                    Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)) as u32,
                    Base::Src => {
                        let bytes = self.import_bytes(row);
                        let at = import_value_at(bytes);
                        let Ok(value) = bytes[at..at + 4].try_into() else {
                            unreachable!("imported records are structurally complete")
                        };
                        u32::from_le_bytes(value)
                    }
                })
            }

            /// The fixed 64-bit record's current value bits (`None`: not
            /// an I64 record).
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn i64_bits(&self, handle: Handle) -> Option<u64> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::I64) {
                    return None;
                }
                Some(match row.base() {
                    // SAFETY: the scan judged eight value bytes inside the
                    // admitted source, right after the stored tag width.
                    Base::Intact => u64::from_le(unsafe {
                        self.zone_of(row)
                            .as_ptr()
                            .add(usize_of(row.start.as_inner() + row.tag_w()))
                            .cast::<u64>()
                            .read_unaligned()
                    }),
                    Base::Replaced | Base::Inserted => self.words.word(WordAt::of_slot(row.value)),
                    Base::Src => {
                        let bytes = self.import_bytes(row);
                        let at = import_value_at(bytes);
                        let Ok(value) = bytes[at..at + 8].try_into() else {
                            unreachable!("imported records are structurally complete")
                        };
                        u64::from_le_bytes(value)
                    }
                })
            }
    };
    (@1s_descend plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Opens a LEN's interior for editing. The payload parses on
            /// the first call — an explicit commitment that these bytes
            /// are a message, never a speculation — and the verdict is
            /// resident: a wire fault or a refusal (lawful wire outside
            #[doc = concat!(" this ", $noun, "'s language or declared bounds) parks on the")]
            /// record and projects unchanged on every later call.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] for scalar records,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::AuthoredPayload`] when the payload was
            /// replaced or command-authored (there is no source interior),
            /// [`EditFault::IndexSpaceExhausted`] when the interior rows
            /// outgrow the row domain (the verdict is not parked). On any
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{Descent, ", stringify!($Machine), "};")]
            ///
            /// // LEN f2 wrapping { varint f1=1 } · LEN f3 { group code }
            /// let msg = [0x12, 0x02, 0x08, 0x01, 0x1A, 0x01, 0x0B];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            ///
            #[doc = concat!(" let Descent::Opened { first: Some(inner) } = ", $noun, ".descend(tops[0]).unwrap() else {")]
            ///     unreachable!()
            /// };
            #[doc = concat!(" assert_eq!(", $noun, ".varint_word(inner).unwrap(), 1);")]
            ///
            /// // The group-bearing payload's refusal is resident, and the
            #[doc = concat!(" // ", $noun, " lives on.")]
            #[doc = concat!(" assert!(matches!(", $noun, ".descend(tops[1]).unwrap(), Descent::Refused(_)));")]
            #[doc = concat!(" assert!(matches!(", $noun, ".descend(tops[1]).unwrap(), Descent::Refused(_)));")]
            /// ```
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                let id = handle.0;
                let row = *gate(&self.rows, handle);
                if row.deleted() {
                    return Err(EditFault::DeletedTarget);
                }
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                if !matches!(row.base(), Base::Intact) {
                    return Err(EditFault::AuthoredPayload);
                }
                if row.opened() {
                    return Ok(Descent::Opened { first: row.kid.map(Handle) });
                }
                if row.faulted() {
                    return Ok(project(&self.faults, row.value));
                }
                let depth = self.depth_of(id);
                if depth >= u32::from(self.limit.as_inner()) {
                    return self.park(
                        id,
                        SlotFault::Refused(Refusal::DepthExceeded { at: row.start.as_inner(), field: row.field }),
                    );
                }
                let body_at = row.payload_at().as_inner();
                let mark = self.rows.len();
                match scan_layer(&mut self.rows, &self.source, body_at, body_at + row.payload_len.as_inner(), Some(id))
                {
                    Ok(first) => {
                        let row = self.row_mut(id);
                        row.kid = first;
                        row.set_opened();
                        Ok(Descent::Opened { first: first.map(Handle) })
                    }
                    Err(halt) => {
                        self.rows.truncate(mark);
                        match halt {
                            Halt::Wire(fault) => self.park(id, SlotFault::Wire(fault)),
                            Halt::Refused(refusal) => self.park(id, SlotFault::Refused(refusal)),
                            Halt::Exhausted => Err(EditFault::IndexSpaceExhausted),
                        }
                    }
                }
            }
    };
    (@1s_descend transfer, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Opens a LEN's interior for editing. The payload parses on
            /// the first call — an explicit commitment that these bytes
            /// are a message, never a speculation — and the verdict is
            /// resident: a wire fault or a refusal (lawful wire outside
            #[doc = concat!(" this ", $noun, "'s language or declared bounds) parks on the")]
            /// record and projects unchanged on every later call.
            ///
            /// An imported record's interior descends too: its rows are
            /// first-class — readable and editable like scanned rows,
            /// addressed over the import's own bytes — and verdict
            /// and fault offsets inside them index the import's byte
            /// zone, not this machine's source.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] for scalar records,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::AuthoredPayload`] when the payload was
            /// replaced or command-authored (there is no source
            /// interior; a live import is the exception above),
            /// [`EditFault::IndexSpaceExhausted`] when the interior rows
            /// outgrow the row domain (the verdict is not parked). On any
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{Descent, ", stringify!($Machine), "};")]
            ///
            /// // LEN f2 wrapping { varint f1=1 } · LEN f3 { group code }
            /// let msg = [0x12, 0x02, 0x08, 0x01, 0x1A, 0x01, 0x0B];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            ///
            #[doc = concat!(" let Descent::Opened { first: Some(inner) } = ", $noun, ".descend(tops[0]).unwrap() else {")]
            ///     unreachable!()
            /// };
            #[doc = concat!(" assert_eq!(", $noun, ".varint_word(inner).unwrap(), 1);")]
            ///
            /// // The group-bearing payload's refusal is resident, and the
            #[doc = concat!(" // ", $noun, " lives on.")]
            #[doc = concat!(" assert!(matches!(", $noun, ".descend(tops[1]).unwrap(), Descent::Refused(_)));")]
            #[doc = concat!(" assert!(matches!(", $noun, ".descend(tops[1]).unwrap(), Descent::Refused(_)));")]
            /// ```
            #[track_caller]
            pub fn descend(&mut self, handle: Handle) -> Result<Descent<'_>, EditFault> {
                let id = handle.0;
                let row = *gate(&self.rows, handle);
                if row.deleted() {
                    return Err(EditFault::DeletedTarget);
                }
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                match row.base() {
                    Base::Intact => {}
                    // An imported LEN's interior parses out of its slot
                    // at slot-local offsets into first-class rows.
                    Base::Src if matches!(row.src_value(), SrcValue::Imported(_)) => {}
                    Base::Src | Base::Replaced | Base::Inserted => {
                        return Err(EditFault::AuthoredPayload);
                    }
                }
                if row.opened() {
                    return Ok(Descent::Opened { first: row.kid.map(Handle) });
                }
                if row.faulted() {
                    return Ok(project(&self.faults, row.value));
                }
                let depth = self.depth_of(id);
                if depth >= u32::from(self.limit.as_inner()) {
                    return self.park(
                        id,
                        SlotFault::Refused(Refusal::DepthExceeded { at: row.start.as_inner(), field: row.field }),
                    );
                }
                // The window and its zone: the document for scanned
                // rows, the import slot (slot-local) for imports.
                let (zone_mark, body_at, body_end): (u8, u32, u32) = if matches!(row.base(), Base::Src) {
                    let bytes = match self.payloads.contiguous(PayloadAt::of_slot(row.value)) {
                        Some(bytes) => bytes,
                        None => unreachable!("imported records land in contiguous slots"),
                    };
                    let at = import_value_at(bytes);
                    match slice::len_word(bytes, at, bytes.len()) {
                        Ok((len, width)) => {
                            let body = admitted_u32(at + usize::from(width));
                            (ZONE_IMPORT, body, body + len.as_inner())
                        }
                        Err(_) => unreachable!("imported records are structurally complete"),
                    }
                } else {
                    (
                        if row.alias() { ZONE_ALIAS } else { 0 },
                        row.payload_at().as_inner(),
                        row.payload_at().as_inner() + row.payload_len.as_inner(),
                    )
                };
                let mark = self.rows.len();
                let scan = if matches!(row.base(), Base::Src) {
                    let bytes = match self.payloads.contiguous(PayloadAt::of_slot(row.value)) {
                        Some(bytes) => bytes,
                        None => unreachable!("imported records land in contiguous slots"),
                    };
                    scan_layer(&mut self.rows, bytes, body_at, body_end, Some(id))
                } else {
                    scan_layer(&mut self.rows, &self.source, body_at, body_end, Some(id))
                };
                match scan {
                    Ok(first) => {
                        // A copy's or import's retained interior parses
                        // lazily; its rows carry their zone identity.
                        if zone_mark != 0 {
                            for interior in &mut self.rows[mark..] {
                                interior.state |= zone_mark;
                            }
                        }
                        let row = self.row_mut(id);
                        row.kid = first;
                        row.set_opened();
                        Ok(Descent::Opened { first: first.map(Handle) })
                    }
                    Err(halt) => {
                        self.rows.truncate(mark);
                        match halt {
                            Halt::Wire(fault) => self.park(id, SlotFault::Wire(fault)),
                            Halt::Refused(refusal) => self.park(id, SlotFault::Refused(refusal)),
                            Halt::Exhausted => Err(EditFault::IndexSpaceExhausted),
                        }
                    }
                }
            }
    };
    (@1s_set_scalar plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The shared scalar setter: kind and deletion gates, then the
            /// one fallible store step, then the state flip.
            #[track_caller]
            fn set_scalar(&mut self, handle: Handle, want: RecordKind, word: u64) -> Result<(), EditFault> {
                let row = *gate(&self.rows, handle);
                if row.kind != want {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                if row.deleted() {
                    return Err(EditFault::DeletedTarget);
                }
                match row.base() {
                    Base::Intact => {
                        let at = self.words.push_word(word).ok_or(EditFault::IndexSpaceExhausted)?;
                        let row = self.row_mut(handle.0);
                        row.value = at.raw();
                        row.set_replaced();
                    }
                    // Re-sets overwrite the minted word in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.words.set_word(WordAt::of_slot(row.value), word);
                    }
                }
                self.mark_dirty(handle.0);
                Ok(())
            }
    };
    (@1s_set_scalar $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The shared scalar setter: kind and deletion gates, then the
            /// one fallible store step, then the state flip.
            #[track_caller]
            fn set_scalar(&mut self, handle: Handle, want: RecordKind, word: u64) -> Result<(), EditFault> {
                let row = *gate(&self.rows, handle);
                if row.kind != want {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                if row.deleted() {
                    return Err(EditFault::DeletedTarget);
                }
                match row.base() {
                    Base::Intact => {
                        let at = self.words.push_word(word).ok_or(EditFault::IndexSpaceExhausted)?;
                        let row = self.row_mut(handle.0);
                        row.value = at.raw();
                        row.set_replaced();
                    }
                    // Re-sets overwrite the minted word in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.words.set_word(WordAt::of_slot(row.value), word);
                    }
                    // A value command on an imported record re-authors it
                    // as an ordinary insertion: the imported spelling is
                    // the value side, and the value just changed whole.
                    // (Scalar rows import whole records; designated
                    // payloads are LENs and never reach a scalar set.)
                    Base::Src => {
                        let at = self.words.push_word(word).ok_or(EditFault::IndexSpaceExhausted)?;
                        let row = self.row_mut(handle.0);
                        row.value = at.raw();
                        row.set_inserted();
                    }
                }
                self.mark_dirty(handle.0);
                Ok(())
            }
    };
    (@1s_apply_insert plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Splices an authored row (the infallible suffix of every
            /// insert command: every reservation holds).
            fn apply_insert(
                &mut self,
                plan: &Plan,
                id: RowId,
                field: FieldNumber,
                kind: RecordKind,
                value: u32,
            ) {
                let next = plan.prev.map_or_else(|| self.first_of(plan.parent), |prev| self.row(prev).next);
                self.rows.push(Row::authored(field, kind, plan.parent, next, value));
                match plan.prev {
                    Some(prev) => self.row_mut(prev).next = Some(id),
                    None => match plan.parent {
                        Some(parent) => self.row_mut(parent).kid = Some(id),
                        None => self.top = Some(id),
                    },
                }
                self.mark_dirty(id);
            }
    };
    (@1s_apply_insert $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The gap a proven plan names: the row that will follow the
            /// splice.
            fn plan_next(&self, plan: &Plan) -> Option<RowId> {
                plan.prev.map_or_else(|| self.first_of(plan.parent), |prev| self.row(prev).next)
            }

            /// Splices a prebuilt row at a proven plan — the linking
            /// suffix every splice shares (the row was built over
            /// [`Self::plan_next`]'s answer).
            fn splice_row(&mut self, plan: &Plan, id: RowId, row: Row) {
                self.rows.push(row);
                match plan.prev {
                    Some(prev) => self.row_mut(prev).next = Some(id),
                    None => match plan.parent {
                        Some(parent) => self.row_mut(parent).kid = Some(id),
                        None => self.top = Some(id),
                    },
                }
            }

            /// Splices an authored row (the infallible suffix of every
            /// insert command: every reservation holds).
            fn apply_insert(
                &mut self,
                plan: &Plan,
                id: RowId,
                field: FieldNumber,
                kind: RecordKind,
                value: u32,
            ) {
                let next = self.plan_next(plan);
                self.splice_row(plan, id, Row::authored(field, kind, plan.parent, next, value));
                self.mark_dirty(id);
            }
    };
    (@1s_transfer_faces plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {};
    (@1s_transfer_faces $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Splices an imported record's row (the infallible suffix
            /// of the external copy faces: every reservation holds).
            fn apply_import(
                &mut self,
                plan: &Plan,
                id: RowId,
                field: FieldNumber,
                kind: RecordKind,
                value: u32,
            ) {
                let next = self.plan_next(plan);
                let mut row = Row::authored(field, kind, plan.parent, next, value);
                row.state = BASE_SRC;
                self.splice_row(plan, id, row);
                self.mark_dirty(id);
            }

            /// Splices a designated-payload insertion's row (the
            /// infallible suffix of the local payload transfer faces:
            /// every reservation holds). The authored row's geometry
            /// words carry the designated subspan.
            fn apply_designated_insert(
                &mut self,
                plan: &Plan,
                id: RowId,
                field: FieldNumber,
                at: Coord,
                len: Extent,
            ) {
                let next = self.plan_next(plan);
                let mut row = Row::authored(field, RecordKind::Len, plan.parent, next, SRC_PAYLOAD_NEW);
                row.state = BASE_SRC;
                row.start = at;
                row.payload_len = len;
                self.splice_row(plan, id, row);
                self.mark_dirty(id);
            }

            // ── source transfer ──

            /// Records a transfer splice's edit witnesses: the whole-
            /// document latch and the ancestor chain from the splice's
            /// parent upward. The spliced root itself stays unmarked — a
            /// clean copy emits its whole span verbatim without an
            /// interior walk, and the alias mask keeps it out of its
            /// chain's tiling runs.
            fn mark_dirty_from(&mut self, parent: Option<RowId>) {
                self.dirty = true;
                let mut cur = parent;
                while let Some(at) = cur {
                    let row = self.row_mut(at);
                    if row.dirty() {
                        break;
                    }
                    row.set_dirty();
                    cur = row.parent;
                }
            }

            /// The transfer faces' source witness: the row is an
            /// original admitted occurrence. A pending edit does not
            /// block a copy — the designation names the source reading.
            #[track_caller]
            fn transfer_source(&self, source: Handle) -> Result<Row, EditFault> {
                let row = *gate(&self.rows, source);
                if !row.has_source() {
                    return Err(EditFault::SourceNotBacked);
                }
                Ok(row)
            }

            /// The move faces' stronger witness: live and unmodified —
            /// the current subtree is exactly the source reading, so the
            /// relocation discards nothing.
            #[track_caller]
            fn move_source(&self, source: Handle) -> Result<Row, EditFault> {
                let row = self.transfer_source(source)?;
                if row.deleted() || !matches!(row.base(), Base::Intact) || row.dirty() {
                    return Err(EditFault::SourceModified);
                }
                Ok(row)
            }

            /// Refuses a destination gap owned by the moved record's own
            /// subtree: with the source suppressed, such a gap has no
            /// emitted owner. A gap right after the source resolves into
            /// the parent's chain and stays lawful.
            fn move_gap_gate(&self, plan: &Plan, source: RowId) -> Result<(), EditFault> {
                let mut cur = plan.parent;
                while let Some(at) = cur {
                    if at == source {
                        return Err(EditFault::MoveIntoSource);
                    }
                    cur = self.row(at).parent;
                }
                Ok(())
            }

            /// Copies the designated record to the anchor: the new
            /// record contributes the source occurrence's exact bytes at
            /// save — met tag spelling, framing words at their met
            /// widths, the whole payload — while the original keeps its
            /// own pre-existing edit state. The copy is output-authored:
            /// its status reads `Inserted`, it answers no source span,
            /// and it does not designate; its interior starts opaque,
            #[doc = concat!(" and a later [`", stringify!($Machine), "::descend`] parses the retained")]
            /// source-backed bytes (unlike caller-authored opaque
            /// payloads). Zero payload bytes stage: the row stores
            /// coordinates into the machine's own source.
            ///
            /// A designation names the source reading, so copying a
            /// record whose value side carries a pending edit copies the
            /// original bytes — save and reopen when the effective state
            /// is the thing to duplicate.
            ///
            /// # Errors
            ///
            /// [`EditFault::SourceNotBacked`] when `source` is not an
            /// original source occurrence (authored, copied, or imported
            /// rows), plus the anchor gates of
            #[doc = concat!(" [`", stringify!($Machine), "::insert_varint`]. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// // varint f1=5 · varint f2=6; copy f1 to the tail.
            /// let msg = [0x08, 0x05, 0x10, 0x06];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".copy_record(first, InsertAt::TailOf(None)).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x08, 0x05, 0x10, 0x06, 0x08, 0x05]);")]
            /// ```
            #[track_caller]
            pub fn copy_record(&mut self, source: Handle, at: InsertAt) -> Result<Handle, EditFault> {
                let src = self.transfer_source(source)?;
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let next = self.plan_next(&plan);
                self.splice_row(&plan, id, src.cloned_alias(plan.parent, next));
                self.mark_dirty_from(plan.parent);
                Ok(Handle(id))
            }

            /// Moves the designated record to the anchor: one atomic
            #[doc = concat!(" command equal to [`", stringify!($Machine), "::copy_record`] plus suppression")]
            /// of the original occurrence — the exact source bytes emit
            /// at the destination and nowhere else. The source bytes are
            /// neither mutated nor re-encoded; the destination handle is
            #[doc = concat!(" the copy's ([`", stringify!($Machine), "::copy_record`]'s contract).")]
            ///
            /// # Errors
            ///
            /// [`EditFault::SourceNotBacked`] when `source` is not an
            /// original source occurrence,
            /// [`EditFault::SourceModified`] when its current subtree is
            /// not the source reading (a replacement, deletion, or
            /// interior edit sits on it — relocating would silently
            /// discard that edit), [`EditFault::MoveIntoSource`] when the
            /// destination gap is owned by the moved record's own
            /// subtree, plus the anchor gates of
            #[doc = concat!(" [`", stringify!($Machine), "::insert_varint`]. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// // varint f1=5 · varint f2=6; move f1 after f2.
            /// let msg = [0x08, 0x05, 0x10, 0x06];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            #[doc = concat!(" ", $noun, ".move_record(tops[0], InsertAt::After(tops[1])).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x10, 0x06, 0x08, 0x05]);")]
            /// ```
            #[track_caller]
            pub fn move_record(&mut self, source: Handle, at: InsertAt) -> Result<Handle, EditFault> {
                let src = self.move_source(source)?;
                let plan = self.resolve_anchor(at)?;
                self.move_gap_gate(&plan, source.0)?;
                let id = self.mint_insert()?;
                let next = self.plan_next(&plan);
                self.splice_row(&plan, id, src.cloned_alias(plan.parent, next));
                self.mark_dirty_from(plan.parent);
                self.row_mut(source.0).set_deleted();
                self.mark_dirty(source.0);
                Ok(Handle(id))
            }

            /// Copies the designated LEN's payload interior to the
            /// target: a replacement keeps the target's own tag verbatim
            /// (and its prefix too while the length is unchanged), an
            /// insertion authors the supplied field's tag and prefix
            /// minimally — only the interior bytes are the source's, and
            /// they ride byte-exact. Zero payload bytes stage: the slot
            /// stores coordinates into the machine's own source. The
            /// interior lands as the source's declaration — opaque bytes,
            /// judged only if an explicit descend later commits them.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless `source` is a LEN,
            /// [`EditFault::SourceNotBacked`] when it is not an original
            /// source occurrence, plus the target's own gates
            #[doc = concat!(" ([`", stringify!($Machine), "::set_payload`]'s for a replacement,")]
            #[doc = concat!(" [`", stringify!($Machine), "::insert_varint`]'s anchor gates for an insertion).")]
            #[doc = concat!(" On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{PayloadTarget, ", stringify!($Machine), "};")]
            ///
            /// // LEN f1 "hi" · LEN f2 "no": replace f2's payload with
            /// // f1's.
            /// let msg = [0x0A, 0x02, 0x68, 0x69, 0x12, 0x02, 0x6E, 0x6F];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            #[doc = concat!(" ", $noun, ".copy_payload(tops[0], PayloadTarget::Replace(tops[1])).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x0A, 0x02, 0x68, 0x69, 0x12, 0x02, 0x68, 0x69]);")]
            /// ```
            #[track_caller]
            pub fn copy_payload(
                &mut self,
                source: Handle,
                target: PayloadTarget,
            ) -> Result<Handle, EditFault> {
                let src = self.transfer_source(source)?;
                if !matches!(src.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: src.kind });
                }
                let payload_at = src.payload_at();
                let payload_len = src.payload_len;
                match target {
                    PayloadTarget::Replace(handle) => {
                        let row = self.payload_set_gate(handle, usize_of(payload_len.as_inner()))?;
                        // The designation rides the row, never a store
                        // slot: rows on scanned framing name the source
                        // row, authored ones carry the subspan in their
                        // own geometry words. A replaced slot stays
                        // behind inert; nothing here can fail.
                        let target = self.row_mut(handle.0);
                        match row.base() {
                            Base::Intact | Base::Replaced => {
                                target.set_src(SRC_PAYLOAD | source.0.as_inner());
                            }
                            Base::Src if matches!(row.src_value(), SrcValue::PayloadRe(_)) => {
                                target.set_src(SRC_PAYLOAD | source.0.as_inner());
                            }
                            // An authored or imported framing re-authors:
                            // the geometry words (meaningless on authored
                            // rows) are free to carry the subspan.
                            Base::Inserted | Base::Src => {
                                target.start = payload_at;
                                target.payload_len = payload_len;
                                target.set_src(SRC_PAYLOAD_NEW);
                            }
                        }
                        let target = self.row_mut(handle.0);
                        target.clear_faulted();
                        self.mark_dirty(handle.0);
                        Ok(handle)
                    }
                    PayloadTarget::Insert { at, field } => {
                        let plan = self.resolve_anchor(at)?;
                        let id = self.mint_insert()?;
                        self.apply_designated_insert(&plan, id, field, payload_at, payload_len);
                        Ok(Handle(id))
                    }
                }
            }

            /// Moves the designated LEN's payload interior to a fresh
            /// record at the anchor: one atomic command equal to
            #[doc = concat!(" [`", stringify!($Machine), "::copy_payload`]'s insertion form plus suppression")]
            /// of the whole source record — removing only the payload
            /// would leave a tag and prefix with no lawful meaning. The
            /// fresh record authors `field`'s tag and prefix minimally;
            /// the interior rides byte-exact, zero bytes staged.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless `source` is a LEN,
            /// [`EditFault::SourceNotBacked`] when it is not an original
            /// source occurrence, [`EditFault::SourceModified`] when its
            /// current subtree is not the source reading,
            /// [`EditFault::MoveIntoSource`] when the destination gap is
            /// owned by the source's own subtree, plus the anchor gates
            #[doc = concat!(" of [`", stringify!($Machine), "::insert_varint`]. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the arguments was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::{DepthLimit, FieldNumber};
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// // varint f1=5 · LEN f2 "hi": relocate the payload to a
            /// // fresh head-of-layer f3.
            /// let msg = [0x08, 0x05, 0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            /// let f3 = FieldNumber::new(3).unwrap();
            #[doc = concat!(" ", $noun, ".move_payload(tops[1], InsertAt::HeadOf(None), f3).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x1A, 0x02, 0x68, 0x69, 0x08, 0x05]);")]
            /// ```
            #[track_caller]
            pub fn move_payload(
                &mut self,
                source: Handle,
                at: InsertAt,
                field: FieldNumber,
            ) -> Result<Handle, EditFault> {
                let src = self.move_source(source)?;
                if !matches!(src.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: src.kind });
                }
                let plan = self.resolve_anchor(at)?;
                self.move_gap_gate(&plan, source.0)?;
                let id = self.mint_insert()?;
                let payload_at = src.payload_at();
                self.apply_designated_insert(&plan, id, field, payload_at, src.payload_len);
                self.row_mut(source.0).set_deleted();
                self.mark_dirty(source.0);
                Ok(Handle(id))
            }
    };
    (@1s_subtree_dirt plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Debug re-derivation of the dirty witness from first
            /// principles: the row's own edit state, or a dirty direct
            /// kid. One level suffices — the save walk visits rows top
            /// down, so induction covers the depth.
            #[cfg(debug_assertions)]
            fn subtree_dirt(&self, row: &Row) -> bool {
                if !matches!(row.base(), Base::Intact) || row.deleted() {
                    return true;
                }
                let mut cur = row.kid;
                while let Some(id) = cur {
                    let kid = self.row(id);
                    if kid.dirty() {
                        return true;
                    }
                    cur = kid.next;
                }
                false
            }
    };
    (@1s_subtree_dirt $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Debug re-derivation of the dirty witness from first
            /// principles: the row's own edit state, or a dirty direct
            /// kid. One level suffices — the save walk visits rows top
            /// down, so induction covers the depth.
            #[cfg(debug_assertions)]
            fn subtree_dirt(&self, row: &Row) -> bool {
                if !matches!(row.base(), Base::Intact) || row.deleted() {
                    return true;
                }
                let mut cur = row.kid;
                while let Some(id) = cur {
                    let kid = self.row(id);
                    // A clean transfer root is a splice all the same: its
                    // span sits elsewhere in the source, so the parent's
                    // subtree cannot tile its own span.
                    if kid.dirty() || kid.alias_root() {
                        return true;
                    }
                    cur = kid.next;
                }
                false
            }
    };
    (@1s_settle plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The save passes' verdict for one row.
            fn settle(&self, row: &Row) -> Arm {
                #[cfg(debug_assertions)]
                debug_assert_eq!(row.dirty(), self.subtree_dirt(row), "row dirt drift");
                if row.deleted() {
                    return Arm::Skip;
                }
                match row.base() {
                    // A wholly untouched record — scalar or container,
                    // opened or not — tiles one source span: the dirty
                    // bit is the subtree edit witness, so its absence
                    // rides the span verbatim without walking the
                    // interior.
                    Base::Intact if !row.dirty() => Arm::Clean { at: row.start.as_inner(), end: row.span_end() },
                    Base::Intact => match row.kind {
                        RecordKind::Len if row.opened() => {
                            let tag_end = row.start.as_inner() + row.tag_w();
                            Arm::Spine {
                                tag_at: row.start.as_inner(),
                                tag_end,
                                prefix_end: tag_end + row.delim_w(),
                                src_len: row.payload_len.as_inner(),
                                first: row.kid,
                            }
                        }
                        // A dirty Intact row is a container with interior
                        // edits, so the scalar arm here is untouched-only
                        // in practice; it stays for totality.
                        _ => Arm::Clean { at: row.start.as_inner(), end: row.span_end() },
                    },
                    Base::Replaced => {
                        let tag_at = row.start.as_inner();
                        let tag_end = row.start.as_inner() + row.tag_w();
                        match row.kind {
                            RecordKind::Varint => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Varint(self.words.word(WordAt::of_slot(row.value))),
                            },
                            RecordKind::I32 => {
                                #[allow(
                                    clippy::cast_possible_truncation,
                                    reason = "fixed 32-bit words are stored zero-extended"
                                )]
                                #[allow(
                                    clippy::as_conversions,
                                    reason = "the stored word is the value's own bits"
                                )]
                                let bits = self.words.word(WordAt::of_slot(row.value)) as u32;
                                Arm::ReValue { tag_at, tag_end, value: Word::Bits32(bits) }
                            }
                            RecordKind::I64 => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Bits64(self.words.word(WordAt::of_slot(row.value))),
                            },
                            RecordKind::Len => Arm::ReBody {
                                tag_at,
                                tag_end,
                                prefix_end: tag_end + row.delim_w(),
                                src_len: row.payload_len.as_inner(),
                                value: PayloadAt::of_slot(row.value),
                            },
                        }
                    }
                    Base::Inserted => {
                        let head = head_word(row.field, row.kind);
                        match row.kind {
                            RecordKind::Varint => Arm::NewValue {
                                head,
                                value: Word::Varint(self.words.word(WordAt::of_slot(row.value))),
                            },
                            RecordKind::I32 => {
                                #[allow(
                                    clippy::cast_possible_truncation,
                                    reason = "fixed 32-bit words are stored zero-extended"
                                )]
                                #[allow(
                                    clippy::as_conversions,
                                    reason = "the stored word is the value's own bits"
                                )]
                                let bits = self.words.word(WordAt::of_slot(row.value)) as u32;
                                Arm::NewValue { head, value: Word::Bits32(bits) }
                            }
                            RecordKind::I64 => Arm::NewValue {
                                head,
                                value: Word::Bits64(self.words.word(WordAt::of_slot(row.value))),
                            },
                            RecordKind::Len => Arm::NewBody { head, value: PayloadAt::of_slot(row.value) },
                        }
                    }
                }
            }
    };
    (@1s_settle transfer, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The save passes' verdict for one row.
            fn settle(&self, row: &Row) -> Arm {
                #[cfg(debug_assertions)]
                debug_assert_eq!(row.dirty(), self.subtree_dirt(row), "row dirt drift");
                if row.deleted() {
                    return Arm::Skip;
                }
                match row.base() {
                    // A wholly untouched record — scalar or container,
                    // opened or not — tiles one source span: the dirty
                    // bit is the subtree edit witness, so its absence
                    // rides the span verbatim without walking the
                    // interior.
                    Base::Intact if !row.dirty() => Arm::Clean { at: row.start.as_inner(), end: row.span_end() },
                    Base::Intact => match row.kind {
                        RecordKind::Len if row.opened() => {
                            let tag_end = row.start.as_inner() + row.tag_w();
                            Arm::Spine {
                                tag_at: row.start.as_inner(),
                                tag_end,
                                prefix_end: tag_end + row.delim_w(),
                                src_len: row.payload_len.as_inner(),
                                first: row.kid,
                            }
                        }
                        // A dirty Intact row is a container with interior
                        // edits, so the scalar arm here is untouched-only
                        // in practice; it stays for totality.
                        _ => Arm::Clean { at: row.start.as_inner(), end: row.span_end() },
                    },
                    Base::Replaced => {
                        let tag_at = row.start.as_inner();
                        let tag_end = row.start.as_inner() + row.tag_w();
                        match row.kind {
                            RecordKind::Varint => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Varint(self.words.word(WordAt::of_slot(row.value))),
                            },
                            RecordKind::I32 => {
                                #[allow(
                                    clippy::cast_possible_truncation,
                                    reason = "fixed 32-bit words are stored zero-extended"
                                )]
                                #[allow(
                                    clippy::as_conversions,
                                    reason = "the stored word is the value's own bits"
                                )]
                                let bits = self.words.word(WordAt::of_slot(row.value)) as u32;
                                Arm::ReValue { tag_at, tag_end, value: Word::Bits32(bits) }
                            }
                            RecordKind::I64 => Arm::ReValue {
                                tag_at,
                                tag_end,
                                value: Word::Bits64(self.words.word(WordAt::of_slot(row.value))),
                            },
                            RecordKind::Len => Arm::ReBody {
                                tag_at,
                                tag_end,
                                prefix_end: tag_end + row.delim_w(),
                                src_len: row.payload_len.as_inner(),
                                value: PayloadAt::of_slot(row.value),
                            },
                        }
                    }
                    Base::Src => match row.src_value() {
                        // A clean import emits its slot's exact bytes
                        // whole; interior edits walk the first-class rows
                        // instead, re-deriving the prefix from the walked
                        // body while the slot tag rides verbatim.
                        SrcValue::Imported(value) => {
                            if row.opened() && row.dirty() {
                                let bytes = self.import_slot(value);
                                let at = import_value_at(bytes);
                                match slice::len_word(bytes, at, bytes.len()) {
                                    Ok((len, width)) => {
                                        let tag_end = admitted_u32(at);
                                        Arm::ImportSpine {
                                            tag_at: 0,
                                            tag_end,
                                            prefix_end: tag_end + u32::from(width),
                                            src_len: len.as_inner(),
                                            value,
                                            first: row.kid,
                                        }
                                    }
                                    Err(_) => unreachable!(
                                        "imported records are structurally complete"
                                    ),
                                }
                            } else {
                                Arm::Import { value }
                            }
                        }
                        SrcValue::PayloadRe(src) => {
                            let source = self.row(src);
                            let tag_end = row.start.as_inner() + row.tag_w();
                            Arm::ReSrcBody {
                                tag_at: row.start.as_inner(),
                                tag_end,
                                prefix_end: tag_end + row.delim_w(),
                                src_len: row.payload_len.as_inner(),
                                at: source.payload_at().as_inner(),
                                len: source.payload_len.as_inner(),
                            }
                        }
                        SrcValue::PayloadNew => Arm::NewSrcBody {
                            head: head_word(row.field, RecordKind::Len),
                            at: row.start.as_inner(),
                            len: row.payload_len.as_inner(),
                        },
                    },
                    Base::Inserted => {
                        let head = head_word(row.field, row.kind);
                        match row.kind {
                            RecordKind::Varint => Arm::NewValue {
                                head,
                                value: Word::Varint(self.words.word(WordAt::of_slot(row.value))),
                            },
                            RecordKind::I32 => {
                                #[allow(
                                    clippy::cast_possible_truncation,
                                    reason = "fixed 32-bit words are stored zero-extended"
                                )]
                                #[allow(
                                    clippy::as_conversions,
                                    reason = "the stored word is the value's own bits"
                                )]
                                let bits = self.words.word(WordAt::of_slot(row.value)) as u32;
                                Arm::NewValue { head, value: Word::Bits32(bits) }
                            }
                            RecordKind::I64 => Arm::NewValue {
                                head,
                                value: Word::Bits64(self.words.word(WordAt::of_slot(row.value))),
                            },
                            RecordKind::Len => Arm::NewBody { head, value: PayloadAt::of_slot(row.value) },
                        }
                    }
                }
            }
    };
    (@1s_size_emit plain $acc:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The size pass over one dirty subtree: accumulates the
            /// root's rewritten size bottom-up, recording every opened
            /// LEN's body (in walk order) for the emit walk's prefix
            /// decisions. The root takes no sibling step — the fused save
            /// drives the top chain itself and only descends where the
            /// dirty witness says the source span cannot ride verbatim.
            fn size_subtree(&self, root: RowId, bodies: &mut Vec<u32>) -> Result<u64, SaveFault> {
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = Some(root);
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        let Close { slot, prefix_w, src_len, at, tag_w } = frame.close;
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at })?;
                        let body = body.as_inner();
                        bodies[slot] = body;
                        let prefix = if body == src_len { prefix_w.w() } else { encoded_len32(body) };
                        acc += frame.outer + u64::from(tag_w.w()) + u64::from(prefix);
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle(row) {
                        Arm::Skip => {}
                        Arm::Clean { at, end } => acc += u64::from(end - at),
                        Arm::ReValue { tag_at, tag_end, value } => {
                            acc += u64::from(tag_end - tag_at) + u64::from(value.width());
                        }
                        Arm::NewValue { head, value } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(value.width());
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let len = self.payloads.len(value);
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
                        }
                        Arm::NewBody { head, value } => {
                            let len = self.payloads.len(value);
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            let slot = bodies.len();
                            bodies.push(0);
                            let (tag_w, prefix_w) = $crate::editor::groupless::one_shot_machine!(
                                @frame_len_widths $acc, row, tag_at, tag_end, prefix_end
                            );
                            spine.push(SizeFrame {
                                // The root closes the walk; interior
                                // containers step to their sibling.
                                next: if spine.is_empty() { None } else { row.next },
                                outer: acc,
                                close: Close { slot, prefix_w, src_len, at: tag_at, tag_w },
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    // A leaf root is the whole subtree.
                    cur = if spine.is_empty() { None } else { row.next };
                }
                Ok(acc)
            }

            /// The emit walk over one dirty subtree: the size walk's twin,
            /// forward, writing into the shared emitter. Climbing out of
            /// containers follows parent links — the spine is the arena
            /// itself — and the root takes no sibling step.
            fn emit_subtree<O: Out>(
                &self,
                emit: &mut O,
                root: RowId,
                bodies: &[u32],
                body_cursor: &mut usize,
            ) {
                let mut open: Option<RowId> = None;
                let mut cur = Some(root);
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = if container == root { None } else { row.next };
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle(row) {
                        Arm::Skip => {}
                        Arm::Clean { at, end } => emit.verbatim(at, end),
                        Arm::ReValue { tag_at, tag_end, value } => {
                            emit.verbatim(tag_at, tag_end);
                            emit.value(value);
                        }
                        Arm::NewValue { head, value } => {
                            emit.word(head);
                            emit.value(value);
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            emit.verbatim(tag_at, tag_end);
                            let len = self.payloads.len(value);
                            if len == src_len {
                                emit.verbatim(tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(len));
                            }
                            self.payloads.for_each_piece(value, |piece| emit.bytes(piece));
                        }
                        Arm::NewBody { head, value } => {
                            emit.word(head);
                            emit.varint(u64::from(self.payloads.len(value)));
                            self.payloads.for_each_piece(value, |piece| emit.bytes(piece));
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            emit.verbatim(tag_at, tag_end);
                            let body = bodies[*body_cursor];
                            *body_cursor += 1;
                            if body == src_len {
                                emit.verbatim(tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(body));
                            }
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    // A leaf root is the whole subtree.
                    cur = if id == root { None } else { row.next };
                }
            }
    };
    (@1s_size_emit transfer $acc:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The size pass over one dirty subtree: accumulates the
            /// root's rewritten size bottom-up, recording every opened
            /// LEN's body (in walk order) for the emit walk's prefix
            /// decisions. The root takes no sibling step — the fused save
            /// drives the top chain itself and only descends where the
            /// dirty witness says the source span cannot ride verbatim.
            fn size_subtree(&self, root: RowId, bodies: &mut Vec<u32>) -> Result<u64, SaveFault> {
                let mut spine: Vec<SizeFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = Some(root);
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        let Close { slot, prefix_w, src_len, at, tag_w } = frame.close;
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at })?;
                        let body = body.as_inner();
                        bodies[slot] = body;
                        let prefix = if body == src_len { prefix_w.w() } else { encoded_len32(body) };
                        acc += frame.outer + u64::from(tag_w.w()) + u64::from(prefix);
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle(row) {
                        Arm::Skip => {}
                        Arm::Clean { at, end } => acc += u64::from(end - at),
                        Arm::ReValue { tag_at, tag_end, value } => {
                            acc += u64::from(tag_end - tag_at) + u64::from(value.width());
                        }
                        Arm::NewValue { head, value } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(value.width());
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let len = self.payloads.len(value);
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
                        }
                        Arm::NewBody { head, value } => {
                            let len = self.payloads.len(value);
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Import { value } => acc += u64::from(self.payloads.len(value)),
                        Arm::ReSrcBody { tag_at, tag_end, prefix_end, src_len, at: _, len } => {
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            acc += u64::from(tag_end - tag_at) + u64::from(prefix) + u64::from(len);
                        }
                        Arm::NewSrcBody { head, at: _, len } => {
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            let slot = bodies.len();
                            bodies.push(0);
                            let (tag_w, prefix_w) = $crate::editor::groupless::one_shot_machine!(
                                @frame_len_widths $acc, row, tag_at, tag_end, prefix_end
                            );
                            spine.push(SizeFrame {
                                // The root closes the walk; interior
                                // containers step to their sibling.
                                next: if spine.is_empty() { None } else { row.next },
                                outer: acc,
                                close: Close { slot, prefix_w, src_len, at: tag_at, tag_w },
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                        Arm::ImportSpine { tag_at, tag_end, prefix_end, src_len, first, .. } => {
                            let slot = bodies.len();
                            bodies.push(0);
                            #[allow(
                                clippy::cast_possible_truncation,
                                clippy::as_conversions,
                                reason = "framing windows span at most five bytes"
                            )]
                            // SAFETY: the settle measured the slot's met
                            // framing — the tag window from the import's
                            // own admission and the prefix from the
                            // kernel's terminated `len_word` read — both
                            // inside the five-byte window.
                            let (tag_w, prefix_w) = unsafe {
                                (
                                    WordWidth::met_unchecked((tag_end - tag_at) as u8),
                                    WordWidth::met_unchecked((prefix_end - tag_end) as u8),
                                )
                            };
                            spine.push(SizeFrame {
                                next: if spine.is_empty() { None } else { row.next },
                                outer: acc,
                                close: Close { slot, prefix_w, src_len, at: tag_at, tag_w },
                            });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    // A leaf root is the whole subtree.
                    cur = if spine.is_empty() { None } else { row.next };
                }
                Ok(acc)
            }

            /// The emit walk over one dirty subtree: the size walk's twin,
            /// forward, writing into the shared emitter. Climbing out of
            /// containers follows parent links — the spine is the arena
            /// itself — and the root takes no sibling step.
            fn emit_subtree<'s, O: Out<'s>>(
                &'s self,
                emit: &mut O,
                root: RowId,
                bodies: &[u32],
                body_cursor: &mut usize,
            ) {
                let mut open: Option<RowId> = None;
                let mut cur = Some(root);
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = if container == root { None } else { row.next };
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle(row) {
                        Arm::Skip => {}
                        Arm::Clean { at, end } => {
                            emit.verbatim_in(self.zone_of(row), at, end);
                        }
                        Arm::ReValue { tag_at, tag_end, value } => {
                            emit.verbatim_in(self.zone_of(row), tag_at, tag_end);
                            emit.value(value);
                        }
                        Arm::NewValue { head, value } => {
                            emit.word(head);
                            emit.value(value);
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let zone = self.zone_of(row);
                            emit.verbatim_in(zone, tag_at, tag_end);
                            let len = self.payloads.len(value);
                            if len == src_len {
                                emit.verbatim_in(zone, tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(len));
                            }
                            self.payloads.for_each_piece(value, |piece| emit.bytes(piece));
                        }
                        Arm::NewBody { head, value } => {
                            emit.word(head);
                            emit.varint(u64::from(self.payloads.len(value)));
                            self.payloads.for_each_piece(value, |piece| emit.bytes(piece));
                        }
                        Arm::Import { value } => {
                            self.payloads.for_each_piece(value, |piece| emit.bytes(piece));
                        }
                        Arm::ReSrcBody { tag_at, tag_end, prefix_end, src_len, at, len } => {
                            let zone = self.zone_of(row);
                            emit.verbatim_in(zone, tag_at, tag_end);
                            if len == src_len {
                                emit.verbatim_in(zone, tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(len));
                            }
                            emit.verbatim(at, at + len);
                        }
                        Arm::NewSrcBody { head, at, len } => {
                            emit.word(head);
                            emit.varint(u64::from(len));
                            emit.verbatim(at, at + len);
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            let zone = self.zone_of(row);
                            emit.verbatim_in(zone, tag_at, tag_end);
                            let body = bodies[*body_cursor];
                            *body_cursor += 1;
                            if body == src_len {
                                emit.verbatim_in(zone, tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(body));
                            }
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                        Arm::ImportSpine { tag_at, tag_end, prefix_end, src_len, value, first } => {
                            let zone = self.import_slot(value);
                            emit.verbatim_in(zone, tag_at, tag_end);
                            let body = bodies[*body_cursor];
                            *body_cursor += 1;
                            if body == src_len {
                                emit.verbatim_in(zone, tag_end, prefix_end);
                            } else {
                                emit.varint(u64::from(body));
                            }
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    // A leaf root is the whole subtree.
                    cur = if id == root { None } else { row.next };
                }
            }
    };
    (@1s_splice_spans plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Span entries for one dirty splice: the emit walk's twin,
            /// advancing an output cursor instead of bytes. Container
            /// entries open with their start and take their end at
            /// climb-out, when the interior has priced itself.
            fn splice_spans(
                &self,
                root: RowId,
                bodies: &[u32],
                start: u32,
                body_cursor: &mut usize,
                entries: &mut Vec<(Handle, Span)>,
            ) -> u32 {
                let mut out = start;
                // Entry indexes of open containers, patched at climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = Some(root);
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        // SAFETY of the index: every container descent
                        // below pushes one frame, and climbs pair with
                        // descents.
                        let Some(at) = frames.pop() else {
                            unreachable!(concat!($noun, " spans: climb without an open frame"))
                        };
                        entries[at].1 = Span::new(entries[at].1.start(), out);
                        cur = if container == root { None } else { row.next };
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle(row) {
                        Arm::Skip => {}
                        Arm::Clean { at, end } => {
                            self.verbatim_spans(id, out, entries);
                            out += end - at;
                        }
                        Arm::ReValue { tag_at, tag_end, value } => {
                            let len = (tag_end - tag_at) + value.width();
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewValue { head, value } => {
                            let len = encoded_len32(head) + value.width();
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let plen = self.payloads.len(value);
                            let prefix =
                                if plen == src_len { prefix_end - tag_end } else { encoded_len32(plen) };
                            let len = (tag_end - tag_at) + prefix + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewBody { head, value } => {
                            let plen = self.payloads.len(value);
                            let len = encoded_len32(head) + encoded_len32(plen) + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first } => {
                            let body = bodies[*body_cursor];
                            *body_cursor += 1;
                            let prefix =
                                if body == src_len { prefix_end - tag_end } else { encoded_len32(body) };
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += (tag_end - tag_at) + prefix;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = if id == root { None } else { row.next };
                }
                out - start
            }
    };
    (@1s_splice_spans transfer, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Span entries for one dirty splice: the emit walk's twin,
            /// advancing an output cursor instead of bytes. Container
            /// entries open with their start and take their end at
            /// climb-out, when the interior has priced itself.
            fn splice_spans(
                &self,
                root: RowId,
                bodies: &[u32],
                start: u32,
                body_cursor: &mut usize,
                entries: &mut Vec<(Handle, Span)>,
            ) -> u32 {
                let mut out = start;
                // Entry indexes of open containers, patched at climb-out.
                let mut frames: Vec<usize> = Vec::new();
                let mut open: Option<RowId> = None;
                let mut cur = Some(root);
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        // SAFETY of the index: every container descent
                        // below pushes one frame, and climbs pair with
                        // descents.
                        let Some(at) = frames.pop() else {
                            unreachable!(concat!($noun, " spans: climb without an open frame"))
                        };
                        entries[at].1 = Span::new(entries[at].1.start(), out);
                        cur = if container == root { None } else { row.next };
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle(row) {
                        Arm::Skip => {}
                        Arm::Clean { at, end } => {
                            self.verbatim_spans(id, out, entries);
                            out += end - at;
                        }
                        Arm::ReValue { tag_at, tag_end, value } => {
                            let len = (tag_end - tag_at) + value.width();
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewValue { head, value } => {
                            let len = encoded_len32(head) + value.width();
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::ReBody { tag_at, tag_end, prefix_end, src_len, value } => {
                            let plen = self.payloads.len(value);
                            let prefix =
                                if plen == src_len { prefix_end - tag_end } else { encoded_len32(plen) };
                            let len = (tag_end - tag_at) + prefix + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::NewBody { head, value } => {
                            let plen = self.payloads.len(value);
                            let len = encoded_len32(head) + encoded_len32(plen) + plen;
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::Import { value } => {
                            let len = self.payloads.len(value);
                            entries.push((Handle(id), Span::new(out, out + len)));
                            out += len;
                        }
                        Arm::ReSrcBody { tag_at, tag_end, prefix_end, src_len, at: _, len } => {
                            let prefix =
                                if len == src_len { prefix_end - tag_end } else { encoded_len32(len) };
                            let total = (tag_end - tag_at) + prefix + len;
                            entries.push((Handle(id), Span::new(out, out + total)));
                            out += total;
                        }
                        Arm::NewSrcBody { head, at: _, len } => {
                            let total = encoded_len32(head) + encoded_len32(len) + len;
                            entries.push((Handle(id), Span::new(out, out + total)));
                            out += total;
                        }
                        Arm::Spine { tag_at, tag_end, prefix_end, src_len, first }
                        | Arm::ImportSpine { tag_at, tag_end, prefix_end, src_len, first, .. } => {
                            let body = bodies[*body_cursor];
                            *body_cursor += 1;
                            let prefix =
                                if body == src_len { prefix_end - tag_end } else { encoded_len32(body) };
                            frames.push(entries.len());
                            entries.push((Handle(id), Span::new(out, out)));
                            out += (tag_end - tag_at) + prefix;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = if id == root { None } else { row.next };
                }
                out - start
            }
    };
    (@1s_pb_mixed plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The LEN record's current payload bytes (`None`: not a LEN
            /// record, or its pending replacement is scatter-supplied —
            #[doc = concat!(" [`", stringify!($Machine), "::set_payload_parts`]'s pieces concatenate only at")]
            /// the save's gather, so no contiguous borrowed view exists
            /// before it): the pending replacement if one is set, the
            /// scanned payload otherwise — readable even while a resident
            /// descend verdict parks on the record.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Len) {
                    return None;
                }
                match row.base() {
                    // SAFETY: the scan judged the declared payload extent
                    // inside the admitted source.
                    Base::Intact => Some(unsafe {
                        self.source.get_unchecked(
                            usize_of(row.payload_at().as_inner())
                            ..usize_of(row.payload_at().as_inner() + row.payload_len.as_inner()),
                        )
                    }),
                    Base::Replaced | Base::Inserted => {
                        self.payloads.contiguous(PayloadAt::of_slot(row.value))
                    }
                }
            }
    };
    (@1s_pb_mixed transfer, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The LEN record's current payload bytes (`None`: not a LEN
            /// record, or its pending replacement is scatter-supplied —
            #[doc = concat!(" [`", stringify!($Machine), "::set_payload_parts`]'s pieces concatenate only at")]
            /// the save's gather, so no contiguous borrowed view exists
            /// before it): the pending replacement if one is set, the
            /// scanned payload otherwise — readable even while a resident
            /// descend verdict parks on the record.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Len) {
                    return None;
                }
                match row.base() {
                    // SAFETY: the scan judged the declared payload extent
                    // inside the row's admitted zone.
                    Base::Intact => Some(unsafe {
                        self.zone_of(row).get_unchecked(
                            usize_of(row.payload_at().as_inner())
                            ..usize_of(row.payload_at().as_inner() + row.payload_len.as_inner()),
                        )
                    }),
                    Base::Replaced | Base::Inserted => {
                        self.payloads.contiguous(PayloadAt::of_slot(row.value))
                    }
                    Base::Src => match row.src_value() {
                        SrcValue::Imported(value) => Some(self.import_payload(value)),
                        SrcValue::PayloadRe(_) | SrcValue::PayloadNew => {
                            Some(self.designated_bytes(row))
                        }
                    },
                }
            }
    };
    (@1s_sp_mixed plain, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Replaces the LEN record's payload wholesale. The source tag
            /// rides verbatim; the length prefix rides verbatim too when
            /// the new payload keeps the source length, and re-authors
            /// minimally only when the length moved. The payload is
            /// borrowed until the save, where its single copy lands in the
            #[doc = concat!(" output — [`", stringify!($Machine), "::set_payload_copy`] stages a copy instead,")]
            /// for temporaries.
            ///
            /// A record whose interior is open for editing refuses: the
            /// descent was a commitment, and its records' edits would be
            /// silently discarded by a wholesale replacement. A record
            /// with a resident descend fault accepts — replacing a broken
            /// payload is the repair path, and it clears the parked
            /// verdict.
            ///
            /// The payload's interior is the caller's declaration: it lands
            /// as opaque bytes, judged only if an explicit descend later
            /// commits it as a message.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless the record is a LEN,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::OpenedTarget`] when the interior is open,
            /// [`EditFault::PayloadTooLarge`] beyond the length class,
            /// [`EditFault::IndexSpaceExhausted`] when the store's
            #[doc = concat!(" coordinate space is spent. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &$p [u8]) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, payload.len())?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_borrowed(payload).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.payloads.set_borrowed(PayloadAt::of_slot(row.value), payload);
                        row.value
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_sp_mixed $cap:ident, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Replaces the LEN record's payload wholesale. The source tag
            /// rides verbatim; the length prefix rides verbatim too when
            /// the new payload keeps the source length, and re-authors
            /// minimally only when the length moved. The payload is
            /// borrowed until the save, where its single copy lands in the
            #[doc = concat!(" output — [`", stringify!($Machine), "::set_payload_copy`] stages a copy instead,")]
            /// for temporaries.
            ///
            /// A record whose interior is open for editing refuses: the
            /// descent was a commitment, and its records' edits would be
            /// silently discarded by a wholesale replacement. A record
            /// with a resident descend fault accepts — replacing a broken
            /// payload is the repair path, and it clears the parked
            /// verdict.
            ///
            /// The payload's interior is the caller's declaration: it lands
            /// as opaque bytes, judged only if an explicit descend later
            /// commits it as a message.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless the record is a LEN,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::OpenedTarget`] when the interior is open,
            /// [`EditFault::PayloadTooLarge`] beyond the length class,
            /// [`EditFault::IndexSpaceExhausted`] when the store's
            #[doc = concat!(" coordinate space is spent. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &$p [u8]) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, payload.len())?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_borrowed(payload).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.payloads.set_borrowed(PayloadAt::of_slot(row.value), payload);
                        row.value
                    }
                    // A payload command on a transfer-designated record
                    // re-authors it: a replacement designation returns to
                    // an ordinary replacement (its scanned framing kept
                    // riding), imports and authored designations become
                    // ordinary insertions; the old backing stays behind
                    // inert (the commit-only trade).
                    Base::Src => {
                        let at =
                            self.payloads.push_borrowed(payload).ok_or(EditFault::IndexSpaceExhausted)?;
                        let target = self.row_mut(handle.0);
                        match row.src_value() {
                            SrcValue::PayloadRe(_) => target.set_replaced(),
                            SrcValue::Imported(_) | SrcValue::PayloadNew => target.set_inserted(),
                        }
                        at.raw()
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_spc_mixed plain, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            #[doc = concat!(" [`set_payload`](", stringify!($Machine), "::set_payload)'s staging twin: copies")]
            #[doc = concat!(" `payload` into the ", $noun, " at the command, for temporaries")]
            /// that cannot outlive it. Same gates, same save shape; the
            /// interior stays the caller's declaration.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload_copy(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, payload.len())?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_copied(payload).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place; the old
                    // copied extent stays behind inert (commit-only).
                    Base::Replaced | Base::Inserted => {
                        self.payloads
                            .set_copied(PayloadAt::of_slot(row.value), payload)
                            .ok_or(EditFault::IndexSpaceExhausted)?;
                        row.value
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_spc_mixed $cap:ident, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            #[doc = concat!(" [`set_payload`](", stringify!($Machine), "::set_payload)'s staging twin: copies")]
            #[doc = concat!(" `payload` into the ", $noun, " at the command, for temporaries")]
            /// that cannot outlive it. Same gates, same save shape; the
            /// interior stays the caller's declaration.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload_copy(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, payload.len())?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_copied(payload).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place; the old
                    // copied extent stays behind inert (commit-only).
                    Base::Replaced | Base::Inserted => {
                        self.payloads
                            .set_copied(PayloadAt::of_slot(row.value), payload)
                            .ok_or(EditFault::IndexSpaceExhausted)?;
                        row.value
                    }
                    // A payload command on a transfer-designated record
                    // re-authors it: a replacement designation returns to
                    // an ordinary replacement (its scanned framing kept
                    // riding), imports and authored designations become
                    // ordinary insertions; the old backing stays behind
                    // inert (the commit-only trade).
                    Base::Src => {
                        let at =
                            self.payloads.push_copied(payload).ok_or(EditFault::IndexSpaceExhausted)?;
                        let target = self.row_mut(handle.0);
                        match row.src_value() {
                            SrcValue::PayloadRe(_) => target.set_replaced(),
                            SrcValue::Imported(_) | SrcValue::PayloadNew => target.set_inserted(),
                        }
                        at.raw()
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_spp_mixed plain, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            #[doc = concat!(" [`set_payload`](", stringify!($Machine), "::set_payload)'s scatter twin: the")]
            /// payload arrives as borrowed pieces that concatenate behind
            /// one prefix at the save's gather — zero staging copies, and
            /// the pieces stay re-readable (the save may run more than
            /// once). Same gates, same save shape; the length judgment
            /// reads the concatenated length. A scatter-replaced record
            #[doc = concat!(" answers [`", stringify!($Machine), "::payload_bytes`] with `None` (no contiguous")]
            /// view exists before the gather).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload_parts(
                &mut self,
                handle: Handle,
                parts: &$p [&$p [u8]],
            ) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, parts_len_usize(parts))?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_parts(parts).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.payloads.set_parts(PayloadAt::of_slot(row.value), parts);
                        row.value
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_spp_mixed $cap:ident, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            #[doc = concat!(" [`set_payload`](", stringify!($Machine), "::set_payload)'s scatter twin: the")]
            /// payload arrives as borrowed pieces that concatenate behind
            /// one prefix at the save's gather — zero staging copies, and
            /// the pieces stay re-readable (the save may run more than
            /// once). Same gates, same save shape; the length judgment
            /// reads the concatenated length. A scatter-replaced record
            #[doc = concat!(" answers [`", stringify!($Machine), "::payload_bytes`] with `None` (no contiguous")]
            /// view exists before the gather).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload_parts(
                &mut self,
                handle: Handle,
                parts: &$p [&$p [u8]],
            ) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, parts_len_usize(parts))?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_parts(parts).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.payloads.set_parts(PayloadAt::of_slot(row.value), parts);
                        row.value
                    }
                    // A payload command on a transfer-designated record
                    // re-authors it: a replacement designation returns to
                    // an ordinary replacement (its scanned framing kept
                    // riding), imports and authored designations become
                    // ordinary insertions; the old backing stays behind
                    // inert (the commit-only trade).
                    Base::Src => {
                        let at =
                            self.payloads.push_parts(parts).ok_or(EditFault::IndexSpaceExhausted)?;
                        let target = self.row_mut(handle.0);
                        match row.src_value() {
                            SrcValue::PayloadRe(_) => target.set_replaced(),
                            SrcValue::Imported(_) | SrcValue::PayloadNew => target.set_inserted(),
                        }
                        at.raw()
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_pb_borrowed plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The LEN record's current payload bytes (`None`: not a LEN
            /// record, or its pending replacement is scatter-supplied —
            #[doc = concat!(" [`", stringify!($Machine), "::set_payload_parts`]'s pieces concatenate only at")]
            /// the save's gather, so no contiguous borrowed view exists
            /// before it): the pending replacement if one is set, the
            /// scanned payload otherwise — readable even while a resident
            /// descend verdict parks on the record.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Len) {
                    return None;
                }
                match row.base() {
                    // SAFETY: the scan judged the declared payload extent
                    // inside the admitted source.
                    Base::Intact => Some(unsafe {
                        self.source.get_unchecked(
                            usize_of(row.payload_at().as_inner())
                            ..usize_of(row.payload_at().as_inner() + row.payload_len.as_inner()),
                        )
                    }),
                    Base::Replaced | Base::Inserted => {
                        self.payloads.contiguous(PayloadAt::of_slot(row.value))
                    }
                }
            }
    };
    (@1s_pb_borrowed $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The LEN record's current payload bytes (`None`: not a LEN
            /// record, or its pending replacement is scatter-supplied —
            #[doc = concat!(" [`", stringify!($Machine), "::set_payload_parts`]'s pieces concatenate only at")]
            /// the save's gather, so no contiguous borrowed view exists
            /// before it): the pending replacement if one is set, the
            /// scanned payload otherwise — readable even while a resident
            /// descend verdict parks on the record.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Len) {
                    return None;
                }
                match row.base() {
                    // SAFETY: the scan judged the declared payload extent
                    // inside the admitted source.
                    Base::Intact => Some(unsafe {
                        self.source.get_unchecked(
                            usize_of(row.payload_at().as_inner())
                            ..usize_of(row.payload_at().as_inner() + row.payload_len.as_inner()),
                        )
                    }),
                    Base::Replaced | Base::Inserted => {
                        self.payloads.contiguous(PayloadAt::of_slot(row.value))
                    }
                    Base::Src => match row.src_value() {
                        SrcValue::Imported(value) => Some(self.import_payload(value)),
                        SrcValue::PayloadRe(_) | SrcValue::PayloadNew => {
                            Some(self.designated_bytes(row))
                        }
                    },
                }
            }
    };
    (@1s_sp_borrowed plain, mixed: $Mixed:ident, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Replaces the LEN record's payload wholesale. The source tag
            /// rides verbatim; the length prefix rides verbatim too when
            /// the new payload keeps the source length, and re-authors
            /// minimally only when the length moved. The payload is
            /// borrowed until the save, where its single copy lands in the
            #[doc = concat!(" output — the mixed [`", stringify!($Mixed), "`]'s `_copy` twins serve")]
            /// temporaries.
            ///
            /// A record whose interior is open for editing refuses: the
            /// descent was a commitment, and its records' edits would be
            /// silently discarded by a wholesale replacement. A record
            /// with a resident descend fault accepts — replacing a broken
            /// payload is the repair path, and it clears the parked
            /// verdict.
            ///
            /// The payload's interior is the caller's declaration: it lands
            /// as opaque bytes, judged only if an explicit descend later
            /// commits it as a message.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless the record is a LEN,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::OpenedTarget`] when the interior is open,
            /// [`EditFault::PayloadTooLarge`] beyond the length class,
            /// [`EditFault::IndexSpaceExhausted`] when the store's
            #[doc = concat!(" coordinate space is spent. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &$p [u8]) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, payload.len())?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_borrowed(payload).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.payloads.set_borrowed(PayloadAt::of_slot(row.value), payload);
                        row.value
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_sp_borrowed $cap:ident, mixed: $Mixed:ident, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Replaces the LEN record's payload wholesale. The source tag
            /// rides verbatim; the length prefix rides verbatim too when
            /// the new payload keeps the source length, and re-authors
            /// minimally only when the length moved. The payload is
            /// borrowed until the save, where its single copy lands in the
            #[doc = concat!(" output — the mixed [`", stringify!($Mixed), "`]'s `_copy` twins serve")]
            /// temporaries.
            ///
            /// A record whose interior is open for editing refuses: the
            /// descent was a commitment, and its records' edits would be
            /// silently discarded by a wholesale replacement. A record
            /// with a resident descend fault accepts — replacing a broken
            /// payload is the repair path, and it clears the parked
            /// verdict.
            ///
            /// The payload's interior is the caller's declaration: it lands
            /// as opaque bytes, judged only if an explicit descend later
            /// commits it as a message.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless the record is a LEN,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::OpenedTarget`] when the interior is open,
            /// [`EditFault::PayloadTooLarge`] beyond the length class,
            /// [`EditFault::IndexSpaceExhausted`] when the store's
            #[doc = concat!(" coordinate space is spent. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &$p [u8]) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, payload.len())?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_borrowed(payload).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.payloads.set_borrowed(PayloadAt::of_slot(row.value), payload);
                        row.value
                    }
                    // A payload command on a transfer-designated record
                    // re-authors it: a replacement designation returns to
                    // an ordinary replacement (its scanned framing kept
                    // riding), imports and authored designations become
                    // ordinary insertions; the old backing stays behind
                    // inert (the commit-only trade).
                    Base::Src => {
                        let at =
                            self.payloads.push_borrowed(payload).ok_or(EditFault::IndexSpaceExhausted)?;
                        let target = self.row_mut(handle.0);
                        match row.src_value() {
                            SrcValue::PayloadRe(_) => target.set_replaced(),
                            SrcValue::Imported(_) | SrcValue::PayloadNew => target.set_inserted(),
                        }
                        at.raw()
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_spp_borrowed plain, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            #[doc = concat!(" [`set_payload`](", stringify!($Machine), "::set_payload)'s scatter twin: the")]
            /// payload arrives as borrowed pieces that concatenate behind
            /// one prefix at the save's gather — zero staging copies, and
            /// the pieces stay re-readable (the save may run more than
            /// once). Same gates, same save shape; the length judgment
            /// reads the concatenated length. A scatter-replaced record
            #[doc = concat!(" answers [`", stringify!($Machine), "::payload_bytes`] with `None` (no contiguous")]
            /// view exists before the gather).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload_parts(
                &mut self,
                handle: Handle,
                parts: &$p [&$p [u8]],
            ) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, parts_len_usize(parts))?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_parts(parts).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.payloads.set_parts(PayloadAt::of_slot(row.value), parts);
                        row.value
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_spp_borrowed $cap:ident, payload: $p:lifetime, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            #[doc = concat!(" [`set_payload`](", stringify!($Machine), "::set_payload)'s scatter twin: the")]
            /// payload arrives as borrowed pieces that concatenate behind
            /// one prefix at the save's gather — zero staging copies, and
            /// the pieces stay re-readable (the save may run more than
            /// once). Same gates, same save shape; the length judgment
            /// reads the concatenated length. A scatter-replaced record
            #[doc = concat!(" answers [`", stringify!($Machine), "::payload_bytes`] with `None` (no contiguous")]
            /// view exists before the gather).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`].")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload_parts(
                &mut self,
                handle: Handle,
                parts: &$p [&$p [u8]],
            ) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, parts_len_usize(parts))?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_parts(parts).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place: no
                    // growth, no failure edge.
                    Base::Replaced | Base::Inserted => {
                        self.payloads.set_parts(PayloadAt::of_slot(row.value), parts);
                        row.value
                    }
                    // A payload command on a transfer-designated record
                    // re-authors it: a replacement designation returns to
                    // an ordinary replacement (its scanned framing kept
                    // riding), imports and authored designations become
                    // ordinary insertions; the old backing stays behind
                    // inert (the commit-only trade).
                    Base::Src => {
                        let at =
                            self.payloads.push_parts(parts).ok_or(EditFault::IndexSpaceExhausted)?;
                        let target = self.row_mut(handle.0);
                        match row.src_value() {
                            SrcValue::PayloadRe(_) => target.set_replaced(),
                            SrcValue::Imported(_) | SrcValue::PayloadNew => target.set_inserted(),
                        }
                        at.raw()
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_pb_copied plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The LEN record's current payload bytes (`None`: not a LEN
            /// record — every authored payload here is a copied extent,
            /// so a live answer is always contiguous): the pending
            /// replacement if one is set, the
            /// scanned payload otherwise — readable even while a resident
            /// descend verdict parks on the record.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Len) {
                    return None;
                }
                match row.base() {
                    // SAFETY: the scan judged the declared payload extent
                    // inside the admitted source.
                    Base::Intact => Some(unsafe {
                        self.source.get_unchecked(
                            usize_of(row.payload_at().as_inner())
                            ..usize_of(row.payload_at().as_inner() + row.payload_len.as_inner()),
                        )
                    }),
                    Base::Replaced | Base::Inserted => {
                        self.payloads.contiguous(PayloadAt::of_slot(row.value))
                    }
                }
            }
    };
    (@1s_pb_copied $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The LEN record's current payload bytes (`None`: not a LEN
            /// record — every authored payload here is a copied extent,
            /// so a live answer is always contiguous): the pending
            /// replacement if one is set, the
            /// scanned payload otherwise — readable even while a resident
            /// descend verdict parks on the record.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[must_use]
            #[track_caller]
            pub fn payload_bytes(&self, handle: Handle) -> Option<&[u8]> {
                let row = gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Len) {
                    return None;
                }
                match row.base() {
                    // SAFETY: the scan judged the declared payload extent
                    // inside the admitted source.
                    Base::Intact => Some(unsafe {
                        self.source.get_unchecked(
                            usize_of(row.payload_at().as_inner())
                            ..usize_of(row.payload_at().as_inner() + row.payload_len.as_inner()),
                        )
                    }),
                    Base::Replaced | Base::Inserted => {
                        self.payloads.contiguous(PayloadAt::of_slot(row.value))
                    }
                    Base::Src => match row.src_value() {
                        SrcValue::Imported(value) => Some(self.import_payload(value)),
                        SrcValue::PayloadRe(_) | SrcValue::PayloadNew => {
                            Some(self.designated_bytes(row))
                        }
                    },
                }
            }
    };
    (@1s_sp_copied plain, mixed: $Mixed:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Replaces the LEN record's payload wholesale, copying it
            #[doc = concat!(" into the ", $noun, " at the command — temporaries welcome; the")]
            #[doc = concat!(" mixed [`", stringify!($Mixed), "`]'s borrowed default is the")]
            /// zero-staging path. The source tag rides verbatim; the
            /// length prefix rides verbatim too when the new payload
            /// keeps the source length, and re-authors minimally only
            /// when the length moved.
            ///
            /// A record whose interior is open for editing refuses: the
            /// descent was a commitment, and its records' edits would be
            /// silently discarded by a wholesale replacement. A record
            /// with a resident descend fault accepts — replacing a broken
            /// payload is the repair path, and it clears the parked
            /// verdict. The payload's interior is the caller's
            /// declaration: it lands as opaque bytes, judged only if an
            /// explicit descend later commits it as a message.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless the record is a LEN,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::OpenedTarget`] when the interior is open,
            /// [`EditFault::PayloadTooLarge`] beyond the length class,
            /// [`EditFault::IndexSpaceExhausted`] when the store's
            #[doc = concat!(" coordinate space is spent. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, payload.len())?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_copied(payload).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place; the old
                    // copied extent stays behind inert (commit-only).
                    Base::Replaced | Base::Inserted => {
                        self.payloads
                            .set_copied(PayloadAt::of_slot(row.value), payload)
                            .ok_or(EditFault::IndexSpaceExhausted)?;
                        row.value
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_sp_copied $cap:ident, mixed: $Mixed:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// Replaces the LEN record's payload wholesale, copying it
            #[doc = concat!(" into the ", $noun, " at the command — temporaries welcome; the")]
            #[doc = concat!(" mixed [`", stringify!($Mixed), "`]'s borrowed default is the")]
            /// zero-staging path. The source tag rides verbatim; the
            /// length prefix rides verbatim too when the new payload
            /// keeps the source length, and re-authors minimally only
            /// when the length moved.
            ///
            /// A record whose interior is open for editing refuses: the
            /// descent was a commitment, and its records' edits would be
            /// silently discarded by a wholesale replacement. A record
            /// with a resident descend fault accepts — replacing a broken
            /// payload is the repair path, and it clears the parked
            /// verdict. The payload's interior is the caller's
            /// declaration: it lands as opaque bytes, judged only if an
            /// explicit descend later commits it as a message.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless the record is a LEN,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::OpenedTarget`] when the interior is open,
            /// [`EditFault::PayloadTooLarge`] beyond the length class,
            /// [`EditFault::IndexSpaceExhausted`] when the store's
            #[doc = concat!(" coordinate space is spent. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_payload(&mut self, handle: Handle, payload: &[u8]) -> Result<(), EditFault> {
                let row = self.payload_set_gate(handle, payload.len())?;
                let value = match row.base() {
                    Base::Intact => {
                        self.payloads.push_copied(payload).ok_or(EditFault::IndexSpaceExhausted)?.raw()
                    }
                    // Re-sets overwrite the minted slot in place; the old
                    // copied extent stays behind inert (commit-only).
                    Base::Replaced | Base::Inserted => {
                        self.payloads
                            .set_copied(PayloadAt::of_slot(row.value), payload)
                            .ok_or(EditFault::IndexSpaceExhausted)?;
                        row.value
                    }
                    // A payload command on a transfer-designated record
                    // re-authors it: a replacement designation returns to
                    // an ordinary replacement (its scanned framing kept
                    // riding), imports and authored designations become
                    // ordinary insertions; the old backing stays behind
                    // inert (the commit-only trade).
                    Base::Src => {
                        let at =
                            self.payloads.push_copied(payload).ok_or(EditFault::IndexSpaceExhausted)?;
                        let target = self.row_mut(handle.0);
                        match row.src_value() {
                            SrcValue::PayloadRe(_) => target.set_replaced(),
                            SrcValue::Imported(_) | SrcValue::PayloadNew => target.set_inserted(),
                        }
                        at.raw()
                    }
                };
                self.payload_set_commit(handle, value);
                Ok(())
            }
    };
    (@1s_frame_apply plain, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The publishing close: mints or overwrites the slot and
            /// applies the one command.
            fn apply(&mut self) -> Result<Handle, EditFault> {
                match self.op {
                    WriteOp::Set { handle } => {
                        // The gates judged at open; the frame's exclusive
                        // borrow kept the row exactly as they left it.
                        let row = *gate(&self.machine.rows, handle);
                        let value = match row.base() {
                            Base::Intact => self
                                .machine
                                .payloads
                                .stage_finish_push(self.mark)
                                .ok_or(EditFault::IndexSpaceExhausted)?
                                .raw(),
                            // Re-sets overwrite the minted slot in place;
                            // the old extent stays behind inert.
                            Base::Replaced | Base::Inserted => {
                                self.machine
                                    .payloads
                                    .stage_finish_set(PayloadAt::of_slot(row.value), self.mark);
                                row.value
                            }
                        };
                        self.machine.payload_set_commit(handle, value);
                        Ok(handle)
                    }
                    WriteOp::Insert { plan, field } => {
                        let id = self.machine.mint_insert()?;
                        let value = self
                            .machine
                            .payloads
                            .stage_finish_push(self.mark)
                            .ok_or(EditFault::IndexSpaceExhausted)?;
                        self.machine.apply_insert(&plan, id, field, RecordKind::Len, value.raw());
                        Ok(Handle(id))
                    }
                }
            }
    };
    (@1s_frame_apply $cap:ident, $Machine:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]) => {
            /// The publishing close: mints or overwrites the slot and
            /// applies the one command.
            fn apply(&mut self) -> Result<Handle, EditFault> {
                match self.op {
                    WriteOp::Set { handle } => {
                        // The gates judged at open; the frame's exclusive
                        // borrow kept the row exactly as they left it.
                        let row = *gate(&self.machine.rows, handle);
                        let value = match row.base() {
                            Base::Intact => self
                                .machine
                                .payloads
                                .stage_finish_push(self.mark)
                                .ok_or(EditFault::IndexSpaceExhausted)?
                                .raw(),
                            // Re-sets overwrite the minted slot in place;
                            // the old extent stays behind inert.
                            Base::Replaced | Base::Inserted => {
                                self.machine
                                    .payloads
                                    .stage_finish_set(PayloadAt::of_slot(row.value), self.mark);
                                row.value
                            }
                            // A staged set on a transfer-designated
                            // record re-authors it: a replacement
                            // designation returns to an ordinary
                            // replacement, imports and authored
                            // designations become ordinary insertions;
                            // the old backing stays behind inert.
                            Base::Src => {
                                let at = self
                                    .machine
                                    .payloads
                                    .stage_finish_push(self.mark)
                                    .ok_or(EditFault::IndexSpaceExhausted)?;
                                let target = self.machine.row_mut(handle.0);
                                match row.src_value() {
                                    SrcValue::PayloadRe(_) => target.set_replaced(),
                                    SrcValue::Imported(_) | SrcValue::PayloadNew => {
                                        target.set_inserted();
                                    }
                                }
                                at.raw()
                            }
                        };
                        self.machine.payload_set_commit(handle, value);
                        Ok(handle)
                    }
                    WriteOp::Insert { plan, field } => {
                        let id = self.machine.mint_insert()?;
                        let value = self
                            .machine
                            .payloads
                            .stage_finish_push(self.mark)
                            .ok_or(EditFault::IndexSpaceExhausted)?;
                        self.machine.apply_insert(&plan, id, field, RecordKind::Len, value.raw());
                        Ok(Handle(id))
                    }
                }
            }
    };
    (@1s_cloned_alias plain tolerant) => {};
    (@1s_cloned_alias $cap:ident tolerant) => {
            /// A local whole-record copy's row: the source occurrence's
            /// exact geometry under an output-authored identity. The
            /// interior starts opaque — a later explicit descent parses
            /// the retained source-backed bytes.
            const fn cloned_alias(&self, parent: Option<RowId>, next: Option<RowId>) -> Self {
                Self {
                    field: self.field,
                    start: self.start,
                    payload_len: self.payload_len,
                    parent,
                    next,
                    kid: None,
                    value: 0,
                    kind: self.kind,
                    tag_width: self.tag_width,
                    delim_width: self.delim_width,
                    state: BASE_INTACT | ZONE_ALIAS_ROOT,
                }
            }
    };
    (@1s_cloned_alias plain canonical) => {};
    (@1s_cloned_alias $cap:ident canonical) => {
            /// A local whole-record copy's row: the source occurrence's
            /// exact geometry under an output-authored identity. The
            /// interior starts opaque — a later explicit descent parses
            /// the retained source-backed bytes.
            const fn cloned_alias(&self, parent: Option<RowId>, next: Option<RowId>) -> Self {
                Self {
                    field: self.field,
                    start: self.start,
                    payload_len: self.payload_len,
                    parent,
                    next,
                    kid: None,
                    value: 0,
                    kind: self.kind,
                    state: BASE_INTACT | ZONE_ALIAS_ROOT,
                }
            }
    };
    (@canonical_vocab plain tolerant) => {
        /// The canonical walk's verdict for one row: every record in the
        /// materialized commitment closure re-emits with minimal framing,
        /// so no whole-record verbatim arm exists — byte runs ride
        /// verbatim only for fixed-width value bytes and opaque payload
        /// bytes, neither of which contains an emitted varint construct.
        enum CanonicalArm {
            /// Deleted: contributes nothing, subtree included.
            Skip,
            /// Minimal head, then the current word, minimally emitted.
            Varint { head: u32, word: u64 },
            /// Minimal head, then the current four value bytes.
            I32 { head: u32, value: CanonicalValue },
            /// Minimal head, then the current eight value bytes.
            I64 { head: u32, value: CanonicalValue },
            /// Minimal head, minimal prefix for the current payload byte
            /// length, then that payload byte-for-byte: unopened,
            /// faulted, or refused source LENs and every effective
            /// authored payload — the points where the commitment
            /// closure ends.
            OpaqueLen { head: u32, payload: CanonicalPayload },
            /// A source-backed LEN whose interior a successful descend
            /// committed into the closure: its body is walked and the
            /// prefix re-derives from the canonical body total. `at` is
            /// the source offset, for the over-cap fault — in the
            /// coordinate class (the settle holds `row.start` typed),
            /// raw on a layout ground: a coordinate-typed niche here
            /// moves the variant's field order and reshapes the settle
            /// bodies.
            OpenLen { head: u32, first: Option<RowId>, at: u32 },
        }

        /// Where a canonical fixed-width value's bytes come from.
        #[derive(Clone, Copy)]
        enum CanonicalValue {
            /// The source value bytes at this offset, copied verbatim
            /// (in the coordinate class, minted by `payload_at`).
            Doc { at: Coord },
            /// The store word, through the existing bit emitter.
            Store(Word),
        }

        /// Where a canonical opaque payload's bytes come from. The
        /// `Doc` pair names the payload subspan of the row's zone;
        /// both ends live in the coordinate class (the producers hold
        /// the typed proof), and both stay raw words on a layout
        /// ground: a coordinate-typed `at` hands the enum a niche and
        /// repacks it from 12 to 8 bytes, reshaping every settle and
        /// emit body.
        #[derive(Clone, Copy)]
        enum CanonicalPayload {
            /// The source payload extent, copied verbatim.
            Doc { at: u32, len: u32 },
            /// The authored payload store slot.
            Store(PayloadAt),
        }

        /// One frame of the canonical sizing walk's container spine: an
        /// opened LEN waiting on its canonical body total.
        struct CanonicalFrame {
            /// Where the walk resumes after the close.
            next: Option<RowId>,
            /// The enclosing accumulator, restored at close.
            outer: u64,
            /// The LEN's minimal head word.
            head: u32,
            /// The body's slot in the size table.
            slot: usize,
            /// Source offset, for the over-cap fault — in the
            /// coordinate class, raw on a layout ground: a
            /// coordinate-typed niche here reorders the frame's
            /// fields and reshapes the sizing bodies.
            at: u32,
        }
    };
    (@canonical_vocab plain canonical) => {};
    (@canonical_vocab $cap:ident tolerant) => {
        /// The canonical walk's verdict for one row: every record in the
        /// materialized commitment closure re-emits with minimal framing,
        /// so no whole-record verbatim arm exists — byte runs ride
        /// verbatim only for fixed-width value bytes and opaque payload
        /// bytes, neither of which contains an emitted varint construct.
        enum CanonicalArm {
            /// Deleted: contributes nothing, subtree included.
            Skip,
            /// Minimal head, then the current word, minimally emitted.
            Varint { head: u32, word: u64 },
            /// Minimal head, then the current four value bytes.
            I32 { head: u32, value: CanonicalValue },
            /// Minimal head, then the current eight value bytes.
            I64 { head: u32, value: CanonicalValue },
            /// Minimal head, minimal prefix for the current payload byte
            /// length, then that payload byte-for-byte: unopened,
            /// faulted, or refused source LENs and every effective
            /// authored payload — the points where the commitment
            /// closure ends.
            OpaqueLen { head: u32, payload: CanonicalPayload },
            /// A source-backed LEN whose interior a successful descend
            /// committed into the closure: its body is walked and the
            /// prefix re-derives from the canonical body total. `at` is
            /// the source offset, for the over-cap fault — in the
            /// coordinate class (the settle holds `row.start` typed),
            /// raw on a layout ground: a coordinate-typed niche here
            /// moves the variant's field order and reshapes the settle
            /// bodies.
            OpenLen { head: u32, first: Option<RowId>, at: u32 },
        }

        /// Where a canonical fixed-width value's bytes come from.
        #[derive(Clone, Copy)]
        enum CanonicalValue {
            /// The source value bytes at this offset, copied verbatim
            /// (in the coordinate class, minted by `payload_at`).
            Doc { at: Coord },
            /// The store word, through the existing bit emitter.
            Store(Word),
        }

        /// Where a canonical opaque payload's bytes come from. The
        /// `Doc` pair names the payload subspan of the row's zone;
        /// both ends live in the coordinate class (the producers hold
        /// the typed proof), and both stay raw words on a layout
        /// ground: a coordinate-typed `at` hands the enum a niche and
        /// repacks it from 12 to 8 bytes, reshaping every settle and
        /// emit body.
        #[derive(Clone, Copy)]
        enum CanonicalPayload {
            /// The source payload extent, copied verbatim.
            Doc { at: u32, len: u32 },
            /// The authored payload store slot.
            Store(PayloadAt),
            /// The payload subspan of an imported record's slot: the
            /// interior rides byte-exact behind re-derived framing.
            Import(PayloadAt),
        }

        /// One frame of the canonical sizing walk's container spine: an
        /// opened LEN waiting on its canonical body total.
        struct CanonicalFrame {
            /// Where the walk resumes after the close.
            next: Option<RowId>,
            /// The enclosing accumulator, restored at close.
            outer: u64,
            /// The LEN's minimal head word.
            head: u32,
            /// The body's slot in the size table.
            slot: usize,
            /// Source offset, for the over-cap fault — in the
            /// coordinate class, raw on a layout ground: a
            /// coordinate-typed niche here reorders the frame's
            /// fields and reshapes the sizing bodies.
            at: u32,
        }
    };
    (@canonical_vocab $cap:ident canonical) => {};
    // Whether this acceptance's admission already proves every
    // framing word minimal — the canonical proof a designation
    // carries at mint.
    (@mint_proof tolerant) => {
        false
    };
    (@mint_proof canonical) => {
        true
    };
    // The designation's met framing widths, sourced per acceptance:
    // tolerant rows move their stored columns, canonical rows mint
    // the words' own minimal spellings (canonical admission proves
    // met == minimal). The caller has already judged `has_source`.
    (@met_geometry tolerant, $row:ident) => {
        match $row.tag_width {
            Some(tag_w) => (tag_w, $row.delim_width),
            // SAFETY: `has_source` (judged by the caller) is the
            // stored-geometry witness — scanned and cloned rows
            // store their met tag width.
            None => unsafe { core::hint::unreachable_unchecked() },
        }
    };
    (@met_geometry canonical, $row:ident) => {
        (
            WordWidth::minimal_of(head_word($row.field, $row.kind)),
            match $row.kind {
                RecordKind::Len => {
                    Some(WordWidth::minimal_of($row.payload_len.as_inner()))
                }
                RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => None,
            },
        )
    };
    // A spine frame's met framing widths at its push, sourced per
    // acceptance: tolerant rows move their stored columns; canonical
    // rows carry no width columns, so the settle's own windows are
    // re-minted (their spans are the derived framing widths).
    (@frame_len_widths tolerant, $row:ident, $tag_at:ident, $tag_end:ident, $prefix_end:ident) => {
        match ($row.tag_width, $row.delim_width) {
            (Some(tag_w), Some(prefix_w)) => {
                debug_assert!(
                    $tag_end - $tag_at == tag_w.w() && $prefix_end - $tag_end == prefix_w.w(),
                    "the settle's spine windows are the stored met widths"
                );
                (tag_w, prefix_w)
            }
            // SAFETY: the settle frames only geometry-owning LEN rows,
            // whose scan (or clone) birth stored both met width
            // columns.
            _ => unsafe { core::hint::unreachable_unchecked() },
        }
    };
    (@frame_len_widths canonical, $row:ident, $tag_at:ident, $tag_end:ident, $prefix_end:ident) => {{
        #[allow(
            clippy::cast_possible_truncation,
            clippy::as_conversions,
            reason = "framing windows span at most five bytes"
        )]
        // SAFETY: the settle built the windows from the row's own
        // framing (`tag_end = tag_at + tag_w`,
        // `prefix_end = tag_end + delim_w`), and canonical admission
        // pins each width to its word's encoded length — both
        // subtractions land in the five-byte window.
        let widths = unsafe {
            (
                WordWidth::met_unchecked(($tag_end - $tag_at) as u8),
                WordWidth::met_unchecked(($prefix_end - $tag_end) as u8),
            )
        };
        widths
    }};
    // The open-refusal vocabulary rides the buffered doors: a stream
    // cell's machine is minted by its ingest phase's seal alone, so no
    // open judgment — and no fault type for one — exists there.
    (@open_fault buffered, [$noun:literal] [$a_noun:literal]) => {
        #[doc = concat!(" Why ", $a_noun, " refused to open.")]
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum OpenFault {
            /// The source exceeds the coordinate class (`i32::MAX` bytes).
            TooLarge {
                /// The refused source length.
                len: usize,
            },
            /// The root layer violates the wire grammar.
            Wire(Fault),
            #[doc = concat!(" The root layer is lawful wire outside this ", $noun, "'s")]
            /// language or declared bounds.
            Refused(Refusal),
        }

        impl core::fmt::Display for OpenFault {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::TooLarge { len } => {
                        write!(f, "source of {len} bytes exceeds the coordinate class")
                    }
                    Self::Wire(fault) => write!(f, "root layer: {fault}"),
                    Self::Refused(refusal) => write!(f, "root layer: {refusal}"),
                }
            }
        }

        impl core::error::Error for OpenFault {
            #[inline]
            fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
                match self {
                    Self::Wire(fault) => Some(fault),
                    Self::Refused(refusal) => Some(refusal),
                    Self::TooLarge { .. } => None,
                }
            }
        }
    };
    (@open_fault stream, [$noun:literal] [$a_noun:literal]) => {};
    (@refusal tolerant, [$noun:literal]) => {
        #[doc = concat!(" Lawful wire this ", $noun, " refuses: the dialect's capability")]
        /// judgment and the declared depth bound.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Refusal {
            /// A group code: well-formed wire outside this dialect's
            /// language — the capability refusal.
            GroupCode {
                /// Offset of the tag word.
                at: u32,
                /// The field the tag names.
                field: FieldNumber,
                /// The group code bits (3 or 4).
                low3: Low3,
            },
            /// Opening this container would nest past the declared
            /// [`DepthLimit`] bound.
            DepthExceeded {
                /// Offset of the container's head tag.
                at: u32,
                /// The container's field.
                field: FieldNumber,
            },
        }

        impl core::fmt::Display for Refusal {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::GroupCode { at, field, low3 } => write!(
                        f,
                        "tag word at {at} carries group code {} on field {} — outside this dialect",
                        low3.as_inner(),
                        field.as_inner()
                    ),
                    Self::DepthExceeded { at, field } => write!(
                        f,
                        "container of field {} at {at} nests past the declared depth bound",
                        field.as_inner()
                    ),
                }
            }
        }

        impl core::error::Error for Refusal {}
    };
    (@refusal canonical, [$noun:literal]) => {
        #[doc = concat!(" Lawful wire this ", $noun, " refuses: padding outside the")]
        /// canonical-minimal policy, the dialect's capability judgment,
        /// and the declared depth bound.
        #[non_exhaustive]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Refusal {
            /// A tag word wider than its value's own encoding.
            NonMinimalTag {
                /// Offset of the tag word.
                at: u32,
                /// The padded width found.
                width: u8,
            },
            /// A LEN length word wider than its value's own encoding.
            NonMinimalLen {
                /// Offset of the length word.
                at: u32,
                /// The record's field number.
                field: FieldNumber,
                /// The padded width found.
                width: u8,
            },
            /// A varint value wider than its own encoding.
            NonMinimalValue {
                /// Offset of the value.
                at: u32,
                /// The record's field number.
                field: FieldNumber,
                /// The padded width found.
                width: u8,
            },
            /// A group code: well-formed wire outside this dialect's
            /// language — the capability refusal.
            GroupCode {
                /// Offset of the tag word.
                at: u32,
                /// The field the tag names.
                field: FieldNumber,
                /// The group code bits (3 or 4).
                low3: Low3,
            },
            /// Opening this container would nest past the declared
            /// [`DepthLimit`] bound.
            DepthExceeded {
                /// Offset of the container's head tag.
                at: u32,
                /// The container's field.
                field: FieldNumber,
            },
        }

        impl core::fmt::Display for Refusal {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match *self {
                    Self::NonMinimalTag { at, width } => {
                        write!(f, "tag word at {at} is padded to {width} bytes")
                    }
                    Self::NonMinimalLen { at, field, width } => write!(
                        f,
                        "length word of field {} at {at} is padded to {width} bytes",
                        field.as_inner()
                    ),
                    Self::NonMinimalValue { at, field, width } => write!(
                        f,
                        "varint value of field {} at {at} is padded to {width} bytes",
                        field.as_inner()
                    ),
                    Self::GroupCode { at, field, low3 } => write!(
                        f,
                        "tag word at {at} carries group code {} on field {} — outside this dialect",
                        low3.as_inner(),
                        field.as_inner()
                    ),
                    Self::DepthExceeded { at, field } => write!(
                        f,
                        "container of field {} at {at} nests past the declared depth bound",
                        field.as_inner()
                    ),
                }
            }
        }

        impl core::error::Error for Refusal {}
    };
    (@row_struct tolerant) => {
        /// One record row, packed to 32 bytes. The arena is the tree:
        /// parent and sibling links thread it, so every walk in this
        /// module climbs instead of recursing.
        ///
        /// Partition theorem (every span read cites it): a scanned
        /// record's bytes are `tag ⊎ delim ⊎ payload`, pairwise disjoint,
        /// union the whole record — the record span is one formula for all
        /// kinds while the payload's position dispatches on kind. Widths
        /// are stored input facts: tolerant admission accepts padding, and
        /// span arithmetic must reproduce it byte-exactly.
        /// Declaration order fixes the memory order: the coordinate
        /// columns tie with the links on niche size, so the stable
        /// field sort keeps them exactly here.
        #[derive(Clone, Copy)]
        struct Row {
            field: FieldNumber,
            parent: Option<RowId>,
            next: Option<RowId>,
            /// First interior record of an opened container.
            kid: Option<RowId>,
            /// Zone offset of the head tag (the admitted source or an
            /// import slot — both top at the class bound); meaningless
            /// for authored rows (their `tag_width` is `None`).
            start: Coord,
            /// Source payload extent: a LEN's declared length, a varint
            /// value's scanned width, or 4/8 for the fixed kinds.
            /// Meaningless for authored rows.
            payload_len: Extent,
            /// The store coordinate (`Replaced`/`Inserted`), or the
            /// fault-table index under `FLAG_FAULTED`.
            value: u32,
            kind: RecordKind,
            /// The head tag's actual input width; `None` for authored
            /// rows, which have no source geometry.
            tag_width: Option<WordWidth>,
            /// The LEN length prefix's actual input width. `None` for
            /// scalars and authored rows.
            delim_width: Option<WordWidth>,
            /// Packed edit state: base bits, the deleted flag, and the LEN
            /// slot flags.
            state: u8,
        }

        const _: () = assert!(core::mem::size_of::<Option<RowId>>() == 4);
        const _: () = assert!(core::mem::size_of::<Row>() == 32);
    };
    (@row_struct canonical) => {
        /// One record row, packed to 32 bytes. The arena is the tree:
        /// parent and sibling links thread it, so every walk in this
        /// module climbs instead of recursing.
        ///
        /// Partition theorem (every span read cites it): a scanned
        /// record's bytes are `tag ⊎ delim ⊎ payload`, pairwise disjoint,
        /// union the whole record — the record span is one formula for all
        /// kinds while the payload's position dispatches on kind. No
        /// width columns exist: canonical admission proved every framing
        /// word minimal, so widths are pure functions of the stored
        /// facts.
        /// Declaration order fixes the memory order: the coordinate
        /// columns tie with the links on niche size, so the stable
        /// field sort keeps them exactly here.
        #[derive(Clone, Copy)]
        struct Row {
            field: FieldNumber,
            parent: Option<RowId>,
            next: Option<RowId>,
            /// First interior record of an opened container.
            kid: Option<RowId>,
            /// Zone offset of the head tag (the admitted source or an
            /// import slot — both top at the class bound); meaningless
            /// for authored rows (which have no source geometry).
            start: Coord,
            /// Source payload extent: a LEN's declared length, a varint
            /// value's scanned width, or 4/8 for the fixed kinds.
            /// Meaningless for authored rows.
            payload_len: Extent,
            /// The store coordinate (`Replaced`/`Inserted`), or the
            /// fault-table index under `FLAG_FAULTED`.
            value: u32,
            kind: RecordKind,
            /// Packed edit state: base bits, the deleted flag, and the LEN
            /// slot flags.
            state: u8,
        }

        const _: () = assert!(core::mem::size_of::<Option<RowId>>() == 4);
        const _: () = assert!(core::mem::size_of::<Row>() == 32);
    };
    (@row_ctor $cap:ident tolerant) => {
            /// A freshly scanned record.
            const fn scanned(
                field: FieldNumber,
                kind: RecordKind,
                start: Coord,
                payload_len: Extent,
                tag_width: WordWidth,
                delim_width: Option<WordWidth>,
                parent: Option<RowId>,
            ) -> Self {
                Self {
                    field,
                    start,
                    payload_len,
                    parent,
                    next: None,
                    kid: None,
                    value: 0,
                    kind,
                    tag_width: Some(tag_width),
                    delim_width,
                    state: BASE_INTACT,
                }
            }

            /// A command-authored record.
            const fn authored(
                field: FieldNumber,
                kind: RecordKind,
                parent: Option<RowId>,
                next: Option<RowId>,
                value: u32,
            ) -> Self {
                Self {
                    field,
                    start: Coord::MIN,
                    payload_len: Extent::from_width(0),
                    parent,
                    next,
                    kid: None,
                    value,
                    kind,
                    tag_width: None,
                    delim_width: None,
                    state: BASE_INSERTED,
                }
            }

            $crate::editor::groupless::one_shot_machine!(@1s_cloned_alias $cap tolerant);
    };
    (@row_ctor $cap:ident canonical) => {
            /// A freshly scanned record.
            const fn scanned(
                field: FieldNumber,
                kind: RecordKind,
                start: Coord,
                payload_len: Extent,
                parent: Option<RowId>,
            ) -> Self {
                Self {
                    field,
                    start,
                    payload_len,
                    parent,
                    next: None,
                    kid: None,
                    value: 0,
                    kind,
                    state: BASE_INTACT,
                }
            }

            /// A command-authored record.
            const fn authored(
                field: FieldNumber,
                kind: RecordKind,
                parent: Option<RowId>,
                next: Option<RowId>,
                value: u32,
            ) -> Self {
                Self {
                    field,
                    start: Coord::MIN,
                    payload_len: Extent::from_width(0),
                    parent,
                    next,
                    kid: None,
                    value,
                    kind,
                    state: BASE_INSERTED,
                }
            }

            $crate::editor::groupless::one_shot_machine!(@1s_cloned_alias $cap canonical);
    };
    (@row_widths plain tolerant) => {
            /// Stored widths as coordinate-class integers (zero when
            /// absent — every use sits behind a base or kind dispatch that
            /// proves presence).
            const fn tag_w(&self) -> u32 {
                match self.tag_width {
                    Some(w) => w.w(),
                    None => 0,
                }
            }

            const fn delim_w(&self) -> u32 {
                match self.delim_width {
                    Some(w) => w.w(),
                    None => 0,
                }
            }

            /// The scanned-geometry witness: rows minted by a scan carry
            /// their met widths; authored rows never do.
            const fn has_source(&self) -> bool {
                self.tag_width.is_some()
            }
    };
    (@row_widths plain canonical) => {
            /// Derived framing widths as coordinate-class integers (zero
            /// for authored rows, which have no source geometry):
            /// canonical admission proved every framing word minimal, so
            /// each width is its word's own encoded length.
            const fn tag_w(&self) -> u32 {
                if self.has_source() { head_width(self.field, self.kind) } else { 0 }
            }

            const fn delim_w(&self) -> u32 {
                if self.has_source() && matches!(self.kind, RecordKind::Len) {
                    encoded_len32(self.payload_len.as_inner())
                } else {
                    0
                }
            }

            /// The scanned-geometry witness: `Intact` and `Replaced` rows
            /// were minted by a scan and own source bytes; `Inserted`
            /// rows never do.
            const fn has_source(&self) -> bool {
                self.state & BASE_MASK != BASE_INSERTED
            }
    };
    (@row_widths $cap:ident tolerant) => {
            /// Stored widths as coordinate-class integers (zero when
            /// absent — every use sits behind a base or kind dispatch that
            /// proves presence).
            const fn tag_w(&self) -> u32 {
                match self.tag_width {
                    Some(w) => w.w(),
                    None => 0,
                }
            }

            const fn delim_w(&self) -> u32 {
                match self.delim_width {
                    Some(w) => w.w(),
                    None => 0,
                }
            }

            /// The geometry witness: the row's coordinate columns name a
            /// span of the machine's own source (scanned rows and local
            /// whole-record copies alike); authored and imported rows
            /// never do.
            const fn has_geometry(&self) -> bool {
                self.tag_width.is_some()
            }

            /// The public source-identity witness: the row is an
            /// original admitted occurrence. A local whole-record copy
            /// keeps its geometry readable but its identity is
            /// output-authored, so it answers no span, no reverse
            /// lookup, and no designation.
            const fn has_source(&self) -> bool {
                self.has_geometry() && !self.alias()
            }
    };
    (@row_widths $cap:ident canonical) => {
            /// Derived framing widths as coordinate-class integers (zero
            /// for authored rows, which have no source geometry):
            /// canonical admission proved every framing word minimal, so
            /// each width is its word's own encoded length.
            const fn tag_w(&self) -> u32 {
                if self.has_geometry() { head_width(self.field, self.kind) } else { 0 }
            }

            const fn delim_w(&self) -> u32 {
                if self.has_geometry() && matches!(self.kind, RecordKind::Len) {
                    encoded_len32(self.payload_len.as_inner())
                } else {
                    0
                }
            }

            /// The geometry witness: the row's coordinate columns name a
            /// span of the machine's own source. `Intact` and `Replaced`
            /// rows were minted by a scan (local whole-record copies
            /// clone scanned geometry under the same bases); a
            /// replacement designation keeps the scanned framing it
            /// landed on; inserted, imported, and authored-designation
            /// rows never own one.
            const fn has_geometry(&self) -> bool {
                match self.state & BASE_MASK {
                    BASE_INTACT | BASE_REPLACED => true,
                    BASE_INSERTED => false,
                    _ => self.value & SRC_PAYLOAD != 0 && self.value != SRC_PAYLOAD_NEW,
                }
            }

            /// The public source-identity witness: the row is an
            /// original admitted occurrence. A local whole-record copy
            /// keeps its geometry readable but its identity is
            /// output-authored, so it answers no span, no reverse
            /// lookup, and no designation.
            const fn has_source(&self) -> bool {
                self.has_geometry() && !self.alias()
            }
    };
    (@scan tolerant) => {
        /// Scans one flat layer of `bytes[start..end]` into provisional
        /// rows under `parent`. Widths ride onto the rows as scanned;
        /// nothing is re-derived from values. On any halt the caller
        /// discards the provisional tail; nothing here touches published
        /// state.
        fn scan_layer(
            rows: &mut Vec<Row>,
            bytes: &[u8],
            start: u32,
            end: u32,
            parent: Option<RowId>,
        ) -> Result<Option<RowId>, Halt> {
            debug_assert!(usize_of(end) <= bytes.len());
            let extent = usize_of(end);
            let mut first: Option<RowId> = None;
            let mut last: Option<RowId> = None;
            let mut pos = start;
            while pos < end {
                // SAFETY: the extent is bounded by the admitted source
                // slice's length, restated by the debug assertion above.
                let (word, tag_width) = unsafe { slice::tag_word_trusted(bytes, usize_of(pos), extent) }
                    .map_err(|fault| halt_wire(pos, FaultKind::Tag { fault }))?;
                let Some(field) = FieldNumber::from_word(word) else {
                    return Err(halt_wire(pos, FaultKind::FieldZero));
                };
                let value_at = pos + u32::from(tag_width);
                // SAFETY: framing words live in five-byte windows, so the
                // kernel's tag width is in the 1..=5 domain.
                let tag_width = unsafe { WordWidth::met_unchecked(tag_width) };
                let kind = match classify(Low3::from_word(word)) {
                    TagClass::Record(kind) => kind,
                    TagClass::GroupCode => {
                        return Err(Halt::Refused(Refusal::GroupCode {
                            at: pos,
                            field,
                            low3: Low3::from_word(word),
                        }));
                    }
                    TagClass::Unassigned => {
                        return Err(halt_wire(
                            pos,
                            FaultKind::Unassigned { field, low3: Low3::from_word(word) },
                        ));
                    }
                };
                let (payload_len, delim_width, record_end) = match kind {
                    RecordKind::Varint => {
                        // SAFETY: same admitted extent as the tag read above.
                        let (_, width) =
                            unsafe { slice::value64_trusted(bytes, usize_of(value_at), extent) }
                                .map_err(|fault| halt_wire(value_at, FaultKind::Value { field, fault }))?;
                        (Extent::from_width(width), None, value_at + u32::from(width))
                    }
                    RecordKind::I32 | RecordKind::I64 => {
                        let width: u8 = if matches!(kind, RecordKind::I32) { 4 } else { 8 };
                        let need = u32::from(width);
                        let have = end - value_at;
                        if have < need {
                            return Err(halt_wire(value_at, FaultKind::PayloadCut { field, need, have }));
                        }
                        (Extent::from_width(width), None, value_at + need)
                    }
                    RecordKind::Len => {
                        // SAFETY: same admitted extent as the tag read above.
                        let (len, width) =
                            unsafe { slice::len_word_trusted(bytes, usize_of(value_at), extent) }
                                .map_err(|fault| halt_wire(value_at, FaultKind::Len { field, fault }))?;
                        // SAFETY: length prefixes live in five-byte windows.
                        let width = unsafe { WordWidth::met_unchecked(width) };
                        let body = value_at + width.w();
                        if u64::from(body) + u64::from(len.as_inner()) > u64::from(end) {
                            return Err(halt_wire(
                                body,
                                FaultKind::PayloadCut { field, need: len.as_inner(), have: end - body },
                            ));
                        }
                        (Extent::from_len(len), Some(width), body + len.as_inner())
                    }
                };
                let id = mint_row(rows)?;
                match last {
                    Some(prev) => {
                        // SAFETY: `prev` was minted by this scan's push.
                        unsafe { rows.get_unchecked_mut(prev.index()) }.next = Some(id);
                    }
                    None => first = Some(id),
                }
                // SAFETY: the loop guard holds `pos < end`, and every
                // scanned zone (the admitted source, an import slot in
                // the LEN class) tops at the class bound.
                let start = unsafe { Coord::new_unchecked(pos) };
                rows.push(Row::scanned(field, kind, start, payload_len, tag_width, delim_width, parent));
                last = Some(id);
                pos = record_end;
            }
            Ok(first)
        }
    };
    (@scan canonical) => {
        /// The minimal width of a record's head tag.
        const fn head_width(field: FieldNumber, kind: RecordKind) -> u32 {
            encoded_len32(head_word(field, kind))
        }

        /// Scans one flat layer of `bytes[start..end]` into provisional
        /// rows under `parent`, refusing any framing word or varint value
        /// wider than its own encoding — the canonical-minimal gate that
        /// makes every downstream width a pure derivation. On any halt
        /// the caller discards the provisional tail; nothing here touches
        /// published state.
        fn scan_layer(
            rows: &mut Vec<Row>,
            bytes: &[u8],
            start: u32,
            end: u32,
            parent: Option<RowId>,
        ) -> Result<Option<RowId>, Halt> {
            debug_assert!(usize_of(end) <= bytes.len());
            let extent = usize_of(end);
            let mut first: Option<RowId> = None;
            let mut last: Option<RowId> = None;
            let mut pos = start;
            while pos < end {
                // SAFETY: the extent is bounded by the admitted source
                // slice's length, restated by the debug assertion above.
                let (word, tag_width) = unsafe { slice::tag_word_trusted(bytes, usize_of(pos), extent) }
                    .map_err(|fault| halt_wire(pos, FaultKind::Tag { fault }))?;
                if u32::from(tag_width) > encoded_len32(word) {
                    return Err(Halt::Refused(Refusal::NonMinimalTag { at: pos, width: tag_width }));
                }
                let Some(field) = FieldNumber::from_word(word) else {
                    return Err(halt_wire(pos, FaultKind::FieldZero));
                };
                let value_at = pos + u32::from(tag_width);
                let kind = match classify(Low3::from_word(word)) {
                    TagClass::Record(kind) => kind,
                    TagClass::GroupCode => {
                        return Err(Halt::Refused(Refusal::GroupCode {
                            at: pos,
                            field,
                            low3: Low3::from_word(word),
                        }));
                    }
                    TagClass::Unassigned => {
                        return Err(halt_wire(
                            pos,
                            FaultKind::Unassigned { field, low3: Low3::from_word(word) },
                        ));
                    }
                };
                let (payload_len, record_end) = match kind {
                    RecordKind::Varint => {
                        // SAFETY: same admitted extent as the tag read above.
                        let (value, width) =
                            unsafe { slice::value64_trusted(bytes, usize_of(value_at), extent) }
                                .map_err(|fault| halt_wire(value_at, FaultKind::Value { field, fault }))?;
                        if u32::from(width) > encoded_len64(value) {
                            return Err(Halt::Refused(Refusal::NonMinimalValue {
                                at: value_at,
                                field,
                                width,
                            }));
                        }
                        (Extent::from_width(width), value_at + u32::from(width))
                    }
                    RecordKind::I32 | RecordKind::I64 => {
                        let width: u8 = if matches!(kind, RecordKind::I32) { 4 } else { 8 };
                        let need = u32::from(width);
                        let have = end - value_at;
                        if have < need {
                            return Err(halt_wire(value_at, FaultKind::PayloadCut { field, need, have }));
                        }
                        (Extent::from_width(width), value_at + need)
                    }
                    RecordKind::Len => {
                        // SAFETY: same admitted extent as the tag read above.
                        let (len, width) =
                            unsafe { slice::len_word_trusted(bytes, usize_of(value_at), extent) }
                                .map_err(|fault| halt_wire(value_at, FaultKind::Len { field, fault }))?;
                        if u32::from(width) > encoded_len32(len.as_inner()) {
                            return Err(Halt::Refused(Refusal::NonMinimalLen {
                                at: value_at,
                                field,
                                width,
                            }));
                        }
                        let body = value_at + u32::from(width);
                        if u64::from(body) + u64::from(len.as_inner()) > u64::from(end) {
                            return Err(halt_wire(
                                body,
                                FaultKind::PayloadCut { field, need: len.as_inner(), have: end - body },
                            ));
                        }
                        (Extent::from_len(len), body + len.as_inner())
                    }
                };
                let id = mint_row(rows)?;
                match last {
                    Some(prev) => {
                        // SAFETY: `prev` was minted by this scan's push.
                        unsafe { rows.get_unchecked_mut(prev.index()) }.next = Some(id);
                    }
                    None => first = Some(id),
                }
                // SAFETY: the loop guard holds `pos < end`, and every
                // scanned zone (the admitted source, an import slot in
                // the LEN class) tops at the class bound.
                let start = unsafe { Coord::new_unchecked(pos) };
                rows.push(Row::scanned(field, kind, start, payload_len, parent));
                last = Some(id);
                pos = record_end;
            }
            Ok(first)
        }
    };
    (@set_varint tolerant, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {
            /// Replaces the varint record's value. The source tag bytes —
            /// padded or not — still ride verbatim at save; only the value
            /// re-emits, minimally.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless the record is a varint,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::IndexSpaceExhausted`] when the value column's
            #[doc = concat!(" coordinate space is spent. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // Tag padded to two bytes: it still rides verbatim.
            /// let msg = [0x88, 0x00, 0x96, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x88, 0x00, 0x07]);")]
            /// ```
            #[inline]
            #[track_caller]
            pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
                self.set_scalar(handle, RecordKind::Varint, value)
            }
    };
    (@set_varint canonical, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {
            /// Replaces the varint record's value. The source tag bytes
            /// still ride verbatim at save; only the value re-emits,
            /// minimally.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] unless the record is a varint,
            /// [`EditFault::DeletedTarget`] for deleted ones,
            /// [`EditFault::IndexSpaceExhausted`] when the value column's
            #[doc = concat!(" coordinate space is spent. On any `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=150 · varint f2=42; rewrite f1.
            /// let msg = [0x08, 0x96, 0x01, 0x10, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(record, 7).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x08, 0x07, 0x10, 0x2A]);")]
            /// ```
            #[inline]
            #[track_caller]
            pub fn set_varint(&mut self, handle: Handle, value: u64) -> Result<(), EditFault> {
                self.set_scalar(handle, RecordKind::Varint, value)
            }
    };
    (@save_spans tolerant, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {
        $crate::editor::groupless::one_shot_machine!(@save_spans_body [
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=150 (padded) · varint f2=42; delete f2.
            /// let msg = [0x08, 0x96, 0x81, 0x00, 0x10, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            #[doc = concat!(" ", $noun, ".delete(tops[1]).unwrap();")]
            ///
            #[doc = concat!(" let spans = ", $noun, ".save_spans().unwrap();")]
            /// let table: Vec<_> = spans.iter().collect();
            /// assert_eq!(table.len(), 1, "deleted records leave the table");
            /// let (handle, span) = table[0];
            /// assert_eq!(handle, tops[0]);
            /// assert_eq!((span.start(), span.end()), (0, 4));
            /// ```
        ], [$noun], $Machine);
    };
    (@save_spans canonical, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {
        $crate::editor::groupless::one_shot_machine!(@save_spans_body [
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=150 · varint f2=42; delete f2.
            /// let msg = [0x08, 0x96, 0x01, 0x10, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let tops: Vec<_> = ", $noun, ".top().collect();")]
            #[doc = concat!(" ", $noun, ".delete(tops[1]).unwrap();")]
            ///
            #[doc = concat!(" let spans = ", $noun, ".save_spans().unwrap();")]
            /// let table: Vec<_> = spans.iter().collect();
            /// assert_eq!(table.len(), 1, "deleted records leave the table");
            /// let (handle, span) = table[0];
            /// assert_eq!(handle, tops[0]);
            /// assert_eq!((span.start(), span.end()), (0, 3));
            /// ```
        ], [$noun], $Machine);
    };
    (@save_spans_body [$(#[$example:meta])*], [$noun:literal], $Machine:ident) => {
            #[doc = concat!(" The output-order span table of the save this ", $noun, " would")]
            /// emit: every live record — source-endorsed or authored, not
            /// deleted — paired with its whole-record span in the output,
            /// containers enclosing their interiors. One sizing pass runs
            /// first and its priced bodies feed the span walk directly,
            #[doc = concat!(" so the table prices exactly what [`", stringify!($Machine), "::save`]")]
            /// would produce, without emitting a byte.
            ///
            /// Handles do not survive a save-and-reopen; spans do — take a
            /// record's output span here, save, reopen, and the byte
            /// coordinate recovers the record on the other side.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_into`] — the same sizing walk surfaces the")]
            /// same faults.
            ///
            /// # Panics
            ///
            /// If the sizing and span walks disagree — a library bug
            /// caught at the seam.
            ///
            $(#[$example])*
            pub fn save_spans(&self) -> Result<SaveSpans, SaveFault> {
                let (total, bodies) = if self.dirty {
                    self.size_pass()?
                } else {
                    // Admission bounded the source inside the class.
                    (admitted_u32(self.source.len()), Vec::new())
                };
                let mut entries: Vec<(Handle, Span)> = Vec::new();
                let mut cursor = 0;
                let mut out: u32 = 0;
                let mut cur = self.top;
                while let Some(id) = cur {
                    let row = self.row(id);
                    cur = row.next;
                    if row.rides_verbatim() {
                        self.verbatim_spans(id, out, &mut entries);
                        out += row.span_end() - row.start.as_inner();
                        continue;
                    }
                    if row.deleted() {
                        continue;
                    }
                    out += self.splice_spans(id, &bodies, out, &mut cursor, &mut entries);
                }
                assert!(out == total, concat!($noun, " spans: the span walk covers the priced save"));
                Ok(SaveSpans { entries })
            }
    };
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident<$($lt:lifetime),*> { source: $src:ty }
        capability: $cap:ident,
        payloads: $payloads:ty,
        backing: mixed($Frame:ident, $SizedFrame:ident),
        payload: $p:lifetime,
        tenure: $tenure:ident,
        acceptance: $acc:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal,
        doc_mod: $doc_mod:literal,
        doc_open: $doc_open:literal,
        doc_open_empty: $doc_open_empty:literal,
        doc_recipes: $doc_recipes:literal $(,)?
    ) => {
        $crate::editor::groupless::one_shot_machine!(@struct $(#[$mdoc])* $Machine<$($lt),*> { source: $src } $payloads);
        $crate::editor::groupless::one_shot_machine!(@doors $tenure $acc $Machine<$($lt),*> { source: $src } $payloads, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
        $crate::editor::groupless::one_shot_machine!(@core $cap $acc $Machine<$($lt),*> [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty] [$doc_recipes]);
        $crate::editor::groupless::one_shot_machine!(@payload_mixed $cap $acc $Machine<$($lt),*> payload: $p, frames: ($Frame, $SizedFrame), [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
        $crate::editor::groupless::one_shot_machine!(@frames $cap $acc $Machine<$($lt),*> frames: ($Frame, $SizedFrame), [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
    };
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident<$($lt:lifetime),*> { source: $src:ty }
        capability: $cap:ident,
        payloads: $payloads:ty,
        backing: borrowed(mixed: $Mixed:ident),
        payload: $p:lifetime,
        tenure: $tenure:ident,
        acceptance: $acc:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal,
        doc_mod: $doc_mod:literal,
        doc_open: $doc_open:literal,
        doc_open_empty: $doc_open_empty:literal,
        doc_recipes: $doc_recipes:literal $(,)?
    ) => {
        $crate::editor::groupless::one_shot_machine!(@struct $(#[$mdoc])* $Machine<$($lt),*> { source: $src } $payloads);
        $crate::editor::groupless::one_shot_machine!(@doors $tenure $acc $Machine<$($lt),*> { source: $src } $payloads, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
        $crate::editor::groupless::one_shot_machine!(@core $cap $acc $Machine<$($lt),*> [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty] [$doc_recipes]);
        $crate::editor::groupless::one_shot_machine!(@payload_borrowed $cap $acc $Machine<$($lt),*> payload: $p, mixed: $Mixed, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
    };
    (
        $(#[$mdoc:meta])*
        machine $Machine:ident<$($lt:lifetime),*> { source: $src:ty }
        capability: $cap:ident,
        payloads: $payloads:ty,
        backing: copied(mixed: $Mixed:ident, $Frame:ident, $SizedFrame:ident),
        tenure: $tenure:ident,
        acceptance: $acc:ident,
        noun: $noun:literal,
        a_noun: $a_noun:literal,
        A_noun: $A_noun:literal,
        doc_mod: $doc_mod:literal,
        doc_open: $doc_open:literal,
        doc_open_empty: $doc_open_empty:literal,
        doc_recipes: $doc_recipes:literal $(,)?
    ) => {
        $crate::editor::groupless::one_shot_machine!(@struct $(#[$mdoc])* $Machine<$($lt),*> { source: $src } $payloads);
        $crate::editor::groupless::one_shot_machine!(@doors $tenure $acc $Machine<$($lt),*> { source: $src } $payloads, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
        $crate::editor::groupless::one_shot_machine!(@core $cap $acc $Machine<$($lt),*> [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty] [$doc_recipes]);
        $crate::editor::groupless::one_shot_machine!(@payload_copied $cap $acc $Machine<$($lt),*> mixed: $Mixed, frames: ($Frame, $SizedFrame), [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
        $crate::editor::groupless::one_shot_machine!(@frames $cap $acc $Machine<$($lt),*> frames: ($Frame, $SizedFrame), [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
    };
    (
        @struct $(#[$mdoc:meta])* $Machine:ident<$($lt:lifetime),*> { source: $src:ty } $payloads:ty
    ) => {
        $(#[$mdoc])*
        pub struct $Machine<$($lt),*> {
            source: $src,
            rows: Vec<Row>,
            words: WordStore,
            payloads: $payloads,
            faults: Vec<SlotFault>,
            top: Option<RowId>,
            limit: DepthLimit,
            /// The whole-document edit latch: raised by the first edit and
            /// never lowered (commit-only), so a clean save is one copy of
            /// the source, no walk.
            dirty: bool,
        }
    };
    (
        @doors borrow tolerant $Machine:ident<$($lt:lifetime),*> { source: $src:ty } $payloads:ty, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            /// Borrows and scans `source`: zero bytes are copied, the flat
            /// root layer materializes eagerly, and LEN payloads wait for
            #[doc = concat!(" [`", stringify!($Machine), "::descend`].")]
            ///
            /// # Errors
            ///
            /// [`OpenFault::TooLarge`] beyond the coordinate class
            /// (`i32::MAX` bytes), [`OpenFault::Wire`] when the root layer
            /// violates the wire grammar, and [`OpenFault::Refused`] when
            /// it carries a group code.
            ///
            /// # Examples
            ///
            /// Group codes are well-formed wire outside this dialect — a
            /// refusal, typed apart from grammar faults:
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{OpenFault, ", stringify!($Machine), ", Refusal};")]
            ///
            /// let group = [0x0B, 0x0C];
            /// assert!(matches!(
            #[doc = concat!("     ", stringify!($Machine), "::open(&group, DepthLimit::REFERENCE).err(),")]
            ///     Some(OpenFault::Refused(Refusal::GroupCode { at: 0, .. }))
            /// ));
            /// ```
            pub fn open(source: $src, limit: DepthLimit) -> Result<Self, OpenFault> {
                let len = admit(source.len()).ok_or(OpenFault::TooLarge { len: source.len() })?;
                let mut rows = Vec::new();
                let top = scan_layer(&mut rows, source, 0, len, None).map_err(|halt| match halt {
                    Halt::Wire(fault) => OpenFault::Wire(fault),
                    Halt::Refused(refusal) => OpenFault::Refused(refusal),
                    Halt::Exhausted => {
                        // Every root-scanned record costs at least one
                        // source byte and admission bounds the source at
                        // `i32::MAX`, so a fresh arena cannot leave the
                        // row domain.
                        debug_assert!(false, "root scan exhausted the row domain");
                        // SAFETY: the row-count bound argued above.
                        unsafe { core::hint::unreachable_unchecked() }
                    }
                })?;
                Ok(Self {
                    source,
                    rows,
                    words: WordStore::new(),
                    payloads: <$payloads>::new(),
                    faults: Vec::new(),
                    top,
                    limit,
                    dirty: false,
                })
            }

            /// The borrowed source bytes.
            #[inline]
            #[must_use]
            pub const fn source(&self) -> $src {
                self.source
            }
        }
    };
    (
        @doors own tolerant $Machine:ident<$($lt:lifetime),*> { source: $src:ty } $payloads:ty, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            /// Takes tenure of `source` and scans it: zero bytes are
            /// copied (the buffer moves in), the flat root layer
            /// materializes eagerly, and LEN payloads wait for
            #[doc = concat!(" [`", stringify!($Machine), "::descend`].")]
            ///
            /// # Errors
            ///
            /// The refusal returns the buffer intact beside its fault —
            /// transactional tenure: [`OpenFault::TooLarge`] beyond the
            /// coordinate class (`i32::MAX` bytes), [`OpenFault::Wire`]
            /// when the root layer violates the wire grammar, and
            /// [`OpenFault::Refused`] when it carries a group code.
            ///
            /// # Examples
            ///
            /// Group codes are well-formed wire outside this dialect — a
            /// refusal, typed apart from grammar faults, and the buffer
            /// rides back untouched:
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{", stringify!($Machine), ", OpenFault, Refusal};")]
            ///
            /// let group = vec![0x0B, 0x0C];
            #[doc = concat!(" let Err((back, fault)) = ", stringify!($Machine), "::open(group, DepthLimit::REFERENCE) else {")]
            ///     unreachable!()
            /// };
            /// assert!(matches!(fault, OpenFault::Refused(Refusal::GroupCode { at: 0, .. })));
            /// assert_eq!(back, [0x0B, 0x0C]);
            /// ```
            pub fn open(source: $src, limit: DepthLimit) -> Result<Self, ($src, OpenFault)> {
                let Some(len) = admit(source.len()) else {
                    let len = source.len();
                    return Err((source, OpenFault::TooLarge { len }));
                };
                let mut rows = Vec::new();
                let top = match scan_layer(&mut rows, &source, 0, len, None) {
                    Ok(top) => top,
                    Err(Halt::Wire(fault)) => return Err((source, OpenFault::Wire(fault))),
                    Err(Halt::Refused(refusal)) => return Err((source, OpenFault::Refused(refusal))),
                    Err(Halt::Exhausted) => {
                        // Every root-scanned record costs at least one
                        // source byte and admission bounds the source at
                        // `i32::MAX`, so a fresh arena cannot leave the
                        // row domain.
                        debug_assert!(false, "root scan exhausted the row domain");
                        // SAFETY: the row-count bound argued above.
                        unsafe { core::hint::unreachable_unchecked() }
                    }
                };
                Ok(Self {
                    source,
                    rows,
                    words: WordStore::new(),
                    payloads: <$payloads>::new(),
                    faults: Vec::new(),
                    top,
                    limit,
                    dirty: false,
                })
            }

            /// The adopted source bytes.
            #[inline]
            #[must_use]
            pub fn source(&self) -> &[u8] {
                &self.source
            }

            /// Releases the source buffer — the open door's inverse, zero
            /// copies. Pending edits are discarded with the machine
            /// (commit-only editing stages a plan; only a save publishes
            /// it), and the bytes come back exactly as they moved in.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = vec![0x08, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", stringify!($Machine), "::open(msg, DepthLimit::REFERENCE).unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(first, 7).unwrap(); // staged, never saved")]
            #[doc = concat!(" assert_eq!(", $noun, ".into_source(), [0x08, 0x2A]);")]
            /// ```
            #[inline]
            #[must_use]
            pub fn into_source(self) -> $src {
                self.source
            }
        }
    };
    (
        @doors stream $acc:ident $Machine:ident<$($lt:lifetime),*> { source: $src:ty } $payloads:ty, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            /// The ingested source bytes: every fed chunk, concatenated
            /// in arrival order and sealed at `finish`.
            #[inline]
            #[must_use]
            pub fn source(&self) -> &[u8] {
                &self.source
            }

            /// Releases the source buffer — the ingest doors' inverse,
            /// zero copies. Pending edits are discarded with the machine
            /// (commit-only editing stages a plan; only a save publishes
            /// it), and the bytes come back exactly as the feeds
            /// delivered them.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(first, 7).unwrap(); // staged, never saved")]
            #[doc = concat!(" assert_eq!(", $noun, ".into_source(), [0x08, 0x2A]);")]
            /// ```
            #[inline]
            #[must_use]
            pub fn into_source(self) -> $src {
                self.source
            }
        }
    };
    (
        @doors borrow canonical $Machine:ident<$($lt:lifetime),*> { source: $src:ty } $payloads:ty, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            /// Borrows and scans `source` under canonical-minimal
            /// admission: zero bytes are copied, the flat root layer
            /// materializes eagerly, and LEN payloads wait for
            #[doc = concat!(" [`", stringify!($Machine), "::descend`].")]
            ///
            /// # Errors
            ///
            /// [`OpenFault::TooLarge`] beyond the coordinate class
            /// (`i32::MAX` bytes), [`OpenFault::Wire`] when the root layer
            /// violates the wire grammar, and [`OpenFault::Refused`] when
            /// it carries a group code or padding outside the
            /// canonical-minimal policy.
            ///
            /// # Examples
            ///
            /// Padded framing is lawful wire this machine refuses — a
            /// refusal, typed apart from grammar faults:
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{OpenFault, ", stringify!($Machine), ", Refusal};")]
            ///
            /// // Field 1 varint 1, tag padded to two bytes.
            /// let padded = [0x88, 0x00, 0x01];
            /// assert!(matches!(
            #[doc = concat!("     ", stringify!($Machine), "::open(&padded, DepthLimit::REFERENCE).err(),")]
            ///     Some(OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 }))
            /// ));
            /// ```
            pub fn open(source: $src, limit: DepthLimit) -> Result<Self, OpenFault> {
                let len = admit(source.len()).ok_or(OpenFault::TooLarge { len: source.len() })?;
                let mut rows = Vec::new();
                let top = scan_layer(&mut rows, source, 0, len, None).map_err(|halt| match halt {
                    Halt::Wire(fault) => OpenFault::Wire(fault),
                    Halt::Refused(refusal) => OpenFault::Refused(refusal),
                    Halt::Exhausted => {
                        // Every root-scanned record costs at least one
                        // source byte and admission bounds the source at
                        // `i32::MAX`, so a fresh arena cannot leave the
                        // row domain.
                        debug_assert!(false, "root scan exhausted the row domain");
                        // SAFETY: the row-count bound argued above.
                        unsafe { core::hint::unreachable_unchecked() }
                    }
                })?;
                Ok(Self {
                    source,
                    rows,
                    words: WordStore::new(),
                    payloads: <$payloads>::new(),
                    faults: Vec::new(),
                    top,
                    limit,
                    dirty: false,
                })
            }

            /// The borrowed source bytes.
            #[inline]
            #[must_use]
            pub const fn source(&self) -> $src {
                self.source
            }
        }
    };
    (
        @doors own canonical $Machine:ident<$($lt:lifetime),*> { source: $src:ty } $payloads:ty, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            /// Takes tenure of `source` and scans it under
            /// canonical-minimal admission: zero bytes are copied (the
            /// buffer moves in), the flat root layer materializes
            /// eagerly, and LEN payloads wait for
            #[doc = concat!(" [`", stringify!($Machine), "::descend`].")]
            ///
            /// # Errors
            ///
            /// The refusal returns the buffer intact beside its fault —
            /// transactional tenure: [`OpenFault::TooLarge`] beyond the
            /// coordinate class (`i32::MAX` bytes), [`OpenFault::Wire`]
            /// when the root layer violates the wire grammar, and
            /// [`OpenFault::Refused`] when it carries a group code or
            /// padding outside the canonical-minimal policy.
            ///
            /// # Examples
            ///
            /// Padded framing is lawful wire this machine refuses — a
            /// refusal, typed apart from grammar faults, and the buffer
            /// rides back untouched:
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::{", stringify!($Machine), ", OpenFault, Refusal};")]
            ///
            /// // Field 1 varint 1, tag padded to two bytes.
            /// let padded = vec![0x88, 0x00, 0x01];
            #[doc = concat!(" let Err((back, fault)) = ", stringify!($Machine), "::open(padded, DepthLimit::REFERENCE) else {")]
            ///     unreachable!()
            /// };
            /// assert!(matches!(fault, OpenFault::Refused(Refusal::NonMinimalTag { at: 0, width: 2 })));
            /// assert_eq!(back, [0x88, 0x00, 0x01]);
            /// ```
            pub fn open(source: $src, limit: DepthLimit) -> Result<Self, ($src, OpenFault)> {
                let Some(len) = admit(source.len()) else {
                    let len = source.len();
                    return Err((source, OpenFault::TooLarge { len }));
                };
                let mut rows = Vec::new();
                let top = match scan_layer(&mut rows, &source, 0, len, None) {
                    Ok(top) => top,
                    Err(Halt::Wire(fault)) => return Err((source, OpenFault::Wire(fault))),
                    Err(Halt::Refused(refusal)) => return Err((source, OpenFault::Refused(refusal))),
                    Err(Halt::Exhausted) => {
                        // Every root-scanned record costs at least one
                        // source byte and admission bounds the source at
                        // `i32::MAX`, so a fresh arena cannot leave the
                        // row domain.
                        debug_assert!(false, "root scan exhausted the row domain");
                        // SAFETY: the row-count bound argued above.
                        unsafe { core::hint::unreachable_unchecked() }
                    }
                };
                Ok(Self {
                    source,
                    rows,
                    words: WordStore::new(),
                    payloads: <$payloads>::new(),
                    faults: Vec::new(),
                    top,
                    limit,
                    dirty: false,
                })
            }

            /// The adopted source bytes.
            #[inline]
            #[must_use]
            pub fn source(&self) -> &[u8] {
                &self.source
            }

            /// Releases the source buffer — the open door's inverse, zero
            /// copies. Pending edits are discarded with the machine
            /// (commit-only editing stages a plan; only a save publishes
            /// it), and the bytes come back exactly as they moved in.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = vec![0x08, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", stringify!($Machine), "::open(msg, DepthLimit::REFERENCE).unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(first, 7).unwrap(); // staged, never saved")]
            #[doc = concat!(" assert_eq!(", $noun, ".into_source(), [0x08, 0x2A]);")]
            /// ```
            #[inline]
            #[must_use]
            pub fn into_source(self) -> $src {
                self.source
            }
        }
    };
    (
        @core $cap:ident $acc:ident $Machine:ident<$($lt:lifetime),*> [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal] [$doc_recipes:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            // ── internal row access ──

            /// The private construction snapshot the cross-cell
            /// differential judges compare: row order, links, widths,
            /// value words, edit state, the top anchor, the sealed
            /// depth bound, the dirty latch, and the store and
            /// fault-table sizes. Test-only.
            #[cfg(test)]
            #[allow(
                dead_code,
                reason = "the cross-cell differential judges consume each twin's \
                          snapshot; cells outside those judges keep the face their \
                          shared core emits; expect is unusable here: judge-bearing \
                          cells fulfil the lint and non-judge cells do not, within \
                          one build"
            )]
            pub(crate) fn construction_snapshot(
                &self,
            ) -> (
                Vec<(u32, u32, u32, Option<u32>, Option<u32>, Option<u32>, u32, u8, u32, u32, u8)>,
                Option<u32>,
                (u16, bool, usize, usize, usize),
            ) {
                let rows = self
                    .rows
                    .iter()
                    .map(|row| {
                        (
                            row.field.as_inner(),
                            row.start.as_inner(),
                            row.payload_len.as_inner(),
                            row.parent.map(RowId::as_inner),
                            row.next.map(RowId::as_inner),
                            row.kid.map(RowId::as_inner),
                            row.value,
                            match row.kind {
                                RecordKind::Varint => 0u8,
                                RecordKind::I64 => 1,
                                RecordKind::Len => 2,
                                RecordKind::I32 => 5,
                            },
                            row.tag_w(),
                            row.delim_w(),
                            row.state,
                        )
                    })
                    .collect();
                (
                    rows,
                    self.top.map(RowId::as_inner),
                    (
                        self.limit.as_inner(),
                        self.dirty,
                        self.words.words_len(),
                        self.payloads.slots_len(),
                        self.faults.len(),
                    ),
                )
            }

            /// A gated row by coordinate (every public entry gates first).
            fn row(&self, id: RowId) -> &Row {
                // SAFETY: `id` was gated or minted by this machine, and the
                // arena never shrinks.
                unsafe { self.rows.get_unchecked(id.index()) }
            }

            #[doc = concat!(" Mutable twin of [`", stringify!($Machine), "::row`].")]
            fn row_mut(&mut self, id: RowId) -> &mut Row {
                // SAFETY: as [`Self::row`].
                unsafe { self.rows.get_unchecked_mut(id.index()) }
            }

            /// Containers enclosing a row (its nesting depth).
            fn depth_of(&self, id: RowId) -> u32 {
                let mut depth = 0;
                let mut cur = self.row(id).parent;
                while let Some(parent) = cur {
                    depth += 1;
                    cur = self.row(parent).parent;
                }
                depth
            }

            $crate::editor::groupless::one_shot_machine!(@1s_transfer_readers $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
            $crate::editor::groupless::one_shot_machine!(@1s_zone_of $cap, );

            // ── observation ──

            /// The top layer's records in wire order (deleted records
            /// included — topology is stable, presentation filters).
            #[inline]
            pub fn top(&self) -> Children<'_> {
                Children { rows: &self.rows, cur: self.top }
            }

            /// A descended LEN's records in wire order. Empty for scalars
            /// and for containers whose interior never opened.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn children(&self, handle: Handle) -> Children<'_> {
                Children { rows: &self.rows, cur: gate(&self.rows, handle).kid }
            }

            /// The record's enclosing container, `None` at the top layer.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn parent(&self, handle: Handle) -> Option<Handle> {
                gate(&self.rows, handle).parent.map(Handle)
            }

            /// The record's ancestor chain, innermost container first.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn ancestors(&self, handle: Handle) -> Ancestors<'_> {
                Ancestors { rows: &self.rows, cur: gate(&self.rows, handle).parent }
            }

            /// The record's wire kind.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn kind(&self, handle: Handle) -> RecordKind {
                gate(&self.rows, handle).kind
            }

            /// The record's field number.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn field(&self, handle: Handle) -> FieldNumber {
                gate(&self.rows, handle).field
            }

            $crate::editor::groupless::one_shot_machine!(@1s_status $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            /// The record's whole source span (head tag through its last
            /// byte, at the scanned widths); `None` for authored records,
            /// which have no source geometry.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn span(&self, handle: Handle) -> Option<Span> {
                let row = gate(&self.rows, handle);
                if !row.has_source() {
                    return None;
                }
                Some(Span::new(row.start.as_inner(), row.span_end()))
            }

            /// The narrowest source-backed record whose span contains
            /// `pos` — the coordinate-resolving face (a source offset in,
            /// the owning record out). Descends exactly as far as
            /// containers have been opened: an unopened or faulted LEN
            /// answers as itself. Authored records have no source geometry
            /// and are never named; edit state is not consulted (a deleted
            /// record still owns its source bytes). The walk follows the
            /// materialized sibling chains, so its cost is the chain
            /// lengths along one root-to-leaf path; a resident hex view
            /// wants the session's run-table bisection instead (feature
            /// `session-*`).
            #[must_use]
            pub fn narrowest(&self, pos: u32) -> Option<Handle> {
                let mut best: Option<RowId> = None;
                let mut chain = self.top;
                while let Some(first) = chain {
                    let mut hit: Option<RowId> = None;
                    let mut cursor = Some(first);
                    while let Some(id) = cursor {
                        let row = self.row(id);
                        // Authored rows carry no source geometry: skipped,
                        // not named. Source-backed rows sit in the chain in
                        // scan order — ascending offsets — so the first one
                        // past `pos` ends the layer's scan.
                        if row.has_source() {
                            if row.start.as_inner() > pos {
                                break;
                            }
                            // Paved layers make spans disjoint: at most one
                            // record of the chain contains `pos`.
                            if pos < row.span_end() {
                                hit = Some(id);
                            }
                        }
                        cursor = row.next;
                    }
                    let Some(id) = hit else { break };
                    best = Some(id);
                    chain = self.row(id).kid;
                }
                best.map(Handle)
            }

            /// The record's source geometry, split by role at the scanned
            /// widths; `None` for authored records.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn source_spans(&self, handle: Handle) -> Option<RecordSpans> {
                let row = gate(&self.rows, handle);
                if !row.has_source() {
                    return None;
                }
                let tag = Span::new(row.start.as_inner(), row.start.as_inner() + row.tag_w());
                Some(match row.kind {
                    RecordKind::Varint => {
                        RecordSpans::Varint { tag, value: Span::new(tag.end(), row.span_end()) }
                    }
                    RecordKind::I32 => {
                        RecordSpans::I32 { tag, value: Span::new(tag.end(), row.span_end()) }
                    }
                    RecordKind::I64 => {
                        RecordSpans::I64 { tag, value: Span::new(tag.end(), row.span_end()) }
                    }
                    RecordKind::Len => {
                        let payload_at = row.payload_at().as_inner();
                        RecordSpans::Len {
                            tag,
                            prefix: Span::new(tag.end(), payload_at),
                            payload: Span::new(payload_at, row.span_end()),
                        }
                    }
                })
            }

            /// Designates the record for cross-machine transfer: the
            /// exact source record bytes bound to their proved field,
            /// kind, and framing geometry. The designation names the
            /// original admitted occurrence — a pending value replacement
            /// does not ride, and rows without a live source occurrence
            /// (command-authored or deleted ones) refuse.
            ///
            /// # Errors
            ///
            /// [`Fault::NotSourceBacked`](crate::source::groupless::Fault::NotSourceBacked)
            /// for authored and deleted rows.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[track_caller]
            pub fn record_ref(
                &self,
                handle: Handle,
            ) -> Result<crate::source::groupless::RecordRef<'_>, crate::source::groupless::Fault>
            {
                let row = gate(&self.rows, handle);
                if !row.has_source() || row.deleted() {
                    return Err(crate::source::groupless::Fault::NotSourceBacked);
                }
                let at = usize_of(row.start.as_inner());
                let end = usize_of(row.span_end());
                let (tag_w, delim_w) =
                    $crate::editor::groupless::one_shot_machine!(@met_geometry $acc, row);
                Ok(crate::source::groupless::RecordRef::mint(
                    // SAFETY: scanned spans lie within the admitted source.
                    unsafe { self.source.get_unchecked(at..end) },
                    row.field,
                    row.kind,
                    tag_w,
                    delim_w,
                    row.payload_len.as_inner(),
                    $crate::editor::groupless::one_shot_machine!(@mint_proof $acc),
                ))
            }

            $crate::editor::groupless::one_shot_machine!(@1s_value_reads $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            // ── descent ──

            $crate::editor::groupless::one_shot_machine!(@1s_descend $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            /// Parks a resident verdict on a LEN's record and projects it.
            fn park(&mut self, id: RowId, fault: SlotFault) -> Result<Descent<'_>, EditFault> {
                let index = u32::try_from(self.faults.len()).map_err(|_| EditFault::IndexSpaceExhausted)?;
                self.faults.push(fault);
                let row = self.row_mut(id);
                row.value = index;
                row.set_faulted();
                Ok(project(&self.faults, index))
            }

            // ── replacement ──

            /// Records an edit at `id`: the whole-document latch, the
            /// row's own witness bit, and the ancestor chain's. Monotone
            /// bits stop the walk at the first ancestor already carrying
            /// one — its own ancestors were marked when it was.
            fn mark_dirty(&mut self, id: RowId) {
                self.dirty = true;
                let mut cur = Some(id);
                while let Some(at) = cur {
                    let row = self.row_mut(at);
                    if row.dirty() {
                        break;
                    }
                    row.set_dirty();
                    cur = row.parent;
                }
            }

            $crate::editor::groupless::one_shot_machine!(@1s_set_scalar $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@set_varint $acc, [$noun] [$doc_mod] [$doc_open], $Machine);

            /// Replaces the fixed 32-bit record's value bits.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`], with the fixed 32-bit kind gate.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_i32(&mut self, handle: Handle, bits: u32) -> Result<(), EditFault> {
                self.set_scalar(handle, RecordKind::I32, u64::from(bits))
            }

            /// Replaces the fixed 64-bit record's value bits.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_varint`], with the fixed 64-bit kind gate.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn set_i64(&mut self, handle: Handle, bits: u64) -> Result<(), EditFault> {
                self.set_scalar(handle, RecordKind::I64, bits)
            }

            /// The shared payload-set gates; `Ok` carries the row copy.
            #[track_caller]
            fn payload_set_gate(&self, handle: Handle, len: usize) -> Result<Row, EditFault> {
                let row = *gate(&self.rows, handle);
                if !matches!(row.kind, RecordKind::Len) {
                    return Err(EditFault::KindMismatch { have: row.kind });
                }
                if row.deleted() {
                    return Err(EditFault::DeletedTarget);
                }
                if row.opened() {
                    return Err(EditFault::OpenedTarget);
                }
                if len > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len });
                }
                Ok(row)
            }

            /// The infallible suffix of a payload set: the value slot, the
            /// state flip, the dirty mark.
            fn payload_set_commit(&mut self, handle: Handle, value: u32) {
                let row = self.row_mut(handle.0);
                row.value = value;
                row.clear_faulted();
                if matches!(row.base(), Base::Intact) {
                    row.set_replaced();
                }
                self.mark_dirty(handle.0);
            }

            /// Deletes the record: it vanishes whole at save, subtree
            /// included — interior records and any insertions made inside
            /// them emit nothing. Commit-only: there is no restore.
            ///
            /// # Errors
            ///
            /// [`EditFault::DeletedTarget`] when the record is already
            #[doc = concat!(" deleted. On `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            #[inline]
            #[track_caller]
            pub fn delete(&mut self, handle: Handle) -> Result<(), EditFault> {
                let row = gate(&self.rows, handle);
                if row.deleted() {
                    return Err(EditFault::DeletedTarget);
                }
                self.row_mut(handle.0).set_deleted();
                self.mark_dirty(handle.0);
                Ok(())
            }

            // ── insertion ──

            /// Gates an insertion container; `Ok` carries its row.
            #[track_caller]
            fn container_gate(&self, container: Option<Handle>) -> Result<Option<RowId>, EditFault> {
                let Some(handle) = container else {
                    return Ok(None);
                };
                let row = gate(&self.rows, handle);
                if row.deleted() {
                    return Err(EditFault::DeletedTarget);
                }
                match row.kind {
                    RecordKind::Len => {
                        if $crate::editor::groupless::one_shot_machine!(@1s_container_base $cap, row) {
                            return Err(EditFault::AuthoredPayload);
                        }
                        if row.opened() { Ok(Some(handle.0)) } else { Err(EditFault::TargetUnopened) }
                    }
                    RecordKind::Varint | RecordKind::I32 | RecordKind::I64 => {
                        Err(EditFault::KindMismatch { have: row.kind })
                    }
                }
            }

            /// The first record of a container's chain (the top layer for
            /// `None`).
            fn first_of(&self, parent: Option<RowId>) -> Option<RowId> {
                parent.map_or(self.top, |id| self.row(id).kid)
            }

            /// The last record of a container's chain: a linear walk —
            /// commit-only rows carry no tail anchor, so a tail insertion
            /// pays O(siblings).
            fn tail_of(&self, parent: Option<RowId>) -> Option<RowId> {
                let mut cur = self.first_of(parent)?;
                while let Some(next) = self.row(cur).next {
                    cur = next;
                }
                Some(cur)
            }

            /// Resolves an anchor into a proven splice point.
            #[track_caller]
            fn resolve_anchor(&self, at: InsertAt) -> Result<Plan, EditFault> {
                match at {
                    InsertAt::HeadOf(container) => {
                        Ok(Plan { parent: self.container_gate(container)?, prev: None })
                    }
                    InsertAt::TailOf(container) => {
                        let parent = self.container_gate(container)?;
                        Ok(Plan { parent, prev: self.tail_of(parent) })
                    }
                    InsertAt::After(anchor) => {
                        let row = gate(&self.rows, anchor);
                        Ok(Plan { parent: row.parent, prev: Some(anchor.0) })
                    }
                }
            }

            /// Mints the next row coordinate for an insertion.
            fn mint_insert(&self) -> Result<RowId, EditFault> {
                u32::try_from(self.rows.len())
                    .ok()
                    .and_then(RowId::new)
                    .ok_or(EditFault::IndexSpaceExhausted)
            }

            $crate::editor::groupless::one_shot_machine!(@1s_apply_insert $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@1s_transfer_faces $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            /// Inserts a varint record at the anchor. Anchors name gaps:
            /// the head or tail of a container's chain, or the gap right
            /// after a sibling. Authored records emit minimally at save.
            ///
            /// # Errors
            ///
            /// [`EditFault::KindMismatch`] for a scalar container,
            /// [`EditFault::DeletedTarget`] for a deleted one,
            /// [`EditFault::TargetUnopened`] for an undescended LEN,
            /// [`EditFault::AuthoredPayload`] for a replaced or authored
            /// payload, [`EditFault::IndexSpaceExhausted`] when the row or
            #[doc = concat!(" value domain is spent. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::{DepthLimit, FieldNumber};
            #[doc = concat!(" use ", $doc_mod, "::{InsertAt, ", stringify!($Machine), "};")]
            ///
            /// let msg = [0x08, 0x01];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            /// let field = FieldNumber::new(2).unwrap();
            #[doc = concat!(" ", $noun, ".insert_varint(InsertAt::TailOf(None), field, 5).unwrap();")]
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x08, 0x01, 0x10, 0x05]);")]
            /// ```
            #[inline]
            #[track_caller]
            pub fn insert_varint(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                value: u64,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let value = self.words.push_word(value).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::Varint, value.raw());
                Ok(Handle(id))
            }

            /// Inserts a fixed 32-bit record at the anchor.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[inline]
            #[track_caller]
            pub fn insert_i32(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                bits: u32,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let value = self.words.push_word(u64::from(bits)).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::I32, value.raw());
                Ok(Handle(id))
            }

            /// Inserts a fixed 64-bit record at the anchor.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[inline]
            #[track_caller]
            pub fn insert_i64(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                bits: u64,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let value = self.words.push_word(bits).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::I64, value.raw());
                Ok(Handle(id))
            }

            // ── save ──

            $crate::editor::groupless::one_shot_machine!(@1s_subtree_dirt $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@1s_settle $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@1s_size_emit $cap $acc, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            /// The fused sizing pass: one walk prices the whole save and
            /// keeps every splice's LEN bodies, in walk order, for the
            /// emit and span walks to consume — the priced bodies are
            /// computed exactly once per save.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_into`]: the sizing faults, before any")]
            /// consumer sees a byte.
            fn size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut total: u64 = 0;
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.top;
                while let Some(id) = cur {
                    let row = self.row(id);
                    cur = row.next;
                    if row.rides_verbatim() {
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((row.start.as_inner(), id)),
                        }
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        total += u64::from(self.row(last).span_end() - from);
                    }
                    if row.deleted() {
                        continue;
                    }
                    total += self.size_subtree(id, &mut bodies)?;
                }
                if let Some((from, last)) = run.take() {
                    total += u64::from(self.row(last).span_end() - from);
                }
                let total = u32::try_from(total)
                    .ok()
                    .filter(|n| *n <= PayloadLen::MAX.as_inner())
                    .ok_or(SaveFault::DocOverCap { total })?;
                Ok((total, bodies))
            }

            #[doc = concat!(" The exact byte length [`", stringify!($Machine), "::save_into`] would append,")]
            #[doc = concat!(" without producing bytes: the sizing walk alone. ", $A_noun)]
            /// with no edits answers in O(1): the save is the source.
            #[doc = $doc_recipes]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_into`]: [`SaveFault::BodyOverCap`] when a")]
            /// rewritten LEN body outgrows the length class,
            /// [`SaveFault::DocOverCap`] when the document outgrows the
            /// coordinate class.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x96, 0x01, 0x10, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(first, 7).unwrap();")]
            ///
            #[doc = concat!(" let len = ", $noun, ".save_len().unwrap();")]
            /// let mut out = Vec::with_capacity(len as usize);
            #[doc = concat!(" ", $noun, ".save_into(&mut out).unwrap();")]
            /// assert_eq!((out.len(), out), (len as usize, vec![0x08, 0x07, 0x10, 0x2A]));
            /// ```
            pub fn save_len(&self) -> Result<u32, SaveFault> {
                if !self.dirty {
                    // Admission bounded the source inside the class.
                    return Ok(admitted_u32(self.source.len()));
                }
                let mut bodies: Vec<u32> = Vec::new();
                let mut total: u64 = 0;
                // The same run discipline as the save walk: clean spans
                // tile, so a run prices as one subtraction at its boundary.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.top;
                while let Some(id) = cur {
                    let row = self.row(id);
                    cur = row.next;
                    if row.rides_verbatim() {
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((row.start.as_inner(), id)),
                        }
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        total += u64::from(self.row(last).span_end() - from);
                    }
                    if row.deleted() {
                        continue;
                    }
                    bodies.clear();
                    total += self.size_subtree(id, &mut bodies)?;
                }
                if let Some((from, last)) = run.take() {
                    total += u64::from(self.row(last).span_end() - from);
                }
                u32::try_from(total)
                    .ok()
                    .filter(|n| *n <= PayloadLen::MAX.as_inner())
                    .ok_or(SaveFault::DocOverCap { total })
            }

            #[doc = concat!(" Serializes the ", $noun, "'s current state by appending to `out`")]
            /// — existing content is untouched. Across the crate the
            /// storage decides `save_into`'s delivery, like
            /// `io::Write`: a `Vec` face appends, the fixed-scratch
            /// cells' slice face fills exactly. One fused walk runs over
            /// the top chain: records whose subtree carries no edit ride
            /// the source verbatim (contiguous runs coalesced into single
            /// copies, padded framing included) without their interiors
            /// being walked; each dirty record becomes a splice — a local
            /// bottom-up size walk over just that subtree (LEN prefixes
            /// need their body first), then its emission, then a seam
            /// assert that the two agreed. Replaced records keep their
            /// source tags; LEN prefixes ride verbatim while their body
            /// length is unchanged and re-author minimally when it moved;
            #[doc = concat!(" authored records emit minimally. ", $A_noun, " that never took an")]
            /// edit skips the walk outright: its records tile the source,
            /// so the whole slice rides as one copy (descents are reads
            /// and do not spend the latch). The untouched majority
            /// therefore never pays for the sizing that only edits need,
            /// and the buffer grows only as its own `Vec` policy dictates.
            #[doc = $doc_recipes]
            ///
            #[doc = concat!(" Saving is repeatable: the ", $noun, " is not consumed, and the")]
            /// output is an independent buffer with no tie to machine or
            /// source.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when a rewritten LEN body
            /// outgrows the length class, [`SaveFault::DocOverCap`] when
            /// the document outgrows the coordinate class. On any `Err`,
            /// `out` is restored to its incoming length and content, and
            /// the save may be retried.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// let msg = [0x08, 0x96, 0x01, 0x10, 0x2A];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let first = ", $noun, ".top().next().unwrap();")]
            #[doc = concat!(" ", $noun, ".set_varint(first, 7).unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x07, 0x10, 0x2A]);
            /// ```
            ///
            /// # Panics
            ///
            /// If a splice's size and emit walks disagree on a dirty
            /// subtree — a library bug caught at the seam — or if
            /// appending the output to `out` would overflow the vector's
            /// capacity bounds (an extreme the caller can reach on 32-bit
            /// targets with a near-full buffer).
            pub fn save_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                if !self.dirty {
                    out.extend_from_slice(&self.source);
                    return Ok(());
                }
                let start = out.len();
                let mut emit = Emit { out, src: &self.source, run: None };
                let mut bodies: Vec<u32> = Vec::new();
                // The clean majority costs one mask test and a run-tail
                // update per record: sibling spans tile the source, so a
                // run's geometry is read once at its boundary — the first
                // record's start, the last one's end — never per record.
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.top;
                while let Some(id) = cur {
                    let row = self.row(id);
                    cur = row.next;
                    if row.rides_verbatim() {
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((row.start.as_inner(), id)),
                        }
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        emit.verbatim(from, self.row(last).span_end());
                    }
                    if row.deleted() {
                        continue;
                    }
                    // A dirty record is a splice: its subtree sizes
                    // bottom-up first (LEN prefixes need their body), then
                    // emits, then faces the seam. Splices interrupt source
                    // contiguity, so flushing the pending run here costs
                    // no coalescing that could have happened.
                    bodies.clear();
                    let size = match self.size_subtree(id, &mut bodies) {
                        Ok(size) => size,
                        Err(fault) => {
                            emit.out.truncate(start);
                            return Err(fault);
                        }
                    };
                    emit.flush();
                    let mark = emit.out.len();
                    self.emit_subtree(&mut emit, id, &bodies, &mut 0);
                    emit.flush();
                    // The emit walk writes exactly the bytes the size walk
                    // paid for; a drifted splice is a crate bug, pinned
                    // here.
                    assert!(
                        u64::try_from(emit.out.len() - mark).is_ok_and(|n| n == size),
                        concat!($noun, " save: splice size and emit walks disagree")
                    );
                }
                if let Some((from, last)) = run.take() {
                    emit.verbatim(from, self.row(last).span_end());
                }
                emit.flush();
                // The emitted document must land back inside the
                // coordinate class — anything larger could not be
                // re-admitted by this same scenario.
                let total = emit.out.len() - start;
                if u32::try_from(total).ok().filter(|n| *n <= PayloadLen::MAX.as_inner()).is_none() {
                    emit.out.truncate(start);
                    return Err(SaveFault::DocOverCap { total: total as u64 });
                }
                Ok(())
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_into`] into a fresh `Vec<u8>`.")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_into`].")]
            ///
            /// # Panics
            ///
            /// If a splice's size and emit walks disagree — a library bug
            /// caught at the seam. (The fresh buffer this wrapper
            /// allocates cannot reach the capacity extreme
            /// [`Self::save_into`] documents for caller-supplied ones.)
            #[inline]
            pub fn save(&self) -> Result<Vec<u8>, SaveFault> {
                let mut out = Vec::new();
                self.save_into(&mut out)?;
                Ok(out)
            }

            /// Serializes by handing the save's bytes to `sink` as
            /// borrowed slices, in output order — no output buffer:
            /// verbatim runs pass through as windows of the source,
            /// authored words ride a ten-byte stack window, and the
            #[doc = concat!(" concatenation is exactly [`", stringify!($Machine), "::save`]'s output.")]
            ///
            /// One sizing pass runs first and surfaces every fault — its
            /// priced bodies feed the emit walk directly — so nothing can
            #[doc = concat!(" refuse once the first slice is handed over: stronger than")]
            #[doc = concat!(" [`", stringify!($Machine), "::save_into`]'s restore-on-`Err`, which a sink could")]
            /// not offer.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_into`]; on `Err` the sink has been handed")]
            /// nothing.
            ///
            /// # Panics
            ///
            /// If the sizing and emit walks disagree — a library bug
            /// caught at the seam.
            pub fn save_sink(&self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                if !self.dirty {
                    if !self.source.is_empty() {
                        sink(&self.source);
                    }
                    return Ok(());
                }
                let (total, bodies) = self.size_pass()?;
                let mut emit = SinkEmit { src: &self.source, sink: &mut sink, run: None, written: 0 };
                let mut cursor = 0;
                let mut run: Option<(u32, RowId)> = None;
                let mut cur = self.top;
                while let Some(id) = cur {
                    let row = self.row(id);
                    cur = row.next;
                    if row.rides_verbatim() {
                        match &mut run {
                            Some((_, last)) => *last = id,
                            None => run = Some((row.start.as_inner(), id)),
                        }
                        continue;
                    }
                    if let Some((from, last)) = run.take() {
                        emit.verbatim(from, self.row(last).span_end());
                    }
                    if row.deleted() {
                        continue;
                    }
                    emit.flush();
                    self.emit_subtree(&mut emit, id, &bodies, &mut cursor);
                    emit.flush();
                }
                if let Some((from, last)) = run.take() {
                    emit.verbatim(from, self.row(last).span_end());
                }
                emit.flush();
                assert!(emit.written == u64::from(total), concat!($noun, " save: the sink walk covers the price"));
                Ok(())
            }

            $crate::editor::groupless::one_shot_machine!(@save_spans $acc, [$noun] [$doc_mod] [$doc_open], $Machine);

            /// Span entries for one verbatim subtree: every row shifts by
            /// one delta — the subtree's output position against its
            /// source position — and interiors enumerate in preorder.
            fn verbatim_spans(&self, root: RowId, out: u32, entries: &mut Vec<(Handle, Span)>) {
                let base = self.row(root).start.as_inner();
                let mut cur = Some(root);
                while let Some(id) = cur {
                    let row = self.row(id);
                    entries
                        .push((Handle(id), Span::new(row.start.as_inner() - base + out, row.span_end() - base + out)));
                    cur = row.kid.map_or_else(
                        || {
                            let mut climb = id;
                            loop {
                                if climb == root {
                                    break None;
                                }
                                let done = self.row(climb);
                                if let Some(next) = done.next {
                                    break Some(next);
                                }
                                match done.parent {
                                    Some(parent) => climb = parent,
                                    None => break None,
                                }
                            }
                        },
                        Some,
                    );
                }
            }

            $crate::editor::groupless::one_shot_machine!(@1s_splice_spans $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@canonical $cap $acc, [$noun] [$doc_mod] [$doc_open], $Machine);
        }
    };
    (@canonical $cap:ident canonical, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {};
    (@canonical plain canonical, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {};
    (@canonical plain tolerant, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {
            // ── canonical output ──

            /// The canonical walk's verdict for one row, every value
            /// resolved at judgment time. Stored widths are not output
            /// widths here — they remain the source-geometry proof that
            /// locates each value, prefix, and payload.
            fn settle_canonical(&self, row: &Row) -> CanonicalArm {
                if row.deleted() {
                    return CanonicalArm::Skip;
                }
                let head = head_word(row.field, row.kind);
                match row.base() {
                    Base::Intact => match row.kind {
                        RecordKind::Varint => CanonicalArm::Varint {
                            head,
                            // The start column is read raw to keep the
                            // offset sum in the 32-bit unit: a
                            // range-annotated load would let the backend
                            // widen the add and spend an extra
                            // instruction on this path. It stays a
                            // separate load from the opened-Len arm's
                            // typed read: one shared load would either
                            // carry the range fact into this sum or
                            // launder the raw word back into the
                            // coordinate type there.
                            // SAFETY: the scan judged a terminating
                            // in-class varint at this offset inside the
                            // admitted source, and the stored tag width
                            // binds the offset; `Coord` is
                            // `repr(transparent)` over a `u32`-wide
                            // pattern type, so the raw read yields its
                            // inner integer.
                            word: unsafe {
                                let start = (&raw const row.start).cast::<u32>().read();
                                slice::value64_unchecked(
                                    &self.source,
                                    usize_of(start + row.tag_w()),
                                )
                            },
                        },
                        RecordKind::I32 => CanonicalArm::I32 {
                            head,
                            value: CanonicalValue::Doc { at: row.payload_at() },
                        },
                        RecordKind::I64 => CanonicalArm::I64 {
                            head,
                            value: CanonicalValue::Doc { at: row.payload_at() },
                        },
                        RecordKind::Len => {
                            if row.opened() {
                                CanonicalArm::OpenLen { head, first: row.kid, at: row.start.as_inner() }
                            } else {
                                // Unopened, faulted, or refused: the
                                // payload bytes are a declaration, not
                                // records — the closure ends here even
                                // when they happen to parse.
                                CanonicalArm::OpaqueLen {
                                    head,
                                    payload: CanonicalPayload::Doc {
                                        at: row.payload_at().as_inner(),
                                        len: row.payload_len.as_inner(),
                                    },
                                }
                            }
                        }
                    },
                    Base::Replaced | Base::Inserted => match row.kind {
                        RecordKind::Varint => CanonicalArm::Varint {
                            head,
                            word: self.words.word(WordAt::of_slot(row.value)),
                        },
                        RecordKind::I32 => {
                            #[allow(
                                clippy::cast_possible_truncation,
                                reason = "fixed 32-bit words are stored zero-extended"
                            )]
                            #[allow(
                                clippy::as_conversions,
                                reason = "the stored word is the value's own bits"
                            )]
                            let bits = self.words.word(WordAt::of_slot(row.value)) as u32;
                            CanonicalArm::I32 { head, value: CanonicalValue::Store(Word::Bits32(bits)) }
                        }
                        RecordKind::I64 => CanonicalArm::I64 {
                            head,
                            value: CanonicalValue::Store(Word::Bits64(
                                self.words.word(WordAt::of_slot(row.value)),
                            )),
                        },
                        RecordKind::Len => CanonicalArm::OpaqueLen {
                            head,
                            payload: CanonicalPayload::Store(PayloadAt::of_slot(row.value)),
                        },
                    },
                }
            }

            /// The canonical sizing walk: one complete pass over the
            /// materialized commitment closure, accumulating every
            /// opened LEN's canonical body bottom-up and recording it in
            /// walk order for the emit walk's prefixes. Every live row
            /// is visited — the walk follows visibility, not dirt, so a
            /// clean machine still pays it in full.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class.
            fn canonical_size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<CanonicalFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = self.top;
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at })?;
                        let body = body.as_inner();
                        bodies[frame.slot] = body;
                        acc += frame.outer
                            + u64::from(encoded_len32(frame.head))
                            + u64::from(encoded_len32(body));
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle_canonical(row) {
                        CanonicalArm::Skip => {}
                        CanonicalArm::Varint { head, word } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(encoded_len64(word));
                        }
                        CanonicalArm::I32 { head, .. } => acc += u64::from(encoded_len32(head)) + 4,
                        CanonicalArm::I64 { head, .. } => acc += u64::from(encoded_len32(head)) + 8,
                        CanonicalArm::OpaqueLen { head, payload } => {
                            let len = match payload {
                                CanonicalPayload::Doc { len, .. } => len,
                                CanonicalPayload::Store(value) => self.payloads.len(value),
                            };
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        CanonicalArm::OpenLen { head, first, at } => {
                            let slot = bodies.len();
                            bodies.push(0);
                            spine.push(CanonicalFrame { next: row.next, outer: acc, head, slot, at });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|n| *n <= PayloadLen::MAX.as_inner())
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

            /// The canonical emit walk: the sizing walk's twin, forward,
            /// writing into the shared emitter. Climbing out of opened
            /// LENs follows parent links — the spine is the arena itself.
            /// Returns the count of body slots consumed, for the faces'
            /// seam assertion.
            fn canonical_emit_pass<O: Out>(&self, emit: &mut O, bodies: &[u32]) -> usize {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                let mut cur = self.top;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle_canonical(row) {
                        CanonicalArm::Skip => {}
                        CanonicalArm::Varint { head, word } => {
                            emit.word(head);
                            emit.varint(word);
                        }
                        CanonicalArm::I32 { head, value } => {
                            emit.word(head);
                            match value {
                                CanonicalValue::Doc { at } => {
                                    let at = at.as_inner();
                                    emit.verbatim(at, at + 4);
                                }
                                CanonicalValue::Store(word) => emit.value(word),
                            }
                        }
                        CanonicalArm::I64 { head, value } => {
                            emit.word(head);
                            match value {
                                CanonicalValue::Doc { at } => {
                                    let at = at.as_inner();
                                    emit.verbatim(at, at + 8);
                                }
                                CanonicalValue::Store(word) => emit.value(word),
                            }
                        }
                        CanonicalArm::OpaqueLen { head, payload } => {
                            emit.word(head);
                            match payload {
                                CanonicalPayload::Doc { at, len } => {
                                    emit.varint(u64::from(len));
                                    emit.verbatim(at, at + len);
                                }
                                CanonicalPayload::Store(value) => {
                                    emit.varint(u64::from(self.payloads.len(value)));
                                    self.payloads.for_each_piece(value, |piece| emit.bytes(piece));
                                }
                            }
                        }
                        CanonicalArm::OpenLen { head, first, .. } => {
                            emit.word(head);
                            emit.varint(u64::from(bodies[body_cursor]));
                            body_cursor += 1;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                emit.flush();
                body_cursor
            }

            /// Serializes under the `CanonicalMinimal` output standard
            /// into a fresh, exactly sized `Vec<u8>`: minimally emits
            /// every varint construct in the materialized commitment
            /// closure; opaque LEN payload bytes pass unchanged.
            ///
            /// The commitment closure is the row graph this
            #[doc = concat!(" ", $noun, " already materialized: the root layer, plus each")]
            /// source LEN interior a successful descend committed.
            /// Every head tag, LEN prefix, and varint value inside it
            /// re-emits at its value's own width — padding on kept tags
            /// included — and prefix shrinkage cascades through every
            /// opened LEN ancestor. An unopened, faulted, or refused
            /// LEN payload and every authored payload terminate the
            /// closure and ride byte-for-byte behind re-derived framing,
            /// even when those bytes happen to parse. Values, field
            /// order, duplicates, liveness, and the fixed-width bits are
            /// untouched, as is every observable of this
            #[doc = concat!(" ", $noun, " — the face reads `&self`, sizes call-locally, and")]
            /// caches nothing.
            ///
            /// The ordinary [`save`](Self::save) family answers
            /// byte-fidelity instead; both re-ingest under `Tolerant`,
            /// and this family's output additionally closes under the
            /// dialect validator's `CanonicalMinimal` standard.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class. Canonical totals never exceed fidelity totals, so
            /// a state whose fidelity save is in class cannot fault
            /// here. On `Err` nothing was published.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1 (tag padded to two bytes) · LEN f2 [88 00]
            /// let msg = [0x88, 0x00, 0x01, 0x12, 0x02, 0x88, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $doc_open, ".unwrap();")]
            ///
            /// // Fidelity keeps the padded kept tag; the canonical face
            /// // re-emits it minimally. The undescended payload's bytes
            /// // are a declaration and ride opaque.
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), msg);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save_canonical().unwrap(), [0x08, 0x01, 0x12, 0x02, 0x88, 0x00]);")]
            /// ```
            pub fn save_canonical(&self) -> Result<Vec<u8>, SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut out = Vec::with_capacity(usize_of(total));
                let mut emit = Emit { out: &mut out, src: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && out.len() == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(out)
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s emission appended to `out`")]
            /// — existing content is untouched. The sizing walk runs
            /// first and makes one exact reservation, so the appends
            /// never regrow the buffer.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]. Every fault precedes the")]
            /// reservation and the first write: on `Err`, `out` keeps
            /// its length and content.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam — or if reserving the
            /// output in `out` would overflow the vector's capacity
            /// bounds (an extreme the caller can reach on 32-bit
            /// targets with a near-full buffer).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1, value padded to two bytes.
            /// let msg = [0x08, 0x81, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $doc_open, ".unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_canonical_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x01]);
            /// ```
            pub fn save_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                out.reserve_exact(usize_of(total));
                let start = out.len();
                let mut emit = Emit { out, src: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.out.len() - start == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(())
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s bytes handed to `sink` as")]
            /// borrowed slices, in output order — no output buffer:
            /// opaque payload runs and fixed-width source values pass
            /// through as windows of the source, framing words ride a
            /// ten-byte stack window, and the concatenation is exactly
            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s output.")]
            ///
            /// The sizing walk runs first and surfaces every fault, so
            /// nothing can refuse once the first slice is handed over.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]; on `Err` the sink has been")]
            /// handed nothing.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            pub fn save_canonical_sink(&self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut emit = SinkEmit { src: &self.source, sink: &mut sink, run: None, written: 0 };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.written == u64::from(total),
                    concat!($noun, " canonical save: the sink walk covers the price")
                );
                Ok(())
            }
    };
    (@canonical transfer tolerant, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {
            // ── canonical output ──

            /// The canonical walk's verdict for one row, every value
            /// resolved at judgment time. Stored widths are not output
            /// widths here — they remain the source-geometry proof that
            /// locates each value, prefix, and payload.
            fn settle_canonical(&self, row: &Row) -> CanonicalArm {
                if row.deleted() {
                    return CanonicalArm::Skip;
                }
                let head = head_word(row.field, row.kind);
                match row.base() {
                    Base::Intact => match row.kind {
                        RecordKind::Varint => CanonicalArm::Varint {
                            head,
                            // The start column is read raw to keep the
                            // offset sum in the 32-bit unit: a
                            // range-annotated load would let the backend
                            // widen the add and spend an extra
                            // instruction on this path. It stays a
                            // separate load from the opened-Len arm's
                            // typed read: one shared load would either
                            // carry the range fact into this sum or
                            // launder the raw word back into the
                            // coordinate type there.
                            // SAFETY: the scan judged a terminating
                            // in-class varint at this offset inside the
                            // row's admitted zone, and the stored tag
                            // width binds the offset; `Coord` is
                            // `repr(transparent)` over a `u32`-wide
                            // pattern type, so the raw read yields its
                            // inner integer.
                            word: unsafe {
                                let start = (&raw const row.start).cast::<u32>().read();
                                slice::value64_unchecked(
                                    self.zone_of(row),
                                    usize_of(start + row.tag_w()),
                                )
                            },
                        },
                        RecordKind::I32 => CanonicalArm::I32 {
                            head,
                            value: CanonicalValue::Doc { at: row.payload_at() },
                        },
                        RecordKind::I64 => CanonicalArm::I64 {
                            head,
                            value: CanonicalValue::Doc { at: row.payload_at() },
                        },
                        RecordKind::Len => {
                            if row.opened() {
                                CanonicalArm::OpenLen { head, first: row.kid, at: row.start.as_inner() }
                            } else {
                                // Unopened, faulted, or refused: the
                                // payload bytes are a declaration, not
                                // records — the closure ends here even
                                // when they happen to parse.
                                CanonicalArm::OpaqueLen {
                                    head,
                                    payload: CanonicalPayload::Doc {
                                        at: row.payload_at().as_inner(),
                                        len: row.payload_len.as_inner(),
                                    },
                                }
                            }
                        }
                    },
                    // A designated payload is an opaque declaration at
                    // the destination: minimal head and prefix over the
                    // source subspan.
                    Base::Src if !matches!(row.src_value(), SrcValue::Imported(_)) => {
                        let (at, len) = self.designated_span(row);
                        CanonicalArm::OpaqueLen {
                            head,
                            payload: CanonicalPayload::Doc { at: at.as_inner(), len },
                        }
                    }
                    // An imported record re-emits minimally under the
                    // canonical standard: its met framing is decoded from
                    // the slot, never preserved (the ordinary save's
                    // fidelity is the byte-exact face).
                    Base::Src => {
                        let bytes = self.import_bytes(row);
                        let at = import_value_at(bytes);
                        match row.kind {
                            RecordKind::Varint => CanonicalArm::Varint {
                                head,
                                word: match slice::value64(bytes, at, bytes.len()) {
                                    Ok((value, _)) => value,
                                    Err(_) => {
                                        unreachable!("imported records are structurally complete")
                                    }
                                },
                            },
                            RecordKind::I32 => {
                                let Ok(value) = bytes[at..at + 4].try_into() else {
                                    unreachable!("imported records are structurally complete")
                                };
                                CanonicalArm::I32 {
                                    head,
                                    value: CanonicalValue::Store(Word::Bits32(u32::from_le_bytes(
                                        value,
                                    ))),
                                }
                            }
                            RecordKind::I64 => {
                                let Ok(value) = bytes[at..at + 8].try_into() else {
                                    unreachable!("imported records are structurally complete")
                                };
                                CanonicalArm::I64 {
                                    head,
                                    value: CanonicalValue::Store(Word::Bits64(u64::from_le_bytes(
                                        value,
                                    ))),
                                }
                            }
                            // A dirty descended interior joined the
                            // closure and recurses; a clean import's slot
                            // bytes are canonical by admission and emit
                            // wholesale.
                            RecordKind::Len => {
                                if row.opened() && row.dirty() {
                                    CanonicalArm::OpenLen { head, first: row.kid, at: 0 }
                                } else {
                                    CanonicalArm::OpaqueLen {
                                        head,
                                        payload: CanonicalPayload::Import(PayloadAt::of_slot(row.value)),
                                    }
                                }
                            }
                        }
                    }
                    Base::Replaced | Base::Inserted => match row.kind {
                        RecordKind::Varint => CanonicalArm::Varint {
                            head,
                            word: self.words.word(WordAt::of_slot(row.value)),
                        },
                        RecordKind::I32 => {
                            #[allow(
                                clippy::cast_possible_truncation,
                                reason = "fixed 32-bit words are stored zero-extended"
                            )]
                            #[allow(
                                clippy::as_conversions,
                                reason = "the stored word is the value's own bits"
                            )]
                            let bits = self.words.word(WordAt::of_slot(row.value)) as u32;
                            CanonicalArm::I32 { head, value: CanonicalValue::Store(Word::Bits32(bits)) }
                        }
                        RecordKind::I64 => CanonicalArm::I64 {
                            head,
                            value: CanonicalValue::Store(Word::Bits64(
                                self.words.word(WordAt::of_slot(row.value)),
                            )),
                        },
                        RecordKind::Len => CanonicalArm::OpaqueLen {
                            head,
                            payload: CanonicalPayload::Store(PayloadAt::of_slot(row.value)),
                        },
                    },
                }
            }

            /// The canonical sizing walk: one complete pass over the
            /// materialized commitment closure, accumulating every
            /// opened LEN's canonical body bottom-up and recording it in
            /// walk order for the emit walk's prefixes. Every live row
            /// is visited — the walk follows visibility, not dirt, so a
            /// clean machine still pays it in full.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class.
            fn canonical_size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<CanonicalFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = self.top;
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at })?;
                        let body = body.as_inner();
                        bodies[frame.slot] = body;
                        acc += frame.outer
                            + u64::from(encoded_len32(frame.head))
                            + u64::from(encoded_len32(body));
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle_canonical(row) {
                        CanonicalArm::Skip => {}
                        CanonicalArm::Varint { head, word } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(encoded_len64(word));
                        }
                        CanonicalArm::I32 { head, .. } => acc += u64::from(encoded_len32(head)) + 4,
                        CanonicalArm::I64 { head, .. } => acc += u64::from(encoded_len32(head)) + 8,
                        CanonicalArm::OpaqueLen { head, payload } => {
                            let len = match payload {
                                CanonicalPayload::Doc { len, .. } => len,
                                CanonicalPayload::Store(value) => self.payloads.len(value),
                                CanonicalPayload::Import(value) => {
                                    admitted_u32(self.import_payload(value).len())
                                }
                            };
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        CanonicalArm::OpenLen { head, first, at } => {
                            let slot = bodies.len();
                            bodies.push(0);
                            spine.push(CanonicalFrame { next: row.next, outer: acc, head, slot, at });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|n| *n <= PayloadLen::MAX.as_inner())
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

            /// The canonical emit walk: the sizing walk's twin, forward,
            /// writing into the shared emitter. Climbing out of opened
            /// LENs follows parent links — the spine is the arena itself.
            /// Returns the count of body slots consumed, for the faces'
            /// seam assertion.
            fn canonical_emit_pass<'s, O: Out<'s>>(&'s self, emit: &mut O, bodies: &[u32]) -> usize {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                let mut cur = self.top;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle_canonical(row) {
                        CanonicalArm::Skip => {}
                        CanonicalArm::Varint { head, word } => {
                            emit.word(head);
                            emit.varint(word);
                        }
                        CanonicalArm::I32 { head, value } => {
                            emit.word(head);
                            match value {
                                CanonicalValue::Doc { at } => {
                                    let at = at.as_inner();
                                    emit.verbatim_in(self.zone_of(row), at, at + 4);
                                }
                                CanonicalValue::Store(word) => emit.value(word),
                            }
                        }
                        CanonicalArm::I64 { head, value } => {
                            emit.word(head);
                            match value {
                                CanonicalValue::Doc { at } => {
                                    let at = at.as_inner();
                                    emit.verbatim_in(self.zone_of(row), at, at + 8);
                                }
                                CanonicalValue::Store(word) => emit.value(word),
                            }
                        }
                        CanonicalArm::OpaqueLen { head, payload } => {
                            emit.word(head);
                            match payload {
                                CanonicalPayload::Doc { at, len } => {
                                    emit.varint(u64::from(len));
                                    emit.verbatim_in(self.zone_of(row), at, at + len);
                                }
                                CanonicalPayload::Store(value) => {
                                    emit.varint(u64::from(self.payloads.len(value)));
                                    self.payloads.for_each_piece(value, |piece| emit.bytes(piece));
                                }
                                CanonicalPayload::Import(value) => {
                                    let payload = self.import_payload(value);
                                    emit.varint(u64::from(admitted_u32(payload.len())));
                                    emit.bytes(payload);
                                }
                            }
                        }
                        CanonicalArm::OpenLen { head, first, .. } => {
                            emit.word(head);
                            emit.varint(u64::from(bodies[body_cursor]));
                            body_cursor += 1;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                emit.flush();
                body_cursor
            }

            /// Serializes under the `CanonicalMinimal` output standard
            /// into a fresh, exactly sized `Vec<u8>`: minimally emits
            /// every varint construct in the materialized commitment
            /// closure; opaque LEN payload bytes pass unchanged.
            ///
            /// The commitment closure is the row graph this
            #[doc = concat!(" ", $noun, " already materialized: the root layer, plus each")]
            /// source LEN interior a successful descend committed.
            /// Every head tag, LEN prefix, and varint value inside it
            /// re-emits at its value's own width — padding on kept tags
            /// included — and prefix shrinkage cascades through every
            /// opened LEN ancestor. An unopened, faulted, or refused
            /// LEN payload and every authored payload terminate the
            /// closure and ride byte-for-byte behind re-derived framing,
            /// even when those bytes happen to parse. Values, field
            /// order, duplicates, liveness, and the fixed-width bits are
            /// untouched, as is every observable of this
            #[doc = concat!(" ", $noun, " — the face reads `&self`, sizes call-locally, and")]
            /// caches nothing.
            ///
            /// The ordinary [`save`](Self::save) family answers
            /// byte-fidelity instead; both re-ingest under `Tolerant`,
            /// and this family's output additionally closes under the
            /// dialect validator's `CanonicalMinimal` standard.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class. Canonical totals never exceed fidelity totals, so
            /// a state whose fidelity save is in class cannot fault
            /// here. On `Err` nothing was published.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1 (tag padded to two bytes) · LEN f2 [88 00]
            /// let msg = [0x88, 0x00, 0x01, 0x12, 0x02, 0x88, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $doc_open, ".unwrap();")]
            ///
            /// // Fidelity keeps the padded kept tag; the canonical face
            /// // re-emits it minimally. The undescended payload's bytes
            /// // are a declaration and ride opaque.
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), msg);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save_canonical().unwrap(), [0x08, 0x01, 0x12, 0x02, 0x88, 0x00]);")]
            /// ```
            pub fn save_canonical(&self) -> Result<Vec<u8>, SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut out = Vec::with_capacity(usize_of(total));
                let mut emit = Emit { out: &mut out, src: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && out.len() == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(out)
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s emission appended to `out`")]
            /// — existing content is untouched. The sizing walk runs
            /// first and makes one exact reservation, so the appends
            /// never regrow the buffer.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]. Every fault precedes the")]
            /// reservation and the first write: on `Err`, `out` keeps
            /// its length and content.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam — or if reserving the
            /// output in `out` would overflow the vector's capacity
            /// bounds (an extreme the caller can reach on 32-bit
            /// targets with a near-full buffer).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1, value padded to two bytes.
            /// let msg = [0x08, 0x81, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $doc_open, ".unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_canonical_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x01]);
            /// ```
            pub fn save_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                out.reserve_exact(usize_of(total));
                let start = out.len();
                let mut emit = Emit { out, src: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.out.len() - start == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(())
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s bytes handed to `sink` as")]
            /// borrowed slices, in output order — no output buffer:
            /// opaque payload runs and fixed-width source values pass
            /// through as windows of the source, framing words ride a
            /// ten-byte stack window, and the concatenation is exactly
            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s output.")]
            ///
            /// The sizing walk runs first and surfaces every fault, so
            /// nothing can refuse once the first slice is handed over.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]; on `Err` the sink has been")]
            /// handed nothing.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            pub fn save_canonical_sink(&self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut emit = SinkEmit { src: &self.source, sink: &mut sink, run: None, written: 0 };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.written == u64::from(total),
                    concat!($noun, " canonical save: the sink walk covers the price")
                );
                Ok(())
            }
    };
    (@canonical $cap:ident tolerant, [$noun:literal] [$doc_mod:literal] [$doc_open:literal], $Machine:ident) => {
            // ── canonical output ──

            /// The canonical walk's verdict for one row, every value
            /// resolved at judgment time. Stored widths are not output
            /// widths here — they remain the source-geometry proof that
            /// locates each value, prefix, and payload.
            fn settle_canonical(&self, row: &Row) -> CanonicalArm {
                if row.deleted() {
                    return CanonicalArm::Skip;
                }
                let head = head_word(row.field, row.kind);
                match row.base() {
                    Base::Intact => match row.kind {
                        RecordKind::Varint => CanonicalArm::Varint {
                            head,
                            // The start column is read raw to keep the
                            // offset sum in the 32-bit unit: a
                            // range-annotated load would let the backend
                            // widen the add and spend an extra
                            // instruction on this path. It stays a
                            // separate load from the opened-Len arm's
                            // typed read: one shared load would either
                            // carry the range fact into this sum or
                            // launder the raw word back into the
                            // coordinate type there.
                            // SAFETY: the scan judged a terminating
                            // in-class varint at this offset inside the
                            // admitted source, and the stored tag width
                            // binds the offset; `Coord` is
                            // `repr(transparent)` over a `u32`-wide
                            // pattern type, so the raw read yields its
                            // inner integer.
                            word: unsafe {
                                let start = (&raw const row.start).cast::<u32>().read();
                                slice::value64_unchecked(
                                    &self.source,
                                    usize_of(start + row.tag_w()),
                                )
                            },
                        },
                        RecordKind::I32 => CanonicalArm::I32 {
                            head,
                            value: CanonicalValue::Doc { at: row.payload_at() },
                        },
                        RecordKind::I64 => CanonicalArm::I64 {
                            head,
                            value: CanonicalValue::Doc { at: row.payload_at() },
                        },
                        RecordKind::Len => {
                            if row.opened() {
                                CanonicalArm::OpenLen { head, first: row.kid, at: row.start.as_inner() }
                            } else {
                                // Unopened, faulted, or refused: the
                                // payload bytes are a declaration, not
                                // records — the closure ends here even
                                // when they happen to parse.
                                CanonicalArm::OpaqueLen {
                                    head,
                                    payload: CanonicalPayload::Doc {
                                        at: row.payload_at().as_inner(),
                                        len: row.payload_len.as_inner(),
                                    },
                                }
                            }
                        }
                    },
                    // A designated payload is an opaque declaration at
                    // the destination: minimal head and prefix over the
                    // source subspan.
                    Base::Src if !matches!(row.src_value(), SrcValue::Imported(_)) => {
                        let (at, len) = self.designated_span(row);
                        CanonicalArm::OpaqueLen {
                            head,
                            payload: CanonicalPayload::Doc { at: at.as_inner(), len },
                        }
                    }
                    // An imported record re-emits minimally under the
                    // canonical standard: its met framing is decoded from
                    // the slot, never preserved (the ordinary save's
                    // fidelity is the byte-exact face).
                    Base::Src => {
                        let bytes = self.import_bytes(row);
                        let at = import_value_at(bytes);
                        match row.kind {
                            RecordKind::Varint => CanonicalArm::Varint {
                                head,
                                word: match slice::value64(bytes, at, bytes.len()) {
                                    Ok((value, _)) => value,
                                    Err(_) => {
                                        unreachable!("imported records are structurally complete")
                                    }
                                },
                            },
                            RecordKind::I32 => {
                                let Ok(value) = bytes[at..at + 4].try_into() else {
                                    unreachable!("imported records are structurally complete")
                                };
                                CanonicalArm::I32 {
                                    head,
                                    value: CanonicalValue::Store(Word::Bits32(u32::from_le_bytes(
                                        value,
                                    ))),
                                }
                            }
                            RecordKind::I64 => {
                                let Ok(value) = bytes[at..at + 8].try_into() else {
                                    unreachable!("imported records are structurally complete")
                                };
                                CanonicalArm::I64 {
                                    head,
                                    value: CanonicalValue::Store(Word::Bits64(u64::from_le_bytes(
                                        value,
                                    ))),
                                }
                            }
                            RecordKind::Len => CanonicalArm::OpaqueLen {
                                head,
                                payload: CanonicalPayload::Import(PayloadAt::of_slot(row.value)),
                            },
                        }
                    }
                    Base::Replaced | Base::Inserted => match row.kind {
                        RecordKind::Varint => CanonicalArm::Varint {
                            head,
                            word: self.words.word(WordAt::of_slot(row.value)),
                        },
                        RecordKind::I32 => {
                            #[allow(
                                clippy::cast_possible_truncation,
                                reason = "fixed 32-bit words are stored zero-extended"
                            )]
                            #[allow(
                                clippy::as_conversions,
                                reason = "the stored word is the value's own bits"
                            )]
                            let bits = self.words.word(WordAt::of_slot(row.value)) as u32;
                            CanonicalArm::I32 { head, value: CanonicalValue::Store(Word::Bits32(bits)) }
                        }
                        RecordKind::I64 => CanonicalArm::I64 {
                            head,
                            value: CanonicalValue::Store(Word::Bits64(
                                self.words.word(WordAt::of_slot(row.value)),
                            )),
                        },
                        RecordKind::Len => CanonicalArm::OpaqueLen {
                            head,
                            payload: CanonicalPayload::Store(PayloadAt::of_slot(row.value)),
                        },
                    },
                }
            }

            /// The canonical sizing walk: one complete pass over the
            /// materialized commitment closure, accumulating every
            /// opened LEN's canonical body bottom-up and recording it in
            /// walk order for the emit walk's prefixes. Every live row
            /// is visited — the walk follows visibility, not dirt, so a
            /// clean machine still pays it in full.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class.
            fn canonical_size_pass(&self) -> Result<(u32, Vec<u32>), SaveFault> {
                let mut bodies: Vec<u32> = Vec::new();
                let mut spine: Vec<CanonicalFrame> = Vec::new();
                let mut acc: u64 = 0;
                let mut cur = self.top;
                loop {
                    let Some(id) = cur else {
                        let Some(frame) = spine.pop() else { break };
                        let body = u32::try_from(acc)
                            .ok()
                            .and_then(PayloadLen::new)
                            .ok_or(SaveFault::BodyOverCap { at: frame.at })?;
                        let body = body.as_inner();
                        bodies[frame.slot] = body;
                        acc += frame.outer
                            + u64::from(encoded_len32(frame.head))
                            + u64::from(encoded_len32(body));
                        cur = frame.next;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle_canonical(row) {
                        CanonicalArm::Skip => {}
                        CanonicalArm::Varint { head, word } => {
                            acc += u64::from(encoded_len32(head)) + u64::from(encoded_len64(word));
                        }
                        CanonicalArm::I32 { head, .. } => acc += u64::from(encoded_len32(head)) + 4,
                        CanonicalArm::I64 { head, .. } => acc += u64::from(encoded_len32(head)) + 8,
                        CanonicalArm::OpaqueLen { head, payload } => {
                            let len = match payload {
                                CanonicalPayload::Doc { len, .. } => len,
                                CanonicalPayload::Store(value) => self.payloads.len(value),
                                CanonicalPayload::Import(value) => {
                                    admitted_u32(self.import_payload(value).len())
                                }
                            };
                            acc += u64::from(encoded_len32(head))
                                + u64::from(encoded_len32(len))
                                + u64::from(len);
                        }
                        CanonicalArm::OpenLen { head, first, at } => {
                            let slot = bodies.len();
                            bodies.push(0);
                            spine.push(CanonicalFrame { next: row.next, outer: acc, head, slot, at });
                            acc = 0;
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                let total = u32::try_from(acc)
                    .ok()
                    .filter(|n| *n <= PayloadLen::MAX.as_inner())
                    .ok_or(SaveFault::DocOverCap { total: acc })?;
                Ok((total, bodies))
            }

            /// The canonical emit walk: the sizing walk's twin, forward,
            /// writing into the shared emitter. Climbing out of opened
            /// LENs follows parent links — the spine is the arena itself.
            /// Returns the count of body slots consumed, for the faces'
            /// seam assertion.
            fn canonical_emit_pass<O: Out>(&self, emit: &mut O, bodies: &[u32]) -> usize {
                let mut body_cursor = 0;
                let mut open: Option<RowId> = None;
                let mut cur = self.top;
                loop {
                    let Some(id) = cur else {
                        let Some(container) = open else { break };
                        let row = self.row(container);
                        cur = row.next;
                        open = row.parent;
                        continue;
                    };
                    let row = self.row(id);
                    match self.settle_canonical(row) {
                        CanonicalArm::Skip => {}
                        CanonicalArm::Varint { head, word } => {
                            emit.word(head);
                            emit.varint(word);
                        }
                        CanonicalArm::I32 { head, value } => {
                            emit.word(head);
                            match value {
                                CanonicalValue::Doc { at } => {
                                    let at = at.as_inner();
                                    emit.verbatim(at, at + 4);
                                }
                                CanonicalValue::Store(word) => emit.value(word),
                            }
                        }
                        CanonicalArm::I64 { head, value } => {
                            emit.word(head);
                            match value {
                                CanonicalValue::Doc { at } => {
                                    let at = at.as_inner();
                                    emit.verbatim(at, at + 8);
                                }
                                CanonicalValue::Store(word) => emit.value(word),
                            }
                        }
                        CanonicalArm::OpaqueLen { head, payload } => {
                            emit.word(head);
                            match payload {
                                CanonicalPayload::Doc { at, len } => {
                                    emit.varint(u64::from(len));
                                    emit.verbatim(at, at + len);
                                }
                                CanonicalPayload::Store(value) => {
                                    emit.varint(u64::from(self.payloads.len(value)));
                                    self.payloads.for_each_piece(value, |piece| emit.bytes(piece));
                                }
                                CanonicalPayload::Import(value) => {
                                    let payload = self.import_payload(value);
                                    emit.varint(u64::from(admitted_u32(payload.len())));
                                    emit.bytes(payload);
                                }
                            }
                        }
                        CanonicalArm::OpenLen { head, first, .. } => {
                            emit.word(head);
                            emit.varint(u64::from(bodies[body_cursor]));
                            body_cursor += 1;
                            open = Some(id);
                            cur = first;
                            continue;
                        }
                    }
                    cur = row.next;
                }
                emit.flush();
                body_cursor
            }

            /// Serializes under the `CanonicalMinimal` output standard
            /// into a fresh, exactly sized `Vec<u8>`: minimally emits
            /// every varint construct in the materialized commitment
            /// closure; opaque LEN payload bytes pass unchanged.
            ///
            /// The commitment closure is the row graph this
            #[doc = concat!(" ", $noun, " already materialized: the root layer, plus each")]
            /// source LEN interior a successful descend committed.
            /// Every head tag, LEN prefix, and varint value inside it
            /// re-emits at its value's own width — padding on kept tags
            /// included — and prefix shrinkage cascades through every
            /// opened LEN ancestor. An unopened, faulted, or refused
            /// LEN payload and every authored payload terminate the
            /// closure and ride byte-for-byte behind re-derived framing,
            /// even when those bytes happen to parse. Values, field
            /// order, duplicates, liveness, and the fixed-width bits are
            /// untouched, as is every observable of this
            #[doc = concat!(" ", $noun, " — the face reads `&self`, sizes call-locally, and")]
            /// caches nothing.
            ///
            /// The ordinary [`save`](Self::save) family answers
            /// byte-fidelity instead; both re-ingest under `Tolerant`,
            /// and this family's output additionally closes under the
            /// dialect validator's `CanonicalMinimal` standard.
            ///
            /// # Errors
            ///
            /// [`SaveFault::BodyOverCap`] when an opened LEN's canonical
            /// body outgrows the length class, [`SaveFault::DocOverCap`]
            /// when the canonical document outgrows the coordinate
            /// class. Canonical totals never exceed fidelity totals, so
            /// a state whose fidelity save is in class cannot fault
            /// here. On `Err` nothing was published.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1 (tag padded to two bytes) · LEN f2 [88 00]
            /// let msg = [0x88, 0x00, 0x01, 0x12, 0x02, 0x88, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $doc_open, ".unwrap();")]
            ///
            /// // Fidelity keeps the padded kept tag; the canonical face
            /// // re-emits it minimally. The undescended payload's bytes
            /// // are a declaration and ride opaque.
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), msg);")]
            #[doc = concat!(" assert_eq!(", $noun, ".save_canonical().unwrap(), [0x08, 0x01, 0x12, 0x02, 0x88, 0x00]);")]
            /// ```
            pub fn save_canonical(&self) -> Result<Vec<u8>, SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut out = Vec::with_capacity(usize_of(total));
                let mut emit = Emit { out: &mut out, src: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && out.len() == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(out)
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s emission appended to `out`")]
            /// — existing content is untouched. The sizing walk runs
            /// first and makes one exact reservation, so the appends
            /// never regrow the buffer.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]. Every fault precedes the")]
            /// reservation and the first write: on `Err`, `out` keeps
            /// its length and content.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam — or if reserving the
            /// output in `out` would overflow the vector's capacity
            /// bounds (an extreme the caller can reach on 32-bit
            /// targets with a near-full buffer).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // varint f1=1, value padded to two bytes.
            /// let msg = [0x08, 0x81, 0x00];
            #[doc = concat!(" let ", $noun, " = ", $doc_open, ".unwrap();")]
            ///
            /// let mut out = vec![0xFF];
            #[doc = concat!(" ", $noun, ".save_canonical_into(&mut out).unwrap();")]
            /// assert_eq!(out, [0xFF, 0x08, 0x01]);
            /// ```
            pub fn save_canonical_into(&self, out: &mut Vec<u8>) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                out.reserve_exact(usize_of(total));
                let start = out.len();
                let mut emit = Emit { out, src: &self.source, run: None };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.out.len() - start == usize_of(total),
                    concat!($noun, " canonical save: sizing and emission disagree")
                );
                Ok(())
            }

            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s bytes handed to `sink` as")]
            /// borrowed slices, in output order — no output buffer:
            /// opaque payload runs and fixed-width source values pass
            /// through as windows of the source, framing words ride a
            /// ten-byte stack window, and the concatenation is exactly
            #[doc = concat!(" [`", stringify!($Machine), "::save_canonical`]'s output.")]
            ///
            /// The sizing walk runs first and surfaces every fault, so
            /// nothing can refuse once the first slice is handed over.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::save_canonical`]; on `Err` the sink has been")]
            /// handed nothing.
            ///
            /// # Panics
            ///
            /// If the canonical sizing and emit walks disagree — a
            /// library bug caught at the seam.
            pub fn save_canonical_sink(&self, mut sink: impl FnMut(&[u8])) -> Result<(), SaveFault> {
                let (total, bodies) = self.canonical_size_pass()?;
                let mut emit = SinkEmit { src: &self.source, sink: &mut sink, run: None, written: 0 };
                let consumed = self.canonical_emit_pass(&mut emit, &bodies);
                assert!(
                    consumed == bodies.len() && emit.written == u64::from(total),
                    concat!($noun, " canonical save: the sink walk covers the price")
                );
                Ok(())
            }
    };
    (
        @payload_mixed $cap:ident $acc:ident $Machine:ident<$($lt:lifetime),*> payload: $p:lifetime, frames: ($Frame:ident, $SizedFrame:ident), [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            $crate::editor::groupless::one_shot_machine!(@import_borrowed $cap $acc $Machine, payload: $p, [$noun]);
            $crate::editor::groupless::one_shot_machine!(@import_copied $cap $acc $Machine, name: copy_record_from_copy, doc: " twin: the record bytes are staged by copy at the command, for designations that cannot outlive the call", [$noun]);

            $crate::editor::groupless::one_shot_machine!(@1s_pb_mixed $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@1s_sp_mixed $cap, payload: $p, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@1s_spc_mixed $cap, payload: $p, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@1s_spp_mixed $cap, payload: $p, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            /// Inserts a LEN record with an authored payload at the
            /// anchor. The payload is borrowed until the save, where its
            /// single copy lands in the output —
            #[doc = concat!(" [`", stringify!($Machine), "::insert_payload_copy`] stages a copy instead, for")]
            /// temporaries. Its interior is the caller's declaration: it
            /// lands as opaque bytes, judged only if an explicit descend
            /// later commits it as a message.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
            /// [`EditFault::PayloadTooLarge`] beyond the length class.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[inline]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &$p [u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                let value = self.payloads.push_borrowed(payload).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value.raw());
                Ok(Handle(id))
            }

            #[doc = concat!(" [`insert_payload`](", stringify!($Machine), "::insert_payload)'s staging twin:")]
            #[doc = concat!(" copies `payload` into the ", $noun, " at the command, for")]
            /// temporaries that cannot outlive it. Same gates, same save
            /// shape; the interior stays the caller's declaration.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`].")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[inline]
            #[track_caller]
            pub fn insert_payload_copy(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &[u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                let value = self.payloads.push_copied(payload).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value.raw());
                Ok(Handle(id))
            }

            #[doc = concat!(" [`insert_payload`](", stringify!($Machine), "::insert_payload)'s scatter twin:")]
            /// the payload arrives as borrowed pieces that concatenate
            /// behind one prefix at the save's gather — zero staging
            /// copies, re-readable pieces
            #[doc = concat!(" ([`", stringify!($Machine), "::set_payload_parts`]'s contract, at an anchor).")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`], the length judgment reading")]
            /// the concatenated length.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[inline]
            #[track_caller]
            pub fn insert_payload_parts(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                parts: &$p [&$p [u8]],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let len = parts_len_usize(parts);
                if len > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len });
                }
                let value = self.payloads.push_parts(parts).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value.raw());
                Ok(Handle(id))
            }

            // ── the staged payload frame ──

            /// Opens a staged replacement of the LEN record's payload:
            #[doc = concat!(" chunks copy into the ", $noun, " through the returned frame, and")]
            /// the record flips atomically at
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish) — until then the ", $noun, " is")]
            /// observably unchanged, and an abandoned frame reclaims its
            /// staged bytes whole. The gates judge here, so the frame
            /// itself cannot discover a refused target.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload_copy`]'s gates: KindMismatch,")]
            #[doc = concat!(" DeletedTarget, OpenedTarget. On `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two transient chunks.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            ///
            #[doc = concat!(" let mut frame = ", $noun, ".begin_set_payload(record).unwrap();")]
            /// frame.write(&[0x61]).unwrap();
            /// frame.write(&[0x62, 0x63]).unwrap();
            /// frame.finish().unwrap();
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x12, 0x03, 0x61, 0x62, 0x63]);")]
            /// ```
            #[track_caller]
            pub fn begin_set_payload(
                &mut self,
                handle: Handle,
            ) -> Result<$Frame<'_, $($lt),*>, EditFault> {
                self.payload_set_gate(handle, 0)?;
                let mark = self.payloads.stage_mark();
                Ok($Frame { machine: self, op: WriteOp::Set { handle }, mark })
            }

            /// Opens a staged insertion of a fresh LEN record at the
            #[doc = concat!(" anchor: chunks copy into the ", $noun, " through the returned")]
            /// frame, and exactly one row splices at
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish) — until then the ", $noun, " is")]
            #[doc = concat!(" observably unchanged ([`", stringify!($Machine), "::begin_set_payload`]'s frame")]
            /// contract). The anchor resolves here; the frame's exclusive
            /// borrow keeps it valid through the close.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload_copy`]'s anchor gates. On `Err`")]
            #[doc = concat!(" the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn begin_insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
            ) -> Result<$Frame<'_, $($lt),*>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let mark = self.payloads.stage_mark();
                Ok($Frame { machine: self, op: WriteOp::Insert { plan, field }, mark })
            }

            /// Judges a length-class declaration into the staging column
            /// and reserves its bytes exactly once — the sized doors'
            /// shared suffix. The callers' gates already judged `len` into
            /// the length class.
            fn stage_declare(&mut self, len: usize) -> Result<u32, EditFault> {
                let declared = admitted_u32(len);
                if u64::from(self.payloads.stage_mark()) + u64::from(declared) > u64::from(u32::MAX) {
                    return Err(EditFault::IndexSpaceExhausted);
                }
                self.payloads.stage_reserve(len);
                Ok(declared)
            }

            #[doc = concat!(" [`begin_set_payload`](", stringify!($Machine), "::begin_set_payload)'s")]
            /// declared-length twin: the caller states the payload's exact
            /// byte length up front, so the class judgment lands here —
            /// zero allocation on refusal — and the staging column
            /// reserves exactly once. The frame is held to its word: a
            /// write past the declaration refuses
            /// [`FrameFault::OverDeclared`], a finish short of it refuses
            /// [`FrameFault::UnderDeclared`], and either fault leaves the
            #[doc = concat!(" ", $noun, " unchanged (the undeclared frame's contract). The")]
            /// undeclared door serves callers streaming an unknown total.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_set_payload`]'s gates, plus")]
            /// [`EditFault::PayloadTooLarge`] when `len` exceeds the
            /// length class — judged before anything is reserved — and
            /// [`EditFault::IndexSpaceExhausted`] when the staging
            /// column's offset domain cannot hold `len` more bytes. On
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two chunks of a declared five.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            ///
            #[doc = concat!(" let mut frame = ", $noun, ".begin_set_payload_sized(record, 5).unwrap();")]
            /// frame.write(b"wor").unwrap();
            /// frame.write(b"ld").unwrap();
            /// frame.finish().unwrap();
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x12, 0x05, 0x77, 0x6F, 0x72, 0x6C, 0x64]);")]
            /// ```
            #[track_caller]
            pub fn begin_set_payload_sized(
                &mut self,
                handle: Handle,
                len: usize,
            ) -> Result<$SizedFrame<'_, $($lt),*>, EditFault> {
                self.payload_set_gate(handle, len)?;
                let declared = self.stage_declare(len)?;
                let mark = self.payloads.stage_mark();
                Ok($SizedFrame {
                    inner: $Frame { machine: self, op: WriteOp::Set { handle }, mark },
                    declared,
                })
            }

            #[doc = concat!(" [`begin_insert_payload`](", stringify!($Machine), "::begin_insert_payload)'s")]
            /// declared-length twin
            #[doc = concat!(" ([`", stringify!($Machine), "::begin_set_payload_sized`]'s door contract, at an")]
            /// anchor).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_insert_payload`]'s anchor gates, plus the")]
            /// sized door's judgments: [`EditFault::PayloadTooLarge`]
            /// when `len` exceeds the length class — judged before
            /// anything is reserved — and
            /// [`EditFault::IndexSpaceExhausted`] when the staging
            /// column's offset domain cannot hold `len` more bytes. On
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn begin_insert_payload_sized(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                len: usize,
            ) -> Result<$SizedFrame<'_, $($lt),*>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                if len > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len });
                }
                let declared = self.stage_declare(len)?;
                let mark = self.payloads.stage_mark();
                Ok($SizedFrame {
                    inner: $Frame { machine: self, op: WriteOp::Insert { plan, field }, mark },
                    declared,
                })
            }
        }
    };
    (
        @payload_borrowed $cap:ident $acc:ident $Machine:ident<$($lt:lifetime),*> payload: $p:lifetime, mixed: $Mixed:ident, [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            $crate::editor::groupless::one_shot_machine!(@import_borrowed $cap $acc $Machine, payload: $p, [$noun]);

            $crate::editor::groupless::one_shot_machine!(@1s_pb_borrowed $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);


            $crate::editor::groupless::one_shot_machine!(@1s_sp_borrowed $cap, mixed: $Mixed, payload: $p, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);


            $crate::editor::groupless::one_shot_machine!(@1s_spp_borrowed $cap, payload: $p, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);


            /// Inserts a LEN record with an authored payload at the
            /// anchor. The payload is borrowed until the save, where its
            /// single copy lands in the output — the mixed
            #[doc = concat!(" [`", stringify!($Mixed), "`]'s `_copy` twins serve temporaries. Its")]
            /// interior is the caller's declaration: it
            /// lands as opaque bytes, judged only if an explicit descend
            /// later commits it as a message.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
            /// [`EditFault::PayloadTooLarge`] beyond the length class.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[inline]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &$p [u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                let value = self.payloads.push_borrowed(payload).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value.raw());
                Ok(Handle(id))
            }


            #[doc = concat!(" [`insert_payload`](", stringify!($Machine), "::insert_payload)'s scatter twin:")]
            /// the payload arrives as borrowed pieces that concatenate
            /// behind one prefix at the save's gather — zero staging
            /// copies, re-readable pieces
            #[doc = concat!(" ([`", stringify!($Machine), "::set_payload_parts`]'s contract, at an anchor).")]
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`], the length judgment reading")]
            /// the concatenated length.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[inline]
            #[track_caller]
            pub fn insert_payload_parts(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                parts: &$p [&$p [u8]],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let len = parts_len_usize(parts);
                if len > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len });
                }
                let value = self.payloads.push_parts(parts).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value.raw());
                Ok(Handle(id))
            }
        }
    };
    (
        @payload_copied $cap:ident $acc:ident $Machine:ident<$($lt:lifetime),*> mixed: $Mixed:ident, frames: ($Frame:ident, $SizedFrame:ident), [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {
        impl<$($lt),*> $Machine<$($lt),*> {
            $crate::editor::groupless::one_shot_machine!(@import_copied $cap $acc $Machine, name: copy_record_from, doc: ": the record bytes are staged by copy at the command, so no designation lifetime binds the caller", [$noun]);

            $crate::editor::groupless::one_shot_machine!(@1s_pb_copied $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            $crate::editor::groupless::one_shot_machine!(@1s_sp_copied $cap, mixed: $Mixed, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);

            /// Inserts a LEN record with an authored payload at the
            /// anchor, copying the payload at the command — temporaries
            #[doc = concat!(" welcome; the mixed [`", stringify!($Mixed), "`]'s borrowed default is")]
            /// the zero-staging path. Its interior is the caller's
            /// declaration: it lands as opaque bytes, judged only if an
            /// explicit descend later commits it as a message.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_varint`], plus")]
            /// [`EditFault::PayloadTooLarge`] beyond the length class.
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[inline]
            #[track_caller]
            pub fn insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                payload: &[u8],
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                if payload.len() > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len: payload.len() });
                }
                let value = self.payloads.push_copied(payload).ok_or(EditFault::IndexSpaceExhausted)?;
                self.apply_insert(&plan, id, field, RecordKind::Len, value.raw());
                Ok(Handle(id))
            }


            // ── the staged payload frame ──

            /// Opens a staged replacement of the LEN record's payload:
            #[doc = concat!(" chunks copy into the ", $noun, " through the returned frame, and")]
            /// the record flips atomically at
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish) — until then the ", $noun, " is")]
            /// observably unchanged, and an abandoned frame reclaims its
            /// staged bytes whole. The gates judge here, so the frame
            /// itself cannot discover a refused target.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::set_payload`]'s gates: KindMismatch,")]
            #[doc = concat!(" DeletedTarget, OpenedTarget. On `Err` the ", $noun, " is")]
            /// unchanged.
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two transient chunks.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            ///
            #[doc = concat!(" let mut frame = ", $noun, ".begin_set_payload(record).unwrap();")]
            /// frame.write(&[0x61]).unwrap();
            /// frame.write(&[0x62, 0x63]).unwrap();
            /// frame.finish().unwrap();
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x12, 0x03, 0x61, 0x62, 0x63]);")]
            /// ```
            #[track_caller]
            pub fn begin_set_payload(
                &mut self,
                handle: Handle,
            ) -> Result<$Frame<'_, $($lt),*>, EditFault> {
                self.payload_set_gate(handle, 0)?;
                let mark = self.payloads.stage_mark();
                Ok($Frame { machine: self, op: WriteOp::Set { handle }, mark })
            }


            /// Opens a staged insertion of a fresh LEN record at the
            #[doc = concat!(" anchor: chunks copy into the ", $noun, " through the returned")]
            /// frame, and exactly one row splices at
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish) — until then the ", $noun, " is")]
            #[doc = concat!(" observably unchanged ([`", stringify!($Machine), "::begin_set_payload`]'s frame")]
            /// contract). The anchor resolves here; the frame's exclusive
            /// borrow keeps it valid through the close.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::insert_payload`]'s anchor gates. On `Err`")]
            #[doc = concat!(" the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn begin_insert_payload(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
            ) -> Result<$Frame<'_, $($lt),*>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let mark = self.payloads.stage_mark();
                Ok($Frame { machine: self, op: WriteOp::Insert { plan, field }, mark })
            }


            /// Judges a length-class declaration into the staging column
            /// and reserves its bytes exactly once — the sized doors'
            /// shared suffix. The callers' gates already judged `len` into
            /// the length class.
            fn stage_declare(&mut self, len: usize) -> Result<u32, EditFault> {
                let declared = admitted_u32(len);
                if u64::from(self.payloads.stage_mark()) + u64::from(declared) > u64::from(u32::MAX) {
                    return Err(EditFault::IndexSpaceExhausted);
                }
                self.payloads.stage_reserve(len);
                Ok(declared)
            }


            #[doc = concat!(" [`begin_set_payload`](", stringify!($Machine), "::begin_set_payload)'s")]
            /// declared-length twin: the caller states the payload's exact
            /// byte length up front, so the class judgment lands here —
            /// zero allocation on refusal — and the staging column
            /// reserves exactly once. The frame is held to its word: a
            /// write past the declaration refuses
            /// [`FrameFault::OverDeclared`], a finish short of it refuses
            /// [`FrameFault::UnderDeclared`], and either fault leaves the
            #[doc = concat!(" ", $noun, " unchanged (the undeclared frame's contract). The")]
            /// undeclared door serves callers streaming an unknown total.
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_set_payload`]'s gates, plus")]
            /// [`EditFault::PayloadTooLarge`] when `len` exceeds the
            /// length class — judged before anything is reserved — and
            /// [`EditFault::IndexSpaceExhausted`] when the staging
            /// column's offset domain cannot hold `len` more bytes. On
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            #[doc = concat!(" Panics if `handle` was not minted by this ", $noun, " (the arena")]
            /// index contract).
            ///
            /// # Examples
            ///
            /// ```
            /// use protobuf_edit::DepthLimit;
            #[doc = concat!(" use ", $doc_mod, "::", stringify!($Machine), ";")]
            ///
            /// // LEN f2 "hi" — replaced from two chunks of a declared five.
            /// let msg = [0x12, 0x02, 0x68, 0x69];
            #[doc = concat!(" let mut ", $noun, " = ", $doc_open, ".unwrap();")]
            #[doc = concat!(" let record = ", $noun, ".top().next().unwrap();")]
            ///
            #[doc = concat!(" let mut frame = ", $noun, ".begin_set_payload_sized(record, 5).unwrap();")]
            /// frame.write(b"wor").unwrap();
            /// frame.write(b"ld").unwrap();
            /// frame.finish().unwrap();
            #[doc = concat!(" assert_eq!(", $noun, ".save().unwrap(), [0x12, 0x05, 0x77, 0x6F, 0x72, 0x6C, 0x64]);")]
            /// ```
            #[track_caller]
            pub fn begin_set_payload_sized(
                &mut self,
                handle: Handle,
                len: usize,
            ) -> Result<$SizedFrame<'_, $($lt),*>, EditFault> {
                self.payload_set_gate(handle, len)?;
                let declared = self.stage_declare(len)?;
                let mark = self.payloads.stage_mark();
                Ok($SizedFrame {
                    inner: $Frame { machine: self, op: WriteOp::Set { handle }, mark },
                    declared,
                })
            }


            #[doc = concat!(" [`begin_insert_payload`](", stringify!($Machine), "::begin_insert_payload)'s")]
            /// declared-length twin
            #[doc = concat!(" ([`", stringify!($Machine), "::begin_set_payload_sized`]'s door contract, at an")]
            /// anchor).
            ///
            /// # Errors
            ///
            #[doc = concat!(" As [`", stringify!($Machine), "::begin_insert_payload`]'s anchor gates, plus the")]
            /// sized door's judgments: [`EditFault::PayloadTooLarge`]
            /// when `len` exceeds the length class — judged before
            /// anything is reserved — and
            /// [`EditFault::IndexSpaceExhausted`] when the staging
            /// column's offset domain cannot hold `len` more bytes. On
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by this
            #[doc = concat!(" ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn begin_insert_payload_sized(
                &mut self,
                at: InsertAt,
                field: FieldNumber,
                len: usize,
            ) -> Result<$SizedFrame<'_, $($lt),*>, EditFault> {
                let plan = self.resolve_anchor(at)?;
                if len > usize_of(PayloadLen::MAX.as_inner()) {
                    return Err(EditFault::PayloadTooLarge { len });
                }
                let declared = self.stage_declare(len)?;
                let mark = self.payloads.stage_mark();
                Ok($SizedFrame {
                    inner: $Frame { machine: self, op: WriteOp::Insert { plan, field }, mark },
                    declared,
                })
            }
        }
    };
    (@import_borrowed plain $acc:ident $Machine:ident, payload: $p:lifetime, [$noun:literal]) => {};
    (@import_copied plain $acc:ident $Machine:ident, name: $name:ident, doc: $doc:literal, [$noun:literal]) => {};
    (
        @import_borrowed $cap:ident tolerant $Machine:ident, payload: $p:lifetime, [$noun:literal]
    ) => {
            /// Copies one designated external record to the anchor: the
            /// designation's exact bytes — met tag spelling and framing
            /// widths included — contribute whole at save, nothing
            /// re-encoded. The record bytes stay borrowed until the save
            /// copies them once into the output, so the designation's
            /// backing must outlive this machine's payload tenure. The
            /// imported record is output-authored: its status reads
            /// `Inserted`, it answers no source span, and it does not
            /// designate onward; its interior is the source's opaque
            /// declaration.
            ///
            /// # Errors
            ///
            /// [`EditFault::IndexSpaceExhausted`] when the slot space is
            /// spent, plus the anchor gates of `insert_varint`. On any
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::RecordRef<$p>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let value = self
                    .payloads
                    .push_borrowed(source.as_bytes())
                    .ok_or(EditFault::IndexSpaceExhausted)?;
                // The import mint stays below the designation bit; the
                // slot past it is unreachable and inert.
                if value.raw() & SRC_PAYLOAD != 0 {
                    return Err(EditFault::IndexSpaceExhausted);
                }
                self.apply_import(&plan, id, source.field(), source.kind(), value.raw());
                Ok(Handle(id))
            }
    };
    (
        @import_borrowed $cap:ident canonical $Machine:ident, payload: $p:lifetime, [$noun:literal]
    ) => {
            /// Copies one designated external record to the anchor: the
            /// designation's exact bytes contribute whole at save,
            /// nothing re-encoded. This host admits canonically, so the
            /// argument is the proof-carrying form — a tolerant
            /// designation upgrades through `try_canonical`, which
            /// refuses padded framing before any mutation. The record
            /// bytes stay borrowed until the save copies them once into
            /// the output, so the designation's backing must outlive
            /// this machine's payload tenure. The imported record is
            /// output-authored: its status reads `Inserted`, it answers
            /// no source span, and it does not designate onward; its
            /// interior is the source's opaque declaration.
            ///
            /// # Errors
            ///
            /// [`EditFault::IndexSpaceExhausted`] when the slot space is
            /// spent, plus the anchor gates of `insert_varint`. On any
            #[doc = concat!(" `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn copy_record_from(
                &mut self,
                source: crate::source::groupless::CanonicalRecordRef<$p>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let value = self
                    .payloads
                    .push_borrowed(source.as_bytes())
                    .ok_or(EditFault::IndexSpaceExhausted)?;
                // The import mint stays below the designation bit; the
                // slot past it is unreachable and inert.
                if value.raw() & SRC_PAYLOAD != 0 {
                    return Err(EditFault::IndexSpaceExhausted);
                }
                self.apply_import(&plan, id, source.field(), source.kind(), value.raw());
                Ok(Handle(id))
            }
    };
    (
        @import_copied $cap:ident tolerant $Machine:ident, name: $name:ident, doc: $doc:literal, [$noun:literal]
    ) => {
            #[doc = concat!(" [`copy_record_from`](", stringify!($Machine), "::copy_record_from)'s staging")]
            #[doc = concat!($doc, ". The designation's exact bytes — met tag spelling and")]
            /// framing widths included — contribute whole at save,
            /// nothing re-encoded; one exact record-length copy lands in
            /// the byte zone at the command. The imported record is
            /// output-authored: its status reads `Inserted`, it answers
            /// no source span, and it does not designate onward.
            ///
            /// # Errors
            ///
            /// [`EditFault::IndexSpaceExhausted`] when the slot space or
            /// byte-zone offset domain is spent, plus the anchor gates
            #[doc = concat!(" of `insert_varint`. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn $name(
                &mut self,
                source: crate::source::groupless::RecordRef<'_>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let value = self
                    .payloads
                    .push_copied(source.as_bytes())
                    .ok_or(EditFault::IndexSpaceExhausted)?;
                // The import mint stays below the designation bit; the
                // slot past it is unreachable and inert.
                if value.raw() & SRC_PAYLOAD != 0 {
                    return Err(EditFault::IndexSpaceExhausted);
                }
                self.apply_import(&plan, id, source.field(), source.kind(), value.raw());
                Ok(Handle(id))
            }
    };
    (
        @import_copied $cap:ident canonical $Machine:ident, name: $name:ident, doc: $doc:literal, [$noun:literal]
    ) => {
            #[doc = concat!(" [`copy_record_from`](", stringify!($Machine), "::copy_record_from)'s staging")]
            #[doc = concat!($doc, ". This host admits canonically, so the argument is the")]
            /// proof-carrying form — a tolerant designation upgrades
            /// through `try_canonical`, which refuses padded framing
            /// before any mutation. The designation's exact bytes
            /// contribute whole at save, nothing re-encoded; one exact
            /// record-length copy lands in the byte zone at the command.
            /// The imported record is output-authored: its status reads
            /// `Inserted`, it answers no source span, and it does not
            /// designate onward.
            ///
            /// # Errors
            ///
            /// [`EditFault::IndexSpaceExhausted`] when the slot space or
            /// byte-zone offset domain is spent, plus the anchor gates
            #[doc = concat!(" of `insert_varint`. On any `Err` the ", $noun, " is unchanged.")]
            ///
            /// # Panics
            ///
            /// Panics if a handle inside the anchor was not minted by
            #[doc = concat!(" this ", $noun, " (the arena index contract).")]
            #[track_caller]
            pub fn $name(
                &mut self,
                source: crate::source::groupless::CanonicalRecordRef<'_>,
                at: InsertAt,
            ) -> Result<Handle, EditFault> {
                let plan = self.resolve_anchor(at)?;
                let id = self.mint_insert()?;
                let value = self
                    .payloads
                    .push_copied(source.as_bytes())
                    .ok_or(EditFault::IndexSpaceExhausted)?;
                // The import mint stays below the designation bit; the
                // slot past it is unreachable and inert.
                if value.raw() & SRC_PAYLOAD != 0 {
                    return Err(EditFault::IndexSpaceExhausted);
                }
                self.apply_import(&plan, id, source.field(), source.kind(), value.raw());
                Ok(Handle(id))
            }
    };
    (
        @frames $cap:ident $acc:ident $Machine:ident<$($lt:lifetime),*> frames: ($Frame:ident, $SizedFrame:ident), [$noun:literal] [$a_noun:literal] [$A_noun:literal] [$doc_mod:literal] [$doc_open:literal] [$doc_open_empty:literal]
    ) => {

        /// A staged payload frame.
        ///
        #[doc = concat!(" Chunks copy into the ", $noun, " as they arrive, and exactly one")]
        #[doc = concat!(" record changes at [`finish`](", stringify!($Frame), "::finish) — before")]
        #[doc = concat!(" it, the ", $noun, " is observably unchanged. Dropping the frame")]
        /// unfinished reclaims its staged bytes — the staging column
        /// returns to its pre-frame byte cursor and offset space, while
        /// capacity gained while staging may be retained for reuse — and
        #[doc = concat!(" its exclusive borrow of the ", $noun, " keeps every other command")]
        /// out while it lives.
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct $Frame<'w, $($lt),*> {
            machine: &'w mut $Machine<$($lt),*>,
            op: WriteOp,
            /// The staging column's tail at open: the staged extent is
            /// `mark..` for the frame's whole life.
            mark: u32,
        }

        impl<$($lt),*> Drop for $Frame<'_ $(, $lt)*> {
            /// Reclaims the staged extent: only a publishing
            #[doc = concat!(" [`finish`](", stringify!($Frame), "::finish) keeps the staged bytes, so")]
            /// abandonment and every refusal path leave the staging
            /// column's byte cursor and offset space exactly as the door
            /// found them (reserved capacity may be retained).
            fn drop(&mut self) {
                self.machine.payloads.stage_abandon(self.mark);
            }
        }

        impl<$($lt),*> $Frame<'_ $(, $lt)*> {
            /// Appends one chunk to the staged payload, copying it at the
            /// call — temporaries welcome; the staging column owns them.
            /// An empty chunk is a no-op.
            ///
            /// # Errors
            ///
            /// [`EditFault::PayloadTooLarge`] when the staged total would
            /// leave the length class,
            /// [`EditFault::IndexSpaceExhausted`] when the staging
            /// column's coordinate space is spent. On `Err` the chunk is
            /// not staged and the frame stays usable.
            pub fn write(&mut self, chunk: &[u8]) -> Result<(), EditFault> {
                let staged = u64::from(self.machine.payloads.staged_len(self.mark));
                #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(PayloadLen::MAX.as_inner()) {
                    let len = usize::try_from(total).unwrap_or(usize::MAX);
                    return Err(EditFault::PayloadTooLarge { len });
                }
                self.machine.payloads.stage_chunk(chunk).ok_or(EditFault::IndexSpaceExhausted)?;
                Ok(())
            }

            /// Installs the staged payload: the set flips its record, the
            /// insert splices exactly one fresh row — atomically, now.
            /// Returns the changed record's handle (the set's own target,
            /// or the minted insertion).
            ///
            /// # Errors
            ///
            /// [`EditFault::IndexSpaceExhausted`] when the row or value
            #[doc = concat!(" coordinate space is spent. On `Err` the ", $noun, " is unchanged")]
            /// — the staged bytes are reclaimed with the frame.
            pub fn finish(mut self) -> Result<Handle, EditFault> {
                match self.apply() {
                    Ok(handle) => {
                        // Published: a slot now covers the staged
                        // extent, so defuse the drop reclamation.
                        core::mem::forget(self);
                        Ok(handle)
                    }
                    // Dropping the frame reclaims the staged extent.
                    Err(fault) => Err(fault),
                }
            }

            $crate::editor::groupless::one_shot_machine!(@1s_frame_apply $cap, $Machine, [$noun] [$a_noun] [$A_noun] [$doc_mod] [$doc_open] [$doc_open_empty]);
        }

        /// A staged payload frame held to a declared length.
        ///
        /// The declaration was judged and its bytes reserved when the door
        #[doc = concat!(" opened ([`", stringify!($Machine), "::begin_set_payload_sized`],")]
        #[doc = concat!(" [`", stringify!($Machine), "::begin_insert_payload_sized`]), so staging never")]
        /// regrows the column; a write past the declaration refuses
        /// [`FrameFault::OverDeclared`] and [`finish`](Self::finish)
        /// installs only the exact declared extent —
        /// [`FrameFault::UnderDeclared`] otherwise. The declaration
        /// judgments live on the frame faces alone, so the sized faces
        /// speak [`FrameFault`]; everything else is the
        /// undeclared frame's contract: chunks copy in as they arrive,
        /// exactly one record changes at the finish, and a dropped or
        /// refused frame reclaims its staged bytes.
        #[must_use = "a payload frame installs nothing until finished"]
        pub struct $SizedFrame<'w, $($lt),*> {
            inner: $Frame<'w, $($lt),*>,
            /// The declared payload length, in the length class.
            declared: u32,
        }

        impl<$($lt),*> $SizedFrame<'_ $(, $lt)*> {
            /// Appends one chunk to the staged payload, copying it at the
            /// call into the bytes the door reserved — spending the
            /// door's proof: no bound, domain, or allocator judgment
            /// re-runs here, only the declaration compare below.
            /// An empty chunk is a no-op.
            ///
            /// # Errors
            ///
            /// [`FrameFault::OverDeclared`] when the staged total would
            /// pass the declaration. On `Err` the chunk is not staged and
            /// the frame stays usable.
            pub fn write(&mut self, chunk: &[u8]) -> Result<(), FrameFault> {
                let staged = u64::from(self.inner.machine.payloads.staged_len(self.inner.mark));
                #[allow(clippy::as_conversions, reason = "chunk lengths widen losslessly to u64")]
                let total = staged.saturating_add(chunk.len() as u64);
                if total > u64::from(self.declared) {
                    return Err(FrameFault::OverDeclared { declared: self.declared, total });
                }
                // The door judged the declaration into the length class
                // and the column's offset domain and reserved its bytes;
                // the gate above bounds the staged total inside the
                // declaration, so this append stays inside both.
                self.inner.machine.payloads.stage_chunk_reserved(chunk);
                Ok(())
            }

            /// Installs the staged payload exactly as declared — the
            #[doc = concat!(" undeclared frame's [`finish`](", stringify!($Frame), "::finish), behind")]
            /// the declaration judgment.
            ///
            /// # Errors
            ///
            /// [`FrameFault::UnderDeclared`] when fewer bytes than declared
            /// were staged, [`FrameFault::IndexSpaceExhausted`] when the
            #[doc = concat!(" row or value coordinate space is spent. On `Err` the ", $noun)]
            /// is unchanged — the staged bytes are reclaimed with the
            /// frame.
            pub fn finish(self) -> Result<Handle, FrameFault> {
                let staged = self.inner.machine.payloads.staged_len(self.inner.mark);
                if staged != self.declared {
                    return Err(FrameFault::UnderDeclared { declared: self.declared, staged });
                }
                self.inner.finish().map_err(close_fault)
            }
        }
    };
}

pub(crate) use one_shot_machine;
